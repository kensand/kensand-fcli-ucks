// f ssh — ssh/scp/rsync with a private key that lives in `f creds`, never on disk.
//
// Why this exists: the usual answer ("put the key in the vault, write it to a
// temp file, chmod 600, delete it after") leaks a live copy of the key to disk on
// every use, and OpenSSH refuses an unencrypted PEM on stdin only when it has to
// prompt for a passphrase. It does not: `ssh-add -` reads a key from stdin. So
// this uck pipes the vault value straight into ssh-add over stdin, the key lives
// only in the agent's memory, and nothing key-shaped is ever written.
//
// Verified on OpenSSH 10.6: `cat key | ssh-add -` -> "Identity added: (stdin)".
//
// Two ways to use the key:
//   f ssh setup            write a stable IdentityFile + include block so plain
//                          ssh / scp / rsync / git-over-ssh work with no wrapper
//   f ssh <host> [args]    per-command injection, for when you don't want the
//                          config file touched
//
// The per-command path passes the identity by path, then *proves* the key is
// actually loaded by asking a throwaway agent with no other identities:
//   ssh -G          proves the path is readable and is the configured identity
//   -o IdentitiesOnly=yes + IdentityAgent=none on the probe means any failure to
//   present it is fatal and visible, where a real ssh would only warn and fall
//   back to the agent.
//
// Cred names (first hit wins), all overridable with --cred <name>:
//   ssh.key.<host>   host-specific key, e.g. ssh.key.hetzner
//   file:~/.ssh/id_ed25519   the packed file entry (f creds files pack)
//   ssh.key          one personal key for everything
//   ssh              the vault item name
//   id_ed25519       the default filename
// Persistent default: f config set ssh.cred <name>
//
// Commands:
//   f ssh status                     agent + key + source, one line each
//   f ssh setup                      install the IdentityFile include (~/.ssh/config)
//   f ssh teardown                   remove that include
//   f ssh env                        eval "$(f ssh env)" -> SSH_AUTH_SOCK for your shell
//   f ssh agent <cmd...>             run cmd with SSH_AUTH_SOCK set
//   f ssh load [host]                load the key into a long-lived agent
//   f ssh add [host]                 legacy: cat the PEM (needs --secrets)
//   f ssh list                       ssh-add -l for the agent
//   f ssh <host> [ssh args...]       ssh with the key injected
//   f ssh scp|rsync|sftp <args...>   same key injected into those tools
//   f ssh -h                         usage

import { execFileSync, spawn, spawnSync } from "node:child_process";
import net from "node:net";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const F = path.join(process.env.HOME ?? "", ".f");
// The key file deliberately lives under ~/.ssh, NOT ~/.f: sibling ucks treat
// that directory as the credential store's home (`.creds.box`, the daemon
// lockfile, `f creds files pack` recurses through uck dirs), so plaintext key
// material does not belong there.
const SSHD = path.join(os.homedir(), ".ssh", "f-ssh");
const KEYFILE = path.join(SSHD, "id_ed25519");
const CONFIG_PATH = path.join(os.homedir(), ".ssh", "config");
const MARK = "f ssh (kensand-fcli-ucks)";
const CRED_SOCKET = path.join(F, ".creds.sock");
const DEFAULT_CRED = "ssh";

// ---------------------------------------------------------------- diagnostics

function err(msg) {
  process.stderr.write(msg.endsWith("\n") ? msg : msg + "\n");
}

function fail(lines, code = 1) {
  err(lines.map((l) => "f ssh: " + l).join("\n"));
  // exit() directly rather than unwinding: the published harness prints
  // `f: ${e.message}` for anything run() throws, so even an empty sentinel leaks
  // a stray "f: " line under our diagnostics. Exiting also hands the TTY back
  // immediately, which matters after an interactive ssh session.
  exitWith(code);
}

/**
 * The published `f` does `await uck.run(...)` inside a try/catch and then simply
 * returns — an uck's return value sets nothing, so `f ssh host false` exited 0
 * while ssh said the command failed. Every failure path therefore ends here:
 * set the real status and leave.
 *
 * Throwing is deliberate. The harness catches, prints `f: ` + e.message (empty,
 * so the line is a no-op next to our own diagnostics) and returns normally; if we
 * merely returned, the harness's `return` would run `process.exit(0)` over our
 * exitCode. Any other error still propagates so `f` reports it as it always has.
 */
function exitWith(code) {
  process.exitCode = code ?? 0;
  process.exit(process.exitCode);
}

// ------------------------------------------------------------------- config

function readConfig() {
  for (const p of [path.join(F, "f.config.json"), path.join(process.cwd(), "f.config.json")]) {
    try {
      return JSON.parse(fs.readFileSync(p, "utf8"));
    } catch {}
  }
  return {};
}

function configCred() {
  const c = readConfig().ssh;
  if (typeof c === "string") return c;
  if (c && typeof c === "object" && typeof c.cred === "string") return c.cred;
  return null;
}

// -------------------------------------------------------------------- creds

/** Live unlocked daemon state, from the lockfile (never blocks, never prompts). */
function credsUnlocked() {
  let lf;
  try {
    lf = JSON.parse(fs.readFileSync(path.join(F, ".creds-daemon"), "utf8"));
  } catch {
    return null;
  }
  if (!lf?.pid || !lf?.start || !lf?.ttl) return null;
  try {
    process.kill(lf.pid, 0);
  } catch {
    return null;
  }
  return lf.start + lf.ttl * 1000 > Date.now() ? { socket: lf.socket || CRED_SOCKET } : null;
}

/**
 * One request to the creds daemon over its unix socket.
 *
 * The daemon answers with a single JSON object and NO trailing newline
 * (`socket.end(JSON.stringify(resp))` in creds/daemon.js), then closes. Reading
 * until "\n" therefore never completes and every lookup burns the whole timeout
 * — 20s of dead time per miss, which is what made this uck look hung. So:
 * parse on end-of-stream, and opportunistically as soon as a complete JSON
 * object has arrived. `end` is authoritative; the eager path just skips a tick.
 */
function daemonCall(msg, socket, timeoutMs = 5_000) {
  return new Promise((resolve) => {
    let buf = "";
    let done = false;
    let timer = null;
    const finish = (v) => {
      if (done) return;
      done = true;
      if (timer) clearTimeout(timer);
      try { sock.destroy(); } catch {}
      resolve(v);
    };
    const parse = (text) => {
      try {
        return JSON.parse(text);
      } catch {
        return undefined;
      }
    };
    const sock = net.connect({ path: socket });
    // Local socket, single small request: do not let Nagle add a round trip.
    try { sock.setNoDelay(true); } catch {}
    timer = setTimeout(() => finish(null), timeoutMs);
    sock.on("error", () => finish(null));
    sock.on("close", () => finish(parse(buf) ?? null));
    sock.on("data", (d) => {
      buf += d.toString("utf8");
      const v = parse(buf);
      if (v !== undefined) finish(v);
    });
    sock.on("connect", () => {
      try {
        sock.write(JSON.stringify(msg));
      } catch {
        finish(null);
      }
    });
  });
}

/**
 * Read one cred straight from the encrypted box.
 *
 * This uck deliberately does NOT shell out to `f creds get`. That command runs
 * the provider ladder on a local miss, and doing it once per candidate name
 * costs a nested `f` per name (the published harness re-installs every local uck
 * source at startup, so each one is ~0.7s and was measured above 20s as a child
 * of another `f`). Names are few and misses are the common case, so the box is
 * read directly here; `resolveNamed()` is the only place that pays for a nested
 * `f`, and only for names a box read cannot answer at all.
 *
 * The registry handoff is used when the harness provides one; the published `f`
 * passes ctx = { fVersion, ucks, self } with no `registry` at all — which is why
 * `f ha`/`f fj` silently miss their creds — so nothing here depends on it.
 *
 * Returns { value, src } | { locked } | { missing } | { error }.
 */
async function readCred(name, credsApi) {
  const state = credsUnlocked();
  if (!state) return { locked: true };

  // `ssh::password` and friends are provider vocabulary, not box keys.
  if (name.includes("::")) {
    const p = providerGet(name);
    if (p.value) return { value: p.value, src: `vault:${name}` };
    return p.error ? { error: p.error } : { missing: true };
  }

  if (credsApi && typeof credsApi.get === "function") {
    try {
      const v = await credsApi.get(name);
      return v == null || v === "" ? { missing: true } : { value: v, src: `creds:${name}` };
    } catch (e) {
      const m = e?.message ?? String(e);
      if (/locked/i.test(m)) return { locked: true };
      if (/no such cred/i.test(m)) return { missing: true };
      return { error: m };
    }
  }

  // b64, not utf8: a stored key keeps its exact bytes, including any trailing
  // newline the daemon would otherwise have trimmed.
  const r = await daemonCall({ op: "get", name, b64: true }, state.socket);
  if (r?.ok && (r.value != null || r.b64 != null)) {
    const raw = r.b64 != null ? Buffer.from(r.b64, "base64").toString("utf8") : r.value;
    return raw ? { value: raw, src: `creds:${name}` } : { missing: true };
  }
  if (r && r.ok === false && /locked/i.test(r.error ?? "")) return { locked: true };
  return { missing: true };
}

/**
 * Normalize a private key into something ssh-add will accept.
 *
 * The trailing newline is not cosmetic: `printf '%s' "$KEY" | ssh-add -` fails
 * with `Error loading key "(stdin)": invalid format` on OpenSSH 10.6, while the
 * same bytes plus "\n" load fine. The creds daemon trims stored values, so the
 * newline is routinely missing by the time we see the key — append, never
 * merely preserve.
 */
function normalizePem(raw) {
  if (typeof raw !== "string") return null;
  let pem = raw.replace(/\r\n/g, "\n").trim();
  if (!pem) return null;
  // Drop anything wrapped around the key block (vault notes, JSON quoting).
  const m = pem.match(/-----(BEGIN|ORIGINAL)( [A-Z ]*)?-----[\s\S]*-----(END|ORIGINAL) ?[A-Z ]*-----/);
  if (m) pem = m[0];
  return pem + "\n";
}

/** Host part of an [user@]host destination (best effort; "" when unparseable). */
function hostFromDest(dest) {
  if (typeof dest !== "string" || !dest) return "";
  let h = dest.includes("@") ? dest.slice(dest.lastIndexOf("@") + 1) : dest;
  h = h.split(/[\s/]/)[0];
  if (h.startsWith("[")) h = h.slice(1, h.indexOf("]") > 1 ? h.indexOf("]") : undefined);
  return h.split(":")[0];
}

/** A destination is host-ish: no leading dash (an ssh flag), no scheme, no
 *  remote-path syntax. Anything else is not a host and must not be used to pick
 *  a cred — `f ssh -o StrictHostKeyChecking=accept-new host` would otherwise
 *  look up `ssh.key.StrictHostKeyChecking=accept-new`. */
function looksLikeHost(dest) {
  const h = hostFromDest(dest);
  if (!h || dest.startsWith("-") || dest.startsWith("+")) return "";
  if (/^[a-z0-9+-]+:\/\//i.test(dest)) return ""; // ssh://, git:// …
  if (h.includes("=") || h.includes(",")) return "";
  return h;
}

/**
 * Cred names to try, most specific first. `host` may be "" — status, setup and
 * friends have no destination to key off.
 *
 * `--cred` is an override, not a filter: the configured and conventional names
 * stay behind it. A pinned name that stops resolving (vault sync, rename, a
 * re-typed cred) must not turn every connection into "no key found" while the
 * ordinary `ssh` cred sits in the box.
 */
function credCandidates(host, explicit) {
  const names = [];
  if (explicit) names.push(explicit);
  if (process.env.F_SSH_CRED) names.push(process.env.F_SSH_CRED);
  const cfg = configCred();
  if (cfg) names.push(cfg);
  if (host) names.push(`ssh.key.${host}`);
  names.push(`file:${KEYFILE}`);
  names.push("ssh.key", DEFAULT_CRED, "id_ed25519");
  return [...new Set(names)];
}

/**
 * Find the key. Names the daemon can serve (the overwhelming majority) are read
 * over its unix socket, ~1ms each. `file:` and `::field` names are the two things
 * a socket read cannot answer, and those go through a nested `f` — but only for
 * names someone actually asked for, never as silent background fallbacks.
 *
 * Returns { pem, src } | { locked } | { error, name } | { missing: true }.
 */
async function findKey(credsApi, names) {
  const fast = await probeBox(credsApi, names);
  if (fast.pem) return fast;
  if (fast.locked) return { locked: true };

  // Deliberately stops here: nothing in the happy path spawns `f`. Packed
  // `file:` entries and `::field` provider names are resolved only when they
  // were named explicitly (see resolveNamed), never as background fallbacks.
  return fast;
}

/**
 * A name the caller asked for by hand (`--cred`, ssh.cred, or `ssh::password`).
 * These are allowed to cost a nested `f`, because the operator named them and
 * nothing else will answer them; the automatic ladder never pays that price.
 */
function resolveNamed(name) {
  if (name.startsWith("file:")) {
    const f = unpackRaw(name.slice("file:".length));
    if (f.value) return { pem: f.value, src: `creds:${name}` };
    return f.error ? { error: f.error, name } : { missing: true };
  }
  if (name.includes("::")) {
    const p = providerGet(name);
    if (p.value) {
      const pem = normalizePem(p.value);
      if (pem) return { pem, src: `vault:${name}` };
    }
    return p.error ? { error: p.error, name } : { missing: true };
  }
  return { missing: true };
}/** Stage 1: the box, with no subprocess at all. `file:` and `::field` names are
 *  left for stage 2 — the daemon serves neither. */
async function probeBox(credsApi, names) {
  const tried = [];
  let firstError = null;
  for (const name of names) {
    if (tried.includes(name)) continue;
    if (name.startsWith("file:") || name.includes("::")) {
      const r = resolveNamed(name);
      tried.push(name);
      if (r.pem) return { pem: r.pem, src: r.src, tried };
      if (r.error && !firstError) firstError = { name, error: r.error };
      continue;
    }
    const r = await readCred(name, credsApi);
    tried.push(name);
    if (r.locked) return { locked: true, tried };
    if (r.value) {
      const pem = normalizePem(r.value);
      if (!pem) {
        if (!firstError) firstError = { name, error: "value is empty after normalizing" };
        continue;
      }
      return { pem, src: `creds:${name}`, tried };
    }
    if (r.error && !firstError) firstError = { name, error: r.error };
  }
  if (firstError) return { error: firstError.error, name: firstError.name, tried };
  return { missing: true, tried };
}

/** `f creds files unpack <path> -` writes the stored bytes to stdout.
 *  Pass the bare path: the uck prepends `file:` itself, so `file:/x` would
 *  resolve as a relative path and be looked up as `file:file:/x`. */
function unpackRaw(target) {
  const bin = process.env.FCLI_BIN || process.env.F_BIN || "f";
  const env = { ...process.env, F_CREDS_NO_PROVIDER: process.env.F_CREDS_NO_PROVIDER || "1" };
  let out;
  try {
    out = execFileSync(bin, ["creds", "files", "unpack", target, "-"], {
      encoding: "utf8",
      env,
      stdio: ["ignore", "pipe", "pipe"],
      maxBuffer: 4 * 1024 * 1024,
    });
  } catch (e) {
    const msg = (e?.stderr ?? e?.message ?? "").toString().trim().split("\n").filter((l) => l && !/wrote .* bytes .* to stdout/.test(l))[0] || "unpack failed";
    return { value: null, error: msg };
  }
  const pem = out.replace(/\r\n/g, "\n").trim();
  if (!pem) return { value: null, error: `packed entry '${target}' is empty` };
  // unpack prints a warning line on stderr, not stdout, but keep only the key
  // block in case a payload ever arrives with decoration around it.
  return { value: normalizePem(pem) };
}

function looksLikePrivateKey(pem) {
  if (typeof pem !== "string" || !pem.trim()) return false;
  if (/-----(BEGIN|ORIGINAL) /.test(pem)) return true;
  // OpenSSH's own single-line format has no BEGIN marker.
  return /^ssh-privatekey\b/.test(pem.trim());
}

function isEncryptedPem(pem) {
  return /Proc-Type:[^\n]*ENCRYPTED/.test(pem) || /-----BEGIN ENCRYPTED PRIVATE KEY-----/.test(pem);
}

// ------------------------------------------------------------------ helpers

function sshBin(name) {
  return process.env[`F_SSH_${name.toUpperCase()}`] || name;
}

/** Run a command with argv passed verbatim (no shell). */
function run(cmd, argv, opts = {}) {
  const r = spawnSync(cmd, argv, {
    stdio: opts.capture ? ["ignore", "pipe", "pipe"] : "inherit",
    encoding: opts.capture ? "utf8" : undefined,
    env: opts.env ?? process.env,
    timeout: opts.timeout,
  });
  if (r.error) fail([`${cmd}: ${r.error.message}`]);
  return { status: r.status ?? 1, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

function withStdin(input, cmd, argv, opts = {}) {
  const r = spawnSync(cmd, argv, {
    input,
    encoding: "utf8",
    stdio: ["pipe", "pipe", "pipe"],
    env: opts.env ?? process.env,
    timeout: opts.timeout,
  });
  if (r.error) fail([`${cmd}: ${r.error.message}`]);
  return { status: r.status ?? 1, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

// -------------------------------------------------------------------- agent

function socketPath() {
  return process.env.F_SSH_AGENT_SOCKET || path.join(SSHD, "agent.sock");
}

function agentAlive(sock) {
  if (!sock || !fs.existsSync(sock)) return false;
  const r = spawnSync(sshBin("ssh-add"), ["-l"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, SSH_AUTH_SOCK: sock },
    timeout: 10_000,
  });
  return !r.error && (r.status === 0 || r.status === 1);
}

/** Start a detached long-lived agent; returns its socket path. */
function startAgent(sock) {
  fs.mkdirSync(SSHD, { recursive: true, mode: 0o700 });
  try { fs.unlinkSync(sock); } catch {}
  // 0600: uplink ssh-agent -D prints "Agent pid N" on stdout, so the file
  // carries data; umask would otherwise make it world-readable.
  const log = fs.openSync(path.join(SSHD, "agent.log"), "a", 0o600);
  let child;
  try {
    // detached + unref: the agent must outlive this process. spawnSync would
    // sit in the read loop until its timeout and then kill the agent with it.
    child = spawn("setsid", ["nohup", sshBin("ssh-agent"), "-D", "-a", sock], {
      stdio: ["ignore", log, log],
      env: process.env,
      detached: true,
    });
  } catch (e) {
    fail([`cannot start ssh-agent: ${e.message}`]);
  }
  child.on("error", (e) => err(`f ssh: ssh-agent exited: ${e.message}`));
  child.unref();
  try { fs.closeSync(log); } catch {}
  const until = Date.now() + 5_000;
  while (Date.now() < until) {
    if (agentAlive(sock)) return sock;
    spawnSync("sleep", ["0.05"]);
  }
  fail([
    "started ssh-agent but it did not come up",
    `  see ${path.join(SSHD, "agent.log")}`,
  ]);
}

function ensureAgent() {
  const running = process.env.SSH_AUTH_SOCK && agentAlive(process.env.SSH_AUTH_SOCK)
    ? process.env.SSH_AUTH_SOCK
    : agentAlive(socketPath()) ? socketPath() : null;
  return running || startAgent(socketPath());
}

function agentIdentities(sock) {
  const r = spawnSync(sshBin("ssh-add"), ["-l"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, SSH_AUTH_SOCK: sock },
    timeout: 10_000,
  });
  if (r.status !== 0) return [];
  return r.stdout.trim().split("\n").filter(Boolean);
}

function loadIntoAgent(pem, src, sock) {
  const r = withStdin(pem, sshBin("ssh-add"), ["-"], { env: { ...process.env, SSH_AUTH_SOCK: sock } });
  if (r.status === 0) return { ok: true, note: (r.stdout || "").trim() };
  const msg = (r.stderr || r.stdout || "").trim().split("\n")[0];
  if (/passphrase|pass phrase/i.test(msg)) {
    return {
      ok: false,
      reason: "encrypted",
      note: "the key has a passphrase; ssh-add cannot prompt on stdin",
    };
  }
  return { ok: false, note: msg || "ssh-add rejected the key" };
}

// ------------------------------------------------------- per-command keyfile

function tmpKeyfile(pem, src) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "f-ssh-"));
  fs.chmodSync(dir, 0o700);
  const file = path.join(dir, "id");
  fs.writeFileSync(file, normalizePem(pem), { mode: 0o600 });
  const cleanup = () => {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
  };
  process.on("exit", cleanup);
  return { file, cleanup, src };
}

/**
 * Prove the identity is usable before handing it to the real command.
 * Two checks, both fatal-on-failure (a plain ssh would only warn):
 *   ssh -G                     the path parses as an identity file
 *   agent-less ssh to 127.0.0.1  the key is loaded and offered, with no other
 *                              identities in play
 */
function assertIdentityUsable(file, cfg) {
  const g = run(sshBin("ssh"), ["-G", "-F", cfg, "f-ssh-probe.invalid"], { capture: true, timeout: 15_000 });
  if (!/identityfile/.test(g.stdout)) {
    fail([`ssh could not read the identity file`, `  ${g.stderr.trim().split("\n")[0] || "no identityfile in ssh -G output"}`]);
  }
  const p = run(
    sshBin("ssh"),
    [
      "-F", cfg,
      "-o", "IdentityAgent=none",
      "-o", "ConnectTimeout=3",
      "-o", "StrictHostKeyChecking=no",
      "-o", "NumberOfPasswordPrompts=0",
      "127.0.0.1", "true",
    ],
    { capture: true, timeout: 20_000 },
  );
  const out = (p.stderr || "").trim();
  if (/Permission denied \(publickey\)/.test(out)) {
    // With IdentityAgent=none and IdentitiesOnly the only key in play is ours,
    // so a publickey rejection on loopback means the key itself is broken or
    // the file was not loaded. (A listening sshd that rejects it is fine — that
    // means the key *was* offered, which is what we asked.)
    if (!/no matching key|no supported authentication/i.test(out)) {
      fail([
        "the key was loaded but ssh could not present it",
        `  ${out.split("\n")[0]}`,
      ]);
    }
  }
  if (/no such identity|not accessible|invalid format|error in libcrypto|bad passphrase/i.test(out)) {
    fail([`the key from ${"creds"} is not usable`, `  ${out.split("\n")[0]}`]);
  }
}

function identityArgs(file) {
  return ["-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-i", file];
}

/**
 * Per-tool identity injection for the temp-keyfile path.
 *
 * `-o IdentitiesOnly=yes` MUST be delivered through `-F <config>`, not as a
 * command-line `-o`: scp does not forward general ssh options to ssh (it forwards
 * -i, -P, -l, -v …), so `scp -o IdentitiesOnly=yes` dies with
 * `command-line line 0: keyword identitiesonly not supported above` — before the
 * config is even read, which means the whole IdentityFile gets dropped too and
 * scp falls back to the default keys. That failure is silent unless you look at
 * the status code, and the copy looks like it "sort of" ran.
 *
 * So: every ssh-facing option goes in a generated config file, and each tool gets
 * the form it forwards. `-F` overrides the user's own config, so the block is
 * included rather than replacing it.
 *
 * scp's remote-spec syntax (`host:path`) also means a leading `-i file` can be
 * parsed as a second source; putting -i behind -F avoids that reading entirely.
 *
 * `-e` for rsync: OpenSSH 10.6 concatenates repeated -e values into one program
 * string instead of letting the last win, so only -e's *value* is stripped (a
 * caller who set -e deliberately gets their transport with our identity appended).
 * The file is quoted — rsync hands this string to a shell.
 */
function sshConfigText(file) {
  const lines = [];
  if (fs.existsSync(CONFIG_PATH)) lines.push(`Include ${CONFIG_PATH}`);
  lines.push(`IdentityFile ${file}`);
  lines.push("IdentitiesOnly yes");
  lines.push("BatchMode yes");
  return lines.join("\n") + "\n";
}

/** Write the throwaway config next to the key (same 0700 temp dir). */
function tmpConfig(file) {
  const dir = path.dirname(file);
  const cfg = path.join(dir, "config");
  fs.writeFileSync(cfg, sshConfigText(file), { mode: 0o600 });
  return cfg;
}

function injectFor(tool, file, cfg, argv) {
  if (tool === "rsync") {
    const out = [];
    for (let i = 0; i < argv.length; i++) {
      const a = argv[i];
      if (a === "-e") {
        i++;
        continue;
      }
      if (/^-e[^-]/.test(a)) continue;
      const bundled = /^-[a-zA-Z]*e[a-zA-Z]*$/.exec(a);
      if (bundled && bundled[0].length > 2) {
        const rest = bundled[0];
        const shrunk = `-${rest.slice(1, rest.indexOf("e"))}${rest.slice(rest.indexOf("e") + 1)}`;
        out.push(shrunk === "-" ? null : shrunk);
        i++;
        continue;
      }
      out.push(a);
    }
    const quoted = file.includes("'") ? JSON.stringify(file) : `'${file}'`;
    const quotedCfg = cfg.includes("'") ? JSON.stringify(cfg) : `'${cfg}'`;
    return ["-e", `ssh -F ${quotedCfg} -o IdentitiesOnly=yes -o BatchMode=yes -i ${quoted}`, ...out.filter(Boolean)];
  }
  if (tool === "scp") return ["-F", cfg, "-i", file, ...argv];
  return ["-F", cfg, "-i", file, ...argv];
}

// ------------------------------------------------------------- ssh config

function configBlock() {
  return (
    `# ${MARK}\n` +
    `# IdentityFile kept by 'f ssh setup'; the private key lives in the f creds\n` +
    `# store, this file is materialised from it. Remove with 'f ssh teardown'.\n` +
    `IdentityFile ${KEYFILE}\n` +
    `# ${MARK}\n`
  );
}

function configHasBlock(text) {
  return text.includes(`# ${MARK}`);
}

function installConfigBlock() {
  fs.mkdirSync(path.dirname(CONFIG_PATH), { recursive: true, mode: 0o700 });
  const cur = fs.existsSync(CONFIG_PATH) ? fs.readFileSync(CONFIG_PATH, "utf8") : "";
  if (configHasBlock(cur)) return { changed: false, path: CONFIG_PATH };
  fs.writeFileSync(CONFIG_PATH, (cur ? cur.replace(/\n?$/, "\n\n") : "") + configBlock(), { mode: 0o600 });
  return { changed: true, path: CONFIG_PATH };
}

function removeConfigBlock() {
  if (!fs.existsSync(CONFIG_PATH)) return { changed: false, path: CONFIG_PATH };
  const cur = fs.readFileSync(CONFIG_PATH, "utf8");
  // Delete every line from the first marker through the IdentityFile we own,
  // plus the closing marker. Anything the user wrote between markers is left
  // alone only insofar as it is not our IdentityFile line.
  const lines = cur.split("\n");
  const out = [];
  let inBlock = false;
  let removed = 0;
  for (const line of lines) {
    if (!inBlock) {
      if (line.includes(MARK)) {
        inBlock = true;
        removed++;
        continue;
      }
      out.push(line);
      continue;
    }
    removed++;
    if (line.trim() === `IdentityFile ${KEYFILE}` || line.includes(MARK)) {
      inBlock = false;
    }
  }
  if (!removed) return { changed: false, path: CONFIG_PATH };
  fs.writeFileSync(CONFIG_PATH, out.join("\n").replace(/\n{3,}\n$/, "\n"), { mode: 0o600 });
  return { changed: true, path: CONFIG_PATH };
}

function writeKeyfile(pem) {
  fs.mkdirSync(SSHD, { recursive: true, mode: 0o700 });
  const tmp = `${KEYFILE}.tmp.${process.pid}`;
  fs.writeFileSync(tmp, normalizePem(pem), { mode: 0o600 });
  // writeFileSync only applies `mode` when it *creates* a file; a re-run over an
  // existing keyfile would keep whatever mode it already had.
  fs.chmodSync(tmp, 0o600);
  fs.renameSync(tmp, KEYFILE);
  return KEYFILE;
}

// ------------------------------------------------------------------ usage

function usage() {
  err(
    "usage: f ssh <cmd> [args]\n" +
      "  status                         agent, key source, identities\n" +
      "  setup                          write IdentityFile into ~/.ssh/config\n" +
      "  teardown                       remove that include\n" +
      "  env                            eval \"$(f ssh env)\" -> SSH_AUTH_SOCK\n" +
      "  agent <cmd...>                 run cmd with SSH_AUTH_SOCK set\n" +
      "  load [dest]                    load the key into the long-lived agent\n" +
      "  list                           ssh-add -l\n" +
      "  add                            print the PEM (needs F_SSH_SHOW_SECRET=1)\n" +
      "  <host> [args...]               ssh with the key injected\n" +
      "  scp|rsync|sftp <args...>       same, for those tools\n" +
      "\n" +
      "  --cred <name>                  explicit cred/item name (a pin, not a filter)\n" +
      "  --no-agent                     never touch ssh-agent\n" +
      "\n" +
      "The command's own flags go after -- :  f ssh host -- -v uptime\n" +
      "Exit status is the command's, not f's (f itself ignores uck return values).\n" +
      "\n" +
      "creds (first hit wins; or --cred / f config set ssh.cred <name>):\n" +
      "  ssh.key.<host>, " + `file:${KEYFILE}` + ", ssh.key, " + DEFAULT_CRED + ", id_ed25519"
  );
  exitWith(2);
}

// --------------------------------------------------------------- commands

async function cmdStatus(credsApi, opts) {
  const sock = process.env.SSH_AUTH_SOCK && agentAlive(process.env.SSH_AUTH_SOCK)
    ? process.env.SSH_AUTH_SOCK
    : agentAlive(socketPath()) ? socketPath() : null;
  const names = credCandidates("", opts.cred);
  const key = await findKey(credsApi, names);
  const locked = !credsUnlocked();
  console.log(`creds\t${locked ? "locked" : "unlocked"}`);
  console.log(`key\t${key.pem ? key.src : key.locked ? "unknown (creds locked)" : key.error ? `error: ${key.error}` : "not found"}`);
  if (key.pem) {
    console.log(`key.type\t${isEncryptedPem(key.pem) ? "passphrase-protected" : "unencrypted"}`);
    console.log(`keyfile\t${fs.existsSync(KEYFILE) ? KEYFILE : "not set up (f ssh setup)"}`);
  }
  const cfg = fs.existsSync(CONFIG_PATH) ? fs.readFileSync(CONFIG_PATH, "utf8") : "";
  console.log(`ssh-config\t${configHasBlock(cfg) ? `includes ${KEYFILE}` : `no include (${CONFIG_PATH}${cfg ? "" : " missing"})`}`);
  console.log(`agent\t${sock ? sock : "not running"}`);
  for (const id of sock ? agentIdentities(sock) : []) console.log(`identity\t${id}`);
  return 0;
}

async function cmdSetup(credsApi, opts) {
  const key = await findKey(credsApi, credCandidates("", opts.cred));
  if (key.locked) fail(["creds are locked", "  fix: f creds unlock"]);
  if (key.error) fail([`could not read '${key.name}': ${key.error}`]);
  if (!key.pem) fail([
    "no key found",
    `  store one: f creds set ${DEFAULT_CRED} "$(cat ~/.ssh/id_ed25519)"`,
    `  or pack it: f creds files pack ~/.ssh/id_ed25519`,
  ]);
  if (!looksLikePrivateKey(key.pem)) fail([`'${key.src}' does not look like a private key — refusing to write it`]);
  writeKeyfile(key.pem);
  const r = installConfigBlock();
  console.log(`keyfile\t${KEYFILE} (from ${key.src})`);
  console.log(`ssh-config\t${r.changed ? `added include` : `already included`} in ${r.path}`);
  if (isEncryptedPem(key.pem) && !opts.noAgent) {
    err(`f ssh: note — the key has a passphrase. ssh will prompt for it; to avoid that, load it once with 'f ssh load'.`);
  }
  return 0;
}

function cmdTeardown() {
  const r = removeConfigBlock();
  console.log(`ssh-config\t${r.changed ? "removed include from" : "no include in"} ${r.path}`);
  console.log(`keyfile\t${fs.existsSync(KEYFILE) ? KEYFILE + " left in place (rm it yourself if you want it gone)" : "absent"}`);
  return 0;
}

function cmdEnv() {
  const sock = ensureAgent();
  process.stdout.write(`export SSH_AUTH_SOCK='${sock}'\n`);
  return 0;
}

async function cmdAgent(rest) {
  if (!rest.length) fail(["agent needs a command", "  e.g. f ssh agent git pull"]);
  const sock = ensureAgent();
  const r = spawnSync(rest[0], rest.slice(1), { stdio: "inherit", env: { ...process.env, SSH_AUTH_SOCK: sock } });
  if (r.error) fail([`${rest[0]}: ${r.error.message}`]);
  return r.status ?? 1;
}

async function cmdList() {
  const sock = process.env.SSH_AUTH_SOCK && agentAlive(process.env.SSH_AUTH_SOCK)
    ? process.env.SSH_AUTH_SOCK
    : agentAlive(socketPath()) ? socketPath() : null;
  if (!sock) {
    console.log("agent\tnot running");
    return 1;
  }
  const ids = agentIdentities(sock);
  if (!ids.length) {
    console.log(`agent\t${sock} (no identities — f ssh load)`);
    return 1;
  }
  for (const id of ids) console.log(`identity\t${id}`);
  return 0;
}

async function cmdLoad(dest, credsApi, opts) {
  const host = hostFromDest(dest);
  const key = await findKey(credsApi, credCandidates(host, opts.cred));
  if (key.locked) fail(["creds are locked", "  fix: f creds unlock"]);
  if (key.error) fail([`could not read '${key.name}': ${key.error}`]);
  if (!key.pem) fail([
    "no key found",
    `  looked for: ${credCandidates(host, opts.cred).join(", ")}`,
    `  store one: f creds set ${DEFAULT_CRED} "$(cat ~/.ssh/id_ed25519)"`,
  ]);
  if (!looksLikePrivateKey(key.pem)) fail([`'${key.src}' does not look like a private key`]);
  const sock = opts.noAgent ? null : ensureAgent();
  const r = loadIntoAgent(key.pem, key.src, sock);
  if (!r.ok) {
    if (r.reason === "encrypted") {
      fail([
        r.note,
        "  this uck never prompts for a passphrase and never writes the key to disk",
        `  fix: keep the vault copy unencrypted (ssh-keygen -p -f ~/.ssh/id_ed25519 -P ''),`,
        `       or set it up once with 'f ssh setup' and run 'ssh-add ${KEYFILE}' interactively`,
      ]);
    }
    fail([`ssh-add rejected the key: ${r.note}`]);
  }
  console.log(`loaded\t${key.src}`);
  console.log(`agent\t${sock}`);
  return 0;
}

async function cmdAdd(credsApi, opts) {
  if (!process.env.F_SSH_SHOW_SECRET) {
    fail([
      "refusing to print a private key",
      "  the agent path never needs it: f ssh load",
      "  if you really mean it: F_SSH_SHOW_SECRET=1 f ssh add",
    ]);
  }
  const key = await findKey(credsApi, credCandidates("", opts.cred));
  if (key.locked) fail(["creds are locked", "  fix: f creds unlock"]);
  if (!key.pem) fail([`no key found (${key.error ?? "not set"})`]);
  process.stdout.write(key.pem);
  return 0;
}

/** Wrapper path: inject the identity into one of the ssh family tools. */
async function cmdRun(tool, argv, credsApi, opts) {
  if (!argv.length) usage();
  const dest = tool === "rsync" ? "" : argv.find((a) => !a.startsWith("-") && looksLikeHost(a)) ?? "";
  const host = tool === "rsync" ? "" : looksLikeHost(dest);
  const key = await findKey(credsApi, credCandidates(host, opts.cred));
  if (key.locked) fail(["creds are locked", "  fix: f creds unlock", "  or use the agent path: f ssh setup && f ssh load"]);
  if (key.error) fail([`could not read '${key.name}': ${key.error}`]);
  if (!key.pem) fail([
    "no key found",
    `  looked for: ${credCandidates(host, opts.cred).join(", ")}`,
    `  store one: f creds set ${DEFAULT_CRED} "$(cat ~/.ssh/id_ed25519)"`,
  ]);
  if (!looksLikePrivateKey(key.pem)) fail([`'${key.src}' does not look like a private key`]);

  // Agent path is strictly better when it works: no key on disk, and a shared
  // agent is what ssh multiplexing expects.
  if (!opts.noAgent && !isEncryptedPem(key.pem)) {
    const sock = ensureAgent();
    const loaded = loadIntoAgent(key.pem, key.src, sock);
    if (loaded.ok) {
      const bin = sshBin(tool);
      const r = spawnSync(bin, argv, { stdio: "inherit", env: { ...process.env, SSH_AUTH_SOCK: sock } });
      if (r.error) fail([`${bin}: ${r.error.message}`]);
      return r.status ?? 1;
    }
    // Only worth saying when the command then fails too: ssh's own error is the
    // interesting part, and a stray line above it reads like the cause.
    err(`f ssh: agent path unavailable (${loaded.note}); using a temporary identity file`);
  }

  const kf = tmpKeyfile(key.pem, key.src);
  const cfg = tmpConfig(kf.file);
  assertIdentityUsable(kf.file, cfg);
  const bin = sshBin(tool);
  const r = spawnSync(bin, injectFor(tool, kf.file, cfg, argv), { stdio: "inherit", env: process.env });
  if (r.error) {
    kf.cleanup();
    fail([`${bin}: ${r.error.message}`]);
  }
  kf.cleanup();
  return r.status ?? 1;
}

// -------------------------------------------------------------------- main

/**
 * f's harness is a bare passthrough — `uck.run(rest, { _: rest })`, no flag
 * parser — and a literal `--` arrives as its own token. So this uck owns arg
 * splitting: its own flags are read only before the command token, and anything
 * from the command on (plus whatever followed `--`) goes to ssh untouched.
 *
 * `--` only has to appear when the command itself needs flags that ssh would
 * otherwise have to share with us (`f ssh host -- -v uptime`); a bare `--` at
 * the front means "everything after this is the ssh command".
 */
function splitArgs(tokens) {
  const opts = { cred: null, noAgent: false };
  const dd = tokens.indexOf("--");
  const head = dd === -1 ? tokens : tokens.slice(0, dd);
  const tail = dd === -1 ? [] : tokens.slice(dd + 1);
  const help = head.some((a) => a === "-h" || a === "--help");
  const rest = [];
  for (let i = 0; i < head.length; i++) {
    const a = head[i];
    if (a === "--cred" || a === "--item") {
      opts.cred = head[++i];
      if (!opts.cred) fail([`${a} needs a cred name`]);
      continue;
    }
    if (a.startsWith("--cred=")) {
      opts.cred = a.slice("--cred=".length);
      if (!opts.cred) fail(["--cred= needs a cred name"]);
      continue;
    }
    if (a === "--no-agent") {
      opts.noAgent = true;
      continue;
    }
    rest.push(a);
  }
  // `f ssh -- host -v` (or `f ssh -- -- host`): the command starts after the
  // separator, so a leading dash there is ssh's flag, not a missing subcommand.
  if (dd === 0 && rest.length === 0 && tail.length) {
    return { rest: tail, tail: [], opts, help };
  }
  return { rest, tail, opts, help };
}

export function register(ctx) {
  const here = path.dirname(new URL(import.meta.url).pathname);
  return {
    name: "ssh",
    desc:
      "ssh/scp/rsync with a private key from the f creds store (default cred: ssh); keeps it in ssh-agent, never on disk",
    skills: [{ name: "f-ssh", path: path.join(here, "SKILL.md") }],
    run: async (_argv, args) => {
      const credsApi = ctx?.registry?.creds?.credsApi || null;
      const tokens = (args?._ ?? []).map(String);
      const { rest, tail, opts, help } = splitArgs(tokens);
      if (help || !rest.length) usage();

      const sub = rest[0];
      if (sub.startsWith("-") || sub.startsWith("+")) {
        fail([
          `'${sub}' is a flag for ssh/scp/rsync, not an f ssh command`,
          "  f ssh's own flags come first; put the command's after -- :",
          `    f ssh ${sub.split("=")[0]} … -- <host> [command]`,
          "  or set it up once and call ssh directly: f ssh setup",
        ]);
      }
      // The command's argv: everything after the subcommand, plus whatever came
      // after `--`.
      const cmdArgv = [...rest.slice(1), ...tail];
      const dispatch = async () => {
        switch (sub) {
          case "status":
            return cmdStatus(credsApi, opts);
          case "setup":
            return cmdSetup(credsApi, opts);
          case "teardown":
            return cmdTeardown();
          case "env":
            return cmdEnv();
          case "agent":
            return cmdAgent(cmdArgv);
          case "list":
            return cmdList();
          case "add":
            return cmdAdd(credsApi, opts);
          case "load":
            return cmdLoad(cmdArgv[0] ?? "", credsApi, opts);
        }
        // scp/rsync/sftp name their own tool, so their arguments begin right
        // after it: `f ssh scp a.h:x b.h:y` runs `scp a.h:x b.h:y`. For anything
        // else the token is an ssh destination and must stay in argv — dropping
        // it makes ssh resolve the *command* as the hostname.
        const tool = ["scp", "rsync", "sftp"].includes(sub) ? sub : "ssh";
        const argv = tool === "ssh" && sub !== "ssh" ? [sub, ...cmdArgv] : cmdArgv;
        if (!argv.length) fail([`${tool} needs arguments`, "  see: f ssh -h"]);
        return cmdRun(tool, argv, credsApi, opts);
      };
      // exitWith, not `return`: the harness drops uck return values (see above).
      const code = await dispatch();
      exitWith(code);
      return code;
    },
  };
}

export default { register };

