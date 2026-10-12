// f ssh — ssh hosts, config and authorized_keys, carried through the creds store.
//
// Follows the pi-models precedent: `f creds files` is the transport, and the key
// IS the destination (`file:~/<path>`), so one packed entry resolves on every host
// (/home/kenny is not /data/data/com.termux/files/home). This uck adds ssh-specific
// validation and migrations; it reimplements neither git nor the store.
//
// Zero deps: ssh, ssh-keygen, ssh-add and git are all invoked via spawnSync, never
// through a shell, so nothing here expands argv or interpolates a secret.
//
// Two distinct things get packed, and they are treated differently:
//
//   ~/.ssh/config        host aliases + identity files. Machine-INDEPENDENT, so it
//                        packs and restores cleanly. Private key MATERIAL never goes
//                        in it — only paths.
//   ~/.ssh/authorized_keys  the public keys allowed to log IN to this machine.
//
// Private keys are deliberately NOT packed by default. A private key is a bearer
// credential: packing it puts every host you can reach behind one store password, and
// the whole point of `f creds` is that the store is only as strong as its passkey.
// `keys pack` exists and is explicit (--i-know-what-im-doing) for people who want
// exactly that tradeoff; `keys` without the flag refuses and says why.
//
// Commands:
//   f ssh ls                    hosts from ~/.ssh/config (alias, hostName, user, port)
//   f ssh show <host>           the resolved config block for one host
//   f ssh check [host]          can I auth? (ssh -G parse, then BatchMode probe)
//   f ssh run <host> [cmd...]   ssh with the uck's defaults (BatchMode-safe, terse)
//   f ssh keys                  list local public keys + fingerprints
//   f ssh agents                ssh-agent state + what it holds
//   f ssh authorized ls         what is in ~/.ssh/authorized_keys
//   f ssh authorized add <pub>  append one public key (idempotent, no dupes)
//   f ssh authorized rm <match> remove by comment substring (refuses ambiguous)
//   f ssh pack [config|authorized]  push files into the creds store
//   f ssh unpack [config|authorized] restore them (.bak first, never clobber silently)
//   f ssh status                local vs packed: what differs, incl. legacy keys
//   f ssh keys pack --i-know-what-im-doing   opt-in private key packing
//
// Conventions kept from f fj / f pi-models: one fact per line, no boilerplate,
// errors name the fix, and nothing destructive runs without --force.

import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync, copyFileSync, chmodSync, statSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const F = path.join(process.env.HOME ?? homedir(), ".f");
const SSH_DIR = path.join(homedir(), ".ssh");
const CONFIG = path.join(SSH_DIR, "config");
const AUTH_KEYS = path.join(SSH_DIR, "authorized_keys");

// Packed as file:~/... so the same entry works on every host.
const REL = {
  config: ".ssh/config",
  "authorized-keys": ".ssh/authorized_keys",
};

const die = (msg, code = 1) => { console.error(msg); process.exit(code); };
const out = (...a) => console.log(...a);

// ── ssh invocation ───────────────────────────────────────────────────────────
// execFileSync with an argv array: no shell, so no expansion of anything a caller
// passed. Returns { code, out, err } rather than throwing, so callers can report.
function ssh(args, opts = {}) {
  const r = spawnSync("ssh", args, { encoding: "utf8", timeout: opts.timeout ?? 15000, ...opts });
  if (r.error) return { code: -1, out: "", err: r.error.code === "ENOENT" ? "ssh not on PATH" : r.error.message };
  return { code: r.status ?? -1, out: (r.stdout ?? "").trim(), err: (r.stderr ?? "").trim() };
}

function keygen(args) {
  const r = spawnSync("ssh-keygen", args, { encoding: "utf8", timeout: 10000 });
  if (r.error) return { code: -1, out: "", err: "ssh-keygen not on PATH" };
  return { code: r.status ?? -1, out: (r.stdout ?? "").trim(), err: (r.stderr ?? "").trim() };
}

/** Run `f creds …`. No shell, no argv expansion, secrets never in our argv. */
function creds(...args) {
  const r = spawnSync("f", ["creds", ...args], { encoding: "utf8" });
  if (r.error) die(`cannot run f creds: ${r.error.message}`);
  return { code: r.status ?? -1, out: (r.stdout ?? "").trim(), err: (r.stderr ?? "").trim() };
}

// `f creds status` exits 0 whether locked or unlocked; it only reports. A guard on
// its exit code can never fire, so test the text. (Bitten by this in pi-voice work.)
function needUnlocked() {
  const st = creds("status");
  if (!/unlocked/.test(st.out)) die("ssh: creds are locked — run 'f creds unlock' (passkey) first");
}

// ── ~/.ssh/config parsing ────────────────────────────────────────────────────
// Not a full ssh_config parser: enough to answer "what hosts do I have and how do
// I reach them". Wildcard blocks are kept but reported as patterns, since they match
// by suffix rather than naming a host.
function parseConfig(text) {
  const hosts = [];
  let cur = null;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const m = line.match(/^(Host|Match)\s+(.*)$/i);
    if (m) {
      cur = { keywords: {}, patterns: m[2].trim().split(/\s+/) };
      hosts.push(cur);
      continue;
    }
    if (!cur) continue;
    const kv = line.match(/^([A-Za-z]+)\s+(.*)$/);
    if (kv) cur.keywords[kv[1].toLowerCase()] = kv[2].trim();
  }
  return hosts;
}

const readOr = (p) => (existsSync(p) ? readFileSync(p, "utf8") : "");

function hostEntries() {
  const text = readOr(CONFIG);
  if (!text) return [];
  return parseConfig(text);
}

// ── commands ─────────────────────────────────────────────────────────────────
function cmdLs(args) {
  const entries = hostEntries();
  if (!entries.length) { out(`no hosts (${CONFIG} missing or empty)`); return; }
  for (const h of entries) {
    const k = h.keywords;
    const bits = [
      h.patterns.join(","),
      k.hostname ? `host=${k.hostname}` : null,
      k.user ? `user=${k.user}` : null,
      k.port && k.port !== "22" ? `port=${k.port}` : null,
      k.identityfile ? `id=${path.basename(k.identityfile.split(/\s/)[0])}` : null,
      k.proxyjump ? `via=${k.proxyjump}` : null,
      k.proxycommand ? `proxy=cmd` : null,
    ].filter(Boolean);
    out(bits.join("\t"));
  }
}

function cmdShow(host) {
  if (!host) die("usage: f ssh show <host>");
  const entry = hostEntries().find((h) => h.patterns.includes(host));
  if (!entry) die(`ssh: no Host block for '${host}' in ${CONFIG}`);
  out(`Host ${entry.patterns.join(" ")}`);
  for (const [k, v] of Object.entries(entry.keywords)) out(`  ${k} ${v}`);
  // -G gives the effective config after includes, matches and defaults — the single
  // most useful thing here, and it never connects.
  const g = ssh(["-G", host]);
  if (g.code === 0 && g.out) {
    const want = ["hostname", "user", "port", "identityfile", "proxyjump", "proxycommand", "identitiesonly", "preferredauthentications"];
    const eff = g.out.split(/\r?\n/).filter((l) => want.includes(l.split(/\s/)[0].toLowerCase()));
    if (eff.length) { out("effective:"); for (const l of eff) out(`  ${l}`); }
  } else if (g.err) {
    out(`  (ssh -G failed: ${g.err.split(/\r?\n/)[0]})`);
  }
}

// Auth probe. Deliberately strict: BatchMode=yes plus these *Sessions options mean
// ssh can NEVER stop for a password, passphrase or host-key prompt. The classic
// failure of scripted ssh is a silent hang on a prompt; without these, `f ssh check`
// would hang for the whole timeout instead of reporting "needs a password".
function cmdCheck(target, argv) {
  const dest = target || process.argv[3];
  if (!dest) die("usage: f ssh check [host]");
  const g = ssh(["-G", dest]);
  if (g.code !== 0) die(`ssh: cannot resolve '${dest}': ${g.err.split(/\r?\n/)[0] || "unknown host pattern"}`);
  const eff = Object.fromEntries(
    g.out.split(/\r?\n/).map((l) => l.split(/\s+/)).filter((a) => a.length > 1).map((a) => [a[0].toLowerCase(), a.slice(1).join(" ")]),
  );
  out(`target\t${eff.user || "?"}@${eff.hostname || "?"}:${eff.port || "22"}`);
  const idf = (eff.identityfile || "").split(/\s/).filter(Boolean);
  if (idf.length) for (const p of idf) out(`identity\t${p}${existsSync(p.startsWith("~") ? path.join(homedir(), p.slice(2)) : p) ? "" : "\tMISSING"}`);
  else out("identity\t(none configured; agent + default paths only)");

  if (argv.includes("--connect")) {
    const probe = ssh([
      dest, "-o", "BatchMode=yes", "-o", "PreferredAuthentications=publickey",
      "-o", "PubkeyAuthentication=yes", "-o", "PasswordAuthentication=no",
      "-o", "KbdInteractiveAuthentication=no", "-o", "ChallengeResponseAuthentication=no",
      "-o", "NumberOfPasswordPrompts=0", "-o", "StrictHostKeyChecking=accept-new",
      "-o", `ConnectTimeout=${process.env.SSH_CONNECT_TIMEOUT || 8}`,
      "true",
    ], { timeout: 20000 });
    if (probe.code === 0) out("auth\tOK (publickey accepted)");
    else {
      const why = probe.err || `exit ${probe.code}`;
      const hint = /Permission denied/.test(why)
        ? " — key rejected, or wrong user/key: compare 'f ssh keys' against that host's authorized_keys"
        : /timed out|Connection refused|No route/i.test(why) ? " — host unreachable, check 'f ssh show' + network"
        : /Host key verification/i.test(why) ? " — host key changed or unknown" : "";
      out(`auth\tFAIL: ${why.split(/\r?\n/)[0]}${hint}`);
      process.exitCode = 1;
    }
  } else {
    out("auth\tnot probed (add --connect)");
  }
}

function cmdRun(rest) {
  const [dest, ...cmd] = rest;
  if (!dest) die("usage: f ssh run <host> [cmd...]");
  const full = [
    dest, "-o", "BatchMode=yes", "-o", "PreferredAuthentications=publickey",
    "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
    "-o", "NumberOfPasswordPrompts=0", "-o", "StrictHostKeyChecking=accept-new",
    ...(cmd.length ? [cmd.join(" ")] : []),
  ];
  const r = ssh(full, { timeout: 0, stdio: "inherit" });
  if (r.error) die(`ssh: ${r.err}`);
  process.exit(r.code);
}

function cmdKeys() {
  if (!existsSync(SSH_DIR)) { out(`no ${SSH_DIR}`); return; }
  const names = ["id_ed25519", "id_rsa", "id_ecdsa", "id_dsa"];
  const files = new Set();
  for (const f of names) { const p = path.join(SSH_DIR, f + ".pub"); if (existsSync(p)) files.add(p); }
  try {
    for (const f of execFileSync("find", [SSH_DIR, "-maxdepth", "1", "-name", "*.pub"], { encoding: "utf8", timeout: 5000 }).split(/\r?\n/))
      if (f.trim()) files.add(f.trim());
  } catch { /* find missing; the known-names pass above still worked */ }

  const list = [...files].sort();
  if (!list.length) { out(`no public keys in ${SSH_DIR}`); return; }
  for (const p of list) {
    const fp = keygen(["-l", "-f", p]);
    // -l on a .pub prints "256 SHA256:... comment (ED25519)"; parse loosely.
    const m = fp.out.match(/(\d+)\s+(SHA\S+:\S+)\s*(\S*)\s*\((\S+)\)/);
    out(`${path.basename(p)}\t${m ? `${m[4]} ${m[2]}` : (fp.err || "?")}${m && m[3] ? `\t${m[3]}` : ""}`);
  }
  // Private keys that have no .pub sibling are usually leftovers or wrong perms;
  // worth surfacing rather than hiding.
  for (const f of names) {
    const priv = path.join(SSH_DIR, f);
    if (existsSync(priv) && !existsSync(priv + ".pub")) out(`${f}\tNO PUBLIC COUNTERPART — regenerate with: ssh-keygen -y -f ${f}`);
  }
}

function cmdAgents() {
  const sock = process.env.SSH_AUTH_SOCK;
  if (!sock) { out("SSH_AUTH_SOCK unset — no agent"); return; }
  out(`socket\t${sock}${existsSync(sock) ? "" : "\tMISSING (stale)"}`);
  const l = spawnSync("ssh-add", ["-l"], { encoding: "utf8", timeout: 5000 });
  if (l.error) { out("ssh-add\tnot on PATH"); return; }
  if (/Could not open|error connecting/i.test(l.stderr || "")) { out(`agent\tunreachable: ${(l.stderr || "").split(/\r?\n/)[0]}`); return; }
  const lines = (l.stdout || "").trim().split(/\r?\n/).filter(Boolean);
  if (!lines.length) { out("agent\trunning, holds no keys"); return; }
  out(`agent\tholds ${lines.length} key(s)`);
  for (const line of lines) out(`  ${line.trim()}`);
}

// ── authorized_keys ─────────────────────────────────────────────────────────
// One public key per line. Deduping by the base64 material (not the comment), since
// the same key re-added with a different comment is still the same key.
//
// Two spellings of the type are valid and both must be accepted:
//   authorized_keys          ssh-ed25519 AAAAC3Nza… user@host
//   id_*.pub (wire format)   ssh-ed25519@nist.com AAAAC3Nza… user@host
// The @nist.com suffix belongs to the wire format inside the blob; ssh-keygen writes
// the BARE form to authorized_keys. Requiring the suffix rejects every legitimate
// key, so normalise it away and compare on the base64 body.
const KEY_TYPES = [
  "ssh-ed25519", "ssh-rsa", "ssh-dss",
  "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
  "sk-ssh-ed25519", "sk-ecdsa-sha2-nistp256",
];
const bareType = (t) => t.replace(/@nist\.com$/, "");

/**
 * Split a key line into parts, skipping any leading ssh-keygen options
 * (from="...",command="...",restrict,…). Options can contain spaces and quotes, so
 * scan forward for the first token that is a known key type rather than splitting
 * positionally.
 */
function parsePubkey(line) {
  const raw = line.trim();
  if (!raw) return null;
  const toks = raw.split(/\s+/);
  for (let i = 0; i < toks.length; i += 1) {
    if (KEY_TYPES.includes(bareType(toks[i]))) {
      return { options: toks.slice(0, i).join(" "), type: bareType(toks[i]), body: toks[i + 1] ?? "", comment: toks.slice(i + 2).join(" ") };
    }
  }
  return null;
}

function keyMaterial(line) {
  const p = parsePubkey(line);
  return p ? `${p.type} ${p.body}` : line.trim().split(/\s+/).slice(0, 2).join(" ");
}

function cmdAuthorized(sub, rest) {
  if (!existsSync(AUTH_KEYS) && sub !== "add") { out(`no ${AUTH_KEYS} (nothing is authorized to log in here)`); return; }
  const lines = readOr(AUTH_KEYS).split(/\r?\n/);
  const keys = lines.filter((l) => l.trim() && !l.trim().startsWith("#"));

  if (!sub || sub === "ls") {
    if (!keys.length) { out("(empty)"); return; }
    keys.forEach((k, i) => {
      out(`line\t${i + 1}\t${k.trim().slice(0, 44)}…\t${parsePubkey(k)?.comment || "(no comment)"}`);
    });
    // Duplicate material is a real footgun: removing one leaves the other working.
    const seen = new Map();
    for (const k of keys) { const m = keyMaterial(k); seen.set(m, (seen.get(m) || 0) + 1); }
    for (const [m, n] of seen) if (n > 1) out(`DUPLICATE key material x${n}: ${m.slice(0, 30)}… — removing one will not revoke it`);
    return;
  }

  if (sub === "add") {
    const pub = rest.join(" ").trim();
    if (!pub) die("usage: f ssh authorized add '<pubkey line>'   (or: f ssh authorized add @id_ed25519.pub)");
    let entries = pub.startsWith("@") ? readOr(path.join(SSH_DIR, pub.slice(1))).split(/\r?\n/) : [pub];
    const add = entries.map((e) => e.trim()).filter((e) => e && !e.startsWith("#"));
    if (!add.length) die(`ssh: nothing to add from '${pub}'`);
    for (const a of add) validatePubkey(a);
    const have = new Set(keys.map(keyMaterial));
    const fresh = add.filter((a) => !have.has(keyMaterial(a)));
    if (!fresh.length) { out("already present — nothing added"); return; }
    const before = readOr(AUTH_KEYS);
    backup(AUTH_KEYS);
    const next = (before ? (before.endsWith("\n") ? before : before + "\n") : "") + fresh.join("\n") + "\n";
    writeFileSync(AUTH_KEYS, next, { mode: 0o600 });
    chmodSync(AUTH_KEYS, 0o600);
    for (const a of fresh) out(`added\t${parsePubkey(a)?.comment || a.slice(0, 24)}`);
    return;
  }

  if (sub === "rm") {
    const needle = rest.filter((a) => !a.startsWith("--")).join(" ").trim();
    if (!needle) die("usage: f ssh authorized rm <comment>   (exact match; --substr for substring)");
    // Match the COMMENT only, exactly, unless --substr. An earlier version also
    // tested the whole line, which meant `rm ed25519` matched every ed25519 key --
    // a loose substring over key material is how you revoke the wrong key.
    const substr = rest.includes("--substr");
    const force = rest.includes("--force");
    const commentOf = (k) => parsePubkey(k)?.comment ?? "";
    const hit = (k) => { const c = commentOf(k); return substr ? c.includes(needle) : c === needle; };
    const hits = keys.filter(hit);
    if (!hits.length) die(`ssh: no authorized key has comment ${substr ? "containing" : "exactly"} '${needle}' (try 'f ssh authorized ls')`);
    // Ambiguity is destructive: silently removing several keys because a substring
    // was loose is exactly the mistake this uck exists to prevent.
    if (hits.length > 1 && !force)
      die(`ssh: '${needle}' matches ${hits.length} keys — narrow it, or pass --force to remove all:\n` +
        hits.map((h) => `  ${commentOf(h) || h.slice(0, 40)}`).join("\n"));
    // This guard is NOT overridable. --force means "I meant all of these matches",
    // not "lock me out of my own machine", and conflating the two is how a
    // one-way mistake happens. Remove the last key deliberately by editing the file.
    const drop = new Set(hits.map((h) => h.trim()));
    const kept = lines.filter((l) => !drop.has(l.trim()));
    if (!kept.some((l) => l.trim() && !l.trim().startsWith("#")))
      die(`ssh: refusing to remove ${hits.length} key(s) — that is every authorized key on this machine,\n  and you would lock yourself out. Edit ${AUTH_KEYS} by hand if that is really intended.`);
    backup(AUTH_KEYS);
    // Normalise to exactly one trailing newline and no blank lines. The naive
    // `kept.join("\n") + "\n"" expression left a stray blank line behind once a
    // line was removed, because `lines` already contains the empty strings between
    // newlines and the final "" after the last one.
    const body = kept.map((l) => l.trimEnd()).join("\n").replace(/\n{2,}$/, "\n").replace(/\s+$/, "");
    writeFileSync(AUTH_KEYS, body ? body + "\n" : "", { mode: 0o600 });
    chmodSync(AUTH_KEYS, 0o600);
    for (const h of hits) out(`removed\t${commentOf(h) || h.slice(0, 24)}`);
    out(`backup\t${AUTH_KEYS}.bak`);
    return;
  }

  die(`unknown authorized subcommand: ${sub} (ls|add|rm)`);
}

function validatePubkey(line) {
  const p = parsePubkey(line);
  if (!p || !p.body)
    die(`ssh: not a public key line: ${line.trim().slice(0, 48)}…\n  expected '<type> <base64> [comment]', e.g. ssh-ed25519 AAAAC3Nza… user@host`);
  // Standard alphabet with canonical padding only. Buffer.from does NOT throw on bad
  // base64 -- it stops silently -- so a truncated key would otherwise pass here and
  // fail at login.
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(p.body))
    die(`ssh: public key body is not canonical base64: ${p.body.slice(0, 24)}…`);
  const decoded = Buffer.from(p.body, "base64");
  if (decoded.toString("base64").replace(/=+$/, "") !== p.body.replace(/=+$/, ""))
    die("ssh: public key body does not round-trip as base64 (truncated or corrupt)");
  // ed25519's wire blob is 51 bytes (4+19+4+32); shorter cannot be a real key.
  if (decoded.length < 40) die(`ssh: public key body decodes to only ${decoded.length} bytes -- too short to be a real key`);
}

function backup(p) {
  if (!existsSync(p)) return;
  const bak = p + ".bak";
  copyFileSync(p, bak);
  try { chmodSync(bak, 0o600); } catch { /* best effort */ }
}

// ── packing ─────────────────────────────────────────────────────────────────
const PACKABLE = Object.keys(REL);

function cmdPack(what) {
  needUnlocked();
  const targets = what ? [what] : PACKABLE;
  for (const t of targets) {
    if (!PACKABLE.includes(t)) die(`ssh: nothing to pack named '${t}' (have: ${PACKABLE.join(", ")})`);
    const p = path.join(homedir(), REL[t]);
    if (!existsSync(p)) { out(`skip\t${t}\t(no ${REL[t]})`); continue; }
    // An empty authorized_keys is not a state worth restoring — it is the absence of
    // one, and packing it would overwrite a populated file on another host with
    // nothing. Same for an empty config.
    if (statSync(p).size === 0) { out(`skip\t${t}\t(empty ${REL[t]}; refusing to pack a blank file over another host's)`); continue; }
    const r = creds("files", "pack", p);
    if (r.code !== 0) die(`ssh: pack failed for ${t}: ${r.err || r.out}`);
    out(`packed\t${t}\t${statSync(p).size}B`);
  }
}

function cmdUnpack(what, argv) {
  needUnlocked();
  const targets = what ? [what] : PACKABLE;
  for (const t of targets) {
    if (!PACKABLE.includes(t)) die(`ssh: nothing to unpack named '${t}' (have: ${PACKABLE.join(", ")})`);
    const rel = REL[t];
    // Refuse to clobber an existing file unless --force; even then the store's
    // unpack writes a .bak. authorized_keys is a login-control file: getting it
    // wrong locks you out, so silent overwrite is never acceptable.
    const force = argv.includes("--force") ? ["--force"] : [];
    const r = creds("files", "unpack", "~/" + rel, ...force);
    if (r.code !== 0) {
      const m = /exists|clobber|already/.test(r.err + r.out)
        ? ` — ${rel} exists locally; pass --force to overwrite (a .bak is written)` : "";
      out(`skip\t${t}\t${(r.err || r.out).split(/\r?\n/)[0]}${m}`);
      continue;
    }
    out(`restored\t${t}\t~/${rel}`);
  }
  // A world-readable config/authorized_keys is a real ssh failure: sshd ignores
  // authorized_keys with loose perms and ssh warns loudly about config perms.
  for (const t of targets) {
    const p = path.join(homedir(), REL[t]);
    if (existsSync(p) && (statSync(p).mode & 0o077)) {
      chmodSync(p, 0o600);
      out(`perms\t${t}\ttightened to 600 (was loose)`);
    }
  }
}

function cmdStatus() {
  const st = creds("status");
  out(`creds\t${/unlocked/.test(st.out) ? "unlocked" : "locked (run: f creds unlock)"}`);
  const man = (() => { const r = creds("files", "ls", "--json"); try { return JSON.parse(r.out) ?? {}; } catch { return {}; } })();
  for (const t of PACKABLE) {
    const rel = REL[t];
    const key = "file:~/" + rel;
    const p = path.join(homedir(), rel);
    const local = existsSync(p);
    const packed = !!man[key];
    // Size equality is a cheap "probably in step", not a content hash — say so
    // rather than implying we compared bytes.
    const verdict = local && packed ? (statSync(p).size === man[key].bytes ? "\tin step (by size)" : "\tDIFFERS — repack or unpack") : "";
    out(`${t}\tlocal=${local ? statSync(p).size + "B" : "absent"}\tpacked=${packed ? man[key].bytes + "B" : "absent"}${verdict}`);
  }
  // Legacy absolute keys from a pre-portable store: unrestorable on this host.
  for (const k of Object.keys(man))
    if (k.startsWith("file:/") && !k.startsWith("file:" + homedir()))
      out(`LEGACY\t${k}\tstuck on another host — fix: f creds files relabel ${k.slice(5)} ~/${k.split("/").slice(-2).join("/")}`);
}

// ── opt-in private key packing ──────────────────────────────────────────────
function cmdKeysPack(argv) {
  if (!argv.includes("--i-know-what-im-doing")) {
    die("ssh: refusing to pack private keys.\n" +
      "  A private key is a bearer credential: packing it puts EVERY host reachable\n" +
      "  with it behind one store passkey, and the store is only as strong as that\n" +
      "  passkey. Packing is also how a private key ends up on a machine you did not\n" +
      "  choose. If that is the tradeoff you want:\n" +
      "    f ssh keys pack --i-know-what-im-doing\n" +
      "  Prefer ~/.ssh/config identity paths per machine, or an agent (f ssh agents).");
  }
  needUnlocked();
  const names = ["id_ed25519", "id_rsa", "id_ecdsa"].filter((n) => existsSync(path.join(SSH_DIR, n)));
  if (!names.length) { out("no private keys to pack"); return; }
  for (const n of names) {
    const r = creds("files", "pack", path.join(SSH_DIR, n));
    if (r.code !== 0) die(`ssh: failed to pack ${n}: ${r.err || r.out}`);
    out(`packed\t${n}\t(secret — treat the store as a private key now)`);
  }
}

// ── entry ───────────────────────────────────────────────────────────────────
export function register() {
  return {
    name: "ssh",
    desc: "ssh hosts, config and authorized_keys, carried via the creds store",
    run: (argv, args, ctx) => {
      void ctx;
      const [sub, ...rest] = args._ ?? [];
      switch (sub) {
        case undefined: case "help": case "--help":
          out("usage: f ssh <cmd>");
          out("  ls                      hosts from ~/.ssh/config");
          out("  show <host>             config block + effective (ssh -G) values");
          out("  check [host] [--connect]  resolve, then probe publickey auth");
          out("  run <host> [cmd...]     non-interactive ssh, prompts can never hang");
          out("  keys                    local public keys + fingerprints");
          out("  agents                  ssh-agent state + held keys");
          out("  authorized [ls|add|rm]  this machine's authorized_keys");
          out("  pack|unpack|status      carry config + authorized_keys via 'f creds files'");
          out("  keys pack --i-know-what-im-doing   opt-in private key packing");
          return;
        case "ls": return cmdLs();
        case "show": return cmdShow(rest[0]);
        case "check": return cmdCheck(rest[0], rest);
        case "run": return cmdRun(rest);
        case "keys":
          if (rest[0] === "pack") return cmdKeysPack(rest);
          return cmdKeys();
        case "agents": case "agent": return cmdAgents();
        case "authorized": case "auth": return cmdAuthorized(rest[0], rest.slice(1));
        case "pack": return cmdPack(rest[0]);
        case "unpack": return cmdUnpack(rest[0], rest);
        case "status": return cmdStatus();
        default: die(`ssh: unknown command '${sub}' — try 'f ssh help'`);
      }
    },
    // Convention from fj/ha/gh: declare the skill as a PATH pointer, not inline
    // content, so SKILL.md stays the single source of guidance.
    skills: [{ name: "f-ssh", path: path.join(path.dirname(fileURLToPath(import.meta.url)), "SKILL.md") }],
  };
}

export default { register };
