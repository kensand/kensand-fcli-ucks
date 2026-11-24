// doctor/index.js — verify a capability layer actually answers, instead of trusting silence.
// Zero deps: node builtins only.
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readdirSync, existsSync, readFileSync } from "node:fs";
import net from "node:net";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";

const run = promisify(execFile);

const CMDS = ["f", "qmd", "node", "git", "jq"];
// The credential domain is HALF-DEGRADED by default: cached mirror tokens keep working
// while the server that mints them is dead, so one successful `f fj` call proves nothing.
// `status` refreshes without a login attempt; `list`/`get` can trigger one and a 400
// repeated enough can lock the account. Probe with `status` only.
// Real paths on this machine: the creds store is a file, not a directory.
const FILES = [
  ".f/f.config.json",
  ".f/f.creds.enc",
  ".pi/agent/memory/MEMORY.md",
  ".pi-web/sessiond-owner.json",
];
// The bucket list lives in ONE place, so the `--all` audit and the per-uck check cannot
// disagree about where a uck lives.
const BUCKETS_ROOT = ".f/ucks";
const BUCKET_DIRS = [
  path.join(BUCKETS_ROOT, "kensand-fcli-ucks"),
  path.join(BUCKETS_ROOT, "official-ucks-src"),
  path.join(BUCKETS_ROOT, "ucks"),
];

// Every consumer of a health report must branch on `state`, never on whether a row is
// present: `state` is the verdict. Keep the vocabulary and that rule in sync here and in
// SKILL.md, because a report whose shape is undocumented gets misread as "no problems".
const DIRS = [".pi/agent/memory", ".pi-web", BUCKETS_ROOT];

// A degraded tool answers with plausible garbage, or says nothing at all. Both look
// like "fine" to a caller that only checks the exit code.
const HOME = os.homedir();
async function probe(cmd) {
  let where;
  try {
    where = (await run("sh", ["-c", `command -v ${cmd}`])).stdout.trim();
  } catch {
    return { cmd, state: "MISSING", detail: "not on PATH" };
  }
  try {
    const { stdout } = await run(cmd, ["--version"], {
      timeout: 15000,
      encoding: "utf8",
    });
    const line = (stdout || "").trim().split("\n")[0];
    return line
      ? { cmd, state: "OK", detail: `${line} @ ${where}` }
      : { cmd, state: "SILENT", detail: `exit 0, empty --version @ ${where}` };
  } catch (err) {
    const code = err.code === "ETIMEDOUT" ? "timeout" : err.message.split("\n")[0];
    return { cmd, state: "FAIL", detail: `${code} @ ${where}` };
  }
}

// A git bucket that `f up` would reset away is the one thing that destroys work here.
async function bucket(dir) {
  try {
    const { stdout } = await run(
      "git",
      ["-C", dir, "status", "--porcelain=v1", "--branch", "--untracked-files=no"],
      { encoding: "utf8", timeout: 15000 },
    );
    const lines = stdout.trim().split("\n").filter(Boolean);
    const head = lines[0] || "";
    const dirty = lines.length - 1;
    // "## local/x" with no tracking info => detached at a remote tip, or a branch
    // with no upstream. Neither is protected from `f up`.
    const tracked = head.includes("...");
    const detached = head.startsWith("## ") && !tracked;
    const behind = /\bbehind\b/.test(head);
    const ahead = /\bahead\b/.test(head);
    const notes = [];
    if (dirty) notes.push(`${dirty} uncommitted`);
    if (detached) notes.push("no upstream (f up would reset it)");
    if (behind) notes.push("behind origin");
    if (ahead) notes.push("UNPUSHED COMMITS (f up destroys these)");
    const state = notes.length ? "RISK" : "OK";
    return {
      cmd: path.basename(dir),
      state,
      detail: `${head.replace(/^## /, "") || "?"}${notes.length ? ` — ${notes.join("; ")}` : ""}`,
    };
  } catch (err) {
    return { cmd: path.basename(dir), state: "FAIL", detail: err.message.split("\n")[0] };
  }
}

export function register(_ctx) {
  return {
    name: "doctor",
    desc: "is a tool/uck alive? probe commands, buckets, uck usage; --all --json for machine rows (degraded != error)",
    run: async (rawArgv, args) => {
      // THE ARGUMENT-RECEIVING TRAP (found by testing, not reading): f calls
      //   uck.run(rest, uck.argv?.(rest) ?? { _: rest }, ctx)
      // and declares no `argv:` hook here (CONTRACT §2.3), so `args` is literally
      // `{ _: rawArgv }` — flag tokens like `--help` / `--all` are POSITIONALS in `args._`,
      // never `args.help`/`args.all`. Any uck that trusts `args.<flag>` silently ignores the
      // flag and answers the default question. So parse the raw argv here and treat `args._`
      // as a fallback, never as the source of truth for flags.
      //
      // Why both are read, not just one: `tokens` (the raw argv) is authoritative TODAY and
      // is what a future f with real flag parsing would hand us unchanged; `args._` is kept
      // as the fallback for a harness that pre-parses into `_`, and `args[name] === true`
      // for a harness that pre-parses into named keys. All three are OR'd so the uck stays
      // correct across a harness change instead of silently losing a flag.
      const tokens = (Array.isArray(rawArgv) ? rawArgv : []).map(String);
      const flag = (name) =>
        args?.[name] === true ||
        tokens.includes(`--${name}`) ||
        (args?._ ?? []).map(String).includes(`--${name}`);
      // A recognised flag that does not change the OUTPUT SHAPE is still flag blindness.
      // This uck shipped that bug: `--all` was stripped from the target list but `--json`
      // was not, so `f doctor --json` resolved "--json" as a uck name and printed a
      // fabricated `MISSING --json  no index.js in any bucket` row, while
      // `f doctor --all --json` mixed free text with JSON. Honour every flag you accept.
      const CONSUMED = ["--help", "-h", "--all", "--json"];
      const rest = [...new Set([...tokens, ...(args?._ ?? []).map(String)])].filter(
        (s) => !CONSUMED.includes(s),
      );
      const json = flag("json");
      const emit = (obj) => process.stdout.write(JSON.stringify(obj) + "\n");

      if (flag("help") || flag("h")) {
        // Reached only in-process: `f <uck> --help` is routed to `f help <uck>`, which
        // prints the desc, not this. Keep the usage in the desc too.
        process.stdout.write(
          "usage: f doctor [--all] [--json] [uck ...]\n" +
            "  f doctor              probe the capability layer (tools, dirs, buckets, creds)\n" +
            "  f doctor <uck>...     is a uck live? register() shape + flags honoured + usage?\n" +
            "  f doctor --all        audit EVERY uck in the buckets for the SILENT contract\n" +
            "                        (a uck that returns results without writing stdout is mute)\n" +
            "  f doctor --json       machine-readable rows (with --all: {mode,summary,rows});\n" +
            "                        branch on .state, never on a row's presence\n" +
            "exit: 0 healthy, 1 anything degraded. trust only the OK rows.\n",
        );
        return;
      }

      // `--all` closes the audit loop: instead of hand-listing every uck each run, audit
      // every uck in the buckets for the contract that causes silence.
      if (flag("all")) {
        const roots = BUCKET_DIRS.map((d) => path.join(HOME, d)).filter((d) => existsSync(d));
        const names = new Set();
        for (const root of roots) {
          let entries = [];
          try {
            entries = readdirSync(root, { withFileTypes: true });
          } catch {
            continue;
          }
          for (const e of entries) {
            if (e.isDirectory() && existsSync(path.join(root, e.name, "index.js"))) {
              names.add(e.name);
            }
          }
        }
        rest.push(...[...names].sort());
      }

      if (rest.length) {
        const uckRows = [];
        for (const name of rest) {
          const fail = (detail) => {
            uckRows.push({ state: "FAIL", cmd: name, detail });
          };
          let found;
          for (const bucketDir of BUCKET_DIRS.map((d) => path.join(HOME, d))) {
            const p = path.join(bucketDir, name, "index.js");
            if (existsSync(p)) {
              found = { p, bucket: path.basename(bucketDir) };
              break;
            }
          }
          if (!found) {
            fail("no index.js in any bucket");
            continue;
          }
          let shape;
          try {
            const mod = await import(`file://${found.p}`);
            if (typeof mod.register !== "function") {
              fail(`register is not a function (${found.bucket})`);
              continue;
            }
            const r = mod.register({});
            shape = {
              name: r?.name,
              desc: r?.desc,
              run: typeof r?.run,
              skills: Array.isArray(r?.skills) ? r.skills.length : 0,
            };
          } catch (err) {
            fail(`import: ${err.message.split("\n")[0]}`);
            continue;
          }
          if (shape.name !== name) {
            fail(`register() name is ${JSON.stringify(shape.name)}`);
            continue;
          }
          if (shape.run !== "function") {
            fail(`run is ${shape.run}, not a function`);
            continue;
          }
          // Flag blindness. `args` is only a flag-parsed object if the uck declares an
          // `argv:` hook (CONTRACT §2.3); no uck in either bucket does, so f hands
          // `args = { _: rawArgv }` and every `--foo` lives in `args._`. A uck that reads
          // `args.foo` without tokenising the raw argv gets `undefined` and silently
          // answers the DEFAULT case -- plausible wrong output, worse than silence. This
          // check fired on doctor itself: `f doctor --all` quietly ran the bare probe.
          //
          // METAPHYSICS OF THIS CHECK (read before "simplifying" it): it asks whether the
          // uck RECEIVES flags, not whether it parses them. Tokenising is the dominant
          // signal and is accepted as sufficient -- `run: (argv, …)` plus `parseTokens`,
          // `parseArgv` or any `=== "--x"` comparison is fine (mqtt/ha/fj/kuma/slop/ddg).
          // `run: (_argv, args)` + `args.<flag>` with no tokenising is the bug.
          // Detection is deliberately substring-based: an inline-backtick character class
          // inside a regex literal silently matched NOTHING and passed every uck, so the
          // first version of this gate was itself silently broken. Test it against a
          // known-bad uck (SKILL.md) before trusting an all-OK run.
          let flagBlind = [];
          // Read the source ONCE, in the loop scope: the flag-blindness gate and the
          // --json gate below both need it, and a `const` inside the try block was invisible
          // to the second gate (ReferenceError on every named-uck check).
          let src = "";
          try {
            src = readFileSync(found.p, "utf8");
            const declaredHook = new RegExp(["argv", "\\s*:", "[\\s\\S]{0,20}?[\\(A-Za-z_$]"].join("")).test(src);
            // Does the uck compare tokens to "--flag" anywhere? Quote-agnostic substring test.
            const tokenises = src.includes('=== "--') || src.includes("=== '--") || src.includes("=== `--") ||
              src.includes('== "--') || src.includes("startsWith('--") || src.includes('startsWith("--');
            if (!declaredHook && !tokenises) {
              // Flag names as they appear in quoted usage text: "--json", "--host <x>".
              const documented = [
                ...new Set(
                  (src.match(/--([a-z][a-z0-9-]{1,20})/g) || []).map((s) => s.slice(2)),
                ),
              ];
              flagBlind = documented.filter((k) => {
                const bare = k.replace(/-/g, "");
                return src.includes(`args.${k}`) || src.includes(`args.${bare}`) ||
                  src.includes(`args?.${k}`) || src.includes(`args?.${bare}`) ||
                  src.includes(` a.${k}`) || src.includes(` a.${bare}`);
              });
            }
          } catch {
            /* unreadable source is not evidence; leave the row alone */
          }
          if (flagBlind.length) {
            fail(
              `reads args.${flagBlind.slice(0, 4).join("/")} but declares no argv hook and never tokenises raw argv, so those flags are always undefined (${found.bucket})`,
            );
            continue;
          }
          // Second half of the contract, added because this uck violated it itself: a flag
          // that is PARSED but never changes the output is still answered wrongly. Any uck
          // documenting `--json` must actually produce JSON, otherwise it replies to a
          // structured-data question with prose and exits 0.
          // A uck that advertises `--json` must be able to emit JSON. This gate exists
          // because doctor itself advertised --json, silently consumed it as a TARGET NAME,
          // and printed a fabricated `MISSING --json  no index.js in any bucket` row.
          //
          // Deliberately COARSE: is a serializer reachable from stdout at all? Three
          // guard-matching variants were tried and all three false-failed healthy ucks —
          // kuma/slop/ddg use `if (flags.json)`, grafana uses `has(argv,"--json")` with the
          // serializer in an `out()` helper several lines away, providers stashes the guard
          // in a variable (`const dump = a.includes("--json")`) and stringifies inside a
          // later branch. Guard syntax is not a stable signal; "can this uck produce JSON on
          // stdout" is. A gate that calls healthy tools broken is worse than no gate, and a
          // loose gate here still catches the real bug (a uck with no serializer at all).
          if (src && /--json/.test(src)) {
            const stringifiesInline = /process\.stdout\.write\([\s\S]{0,80}?JSON\.stringify/.test(src);
            const stringifiesInWriter =
              /(function|const)\s+(out|emit)\s*[=(][\s\S]{0,200}?JSON\.stringify/.test(src);
            const reachesJson = stringifiesInline || stringifiesInWriter;
            if (!reachesJson) {
              fail(`documents --json but has no JSON serializer on stdout (${found.bucket})`);
              continue;
            }
          }
          // The trap this uck exists for: a uck can be valid, registered and listed
          // in `f` and still answer nothing at the CLI. Probe the BARE invocation and
          // require content -- exit codes are useless here, because a failing CLI makes
          // `f` exit non-zero for reasons unrelated to the uck under test.
          //
          // One probe per uck, and it is the BARE one on purpose: an invocation with flags
          // can mutate state, and `f <uck> --help` is routed to `f help <uck>` rather than
          // reaching the uck. So this loop can never OBSERVE a --json path working; the gate
          // above is a static check and must be labelled as such, not as proof.
          let cli = "";
          let errored = "";
          try {
            const { stdout, stderr } = await run("f", [name], {
              timeout: 20000,
              encoding: "utf8",
            });
            cli = ((stdout || "") + (stderr || "")).trim();
          } catch (err) {
            errored = err.code === 124 ? "timed out" : `exited ${err.code ?? "non-zero"}`;
            cli = ((err.stdout || "") + (err.stderr || "")).trim();
          }
          if (!cli) {
            fail(
              `registers ok (${found.bucket}) but \`f ${name}\` ${errored || "exit 0"} and printed nothing — no usage path`,
            );
            continue;
          }
          const how = errored ? `no --help path; try \`f help ${name}\` (${errored})` : "prints usage";
          uckRows.push({
            state: "OK",
            cmd: name,
            detail: `${JSON.stringify(shape.desc)} — ${how}: ${cli.split("\n")[0].slice(0, 50)}`,
            bucket: found.bucket,
            skills: shape.skills,
            // Honest about what this loop did NOT verify: it ran the bare uck only, so a
            // --json path was matched statically, never executed. Consumers must not read
            // an OK row as "every flag of this uck works".
            verified: "bare invocation + static source gates",
            jsonMode: src ? /--json/.test(src) : null,
          });
        }
        const bad = uckRows.filter((r) => r.state !== "OK").length;
        if (json) {
          emit({
            mode: "ucks",
            health: bad ? "DEGRADED" : "HEALTHY",
            ok: uckRows.length - bad,
            total: uckRows.length,
            rows: uckRows,
          });
        } else {
          for (const r of uckRows) console.log(`${r.state}\t${r.cmd}\t${r.detail}`);
        }
        process.exitCode = bad ? 1 : 0;
        return;
      }

      const rows = [];
      const seen = new Set();

      const cmdResults = await Promise.all(CMDS.map(probe));
      for (const r of cmdResults) {
        rows.push(r);
        seen.add(r.cmd);
      }

      // PATROL CHANNELS. Every patrol lane resolves its server through a NAME before it
      // touches the service, and a name can die while the service is perfectly healthy --
      // which is exactly how `f ha` went dark for a whole run: `homeassistant.local` is
      // mDNS-only (RFC 6762), never sent to unicast DNS, and this box has no mDNS
      // responder, so `f ha ls` said `fetch failed` and read like an HA outage. HA was up
      // at 10.1.5.5:8123 the entire time and `f kuma watch` reported 26/27 UP, so nothing
      // else noticed. The existing rows cannot see this class: the vault/creds rows ask
      // whether a SECRET resolves and the service rows ask whether an ENDPOINT answers --
      // neither asks whether the host even NAMES, and "host unresolvable" and "service
      // down" need different fixes (DNS/mDNS vs. the service).
      //
      // EMITS UNCONDITIONALLY. A gate that prints a row only when it finds something is
      // indistinguishable from a gate that never ran, and I have been fooled by that twice.
      // So this block always prints one row naming how many hosts it checked.
      //
      // ASKS ONLY FOR THE HOST, NEVER THE CREDENTIAL: `urls`-shaped verbs print a resolved
      // base and exit before connecting (verified in ha/index.js and mqtt/index.js -- they
      // `out()` then `return`), and grafana's base is a cred/env/DEFAULT_HOST read with no
      // HTTP call. That keeps this block free of both service writes and vault logins, so
      // running it can never trip a 400/429 login refusal. kuma has no `urls` verb and its
      // base is a hardcoded default (overridable by KUMA_URL), read from source instead.
      const channels = [];
      {
        const readBase = async (argv) => {
          // Distinguish THREE outcomes, because collapsing them manufactures a false verdict:
          // (a) stdout on success, (b) stderr when the CLI exits non-zero, (c) genuinely empty.
          // execFile REJECTS on non-zero, and `e.stdout` is then EMPTY while the explanation is
          // on stderr -- a gate that kept only stdout would report "no base url resolved" for a
          // BROKEN TOOL, which is the same masking this whole block exists to prevent.
          try {
            const { stdout } = await run("f", argv, { timeout: 25000, encoding: "utf8" });
            return { out: String(stdout || ""), err: "" };
          } catch (e) {
            return {
              out: String((e && e.stdout) || ""),
              err: String((e && e.stderr) || (e && e.message) || ""),
            };
          }
        };
        const hostOf = (s) => {
          const m = String(s || "").match(/\bhttps?:\/\/([^/\s"',]+)/i);
          return m ? m[1].split(":")[0] : null;
        };
        const resolves = (host) =>
          new Promise((resolve) => {
            run("getent", ["ahosts", host], { timeout: 8000, encoding: "utf8" })
              .then((r) => resolve(/\S/.test(r.stdout || "") ? r.stdout.trim().split(/\s+/)[0] : null))
              .catch(() => resolve(null));
          });

        const haOut = await readBase(["ha", "urls"]);
        // grafana has NO `urls` verb (verified: `grep -n urls grafana/index.js` -> nothing),
        // so its base is read the same way its own resolve() reads it -- a cred lookup, no
        // HTTP call, no login. A bare read may be mirror-blind, hence the explicit mirror:
        // key too. `--secrets` only: bare `f creds get` prints the 37-byte redaction
        // placeholder, which would be parsed as a hostname.
        let grafBase = { out: "", err: "" };
        for (const nm of ["grafana-host", "mirror:grafana-host"]) {
          const v = await readBase(["creds", "get", nm, "--secrets"]);
          const s = v.out;
          if (/^\[redacted/.test(s)) continue;
          if (/no such cred|not found|^\s*$/i.test(s)) continue;
          grafBase = v; break;
        }
        const mqttOut = await readBase(["mqtt", "urls"]);
        // A lane whose command FAILED is NOT a lane with no config -- say which, using the
        // CLI's own words rather than inventing a diagnosis.
        const failed = [];
        const kumaHost = hostOf(process.env.KUMA_URL || "https://uptime.kensand.net") || null;

        const wanted = [
          { lane: "ha", read: haOut, host: hostOf(haOut.out) },
          { lane: "grafana", read: grafBase, host: hostOf(grafBase.out) || hostOf(process.env.GRAFANA_URL || "https://grafana.kensand.net") },
          { lane: "kuma", read: null, host: kumaHost },
          {
            lane: "mqtt",
            read: mqttOut,
            host: (() => {
              const l = String(mqttOut.out)
                .split("\n")
                .map((x) => x.trim())
                .find((x) => x.startsWith("broker="));
              return l ? l.slice(7).split(":")[0] : null;
            })(),
          },
        ];
        for (const w of wanted) {
          if (w.read && !w.read.out && w.read.err)
            failed.push(`${w.lane}: ${w.read.err.replace(/\r?\n/g, " ").split("Command failed")[0].trim().slice(0, 90) || "command failed"}`);
          if (!w.host) {
            channels.push({ lane: w.lane, host: null, ip: null });
            continue;
          }
          channels.push({ lane: w.lane, host: w.host, ip: await resolves(w.host) });
        }
        if (failed.length) {
          rows.push({
            cmd: "patrol-channels",
            state: "RISK",
            detail:
              `could not read the configured base for ` +
              failed.join(" | ") +
              " -- that is a BROKEN TOOL or an unreadable cred, NOT proof the lane is " +
              "unconfigured, so no host-resolvability claim is made for it.",
          });
        }

        const dead = channels.filter((c) => c.host && !c.ip);
        const unknown = channels.filter((c) => !c.host);
        if (dead.length) {
          rows.push({
            cmd: "patrol-channels",
            state: "RISK",
            detail:
              `${dead.length} patrol lane(s) point at a host that DOES NOT RESOLVE ` +
              "(" +
              dead.map((d) => `${d.lane}=${d.host}`).join(", ") +
              "). This is NOT an outage: the service may be healthy while the NAME is " +
              "dead, and every consumer then reports `fetch failed`/`connect timeout`, " +
              "which reads as the service being down. Check DNS, or mDNS -- a `.local` " +
              "name is mDNS-only (RFC 6762) and is NEVER sent to unicast DNS, so it needs " +
              "a responder like avahi. Fix the NAME first; any baseline measured through " +
              "this lane is a quotation, not evidence, until it resolves.",
          });
        }
        if (unknown.length) {
          rows.push({
            cmd: "patrol-channels",
            state: "INFO",
            detail:
              `no base url resolved for ` +
              unknown.map((u) => u.lane).join(", ") +
              " -- that lane's host could not be audited (unset cred or no `urls` verb), " +
              "which is not the same as it being healthy.",
          });
        }
        const okHosts = channels.filter((c) => c.host && c.ip);
        if (okHosts.length) {
          rows.push({
            cmd: "patrol-channels",
            state: "INFO",
            detail:
              `${okHosts.length}/${channels.length} patrol host(s) RESOLVE (` +
              okHosts.map((c) => `${c.lane}=${c.host}`).join(", ") +
              "). Name resolution only -- a row here never claims the service answered, " +
              "and a lane whose host is missing above was not checked at all.",
          });
        }
      }

      // Half-degraded credential layer: cache masks a dead issuer until the cache dies.
      if (seen.has("f")) {

        const askSocket = (key) =>
          new Promise((resolve) => {
            let buf = "";
            let done = false;
            const finish = (v) => {
              if (done) return;
              done = true;
              try {
                c.destroy();
              } catch {
                /* already closed */
              }
              resolve(v);
            };
            const c = net.connect(path.join(HOME, ".f", ".creds.sock"), () => {
              c.write(JSON.stringify({ op: "get", name: key }));
            });
            c.setTimeout(5000, () => finish("unreachable"));
            c.on("data", (d) => (buf += d));
            c.on("end", () => {
              try {
                const r = JSON.parse(buf);
                if (r && r.ok && r.value != null && r.value !== "") finish("resolves");
                else if (/no such cred/i.test(String(r && r.error))) finish("absent");
                else finish("unresolvable");
              } catch {
                finish("unreachable");
              }
            });
            c.on("error", () => finish("unreachable"));
          });
          // REDACTION SHAPE — `f creds get` REDACTS BY DEFAULT: it prints a fixed
          // placeholder (`[redacted — pass --secrets to reveal]`, 37 bytes) and exits 0
          // whether or not the subject is a secret. Measured on this box: plain
          // `f creds get <cred> | wc -c` answers **37 for every cred**, so a "how many
          // bytes does this cred yield" check measures the WRAPPER, never the value. The
          // class has real damage behind it: `f creds get X | f creds set X` once stored
          // that placeholder as a live credential, and every consumer then died with a
          // ByteString error on code 8212 (the em-dash). `--secrets` DOES reveal the value
          // (verified: gh-token 40B `ghp…`, grafana-token 46B `glsa…`, ha-host 31B), so
          // the row below is about the DEFAULT path a script is most likely to pipe.
          //
          // REACHABILITY IS ASSERTED, not assumed. A gate whose target list is silently
          // empty prints byte-identical output to one that checked everything and found
          // nothing. My first version parsed local names with a `^name\t` regex, but
          // `f creds ls --all` prints them as a BARE column — the list was empty and the
          // gate was vacuous while printing nothing. An empty probe set is therefore a
          // FAIL row, never a pass.
          try {
            const { stdout: lsAll } = await run("f", ["creds", "ls", "--all"], {
              timeout: 30000,
              encoding: "utf8",
            });
            const localNames = (lsAll || "")
              .split("\n")
              .map((l) => l.trim())
              .filter(
                (n) =>
                  n &&
                  !n.startsWith("mirror:") &&
                  !/[\t ]/.test(n) &&
                  !/^[#-]/.test(n) &&
                  !/^[a-z-]+\.[a-z-]+$/i.test(n), // drop `vaultwarden.*` metadata rows
              )
              .slice(0, 3);
            if (localNames.length === 0) {
              rows.push({
                cmd: "creds-redaction",
                state: "FAIL",
                detail:
                  "found no local cred names to probe — cannot claim the redaction " +
                  "surface is healthy (an empty target list is a broken probe, not a pass)",
              });
            } else {
              // One BARE argv per name (what a script pipes) plus the socket verdict for
              // the same key. Never print a value: shape and length only.
              const got = await Promise.all(
                localNames.map(async (n) => {
                  let out = "";
                  try {
                    out = (
                      await run("f", ["creds", "get", n], {
                        timeout: 20000,
                        encoding: "utf8",
                      })
                    ).stdout;
                  } catch (e) {
                    out = (e && e.stdout) || "";
                  }
                  return {
                    n,
                    out: (out || "").replace(/\r?\n$/, ""),
                    sock: await askSocket(n),
                  };
                }),
              );
              const placeholder = got.filter((g) => /^\[redacted/.test(g.out));
              if (placeholder.length) {
                rows.push({
                  cmd: "creds-redaction",
                  state: "INFO",
                  detail:
                    `${placeholder.length}/${got.length} local cred(s) print the ` +
                    "`[redacted — pass --secrets to reveal]` placeholder on bare " +
                    "`f creds get` and exit 0 (" +
                    placeholder.map((g) => g.n).join(", ") +
                    "). All of them RESOLVE on the socket, so nothing is broken — but do " +
                    "NOT pipe the CLI output onward: it is 37 chars of prose with an " +
                    "em-dash (code 8212), and storing it yields a cred that resolves, " +
                    "exits 0, then fails at the service. Use `--secrets`, or read the " +
                    "socket.",
                });
              }
              // CONTRADICTION: the store holds a value but the CLI hands back something
              // that is neither the placeholder nor plausibly the secret. A SIZE check
              // alone would miss a redaction regression (both sides short, non-empty), so
              // compare CONTENT against the socket verdict.
              const contradicted = got.filter(
                (g) =>
                  g.sock === "resolves" &&
                  !/^\[redacted/.test(g.out) &&
                  g.out.length > 0 &&
                  g.out.length < 8,
              );
              if (contradicted.length) {
                rows.push({
                  cmd: "creds-redaction",
                  state: "RISK",
                  detail:
                    `${contradicted.length} cred(s) RESOLVE on the socket but ` +
                    "`f creds get` returned a tiny string (" +
                    contradicted.map((g) => `${g.n}=${g.out.length}B`).join(", ") +
                    ") — neither a secret nor the known placeholder, so the CLI is not " +
                    "handing consumers the value the store holds.",
                });
              }
            }
          } catch {
            /* creds unreachable: the vault row above already answered */
          }
        try {
          const { stdout } = await run("f", ["vaultwarden", "status"], {
            timeout: 30000,
            encoding: "utf8",
          });
          // F_VW_FIXTURE_FILE is a DIAGNOSTIC-INJECTION POINT for this gate only: it lets the
          // real decision code below run on captured/known-bad `status` output WITHOUT another
          // vault login (a 400 must never be retried - lockout). No production path sets it.
          const statusFixture = process.env.F_VW_FIXTURE_FILE;
          const text = statusFixture
            ? readFileSync(statusFixture, "utf8")
            : stdout || "";
          // `status` prints `provider vaultwarden ready` as its FIRST line and the failure
          // further down, so "ready" is never the predicate -- the predicate is the ABSENCE of
          // these markers in the same stdout. Distinguish the two shapes: a REFUSED LOGIN is
          // kenny's to fix (and must not be retried), a TRANSPORT failure is this box's. They
          // used to collapse into one row that asserted "cached mirrors still resolve", which is
          // false whenever a mirror has already lapsed -- so report measured facts, not a guess.
          const refused = /token refresh failed|session failed|HTTP 400/.test(text);
          const transport = /ECONNREFUSED|ENOTFOUND|ETIMEDOUT|EAI_AGAIN|fetch failed/i.test(text);
          if (refused || transport) {
            rows.push({
              cmd: "creds",
              state: "RISK",
              detail:
                (transport && !refused
                  ? "vault unreachable (transport error) -- credential layer unverified"
                  : "vault re-auth refused (HTTP 400)") +
                " -- vault-side renewal is down, so an expired mirror CANNOT be re-fetched and a " +
                "vault-only cred read with --no-cache fails outright. Cached/local creds keep " +
                "working, which is why patrol can look green; the rows below name what is actually " +
                "unreadable. Do not retry a login (lockout risk); needs operator `f vaultwarden config`",
            });
          } else {
            // What decides whether provider creds keep resolving is the per-name
            // mirror expiry, and `f creds ls --all` prints those dates authoritatively
            // (it knows which entries are mirrors and when each one dies). The vault's
            // own "mirror ttl 3600s" line is a config default, NOT an expiry: it read
            // the same while re-auth was broken and after it recovered, so it implied a
            // deadline it had not measured. Never parse ~/.f/.creds-cache.json here —
            // `src:mirror:<name>` in that file is a provider-attribution record whose
            // expiresAt is unrelated to the mirror's life (it claimed forgejo expired
            // 2026-10-13 while the mirror actually runs to 2026-11-28).
            let mirrorNote = "";
            try {
              const { stdout: ls } = await run("f", ["creds", "ls", "--all"], {
                timeout: 30000,
                encoding: "utf8",
              });
              const mirrors = (ls || "")
                .split("\n")
                .map((l) => l.match(/^(mirror:[^\t ]+).*?expires\s+([0-9T:.Z-]+)/))
                .filter(Boolean)
                .map((m) => ({ name: m[1], at: Date.parse(m[2]) }))
                .filter((m) => Number.isFinite(m.at));
              const now = Date.now();
              // VERIFY THE RISK ROW BEFORE REPORTING IT. An expired mirror stamp is
              // metadata; what kenny cares about is whether the value still resolves.
              // Two heartbeats reported "N mirrors EXPIRED — patrol goes dark" for
              // items that still answered `f creds get`, i.e. a false alarm that trains
              // the operator to skim the RISK rows. So resolve each expired mirror and
              // only escalate the ones that actually fail.
              //
              // Read the creds SOCKET, not a nested `f creds get`: doctor already
              // spawns `f vaultwarden status` and `f creds ls --all`, and CONTRACT N12
              // stops at two nested `f` calls. The socket is what `f creds get` itself
              // reads, and the daemon answers STRUCTURALLY — {ok:true,value} when it
              // answers, {ok:false,error:"no such cred: X"} when the item is gone — so
              // a deleted vault item is never mislabelled a dead credential, and no
              // nested command here can trip a vault re-auth (a 400 retry can lock the
              // account). The daemon answers exact keys only, so `mirror:<name>` is
              // asked explicitly.
              // askSocket is hoisted above, shared with the redaction gate.
              const expired = mirrors.filter((m) => m.at <= now);
              const verdicts = await Promise.all(
                expired.map(async (m) => ({ m, v: await askSocket(m.name) })),
              );
              // `absent` (the vault item was deleted) and `unreachable` (the whole store
              // is down — the vault rows already say that) are NOT "this credential
              // died", so they never become a RISK here.
              const dead = verdicts.filter((x) => x.v === "unresolvable").map((x) => x.m);
              const healed = verdicts.filter((x) => x.v === "resolves");
              const soon = mirrors.filter((m) => m.at > now && m.at - now < 48 * 3600 * 1000);
              if (dead.length) {
                rows.push({
                  cmd: "creds-mirror",
                  state: "RISK",
                  detail:
                    `${dead.length} provider mirror(s) EXPIRED and UNRESOLVABLE (` +
                    dead.map((m) => m.name.replace("mirror:", "")).join(", ") +
                    `) — these are values a consumer can no longer read. Re-fetch from the ` +
                    `provider; check with f vaultwarden status and NEVER retry a 400 login (lockout).`,
                });
              }
              if (healed.length) {
                rows.push({
                  cmd: "creds-mirror",
                  state: "INFO",
                  detail:
                    `${healed.length} mirror(s) past their expiry stamp but STILL RESOLVE from the ` +
                    `creds socket (${healed.map((x) => x.m.name.replace("mirror:", "")).join(", ")}) — ` +
                    `the stamp is stale metadata, not a dead credential. Not a fault, do not act.`,
                });
              }
              if (soon.length) {
                mirrorNote = ` — ${soon.length} mirror(s) expire <48h (${soon.map((m) => `${m.name.replace("mirror:", "")} @${new Date(m.at).toISOString().slice(0, 16)}Z`).join(", ")})`;
              } else if (mirrors.length) {
                const next = mirrors.reduce((a, b) => (a.at < b.at ? a : b));
                mirrorNote = ` — ${mirrors.length} mirror(s), next expiry ${next.name.replace("mirror:", "")} @${new Date(next.at).toISOString().slice(0, 16)}Z`;
              }
            } catch {
              /* creds unavailable: the vault row above already answered */
            }
            rows.push({
              cmd: "creds",
              state: "OK",
              detail: `vault answers${mirrorNote}`,
            });
          }
        } catch (err) {
          rows.push({
            cmd: "creds",
            state: "FAIL",
            detail: `f vaultwarden status: ${(err.code === "ETIMEDOUT" ? "timeout" : err.message.split("\n")[0])} — credential layer unverified`,
          });
        }
      }

      for (const d of DIRS) {
        const abs = path.join(HOME, d);
        rows.push({
          cmd: d,
          state: existsSync(abs) ? "OK" : "MISSING",
          detail: existsSync(abs) ? abs : "absent",
        });
      }

      for (const f of FILES) {
        const abs = path.join(HOME, f);
        rows.push({
          cmd: f,
          state: existsSync(abs) ? "OK" : "MISSING",
          detail: existsSync(abs) ? abs : "absent",
        });
      }

      const ucksRoot = path.join(HOME, BUCKETS_ROOT);
      let buckets = [];
      try {
        buckets = readdirSync(ucksRoot, { withFileTypes: true })
          .filter((e) => e.isDirectory())
          .map((e) => path.join(ucksRoot, e.name))
          .filter((p) => existsSync(path.join(p, ".git")));
      } catch (err) {
        rows.push({ cmd: ".f/ucks", state: "FAIL", detail: err.message.split("\n")[0] });
      }
      for (const b of await Promise.all(buckets.map(bucket))) rows.push(b);

      // MIRROR BLINDNESS — a measured gate, not a source regex.
      // The creds daemon answers ONLY the exact key asked for, and a
      // provider-backed (vault) cred is stored under `mirror:<name>`. A uck that
      // falls back to a hand-rolled `daemonCall({op:"get",name})` therefore reads
      // a live vault credential as *unset* — which is how `f gh` told the
      // operator to store a token that already existed. A regex over the bucket
      // cannot decide this (fj/ha/grocy read lists through creds' own
      // `rawCredRead`, and CONTRACT C3 says an absent creds uck is EXPECTED to
      // read the socket), so ask the store directly instead.
      try {
        const { stdout: lsAll } = await run("f", ["creds", "ls", "--all"], {
          timeout: 30000,
          encoding: "utf8",
        });
        const mirrorOnly = (lsAll || "")
          .split("\n")
          .map((l) => l.match(/^(mirror:([^\t ]+))\s*\(mirror;/))
          .filter(Boolean)
          .map((m) => ({ key: m[1], name: m[2] }))
          .filter((m) => {
            // "mirror-only" means the bare key does not also exist locally.
            const bare = new RegExp("^" + m.name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\t", "m");
            return !bare.test(lsAll || "");
          });
        if (mirrorOnly.length) {
          // INFORMATIONAL, deliberately not FAIL/DEGRADED: a mirror-only shape is
          // the NORMAL result of a vault-backed cred, not a fault. RISK is the
          // layer's signal-to-kenny vocabulary; raising DEGRADED here would make
          // `f doctor` exit 1 forever on a healthy box and train everyone to
          // ignore the exit code — a gate that calls healthy tools broken is
          // worse than no gate. Consumers are judged by `f doctor <uck>`.
          rows.push({
            cmd: "creds-mirror-shape",
            state: "INFO",
            detail: `${mirrorOnly.length} cred(s) resolve ONLY as \`mirror:<name>\` (${mirrorOnly.map((m) => m.name).join(", ")}) — the daemon answers exact keys, so a consumer reading the bare key (or a hand-rolled socket client that skipped creds' rawCredRead) sees these as UNSET. gh/ssh/ha verified mirror-aware.`,
          });
        }
      } catch {
        /* creds unreachable: the vault row above already answered */
      }

      // A probe that cannot run must never report a healthy layer.
      if (rows.length === 0) {
        rows.push({
          cmd: "doctor",
          state: "FAIL",
          detail: "no checks ran — cannot claim the layer is healthy",
        });
      }
      const bad = rows.filter((r) => r.state !== "OK" && r.state !== "INFO");
      const health = bad.length ? "DEGRADED" : "HEALTHY";
      if (json) {
        emit({
          mode: "layer",
          health,
          ok: rows.length - bad.length,
          total: rows.length,
          generatedAt: new Date().toISOString(),
          home: HOME,
          rows,
        });
      } else {
        for (const r of rows) console.log(`${r.state}\t${r.cmd}\t${r.detail}`);
        console.log(
          `${health}\t${rows.length - bad.length}/${rows.length} checks ok` +
            (bad.length ? ` — trust only the OK rows this run` : ""),
        );
      }
      process.exitCode = bad.length ? 1 : 0;
    },
    skills: [
      {
        name: "f-doctor",
        path: path.join(path.dirname(fileURLToPath(import.meta.url)), "SKILL.md"),
      },
    ],
  };
}

export default { register };
