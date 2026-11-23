// doctor/index.js — verify a capability layer actually answers, instead of trusting silence.
// Zero deps: node builtins only.
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readdirSync, existsSync, readFileSync } from "node:fs";
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

      // Half-degraded credential layer: cache masks a dead issuer until the cache dies.
      if (seen.has("f")) {
        try {
          const { stdout } = await run("f", ["vaultwarden", "status"], {
            timeout: 30000,
            encoding: "utf8",
          });
          const text = stdout || "";
          const refused = /token refresh failed|session failed|HTTP 400/.test(text);
          if (refused) {
            rows.push({
              cmd: "creds",
              state: "RISK",
              detail:
                "vault re-auth refused (HTTP 400) — cached mirrors still resolve, so " +
                "Forgejo/GitHub patrol LOOKS green and goes dark when the cache expires. " +
                "Do not retry login (lockout risk); needs operator `f vaultwarden config`",
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
              const expired = mirrors.filter((m) => m.at <= now);
              const soon = mirrors.filter((m) => m.at > now && m.at - now < 48 * 3600 * 1000);
              if (expired.length) {
                rows.push({
                  cmd: "creds-mirror",
                  state: "RISK",
                  detail: `${expired.length} provider mirror(s) EXPIRED (${expired.map((m) => m.name.replace("mirror:", "")).join(", ")}) — anything depending on them resolves only until the value is re-fetched`,
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

      // A probe that cannot run must never report a healthy layer.
      if (rows.length === 0) {
        rows.push({
          cmd: "doctor",
          state: "FAIL",
          detail: "no checks ran — cannot claim the layer is healthy",
        });
      }
      const bad = rows.filter((r) => r.state !== "OK");
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
