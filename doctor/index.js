// doctor/index.js — verify a capability layer actually answers, instead of trusting silence.
// Zero deps: node builtins only.
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readdirSync, existsSync, readFileSync } from "node:fs";
import path from "node:path";
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
const DIRS = [".pi/agent/memory", ".pi-web", ".f/ucks"];

// A degraded tool answers with plausible garbage, or says nothing at all. Both look
// like "fine" to a caller that only checks the exit code.
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
    desc: "is a tool/uck actually alive? probe commands, buckets, uck usage (degraded != error)",
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
      const rest = [...new Set([...tokens, ...(args?._ ?? []).map(String)])].filter(
        (s) => s !== "--help" && s !== "-h" && s !== "--all",
      );
      const home = process.env.HOME || "/";

      if (flag("help") || flag("h")) {
        // Reached only in-process: `f <uck> --help` is routed to `f help <uck>`, which
        // prints the desc, not this. Keep the usage in the desc too.
        process.stdout.write(
          "usage: f doctor [--all] [uck ...]\n" +
            "  f doctor              probe the capability layer (tools, dirs, buckets, creds)\n" +
            "  f doctor <uck>...     is a uck live? register() shape + does it print usage?\n" +
            "  f doctor --all        audit EVERY uck in the buckets for the SILENT contract\n" +
            "                        (a uck that returns results without writing stdout is mute)\n" +
            "exit: 0 healthy, 1 anything degraded. trust only the OK rows.\n",
        );
        return;
      }

      // `--all` closes the audit loop: instead of hand-listing every uck each run, audit
      // every uck in the buckets for the contract that causes silence.
      if (flag("all")) {
        const roots = [
          path.join(home, ".f/ucks/kensand-fcli-ucks"),
          path.join(home, ".f/ucks/official-ucks-src"),
          path.join(home, ".f/ucks/ucks"),
        ].filter((d) => existsSync(d));
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
        let bad = 0;
        for (const name of rest) {
          let found;
          for (const bucketDir of [
            path.join(home, ".f/ucks/kensand-fcli-ucks"),
            path.join(home, ".f/ucks/official-ucks-src"),
            path.join(home, ".f/ucks/ucks"),
          ]) {
            const p = path.join(bucketDir, name, "index.js");
            if (existsSync(p)) {
              found = { p, bucket: path.basename(bucketDir) };
              break;
            }
          }
          if (!found) {
            console.log(`MISSING ${name}\tno index.js in any bucket`);
            bad++;
            continue;
          }
          let shape;
          try {
            const mod = await import(`file://${found.p}`);
            if (typeof mod.register !== "function") {
              console.log(`FAIL\t${name}\tregister is not a function (${found.bucket})`);
              bad++;
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
            console.log(`FAIL\t${name}\timport: ${err.message.split("\n")[0]}`);
            bad++;
            continue;
          }
          if (shape.name !== name) {
            console.log(`FAIL\t${name}\tregister() name is ${JSON.stringify(shape.name)}`);
            bad++;
            continue;
          }
          if (shape.run !== "function") {
            console.log(`FAIL\t${name}\trun is ${shape.run}, not a function`);
            bad++;
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
          try {
            const src = readFileSync(found.p, "utf8");
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
            console.log(
              `FAIL\t${name}\treads args.${flagBlind.slice(0, 4).join("/")} but declares no argv hook and never tokenises raw argv, so those flags are always undefined (${found.bucket})`,
            );
            bad++;
            continue;
          }
          // The trap this uck exists for: a uck can be valid, registered and listed
          // in `f` and still answer nothing at the CLI. Probe the BARE invocation and
          // require content -- exit codes are useless here, because a failing CLI makes
          // `f` exit non-zero for reasons unrelated to the uck under test.
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
            console.log(
              `FAIL\t${name}\tregisters ok (${found.bucket}) but \`f ${name}\` ${errored || "exit 0"} and printed nothing — no usage path`,
            );
            bad++;
            continue;
          }
          const how = errored ? `no --help path; try \`f help ${name}\` (${errored})` : "prints usage";
          console.log(`OK\t${name}\t${JSON.stringify(shape.desc)} — ${how}: ${cli.split("\n")[0].slice(0, 50)}`);
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
          const expires = text.match(/mirror ttl\s+(\S+)/);
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
            rows.push({
              cmd: "creds",
              state: "OK",
              detail: `vault answers${expires ? `, mirror ttl ${expires[1]}` : ""}`,
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
        const abs = path.join(home, d);
        rows.push({
          cmd: d,
          state: existsSync(abs) ? "OK" : "MISSING",
          detail: existsSync(abs) ? abs : "absent",
        });
      }

      for (const f of FILES) {
        const abs = path.join(home, f);
        rows.push({
          cmd: f,
          state: existsSync(abs) ? "OK" : "MISSING",
          detail: existsSync(abs) ? abs : "absent",
        });
      }

      const ucksRoot = path.join(home, ".f/ucks");
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

      const bad = rows.filter((r) => r.state !== "OK");
      // A probe that cannot run must never report a healthy layer.
      if (rows.length === 0) {
        console.log("FAIL\tdoctor\tno checks ran — cannot claim the layer is healthy");
        process.exitCode = 1;
        return;
      }
      for (const r of rows) console.log(`${r.state}\t${r.cmd}\t${r.detail}`);
      console.log(
        `${bad.length ? "DEGRADED" : "HEALTHY"}\t${rows.length - bad.length}/${rows.length} checks ok` +
          (bad.length ? ` — trust only the OK rows this run` : ""),
      );
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
