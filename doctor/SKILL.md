---
name: f-doctor
description: Check whether a tool or uck is actually alive before trusting its output. Use when a command returns empty/plausible garbage, a flag seems silently ignored, a daemon-probed tool says "requires X", or before `f up` in a uck bucket — `f doctor` probes commands, creds, buckets and ucks and exits 1 on anything degraded.
---

# f doctor

A degraded tool returns **plausible garbage, not errors**. `f doctor` asserts that each
dependency answers with real data, and treats "said nothing" as a first-class failure
instead of a pass. Use it at the start of unattended/automated work, and before
trusting any observation you did not make in this run.

```
f doctor              # capability layer: tools, dirs, git buckets, credential health
f doctor --all        # audit EVERY uck in every bucket (22 ucks, ~90s: forks one CLI each)
f doctor ha-ws kuma   # is a specific uck actually live?
```

Exit `0` = everything answered. Exit `1` = something is degraded; trust only the `OK` rows.

## States

| State | Meaning | Do |
| --- | --- | --- |
| `OK` | Answered with real content | Trust this run only |
| `SILENT` | Exit 0, **empty output** | Do not read this as success. Reproduce by invoking directly. |
| `FAIL` | Non-zero / threw / timed out, or a uck violates the output/flag contract | Record as a tool failure, not as data about the world |
| `MISSING` | Not on PATH / dir absent | Check *whose* PATH probed it before concluding "not installed" |
| `RISK` | Bucket `f up` would reset away, or credentials that will expire | Fix before it becomes an outage |

## The four traps this exists for

1. **`SILENT` is not `OK`.** A uck can pass `f uck check`, appear in the `f` command
   table, and still print literally nothing with exit 0. f's dispatcher does
   `const result = await uck.run(...)` and only reads a **number** return, so a uck that
   *returns* its result strings instead of writing stdout is mute on every path (`ha-ws`
   did exactly this). Only a content check catches it: `f doctor <uck>`.
2. **A flag can be silently ignored — which is worse than silence, because the output
   looks fine.** f hands a uck `run(rest, args, ctx)` where
   `args = uck.argv?.(rest) ?? { _: rest }`. Unless the uck declares an `argv:` hook
   (CONTRACT §2.3 — no uck in either bucket does), **`args` is just `{ _: rawArgv }`**:
   `--json` is a token in `args._`, and `args.json` is `undefined` forever. Such a uck
   answers the *default* question and exits 0. `f doctor --all` flags this class as `FAIL`.
   Correct shapes: tokenise the raw argv (`parseTokens`/`parseArgv`, or compare
   `=== "--json"`), or declare `argv:`.
3. **`MISSING` usually means the wrong PATH, not a missing package.** A long-lived
   daemon captures its environment at launch, so a tool installed afterwards is invisible
   to the daemon's own probes while resolving fine in your shell. Availability is often
   cached per process — re-check in a fresh session.
4. **Credentials are HALF-DEGRADED by default.** `f doctor` runs `f vaultwarden status`
   (never `list`/`get`: those can trigger a login, and a 400 repeated enough can lock the
   account). When re-auth is refused while cached mirror tokens still resolve, the row is
   `RISK`: Forgejo/GitHub patrol **looks green** and goes dark when the cache expires.

## What `--all` does NOT claim

It asks whether a uck **receives** flags, not whether it parses them correctly, and it
never proves a subcommand returns true data. An all-`OK` run means "every uck answers and
nothing is structurally mute or flag-blind" — nothing more. Per-subcommand correctness is
still your job.

## Test a probe against known-bad AND known-good before trusting it

The first version of the flag-blindness check contained an inline-backtick character class
in a regex literal; it matched nothing, so **every uck passed and the gate was silently
broken**. That is the same bug class the uck exists to detect, reproduced inside the
detector. Before believing an all-`OK` audit, drop two throwaway ucks into a bucket and
confirm each bug class is caught:

```bash
cd ~/.f/ucks/kensand-fcli-ucks
mkdir -p fbad1 fbad2
printf 'export function register(_c){return {name:"fbad1",desc:"d",run:async()=>{return "prints nothing";}};}\nexport default {register};\n' > fbad1/index.js
printf 'const U="usage: f fbad2 <cmd>\\n  --json   structured\\n";\nexport function register(_c){return {name:"fbad2",desc:"d",run:async(_a,args)=>{if(args.json){console.log("[]");return 0;}console.log(U);return 0;}};}\nexport default {register};\n' > fbad2/index.js
f doctor fbad1 fbad2   # expect TWO FAIL rows (mute, flag-blind) — then:
rm -rf fbad1 fbad2
```

Also re-run every terminal path of the thing you changed: `f doctor --help`,
`f doctor --all`, `f doctor <uck>`, and bare `f doctor`. Usage handling that sits before
the main block is the path people miss.

## Buckets (`RISK`)

`f up` resets every clean git bucket to origin. `f doctor` flags the state that actually
destroys work: a bucket checked out on a branch with **no upstream**, detached at a remote
tip, behind origin, or holding unpushed commits. Fix the branch state before running `f up`.
Never force-push or rewrite history.
