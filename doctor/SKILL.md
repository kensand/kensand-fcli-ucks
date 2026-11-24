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
f doctor ha kuma      # is a specific uck actually live?
f doctor --json       # machine-readable: one JSON object, {mode,health,ok,total,rows}
```

Exit `0` = everything answered. Exit `1` = something is degraded; trust only the `OK` rows.

## `--json` shape

`f doctor --json` prints exactly **one** JSON object on stdout (nothing on stderr) and never
mixes prose into it. With `--all` it is `{mode:"ucks",…}`, otherwise `{mode:"layer",…}`:

```jsonc
{ "mode": "layer", "health": "DEGRADED", "ok": 13, "total": 15,
  "generatedAt": "…", "home": "/home/kenny",
  "rows": [ { "state": "RISK", "cmd": "creds", "detail": "…" } ] }
```

**Branch on `.state`, never on whether a row is present** — `state` is the verdict and every
check always emits a row. Uck rows add `bucket`, `skills`, `jsonMode`, and `verified`, which
states honestly what was checked ("bare invocation + static source gates") so an `OK` row is
never mistaken for "every flag of this uck works".

## States

| State | Meaning | Do |
| --- | --- | --- |
| `OK` | Answered with real content | Trust this run only |
| `SILENT` | Exit 0, **empty output** | Do not read this as success. Reproduce by invoking directly. |
| `FAIL` | Non-zero / threw / timed out, or a uck violates the output/flag contract | Record as a tool failure, not as data about the world |
| `MISSING` | Not on PATH / dir absent | Check *whose* PATH probed it before concluding "not installed" |
| `RISK` | Bucket `f up` would reset away, or credentials that will expire | Fix before it becomes an outage |
| `INFO` | A shape worth knowing that is **not** a fault (e.g. mirror-only creds) | Read it; it never changes the exit code |

## The five traps this exists for

1. **`SILENT` is not `OK`.** A uck can pass `f uck check`, appear in the `f` command
   table, and still print literally nothing with exit 0. f's dispatcher does
   `const result = await uck.run(...)` and only reads a **number** return, so a uck that
   *returns* its result strings instead of writing stdout is mute on every path (a uck
   of ours did exactly this, and the fix commit is the only record of which one — name
   the MECHANISM here, not a uck that may not exist next month). Only a content check
   catches it: `f doctor <uck>`.
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
5. **A flag that is *recognised* but not *honoured* is still flag blindness.** This uck
   shipped that bug: `--all` was stripped from the target list but `--json` was not, so
   `f doctor --json` resolved the string `--json` as a **uck name** and printed a fabricated
   `MISSING --json  no index.js in any bucket` row, while `f doctor --all --json` mixed free
   text with JSON. A flag must change the output **shape**, not merely survive parsing. Every
   accepted flag belongs in the strip list *and* in an output branch. `f doctor --all` now
   gates this class: any uck documenting `--json` must reach a JSON serializer on stdout.

## What `--all` does NOT claim

It asks whether a uck **receives** flags, not whether it parses them correctly, and it
never proves a subcommand returns true data. An all-`OK` run means "every uck answers and
nothing is structurally mute or flag-blind" — nothing more. Per-subcommand correctness is
still your job.

It also cannot **execute** a flag. Each uck gets exactly one probe — the **bare** invocation
— because a flagged probe could mutate real state and `f <uck> --help` is routed to
`f help <uck>` instead of reaching the uck. So the `--json` check is a static source gate, and
`verified` on each uck row records that limit. Do not upgrade "it parses flags" into "its
flags work".

## Test a probe against known-bad AND known-good before trusting it

The first version of the flag-blindness check contained an inline-backtick character class
in a regex literal; it matched nothing, so **every uck passed and the gate was silently
broken**. Every later revision of the `--json` gate also failed **in the opposite direction**:
three guard-matching variants each false-failed healthy ucks, because the buckets use three
different flag idioms (`if (flags.json)`, `has(argv,"--json")` with the serializer in a
helper, `const dump = a.includes("--json")` feeding a later branch). A gate that calls healthy
tools broken is worse than no gate — so the shipped test is deliberately coarse (can this uck
serialize JSON to stdout at all?). Fuzz both directions: a known-bad fixture **must** FAIL,
and every real uck **must** PASS.

Before believing an all-`OK` audit, drop two throwaway ucks into a bucket and
confirm each bug class is caught:

```bash
cd ~/.f/ucks/kensand-fcli-ucks
mkdir -p fbad1 fbad2 fbad3
printf 'export function register(_c){return {name:"fbad1",desc:"d",run:async()=>{return "prints nothing";}};}\nexport default {register};\n' > fbad1/index.js
printf 'const U="usage: f fbad2 <cmd>\\n  --json   structured\\n";\nexport function register(_c){return {name:"fbad2",desc:"d",run:async(_a,args)=>{if(args.json){console.log("[]");return 0;}console.log(U);return 0;}};}\nexport default {register};\n' > fbad2/index.js
# recognised flag, no serializer anywhere -> must FAIL the --json gate
printf 'export function register(_c){return {name:"fbad3",desc:"d",run:async(a)=>{if((a||[]).includes("--json")){process.stdout.write("here is your json!\\n");return 0;}process.stdout.write("default\\n");return 0;}};}\nexport default {register};\n' > fbad3/index.js
f doctor fbad1 fbad2 fbad3   # expect THREE FAIL rows (mute, flag-blind, fake --json) — then:
rm -rf fbad1 fbad2 fbad3
f doctor ddg doctor grafana kuma slop creds providers   # expect 7 OK (false-positive control)
```

A fixture whose `register().name` does not match its directory fails the **name** check and
never reaches the gate under test — make them match or you will "verify" nothing.

Also re-run every terminal path of the thing you changed: `f doctor --help`,
`f doctor --all`, `f doctor <uck>`, and bare `f doctor`. Usage handling that sits before
the main block is the path people miss.

## Credential key shapes (`INFO creds-mirror-shape`)

The creds daemon answers **only the exact key asked for**, and a provider-backed
(vaultwarden) cred is stored under `mirror:<name>`. So a credential can be live and
printable via `f creds get <name>` while a **bare** store read of it is a MISS. Measured
on this store:

```
gh-token   bare=true  mirror=false     (local)
ha-token   bare=true  mirror=false     (local)
gh-fcli    bare=false mirror=true      (mirror-only)
npm-token  bare=false mirror=true      (mirror-only)
```

That asymmetry is how `f gh` once told the operator to store a GitHub token that already
existed: its fallback was a hand-rolled `daemonCall({ op: "get", name })` on the bare key.
`f doctor` prints the mirror-only set as `INFO` — **informational, never `DEGRADED`**,
because mirror-only is the normal shape of a vault cred and a gate that exits 1 on a
healthy box teaches everyone to ignore the exit code.

Consumer rule: ask creds' own `resolveCred` first (CONTRACT §6.1), and if you must read the
socket, read **both** `name` and `mirror:name`. `gh`, `ssh` and `ha` are verified
mirror-aware. A single miss is weak evidence, not proof of absence.

## Redaction surface (`creds-redaction`) and proving a branch that needs a locked store

The creds CLI **redacts by default**: bare `f creds get <name>` prints
`[redacted — pass --secrets to reveal]` — 37 characters but **39 bytes**, because the em-dash
is 3 bytes — and exits 0 whether or not the subject is a secret. So "how many bytes does this cred yield?" measures the wrapper, never the value — and
`f creds get X | f creds set X` once stored that placeholder as a live credential, after which
every consumer died on code 8212 (the em-dash). The gate probes a few local names **bare** (what
a script pipes) and cross-checks each against the creds **socket**, which answers structurally.

A row here is one of: `INFO` (they all print the placeholder — expected, nothing broken),
`RISK` (a cred resolves on the socket but the CLI hands back a tiny non-placeholder string), or
`FAIL` (**could not list local creds at all** — the gate did not run, which is never a pass).

The `FAIL` case needs a locked or unreachable store, which no harness can create without
mutating the real one. `F_CREDS_LOCK_DIAG=1` substitutes that rejection at the call site so the
branch is provable; no production path sets it. Test it the way the bug was found — patch the
`f creds ls --all` call to reject with empty `stdout` and the reason on `stderr` in **both** the
shipped file and a baseline copy of it, then compare rows. Baseline answered **zero
`creds-redaction` rows** (a swallowed rejection is indistinguishable from a healthy box);
shipped code answers the `FAIL` row. Any gate whose failure path is only reachable via a state
you cannot produce is a gate you cannot test — make the unreachable state injectable instead.

## Patrol channels (`patrol-channels`)

Every patrol lane resolves its server through a **name** before it touches the service, and a
name can die while the service is perfectly healthy. `f ha` went dark for a whole heartbeat
this way: `homeassistant.local` is mDNS-only (RFC 6762), never sent to unicast DNS, and this
box has no mDNS responder — so `f ha ls` answered `fetch failed` and read like an HA outage
while HA was up at `10.1.5.5:8123` and `f kuma watch` reported 26/27 UP. Neither the creds
rows (does a SECRET resolve) nor the service rows (does an ENDPOINT answer) can see this,
and "host unresolvable" and "service down" need different fixes.

So this gate asks `getent ahosts <host>` for each lane's resolved base (`ha urls`, `mqtt
urls`, a `grafana-host` cred read, kuma's configured default) and reports:

- **`RISK` host does not resolve** — check DNS, or mDNS for a `.local` name. NOT an outage.
- **`RISK` could not read the configured base** — the lane's command FAILED, which means a
  broken tool or an unreadable cred. That is deliberately NOT reported as "unconfigured":
  `execFile` rejects on non-zero and leaves `e.stdout` empty, so a stdout-only gate would
  silently rename "broken" into "not set up".
- **`INFO` N hosts resolve** — name resolution only; it never claims the service answered.

It **emits unconditionally**, because a gate that prints a row only when it finds something is
indistinguishable from a gate that never ran. It asks only for the HOST, never the credential:
the `urls`-shaped verbs print a resolved base and return before connecting, and grafana's base
is a cred/env/default read with no HTTP call — so running this gate can never trip a service
write or a vault login.

Consequence worth remembering: **a patrol baseline is a claim about its transport.** While a
lane's host is unresolvable, every number measured through it is a quotation, not evidence.

## Buckets (`RISK`)

`f up` resets every clean git bucket to origin. `f doctor` flags the state that actually
destroys work: a bucket checked out on a branch with **no upstream**, detached at a remote
tip, behind origin, or holding unpushed commits. Fix the branch state before running `f up`.
Never force-push or rewrite history.
