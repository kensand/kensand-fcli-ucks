---
name: f-doctor
description: Check whether a tool or uck is actually alive before trusting its output. Use when a command returns empty/plausible garbage, a daemon-probed tool says "requires X", or before `f up` in a uck bucket — `f doctor` probes commands, buckets and ucks and exits 1 on anything degraded.
---

# f doctor

A degraded tool returns **plausible garbage, not errors**. `f doctor` asserts that each
dependency answers with real data, and treats "said nothing" as a first-class failure
instead of a pass. Use it at the start of unattended/automated work, and before
trusting any observation you did not make in this run.

```
f doctor              # probe the capability layer: tools, dirs, git buckets
f doctor ha-ws kuma   # is a specific uck actually live?
```

Exit `0` = everything answered. Exit `1` = something is degraded; trust only the `OK` rows.

## States

| State | Meaning | Do |
| --- | --- | --- |
| `OK` | Answered with real content | Trust this run only |
| `SILENT` | Exit 0, **empty output** | Do not read this as success. Reproduce by invoking directly. |
| `FAIL` | Non-zero / threw / timed out | Record as a tool failure, not as data about the world |
| `MISSING` | Not on PATH / dir absent | Check *whose* PATH probed it before concluding "not installed" |
| `RISK` | Bucket `f up` would reset away | Publish or stop before `f up` |

## The two traps this exists for

1. **`SILENT` is not `OK`.** A uck can pass `f uck check`, appear in the `f` command
   table, and still print literally nothing for `--help` and bare invocation with exit
   code 0 (`f ha-ws` on this machine does exactly that). Only a content check catches it:
   ```
   f doctor ha-ws
   ```
2. **`MISSING` usually means the wrong PATH, not a missing package.** A long-lived
   daemon captures its environment at launch, so a tool installed afterwards is invisible
   to the daemon's own probes while resolving fine in your shell. Before concluding
   "not installed", compare `command -v X` here against the daemon's PATH, and remember
   availability is often cached per process — re-check in a fresh session.

## Buckets (`RISK`)

`f up` resets every clean git bucket to origin. `f doctor` flags the state that actually
destroys work: a bucket checked out on a branch with **no upstream**, detached at a remote
tip, behind origin, or holding unpushed commits. Fix the branch state before running `f up`.
Never force-push or rewrite history.
