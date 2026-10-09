---
name: f-fj
description: Call the Forgejo/Gitea API via `f fj` (issues, PRs, pipelines) instead of raw curl or the fj CLI. Uses the token from f creds.
---

# f fj — Forgejo/Gitea API

`f fj` wraps the @llamaduck/forgejo-ts SDK (all 491 /api/v1 endpoints). Run it **inside a clone** of the instance: the base URL is resolved from the git origin, and the token comes from `f creds` under the instance host name.

## Auth (once per machine)

```
f creds unlock            # if locked (daemon holds the scrypt+AES-GCM key)
f creds set forgejo.kensand.net <token>
```

## Commands

```
f fj ls [query]                  list/search endpoint names (491)
f fj call <name> [json]          call a named endpoint; json = {key:val, body:{...}}
f fj call <name> -f file         read params from file
f fj <METHOD> <path> [json]      raw call, e.g. GET /repos/<org>/<repo>
f fj whoami                      userGetCurrent (needs auth)
f fj urls                        show resolved base url + token source
f fj runs [newest|<id>]          list/show action runs
f fj joblogs <id> [grep]         download + grep a run's job logs
f fj pr check [number]           PR + CI status (default: PR of head branch)
f fj pr merge [number] [-m s]    merge a PR (squash|merge|rebase, default squash)
f fj pr status <sha|ref>         commit CI status (e.g. HEAD, origin/main)
f fj pr open                     list open PRs of the current repo
```

`runs`, `joblogs`, and `pr` take `--repo <owner>/<repo>` to target a repo other than the current git origin.

`json` arg: flat keys map to path/query params; a `body` key is the request body.

## Common replacements

| Raw | f fj |
| --- | --- |
| did this PR's CI pass? | `f fj pr check` (no number = PR of your branch) |
| merge a PR | `f fj pr merge <n>` |
| CI status of a commit | `f fj pr status HEAD` |
| list open PRs on origin | `f fj pr open` (or `f fj call repoListPullRequests …`) |
| get a PR | `f fj call repoGetPullRequest {owner,repo,number}` |
| create/update an issue | `f fj call issueCreate {owner,repo,body:{title,body}}` |
| list repo issues | `f fj call issueList {owner,repo,state:"all"}` |

Find the exact endpoint name with `f fj ls <word>` when unsure (e.g. `f fj ls pipeline` for CI, `f fj ls issue` for issues).

## Gotchas

- No token: `f fj` fails immediately and says whether creds are locked or unset. Fix with `f creds unlock` / `f creds set <host> <token>`, or pass `--token <tok>`.
- `--url <base>` overrides the git-origin base (e.g. for a repo not on the instance you're standing in).
- `--wait [sec]` blocks until a cred appears (default 300s) — useful in jobs that start before a human unlocks creds.
