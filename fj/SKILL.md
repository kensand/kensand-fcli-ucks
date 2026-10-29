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
f fj pr create [--head b] [--base b] [--title t] [--body text|-|--body-file p]
                                 open a PR. head = current branch, title = its last
                                 commit subject, base = origin/HEAD (else main).
                                 Fails if a PR is already open for the branch.
f fj pr merge [number] [-m s]    merge a PR (squash|merge|rebase, default squash)
f fj pr review [number] <approve|request-changes|comment> [-b text]
f fj pr status <sha|ref>         commit CI status (e.g. HEAD, origin/main)
f fj pr open                     list open PRs of the current repo
```

`runs`, `joblogs`, and `pr` take `--repo <owner>/<repo>` to target a repo other than the current git origin.

`json` arg: flat keys map to path/query params; a `body` key is the request body.

## Common replacements

| Raw | f fj |
| --- | --- |
| did this PR's CI pass? | `f fj pr check` (no number = PR of your branch) |
| open a PR for the current branch | `f fj pr create` (add `--body-file` for a long description) |
| merge a PR | `f fj pr merge <n>` |
| approve a PR | `f fj pr review <n> approve` |
| CI status of a commit | `f fj pr status HEAD` |
| list open PRs on origin | `f fj pr open` (or `f fj call repoListPullRequests …`) |
| get a PR | `f fj call repoGetPullRequest {owner,repo,number}` |
| create/update an issue | `f fj call issueCreate {owner,repo,body:{title,body}}` |
| list repo issues | `f fj call issueList {owner,repo,state:"all"}` |

Find the exact endpoint name with `f fj ls <word>` when unsure (e.g. `f fj ls pipeline` for CI, `f fj ls issue` for issues).

## Gotchas

- **Reviews: `event=APPROVED`, never `APPROVE`.** Approve and request-changes are
  the *same* endpoint — `POST /repos/{owner}/{repo}/pulls/{index}/reviews` (plus
  `.../reviews/{id}` for the two-step submit); there is no approve-only route, and
  the only difference between the two operations is the enum string. This instance
  speaks the Forgejo-native enum (`APPROVED | REQUEST_CHANGES | COMMENT`), not
  GitHub's `APPROVE`; `APPROVE` is rejected. Because the SDK throws the HTTP status
  away, a wrong enum looks like a silent no-op rather than a 422 — `pr review`
  confirms by reading back the stored `state`. Raw call, if you bypass the helper:
  `f fj POST /repos/<o>/<r>/pulls/<n>/reviews '{body:{event:"APPROVED"}}'`.
- No token: `f fj` fails immediately and says whether creds are locked or unset. Fix with `f creds unlock` / `f creds set <host> <token>`, or pass `--token <tok>`.
- **All creds access goes through `credsApi.resolveCred` — there is one
  interface, and it is not this uck's to reimplement.** `f fj` reads no
  `~/.f/.creds-daemon`, opens no `~/.f/.creds.sock`, and matches no creds error
  text; `resolveToken()` is a few lines that call creds and pass its
  `reason`/`credHint` through. That is the fix for a real split-brain: six ucks
  each kept a copy of creds' lockfile check, `f creds unlock --permanent` stores
  `ttl: null, permanent: true`, every copy tested `!lf.ttl` and declared a
  permanent session "expired at t=0" — so `f fj whoami` said `creds are locked`
  while `f creds status` beside it said `unlocked (permanent)`. If those two
  commands ever disagree again, the bug is that something reads the lockfile
  again; grep for `.creds-daemon` and delete it, do not add a second reader.
  Interface + rules: `creds/CONTRACT.md` §6.1 (C0).
- A permanently unlocked store **restarts its own daemon** after a reboot or OOM
  kill. `f fj` triggers that the same way `f creds ls` does, so a fresh boot needs
  no human. It never prompts: a store with no permanent unlock reports `locked`.
- `--url <base>` overrides the git-origin base (e.g. for a repo not on the instance you're standing in).
- `--wait [sec]` blocks until a cred appears (default 300s) — useful in jobs that start before a human unlocks creds.
