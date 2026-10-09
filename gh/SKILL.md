---
name: f-gh
description: Query and control GitHub via `f gh` (repos, issues, PRs, releases, search, raw REST) instead of curl or the `gh` CLI. Uses the token from f creds (gh-token).
---

# f gh — GitHub API

Token-efficient wrapper around the GitHub REST API via `@octokit/rest`. Terse output, one fact per line.

## Setup (once)

```
f creds set gh-token <personal-access-token>
```

The base URL defaults to `https://api.github.com`. For GitHub Enterprise, set
`f creds set gh "https://ghe-host/api/v3|<token>"` (combined cred) or
`GITHUB_URL` / `gh.baseUrl` in f.config.json.
`f gh info` shows auth + rate limit. If creds are locked: `f creds unlock`.

## Commands

```
f gh whoami                       current user
f gh info                         rate limit + auth status
f gh ls [query]                   list/search endpoint names
f gh repo [ls]                    list your repos / show current repo
f gh issue [ls|new|<n>]           list / create / show issues
f gh issue new title=... body=...
f gh pr [ls|<n>]                  list / show PRs
f gh release [ls|new]             list / create releases
f gh search <query> [--type repos|code]
f gh <METHOD> <path> [json]       raw REST, e.g. GET /repos/octocat/hello-world
```

Most commands take `--repo <owner>/<repo>`; by default they use the git origin
of the current directory, so `f gh issue` inside a clone targets that repo.

## Examples

- "what's the CI / latest PR on this repo" → `f gh pr`
- "open an issue" → `f gh issue new title="bug" body="details..."`
- "list releases" → `f gh release`
- "find repos matching x" → `f gh search x --type repos`
- "any endpoint not wrapped" → `f gh GET /repos/<o>/<r>/actions/runs`

## Notes

- `issue ls` defaults to `--state open`; pass `--state all` or `closed`.
- `pr ls` shows `#n state  title  head -> base  author`.
- The raw passthrough (`GET`/`POST`/…) covers the entire REST surface; the
  wrapped commands are just the common ones. `f gh ls` lists the catalog.
- Token precedence: `--token` > `GITHUB_TOKEN` > creds (`gh-token`,
  `github-token`, or combined `gh`).
