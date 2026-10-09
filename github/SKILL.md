---
name: f-github
description: Query and control GitHub via `f github` (repos, issues, PRs, releases, search, raw REST) instead of curl or the `gh` CLI. Uses the token from f creds (gh-token).
---

# f github — GitHub API

Token-efficient wrapper around the GitHub REST API via `@octokit/rest`. Terse output, one fact per line.

## Setup (once)

```
f creds set gh-token <personal-access-token>
```

The base URL defaults to `https://api.github.com`. For GitHub Enterprise, set
`f creds set gh "https://ghe-host/api/v3|<token>"` (combined cred) or
`GITHUB_URL` / `gh.baseUrl` in f.config.json.
`f github info` shows auth + rate limit. If creds are locked: `f creds unlock`.

## Commands

```
f github whoami                       current user
f github info                         rate limit + auth status
f github ls [query]                   list/search endpoint names
f github repo [ls]                    list your repos / show current repo
f github issue [ls|new|<n>]           list / create / show issues
f github issue new title=... body=...
f github pr [ls|<n>]                  list / show PRs
f github release [ls|new]             list / create releases
f github search <query> [--type repos|code]
f github <METHOD> <path> [json]       raw REST, e.g. GET /repos/octocat/hello-world
```

Most commands take `--repo <owner>/<repo>`; by default they use the git origin
of the current directory, so `f github issue` inside a clone targets that repo.

## Examples

- "what's the CI / latest PR on this repo" → `f github pr`
- "open an issue" → `f github issue new title="bug" body="details..."`
- "list releases" → `f github release`
- "find repos matching x" → `f github search x --type repos`
- "any endpoint not wrapped" → `f github GET /repos/<o>/<r>/actions/runs`

## Notes

- `issue ls` defaults to `--state open`; pass `--state all` or `closed`.
- `pr ls` shows `#n state  title  head -> base  author`.
- The raw passthrough (`GET`/`POST`/…) covers the entire REST surface; the
  wrapped commands are just the common ones. `f github ls` lists the catalog.
- Token precedence: `--token` > `GITHUB_TOKEN` > creds (`gh-token`,
  `github-token`, or combined `gh`).
