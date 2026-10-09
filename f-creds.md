---
name: f-creds
description: Store and use credentials via `f creds` (scrypt+AES-GCM, daemon+socket, ttl) instead of env vars or echoing secrets.
---

# f creds — credential store

Encrypted credential store (scrypt+AES-GCM). A local daemon holds the key in memory; commands talk to it over a socket. Never write secrets to env vars, files, or command output.

## Commands

```
f creds unlock [passkey] [--ttl sec]   start daemon (default ttl 600s)
f creds lock                            stop daemon, zeroize key
f creds status                          locked / unlocked + time left
f creds set <name> <value>              store a cred
f creds get <name> [--secrets]          print a cred (redacted without --secrets)
f creds request <name> [--timeout sec]  block until the cred is set elsewhere
f creds waiters                         list open waiting requests (other terminals)
f creds fill [name]                     prompt + set value(s) for open waiters
f creds ls                              list names
f creds rm <name>                       remove a cred
```

## Conventions

- Name a cred after what it authenticates: `forgejo.kensand.net` for a Forgejo token, `github.com` for a GitHub token, `npmjs.com` for an npm token. `f fj` looks up the cred named after the resolved base-URL host.
- Before using a cred programmatically, check `f creds status`; if locked, `f creds unlock` (asks for the passkey) — or `f creds request <name>` to block until a human runs `f creds fill`.
- In long-lived jobs: `f fj --wait` already blocks for the cred.

## Anti-patterns

- `export FORGEJO_TOKEN=...` in a script — the token ends up in shell history and process lists.
- `curl -H "Authorization: Bearer $(cat ~/.token)"` — read the value via `f creds get` only inside the same `f` invocation (e.g. `f fj` does this internally); do not print secrets with `--secrets` unless the user explicitly asks.
