---
name: f-vaultwarden
description: Read credentials from a Vaultwarden/Bitwarden server with a zero-dep native client, and serve them to `f creds` as a provider on a local miss. Trigger - a secret lives in the vault, or `f creds get <name>` says "no such cred" for something that exists in Vaultwarden.
---

# Vaultwarden as a credential source

`f vaultwarden` talks to a Vaultwarden (Bitwarden-compatible) server directly —
no `bw` binary, no npm deps, just `node:crypto` and `fetch`. It is wired into
`f creds` as a **provider**: `f creds get <name>` checks the local encrypted
store first and only falls through to the vault on a miss, mirroring a successful
hit locally under a TTL.

The thing to internalise: **the master password does two jobs.** It is the login
credential *and* the key that unlocks the vault. An API key does neither — it
only exists to get past 2FA — so it is **optional**, and you do not need one when
2FA is off.

Login is tried as password-grant-first, API-key-fallback. Scope rules are
per-grant and were probed against a live server with a nonexistent account: the
password grant needs `api offline_access` (bare `api` is rejected outright),
while `client_credentials` needs exactly `api`. So **a "Scope ... not supported"
error is this uck's bug, not your credentials** — report it rather than retyping
a correct password.

One secret does remain: the master password lives inside the `f creds` box
(`vaultwarden.master-password`), so the vault cannot bootstrap itself — `f creds
unlock` must come from something else.

## Setup (once)

```
f vaultwarden config --server https://vault.example.com --email you@example.com
f vaultwarden config --master-password             # prompts, no echo
f vaultwarden test                                 # login + decrypt + report

# only if the account has 2FA on -- the password grant cannot satisfy it from a CLI:
f vaultwarden apikey <client-id> <client-secret>   # web vault: Settings > API Key
```

`f vaultwarden test` is the thing to run first: it authenticates, unwraps the
symmetric key, decrypts a sample item, and prints counts. It changes nothing. If
it passes, everything below works; if it fails, its message names the stage.

Non-secret config goes in `f.config.json` under `vaultwarden`. Secrets go in the
creds box. Never in argv-visible places.

## Resolving a secret

```
f creds get github.com          # local store first, vault on miss
f vaultwarden get github.com    # go straight to the vault, skip the mirror
f vaultwarden get 'My Item::username'
f vaultwarden list --search git
```

Name forms: an item **name** (`My Item`), an item **id**, a **host** from an
item's URIs (`github.com`), or a **map key** (see below). Append `::field` for
anything but the password — `username`, `totp`, `note`, `uri`, `field:<name>`.

Host names are the reason `f creds get github.com` works without any map entry:
the URIs attached to a vault item are harvested as candidate names.

## When two items share a name

Vaultwarden item **names are not unique**; ids are. If two items are both called
`github.com`, resolution refuses rather than picking one, and prints both with
their ids and available fields. Pin it deterministically:

```
f vaultwarden map github.com 'aaaaaaaa-1b2c-…::password'
f vaultwarden map gh-work   'bbbbbbbb-3d4e-…::username'
```

Point map targets at **ids** when names collide. A map target that is still
ambiguous is reported as an error, never resolved by first match.

## Mirrors, TTL, and staleness

A vault hit is stored as `mirror:<name>` so repeat reads are fast and work with
the vault unreachable. Defaults: 3600s TTL, and a 300s **negative** cache so an
unknown name does not hammer the server on every call.

```
f creds get <name> --provider         # force a fresh vault read, ignore the mirror
f creds get <name> --no-provider      # local store only (fails if only in the vault)
f vaultwarden cache                   # is the derived key cached? how old?
f vaultwarden cache --clear           # drop it (forces PBKDF2 re-derivation)
f vaultwarden forget                  # key cache + cached tokens
```

Because a mirror is a copy of a secret sitting in the same encrypted box, treat
`f creds rm mirror:<name>` as a real secret-deletion operation.

## Plaintext http

Refused by default. Both the master-password hash and the API key travel in
request bodies, so plain http is a credential leak on any network you do not
fully control. For a genuinely loopback/LAN/tailscale-only server:

```
"vaultwarden": { "allowInsecureHttp": true }
```

The error names whether the host is loopback before you decide.

## How it works, and why

Crypto chain, implemented against `node:crypto` (verified with RFC 5869 / RFC
6070 vectors in `test/crypto.test.mjs`):

1. `PBKDF2-HMAC-SHA256(masterPassword, email, iterations)` → master key.
   Iterations come from `/identity/accounts/prelogin` (usually 600000). The salt
   is the **email alone** — not email+password.
2. `HKDF-Expand-SHA256(masterKey, "enc")` and `(..., "mac")` → the two keys that
   unwrap the account's symmetric key from `profile.key`.
3. `masterPasswordHash = HMAC-SHA256(masterKey, password)` → what the token
   endpoint receives for the password grant. The password itself never leaves.
4. Every field is `type.iv|ciphertext|mac`: AES-256-CBC, verified with
   HMAC-SHA256 over `iv||ciphertext` **before** returning a value.

MAC failure is an error, never empty-string-or-garbage. Type-0 (unencrypted)
envelopes are returned as plaintext; type-1 (no MAC) is refused by default.

Cached derived keys mean a read does not redo a ~1s PBKDF2 every time. A cached
token that comes back 401/403 is refreshed once if a refresh token was stored,
then the cache is discarded — a network error is *not* treated as a reason to
re-derive and retry.

## Writing

Only `set-totp` writes, and only to the item you name. It re-encrypts with the
item's own key and PUTs the ciphertext back. Read-only is the default everywhere
else; nothing in the resolution path can mutate the vault.

## Tests

```
node test/crypto.test.mjs    # 27: crypto vectors, envelope handling, error shapes
node test/e2e.test.mjs       # 30: whole provider ladder vs a mock Vaultwarden
```

`e2e.test.mjs` spins up a real `f creds` daemon in a throwaway `HOME` and a mock
Vaultwarden that enforces the real server's rules (it rejects `scope != api`,
demands `device_identifier`/`device_name`, 400s a form-encoded prelogin, and
answers with Vaultwarden's camelCase error bodies). The master password never
leaves the store during the run, so a broken key derivation fails the suite
rather than being papered over. Both are offline and touch nothing real.

They do **not** cover: real TLS, org/collection ciphers, attachments, 2FA flows,
or your actual KDF. `f vaultwarden test` covers those against the live server.

## Troubleshooting

| message | meaning |
|---|---|
| `master password is wrong` | MAC check failed on the symmetric-key unwrap. Re-run `config --master-password`. Not a network problem. |
| `no server configured` | run `config --server/--email` |
| `Scope not supported` | server rejects the OAuth scope; current code sends `scope=api` (verified live) |
| `device_identifier cannot be blank` | server wants snake_case device fields; current code sends both spellings |
| `Too many login requests` (429) | rate-limited; **stop retrying**, it extends the lockout |
| `requires 2FA` | the password grant hit a 2FA policy. Add an API key (`apikey`) — bypassing 2FA is its only purpose. |
| `Scope ... not supported` | a bug in this uck, not in your account: scope rules differ per grant (see above). Report it. |
| `unrecognised response shape` | your server returns something unexpected — the error lists its keys, and it deliberately refuses to read that as an empty vault |
| `the creds store is locked` | `f creds unlock` — the vault cannot be consulted or written to while locked |

If `f providers` does not list `vaultwarden`, the uck failed to load: run
`f vaultwarden status` and read the error.
