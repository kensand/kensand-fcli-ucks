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

The one thing to internalise: **an API key alone cannot decrypt a vault.** API
keys authenticate; the master password is what unlocks the cryptography. So this
uck needs *both*, and the master password is itself kept inside the `f creds`
box (`vaultwarden.master-password`) — the vault cannot bootstrap itself.

## Setup (once)

```
f vaultwarden config --server https://vault.example.com --email you@example.com
f vaultwarden apikey <client-id> <client-secret>   # from the web vault: Settings > API Key
f vaultwarden config --master-password             # prompts, no echo
f vaultwarden test                                 # login + decrypt + report
```

`f vaultwarden test` is the thing to run first: it authenticates, unwraps the
symmetric key, decrypts a sample item, and prints counts. It changes nothing. If
it passes, everything below works; if it fails, its message names the stage.

Non-secret config goes in `f.config.json` under `vaultwarden`. Secrets go in the
creds box. Never in argv-visible places.

## SSO (OIDC) — supported, but it does not replace the master password

```sh
f vaultwarden sso status                     # does the server support it?
f vaultwarden sso login                      # browser flow, then caches key material
f vaultwarden sso login --force              # skip the "is SSO enabled" probe
f vaultwarden sso login --port 8065 --timeout 120
```

Implemented, tested, and worth having: SSO gets you in when the server runs
`SSO_ENABLED=true` with `SSO_ONLY=true` (which refuses password logins outright), and it
yields a **`refresh_token`** so the session renews for ~30 days without a browser. An API
key does neither — `client_credentials` grants return no refresh token, so an API-key
session can only be re-established by a fresh login.

**It does not remove the master password.** SSO replaces *authentication*; the vault key is
still wrapped in a key derived from the master password, which no SSO token carries. The
code reads `UserDecryptionOptions.HasMasterPassword` from the token response and asserts
the requirement rather than assuming it. When an account genuinely has no master password,
the error says so and does **not** tell you to configure one — the missing piece is a
registered device key pair, which this uck cannot enrol.

If the actual goal is *unattended* credentials, the API-key path already provides it:
store `vaultwarden.master-password` in the creds box and headless works. SSO cannot improve
that case — Bitwarden's passwordless unlock (TDE / Key Connector) is Bitwarden-Cloud-only
and not implemented in Vaultwarden, and `--code` bypasses the SSO claim entirely. See "Why a
master password is unavoidable" below.

The wire contract, re-read from Vaultwarden's `identity.rs`/`sso.rs` after the first
guess produced a 404. Implement it from this, not from intuition:

- `GET /identity/sso/prevalidate` — unauthenticated. Enabled answers **`{"token": "<jwt>"}`**
  and nothing else; disabled answers an error body. There is **no** boolean `ssoEnabled`
  field, so `!!j.ssoEnabled` is permanently false and `sso status` will tell you SSO is off
  on a server where it works.
- `GET /identity/connect/authorize?client_id&redirect_uri&state&code_challenge&code_challenge_method`
  — **a GET that answers 307 to the identity provider.** There is **no** `POST
  /identity/sso/token`; that endpoint does not exist and 404s. `code_challenge_method` must
  be exactly `S256`. For `client_id=cli` the `redirect_uri` must be `http://localhost:8065`
  through `8070` — every other value is rejected with `Unsupported redirect uri`.
- The client must **stop** at the first off-server `Location`. Fetching the IdP's own login
  URL is pointless: completing the flow needs a human.
- `POST /identity/connect/token` with `grant_type=authorization_code`, the `code`, and the
  `code_verifier` — no client secret, PKCE replaces it. Device fields (`device_identifier`,
  `device_name`, `device_type`) are required here too.
- `grant_type=refresh_token` needs only `client_id` + `refresh_token`. This is what makes the
  browser a one-time event.

Two things that bite during the browser hop:

- The callback binds **both** `127.0.0.1` and `::1`. The `redirect_uri` is literally
  `http://localhost:NNNN`, and `localhost` resolves to `::1` before `127.0.0.1` on most
  systems, so an IPv4-only listener refuses the browser's actual connection and the login
  dies on a timeout with nothing to show for it.
- If the callback cannot bind the *exact* port registered as `redirect_uri`, it fails
  loudly instead of taking the next free one. A browser redirect to a port nobody listens
  on looks like a hang, not like a port problem.
- `f vaultwarden sso status` distinguishes "the server refused prevalidate" (SSO is off)
  from "could not reach the server". They need different fixes, and reporting a network
  failure as "not enabled" sends you reconfiguring a server setting that is fine.

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
node test/run-all.mjs            # all three suites
node test/crypto.test.mjs        # 31: crypto vectors, envelope handling, error shapes
node test/sso.test.mjs           # 27: OIDC flow + the loopback callback listener
node test/e2e.test.mjs           # 32: whole provider ladder vs a mock Vaultwarden
```

`e2e.test.mjs` spins up a real `f creds` daemon in a throwaway `HOME` and a mock
Vaultwarden that enforces the real server's rules (it rejects `scope != api`,
demands `device_identifier`/`device_name`, 400s a form-encoded prelogin, and
answers with Vaultwarden's camelCase error bodies). The master password never
leaves the store during the run, so a broken key derivation fails the suite
rather than being papered over.

`sso.test.mjs` uses a mock identity server whose field checks are copied from
Vaultwarden's `identity.rs` / `sso.rs`, so a drift in our request shape is rejected the
way the real server rejects it. It asserts the parts that are easy to get wrong: PKCE uses
`S256`, the API client secret is *not* forwarded on the SSO grant, a tampered verifier
fails, `HasMasterPassword` is read rather than assumed, and the callback refuses a `state`
mismatch, binds loopback only, and actually releases the port.

Two hazards if you add tests here:
- A test that resolves config **without** overriding `HOME` will use the operator's real
  `~/.f/f.config.json` and send live requests to their server. Note that `CONFIG` in
  `index.js` is computed at module load, so setting `process.env.HOME` after importing has
  no effect — import with a cache-busting query (`?t=${Date.now()}`) after setting `HOME`.
- Tests that share a loopback port must `await p.closed` between attempts, because the
  listener closes ~250ms after settling so the browser can render its page.

All suites are offline and touch nothing real. They do **not** cover: real TLS, org
collections, `device-encryption` (key-pair) unlock, attachments, or your actual KDF —
`f vaultwarden test` covers those against the live server.

## Troubleshooting

| message | meaning |
|---|---|
| `master password is wrong` | MAC check failed on the symmetric-key unwrap. Re-run `config --master-password`. Not a network problem. |
| `no server configured` | run `config --server/--email` |
| `Scope not supported` | server rejects the OAuth scope; current code sends `scope=api` (verified live) |
| `device_identifier cannot be blank` | server wants snake_case device fields; current code sends both spellings |
| `Too many login requests` (429) | rate-limited; **stop retrying**, it extends the lockout |
| `2FA is required` | the password grant hit a 2FA policy. Use the API key instead (`apikey`), which bypasses it. |
| `unrecognised response shape` | your server returns something unexpected — the error lists its keys, and it deliberately refuses to read that as an empty vault |
| `the creds store is locked` | `f creds unlock` — the vault cannot be consulted or written to while locked |
| `this account has no master password` | SSO succeeded but the account uses device-key unlock, which this uck cannot enrol. Do **not** run `config --master-password`; there is no password to store. Use an API key on an account that has one, or enrol the device in a web vault. |
| `sso login` opens the browser, then times out | the redirect never reached the callback. Check the port: `ss -tlnp \| grep -E ':806[5-9]\|:8070'`. A listener bound to `127.0.0.1` only is the classic cause — `localhost` resolves to `::1` first, so the browser's connection is refused. This uck binds both loopbacks; if you patched it to bind one, restore that. |
| `port N is in use` / `no free port` with nothing obviously listening | a previous attempt's listener is still shutting down, or a stale process holds it. Kill it — the message names the port. It does not fall back to another port on purpose: the IdP was told to redirect to that exact one. |
| `sso status` → `unknown (could not reach the server)` | network/TLS/DNS, per the `error` line. Not a server setting — do not go editing `SSO_ENABLED`. |
| `sso login` → **HTTP 404** | the authorize step is `GET /identity/connect/authorize` (307 to the IdP). A `POST /identity/sso/token` does not exist — an earlier version of this client invented it. If you are reading this after rewriting the flow, check the verb and the path before blaming the server. |
| `sso status` says `not enabled` but SSO clearly works | prevalidate returns `{"token": ...}`, not a boolean. Checking `j.ssoEnabled` is always false. Fixed in `ssoEnabled()`; do not reintroduce it. |
| SSO succeeds and it still asks for the master password | expected, not a bug. See the SSO section above. |

If `f providers` does not list `vaultwarden`, the uck failed to load: run
`f vaultwarden status` and read the error.

A trap worth knowing if you touch `lib/sso-callback.js`: `captureSsoCode` is **not** an
`async` function, deliberately. It returns a promise carrying a `.closed` promise, and an
`async` wrapper would return a *new* promise whose `.closed` is `undefined` — so
`await p.closed` resolves instantly and frees nothing. That bug was live for a while and
looked like a port-leak mystery: every port appeared permanently stuck after one SSO
attempt. Tests must therefore do `const p = captureSsoCode(...)` then `await p.closed`.
