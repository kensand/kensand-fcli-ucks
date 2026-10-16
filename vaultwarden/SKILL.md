---
name: f-vaultwarden
description: Read credentials from a Vaultwarden/Bitwarden server with a zero-dep native client, and serve them to `f creds` as a provider on a local miss. Trigger - a secret lives in the vault, or `f creds get <name>` says "no such cred" for something that exists in Vaultwarden.
---

# Vaultwarden as a credential source

> **Full command reference, setup walkthrough, and defaults: [`README.md`](./README.md).**
> This file is the failure-mode and debugging guide — start at
> [Troubleshooting](#troubleshooting) if something already broke.

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
```

If `test` reports the server refused a token, check whether the account signs in
through an identity provider before touching the password again:

```
f vaultwarden sso status                           # unauthenticated probe, no risk
f vaultwarden sso login                            # opens a browser, PKCE callback
f vaultwarden sso login --manual                   # over ssh / in a container: no port
                                                   # bound, paste the redirect URL back
```

`enabled` means the password grant **cannot** authenticate this account — not that
the password is wrong. SSO replaces the *login*, never the *decryption*: the vault
key is still wrapped in a key derived from the master password, so
`config --master-password` is still required unless the account genuinely never had
one (SSO-created accounts have no password at all, and opening those needs an
enrolled device key pair, which this uck deliberately does not implement). In
return, SSO yields a refresh token, so the session renews for ~30 days without a
browser.

A password grant that *does* work is still blocked by 2FA. Two ways around it, and
SSO is the one to try first:

```
f vaultwarden sso login                              # sign in via the identity provider,
                                                     # 2FA included; earns a ~30-day refresh token
f vaultwarden apikey <client-id> <client-secret>     # web vault: Settings > Security > Keys
```

An API key skips 2FA by design and decrypts nothing on its own; it is the fallback
for when there is no SSO, or once the refresh token has lapsed.

`f vaultwarden test` is the thing to run first: it authenticates, unwraps the
symmetric key, decrypts a sample item, and prints counts. It changes nothing. If
it passes, everything below works; if it fails, its message names the stage.

Non-secret config goes in `f.config.json` under `vaultwarden`. Secrets go in the
creds box. Never in argv-visible places.

### Who is allowed to run setup

**The human runs setup. An agent does not, and cannot do it correctly.** This is
not a politeness rule about secrets staying out of logs — it is a hard capability
boundary, and violating it produces a *worse* failure than refusing:

| Step | Who | Why |
| --- | --- | --- |
| `config --server`, `--email`, `--folder` | either | non-secret, lands in `f.config.json` |
| `status`, `sso status`, `list`, `get` | either | read-only, no new secret entrusted to it |
| `config --master-password` | **human, at a TTY** | see below |
| `sso login` | **human, in a browser** | the browser must be on the machine that owns `localhost:<port>` |
| `apikey <id> <secret>` | **human** | the operator authorises which key may read the vault |

An agent runs its commands with **stdin as a pipe, not a tty**. That is the whole
problem, because `promptSecret()` falls back to plain `readline` when stdin is not
a tty. So a piped master password does not error — it is **accepted silently**.

And the failure is *deferred*, which is what makes it dangerous:

```
agent pipes a guessed/empty password  ->  "stored  vault master password"   <- looks like success
hours later, first real decrypt        ->  MAC verification failed
```

By then the wrong password is sitting in the encrypted box, and the error you
eventually get — *"the SSO session works but the stored master password does not
unlock the vault — do not retry blindly, retype it"* — points at a keystroke nobody
made interactively. An agent that *guesses* and gets that MAC error has
authenticated nothing, learned nothing, and left a booby-trapped credential behind.

The same asymmetry applies to `sso login`: no code is ever delivered on a piped
stdin, so the attempt can only end by **waiting out the full callback timeout** —
~180s default of a live PKCE challenge and a bound port, dead on the floor. That is
the same shape as the IPv4-only-listener problem called out in `lib/sso-callback.js`:
*"the sign-in dies on a timeout with nothing to show for it."* So the cost of an
agent attempting SSO is a guaranteed 180s timeout plus a burned challenge, and the
benefit is zero.

What an agent *should* do when it hits an unconfigured provider:

```
f vaultwarden status      # read-only; names the one missing piece
```

then hand the human the exact command from that output and stop. `status` is
deliberately built to be safe to run unprivileged — it re-checks credentials but
never spawns itself recursively, so probing readiness cannot deadlock.

The `not ready` that appears **before** any credential exists is not a bug and not
a bug report. Note also that `ready`/`not ready` answers *"can this provider be
asked at all"*, not *"did the answer come from the vault"* — see
[Troubleshooting](#troubleshooting).

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
f creds get <name> --vault            # skip the mirror, revalidate with the provider now
f creds get <name> --local            # never consult providers
f creds get <name> --source           # provenance to stderr, e.g. `local:<name>`,
                                      # `vaultwarden:<name> (mirrored)`, `vault:mirror:<name>`
f creds get <name> --no-cache         # ignore/clear the negative cache first
f creds forget <name>                 # drop that name's mirror(s) + negative cache
f vaultwarden cache                   # is the derived key cached? how old?
f vaultwarden cache --clear           # drop it (forces PBKDF2 re-derivation)
f vaultwarden forget                  # key cache + cached tokens
```

There is **no `--provider` / `--no-provider`**; `--vault` and `--local` are the pair.

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

## Best practices

**Ordering that actually saves time**, when a vault read fails:

1. `f vaultwarden status` — is it configured and unlocked at all?
2. `f vaultwarden test` — names the failing stage, changes nothing.
3. `f vaultwarden sso status` — before you touch the password. If SSO is `enabled`, the
   password grant *cannot* work and no amount of retyping will change that.
4. Only then suspect the credential.

**Never retry a refused password grant.** Bitwarden returns the same `Username or
password is incorrect` for a wrong email, a wrong password, and a *rejected request*,
and the server rate-limits with a lockout that your retries extend. Prove the password
offline (below) instead of asking the server.

**Prove, don't infer, at every crypto boundary.** A MAC failure is the only signal that
a key is wrong; a padding or length error means you got as far as decrypting with
something and the shape is already broken. When a number looks impossible (a 64-byte
key reported as 13 bytes), check your own conversion before the account.

**Treat these as client bugs, not vault problems** — each has been one here:
`unexpected symmetric key length`, `Scope … not supported`, `unrecognised response
shape`. All three are the client mis-reading a server, and all three were.

**An empty result is not a parse bug until the raw response agrees.** `test` printing
`0 item(s)` was a genuinely empty vault; confirm against the endpoint before rewriting
the response-shape logic.

**Keep secrets out of argv.** `config --master-password` prompts; `apikey` takes
arguments because there is no interactive path in the provider probe — accept that
trade-off knowingly rather than adding `--password <x>` "for convenience".

**When you change this uck:** mutation-test the fix. Break it on purpose and confirm a
test goes red. Several "passing" tests here were proven worthless that way — including
fixtures that base64-wrapped a key exactly the way the buggy code did, so they agreed
with the bug instead of catching it. A fixture that agrees with the code it tests
proves nothing; pin fixtures to bytes read off a real server.

## Tests

```
node test/run-all.mjs               # all suites
node test/crypto.test.mjs           # 33: crypto vectors, envelope handling, error shapes
node test/e2e.test.mjs              # 57: whole provider ladder vs a mock Vaultwarden
node test/bitwarden-wasm.test.mjs   #  7: byte-for-byte agreement with the official wasm
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
| `the server refused to issue a token` | Bitwarden answers `Username or password is incorrect` for a wrong email, a wrong password, **and** a rejected request — it does not say which. Do not assume the password: prove it offline first (see below). `rejected fields:` in the output names the cause when the server gives one. |
| `MAC verification failed` | the stored master password does not derive the key that opens `profile.key`. Re-run `config --master-password`. Not a network problem. |
| `unexpected symmetric key length` | **almost always a client bug, not your vault.** The wrapped user key is 64 *raw* bytes; if this ever reappears, look for a `Buffer` → `toString("utf8")` → `base64` round trip before suspecting the account. See the note below. |
| `no server configured` | run `config --server/--email` |
| `Scope (api) not supported` | correct behaviour, not a bug: this server allows `api` only on `client_credentials`. Password/SSO grants need `api offline_access`. |
| `device_identifier cannot be blank` | server wants snake_case device fields **and only one spelling**; sending both snake and camel makes Rocket reject it as blank. |
| `Too many login requests` (429) | rate-limited; **stop retrying**, it extends the lockout |
| `requires 2FA` | the password grant hit a 2FA policy. Use `f vaultwarden sso login` — the identity provider handles 2FA. An API key (`apikey`) also skips it, but only as a fallback where there is no SSO. |
| `unrecognised response shape` | your server returns something unexpected — the error lists its keys, and it deliberately refuses to read that as an empty vault |
| `the creds store is locked` | `f creds unlock` — the vault cannot be consulted or written to while locked |

### Proving a master password without logging in

A rejected login is ambiguous; a MAC check is not. If a vault can be opened at all,
the password is right, regardless of what the identity endpoint says:

```js
const C = await import("./lib/vwclient.js");
// profile.key comes from an authenticated /api/sync (or from the browser's own
// sync response, where it equals userDecryption.masterPasswordUnlock.masterKeyEncryptedUserKey)
C.deriveKeys({ email, password, kdfIterations, encryptedKey: profileKey });
```

> **Before believing a crypto error here, prove it is crypto.** This snippet only
> prints an error if you feed it a real `profile.key` and a real password, and it can
> fail for reasons that have nothing to do with either. The worst version of this
> printed `f: f: Unsupported state or unable to authenticate data` — OpenSSL's wording
> for an AES-GCM tag mismatch — and it sent hours into key derivation, Argon2id, and
> base64 handling. **None of it was real.** The credential had simply never been
> stored, and `credsGet` was forwarding the child `f creds` process's stderr verbatim;
> the doubled `f: ` was the tell, because *this* process prefixes too, so the text was
> someone else's. A MAC failure from this client's own code says
> `MAC verification failed (wrong key, or tampered ciphertext)`. If the message does
> not say that, it is not a MAC failure — read the stack (`VW_TRACE=1`) before
> suspecting the maths. A message that names the wrong subsystem is a defect, not
> decoration: it relocates the entire investigation.
>
> Two related traps from the same session, both invisible to `node --check`:
> an SSO restore that brought call sites without the functions they called, and
> `return { kdfType, kdfIterations }` shorthand for a variable declared as
> `iterations` — valid syntax, `ReferenceError` at runtime, sitting on the only
> KDF path the account could take, so *no* vault could ever open. Shorthand property
> names are not checked; when a variable name and its value's name differ, name the
> property.
>
> Separately: `f vaultwarden test` reporting `0 item(s)` can be a genuinely empty
> vault. Confirm against the raw endpoint before reading a parse bug into it.

This distinction cost hours: `f vaultwarden test` insisted the password was wrong
while the very same password decrypted the account's own `profile.key`. The real
cause was the client, and afterwards the account still could not log in — because
it is **SSO-provisioned** and has no server-side password hash. Check that next:

```
f vaultwarden sso status     # enabled = the password grant cannot authenticate this account
```

### The one bug worth remembering

`unwrapSymmetricKey` must verify the MAC **before** decrypting, and must keep the
plaintext **binary**. Decrypting first hides a wrong key behind a PKCS#7 padding
failure, which surfaces as a key *length* error. And the plaintext is 64 raw bytes,
not base64 — pushing it through `toString("utf8")` turns every byte ≥ 0x80 into
U+FFFD, which decodes back to **13 bytes**. Three different wrong diagnoses ("weird
vault", "double base64", "wrong password") all came from that one number, and the
test suite did not catch it because the fixtures base64-wrapped the key exactly like
the buggy code did. A fixture that agrees with the code it tests proves nothing;
these ones are pinned to bytes read off a real server.

If `f providers` does not list `vaultwarden`, the uck failed to load: run
`f vaultwarden status` and read the error.
