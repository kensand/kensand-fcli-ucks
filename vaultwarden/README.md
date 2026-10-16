# f vaultwarden

Read secrets out of a **Vaultwarden** (Bitwarden-compatible) server and serve them to
`f creds` as a credential provider.

Zero dependencies: `node:crypto` + `fetch`. No `bw` binary, no npm packages, no
headless-browser automation. The whole crypto chain — PBKDF2, HKDF, AES-256-CBC +
HMAC-SHA256 envelopes, master-password hash — is implemented directly against the
Bitwarden spec, and cross-checked against `bitwarden-wasm` bytes and RFC vectors.

```
f creds get github.com        # local store first; the vault is consulted on a miss
```

---

## The two facts that explain everything else

**1. The master password does two jobs.** It is the login credential *and* the key
that unlocks the vault. An API key does **neither** — it only gets you past 2FA — so
it is optional, and you don't need one if 2FA is off.

**2. SSO replaces authentication, never decryption.** Signing in through an identity
provider gets you a token; it does not get you the vault key. The key is still wrapped
under a key derived from the master password, so an SSO account **still needs
`config --master-password`** — unless it genuinely never had one (SSO-created accounts
have no password at all, and opening those requires an enrolled device key pair, which
this uck deliberately does not implement).

One consequence worth stating plainly: the master password lives *inside* the
`f creds` box, so the vault cannot bootstrap itself. `f creds unlock` must come from
somewhere else.

---

## Setup

```bash
f vaultwarden config --server https://vault.example.com --email you@example.com
f vaultwarden config --master-password      # prompts, no echo, never touches argv
f vaultwarden test                          # login + unwrap + decrypt + counts
```

`test` changes nothing and is the thing to run first. It authenticates, unwraps the
symmetric key, decrypts real items, and prints counts. If it passes, everything below
works; if it fails, its message names the stage that failed.

Non-secret config goes in `f.config.json` under `vaultwarden`. Secrets go in the creds
box. **Never in anything argv-visible.**

### If the account signs in through an identity provider

Check *before* retyping a password:

```bash
f vaultwarden sso status          # unauthenticated probe, cannot lock anything
f vaultwarden sso login           # opens a browser, PKCE callback on localhost
f vaultwarden sso login --manual  # over ssh / in a container: binds no port
```

`enabled` means the **password grant cannot authenticate this account** — it does not
mean your password is wrong. In return for the browser dance, SSO issues a refresh
token, so sessions renew for ~30 days without touching a browser again.

`--manual` is the one that works anywhere: it prints an authorize URL, you open it on
any device, and you paste the redirect URL (or just the `code=`) back. Note the PKCE
verifier lives **only in that process's memory** — Ctrl-C and the whole exchange must
start over.

### If 2FA is on

A working password grant is still blocked by a 2FA policy. Try SSO first — it signs
in through the identity provider, 2FA included, and returns a refresh token good for
about 30 days:

```bash
f vaultwarden sso login
```

An API key is the fallback (no SSO on the server, or the refresh token has lapsed).
It skips 2FA by design and cannot decrypt anything by itself:

```bash
f vaultwarden apikey <client-id> <client-secret>   # web vault: Settings > Security > Keys
```

---

## Resolving a secret

```bash
f creds get github.com            # local store first, vault on a miss
f vaultwarden get github.com      # straight to the vault, ignore the mirror
f vaultwarden get 'My Item::username'
f vaultwarden list --search git
f vaultwarden list                # every item + the cred names each can answer
```

**Name forms:** an item **name** (`My Item`), an item **id**, a **host** from an item's
URIs (`github.com`), or a **map key**.

**Fields:** append `::field` for anything but the password — `username`, `totp`,
`note`, `uri`, `field:<name>`.

Host names are why `f creds get github.com` works with no configuration at all: the
URIs attached to a vault item are harvested as candidate names.

### Ambiguity is an error, never a coin flip

Vaultwarden item **names are not unique**; ids are. If two items resolve to the same
name, this uck refuses and prints both with their ids and available fields. Pin it
deterministically:

```bash
f vaultwarden map github.com 'aaaaaaaa-1b2c-…::password'
f vaultwarden map gh-work    'bbbbbbbb-3d4e-…::username'
f vaultwarden unmap gh-work
```

Point map targets at **ids** when names collide. A map target that is itself still
ambiguous is reported, never resolved by "first match".

---

## Mirrors, TTL, staleness

A vault hit is stored as `mirror:<name>`, so repeat reads are fast and keep working
with the vault unreachable.

| knob | default |
|---|---|
| mirror TTL | 3600s (`MIRROR_TTL_SEC`) |
| negative cache (unknown names) | 300s |
| derived-key cache | 8h (`KEY_CACHE_TTL_SEC`) |

```bash
f creds get <name> --vault        # skip the mirror, revalidate with the provider now
f creds get <name> --local        # never consult providers
f creds get <name> --source       # provenance to stderr, e.g. `local:<name>`,
                                  # `vaultwarden:<name> (mirrored)`, `vault:mirror:<name>`
f creds get <name> --no-cache     # ignore/clear the negative cache first
f creds forget <name>             # drop mirror(s) + negative cache for a name
f vaultwarden cache               # is the derived key cached? how old?
f vaultwarden cache --clear       # force PBKDF2 re-derivation
f vaultwarden forget              # key cache + cached tokens
```

A mirror is a **copy of a secret** sitting in the same encrypted box. Treat
`f creds rm mirror:<name>` as a real secret-deletion operation.

---

## Commands

| command | what it does |
|---|---|
| `config [--server <url>] [--email <addr>] [--master-password] [--print]` | set non-secret config; prompts for the password without echoing |
| `apikey <client-id> <client-secret>` | store the vault API key (skips 2FA) |
| `status` | config + readiness + what it can currently answer |
| `test` | login, decrypt, report counts. **Changes nothing.** |
| `list [--search <s>]` | items + the cred names each can answer |
| `get <name> [--secrets]` | resolve one cred |
| `map` / `unmap <cred-name>` | pin a cred name to an `<Item::field>` / remove it |
| `set-totp <name> <secret>` | **WRITE** — store a TOTP secret on an item |
| `cache [--clear]` | the derived-key cache |
| `forget` | clear key cache + cached tokens |
| `sso status` | is OIDC SSO enabled? (unauthenticated probe) |
| `sso login [--port <8065-8070>] [--timeout <sec>] [--force]` | sign in via the IdP, exchange the PKCE code |
| `sso login --manual` | same, binds no port; paste the redirect URL back |

Writes are the deliberate exception. **Only `set-totp` writes**, and only to the item
you name — it re-encrypts with that item's own key and PUTs the ciphertext back.
Nothing in the resolution path can mutate the vault.

---

## Plain http is refused

Both the master-password hash and the API key travel in request bodies, so plain http
is a credential leak on any network you don't fully control. For a genuinely
loopback / LAN / tailscale-only server:

```json
"vaultwarden": { "allowInsecureHttp": true }
```

The refusal names whether the host is loopback before you decide.

---

## As a credential provider

This uck is also a **provider** for `f creds`: on a local miss, `f creds get <name>`
asks it and mirrors a hit as `mirror:<name>`.

The provider interface (`resolve` / `has` / `status` / `mirrorTtlSec` /
`hasExternalApi`) is specified in
[`fcli-ucks/creds/README.md`](../../fcli-ucks/creds/README.md) — that file is the
contract, this one is one implementation of it. The parts that bite, in short:

- `resolve()` returns a value, or **`null` only when the name is genuinely not yours**.
  Returning `null` for a *failure* silently becomes "no such credential" — throw instead,
  with an actionable message. That is why `resolve` throws on a locked store, an
  unreachable server, and a bad master password rather than reporting an empty vault.
- `has()` is omitted deliberately: it is a pre-filter consulted *before* `resolve`, and a
  "not mine" from a network timeout would suppress `resolve` and make the vault look
  empty instead of broken.
- `mirrorTtlSec: 3600` is a floor, clamped to the daemon's remaining unlocked lifetime.
- Provider module scope must be side-effect free — `f providers --dump` evaluates it in
  every `f` process, including unrelated ones.
- If `f providers` does not list `vaultwarden`, the uck failed to load. Run
  `f vaultwarden status` and read the error.

## How it works

1. `PBKDF2-HMAC-SHA256(masterPassword, email, iterations)` → master key.
   Iterations come from `/identity/accounts/prelogin` (commonly 600000). The salt is
   the **email alone** — not email+password.
2. `HKDF-Expand-SHA256(masterKey, "enc")` and `(..., "mac")` → the two keys that unwrap
   the account's symmetric key from `sync.profile.key`.
3. `masterPasswordHash = HMAC-SHA256(masterKey, password)` → what the token endpoint
   receives. The password itself never leaves the machine.
4. Every field is `type.iv|ciphertext|mac`: AES-256-CBC, HMAC-SHA256 over
   `iv||ciphertext` **verified before** a value is returned.

MAC failure is an **error**, never an empty string or garbage. Type-0 (unencrypted)
envelopes are returned as plaintext; type-1 (no MAC) is refused by default.

**KDF is per-account and the client cannot choose it.** `prelogin`'s `kdf` type is read
and honoured, never defaulted — a wrong KDF derives a *silent* wrong key whose only
symptom is a MAC failure reading as "wrong master password". PBKDF2 is implemented;
Argon2id is **rejected explicitly** with instructions to switch the account's key type
in the web vault (export a backup first — it re-encrypts the vault).

Cached derived keys mean a read doesn't redo a ~1s PBKDF2. A cached token that returns
401/403 is refreshed **once** if a refresh token exists, then the cache is discarded —
a network error is never treated as a reason to re-derive and retry.

### Server behaviour, probed rather than assumed

Scope rules are **per-grant**, and were determined against a live server with a
nonexistent account:

- password grant and SSO code exchange: `scope=api offline_access` — bare `api` is
  **rejected outright**, and `offline_access` is what earns the refresh token
- `client_credentials` (API key): exactly `api`

So a `Scope … not supported` error is **this uck's bug, not your credentials** — report
it rather than retyping a correct password.

Device fields must be **snake_case and sent once**: sending both `device_identifier`
and `deviceIdentifier` makes Rocket reject the request as blank.

---

## Tests

```bash
node test/run-all.mjs              # everything
node test/crypto.test.mjs          # 33  crypto vectors, envelope handling, error shapes
node test/e2e.test.mjs             # 57  whole provider ladder vs a mock Vaultwarden
node test/bitwarden-wasm.test.mjs  # 7   byte-for-byte agreement with the official wasm
```

`e2e.test.mjs` spins up a **real `f creds` daemon** in a throwaway `HOME` plus a mock
Vaultwarden that enforces the real server's rules — it rejects a wrong `scope`, demands
the device fields, 400s a form-encoded prelogin, refuses duplicated device fields,
honours per-grant scope rules, and answers with Vaultwarden's camelCase error bodies.
The master password never leaves the store during the run, so broken key derivation
fails the suite instead of being papered over. All suites are offline and touch nothing
real.

Coverage gaps, stated: real TLS, org/collection ciphers, attachments, 2FA flows, and
your actual KDF. `f vaultwarden test` covers those against the live server.

Two fixes are **not** covered by a passing test, and are documented as reading rather
than proof: awaiting the SSO token persistence (removing both `await`s keeps the suite
green — a floating rejection fires after the child exits), and stripping the child's
`f: ` prefix from credential errors (an absent prefix and a stripped one are
indistinguishable to the assertion). See SKILL.md's troubleshooting section for why the
second one mattered.

---

## If it misbehaves

```bash
f vaultwarden status              # readiness + what it can answer
f providers                       # is the uck registered at all?
VW_TRACE=1 f vaultwarden <cmd>    # stack trace instead of one line
```

Read **SKILL.md** for the failure-mode table and the debugging notes. The short version:

- **`MAC verification failed`** — the stored master password does not derive the key
  that opens `profile.key`. Re-run `config --master-password`. Not a network problem.
- **Anything else that smells like crypto** (OpenSSL wording such as `unsupported state
  or unable to authenticate data`) is **not** this client's MAC check — that message is
  specific. Get a stack before suspecting the maths.
- **`the server refused to issue a token`** — ambiguous by design; prove the password
  offline (SKILL.md) before retrying, and watch for `Too many login requests`.
