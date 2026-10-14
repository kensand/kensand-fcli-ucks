// Bitwarden/Vaultwarden client — zero deps, node:crypto + fetch only.
//
// Implements the subset of the Bitwarden identity + vault protocol that
// Vaultwarden serves: /prelogin, /connect/token, /api/sync, and the client-side
// crypto needed to read a personal vault.
//
// ## Why this is not just a call to the Bitwarden SDK
//
// @bitwarden/sdk-napi covers Secrets Manager (organisation machine accounts),
// not personal vaults — which is what Vaultwarden is. `bw`/`rbw` are external
// binaries. So this file speaks the wire protocol directly.
//
// ## Key hierarchy (this is the part worth understanding before editing)
//
//   masterPassword + email
//     └─ PBKDF2-HMAC-SHA256(password, email, kdfIterations) -> masterKey (32B)
//          ├─ HKDF-Expand(masterKey, "enc") -> stretched enc key
//          ├─ HKDF-Expand(masterKey, "mac") -> stretched mac key
//          └─ HMAC-SHA256(masterKey, password) -> password hash sent as the
//             "password" field of the password grant (the server never sees the
//             master password itself)
//
//   stretched keys decrypt profile.key -> 64B = symmetricKey(32) ‖ macKey(32)
//   each cipher field is then decrypted with that symmetric key pair.
//
// Note the consequence: **the master password is unavoidable.** An API key
// (client_credentials) only buys you an access token that skips the 2FA round
// trip; it cannot decrypt anything. Vault contents always require the master
// password, by design.
//
// ## Envelope format
//
//   "2.<b64(iv)>|<b64(ciphertext)>|<b64(hmac)>"     type 2 = AES-256-CBC + HMAC
//   "1.<b64(iv)>|<b64(ciphertext)>"                  type 1 = legacy, no MAC
//   "0.<b64>"                                        type 0 = plaintext (some uris)
//
// HMAC is HMAC-SHA256(macKey, iv ‖ ciphertext) and must be verified before the
// plaintext is handed to the caller (decrypt-then-verify would be the bug).
// Type 1 is refused by default: it has no integrity tag.

import crypto from "node:crypto";

const DEVICE_TYPE_CLI = 14;
// Verified against the live server: this Vaultwarden reads snake_case device
// fields (`device_identifier`, `device_name`) and *only* accepts `scope=api` for
// the client_credentials grant — `api offline_access` and `api.device` are both
// refused with "Scope not supported", so the original form could never log in.
// Field names are sent in both cases: cheap insurance against a server that
// validates one spelling or the other, and unknown fields are ignored.
const DEVICE_IDENTIFIER = "f-vaultwarden-uck";
const DEVICE_NAME = "f creds (vaultwarden provider)";
const API_SCOPE = "api";
const UA = "f-cli/vaultwarden-provider";

/*
 * SSO constants, taken from the server's own behaviour rather than guessed.
 *
 * `client_id=cli` is the only one the server accepts for a command-line flow, and
 * it mandates an http://localhost:8065..8070 redirect (src/sso.rs authorize_url).
 * `web`/`browser` point at the server's own sso-connector.html and `desktop`/`mobile`
 * expect a custom scheme, neither of which a headless CLI can service.
 *
 * Scope is `api offline_access`: offline_access is what earns the refresh_token, and
 * unlike the API-key grant (where this server refuses anything but `api`) the SSO
 * grant is a normal user login and accepts it. Kept separate from API_SCOPE because
 * the two grants have different, independently-verified scope rules.
 */
const SSO_CLIENT_ID = "cli";
const SSO_SCOPE = "api offline_access";

/** Bitwarden KdfType: 0 = PBKDF2-SHA256, 1 = Argon2id. */
export const KDF_PBKDF2_SHA256 = 0;
export const KDF_ARGON2ID = 1;

/** Cipher type codes (Bitwarden `EncryptionType`). */
export const ENC = { AES_256_CBC_PLAIN: 0, AES_128_CBC: 1, AES_256_CBC_HMAC: 2, RSA_2048_OAEP: 3 };

/** Cipher `type` values we surface. */
export const CIPHER_TYPE = { LOGIN: 1, SECURE_NOTE: 2, CARD: 3, IDENTITY: 4 };

/* ------------------------------------------------------------------ crypto */

/** PBKDF2-HMAC-SHA256(masterPassword, email, iterations) -> 32B masterKey. */
/**
 * hash-wasm is an OPTIONAL dependency: it provides the Argon2id WASM that Bitwarden
 * accounts with kdf=1 require. It is imported lazily so an installation without
 * `npm install` still works for the far more common PBKDF2 accounts — the zero-dep
 * path must not regress when a dependency is added.
 */
let _argon2id = null;
/**
 * Load the optional Argon2id implementation.
 *
 * `impl` exists so the "dependency is missing" branch is testable without uninstalling
 * anything. It must not cache the result: a test that asks for the unavailable path has
 * to leave the real loader usable afterwards, or it poisons every later derivation.
 */
async function loadArgon2id({ impl = null } = {}) {
  if (impl) return impl;
  if (_argon2id === null) {
    try {
      ({ argon2id: _argon2id } = await import("hash-wasm"));
      if (typeof _argon2id !== "function") _argon2id = false;
    } catch { _argon2id = false; }
  }
  if (!_argon2id) {
    throw new Error(
      "Argon2id is needed for this account, but the optional 'hash-wasm' dependency is not\n" +
      "  installed. Fix:  cd <this uck's directory> && npm install\n" +
      "  (PBKDF2 accounts need no dependencies at all, which is why this one is optional.)",
    );
  }
  return _argon2id;
}

/** Whether Argon2id can be used right now (i.e. the optional dependency is installed). */
export async function argon2idAvailable() {
  try { await loadArgon2id(); return true; } catch { return false; }
}

export function makeMasterKey(password, email, iterations) {
  if (!Number.isInteger(iterations) || iterations <= 0) {
    throw new Error(`invalid kdfIterations from server: ${iterations}`);
  }
  return crypto.pbkdf2Sync(Buffer.from(String(password), "utf8"), Buffer.from(String(email), "utf8"), iterations, 32, "sha256");
}

/**
 * Argon2id master key (Bitwarden KdfType 1), matching what the clients actually send.
 *
 * Taken from libs/common/src/platform/services/web-crypto-function.service.ts:
 *
 *   argon2.hash({ pass, salt, time: iterations, mem: memory,
 *                 parallelism, hashLen: 32, type: ArgonType.Argon2id })
 *
 * Three things here are easy to get wrong and each yields a WRONG key that then fails
 * its MAC check and looks exactly like "you typed the master password wrong":
 *
 *  - hashLen is 32, NOT 64. The native SDK derives 512 bits; the WebCrypto/WASM path
 *    (web-crypto-function.service.ts) derives 256 and this mirrors that.
 *  - memory arrives in MIBIBYTES and hash-wasm wants KiB, so it is multiplied by 1024 —
 *    see the kdf.rs quote below. An earlier revision of this file asserted the opposite
 *    ("64 means 64 KiB") and pinned that mistake in a test; the Rust source settles it.
 *  - Argon2id has no 64-byte mode in this path, so there is nothing to "split"; the
 *    32-byte tag is stretched with HKDF like the PBKDF2 output is.
 *
 * No secret and no associated data: Bitwarden passes neither, and hash-wasm's `secret`
 * handling does not reproduce the RFC 9106 vector, so it must not be used.
 */
export async function makeMasterKeyArgon2id(password, email, { iterations, memory, parallelism, _argon2impl = null } = {}) {
  const argon2id = await loadArgon2id({ impl: _argon2impl });
  for (const [name, v] of [["iterations", iterations], ["memory", memory], ["parallelism", parallelism]]) {
    if (!Number.isInteger(v) || v <= 0) throw new Error(`invalid argon2id ${name} from server: ${v}`);
  }
  const out = await argon2id({
    password: Buffer.from(String(password), "utf8"),
    salt: Buffer.from(String(email).trim().toLowerCase(), "utf8"), // Bitwarden trims+lowercases the email
    parallelism,
    iterations,
    // kdfMemory is MiB; hash-wasm's memorySize is KiB. bitwarden_crypto/src/crypto/kdf.rs:
    //     let memory = memory.get() * 1024; // Convert MiB to KiB;
    // Passing the server's number through raw would derive with 64 KiB where 64 MiB was
    // meant -- a wrong key, indistinguishable from a wrong master password.
    memorySize: memory * 1024,
    hashLength: 32,              // the WebCrypto/WASM path derives 32, not the SDK's 64
    outputType: "binary",
  });
  return Buffer.from(out);
}


/**
 * HKDF-Expand (RFC 5869 §2.3) using `prk` directly as the pseudorandom key —
 * i.e. Extract is skipped, which is legitimate here because the masterKey is
 * already a uniform 32-byte PBKDF2 output (RFC 5869 §3.3). Exported so the test
 * suite can check it against the RFC's own vectors.
 */
export function hkdfExpand(prk, info, length) {
  if (!Buffer.isBuffer(prk) || prk.length < 32) throw new Error("hkdfExpand: prk must be at least 32 bytes");
  if (!Number.isInteger(length) || length <= 0 || length > 255 * 32) throw new Error(`hkdfExpand: bad length ${length}`);
  const hashLen = 32;
  const n = Math.ceil(length / hashLen);
  const out = Buffer.allocUnsafe(n * hashLen);
  let prev = Buffer.alloc(0);
  const infoBuf = Buffer.isBuffer(info) ? info : Buffer.from(String(info), "utf8");
  for (let i = 1; i <= n; i++) {
    prev = crypto.createHmac("sha256", prk).update(prev).update(infoBuf).update(Buffer.from([i])).digest();
    prev.copy(out, (i - 1) * hashLen);
  }
  return out.subarray(0, length);
}

/** masterKey -> { encKey, macKey } used to unwrap the account symmetric key. */
export function stretchMasterKey(masterKey) {
  return { encKey: hkdfExpand(masterKey, Buffer.from("enc", "utf8"), 32), macKey: hkdfExpand(masterKey, Buffer.from("mac", "utf8"), 32) };
}

/** The value sent as `password` in the password grant. */
export function masterPasswordHash(masterKey, password) {
  return crypto.createHmac("sha256", masterKey).update(Buffer.from(String(password), "utf8")).digest();
}

/** Parse "2.iv|ct|mac" (also type 0/1) into its parts. */
export function parseEnvelope(s) {
  if (typeof s !== "string") return null;
  const dot = s.indexOf(".");
  if (dot < 0) return null;
  const type = Number(s.slice(0, dot));
  const rest = s.slice(dot + 1);
  if (!Number.isInteger(type)) return null;
  if (type === ENC.AES_256_CBC_PLAIN) return { type, data: Buffer.from(rest, "base64") };
  const parts = rest.split("|");
  if (parts.length < 2) return null;
  // A type-2 envelope is `iv|data|mac`. Taking parts[0]/parts[1] and treating parts[2] as
  // optional silently truncates the ciphertext by one 16-byte block when the MAC is
  // actually present, which surfaces as a plaintext 15 bytes short -- corrupt data, not an
  // error. The segment count is therefore checked, not ignored.
  if (type === ENC.AES_256_CBC_HMAC && parts.length !== 3) {
    throw new Error(`type 2 envelope has ${parts.length} segments, expected 3 (iv|data|mac): ${String(s).slice(0, 16)}…`);
  }
  return { type, iv: Buffer.from(parts[0], "base64"), ct: Buffer.from(parts[1], "base64"), mac: parts[2] ? Buffer.from(parts[2], "base64") : null };
}

/** Constant-time buffer compare. */
function tagEqual(a, b) {
  if (a === null || b === null || a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/**
 * Decrypt a Bitwarden envelope with an { encKey, macKey } pair.
 * Returns undefined for null/empty input (many optional fields are absent).
 * Throws on a MAC mismatch — that is a wrong key, not corrupted data.
 */
export function decryptString(value, keys, { allowUnauthenticated = false } = {}) {
  if (value == null || value === "") return undefined;
  const env = parseEnvelope(value);
  if (!env) throw new Error(`unrecognised ciphertext envelope: ${String(value).slice(0, 24)}…`);
  if (env.type === ENC.AES_256_CBC_PLAIN) return env.data.toString("utf8");

  if (env.type === ENC.AES_256_CBC_HMAC) {
    if (!env.mac) throw new Error("type 2 ciphertext without a MAC tag");
    const expect = crypto.createHmac("sha256", keys.macKey).update(env.iv).update(env.ct).digest();
    if (!tagEqual(expect, env.mac)) throw new Error("MAC verification failed (wrong key, or tampered ciphertext)");
  } else if (env.type === ENC.AES_128_CBC) {
    // Legacy AES-256-CBC with no integrity tag. Never on by default.
    if (!allowUnauthenticated) {
      throw new Error("type 1 ciphertext has no integrity tag — refusing (pass --allow-insecure-crypto if you really must)");
    }
  } else {
    throw new Error(`unsupported encryption type ${env.type}`);
  }

  // An IV that is not exactly 16 bytes means the envelope's segments were read in the wrong
  // order, and a bad final block means the key or the ciphertext is wrong. Both used to be
  // caught upstream and re-thrown as "MAC verification failed", which blamed the operator's
  // perfectly good master password for what was this file mis-parsing the envelope. Keep the
  // distinct messages; do not collapse them.
  if (env.iv.length !== 16) {
    throw new Error(`AES-CBC needs a 16-byte IV, got ${env.iv.length} -- envelope segments are not (iv,data,mac) as assumed`);
  }
  const d = crypto.createDecipheriv("aes-256-cbc", keys.encKey, env.iv);
  return Buffer.concat([d.update(env.ct), d.final()]).toString("utf8");
}

/** Inverse of decryptString — needed to push values back (TOTP writes). */
export function encryptString(plaintext, keys) {
  const iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv("aes-256-cbc", keys.encKey, iv);
  const ct = Buffer.concat([c.update(Buffer.from(String(plaintext), "utf8")), c.final()]);
  const mac = crypto.createHmac("sha256", keys.macKey).update(iv).update(ct).digest();
  return `2.${iv.toString("base64")}|${ct.toString("base64")}|${mac.toString("base64")}`;
}

/** Unwrap profile.key with the stretched keys -> { symmetricKey, macKey }. */
/**
 * Unwrap profile.key with the stretched keys.
 *
 * Returns the account key pair under BOTH names Bitwarden uses for it:
 * `encKey`/`macKey` (what decryptString consumes) and `symmetricKey` (Bitwarden's
 * term for the same 32 bytes). Getting these two names confused is the classic
 * failure here — it produces a key set that silently decrypts nothing.
 */
export function unwrapSymmetricKey(encryptedKey, stretched) {
  // Bitwarden's user key is stored as base64(base64(64 key bytes)): after the envelope is
  // opened, the plaintext is a base64 STRING (88 chars, "=="-padded, for a 64-byte key), and
  // decoding that string once yields the key.
  //
  // "Just decode twice" is the trap an earlier revision of this file fell into. Buffer's
  // base64 decoder never errors on non-base64 input -- it returns however many whole 3-byte
  // groups it can form. Feeding it the raw 64 bytes returns 48 bytes here, and other real key
  // blobs gave 13 and 15. That is where "unexpected symmetric key length" came from: a vault
  // that was fine, reported as unreadable. The length check below is the thing that makes
  // that impossible to miss, so it must stay ahead of any use of the key.
  const raw = decryptString(encryptedKey, stretched);
  const buf = Buffer.from(raw, "base64");
  if (buf.length !== 64) throw new Error(`unexpected symmetric key length ${buf.length} (want 64)`);
  const encKey = buf.subarray(0, 32);
  return { encKey, macKey: buf.subarray(32, 64), symmetricKey: encKey };
}

/* -------------------------------------------------------------- api client */

/** Minimal JSON/form HTTP layer over fetch, with Vaultwarden's error shape. */

/**
 * When the server claims a form field was blank, say which fields we actually sent.
 *
 * `device_identifier cannot be blank` can mean "the client never sent it" or "the server
 * received it under a name it would not bind" — and those need opposite fixes. Without
 * this the operator and I can only guess, which is how a single SSO session lost several
 * rounds of wrong theories. This echoes the real request keys, so the next run is
 * evidence rather than speculation. Only fires on the exact "cannot be blank" shape.
 */
function fieldEcho(method, path, form, detail) {
  if (!form || !/cannot be blank/i.test(String(detail || ""))) return "";
  const keys = Object.keys(form).filter((k) => form[k] !== undefined && form[k] !== null && form[k] !== "");
  return `\n  fields actually sent in this request: ${keys.join(", ") || "(none)"}`
    + `\n  if the field named above appears there, the server received it under a name it`
    + ` would not bind (Vaultwarden\'s FromForm uncased matching is CASE-insensitive only:`
    + ` underscores are not folded, so deviceIdentifier does NOT match device_identifier).`;
}

export class VaultwardenApi {
  constructor({ server, timeoutMs = 20000, fetchFn = null, allowInsecureHttp = false } = {}) {
    if (!server) throw new Error("no vaultwarden server configured (f vaultwarden config --server https://…)");
    this.server = server.replace(/\/+$/, "");
    if (!/^https?:\/\//.test(this.server)) throw new Error(`server must be an http(s) URL, got '${server}'`);
    if (!allowInsecureHttp && this.server.startsWith("http://")) {
      // A self-hosted Vaultwarden is very often plain http over tailscale/lan, so
      // this is a real decision and not a formality: the master-password hash and
      // the API key both travel in the request body. Loopback is called out
      // because it is the one case that is genuinely safe (and what tests use).
      const host = (() => { try { return new URL(this.server).hostname; } catch { return ""; } })();
      const loopback = host === "127.0.0.1" || host === "localhost" || host === "::1" || host === "[::1]";
      throw new Error(
        `refusing to send credentials over plaintext http: ${this.server}` +
          (loopback ? " (loopback; pass --allow-insecure-http or set vaultwarden.allowInsecureHttp to allow it)"
                    : " — put TLS in front of it, or pass --allow-insecure-http if this is a LAN/tailscale address"),
      );
    }
    this.timeoutMs = timeoutMs;
    this.fetch = fetchFn ?? ((...a) => fetch(...a));
    this.accessToken = null;
    this.refreshToken = null;
    // When the current access token actually stops working, per the server's own
    // expires_in. Anything that caches a bearer token needs this: assuming a
    // longer life than the server grants means confident 401s on every read.
    this.accessExpiresAt = null;
  }

  async #request(path, { method = "GET", form = null, json = null, auth = true, headers = {} } = {}) {
    const url = `${this.server}${path}`;
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), this.timeoutMs);
    const h = { Accept: "application/json", "User-Agent": UA, ...headers };
    if (auth && this.accessToken) h.Authorization = `Bearer ${this.accessToken}`;
    let body;
    if (form) { h["Content-Type"] = "application/x-www-form-urlencoded"; body = new URLSearchParams(form).toString(); }
    else if (json != null) { h["Content-Type"] = "application/json"; body = JSON.stringify(json); }
    let res;
    try {
      res = await this.fetch(url, { method, headers: h, body, signal: ac.signal });
    } catch (e) {
      if (e?.name === "AbortError") throw new Error(`timed out after ${this.timeoutMs}ms: ${url} (is the server reachable?)`);
      throw new Error(`cannot reach ${url}: ${e?.cause?.message ?? e?.message ?? e} — check VPN/tailwind/dns (getaddrinfo errors usually mean the name does not resolve)`);
    } finally {
      clearTimeout(timer);
    }
    const text = await res.text();
    if (!res.ok) {
      // Vaultwarden answers with camelCase bodies (`message`, `validationErrors`)
      // while Identity uses `error_description`; the original extractor checked
      // `j.message` but not `j.message`, so every real Vaultwarden error
      // degraded to a bare status code. Empty `error_description` must also not
      // win over the populated `message` beside it.
      let detail = "";
      try {
        const j = JSON.parse(text);
        const ve = j?.validationErrors && typeof j.validationErrors === "object"
          ? Object.values(j.validationErrors).flat().filter(Boolean).join("; ")
          : "";
        detail = [j?.error_description, j?.message, j?.Message, j?.errorModel?.message, ve]
          .map((s) => (typeof s === "string" ? s.trim() : ""))
          .filter(Boolean)
          .find((s, i, all) => all.indexOf(s) === i)
          ?.slice(0, 300) ?? "";
      } catch { detail = text.replace(/\s+/g, " ").trim().slice(0, 200); }

      // Status-specific guidance: without these, the operator sees "HTTP 429" and
      // has no way to know whether to wait, re-authenticate, or fix their config.
      const hint =
        res.status === 429 ? " — the server is rate-limiting logins; wait a few minutes before retrying (repeated attempts extend the lockout)"
          : res.status === 404 && path.includes("prelogin") ? " — the server has no prelogin endpoint for this account (is the email correct?)"
          : res.status === 401 && auth ? " — the access token expired or was revoked; run: f vaultwarden forget"
          : res.status >= 500 ? " — the server failed (this is not a problem with your credentials)"
          : "";
      const err = new Error(`${method} ${path} -> HTTP ${res.status}${detail ? `: ${detail}` : ""}${hint}${fieldEcho(method, path, form, detail)}`);
      err.status = res.status;
      err.body = detail;
      throw err;
    }
    if (!text) return null;
    try {
      return JSON.parse(text);
    } catch {
      throw new Error(`${method} ${path} returned non-JSON (${text.slice(0, 80)}) — is ${this.server} really a Vaultwarden server?`);
    }
  }

  /** KDF parameters for an account. kdf===0 means Bitwarden's default 600000. */
  async prelogin(email) {
    // Sent as JSON, not a form body: verified against a live Vaultwarden, which
    // answers `{"email":…}` as JSON with 200 and rejects the same field sent as
    // application/x-www-form-urlencoded with 400. The two spellings are sent
    // together because the official clients differ on which they use.
    let j = await this.#request("/identity/accounts/prelogin", { method: "POST", json: { email }, auth: false }).catch((e) => {
      if (e.status !== 400 && e.status !== 415) throw e;
      return this.#request("/identity/accounts/prelogin", { method: "POST", form: { email }, auth: false });
    });
    const kdf = Number(j?.kdf ?? 0);
    const kdfIterations = Number(j?.kdfIterations ?? 0);
    if (!Number.isFinite(kdfIterations) || kdfIterations <= 0) {
      // A missing iteration count used to become 600000. For an Argon2id account that
      // number is meaningless (the server said 3), and inventing one derives a wrong key.
      throw new Error(`prelogin returned no usable kdfIterations (${j?.kdfIterations}) for ${email}; refusing to guess`);
    }
    // Both fields matter: kdf selects the algorithm (0 = PBKDF2-SHA256, 1 = Argon2id) and
    // the caller must reject anything but 0 rather than derive with the wrong algorithm.
    return { kdf, kdfIterations, kdfMemory: j?.kdfMemory ?? null, kdfParallelism: j?.kdfParallelism ?? null };
  }

  /** API-key grant. Skips 2FA; yields a token but CANNOT decrypt anything. */
  async loginApiKey({ clientId, clientSecret }) {
    const j = await this.#request("/identity/connect/token", {
      method: "POST",
      auth: false,
      form: {
        grant_type: "client_credentials", scope: API_SCOPE,
        client_id: clientId, client_secret: clientSecret,
        device_type: String(DEVICE_TYPE_CLI),
        device_identifier: DEVICE_IDENTIFIER,
        device_name: DEVICE_NAME,
      },
    });
    if (!j?.access_token) throw new Error("token response had no access_token");
    this.#adoptTokens(j);
    return j;
  }

  /**
   * The client_credentials (API key) grant returns no refresh_token, so a cached
   * access token from it is unrenewable and must not be treated as renewable.
   */
  #adoptTokens(j) {
    this.accessToken = j.access_token;
    this.refreshToken = j.refresh_token ?? null;
    const secs = Number(j.expires_in);
    this.accessExpiresAt = Number.isFinite(secs) && secs > 0 ? Date.now() + secs * 1000 : null;
  }

  /** Password grant. `passwordHash` is masterPasswordHash(), not the raw password. */
  async loginPassword({ email, passwordHash }) {
    const j = await this.#request("/identity/connect/token", {
      method: "POST",
      auth: false,
      form: {
        grant_type: "password", username: email, password: passwordHash.toString("base64"),
        scope: API_SCOPE, client_id: "device",
        device_type: String(DEVICE_TYPE_CLI),
        device_identifier: DEVICE_IDENTIFIER,
        device_name: DEVICE_NAME,
      },
    });
    if (!j?.access_token) {
      const twoFactor = j?.twoFactorProviders ?? j?.twoFactorProviders2;
      const err = new Error("login returned no access_token" + (twoFactor ? ` — 2FA is required (${Object.keys(twoFactor).join(", ")})` : ""));
      err.twoFactor = twoFactor ?? null;
      throw err;
    }
    this.#adoptTokens(j);
    return j;
  }

  /**
   * Renew via a stored refresh_token. Vaultwarden issues these for 30 days
   * (DEFAULT_REFRESH_VALIDITY) on the password/SSO grants, so this is the one
   * path that lets a CLI run for days without re-prompting for the master
   * password. It is simply unavailable after an API-key login.
   */
  async refresh() {
    if (!this.refreshToken) return false;
    const j = await this.#request("/identity/connect/token", {
      method: "POST", auth: false,
      form: { grant_type: "refresh_token", refresh_token: this.refreshToken, client_id: "device" },
    });
    if (!j?.access_token) return false;
    this.#adoptTokens({ ...j, refresh_token: j.refresh_token ?? this.refreshToken });
    // A refresh that returns no refresh_token reuses the old one. Vaultwarden normally
    // rotates it; if it does not, the reused token may already be spent, which shows up as
    // a 401 on the very next call with `authenticated: yes` in the log above it. Say so
    // here, at the place the fact is known, instead of letting the operator read a
    // contradictory pair of lines.
    if (!j.refresh_token) {
      this.refreshTokenUnrotated = true;
      debug("token refresh returned no new refresh_token; reusing the existing one");
    }
    return true;
  }

  /** Adopt a token obtained elsewhere. `expiresAt` is an epoch-ms deadline. */
  setAccessToken(token, { expiresAt = null, refreshToken = null } = {}) {
    this.accessToken = token;
    this.accessExpiresAt = expiresAt;
    if (refreshToken) this.refreshToken = refreshToken;
  }

  /* -------------------------------------------------------------- SSO */

  /**
   * Whether this server has OIDC SSO turned on, without needing a token.
   * `GET /identity/sso/prevalidate` returns {2faRequired, ssoEnabled, ssoOrgIdentifier}
   * when SSO is configured, and a 400 when it is not. That makes it a cheap,
   * unauthenticated probe: better than reading the config and being wrong.
   */
  /**
   * Does this server offer SSO? `GET /identity/sso/prevalidate` is the unauthenticated
   * probe. Shape matters and was got wrong once: current Vaultwarden returns
   * `{"token": "<jwt>"}` when enabled and errors with "SSO sign-in is not available"
   * when not. There is no boolean `ssoEnabled` field, so testing for one reports "not
   * enabled" against a server whose SSO works fine. Presence of the token is the signal;
   * the older spelling is still accepted so a version change is not misread.
   */
  async ssoEnabled() {
    try {
      const j = await this.#request("/identity/sso/prevalidate", { auth: false });
      const enabled = Boolean(j?.token ?? j?.Token ?? j?.ssoEnabled);
      return { enabled, orgIdentifier: j?.ssoOrgIdentifier ?? j?.orgIdentifier ?? null, raw: j, reachable: true };
    } catch (e) {
      // "SSO is off" and "I could not ask" are different answers. Vaultwarden answers
      // this route with a 400 when SSO is disabled, so only an HTTP-level refusal
      // means disabled; a refused connection, TLS problem or timeout means unknown,
      // and reporting that as "not enabled" sends the operator to change a server
      // setting that is probably fine.
      const msg = String(e?.message ?? e);
      const refused = /\bHTTP [45]\d\d/i.test(msg);
      if (refused) return { enabled: false, orgIdentifier: null, raw: null, reachable: true };
      return { enabled: false, orgIdentifier: null, raw: null, reachable: false, error: msg };
    }
  }

  /**
   * Start an SSO authorization: build the IdP URL the operator opens in a browser.
   *
   * Server-side contract (src/sso.rs `authorize_url`): with `client_id=cli` the
   * redirect MUST be `http://localhost:8065..8070`, so a CLI has to run a local
   * callback server on one of those ports or the server rejects it outright. Any
   * other client_id is refused for us ("Unsupported client"), so there is no
   * headless shortcut — the browser hop is the design.
   *
   * `state` is generated by the server and returned to us, so we do not validate
   * it; the `state` echoed back to the callback is the server's own cookie-ish
   * value. We do keep the PKCE `code_verifier`, which is the secret that makes a
   * captured `code` useless to anyone else.
   */
  /**
   * Start an SSO authorization: produce the URL to open in a browser.
   *
   * The real entry point is `GET /identity/connect/authorize` (identity.rs `authorize`),
   * which answers **307 Redirect** to the identity provider. There is no JSON endpoint
   * that hands back an authorize URL — an earlier version of this method POSTed to
   * `/identity/sso/token`, which does not exist, and the server answered 404.
   *
   * So: follow redirects, but *stop* at the IdP. The chain is
   *   /identity/connect/authorize  ->  <issuer>/authorize  ->  (only once a human is
   *   involved) back to http://localhost:<port>. We want the first hop off-box, which is
   *   the URL to show/open; fetching it further would mean driving the IdP without a
   *   browser, which is exactly what we cannot do.
   *
   * @param opts.redirectPort one of 8065-8070; sso.rs accepts nothing else for cli.
   */
  /**
   * Build the SSO authorize URL to hand to a browser.
   *
   * It must be the VAULTWARDEN url — `/identity/connect/authorize?...` — and NOT the
   * IdP url that endpoint redirects to. Vaultwarden sets the browser-binding cookie
   * `VW_SSO_BINDING` on that first response, and `oidcsignin` requires it back (it
   * stores only the SHA-256 of the token). A cookie follows the browser, not the
   * program: if this method resolved the redirect with fetch and returned the IdP url,
   * the Set-Cookie would land in this process's nothing, the browser would complete the
   * IdP round trip carrying no binding cookie, and every attempt would fail
   * `SSO session binding mismatch` — with a valid code, because the IdP half works.
   * That is exactly what happened, and it is why the web vault succeeded: the web vault
   * navigates to `/identity/connect/authorize` *in the browser*.
   *
   * So: no request is made here at all. The browser does the whole chain.
   *
   * @param opts.redirectPort one of 8065-8070; sso.rs `authorize_url` accepts nothing
   *                          else for client_id=cli.
   */
  ssoAuthorizeUrl({ redirectPort = 8065, _onAuthorizeUrl = null } = {}) {
    if (!Number.isInteger(redirectPort) || redirectPort < 8065 || redirectPort > 8070) {
      throw new Error(`redirectPort must be an integer 8065-8070 for client_id=cli (got ${redirectPort})`);
    }
    const codeVerifier = crypto.randomBytes(32).toString("base64url");
    const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
    const state = crypto.randomBytes(16).toString("base64url");
    const q = new URLSearchParams({
      client_id: SSO_CLIENT_ID,
      response_type: "code",
      state,
      code_challenge: codeChallenge,
      code_challenge_method: "S256", // the server requires this literal string
      redirect_uri: `http://localhost:${redirectPort}`,
    });
    const authorizeUrl = `${this.server}/identity/connect/authorize?${q}`;
    // Seam for the tests only: a real IdP learns the challenge when the human's browser
    // arrives at this URL; our mock cannot observe the browser, so it is told here.
    if (_onAuthorizeUrl) _onAuthorizeUrl(authorizeUrl);
    return { authorizeUrl, codeVerifier, state, redirectPort };
  }

  /**
   * Does the server support SSO, without the operator having to try a browser? This is
   * a separate, harmless probe; it is *not* part of the authorize chain and must not be
   * used to prefetch or replace it.
   */
  /**
   * Exchange the browser's authorization code for a vault session.
   *
   * Required by the server for this grant (src/api/identity.rs): client_id, code,
   * code_verifier, device_identifier, device_name, device_type. No client secret —
   * PKCE replaces it. Unlike the API-key grant, this one returns a refresh_token
   * (unless the server sets SSO_AUTH_ONLY_NOT_SESSION), so the session renews for
   * 30 days instead of dying after 2h.
   *
   * The same response carries what key derivation needs — Key, PrivateKey,
   * Kdf/KdfIterations and UserDecryptionOptions — so an SSO session never needs
   * `prelogin`, which is the endpoint an SSO-only account may not be able to use.
   */
  async loginSso({ code, codeVerifier }) {
    const j = await this.#request("/identity/connect/token", {
      method: "POST",
      auth: false,
      form: {
        grant_type: "authorization_code",
        client_id: SSO_CLIENT_ID,
        code,
        code_verifier: codeVerifier,
        scope: SSO_SCOPE,
        device_type: String(DEVICE_TYPE_CLI),
        device_identifier: DEVICE_IDENTIFIER,
        device_name: DEVICE_NAME,
      },
    });
    if (!j?.access_token) {
      const desc = j?.error_description || j?.error || JSON.stringify(j ?? {}).slice(0, 200);
      throw new Error(`SSO token exchange failed: ${desc}`);
    }
    this.#adoptTokens(j);
    return j;
  }

  /**
   * Derive vault keys from an SSO token response.
   *
   * Two genuinely different cases, and conflating them is the trap:
   *
   *  - HasMasterPassword true: SSO replaced *authentication only*. The vault key is
   *    still wrapped with a key derived from the master password, so it is still
   *    required. This is the common case, and the answer to "does SSO remove the
   *    master password": usually no.
   *
   *  - HasMasterPassword false: the account was created through SSO and never had
   *    one. There is no master password to ask for; the user key comes from the
   *    device key pair registered at enrolment (RSA-OAEP). This is the case where
   *    SSO really is sufficient, and it needs `devicePrivateKey` + `devicePublicKey`
   *    obtained during enrolment — it cannot be conjured from a token alone.
   *
   * Throws a message that names the case, so the operator is not told to configure
   * a master password that does not exist.
   */
  static async keysFromSsoToken(tokenJson, { email, masterPassword } = {}) {
    const udo = tokenJson?.UserDecryptionOptions ?? tokenJson?.userDecryptionOptions ?? {};
    const hasMaster = udo.HasMasterPassword ?? udo.hasMasterPassword ?? true;
    const encKey = tokenJson?.Key ?? tokenJson?.key
      ?? udo?.MasterPasswordUnlock?.MasterKeyEncryptedUserKey
      ?? udo?.MasterPasswordUnlock?.MasterKeyWrappedUserKey ?? null;
    // Never default this. An absent Kdf used to fall back to PBKDF2, which then derived a
    // WRONG key and reported "MAC verification failed" — i.e. it accused the operator of
    // typing the wrong master password when the real problem was the algorithm. Bitwarden
    // Kdf 1 is Argon2id, which this client does not implement; it must be named, not
    // silently reinterpreted as PBKDF2.
    const kdfType = Number(tokenJson?.Kdf ?? tokenJson?.kdf ?? Number.NaN);
    const iterations = Number(tokenJson?.KdfIterations ?? tokenJson?.kdfIterations ?? 0);

    if (!hasMaster) {
      throw new Error(
        "this account has no master password: it is SSO-only, and its vault key is sealed to an\n" +
        "  enrolled device key pair (RSA-OAEP), which this CLI has not registered.\n" +
        "  Not implemented here — opening it needs the device-registration ceremony.\n" +
        "  Do NOT store a master password for this account; there isn't one.",
      );
    }

    if (!encKey) {
      throw new Error(`SSO response had no encrypted user key (Key / MasterKeyEncryptedUserKey missing)`);
    }
    if (!masterPassword) {
      throw new Error(
        `this account still uses a master password: SSO authenticated you, but the vault\n` +
        `  key is wrapped with a password-derived key and cannot be unwrapped without it.\n` +
        `  f vaultwarden config --master-password`,
      );
    }
    if (!Number.isInteger(kdfType)) {
      throw new Error("the server did not report which KDF this account uses; refusing to guess");
    }
    if (!Number.isInteger(iterations) || iterations <= 0) {
      throw new Error(`SSO response had no usable KdfIterations: ${tokenJson?.KdfIterations}`);
    }
    const accountEmail = udo?.MasterPasswordUnlock?.Salt || email;
    if (!accountEmail) throw new Error("no email available to use as the KDF salt");
    return deriveKeys({
      email: accountEmail, password: masterPassword, kdfIterations: iterations, encryptedKey: encKey,
      kdfType,
      kdfMemory: Number(tokenJson?.KdfMemory ?? tokenJson?.kdfMemory ?? 0) || null,
      kdfParallelism: Number(tokenJson?.KdfParallelism ?? tokenJson?.kdfParallelism ?? 0) || null,
    });
  }

  /** Full vault: profile.key + every cipher. */
  sync() { return this.#request("/api/sync"); }

  /** Ciphers only — cheaper than sync when you already hold the keys. */
  ciphers() { return this.#request("/api/ciphers"); }

  putCipher(id, payload) { return this.#request(`/api/ciphers/${encodeURIComponent(id)}`, { method: "PUT", json: payload }); }

  alive() { return this.#request("/alive", { auth: false }); }
}

/* ---------------------------------------------------------------- vault */

/**
 * A decrypted view of one vault item, plus enough of the original ciphertext to
 * write fields back without a round trip.
 */
export class VaultItem {
  constructor(raw, keys, opts = {}) {
    this.id = raw.id;
    this.raw = raw;
    this.type = raw.type;
    this.folderId = raw.folderId ?? null;
    this.errors = {};
    // A field that will not decrypt is recorded in `errors` and left undefined
    // rather than thrown: one legacy (unauthenticated) or otherwise odd item must
    // not stop the rest of the vault from yielding credentials.
    const dec = (what, value) => {
      try {
        return decryptString(value, keys, opts);
      } catch (e) {
        // Record it, and keep the message: a vault where every field "fails"
        // usually means a wrong master password, and that has to be legible.
        this.errors[what] = e.message;
        return undefined;
      }
    };

    this.name = dec("name", raw.name) ?? "(undecryptable)";
    this.notes = dec("notes", raw.notes);
    this.login = null;
    this.fields = [];
    this.hidden = { name: raw.name, notes: raw.notes, login: raw.login ? { ...raw.login } : null };
    if (raw.type === CIPHER_TYPE.LOGIN && raw.login) {
      const l = raw.login;
      this.login = {
        username: dec("login.username", l.username),
        password: dec("login.password", l.password),
        totp: dec("login.totp", l.totp),
        uris: Array.isArray(l.uris)
          ? l.uris.map((u) => {
              let uri;
              try { uri = decryptString(u.uri, keys, opts); } catch { uri = undefined; }
              return { match: u.match, uri: uri ?? u.uri };
            })
          : [],
      };
    }
    if (raw.type === CIPHER_TYPE.SECURE_NOTE) {
      // Secure notes keep the text in `login.username`; some clients use `note`.
      this.note = dec("note", raw.login?.username) ?? dec("note2", raw.note);
    }
    for (const [i, f] of (raw.fields ?? []).entries()) {
      this.fields.push({
        name: dec(`fields[${i}].name`, f.name),
        value: dec(`fields[${i}].value`, f.value),
        type: f.type,
        linkedId: f.linkedId ?? null,
      });
    }
  }

  /** All uris of a login item (lowercased, for host matching). */
  uriList() {
    return (this.login?.uris ?? []).map((u) => u.uri).filter(Boolean).map((u) => u.toLowerCase().trim());
  }

  /** Decrypt a hidden field, or null if it holds no secret. */
  hiddenField(which) {
    if (!this.hidden?.login?.[which]) return null;
    return this.hidden.login[which]; // ciphertext; caller decrypts with keys
  }

  /** True when nothing in this item decrypted — almost always a wrong key. */
  fullyFailed() {
    return Object.keys(this.errors).length > 0 && this.name === "(undecryptable)";
  }

  /** Resolve a `name::suffix` selector to a value, or undefined. */
  select(suffix) {
    if (suffix == null || suffix === "password") return this.login?.password;
    if (suffix === "username") return this.login?.username;
    if (suffix === "totp") return this.login?.totp ?? this.login?.totpSource;
    if (suffix === "note") return this.note ?? this.notes;
    if (suffix === "uri") return this.uriList()[0];
    if (suffix.startsWith("field:")) {
      const want = suffix.slice(6).toLowerCase();
      return this.fields.find((f) => (f.name ?? "").toLowerCase() === want)?.value;
    }
    return undefined;
  }

  /** Fields the operator can ask for by suffix, and which of them hold values. */
  fieldSummary() {
    const out = [];
    if (this.login?.username) out.push("username");
    if (this.login?.password) out.push("password");
    if (this.login?.totp) out.push("totp");
    if (this.note) out.push("note");
    for (const f of this.fields) if (f.value) out.push(`field:${f.name}`);
    return out;
  }
}

/** Derive the working key set from an email + master password + a sync payload. */
/**
 * Whether an SSO token response describes an account that can be opened without a
 * master password.
 *
 * `HasMasterPassword:false` means the account was created through SSO and never had
 * one; its user key is sealed to an enrolled device key pair (EncryptionType 3 /
 * RSA-OAEP). Opening that vault needs the device private key *and* the account key
 * that protects it — material an enrolled client holds and a fresh CLI does not.
 *
 * Deliberately not implemented: unwrapping it requires the full device-registration
 * ceremony and cannot be tested offline, so claiming support would be fiction. We
 * detect the case and say so plainly instead of asking the operator for a master
 * password that does not exist.
 */
export function ssoRequiresMasterPassword(tokenJson) {
  const udo = tokenJson?.UserDecryptionOptions ?? tokenJson?.userDecryptionOptions ?? {};
  const hasMaster = udo.HasMasterPassword ?? udo.hasMasterPassword ?? true;
  return !!hasMaster;
}

/**
 * The vault's KDF is per-account and the client cannot choose it. Bitwarden's enum:
 * 0 = PBKDF2-SHA256, 1 = Argon2id. Saying "unsupported kdf 1" is useless; name the
 * algorithm and the setting that controls it.
 */
function kdfUnsupportedMessage(kdfType) {
  const name = kdfType === 1 ? "Argon2id" : `KDF type ${kdfType}`;
  return (
    `this account uses ${name}, which this client cannot derive keys with (only\n` +
    `  PBKDF2-SHA256 is implemented). Nothing is wrong with your master password — the\n` +
    `  algorithm is. Web vault -> Settings -> Security -> Keys -> Encryption key type\n` +
    `  switches the account to PBKDF2 (it re-encrypts the vault; export a backup first).`
  );
}

export async function deriveKeys({ email, password, kdfIterations, encryptedKey, kdfType = KDF_PBKDF2_SHA256, kdfMemory = null, kdfParallelism = null }) {
  // The KDF is per-account and not negotiable; passing the wrong one produces a wrong key
  // whose MAC failure reads as "wrong master password". kdfType comes from prelogin's
  // `kdf` (or the token response's `Kdf`), never from a default.
  let masterKey;
  if (Number(kdfType) === KDF_PBKDF2_SHA256) {
    masterKey = makeMasterKey(password, email, kdfIterations);
  } else if (Number(kdfType) === KDF_ARGON2ID) {
    masterKey = await makeMasterKeyArgon2id(password, email, { iterations: kdfIterations, memory: kdfMemory, parallelism: kdfParallelism });
  } else {
    throw new Error(kdfUnsupportedMessage(kdfType));
  }
  const stretched = stretchMasterKey(masterKey);
  const keys = unwrapSymmetricKey(encryptedKey, stretched);
  keys.masterKey = masterKey;
  keys.stretched = stretched;
  keys.passwordHash = masterPasswordHash(masterKey, password);
  return keys;
}

/**
 * Pull the cipher array out of either response shape.
 *
 *   GET /api/sync    -> { profile: {...}, ciphers: [ ... ] }
 *   GET /api/ciphers -> { object: "list", data: [ ... ], continuationToken: null }
 *
 * The list shape is confirmed against Vaultwarden's own source
 * (src/api/core/ciphers.rs builds `json!({"data": ..., "object": "list",
 * "continuationToken": null})`): `data` IS the array, never `{"data":{"data":...}}`.
 * Upstream Bitwarden capitalises those keys (`"Data"`, `"Object"`) in older
 * releases, so both spellings are accepted.
 *
 * Shapes are matched on their distinguishing key rather than by trying candidates
 * in order: `data` means different things in the two responses, and a permissive
 * fallback returns *zero* items when the wrong one matches — which reads as "your
 * vault is empty" instead of "I misread the response". Unrecognised shapes throw.
 */
export function ciphersFrom(payload, { source = "vault payload" } = {}) {
  if (!payload || typeof payload !== "object") throw new Error(`${source}: empty response`);
  const pick = (o, keys) => { for (const k of keys) if (o?.[k] !== undefined) return o[k]; return undefined; };
  const object = pick(payload, ["object", "Object"]);
  const data = pick(payload, ["data", "Data"]);
  const cont = pick(payload, ["continuationToken", "ContinuationToken"]);
  const ciphers = pick(payload, ["ciphers", "Ciphers"]);

  if (typeof object === "string" && /list/i.test(object) && Array.isArray(data)) {
    // Vaultwarden always returns null here; non-null means more pages exist, and
    // reading only the first would silently hide most of the vault.
    if (cont != null) throw new Error(`${source}: response is paginated — unhandled, use /api/sync`);
    return data;
  }
  if (Array.isArray(ciphers)) return ciphers; // /api/sync
  if (payload.profile || payload.Profile) {
    // A sync carrying no ciphers key at all is a genuinely empty vault.
    if (ciphers == null) return [];
    throw new Error(`${source}: ciphers is ${typeof ciphers}, not an array`);
  }
  throw new Error(
    `${source}: unrecognised response shape (keys: ${Object.keys(payload).join(", ")})` +
      " — refusing to treat it as an empty vault",
  );
}

/** Decrypt every cipher in a sync/ciphers payload. */
export function decryptVault(payload, keys, opts = {}) {
  return ciphersFrom(payload).map((c) => new VaultItem(c, keys, opts));
}

export default { VaultwardenApi, VaultItem, deriveKeys, makeMasterKeyArgon2id, decryptVault, ciphersFrom, decryptString, encryptString, makeMasterKey, stretchMasterKey, hkdfExpand, masterPasswordHash, parseEnvelope, unwrapSymmetricKey, ENC, CIPHER_TYPE };
