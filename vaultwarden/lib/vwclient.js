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
/**
 * Device fields are required -- omit them entirely and the server answers
 * "device_identifier cannot be blank". Send them in ONE spelling: snake_case works, camelCase
 * works, and BOTH TOGETHER produce that same "cannot be blank" error, because Rocket's form
 * binder refuses a field supplied more than once. Verified against a live Vaultwarden for both
 * the password and client_credentials grants; the duplication here is what made every real
 * login fail while every test passed.
 *
 * It is also the reason the mock below must reject the duplication rather than tolerate it: a
 * mock that accepts a request the real server rejects is how this survived the whole test suite.
 */
const DEVICE_IDENTIFIER = "f-vaultwarden-uck";
const DEVICE_NAME = "f creds (vaultwarden provider)";
/**
 * Vaultwarden rejects the bare `api` scope outright — "Scope (api) not supported" — so the
 * password grant never reaches credential validation with it. `api offline_access` is the
 * spelling that gets through. Do not reuse it for client_credentials: that grant has its own
 * accepted scope set and answers "Scope not supported" for offline_access.
 */
const API_SCOPE = "api";
const PASSWORD_SCOPE = "api offline_access";
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
 * grant is a normal user login and accepts it. Kept separate from API_SCOPE and from
 * PASSWORD_SCOPE because the three grants have different, independently-verified rules.
 */
const SSO_CLIENT_ID = "cli";
const SSO_SCOPE = "api offline_access";


const UA = "f-cli/vaultwarden-provider";

/** Cipher type codes (Bitwarden `EncryptionType`). */
export const ENC = { AES_256_CBC_PLAIN: 0, AES_128_CBC: 1, AES_256_CBC_HMAC: 2, RSA_2048_OAEP: 3 };

/** Cipher `type` values we surface. */
export const CIPHER_TYPE = { LOGIN: 1, SECURE_NOTE: 2, CARD: 3, IDENTITY: 4 };

/* ------------------------------------------------------------------ crypto */

/** PBKDF2-HMAC-SHA256(masterPassword, email, iterations) -> 32B masterKey. */
export function makeMasterKey(password, email, iterations) {
  if (!Number.isInteger(iterations) || iterations <= 0) {
    throw new Error(`invalid kdfIterations from server: ${iterations}`);
  }
  return crypto.pbkdf2Sync(Buffer.from(String(password), "utf8"), Buffer.from(String(email), "utf8"), iterations, 32, "sha256");
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
/**
 * Decrypt to raw BYTES. The text API cannot be used for binary payloads: it returns a utf8 JS
 * string, so any byte >= 0x80 is lost -- which is exactly how the wrapped user key stopped
 * being readable. Anything that is not text (the user key, attachments) must use this.
 */
export function decryptBytes(encrypted, keys) {
  const env = parseEnvelope(encrypted);
  if (!env) throw new Error(`unrecognised ciphertext envelope: ${String(encrypted).slice(0, 24)}…`);
  if (env.iv.length !== 16) throw new Error(`ciphertext envelope has a ${env.iv.length}-byte IV (want 16) — refusing`);
  if (env.type === ENC.AES_128_CBC) throw new Error("type 1 ciphertext has no integrity tag — refusing (pass --allow-insecure-crypto if you really must)");
  if (env.type !== ENC.AES_256_CBC_HMAC) {
    if (env.type === ENC.AES_256_CBC_PLAIN) return env.data;
    throw new Error(`unsupported encryption type ${env.type}`);
  }
  if (!env.mac) throw new Error(`type-2 ciphertext missing its MAC tag: ${String(encrypted).slice(0, 24)}…`);
  const want = crypto.createHmac("sha256", keys.macKey).update(env.iv).update(env.ct).digest();
  if (!tagEqual(want, env.mac)) throw new Error("MAC verification failed (wrong key, or tampered ciphertext)");
  const d = crypto.createDecipheriv("aes-256-cbc", keys.encKey, env.iv);
  return Buffer.concat([d.update(env.ct), d.final()]);
}

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
  // The wrapped user key decrypts to 64 RAW key bytes -- enc(32) || mac(32). Not base64, and
  // not "base64 of base64": measured against a real Vaultwarden, `sync.profile.key` and
  // `userDecryption.masterPasswordUnlock.masterKeyEncryptedUserKey` are the same envelope and
  // its plaintext begins 0x01 0x9E 0xAC ... (raw binary). Both earlier guesses here -- "double
  // base64", then "88 chars of base64" -- came from reading a spec page instead of the bytes,
  // and both would have been caught by one real account, which is what the fixture in
  // test/crypto.test.mjs now is.
  //
  // Verify the MAC on the CIPHERTEXT first, exactly as Bitwarden does, and only then decrypt.
  // Decrypting first -- which this function used to do via decryptString -- destroys the
  // distinction that matters: with the wrong master key the CBC plaintext is random, so
  // PKCS#7 unpadding throws here, and the operator sees
  //     unexpected symmetric key length 13 (want 64)
  // for what is actually a wrong master password. That message cost hours: it was read as a
  // vault-shape bug on a server nobody could inspect, while the password was correct all
  // along and the real fault was the order of these two operations.
  const env = parseEnvelope(encryptedKey);
  if (!env) throw new Error(`unrecognised wrapped-key envelope: ${String(encryptedKey).slice(0, 24)}…`);
  if (env.type !== ENC.AES_256_CBC_HMAC) {
    if (env.type === ENC.AES_128_CBC) throw new Error("wrapped key uses unauthenticated type 1 ciphertext — refusing (pass --allow-insecure-crypto if you really must)");
    throw new Error(`unsupported wrapped-key encryption type ${env.type}`);
  }
  if (!env.mac) throw new Error("wrapped key has no MAC tag");
  const want = crypto.createHmac("sha256", stretched.macKey).update(env.iv).update(env.ct).digest();
  if (!tagEqual(want, env.mac)) throw new Error("MAC verification failed (wrong key, or tampered ciphertext)");

  const d = crypto.createDecipheriv("aes-256-cbc", stretched.encKey, env.iv);
  // Keep this BINARY. The plaintext is 64 raw key bytes, not text and not base64: converting
  // it with toString("utf8") replaces every byte above 0x7F with U+FFFD, and re-decoding that
  // damaged string yields 13 bytes. That is where the "unexpected symmetric key length 13"
  // that haunted this uck actually came from -- not a weird vault shape, not a wrong master
  // password, but a Buffer->string round trip through UTF-8. Verified against a real Vaultwarden.
  const buf = Buffer.concat([d.update(env.ct), d.final()]);
  if (buf.length !== 64) {
    throw new Error(`unexpected symmetric key length ${buf.length} (want 64)`);
  }
  const encKey = buf.subarray(0, 32);
  return { encKey, macKey: buf.subarray(32, 64), symmetricKey: encKey };
}

/* -------------------------------------------------------------- api client */

/** Minimal JSON/form HTTP layer over fetch, with Vaultwarden's error shape. */
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
      const err = new Error(`${method} ${path} -> HTTP ${res.status}${detail ? `: ${detail}` : ""}${hint}`);
      err.status = res.status;
      err.body = detail;
      // Raw text for debugging, kept separate from the parsed `detail` above.
      err.rawBody = text;
      // Validation failures are the ones worth echoing: this server rejected a login because a
      // form field was duplicated, and the only trace was "device_identifier cannot be blank"
      // buried in validationErrors. Never echo a whole body -- token responses legitimately
      // contain access/refresh tokens -- so surface the MESSAGE text and the FIELD NAMES only.
      try {
        const j = JSON.parse(text);
        const ve = j?.validationErrors && typeof j.validationErrors === "object" ? j.validationErrors : null;
        if (ve) err.fieldErrors = Object.entries(ve).map(([k, v]) => `${k}: ${[].concat(v).join(", ")}`);
      } catch { /* non-JSON body; nothing structured to report */ }
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
    const kdfIterations = Number(j?.kdfIterations ?? 600000);
    return { kdf: Number(j?.kdf ?? 0), kdfIterations: Number.isFinite(kdfIterations) && kdfIterations > 0 ? kdfIterations : 600000 };
  }

  /** API-key grant. Skips 2FA; yields a token but CANNOT decrypt anything. */
  async loginApiKey({ clientId, clientSecret }) {
    const j = await this.#request("/identity/connect/token", {
      method: "POST",
      auth: false,
      form: {
        grant_type: "client_credentials", scope: API_SCOPE,
        client_id: clientId, client_secret: clientSecret,
        device_identifier: DEVICE_IDENTIFIER, device_name: DEVICE_NAME, device_type: String(DEVICE_TYPE_CLI),
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
        scope: PASSWORD_SCOPE, client_id: "device",
        device_identifier: DEVICE_IDENTIFIER, device_name: DEVICE_NAME, device_type: String(DEVICE_TYPE_CLI),
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
export function deriveKeys({ email, password, kdfIterations, encryptedKey }) {
  const masterKey = makeMasterKey(password, email, kdfIterations);
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

export default { VaultwardenApi, VaultItem, deriveKeys, decryptVault, ciphersFrom, decryptString, encryptString, makeMasterKey, stretchMasterKey, hkdfExpand, masterPasswordHash, parseEnvelope, unwrapSymmetricKey, ENC, CIPHER_TYPE };

export function ssoRequiresMasterPassword(tokenJson) {
  const udo = tokenJson?.UserDecryptionOptions ?? tokenJson?.userDecryptionOptions ?? {};
  const hasMaster = udo.HasMasterPassword ?? udo.hasMasterPassword ?? true;
  return !!hasMaster;
}
