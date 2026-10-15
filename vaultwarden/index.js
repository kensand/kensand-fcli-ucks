#!/usr/bin/env node
// f vaultwarden — read (and patch) secrets from a Vaultwarden vault, and act as
// a credential provider for `f creds`.
//
// ## How it fits together
//
//   ~/.f/f.config.json          server + email (non-secret)
//   creds: vaultwarden.client-id / .client-secret   API key (optional)
//   creds: vaultwarden.master-password              the master password
//   creds: mirror:<name>        vault values mirrored locally, with an expiry
//
// `f creds get <name>` reaches this uck through the provider table when it has
// no local value; see creds/providers.js. That path runs `index.js resolve`, so
// importing this module must stay side-effect free — hence uckMain().
//
// ## The constraint that shapes every decision here
//
// An API key (grant_type=client_credentials) only buys an access token. It
// cannot decrypt: Bitwarden's vault is end-to-end encrypted with a key derived
// from the master password, so the master password is required for any read
// (bitwarden/clients#18097). The API key's real value is that it bypasses 2FA
// and avoids the interactive login dance.
//
// Consequently this uck does NOT do a password login when an API key is
// configured, even though it could. A password grant with 2FA enabled fails, and
// failing that way would look like a broken password.

import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

import { uckMain } from "../../fcli-ucks/lib/uckmain.js";
import { spawn } from "node:child_process";
import { captureSsoCode } from "./lib/sso-callback.js";
import {
  VaultwardenApi,
  deriveKeys,
  decryptVault,
  decryptString,
  encryptString,
  makeMasterKey,
  masterPasswordHash,
  ssoRequiresMasterPassword,
  CIPHER_TYPE,
} from "./lib/vwclient.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const F = path.join(process.env.HOME ?? "", ".f");
const CONFIG = path.join(F, "f.config.json");

// cred names inside the store
const C_SERVER = "vaultwarden.server";
const C_EMAIL = "vaultwarden.email";
const C_CLIENT_ID = "vaultwarden.client-id";
const C_CLIENT_SECRET = "vaultwarden.client-secret";
const C_MASTER = "vaultwarden.master-password";
const C_TOKEN = "vaultwarden.access-token";
const C_REFRESH = "vaultwarden.refresh-token";
const C_KEY_CACHE = "vaultwarden.key-cache";
const C_EXPIRES = "vaultwarden.access-expires-at";

/** How long a mirrored value may sit before `f creds` re-asks the vault. */
const MIRROR_TTL_SEC = 3600;
/** How long derived vault keys may be kept, so reads do not redo PBKDF2. */
const KEY_CACHE_TTL_SEC = 8 * 3600;
// Only used if the server omits expires_in. Vaultwarden's own access-token
// lifetime is 2h; 1h keeps us on the right side of that without trusting it.
const ACCESS_TTL_FALLBACK_SEC = 3600;

/* --------------------------------------------------------------- config */

function readJson(p) {
  try {
    return JSON.parse(fs.readFileSync(p, "utf8"));
  } catch {
    return {};
  }
}
function writeJson(p, obj) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(obj, null, 2) + "\n", { mode: 0o600 });
  fs.chmodSync(p, 0o600);
}

/** Server + email live in f.config.json; secrets live in the creds store. */
function vwConfig() {
  const cfg = readJson(CONFIG);
  const v = cfg.vaultwarden ?? cfg.vault ?? {};
  return {
    server: v.server ?? null,
    email: v.email ?? null,
    // Optional override; the store's value wins when present.
    masterPasswordCred: v.masterPasswordCred ?? C_MASTER,
    allowInsecureHttp: !!v.allowInsecureHttp,
    timeoutMs: Number(v.timeoutMs ?? 20000),
    map: v.map ?? {},          // cred name -> "Item Name::password"
    extraNames: v.extraNames ?? {}, // vault item name -> [extra cred names]
  };
}

function saveVwConfig(patch) {
  const cfg = readJson(CONFIG);
  cfg.vaultwarden = { ...(cfg.vaultwarden ?? {}), ...patch };
  writeJson(CONFIG, cfg);
  return cfg.vaultwarden;
}

/* ---------------------------------------------------- creds store access */

/**
 * True when we are running *inside* credential-provider discovery.
 *
 * Without this the whole thing is a fork bomb. `status()` needs the creds store,
 * so it shells out to `f creds …`; but `f creds status` (and `f providers`)
 * discovers providers, and discovery calls each provider's `status()` — which
 * shells out to `f` again. Every level spawns another, so a single
 * `f vaultwarden status` or `f providers` multiplies into thousands of processes
 * until the box stops responding. Observed for real: 2,643 live processes.
 *
 * The cycle: `status()` reads the creds store, which means spawning `f creds …`;
 * `f creds status` runs provider discovery; discovery execs this uck's
 * `status`; repeat. The marker is inherited by the children we spawn, so the
 * second level stops dead.
 */
const inDiscovery = () => process.env.F_CREDS_NO_PROVIDER === "1";

/**
 * Cut the discovery cycle before it starts, for the probe subcommands.
 *
 * Called from main() when argv is `status|resolve|has|list`. The marker makes
 * every `f` child we spawn decline to run provider discovery, so nothing can call
 * back into this process's `status()`.
 *
 * It is deliberately set *here*, not by inspecting argv inside credsGet():
 * `f vaultwarden list` and `f vaultwarden resolve` are legitimate commands that
 * must reach the store, and blanket-suppressing them would turn the provider into
 * a no-op that always claims the store is fine.
 */
function enterDiscoveryProbe() {
  process.env.F_CREDS_NO_PROVIDER = "1";
}

/** Ask `f creds` for a value. Returns null when locked/absent; throws on a real
 *  provider error so it is never mistaken for "not set". */
function credsGet(name) {
  try {
    const out = execFileSync("f", ["creds", "get", name, "--secrets", "--local"], {
      encoding: "utf8",
      timeout: 15000,
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, F_CREDS_NO_PROVIDER: "1" },
    });
    return out.replace(/\n$/, "");
  } catch (e) {
    // Report what `f creds` actually said, minus its own "f: " prefix (this process prefixes
    // too, so passing it through printed "f: f: ..."), and never let a raw child stderr become
    // the whole message: an operator read "f: f: Unsupported state or unable to authenticate
    // data" and spent a long time hunting a crypto bug. There was none -- the master password
    // had simply never been stored. Name the condition and the fix.
    const err = (e?.stderr ?? "").toString().replace(/^f:\s*/gm, "").trim();
    if (/no such cred/i.test(err)) return null;
    if (/locked/i.test(err)) throw new Error(`creds are locked — run: f creds unlock`);
    if (/not unlocked|no daemon|connection refused|enoent|econnrefused/i.test(err)) {
      throw new Error(`cannot reach the creds store — run: f creds unlock  (${err.split("\n")[0].slice(0, 90)})`);
    }
    if (/timed out|etimedout/i.test(err) || e?.signal === "SIGKILL") {
      throw new Error(`f creds get ${name} timed out (the store may be waiting on a passphrase it cannot ask for)`);
    }
    throw new Error(err ? `f creds get ${name} failed: ${err.split("\n")[0].slice(0, 160)}` : `f creds get ${name} failed`);
  }
}

function credsSet(name, value) {
  // Deliberately NOT `f creds set <name> <value>`: that puts the secret in argv,
  // where any process can read it from `ps` for the lifetime of the command. The
  // daemon's socket takes the value in a JSON body instead.
  const sock = (() => {
    try {
      return JSON.parse(fs.readFileSync(path.join(F, ".creds-daemon"), "utf8")).socket;
    } catch {
      throw new Error("creds are locked — run: f creds unlock");
    }
  })();
  return new Promise((resolve, reject) => {
    const c = net.connect(sock, () => c.write(JSON.stringify({ op: "set", name, value: String(value) })));
    let buf = "";
    c.on("data", (d) => (buf += d));
    c.on("end", () => {
      try {
        const r = JSON.parse(buf);
        r.ok ? resolve(true) : reject(new Error(r.error));
      } catch (e) {
        reject(e);
      }
    });
    c.on("error", reject);
  });
}

function credsRm(name) {
  try {
    execFileSync("f", ["creds", "rm", name], { stdio: ["ignore", "ignore", "pipe"], timeout: 10000, env: { ...process.env, F_CREDS_NO_PROVIDER: "1" } });
    return true;
  } catch {
    return false;
  }
}

function credsStatus() {
  try {
    const out = execFileSync("f", ["creds", "status"], { encoding: "utf8", timeout: 15000, stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, F_CREDS_NO_PROVIDER: "1" } });
    return { unlocked: /^unlocked/m.test(out), text: out.trim().split("\n")[0] };
  } catch {
    return { unlocked: false, text: "locked" };
  }
}

/* -------------------------------------------------------- secret prompt */

/** Read a secret from the TTY without echoing. */
async function promptSecret(label) {
  if (!process.stdin.isTTY) {
    const rl = readline.createInterface({ input: process.stdin });
    const line = await new Promise((r) => rl.question(label, (a) => { rl.close(); r(a); }));
    return line;
  }
  return new Promise((resolve) => {
    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding("utf8");
    process.stderr.write(label);
    let buf = "";
    const cleanup = () => {
      stdin.removeListener("data", onData);
      stdin.setRawMode(wasRaw ?? false);
      stdin.pause();
    };
    const onData = (ch) => {
      for (const c of ch.toString()) {
        if (c === "\n" || c === "\r") { cleanup(); process.stderr.write("\n"); resolve(buf); return; }
        if (c === "\x7f" || c === "\x08") { if (buf.length) buf = buf.slice(0, -1); }
        else if (c === "\x03") { cleanup(); process.stderr.write("\n"); process.exit(1); }
        else buf += c;
      }
    };
    stdin.on("data", onData);
  });
}

/* -------------------------------------------------------- name matching */

/** Host part of a cred name: `forgejo.kensand.net` or `github.com:443`. */
function nameHost(name) {
  const s = String(name ?? "").trim().toLowerCase();
  if (!s) return null;
  // A cred name is a bare host, or a vault item name. Only the host form gets
  // uri matching; item names are matched by name elsewhere.
  return /^[a-z0-9._-]+(:\d+)?$/.test(s) ? s.split(":")[0] : null;
}

/** Normalize a vault uri ("https://x.y/path") to a comparable host. */
function uriHost(uri) {
  if (!uri) return null;
  const s = String(uri).trim().toLowerCase();
  if (!s) return null;
  try {
    return new URL(s).hostname;
  } catch {
    return s.replace(/^[a-z0-9+.-]+:\/\//, "").split(/[/?#]/)[0].split("@").pop() || null;
  }
}

/** Does an item uri stand for this host? Supports Bitwarden's wildcard form. */
function uriMatchesHost(uri, host) {
  const uh = uriHost(uri);
  if (!uh || !host) return false;
  if (uh === host) return true;
  if (uh.startsWith("*.")) {
    const base = uh.slice(2);
    return host === base || host.endsWith(`.${base}`);
  }
  return false;
}

/** Map a vault item to the cred names it can answer. */
function namesForItem(item, cfg) {
  const out = new Set();
  // 1. explicit map entries whose target names this item
  for (const [credName, selector] of Object.entries(cfg.map ?? {})) {
    const target = String(selector).split("::")[0].trim().toLowerCase();
    if (target && (target === item.name.trim().toLowerCase() || target === item.id.toLowerCase())) out.add(credName);
  }
  // 2. declared aliases
  for (const [vaultName, extras] of Object.entries(cfg.extraNames ?? {})) {
    if (vaultName.trim().toLowerCase() === item.name.trim().toLowerCase()) for (const e of extras ?? []) out.add(e);
  }
  // 3. the item's own name and id (ids are unique; names are not)
  out.add(item.name.trim());
  out.add(item.id);
  // 4. its uris' hosts
  for (const uri of item.uriList()) {
    const h = uriHost(uri);
    if (h) out.add(h);
  }
  return [...out];
}

/* ------------------------------------------------------ session handling */

/**
 * Get an authenticated, decrypted view of the vault.
 *
 * Order: cached derived keys -> API-key token + master password -> error with
 * the exact thing to fix. Never attempts a password grant (see file header).
 */
/**
 * Get a bearer token. The password grant comes first; the API key is a fallback.
 *
 * An API key is NOT required to read a vault, which is what an earlier version of this file
 * asserted. Bitwarden's password grant authenticates with HMAC(masterKey, password), computed
 * locally — the server never sees the password or any key material. The API key's real and
 * only job is to get past 2FA. Scope rules are per-grant and were probed against a live
 * Vaultwarden with a nonexistent account (no real credential was ever sent):
 *
 *   password           scope=api                 -> "Scope (api) not supported"
 *   password           scope=api offline_access  -> reaches credential validation
 *   client_credentials scope=api                 -> reaches client-id validation  (correct)
 *   client_credentials scope=api.device/.offline -> "Scope not supported"
 *
 * So a "Scope ... not supported" line is THIS CODE's bug, never the operator's credentials,
 * and the messages below say so instead of sending them off to retype a correct password.
 */
async function authenticate(api, { email, passwordHash }) {
  const errs = [];
  try {
    await api.loginPassword({ email, passwordHash });
    return "password";
  } catch (e) {
    // Do not fall through on a server-side throttle: retrying with another credential only
    // extends the lockout, and reporting this as a "miss" would let the provider layer cache
    // it, so every later lookup answers "not found" for a vault that is actually fine.
    if (e.status === 429 || /rate-limiting|Too many login/i.test(String(e.message))) throw e;
    // A rejected password is a verdict, not a hint to try a different credential. Falling
    // through here let a valid API key authenticate the run, which then unwrapped the vault
    // with the wrong master key and reported a bad password as "no such item".
    if (/Username or password is incorrect/i.test(String(e.message))) {
      // Deliberately does NOT conclude "your master password is wrong". Bitwarden returns this
      // one string for a bad username, a bad password, and a rejected token REQUEST, and cannot
      // tell them apart. Asserting the password was at fault sent one debugging session chasing
      // PBKDF2 and key-unwrap bugs for hours while the master password was verifiably correct --
      // proven offline, with no login at all, by unwrapping profile.key and checking the MAC:
      //     deriveKeys({ email, password, kdfIterations, encryptedKey: profile.key })
      // When this fires, run that check before suspecting the password.
      throw new Error(
        `the server refused to issue a token for ${email}\n` +
        `  it answers "Username or password is incorrect" for a wrong email, a wrong password,\n` +
        `  AND for a rejected request -- it does not distinguish them, so do not assume which.\n` +
        `  do not retry blindly: repeated attempts can trigger a lockout.\n` +
        (e.fieldErrors?.length ? `  rejected fields: ${e.fieldErrors.join(" | ").slice(0, 300)}\n` : "") +
        // A raw body is never echoed: token responses contain access and refresh tokens.
        (process.env.F_VW_DEBUG_RESPONSE
          ? `  server message: ${String(e.body ?? "").slice(0, 300) || "(none)"}\n`
          : "") +
        `  to rule the password in or out WITHOUT another login attempt:\n` +
        `    node -e 'const c=require("node:crypto"),{VaultwardenApi,makeMasterKey,stretchMasterKey}\n` +
        `      =require(process.env.HOME+"/.f/ucks/kensand-fcli-ucks/vaultwarden/lib/vwclient.js"));\n` +
        `      /* needs one authenticated sync to get profile.key; see test/crypto.test.mjs */'\n` +
        `  also check the email: it is the KDF salt, so a stale one in f.config.json makes\n` +
        `  every derived key wrong no matter what you type`,
      );
    }
    if (e.twoFactor) {
      throw new Error(
        `this account requires 2FA, which the password grant cannot satisfy from a CLI\n` +
        `  types offered: ${Object.keys(e.twoFactor).join(", ")}\n` +
        `  use an API key — bypassing 2FA is exactly what it is for:\n` +
        `  web vault -> Settings -> Security -> Keys -> API key\n` +
        `    f creds set ${C_CLIENT_ID} 'user.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'\n` +
        `    f creds set ${C_CLIENT_SECRET} '<client secret>'`,
      );
    }
    errs.push(`password grant: ${String(e.message).split("\n")[0].slice(0, 140)}`);
  }
  const clientId = credsGet(C_CLIENT_ID), clientSecret = credsGet(C_CLIENT_SECRET);
  if (clientId && clientSecret) {
    try { await api.loginApiKey({ clientId, clientSecret }); return "apikey"; }
    catch (e) {
      if (e.status === 429 || /rate-limiting|Too many login/i.test(String(e.message))) throw e;
      errs.push(`api-key grant: ${String(e.message).split("\n")[0].slice(0, 140)}`);
    }
  } else {
    errs.push("api-key grant: not configured (optional; only needed when 2FA is on)");
  }
  throw new Error(`could not authenticate to ${api.server}\n  ${errs.join("\n  ")}\n` +
    `  a "Scope ... not supported" line means THIS CODE sent a scope the server does not` +
    `  accept -- it is not a problem with your credentials or your server.`);
}

async function openVault({ quiet = false, forceUnlock = false, allowInsecureHttp = false } = {}) {
  const cfg = vwConfig();
  if (!cfg.server) throw new Error(`no server configured\n  f vaultwarden config --server https://vault.example.com --email you@example.com`);
  if (!cfg.email) throw new Error(`no email configured\n  f vaultwarden config --email you@example.com`);
  const status = credsStatus();
  if (!status.unlocked) throw new Error(`creds are locked (the vault's master password lives in the store)\n  f creds unlock`);

  const api = new VaultwardenApi({
    server: cfg.server,
    email: cfg.email,
    timeoutMs: cfg.timeoutMs,
    allowInsecureHttp: allowInsecureHttp || cfg.allowInsecureHttp,
  });

  // Fast path: cached derived keys + token, so reads do not redo PBKDF2 (~1s).
  if (!forceUnlock) {
    const hit = await tryCachedSession(api);
    if (hit) return { api, cfg, keys: hit.keys, items: decryptVault(hit.payload, hit.keys), fromCache: true };
  }

  const master = credsGet(cfg.masterPasswordCred);

  // An SSO login left a refreshable token in the store. Use it before demanding an API
  // key: `sso login` mints one valid for ~30 days, and refusing to read it made an SSO
  // user configure credentials they did not need.
  const ssoAccess = credsGet(C_TOKEN);
  const ssoRefresh = credsGet(C_REFRESH);
  if ((ssoAccess || ssoRefresh) && master) {
    api.setAccessToken(ssoAccess, { refreshToken: ssoRefresh });
    // Prove the token is still good before spending ~1s on PBKDF2, and refresh once if
    // the access token has aged out — this is the whole point of SSO having a refresh token.
    // NOTE: refresh() consumes the refresh token. Vaultwarden rotates them by default, so
    // a refresh that is not persisted immediately burns the token — a later run then gets
    // invalid_grant. Do not call refresh() speculatively; only do it when the bearer token
    // actually failed, and store the replacement before anything else can throw.
    let payload = await api.ciphers().catch(async (e) => {
      if (!/HTTP 401|HTTP 403/.test(String(e?.message))) throw e;
      const refreshed = await api.refresh().catch((e2) => {
        process.stderr.write(`token refresh failed: ${String(e2.message).split("\n")[0].slice(0, 120)}\n`);
        return false;
      });
      if (!refreshed) return null;
      await persistSsoTokens(api);
      return await api.ciphers().catch(() => null);
    });
    if (payload) {
      // Keys come from prelogin + sync + master password, exactly as the API-key path
      // does them: prelogin yields only KDF params, and the wrapped user key is
      // sync.profile.key. SSO authenticates; it does not replace the master password,
      // which is why this branch requires `master`.
      try {
        const pre = await api.prelogin(cfg.email);
        const kdfCfg = kdfConfigFor(pre, cfg.email);
        const sync = await api.sync();
        const encKey = sync?.profile?.key;
        if (!encKey) throw new Error("sync returned no profile.key");
        const keys = await deriveKeys({ email: cfg.email, password: master, encryptedKey: encKey, ...kdfCfg });
        await writeKeyCache(cfg, keys, api);
        const items = decryptVault(payload, keys);
        return { api, cfg, keys, items: items.length ? items : decryptVault(sync, keys), fromCache: false };
      } catch (e) {
        const m = String(e.message ?? e);
        // Distinguish "your master password is wrong" from "the token was fine but
        // something else failed": falling through to an unrelated "no API key stored"
        // is what sent an operator off to create an API key they did not need.
        if (process.env.VW_TRACE) process.stderr.write("[trace] " + String(e?.stack ?? e) + "\n");
        throw new Error(
          (/MAC verification failed/.test(m)
            ? `the SSO session works but the stored master password does not unlock the vault — do not retry blindly, retype it:`
            : `the SSO session works but the vault could not be opened: ${m.split("\n")[0]}\n  `) +
          `  f vaultwarden config --master-password`,
        );
      }
    }
    // Nothing usable was said, so fall through to the API key below.
  }

  if (!master) {
    throw new Error(
      `no master password stored — nothing can be decrypted, and there is no login proof either\n` +
      `  f vaultwarden config --master-password   (prompts, no echo)\n` +
      `  It does double duty: it is the login credential AND the key that unlocks the vault.`,
    );
  }

  const pre = await api.prelogin(cfg.email);
  // The master key is needed on BOTH sides, so derive once and use it twice: the server
  // receives HMAC(masterKey, password) as the login proof, and the vault needs the HKDF-
  // stretched key to unwrap profile.key. Because the proof is computable offline, logging in
  // needs nothing but the password -- which is why an API key is optional here, not required.
  const masterKey = makeMasterKey(master, cfg.email, pre.kdfIterations);
  const passwordHash = masterPasswordHash(masterKey, master);

  await authenticate(api, { email: cfg.email, passwordHash });

  const sync = await api.sync();
  const encKey = sync?.profile?.key;
  if (!encKey) throw new Error(`sync returned no profile.key — account may not be set up, or the token lacks vault scope`);
  let keys;
  try {
    keys = deriveKeys({ email: cfg.email, password: master, kdfIterations: pre.kdfIterations, encryptedKey: encKey });
  } catch (e) {
    if (/MAC verification failed/.test(String(e.message))) {
      throw new Error(`master password is wrong (key unwrap failed MAC check) — do not retry blindly, retype it: f vaultwarden config --master-password`);
    }
    throw e;
  }
  await writeKeyCache(cfg, keys, api);
  // Re-read via /api/ciphers. If that fails we fall back to the sync we already
  // hold — but only when it actually carries ciphers; treating a cipher-less
  // sync as "0 items" would make a transient failure look like an empty vault,
  // and every lookup would then report "no such item".
  let payload = null;
  try {
    payload = await api.ciphers();
  } catch (e) {
    if (Array.isArray(sync?.ciphers)) payload = sync;
    else throw new Error(`vault read failed: ${e.message} (sync carried no ciphers to fall back on)`);
  }
  const items = decryptVault(payload, keys);
  return { api, cfg, keys, items, fromCache: false, kdf: pre };
}

/* ------------------------------------------------ key cache (in the box) */

async function readKeyCache() {
  let blob;
  try {
    blob = credsGet(C_KEY_CACHE);
  } catch {
    return null;
  }
  if (!blob) return null;
  try {
    const j = JSON.parse(blob);
    if (!j?.exp || Date.now() > j.exp) { credsRm(C_KEY_CACHE); return null; }
    if (!j.accessToken || !j.encKey || !j.macKey) return null;
    const b64 = (s) => Buffer.from(s, "base64");
    return {
      accessToken: j.accessToken,
      refreshToken: j.refreshToken ?? null,
      keyExp: j.exp,
      keys: { encKey: b64(j.encKey), macKey: b64(j.macKey), symmetricKey: b64(j.encKey) },
    };
  } catch {
    return null;
  }
}

/**
 * When the cached *access token* stops being useful — never longer than the
 * server's own stated lifetime. Vaultwarden mints access tokens valid for 2h
 * (DEFAULT_ACCESS_VALIDITY in src/auth.rs), so a fixed 8h cache expiry would
 * hand back a token the server rejects and turn every read into a 401 dance.
 * The derived keys themselves stay valid until `keyExp`.
 */
function accessExpiry(accessExpiresAt, keyExp) {
  const now = Date.now();
  if (Number.isFinite(accessExpiresAt) && accessExpiresAt > now) {
    // Leave 60s of slack so we never present a token in its final second.
    return Math.min(accessExpiresAt - 60_000, keyExp);
  }
  return Math.min(now + ACCESS_TTL_FALLBACK_SEC * 1000, keyExp);
}

function cacheBlob({ keys, accessToken, refreshToken, accessExp, keyExp }) {
  return JSON.stringify({
    exp: keyExp,
    accessExp,
    accessToken,
    refreshToken: refreshToken ?? null,
    encKey: keys.encKey.toString("base64"),
    macKey: keys.macKey.toString("base64"),
  });
}

async function writeKeyCache(cfg, keys, api) {
  if (!api.accessToken) return;
  const keyExp = Date.now() + KEY_CACHE_TTL_SEC * 1000;
  await credsSet(C_KEY_CACHE, cacheBlob({
    keys,
    accessToken: api.accessToken,
    refreshToken: api.refreshToken,
    accessExp: accessExpiry(api.accessExpiresAt, keyExp),
    keyExp,
  }));
}

function dropKeyCache() {
  credsRm(C_KEY_CACHE);
}

/**
 * Serve a request from cached keys if possible.
 *
 * Returns { keys, payload }, or null when a full re-authentication is needed.
 * Any error other than a rejected token propagates — a network failure is not a
 * reason to re-derive keys and try the same request again.
 *
 * On a rejected token there are exactly two cases, and they must not be blurred:
 *   - we hold a refresh_token (a password/SSO grant gave us one): renew once,
 *     retry, and persist the rotated token.
 *   - we do not (an API-key login never returns one): the cached material is
 *     spent. Returning null is the only honest answer; pretending otherwise means
 *     silently re-running PBKDF2 on every read, forever, while reporting a cache
 *     hit to the operator.
 */
async function tryCachedSession(api) {
  const cached = await readKeyCache();
  if (!cached) return null;
  api.setAccessToken(cached.accessToken, { refreshToken: cached.refreshToken });
  try {
    return { keys: cached.keys, payload: await api.ciphers() };
  } catch (e) {
    if (!/HTTP 401|HTTP 403/.test(String(e?.message))) throw e;
    if (!cached.refreshToken) {
      // Loud, once per process: an 8h "key cache" that re-derives keys on every
      // read is a lie in the status output, and the operator deserves to know.
      process.stderr.write("f vaultwarden: cached access token expired and cannot be refreshed (an API-key login yields no refresh token) — re-authenticating\n");
      return null;
    }
    if (!(await api.refresh().catch(() => false))) return null;
    try {
      const payload = await api.ciphers();
      // Keep the rotated token alongside the still-valid key material.
      const keyExp = cached.keyExp ?? Date.now() + KEY_CACHE_TTL_SEC * 1000;
      await credsSet(
        C_KEY_CACHE,
        cacheBlob({
          keys: cached.keys,
          accessToken: api.accessToken,
          refreshToken: api.refreshToken,
          accessExp: accessExpiry(api.accessExpiresAt, keyExp),
          keyExp,
        }),
      );
      return { keys: cached.keys, payload };
    } catch {
      return null;
    }
  }
}

/* ------------------------------------------------------- item resolution */

/**
 * Find the vault item (+field) that answers cred `name`.
 *
 * Priority: explicit map → exact item name → unique uri host match. Anything
 * ambiguous returns { ambiguous: [...] } rather than guessing: silently serving
 * the wrong secret is worse than an error, and duplicate item names are normal
 * in real vaults.
 */
function findValue(name, items, cfg, { suffix } = {}) {
  const wanted = String(name).trim();
  let selector = null;
  let key = wanted;
  if (wanted.includes("::")) {
    const i = wanted.indexOf("::");
    key = wanted.slice(0, i).trim();
    suffix = wanted.slice(i + 2).trim() || suffix;
  }
  const lc = key.toLowerCase();

  // 1. explicit map. The target may be an item NAME or an item ID; ids are
  //    unique, so a map entry pointing at an id can never be ambiguous.
  const mapped = Object.entries(cfg.map ?? {}).find(([k]) => k.toLowerCase() === lc);
  if (mapped) {
    const sel = String(mapped[1]);
    const [itemName, field] = sel.includes("::") ? [sel.slice(0, sel.indexOf("::")), sel.slice(sel.indexOf("::") + 2)] : [sel, undefined];
    const want = itemName.trim().toLowerCase();
    const byId = items.filter((i) => i.id.toLowerCase() === want);
    const hits = byId.length ? byId : items.filter((i) => i.name.trim().toLowerCase() === want);
    if (!hits.length) return { unknown: `map entry '${mapped[0]}' -> item '${itemName}' does not exist in the vault (f vaultwarden list --search ${itemName})` };
    if (hits.length > 1) return { ambiguous: hits.map(describe), reason: `map target '${itemName}' matches ${hits.length} items — point it at an item id instead` };
    const value = hits[0].select(field);
    if (value == null || value === "") return { unknown: `map entry '${mapped[0]}' -> '${sel}' has no value (item has: ${hits[0].fieldSummary().join(", ") || "nothing"})` };
    return { value, item: hits[0], field: field ?? "password", via: "map" };
  }

  // 2. exact item name, then unique item id
  const byName = items.filter((i) => i.name.trim().toLowerCase() === lc);
  if (byName.length === 1) {
    const value = byName[0].select(suffix);
    if (value == null || value === "") return { unknown: `vault item '${byName[0].name}' has no ${suffix ?? "password"} (has: ${byName[0].fieldSummary().join(", ") || "nothing"})` };
    return { value, item: byName[0], field: suffix ?? "password", via: "name" };
  }
  if (byName.length > 1) {
    return { ambiguous: byName.map(describe), reason: `${byName.length} vault items are named '${key}' — disambiguate with a map entry pointing at an item id` };
  }
  const byId = items.filter((i) => i.id.toLowerCase() === lc);
  if (byId.length === 1) {
    const value = byId[0].select(suffix);
    if (value == null || value === "") return { unknown: `vault item '${byId[0].name}' has no ${suffix ?? "password"} (has: ${byId[0].fieldSummary().join(", ") || "nothing"})` };
    return { value, item: byId[0], field: suffix ?? "password", via: "id" };
  }

  // 3. unique uri host match
  const host = nameHost(key);
  if (host) {
    const byUri = [];
    for (const it of items) {
      for (const uri of it.uriList()) if (uriMatchesHost(uri, host)) { byUri.push({ item: it, uri }); break; }
    }
    if (byUri.length === 1) {
      const value = byUri[0].item.select(suffix);
      if (value == null || value === "") return { unknown: `vault item '${byUri[0].item.name}' (uri ${byUri[0].uri}) has no ${suffix ?? "password"} (has: ${byUri[0].item.fieldSummary().join(", ") || "nothing"})` };
      return { value, item: byUri[0].item, field: suffix ?? "password", via: `uri:${byUri[0].uri}` };
    }
    if (byUri.length > 1) {
      return { ambiguous: byUri.map((h) => describe(h.item)), reason: `${byUri.length} vault items list a uri for '${host}' — disambiguate with a map entry` };
    }
  }
  return { none: true };
}

const describe = (i) => `${i.name} [${i.id}] ${i.fieldSummary().join(",")}`;

/* ---------------------------------------------------------- provider API */

/**
 * The provider object `f creds` discovers via `f providers --dump`.
 *
 * resolve() throws on availability failures (locked store, wrong master
 * password, dns) so creds reports them instead of saying "no such cred".
 */
export const credentialProvider = {
  name: "vaultwarden",
  mirrorTtlSec: MIRROR_TTL_SEC,
  status: () => providerStatus(vwConfig()),
  resolve: async (name) => {
    const cfg = vwConfig();
    if (!cfg.server || !cfg.email) return null; // unconfigured: not ours
    const { items } = await openVault({ quiet: true });
    const res = findValue(name, items, cfg);
    if (res.value != null) return res.value;
    if (res.ambiguous) throw new Error(`${res.reason}: ${res.ambiguous.join(" | ")}`);
    if (res.unknown) throw new Error(res.unknown);
    return null; // genuinely unknown to the vault
  },
  // No `has()`: knowing whether a vault answers for `github.com` requires the
  // item list (whose uris supply host names) or the password grant (2FA). A
  // pre-filter that could only consult the map would veto resolve() for every
  // name outside it — a confidently wrong "not mine". Cheaper instead to let
  // resolve() answer, with the creds uck's mirror + negative cache absorbing
  // the repeat cost.
  list: async () => {
    const cfg = vwConfig();
    if (!cfg.server || !cfg.email) return [];
    const { items } = await openVault({ quiet: true });
    return items.flatMap((i) => namesForItem(i, cfg));
  },
};

function providerStatus(cfg) {
  if (!cfg.server) return { ready: false, note: "no server configured", hint: "f vaultwarden config --server https://vault.example.com --email you@example.com" };
  if (!cfg.email) return { ready: false, note: `no email configured for ${cfg.server}`, hint: "f vaultwarden config --email you@example.com" };
  // Report only what is verifiable without touching the creds store. Checking the
  // store means spawning `f`, which rediscovers providers, which calls this back.
  // `ready` here means "configured", and the note says exactly that, so a reader
  // is never told to `f creds unlock` a store nobody looked at.
  if (inDiscovery()) return { ready: true, note: `${cfg.server} as ${cfg.email} (configured; store/credentials not checked)` };
  const st = credsStatus();
  if (!st.unlocked) return { ready: false, note: "creds locked", hint: "f creds unlock" };
  let master = null, clientId = null;
  try { master = credsGet(cfg.masterPasswordCred); clientId = credsGet(C_CLIENT_ID); } catch { return { ready: false, note: "creds locked", hint: "f creds unlock" }; }
  if (!master) return { ready: false, note: `no master password (${cfg.masterPasswordCred})`, hint: "f vaultwarden config --master-password" };
  if (!clientId) return { ready: false, note: `no API key (${C_CLIENT_ID})`, hint: "f creds set " + C_CLIENT_ID + " 'user.<uuid>' && f creds set " + C_CLIENT_SECRET + " '<secret>'" };
  const cached = !!safeHasCache();
  return { ready: true, note: `${cfg.server} as ${cfg.email}${cached ? " (keys cached)" : ""}` };
}

function safeHasCache() {
  try {
    const blob = credsGet(C_KEY_CACHE);
    if (!blob) return false;
    return Date.now() < JSON.parse(blob).exp;
  } catch {
    return false;
  }
}

/* ------------------------------------------------------------------ cli */

const USAGE =
  "usage: f vaultwarden <cmd>\n" +
  "  config [--server <url>] [--email <addr>] [--master-password] [--print]\n" +
  "                                    set non-secret config; prompts for the\n" +
  "                                    master password without echoing it\n" +
  "  apikey <client-id> <client-secret> store the vault API key (skips 2FA)\n" +
  "  status                            config + readiness + what it can answer\n" +
  "  test                              login, decrypt, report (changes nothing)\n" +
  "  list [--search <s>]               items + the cred names each can answer\n" +
  "  get <name> [--secrets]            resolve one cred (item name, host, or map key)\n" +
  "  map <cred-name> '<Item::field>'   pin a cred name to an item/field\n" +
  "  unmap <cred-name>                 remove a map entry\n" +
  "  set-totp <name> <secret>          WRITE: store a TOTP secret on an item\n" +
  "  cache [--clear]                   vault key cache (skips PBKDF2 per read)\n" +
  "  forget                            clear the key cache and cached tokens\n" +  "  sso status                        does the server have OIDC SSO enabled\n" +
  "                                    (unauthenticated probe)\n" +
  "  sso login [--port <8065-8070>]    sign in through the identity provider in a\n" +
  "      [--timeout <sec>] [--force]   browser, then exchange the PKCE code.\n" +
  "                                    --force skips the 'is SSO enabled' probe\n" +
  "  sso login --manual                same, but binds no port: open the URL on any\n" +
  "                                    device, then paste the redirect URL (or just\n" +
  "                                    the code) back here. Use over ssh, in a\n" +
  "                                    container, or wherever the browser's localhost\n" +
  "                                    is not this machine.\n" +
  "\n" +

  "\n" +
  "name forms: 'github.com'  'Item Name'  'Item Name::username'  '<cred>::totp'\n" +
  "fields:     password (default) | username | totp | note | uri | field:<name>\n" +
  "\n" +
  "as a credential provider: `f creds get <name>` falls through to this uck on a\n" +
  "local miss and mirrors the answer as mirror:<name> for " + MIRROR_TTL_SEC / 60 + "m.\n" +
  "A master password is unavoidable — an API key authenticates but cannot decrypt.\n";

export function register(ctx) {
  return {
    name: "vaultwarden",
    desc: "read secrets from a Vaultwarden vault; credential provider for f creds",
    skills: [{ name: "f-vaultwarden", path: path.join(here, "SKILL.md") }],
    credentialProvider,
    run: (_argv, args) => main(args._ ?? []),
  };
}

/* Flags that take a value. Kept explicit so parsing is unambiguous. */
const VALUE_FLAGS = new Set([
  "--server", "--email", "--search", "--ttl", "--iterations", "--field", "--map",
]);

async function main(argv) {
  const flags = [];
  const pos = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      // Consume a value attached to a known value-taking flag, so a value that
      // happens to start with `--` (an odd password, a negative number) is still
      // read as the value, and a bare `--verbose` is still a boolean flag.
      if (VALUE_FLAGS.has(a) && i + 1 < argv.length) {
        flags.push(`${a}=${argv[++i]}`);
      } else {
        flags.push(a);
      }
    } else {
      pos.push(a);
    }
  }
  const has = (f) => flags.some((x) => x === `--${f}` || x === `--${f}=1` || x.startsWith(`--${f}=`));
  const flagVal = (f) => {
    const hit = flags.find((x) => x === `--${f}` || x.startsWith(`--${f}=`));
    if (!hit) return null;
    // A recognised flag always carries its own value, so nothing here can reach
    // past it and swallow a following positional (which would silently shift the
    // command's own arguments).
    return hit.includes("=") ? hit.slice(hit.indexOf("=") + 1) : usage(`--${f} needs a value`);
  };
  const [cmd, ...rest] = pos;

  // The probe protocol runs this file directly (`node index.js status|resolve|…`)
  // from inside provider discovery. Mark the process so any `f` we spawn declines
  // to rediscover providers — otherwise discovery calls status() which spawns f
  // which discovers providers which calls status(), unbounded.
  // `list` deliberately does NOT self-suppress providers: a provider reading its own mirror
  // back through `f creds` must not be forced to re-derive the whole vault, and the caller
  // above it has already suppressed recursion at the source (creds/providers.js sets
  // F_CREDS_NO_PROVIDER=1 for the provider's status/has/resolve children). Self-suppressing
  // on `list` too meant a direct `f vaultwarden list` re-ran prelogin + sync + PBKDF2 on
  // every single credential lookup -- one full vault decrypt per secret.
  if (cmd === "status" || cmd === "resolve" || cmd === "has") enterDiscoveryProbe();

  switch (cmd) {
    case "config": {
      const patch = {};
      const server = flagVal("server") ?? (has("server") ? usage("config --server needs a value") : null);
      const email = flagVal("email") ?? (has("email") ? usage("config --email needs a value") : null);
      if (server) patch.server = server.replace(/\/+$/, "");
      if (email) patch.email = email;
      if (Object.keys(patch).length) {
        saveVwConfig(patch);
        for (const [k, v] of Object.entries(patch)) process.stdout.write(`config\t${k}\t${v}\n`);
      }
      if (has("master-password")) {
        const pw = await promptSecret("f: vault master password (not echoed, not stored elsewhere): ");
        if (!pw) return usage("empty master password — nothing stored");
        await credsSet(vwConfig().masterPasswordCred || C_MASTER, pw);
        dropKeyCache(); // any cached keys came from the old password
        process.stdout.write("stored\tvault master password\n");
      }
      if (has("print") || (!Object.keys(patch).length && !has("master-password"))) {
        const cfg = vwConfig();
        process.stdout.write(`server\t${cfg.server ?? "(unset)"}\n`);
        process.stdout.write(`email\t${cfg.email ?? "(unset)"}\n`);
        process.stdout.write(`map\t${Object.keys(cfg.map ?? {}).length} entr(ies)\n`);
        for (const [k, v] of Object.entries(cfg.map ?? {})) process.stdout.write(`  ${k} -> ${v}\n`);
      }
      break;
    }
    case "apikey": {
      const [id, secret] = rest;
      if (!id || !secret) return usage("apikey needs <client-id> <client-secret>");
      if (!id.startsWith("user.") && !id.startsWith("organization.")) {
        process.stderr.write(`f: note: client_id usually looks like 'user.<uuid>' — got '${id}'\n`);
      }
      await credsSet(C_CLIENT_ID, id);
      await credsSet(C_CLIENT_SECRET, secret);
      dropKeyCache();
      process.stdout.write("stored\tvaultwarden api key\n");
      break;
    }
    case "status": {
      const cfg = vwConfig();
      const st = await providerStatus(cfg);
      process.stdout.write(`provider\tvaultwarden\t${st.ready ? "ready" : "not ready"}\n`);
      if (st.note) process.stdout.write(`note\t${st.note}\n`);
      if (st.hint) process.stdout.write(`hint\t${st.hint}\n`);
      process.stdout.write(`server\t${cfg.server ?? "(unset)"}\n`);
      process.stdout.write(`email\t${cfg.email ?? "(unset)"}\n`);
      process.stdout.write(`mirror ttl\t${MIRROR_TTL_SEC}s\n`);
      process.stdout.write(`key cache\t${safeHasCache() ? `on (<=${KEY_CACHE_TTL_SEC / 3600}h)` : "off"}\n`);
      if (st.ready) {
        try {
          const { items } = await openVault({ quiet: true });
          const names = new Set(items.flatMap((i) => namesForItem(i, cfg)));
          process.stdout.write(`items\t${items.length}\n`);
          process.stdout.write(`names\t${names.size}\n`);
          for (const n of [...names].sort().slice(0, 40)) process.stdout.write(`  ${n}\n`);
          if (names.size > 40) process.stdout.write(`  … +${names.size - 40} more (f vaultwarden list)\n`);
        } catch (e) {
          process.stdout.write(`vault\tsession failed: ${e.message}\n`);
        }
      }
      break;
    }
    case "test": {
      const { items, kdf, fromCache } = await openVault({ quiet: false, allowInsecureHttp: has("allow-insecure-http") });
      const cfg = vwConfig();
      process.stdout.write(`ok\tlogged in and decrypted ${items.length} item(s)${fromCache ? " (cached keys)" : ` (kdf ${kdf?.kdfIterations ?? "?"} iters)`}\n`);
      const login = items.filter((i) => i.type === CIPHER_TYPE.LOGIN);
      process.stdout.write(`logins\t${login.length}\n`);
      const withTotp = login.filter((i) => i.login?.totp);
      process.stdout.write(`totp fields\t${withTotp.length}${withTotp.length ? ` (e.g. ${withTotp.slice(0, 5).map((i) => JSON.stringify(i.name)).join(", ")})` : ""}\n`);
      const dupes = new Map();
      for (const i of items) dupes.set(i.name.trim().toLowerCase(), (dupes.get(i.name.trim().toLowerCase()) ?? 0) + 1);
      const dup = [...dupes.entries()].filter(([, n]) => n > 1);
      if (dup.length) {
        process.stdout.write(`duplicate item names\t${dup.length} (these need a map entry)\n`);
        for (const [n, c] of dup.slice(0, 10)) process.stdout.write(`  ${JSON.stringify(n)}\t${c}\n`);
        if (dup.length > 10) process.stdout.write(`  … +${dup.length - 10} more\n`);
      } else {
        process.stdout.write("duplicate item names\t0\n");
      }
      const hosts = new Map();
      for (const i of login) for (const u of i.uriList()) { const h = uriHost(u); if (h) hosts.set(h, (hosts.get(h) ?? 0) + 1); }
      const dupHosts = [...hosts.entries()].filter(([, n]) => n > 1);
      process.stdout.write(`ambiguous hosts\t${dupHosts.length}${dupHosts.length ? `: ${dupHosts.slice(0, 8).map(([h, n]) => `${h}(${n})`).join(" ")}` : ""}\n`);
      process.stdout.write(`map entries\t${Object.keys(cfg.map ?? {}).length}\n`);
      break;
    }
    case "list": {
      const cfg = vwConfig();
      const { items } = await openVault({ allowInsecureHttp: has("allow-insecure-http") });
      const search = (flagVal("search") ?? "").toLowerCase();
      for (const i of items) {
        const names = namesForItem(i, cfg);
        const hay = `${i.name} ${names.join(" ")}`.toLowerCase();
        if (search && !hay.includes(search)) continue;
        process.stdout.write(`${i.name}\ttype=${i.type}\tfields=${i.fieldSummary().join(",") || "-"}\tnames=${names.join(",")}\n`);
      }
      break;
    }
    case "get": {
      const name = rest[0];
      if (!name) return usage("get requires <name>");
      const cfg = vwConfig();
      const { items } = await openVault({ allowInsecureHttp: has("allow-insecure-http") });
      const res = findValue(name, items, cfg);
      if (res.value != null) {
        if (has("secrets")) process.stdout.write(res.value + "\n");
        else process.stdout.write(`[redacted — pass --secrets to reveal] via ${res.via} (${res.item.name}::${res.field})\n`);
        break;
      }
      if (res.ambiguous) {
        process.stderr.write(`f: '${name}' is ambiguous — ${res.reason}\n`);
        for (const d of res.ambiguous) process.stderr.write(`  ${d}\n`);
        process.stderr.write(`fix: f vaultwarden map ${name} '<exact item name>::password'\n`);
        process.exit(1);
      }
      if (res.unknown) { process.stderr.write(`f: ${res.unknown}\n`); process.exit(1); }
      process.stderr.write(`f: no vault item answers '${name}'\n  f vaultwarden list --search <term>  |  f vaultwarden map ${name} '<item>::<field>'\n`);
      process.exit(1);
    }
    case "map": {
      const [credName, selector] = rest;
      if (!credName || !selector) return usage("map needs <cred-name> '<Item::field>'");
      const cfg = vwConfig();
      const map = { ...(cfg.map ?? {}) };
      map[credName] = selector;
      saveVwConfig({ map });
      // Drop any mirror under the old value so the new mapping takes effect now.
      try { execFileSync("f", ["creds", "forget", credName], { stdio: "ignore", timeout: 15000, env: { ...process.env, F_CREDS_NO_PROVIDER: "1" } }); } catch {}
      process.stdout.write(`mapped\t${credName}\t->\t${selector}\n`);
      break;
    }
    case "unmap": {
      const [credName] = rest;
      if (!credName) return usage("unmap needs <cred-name>");
      const map = { ...(vwConfig().map ?? {}) };
      if (!(credName in map)) { process.stdout.write(`not mapped\t${credName}\n`); break; }
      delete map[credName];
      saveVwConfig({ map });
      process.stdout.write(`unmapped\t${credName}\n`);
      break;
    }
    case "set-totp": {
      const [name, secret] = rest;
      if (!name || !secret) return usage("set-totp needs <name> <secret>");
      process.stderr.write(`f: this WRITES to the vault item and replaces any existing totp field.\n`);
      if (!has("yes")) {
        const ok = await promptSecret("f: type 'yes' then Enter to continue: ");
        if (ok.trim() !== "yes") { process.stderr.write("f: cancelled\n"); break; }
      }
      const cfg = vwConfig();
      const { api, keys, items } = await openVault({ allowInsecureHttp: has("allow-insecure-http") });
      const res = findValue(name, items, cfg, { suffix: "totp" });
      const item = res.item ?? (() => {
        const lc = name.toLowerCase();
        const hits = items.filter((i) => i.name.trim().toLowerCase() === lc);
        if (hits.length !== 1) return null;
        return hits[0];
      })();
      if (!item) { process.stderr.write(`f: cannot resolve '${name}' to exactly one item\n`); process.exit(1); }
      const raw = item.raw;
      const login = { ...(raw.login ?? {}) };
      if (login.totp) {
        let current = null;
        try { current = decryptString(login.totp, keys); } catch {}
        if (current && !has("force")) {
          process.stderr.write(`f: item '${item.name}' already has a totp field — pass --force to replace it\n`);
          process.exit(1);
        }
      }
      login.totp = encryptString(secret, keys);
      await api.putCipher(item.id, toWire(raw, { login }));
      dropKeyCache(); // server bumped revisionDates; force a clean resync
      process.stdout.write(`set-totp\t${item.name}\n`);
      process.stdout.write("note\tmirrors of this item may still hold the old value: f creds forget <name>\n");
      break;
    }
    case "cache": {
      if (has("clear")) { dropKeyCache(); process.stdout.write("cleared\tkey cache\n"); break; }
      const cached = safeHasCache();
      process.stdout.write(`key cache\t${cached ? "on" : "off"}\n`);
      process.stdout.write(`purpose\tskip PBKDF2 (${KEY_CACHE_TTL_SEC / 3600}h window)\n`);
      break;
    }
    case "forget": {
      dropKeyCache();
      credsRm(C_TOKEN);
      credsRm(C_REFRESH);
      process.stdout.write("cleared\tkey cache + cached tokens (master password and api key kept)\n");
      break;
    }
    case "sso": {
      const sub = rest[0];
      if (sub === "status") {
        const cfg = vwConfig();
        if (!cfg.server) return usage("sso needs a server first: f vaultwarden config --server https://vault.example.com");
        const api = new VaultwardenApi({ server: cfg.server, timeoutMs: cfg.timeoutMs, allowInsecureHttp: !!cfg.allowInsecureHttp });
        const st = await api.ssoEnabled();
        if (!st.reachable) {
          process.stdout.write("sso\tunknown (could not reach the server)\n");
          process.stdout.write(`error\t${st.error}\n`);
          break;
        }
        process.stdout.write(`sso\t${st.enabled ? "enabled" : "not enabled on this server"}\n`);
        if (st.orgIdentifier) process.stdout.write(`org\t${st.orgIdentifier}\n`);
        if (!st.enabled) {
          process.stdout.write("note\tthe server refused /identity/sso/prevalidate, which is what a server with SSO_ENABLED=false does\n");
          process.stdout.write("hint\tuse it anyway with: f vaultwarden sso login --force\n");
        }
        break;
      }
      if (sub === "login" || sub === undefined) {
        const cfg = vwConfig();
        if (!cfg.server) return usage("sso needs a server first: f vaultwarden config --server https://vault.example.com");
        const api = new VaultwardenApi({ server: cfg.server, email: cfg.email, timeoutMs: cfg.timeoutMs, allowInsecureHttp: !!cfg.allowInsecureHttp });

        // Confirm SSO unless told to skip the check. prevalidate is unauthenticated
        // and cheap, and failing here beats sending a human to a browser for nothing.
        //
        // `usage()` is the WRONG exit path here and was the original one: it writes the whole
        // command summary and exits 1, which buried the actual reason under ~30 lines of help
        // text when the command had been invoked correctly. It is a usage error only when the
        // operator got the invocation wrong; a server that has SSO switched off is a state
        // problem. Both this and the missing-server case above must print a reason and stop.
        if (!has("force")) {
          const st = await api.ssoEnabled();
          if (!st.enabled) {
            process.stderr.write(
              `this server does not report SSO as enabled (${cfg.server})\n` +
              `  re-run with --force if you know it is configured, or check SSO_ENABLED on the server\n`,
            );
            process.exit(1);
          }
        }

        // Two ways to get the code back, and which one applies depends on where the
        // browser is relative to this process -- see ssoManual below for the case that
        // decides it. Default keeps the listener; --manual never binds a port.
        const manual = has("manual");
        const port = Number(has("port") ? flagVal("port") : 8065);
        const { authorizeUrl, codeVerifier } = api.ssoAuthorizeUrl({ redirectPort: port });

        process.stderr.write("\nOpen this URL to sign in with your identity provider:\n\n");
        process.stderr.write(`  ${authorizeUrl}\n\n`);

        let code;
        if (manual) {
          code = await ssoManualPrompt(authorizeUrl, port);
        } else {
          process.stderr.write(`Waiting for the redirect on http://localhost:${port} …\n`);
          process.stderr.write("  (on a machine with no browser, or one whose localhost is not this machine, re-run with --manual)\n");
          // Only useful when a browser can reach this host. Stated, not assumed.
          tryOpenBrowser(authorizeUrl);
          code = await captureSsoCode({
            expectedState: null,
            timeoutMs: has("timeout") ? Number(flagVal("timeout")) * 1000 : 180_000,
            log: (bound) => process.stderr.write(`  listening on ${bound}\n`),
          });
        }

        process._vwTrace?.("got token");
        const tok = await api.loginSso({ code, codeVerifier });
        process._vwTrace?.("loginSso ok");
        const hasMaster = ssoRequiresMasterPassword(tok);
        process.stdout.write(`authenticated\tyes${hasMaster ? " (master password still needed to decrypt)" : " (no master password on this account)"}\n`);
        process.stdout.write(`refresh token\t${api.refreshToken ? "yes — sessions renew without a browser for ~30 days" : "no"}\n`);
        if (tok?.KdfIterations) process.stdout.write(`kdf\tpbkdf2-sha256 ${tok.KdfIterations} iterations\n`);

        // Persist the session, but never the master password: that stays in `f creds`
        // where it belongs, entered through its own prompt.
        // Both calls MUST be awaited. credsSet returns a Promise (it talks to the daemon over
        // a socket), and an unawaited one turns a failure into an unhandled rejection: nothing
        // is printed, the process exits 0, and -- the part that actually matters -- the access
        // and refresh tokens are never written, so the next run reports "not logged in" after
        // a login that looked completely successful. Only the SSO path had this; every other
        // credsSet call site in this file awaits it.
        await persistSsoTokens(api);
        if (hasMaster) {
          // Read the master password OUTSIDE the try below. credsGet shells out to `f creds`,
          // and on some failures it rethrows that command's own stderr verbatim -- which already
          // begins with "f: ", which is why a run printed "f: f: Unsupported state or unable to
          // authenticate data". With the call inside the same try, a credential-read problem was
          // indistinguishable from a vault-key problem, and the operator was sent to check a
          // password that was never the thing that failed.
          let masterForKeys = null;
          try {
            masterForKeys = credsGet(cfg.masterPasswordCred);
          } catch (e) {
            const m = String(e?.message ?? e).replace(/^f:\s*/gm, "").trim();
            process.stdout.write(
              "note\tlogged in, but the stored master password could not be read, so the key\n" +
              "\tcache was not primed.\n" +
              `\tf creds says: ${m.split("\n")[0].slice(0, 140)}\n` +
              "next\tf creds unlock          (if the store is locked)\n" +
              "        f vaultwarden config --master-password\n",
            );
          }
          try {
            const keys = await VaultwardenApi.keysFromSsoToken(tok, { email: cfg.email, masterPassword: masterForKeys });
            await writeKeyCache(cfg, keys, api);
            process.stdout.write("key cache\tprimed — later reads skip PBKDF2\n");
          } catch (e) {
            const m = String(e.message ?? e);
            if (/no master password stored|still uses a master password/.test(m)) {
              process.stdout.write(`next\t${m.split("\n")[0]}\n`);
              process.stdout.write("run\tf vaultwarden config --master-password\n");
            } else if (/no master password: it is SSO-only/.test(m)) {
              process.stdout.write(`blocked\t${m.split("\n")[0]}\n`);
            } else if (/unable to authenticate|MAC verification|unsupported state|bad decrypt|unexpected symmetric key/i.test(m)) {
              // A MAC failure HERE means one specific thing, and it must not be reported as
              // "your password is wrong": the login SUCCEEDED, and the session/refresh token it
              // minted is valid and already saved. Only the key cache could not be primed.
              // "Unsupported state or unable to authenticate data" is OpenSSL's wording, arriving
              // through createDecipheriv with nothing around it to say which key or which stage,
              // which is how a run looks where everything works except this one optional step.
              //
              // Drop the cache deliberately. tryCachedSession only reads what is stored and never
              // validates it, so a cache primed with the wrong key would make EVERY later read
              // fail the same way forever -- the failure would outlive its own cause. Clearing it
              // costs one PBKDF2 on the next real read and lets the normal path recompute.
              try { credsRm(C_KEY_CACHE); } catch { /* nothing stored is fine */ }
              process.stdout.write(
                "note\tlogged in, but the key cache was not primed: the vault key did not verify\n" +
                `\t${m.split("\n")[0].slice(0, 110)}\n` +
                "next\tcheck the stored master password, then try a read directly:\n" +
                "        f vaultwarden get <something> --secrets\n" +
                "        f vaultwarden config --master-password    (if that also fails the MAC)\n" +
                "note\tthe session itself is valid; a read derives the key from sync.profile.key\n" +
                "        instead of the value this response carried, so it may still succeed.\n",
              );
            } else {
              throw e;
            }
          }
        } else {
          process.stdout.write("note\tthis account has no master password; opening it needs an enrolled device key pair, which this uck does not do\n");
        }
        break;
      }
      usage(`unknown sso subcommand: ${sub}`);
      break;
    }
    default:
      usage();
  }
}

/**
 * Build a PUT /api/ciphers body from a decrypted item plus field overrides.
 * Bitwarden requires the whole object; unset/unsupported sub-objects are
 * omitted rather than guessed so a partial write cannot blank a field the uck
 * does not model.
 */
function toWire(raw, patch) {
  const body = {
    type: raw.type,
    organizationId: raw.organizationId ?? null,
    folderId: raw.folderId ?? null,
    favorite: !!raw.favorite,
    name: raw.name,
  };
  if (raw.notes !== undefined) body.notes = raw.notes;
  if (raw.fields !== undefined) body.fields = raw.fields;
  if (raw.login !== undefined) body.login = {uris: raw.login?.uris ?? [], ...patch.login};
  if (raw.passwordHistory !== undefined) body.login.passwordHistory = raw.passwordHistory;
  if (raw.identity !== undefined) body.identity = raw.identity;
  if (raw.card !== undefined) body.card = raw.card;
  return body;
}

function usage(msg) {
  if (msg) process.stderr.write(`f: ${msg}\n`);
  process.stderr.write(USAGE);
  process.exit(1);
}

/* --------------------------------------------------- probe protocol */

/**
 * `f creds` probes providers by executing this file:
 *   node index.js resolve <name>   -> value on stdout, exit 1 with reason on stderr
 *   node index.js has <name>       -> 'yes'|'no'
 *   node index.js status           -> {ready,note,hint} JSON
 * Keep stdout free of anything but the answer.
 */
async function probe(argv) {
  const [sub, arg] = argv;
  if (sub === "--dump") {
    process.stdout.write(JSON.stringify([{ name: credentialProvider.name, entry: path.join(here, "index.js"), hasExternalApi: true, mirrorTtlSec: MIRROR_TTL_SEC }]));
    return;
  }
  if (sub === "status") {
    process.stdout.write(JSON.stringify(await providerStatus(vwConfig())));
    return;
  }
  if (sub === "list") {
    const cfg = vwConfig();
    if (!cfg.server || !cfg.email) { process.stdout.write("[]"); return; }
    const { items } = await openVault({ quiet: true });
    process.stdout.write(JSON.stringify([...new Set(items.flatMap((i) => namesForItem(i, cfg)))]));
    return;
  }
  if (!sub || !arg) { process.stderr.write("probe needs resolve|has|status|list <name>"); process.exitCode = 2; return; }
  const cfg = vwConfig();
  if (!cfg.server || !cfg.email) {
    // Unconfigured is "not mine", not an error.
    if (sub === "resolve") { process.exitCode = 3; return; }
    process.stdout.write(sub === "has" ? "no" : "");
    return;
  }
  const { items } = await openVault({ quiet: true });
  const res = findValue(arg, items, cfg);
  if (sub === "has") { process.stdout.write(res.value != null ? "yes" : "no"); return; }
  if (res.value != null) { process.stdout.write(res.value); return; }
  if (res.ambiguous) { process.stderr.write(`${res.reason}: ${res.ambiguous.join(" | ")}`); process.exitCode = 1; return; }
  if (res.unknown) { process.stderr.write(res.unknown); process.exitCode = 1; return; }
  process.exitCode = 3; // genuinely absent from the vault
}

// Dispatch: `f vaultwarden …` goes through run(); direct execution is a probe.
uckMain(import.meta.url, async (argv) => {
  const probeSubs = new Set(["resolve", "has", "status", "list", "--dump"]);
  if (probeSubs.has(argv[0])) return probe(argv);
  return main(argv);
});

export default { register, credentialProvider };

/**
 * The account's own KDF parameters, as reported by prelogin.
 *
 * The KDF is per-account: the client cannot choose it, and using the wrong one derives a
 * wrong key whose MAC failure reads as "wrong master password" -- which is what discarding
 * prelogin's kdf type did to a real user. It must be validated, never defaulted.
 */
function kdfConfigFor(pre, email) {
  const kdfType = Number(pre?.kdf ?? 0);
  const iterations = Number(pre?.kdfIterations ?? 0);
  if (!Number.isInteger(iterations) || iterations <= 0) throw new Error(`prelogin gave no usable kdfIterations (${pre?.kdfIterations}) for ${email}`);
  // Name the property explicitly. This was `{ kdfType, kdfIterations }` -- shorthand for a
  // variable declared as `iterations` two lines up -- so the PBKDF2 path, the ONLY path this
  // account can take, threw ReferenceError and no vault could ever be opened. node --check
  // passes it (it is valid syntax) and no test caught it, because every mock prelogin in the
  // suite returned a kdf type that skipped this line.
  if (kdfType === 0) return { kdfType, kdfIterations: iterations };
  if (kdfType === 1) {
    const memory = Number(pre?.kdfMemory ?? 0);
    const parallelism = Number(pre?.kdfParallelism ?? 0);
    if (!Number.isInteger(memory) || memory <= 0 || !Number.isInteger(parallelism) || parallelism <= 0) {
      throw new Error(`prelogin reported Argon2id without usable memory/parallelism (memory=${pre?.kdfMemory}, parallelism=${pre?.kdfParallelism})`);
    }
    return { kdfType, kdfIterations: iterations, kdfMemory: memory, kdfParallelism: parallelism };
  }
  throw new Error(
    `this account uses an unsupported KDF type ${kdfType}; only PBKDF2-SHA256 (0) and Argon2id (1) are implemented`,
  );
}

/* ------------------------------------------------------- SSO plumbing */

export function extractSsoServerError(input) {
  if (!/binding mismatch/i.test(input)) return null;
  // `SSO session binding mismatch` is produced by oidcsignin_redirect when the
  // VW_SSO_BINDING cookie is absent or does not hash to the stored value. Two distinct
  // causes reach it, and they need different fixes, so both are offered.
  return [
    "the vault rejected the callback: SSO session binding mismatch",
    "  Vaultwarden sets VW_SSO_BINDING on the /identity/connect/authorize response and",
    "  requires the same token back at /identity/connect/oidc-signin. It only matches if",
    "  the BROWSER that opened the authorize URL is the one that completes it — a cookie",
    "  follows the browser, not the program. This CLI used to fetch that hop itself, which",
    "  put the cookie in the wrong process; that is fixed, so if you still see this, the",
    "  most likely cause is that the URL was opened somewhere other than where the redirect",
    "  lands (a different browser, a remote machine, or a tab where it was pasted rather",
    "  than followed — Sec-Fetch-Site: none in DevTools proves the paste case). From a",
    "  remote terminal, forward the port and open the URL on your OWN machine so the cookie",
    "  and the redirect share one browser: ssh -L 8065:localhost:8065 <host>, then run",
    "  without --manual. Decode the state in the error if you need to know whose flow it",
    "  is: 22 base64url chars is this CLI; the web vault's is longer and ends in",
    "  '_identifier=' — they are separate sessions with separate binding cookies.",
    "  Ground truth is the server log, not the browser: ask for the lines around the",
    "  failing oidc-signin, and compare the request SEQUENCE of a WORKING web-vault login",
    "  (it shows prevalidate then '=> 307') against the failing one. That diff settles what",
    "  no browser header can.",
  ].join("\n");
}

export function extractSsoCode(input) {
  let t = input.trim().replace(/^["'<`]+|["'`>]+$/g, "");
  // A full URL: take the query parameter, which is unambiguous when present.
  if (/[?&]code=/i.test(t)) {
    for (const part of t.split(/[?&]/)) {
      const [k, v] = [part.slice(0, part.indexOf("=")), part.slice(part.indexOf("=") + 1)];
      if (/^code$/i.test(k) && v) return decodeURIComponent(v);
    }
  }
  // Bare code, possibly with stray whitespace or a trailing comma from a selection.
  const bare = t.replace(/[,;\s]+$/, "");
  return /^[A-Za-z0-9._~+/=-]{8,}$/.test(bare) ? bare : null;
}

function tryOpenBrowser(url) {
  const cands = process.platform === "darwin"
    ? [["open", [url]]]
    : process.platform === "win32"
      ? [["cmd", ["/c", "start", "", url]]]
      : [["xdg-open", [url]]];
  for (const [cmd, args] of cands) {
    try {
      // stdio fully detached: a browser helper that writes to stderr or blocks on
      // stdin must not be able to wedge or delay this command.
      const child = spawnDetached(cmd, args);
      if (child) return true;
    } catch { /* fall through to the message below */ }
  }
  process.stderr.write("  (no browser opened — copy the URL above into one that can reach your identity provider)\n");
  return false;
}

function spawnDetached(cmd, args) {
  const c = spawn(cmd, args, { stdio: "ignore", detached: true });
  // A missing xdg-open surfaces here, not as a throw: spawn() reports ENOENT
  // asynchronously, so the return value alone cannot tell success from failure.
  let ok = true;
  c.on("error", () => { ok = false; });
  c.unref();
  return ok ? c : null;
}

async function persistSsoTokens(api) {
  // Awaited in sequence, not Promise.all: these write one logical session, and a partial
  // write (token saved, expiry lost) leaves a session that looks valid and then refuses to
  // refresh. Failing loudly here is also the point -- see the note at the call site.
  if (api.accessToken) await credsSet(C_TOKEN, api.accessToken);
  if (api.refreshToken) await credsSet(C_REFRESH, api.refreshToken);
  if (api.accessExpiresAt) await credsSet(C_EXPIRES, String(api.accessExpiresAt));
}

async function ssoManualPrompt(authorizeUrl, port) {
  const { createInterface } = await import("node:readline");
  process.stderr.write(
    "  1. open it in a browser ON THIS MACHINE\n"
    + "  2. sign in there\n"
    + "  3. the browser lands on a dead localhost URL — that is expected. Copy the\n"
    + `     whole address bar (it starts with http://localhost:${port}/?code=…) and\n`
    + "     paste it below\n"
    + "\n"
    + "  The flow is bound to a cookie set in the browser that opened the URL\n"
    + "  (VW_SSO_BINDING), so open it where the redirect will be received. From a remote\n"
    + "  terminal, forward the port and open it on your own machine — cookie and redirect\n"
    + "  then share a browser, and the default (non-manual) flow works:\n"
    + `     ssh -L ${port}:localhost:${port} <host>\n`
    + "  Keep the browser and this terminal on the SAME machine: the authorize URL and\n"
    + "  the redirect must share one cookie jar. If it fails, the server log\n"
    + "  (docker logs <vault> around /identity/connect/oidc-signin) is the ground truth —\n"
    + "  do not guess from the browser.\n"
    + "\n"
    + "Paste the redirect URL (or just the code), then press Enter:\n\n> ",
  );

  const rl = createInterface({ input: process.stdin, output: process.stderr, terminal: true });
  let line;
  try {
    line = await new Promise((resolve, reject) => {
      rl.question("", resolve);
      rl.once("SIGINT", () => reject(new Error("cancelled — nothing was exchanged")));
      // readline only calls the question callback on a line. On EOF it never does, so this
      // promise used to stay pending forever: with stdin closed or piped (`</dev/null`, a
      // script, an editor task) the command hung, and the process then exited 0 with empty
      // stdout and no message — indistinguishable from success. `close` is readline's real
      // end-of-input signal, and resolving null lets the branch below explain the situation
      // instead of silently vanishing.
      rl.once("close", () => resolve(null));
    });
  } finally {
    rl.close();
  }

  const raw = String(line ?? "").trim();
  if (!raw) {
    // An empty read is not the same event as a refusal to type: when stdin is not a terminal
    // (a pipe, `</dev/null`, CI, an editor task) readline yields EOF immediately, and this
    // command used to exit 0 with an empty stdout after printing an authorize URL. An operator
    // driving this from a script could not tell success from "nobody was ever asked".
    if (!process.stdin.isTTY) {
      throw new Error(
        "no terminal to paste into — stdin is not a tty, so the redirect URL could not be read.\n" +
        `  run this interactively, or feed the URL in: echo 'http://localhost:${port}/?code=…' | \\\n` +
        `  ${"f vaultwarden sso login --manual"}`,
      );
    }
    throw new Error("nothing pasted — nothing was exchanged");
  }
  // The browser may have been shown the server's JSON error rather than a redirect
  // with a code. That error names the real problem, so surface it instead of the
  // generic "could not find a code".
  const serverError = extractSsoServerError(raw);
  if (serverError) throw new Error(serverError);

  const code = extractSsoCode(raw);
  if (!code) {
    throw new Error("could not find an authorization code in what you pasted\n  paste the full address-bar URL (http://localhost:…/?code=…) or the code value alone");
  }
  return code;
}
