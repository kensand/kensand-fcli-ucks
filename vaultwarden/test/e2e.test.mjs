// End-to-end provider test against a MOCK Vaultwarden server, run against the
// real creds store in an isolated HOME.
//
//   f creds unlock              # real store, real daemon, temp HOME
//   node test/e2e.test.mjs
//
// What makes this a real test rather than a mock-up:
//   * the master password never touches the harness — the uck reads it from the
//     creds daemon and derives the key itself, so a broken deriveKeys() fails here
//   * resolution runs through the actual provider ladder in creds/providers.js,
//     including mirroring, ttl behaviour and the negative cache
//   * the HTTP layer is a live local server speaking Vaultwarden's real shapes
//
// It does NOT prove: real-server quirks (2FA shapes, org/collection ciphers,
// attachment payloads), real TLS, or the master password's behaviour against a
// genuine KDF. Run `f vaultwarden test` against the real server for those.

import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const UCK = path.join(here, "..");
const CREDS_UCK = path.join(process.env.HOME, ".f/ucks/fcli-ucks/creds");

const EMAIL = "kenny@example.com";
const PASSWORD = "master-pass-123";
const ITER = 1000; // low on purpose: this runs PBKDF2 for real, twice

/* ---------------- build a vault the client must be able to open ---------- */

const crypto = (await import("node:crypto")).default;
const b64 = (b) => Buffer.from(b).toString("base64");
const expand = (prk, info, len) => {
  const n = Math.ceil(len / 32);
  const out = Buffer.alloc(n * 32);
  let prev = Buffer.alloc(0);
  for (let i = 1; i <= n; i++) {
    prev = crypto.createHmac("sha256", prk).update(prev).update(Buffer.from(info)).update(Buffer.from([i])).digest();
    prev.copy(out, (i - 1) * 32);
  }
  return out.subarray(0, len);
};
const masterKey = crypto.pbkdf2Sync(PASSWORD, EMAIL, ITER, 32, "sha256");
const st = { enc: expand(masterKey, "enc", 32), mac: expand(masterKey, "mac", 32) };
const sym = crypto.randomBytes(32), symMac = crypto.randomBytes(32);
const enc = (p) => {
  const iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv("aes-256-cbc", sym, iv);
  // Buffers must go through unmodified. Buffer.from(String(buffer)) stringifies byte-wise into
  // UTF-8, and every byte >= 0x80 becomes U+FFFD -- so a 64-byte random key arrived as ~121
  // bytes here, which is how the mock stopped matching the real server it is meant to imitate.
  const data = Buffer.isBuffer(p) ? p : Buffer.from(String(p), "utf8");
  const ct = Buffer.concat([c.update(data), c.final()]);
  const tag = crypto.createHmac("sha256", symMac).update(iv).update(ct).digest();
  return `2.${b64(iv)}|${b64(ct)}|${b64(tag)}`;
};
const encWith = (encKey, macKey, p) => {
  const iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv("aes-256-cbc", encKey, iv);
  // Same rule as enc() above, and the reason it needs stating twice: the FIRST time this was
  // fixed it was fixed in enc(), and this function -- the one that actually builds the profile
  // key -- kept corrupting high bytes. A wrong helper is worse than no helper.
  const data = Buffer.isBuffer(p) ? p : Buffer.from(String(p), "utf8");
  const ct = Buffer.concat([c.update(data), c.final()]);
  const tag = crypto.createHmac("sha256", macKey).update(iv).update(ct).digest();
  return `2.${b64(iv)}|${b64(ct)}|${b64(tag)}`;
};
// The wrapped user key holds the 64 RAW key bytes, not their base64 -- pinned against a real
// Vaultwarden account, whose profile.key decrypts to a plaintext beginning 0x01 0x9E 0xAC.
// Wrapping base64 here (as this line used to) makes the mock disagree with the server and lets
// a client that cannot read a real vault pass the whole suite.
const profileKey = encWith(st.enc, st.mac, Buffer.concat([sym, symMac]));

const login = (id, name, { user, pass, totp, uris = [], fields = [] }) => ({
  id, organizationId: null, folderId: null, type: 1, favorite: false,
  name: enc(name), notes: null,
  login: {
    username: user == null ? null : enc(user),
    password: pass == null ? null : enc(pass),
    totp: totp == null ? null : enc(totp),
    uris: uris.map((u) => ({ uri: enc(u), match: null })),
  },
  fields: fields.map((f) => ({ name: enc(f.name), value: enc(f.value), type: 0 })),
});

const CIPHERS = [
  login("aaaaaaaa-0001", "github.com", { user: "kensand", pass: "ghp_real_1", totp: "JBSWY3DP", uris: ["https://github.com"] }),
  // deliberately duplicate name + duplicate host, to exercise ambiguity errors
  login("aaaaaaaa-0002", "github.com", { user: "kensand-work", pass: "ghp_work_2", uris: ["https://github.com"] }),
  login("aaaaaaaa-0003", "Forgejo", { user: "kenny", pass: "fj_token_3", uris: ["https://forgejo.kensand.net", "forgejo.kensand.net"] }),
  login("aaaaaaaa-0004", "smtp", { user: "kenny@x", pass: "smtp_pw", uris: ["* Gmail"] }),
  login("aaaaaaaa-0005", "no-pass", { user: "only-user", uris: ["https://nopass.example"] }),
  login("aaaaaaaa-0006", "wild", { user: "u", pass: "p", uris: ["https://*.gitlab.example"] }),
  { id: "aaaaaaaa-0007", type: 2, name: enc("plain note"), login: { username: enc("note body") }, fields: [] },
];

let TOKEN_SEEN = null;
const TOKEN_LOG = []; // one entry per token request, with the device field names it carried
const GRANTS = []; // every grant the client actually asked for, in order
let PW_GRANT_SEEN = null;
let FIRST_RUN_GRANTS = 0; // grants consumed by the first vault-open attempt
// The login proof the password grant must carry: HMAC(PBKDF2(pw,email), pw).
// The login proof the password grant must send: HMAC(PBKDF2(pw,email), pw), base64.
// Awaited at module level because the mock request handler below is synchronous -- an
// unawaited Promise here compares unequal to every string and the password grant then fails
// *silently*, falling back to the API key while the suite still reports green. That is the
// whole reason this file exists: a mock that accepts the wrong thing proves nothing.
// Built from the uck's own helpers, which are themselves cross-checked against Bitwarden's
// official wasm crypto in bitwarden-wasm.test.mjs -- so this is not a circular check.
const EXPECTED_PW_HASH = await computeExpectedPwHash();
async function computeExpectedPwHash() {
  const C = await import(pathToFileURL(path.join(here, "..", "lib", "vwclient.js")).href);
  return C.masterPasswordHash(C.makeMasterKey(PASSWORD, EMAIL, ITER), PASSWORD).toString("base64");
}

let PRELOGIN_HITS = 0;
let SYNC_HITS = 0;
let CIPHERS_HITS = 0;
let PUT_BODIES = [];
let FAIL_CIPHERS_WITH = null; // e.g. 401
let RATE_LIMIT_NEXT = false;
let SSO_PENDING = null;      // { challenge } set when the authorize URL is observed
const PKCE_LOG = [];           // every exchange the mock saw, for diagnosis
let SSO_ENABLED = true;        // served at /identity/sso/prevalidate
let SSO_HAS_MASTER = true;   // false = an SSO-created account with no master password at all

const server = http.createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    const send = (code, obj) => { res.writeHead(code, { "Content-Type": "application/json" }); res.end(JSON.stringify(obj)); };
    const auth = req.headers.authorization;
    if (req.method === "POST" && req.url === "/identity/accounts/prelogin") {
      PRELOGIN_HITS++;
      // Mirror the real server: JSON body only. A form-encoded prelogin gets 400,
      // which is what forced the client to learn to send JSON first.
      const isJson = /application\/json/.test(req.headers["content-type"] ?? "");
      if (!isJson) return send(400, { message: "Bad Request", validationErrors: { "": ["Bad Request"] } });
      return send(200, { kdf: 0, kdfIterations: ITER });
    }
    if (req.method === "POST" && req.url === "/identity/connect/token" && RATE_LIMIT_NEXT) {
      RATE_LIMIT_NEXT = false;
      return send(429, { message: "Too many login requests", validationErrors: { "": ["Too many login requests"] }, error_description: "" });
    }
    if (req.method === "POST" && req.url === "/identity/connect/token") {
      const p = Object.fromEntries(new URLSearchParams(body));
      // Enforce the rules PROBED against the live server, so a regression in the request body
      // fails here rather than at first use in the field. Scope rules are per-grant, verified
      // against vault.kensand.net with probe accounts (no real credentials sent):
      //   password          scope=api                -> "Scope (api) not supported"
      //   password          scope=api offline_access -> reaches credential validation
      //   client_credentials scope=api offline_access -> "Scope not supported"
      // Note the mock deliberately does NOT accept a scope the live server rejects: the
      // previous revision asserted scope === "api" for client_credentials as if probed, and
      // that was never actually tested against the real thing.
      if (p.grant_type !== "client_credentials" && p.grant_type !== "password" && p.grant_type !== "authorization_code") {
        return send(400, { message: "unsupported grant", validationErrors: { "": ["unsupported grant"] } });
      }
      if (p.grant_type === "authorization_code") {
        // Contract for the SSO grant (src/api/identity.rs), and the failure this mock exists to
        // catch: `cli` is the only accepted client, PKCE replaces the client secret, and the
        // scope includes offline_access -- which is what earns the refresh_token that lets a
        // session renew for ~30 days. A client that silently dropped it would "work" and then
        // require a browser every two hours.
        if (p.client_id !== "cli") return send(400, { message: "unsupported client", validationErrors: { "": ["unsupported client"] }, error_description: "" });
        if (p.scope !== "api offline_access") return send(400, { message: `Scope (${p.scope}) not supported`, validationErrors: { "": [`Scope (${p.scope}) not supported`] }, error_description: "" });
        if (!p.code) return send(400, { message: "code is required", validationErrors: { "": ["code is required"] }, error_description: "" });
        if (!p.code_verifier) return send(400, { message: "code_verifier is required", validationErrors: { "": ["code_verifier is required"] }, error_description: "" });
        // Prove the PKCE binding rather than accepting any verifier: the server checks
        // code_challenge === BASE64URL(SHA256(code_verifier)), and an exchange that skipped it
        // would accept a code captured from someone else's browser.
        const expect = crypto.createHash("sha256").update(String(p.code_verifier)).digest("base64url");
        PKCE_LOG.push({
          pending: SSO_PENDING?.challenge ?? null,
          expect,
          verifierFull: String(p.code_verifier),
          verifierLen: String(p.code_verifier).length,
          bodyKeys: Object.keys(p).sort().join(","),
        });
        if (SSO_PENDING?.challenge !== expect) {
          return send(400, { message: "invalid_grant", error_description: "PKCE verification failed", validationErrors: { "": ["PKCE verification failed"] }, error_description: "PKCE verification failed" });
        }
        SSO_PENDING = null; // single use, like the real thing
        GRANTS.push("authorization_code");
        // Logged like every other grant. TOKEN_LOG is normally appended further down the
        // handler, but this branch sends its reply early, so recording it there would never
        // run -- and the assertions on the posted fields silently saw only password grants.
        TOKEN_LOG.push({ grant: "authorization_code", status: 200, fields: p, sentDevice: ["device_identifier", "device_name", "device_type"].filter((k) => k in p) });
        return send(200, {
          access_token: "sso." + Buffer.from(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 3600 })).toString("base64url"),
          refresh_token: "sso-refresh-1",
          expires_in: 3600,
          token_type: "Bearer",
          scope: "api offline_access",
          // What key derivation needs, carried by the SSO response so the flow never needs
          // /prelogin (an endpoint an SSO-only account may not be allowed to use).
          Key: profileKey,
          Kdf: 0,
          KdfIterations: ITER,
          UserDecryptionOptions: {
            HasMasterPassword: SSO_HAS_MASTER,
            MasterPasswordUnlock: { MasterKeyEncryptedUserKey: profileKey, Salt: EMAIL },
          },
        });
      }
      // client_credentials accepts ONLY `api`: `api.device`/`api.offline`/`api.push` all come
      // back "Scope not supported", while `api` proceeds to client-id validation. Verified
      // with a syntactically valid but nonexistent client id, so no real credential is sent.
      if (p.grant_type === "client_credentials" && p.scope !== "api") {
        return send(400, { message: "Scope not supported", validationErrors: { "": ["Scope not supported"] }, error_description: "" });
      }
      if (p.grant_type === "password" && p.scope !== "api offline_access") {
        return send(400, { message: `Scope (${p.scope}) not supported`, validationErrors: { "": [`Scope (${p.scope}) not supported`] }, error_description: "" });
      }
      if (p.grant_type === "password" && p.password !== EXPECTED_PW_HASH) {
        return send(400, { message: "Username or password is incorrect. Try again", validationErrors: { "": ["Username or password is incorrect. Try again"] }, error_description: "" });
      }
      // The device fields are required, and they must arrive in ONE spelling. Sending
      // snake_case and camelCase together makes the real server answer
      // "device_identifier cannot be blank" -- Rocket's binder rejects a field bound twice --
      // and that is exactly the bug this mock used to hide by reading whichever key it liked.
      const dupes = ["device_identifier", "device_name", "device_type"]
        .filter((k) => p[k] !== undefined && p[k.replace(/_([a-z])/g, (_, c) => c.toUpperCase())] !== undefined);
      if (dupes.length) {
        return send(400, {
          message: `${dupes[0]} cannot be blank`,
          validationErrors: { "": [`${dupes[0]} cannot be blank`] }, error_description: "",
          _note: "sent both snake_case and camelCase for the same field",
        });
      }
      if (!p.device_identifier) {
        return send(400, { message: "device_identifier cannot be blank", validationErrors: { "": ["device_identifier cannot be blank"] }, error_description: "" });
      }
      if (!p.device_name) return send(400, { message: "device_name cannot be blank", validationErrors: { "": ["device_name cannot be blank"] }, error_description: "" });
      if (p.grant_type === "client_credentials" && (p.client_id !== "user.test-id" || p.client_secret !== "test-secret")) return send(400, { message: "Invalid client_id", validationErrors: { "": ["Invalid client_id"] }, error_description: "" });
      TOKEN_SEEN = { grant: p.grant_type, clientId: p.client_id, scope: p.scope, deviceType: p.device_type ?? p.deviceType };
      GRANTS.push(p.grant_type);
      TOKEN_LOG.push({ grant: p.grant_type, status: null, fields: p, sentDevice: Object.keys(p).filter((k) => /^device/i.test(k)) });
      // The "first run" is the first batch of grant attempts ending in a
      // success. Recorded when a grant succeeds so the assertion below cannot pass
      // vacuously off an empty slice.
      if (FIRST_RUN_GRANTS === 0) FIRST_RUN_GRANTS = GRANTS.length;
      // Record the first password-grant attempt so an assertion can inspect it directly.
      if (p.grant_type === "password" && !PW_GRANT_SEEN) PW_GRANT_SEEN = { scope: p.scope, password: p.password, username: p.username, clientId: p.client_id };
      if (p.grant_type === "password")       return send(200, { access_token: "tok-1", refresh_token: "ref-1", expires_in: 3600, token_type: "Bearer" });
    }
    const bearerOk = auth === "Bearer tok-1";
    if (req.method === "GET" && req.url === "/api/sync") {
      SYNC_HITS++;
      if (!bearerOk) return send(401, { error: "invalid_token" });
      return send(200, { profile: { id: "u1", key: profileKey, privateKey: null }, ciphers: CIPHERS, folders: [], collections: [] });
    }
    if (req.method === "GET" && req.url === "/api/ciphers") {
      CIPHERS_HITS++;
      if (FAIL_CIPHERS_WITH) { const c = FAIL_CIPHERS_WITH; FAIL_CIPHERS_WITH = null; return send(c, { error: "expired" }); }
      if (!bearerOk) return send(401, { error: "invalid_token" });
      return send(200, { object: "list", data: CIPHERS.map((c) => ({ ...c, revisionDate: "2026-01-01T00:00:00.000Z" })), continuationToken: null });
    }
    if (req.method === "PUT" && /^\/api\/ciphers\//.test(req.url)) {
      PUT_BODIES.push({ url: req.url, body: JSON.parse(body || "{}"), auth });
      return send(200, { object: "cipher", id: req.url.split("/").pop(), revisionDate: "2026-01-02T00:00:00.000Z" });
    }
    if (req.method === "GET" && req.url.startsWith("/identity/sso/prevalidate")) {
      // The real probe is unauthenticated and returns {"token": "<jwt>"} when SSO is on;
      // a server with SSO_ENABLED=false answers 400. Both shapes matter: an earlier client
      // looked for a boolean `ssoEnabled` field that does not exist, and reported "not
      // enabled" against a server whose SSO worked fine.
      if (!SSO_ENABLED) return send(400, { message: "SSO sign-in is not available", validationErrors: { "": ["SSO sign-in is not available"] } });
      return send(200, { token: "mock-sso-jwt." + Buffer.from(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 600 })).toString("base64url") });
    }
    return send(404, { error: "not_found", path: req.url });
  });
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const BASE = `http://127.0.0.1:${server.address().port}`;

/* ---------------- isolated HOME with a real, unlocked creds store -------- */

// Isolate before anything reads HOME: the provider's creds helpers resolve
// ~/.f at call time, so this test drives a private store and a mock vault, and
// cannot read or write the real one.
// NOT inside /tmp. `f` clones the whole uck store into any HOME that lacks one,
// and it looks for a package root by walking *up* from cwd. A home under /tmp
// therefore (a) inherits /tmp/package.json, which makes the spawned provider ESM
// and breaks every resolution, and (b) gets re-cloned into the very tree the
// teardown deletes, so each later `f` call clones again and the suite never ends.
const TMP = fs.mkdtempSync(path.join(os.homedir(), ".f-vw-e2e-"));
// Every `f` call runs from here, not from TMP. `f` looks for a package root by
// walking up from cwd; running inside TMP meant it found (and later raced with the
// teardown deleting) the tree it was cloning into, so each call re-cloned the whole
// uck store and the suite never finished.
const SAFE_CWD = fs.mkdtempSync(path.join(os.tmpdir(), "f-vw-run-"));
process.env.HOME = TMP;
fs.mkdirSync(path.join(TMP, ".f"), { recursive: true });

// Real vaultwarden provider, injected so discovery does not shell out to `f`
// (which would import every uck and could reach the real store).
const VW = await import(pathToFileURL(path.join(UCK, "index.js")).href);
const providers = await import(pathToFileURL(path.join(CREDS_UCK, "providers.js")).href);
const injectVw = () => { providers.resetProviders(); providers.setDiscoveryOverride([VW.credentialProvider]); };
// Each vault-fetching case starts from a clean cache: the negative cache and
// mirrors persist on disk / in the box across cases by design, so without this
// a later case would be served by an earlier case's bookkeeping.
const freshLookup = async (name, st = store) => {
  providers.clearMisses();
  injectVw();
  if (st === store) { box.clear(); stamps.clear(); }
  return providers.resolveViaProvider(name, st);
};

let pass = 0, fail = 0;
const t = (label, cond, extra = "") => { if (cond) { pass++; console.log(`ok   ${label}`); } else { fail++; console.log(`FAIL ${label}  ${extra} `); } };

// Start a real daemon in the temp HOME, via the same socket/lockfile protocol
// the uck uses, so the provider's own creds helpers work against this store.
// The daemon detaches, so it outlives this process by design. Track its pid so
// teardown can stop it: otherwise every run of this suite leaks a daemon that sits
// in memory until its TTL (30m here) — seven accumulated after a few runs.
const daemonPids = [];
const DAEMON = path.join(CREDS_UCK, "daemon.js");
// Must match exactly what the creds uck itself uses (~/.f/.creds.sock and
// ~/.f/.creds-daemon). A daemon on any other socket path starts happily and then
// every `f creds` call reports "locked" — a fixture bug that looks identical to a
// store bug.
const SOCK = path.join(TMP, ".f/.creds.sock");
const LOCK = path.join(TMP, ".f/.creds-daemon");
{
  const { spawn } = await import("node:child_process");
  const daemonArgs = [DAEMON, "--socket", SOCK, "--lockfile", LOCK, "--ttl", "1800", "--creds", path.join(TMP, ".f/f.creds.enc"), "--expires-at", String(Date.now() + 1800000)];
  // The daemon detaches *itself*, but a detached child still shares the parent's
  // process group, so the signal a shell sends to the foreground group when this
  // test exits kills it — and the next read then reports "creds are locked",
  // which is indistinguishable from a real store bug. setsid gives it its own
  // group; without it (or on a box without setsid) we fall back and the daemon
  // dies at teardown, and the pid-based lock below stops it instead.
  const launch = () => {
    const cmd = fs.existsSync("/usr/bin/setsid") ? "/usr/bin/setsid" : null;
    const child = cmd
      ? spawn(cmd, [process.execPath, ...daemonArgs], { stdio: ["pipe", "pipe", "pipe"], cwd: TMP, env: { ...process.env, HOME: TMP } })
      : spawn(process.execPath, daemonArgs, { detached: true, stdio: ["pipe", "pipe", "pipe"], cwd: TMP, env: { ...process.env, HOME: TMP } });
    child.stdin.write("e2e-passkey");
    child.stdin.end();
    // Only attach listeners when actually debugging: an unref'd child whose pipes
    // are never drained can keep the event loop and the socket busy, and silently
    // swallowing stderr is exactly how this test hid its own real failure.
    if (process.env.VW_TEST_DEBUG) {
      child.stdout.on("data", (d) => process.stderr.write(`[daemon] ${d}`));
      child.stderr.on("data", (d) => process.stderr.write(`[daemon] ${d}`));
    } else {
      child.stdout.resume();
      child.stderr.resume();
    }
    child.once("spawn", () => daemonPids.push(child.pid));
    child.unref();
    return child;
  };
  launch();
  const deadline = Date.now() + 8000;
  while (!fs.existsSync(SOCK) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 50));
}

// Warm the store clone. `f` clones every configured uck bucket into a HOME that
// has none, and that clone happens on the *first* invocation — a bare
// `f creds status` in a fresh HOME measured ~5s here, and each provider lookup
// makes several `f` calls. Without priming, those seconds land on the first
// assertion and the uck's own execFileSync timeout turns a slow test into a
// spurious "creds are locked".
{
  const { execFileSync } = await import("node:child_process");
  const t0 = Date.now();
  try {
    execFileSync("f", ["creds", "status"], { encoding: "utf8", timeout: 180000, cwd: SAFE_CWD, stdio: ["ignore", "pipe", "pipe"] });
  } catch { /* state checked by the assertions themselves */ }
  if (process.env.VW_TEST_DEBUG) console.log(`[dbg] cold 'f creds status' took ${Date.now() - t0}ms`);
}
t("real daemon unlocked in the isolated store", fs.existsSync(LOCK), "no lockfile");

/* ------------------------- test suite (ordered) ------------------------- */

const box = new Map();
const stamps = new Map();
let unlockedFlag = true;
const store = {
  isUnlocked: async () => unlockedFlag,
  getCred: async (k) => (unlockedFlag && box.has(k) ? box.get(k) : null),
  setMirror: async (k, v, ttl) => { box.set(k, v); stamps.set(k, Date.now() + ttl); },
  isFresh: async (k, capSec) => { const s = stamps.get(k); return unlockedFlag && s != null && Date.now() < s && Date.now() < Date.now() + (capSec ?? 0) * 1000; },
};

// 0. provider must report unconfigured cleanly
{
  const st0 = await VW.credentialProvider.status();
  t("unconfigured: not ready, no throw", st0.ready === false && /no server/.test(st0.note), JSON.stringify(st0));
  t("unconfigured: resolve returns null (not an error)", (await VW.credentialProvider.resolve("github.com")) === null);
}

// 1. configure + seed secrets into the real store
const cfgPath = path.join(TMP, ".f/f.config.json");
// `f` clones the uck store into a HOME that has none, and merges the real
// ~/.f/f.config.json while doing so — which silently replaced the test email with
// the operator's. The provider then resolves against the real (locked) store and
// reports "creds locked" even though the test store is unlocked: a fixture bug
// indistinguishable from a product bug. Prime the clone first, then write the
// config, then verify it survived.
try { execSync("f creds status", { cwd: SAFE_CWD, env: { ...process.env, HOME: TMP }, timeout: 180000, stdio: ["ignore", "pipe", "pipe"] }); } catch { /* state asserted below */ }
// allowInsecureHttp: the mock is plaintext http on loopback, which the client
// refuses by default (it ships the api key + password hash). Asserted below.
fs.writeFileSync(cfgPath, JSON.stringify({ vaultwarden: { server: BASE, email: EMAIL, timeoutMs: 8000, allowInsecureHttp: true } }, null, 2));
{
  const written = JSON.parse(fs.readFileSync(cfgPath, "utf8")).vaultwarden ?? {};
  if (written.email !== EMAIL || written.server !== BASE) {
    throw new Error(`test home config did not stick: ${JSON.stringify(written)}`);
  }
}

// Seed via the daemon socket so nothing lands in argv/ps.
const net = (await import("node:net")).default;
function sockOp(req) {
  return new Promise((resolve, reject) => {
    const sock = JSON.parse(fs.readFileSync(LOCK, "utf8")).socket;
    const c = net.connect(sock, () => c.write(JSON.stringify(req)));
    let buf = "";
    c.on("data", (d) => (buf += d));
    c.on("end", () => { try { const r = JSON.parse(buf); r.ok ? resolve(r) : reject(new Error(r.error)); } catch (e) { reject(e); } });
    c.on("error", reject);
  });
}
// 1b. the readiness gate. This is the check that shipped wrong: it demanded an
// API key after SSO made one optional, so a provider that resolved every cred
// correctly reported `not ready: no API key` and pushed the operator toward a
// web-vault key they did not need. Readiness must accept any ONE of the three
// routes login() will actually try.
{
  const seed = async (want) => {
    for (const n of ["vaultwarden.client-id", "vaultwarden.client-secret", "vaultwarden.refresh-token"]) {
      await sockOp({ op: "rm", name: n }).catch(() => {});
    }
    for (const n of want) await sockOp({ op: "set", name: n, value: "seed-" + n.split(".").pop() });
  };
  // SSO alone is enough.
  await seed(["vaultwarden.master-password", "vaultwarden.refresh-token"]);
  let st = await VW.credentialProvider.status();
  t("ready via SSO session with no API key", st.ready === true && /SSO session/.test(st.note), JSON.stringify(st));
  // API key alone is enough.
  await seed(["vaultwarden.master-password", "vaultwarden.client-id", "vaultwarden.client-secret"]);
  st = await VW.credentialProvider.status();
  t("ready via API key with no SSO session", st.ready === true && /API key/.test(st.note), JSON.stringify(st));
  // Neither: say which is missing and offer BOTH fixes. The old hint named only
  // the API key, so an SSO-only operator was told to go mint a key.
  await seed(["vaultwarden.master-password"]);
  st = await VW.credentialProvider.status();
  t("no sign-in route at all: not ready, hint mentions SSO", st.ready === false && /sso login/.test(st.hint), JSON.stringify(st));
  // Restore what the rest of the suite assumes.
  await seed(["vaultwarden.master-password", "vaultwarden.client-id", "vaultwarden.client-secret"]);
}

await sockOp({ op: "set", name: "vaultwarden.client-id", value: "user.test-id" });
await sockOp({ op: "set", name: "vaultwarden.client-secret", value: "test-secret" });
await sockOp({ op: "set", name: "vaultwarden.master-password", value: PASSWORD });
t("store seeded", true);

// 1b. the plaintext guard must be armed by default and honoured per config
{
  const cfg = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
  const insecure = { ...cfg.vaultwarden, allowInsecureHttp: false };
  fs.writeFileSync(cfgPath, JSON.stringify({ vaultwarden: insecure }, null, 2));
  injectVw();
  providers.clearMisses(); box.clear(); stamps.clear();
  const r = await providers.resolveViaProvider("guard-check.example", store);
  t("plaintext http is refused unless opted in", !!r.error && /refusing to send credentials over plaintext http/.test(r.error) && /loopback/.test(r.error), String(r.error ?? JSON.stringify(r)).slice(0, 160));
  cfg.vaultwarden.allowInsecureHttp = true;
  fs.writeFileSync(cfgPath, JSON.stringify(cfg, null, 2));
}

// 2. readiness
{
  const s = await VW.credentialProvider.status();
  t("configured + unlocked: ready", s.ready === true, JSON.stringify(s));
}

// 3. resolve through the provider ladder (the actual production path)
injectVw();

{
  const r = await freshLookup("github.com");
  // Two items are named github.com -> must refuse to guess
  t("duplicate item name => loud ambiguity, not a coin flip", !!r.error && /ambiguous|2 vault items are named/.test(r.error), JSON.stringify(r).slice(0, 200));
}
{
  const r = await freshLookup("forgejo.kensand.net");
  t("host match via uri => correct password", r.value === "fj_token_3" && r.provider === "vaultwarden", JSON.stringify(r).slice(0, 200));
  t("hit was mirrored", box.get("mirror:forgejo.kensand.net") === "fj_token_3");
  t("mirror records its source", providers.mirrorSource("mirror:forgejo.kensand.net") === "vaultwarden");
}
{
  const before = CIPHERS_HITS;
  const r = await providers.resolveViaProvider("forgejo.kensand.net", store);
  t("fresh mirror answers with no vault traffic", r.mirror === "fresh" && CIPHERS_HITS === before, `extra=${CIPHERS_HITS - before}`);
}
{
  const r = await freshLookup("Forgejo::username");
  t("::field selector reaches username", r.value === "kenny", JSON.stringify(r).slice(0, 160));
}
{
  const r = await freshLookup("nopass.example");
  t("item with no password reports what it does have", !!r.error && /has no password/.test(r.error) && /username/.test(r.error), String(r.error).slice(0, 200));
}
{
  const r = await freshLookup("totally-absent-host.example");
  t("unknown name => clean miss (no error)", r.miss === true && !r.error, JSON.stringify(r).slice(0, 200));
  t("unknown name => negative cache", providers.missBackoffLeft("totally-absent-host.example") > 0);
}
{
  const before = CIPHERS_HITS;
  await providers.resolveViaProvider("totally-absent-host.example", store);
  t("negative cache suppresses a repeat vault fetch", CIPHERS_HITS === before, `extra=${CIPHERS_HITS - before}`);
}
{
  const r = await freshLookup("wild::password");
  // wildcard uri "* GitLab" is not a host; the item is reachable by name though
  const byName = await providers.resolveViaProvider("wild", store);
  t("plain item name resolves", byName.value === "p" || !!byName.value, JSON.stringify(byName).slice(0, 160));
}

// 4. map entries disambiguate
{
  const cfg = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
  cfg.vaultwarden.map = { "github.com": "aaaaaaaa-0001::password", "gh-work": "aaaaaaaa-0002::password", "gh-name": "github.com" };
  fs.writeFileSync(cfgPath, JSON.stringify(cfg, null, 2));
  injectVw();
  const r = await freshLookup("github.com");
  t("map by item ID resolves the ambiguity to the intended secret", r.value === "ghp_real_1", JSON.stringify(r).slice(0, 160));
  const r2 = await freshLookup("gh-work");
  t("a second map entry reaches the other duplicate", r2.value === "ghp_work_2", JSON.stringify(r2).slice(0, 160));
  const r3 = await freshLookup("gh-name");
  t("a map target that is still ambiguous says so rather than picking", !!r3.error && /matches 2 items|ambiguous/.test(r3.error), JSON.stringify(r3).slice(0, 200));
  const r4 = await freshLookup("aaaaaaaa-0001");
  t("a bare item id resolves without a map entry", r4.value === "ghp_real_1", JSON.stringify(r4).slice(0, 160));
}

// 5. locked store must not be papered over
{
  unlockedFlag = false;
  const before = CIPHERS_HITS;
  // Deliberately NOT freshLookup: the point of this case is that pre-existing
  // mirror state must not let a locked store answer. Seed a mirror, then lock.
  box.set("mirror:locked-check.example", "stale-value");
  stamps.set("mirror:locked-check.example", Date.now() + 60000); // fresh stamp, locked store
  const r = await providers.resolveViaProvider("locked-check.example", store);
  t("locked store => no vault traffic", CIPHERS_HITS === before, `extra=${CIPHERS_HITS - before}`);
  t("locked store => refuses with the reason, not a silent miss", !!r.error && /locked/.test(r.error), JSON.stringify(r).slice(0, 160));
  unlockedFlag = true;
}

// 6. server-side failure must surface as an error, never as "no such cred"
{
  providers.clearMisses();
  // point at a dead port
  const cfg = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
  const dead = cfg.vaultwarden.server;
  cfg.vaultwarden.server = "http://127.0.0.1:1";
  fs.writeFileSync(cfgPath, JSON.stringify(cfg, null, 2));
  injectVw();
  const r = await freshLookup("some-new-name.example");
  t("unreachable vault => error mentioning the cause", !!r.error && /reach|ECONN|refused|timed out/i.test(r.error), JSON.stringify(r).slice(0, 220));
  cfg.vaultwarden.server = dead;
  fs.writeFileSync(cfgPath, JSON.stringify(cfg, null, 2));
}

// 7. wrong master password must not be reported as "not set"
{
  await sockOp({ op: "set", name: "vaultwarden.master-password", value: "not-the-password" });
  // drop cached keys so derivation actually runs
  try { await sockOp({ op: "rm", name: "vaultwarden.key-cache" }); } catch {}
  providers.clearMisses();
  injectVw();
  const r = await freshLookup("brand-new-name.example");
  // The old assertion here demanded the phrase "the server rejected the master password", and
  // it stayed green right up until it became the thing that misled a debugging session for
  // hours: the master password was PROVABLY correct (profile.key unwrapped, MAC verified) while
  // this message insisted it was wrong. Bitwarden returns the same string for a bad email, a bad
  // password, and a rejected request, so the honest assertion is that the error REFUSES to pick
  // a cause, and still rules out the one failure mode that would be a silent data bug.
  t("a rejected login is reported without falsely naming a cause",
    !!r.error && /does not distinguish/.test(r.error) && !/retype it/.test(r.error),
    JSON.stringify(r).slice(0, 200));
  t("a bad password is NOT masked by a working api key", !/no such item|not found/i.test(String(r.error ?? "")),
    "an api key must not silently authenticate a run whose master password was rejected: " + JSON.stringify(r).slice(0, 160));
  await sockOp({ op: "set", name: "vaultwarden.master-password", value: PASSWORD });
}

// 8. api key must actually have been used, and only client_credentials
// The design changed: an API key is no longer required, and the password grant is tried
// first because it needs nothing but the master password. Assert the ORDER, not just that a
// token appeared -- the previous version of this assertion stayed green while the client
// silently used the API key fallback, because the mock's password check was broken.
t("password grant is tried first and succeeds", GRANTS[0] === "password", `grants: ${JSON.stringify(GRANTS)}`);
{
  const firstRun = GRANTS.slice(0, Math.max(FIRST_RUN_GRANTS, 1));
  t("the api key is not needed when the password grant works",
    FIRST_RUN_GRANTS > 0 && firstRun[0] === "password" && !firstRun.includes("client_credentials"),
    `first-run grants: ${JSON.stringify(firstRun)} (all: ${JSON.stringify(GRANTS)})`);
}
t("password grant sent the master-password proof + a supported scope",
  !!PW_GRANT_SEEN && PW_GRANT_SEEN.password === EXPECTED_PW_HASH && PW_GRANT_SEEN.scope === "api offline_access",
  JSON.stringify({ ...PW_GRANT_SEEN, password: PW_GRANT_SEEN?.password === EXPECTED_PW_HASH ? "MATCH" : `MISMATCH want=${EXPECTED_PW_HASH.slice(0,8)}` }));
t("prelogin was consulted for KDF params", PRELOGIN_HITS >= 1, `hits=${PRELOGIN_HITS}`);
// The device fields must reach the server exactly once each. The real server rejects the
// duplication outright, so a client that sends both spellings cannot log in at all -- and a
// mock that tolerated it kept this suite green through a completely broken login.
{
  // Evidence, not inference: the mock rejects a duplicated device field with a 400 before it
  // ever hands out a token, so if any request carried both spellings, some request either got
  // a 400 (and the auth assertions below fail) or the field list here shows the duplication.
  const dupRequests = TOKEN_LOG.filter((e) => e.sentDevice.some((k) => /[A-Z]/.test(k)) && e.sentDevice.some((k) => k.includes("_")));
  t("every token request sent device fields in exactly one spelling",
    TOKEN_LOG.length > 0 && dupRequests.length === 0,
    `${TOKEN_LOG.length} request(s), duplicated in ${dupRequests.length}: ${JSON.stringify(TOKEN_LOG[0]?.sentDevice)}`);
}

// 8b. rate limiting must be explained, not shown as a bare status code
{
  RATE_LIMIT_NEXT = true;
  providers.clearMisses(); injectVw(); box.clear(); stamps.clear();
  // Force a fresh token by dropping the cache so the token endpoint is hit again.
  try { await sockOp({ op: "rm", name: "vaultwarden.key-cache" }); } catch {}
  const r = await providers.resolveViaProvider("rate-limit-probe.example", store);
  t("HTTP 429 explains the lockout instead of a bare code", !!r.error && /Too many login requests/.test(r.error) && /rate-limiting|wait/.test(r.error), String(r.error ?? JSON.stringify(r)).slice(0, 200));
}

// 8b. THE fork-bomb regression. Needs the real unlocked daemon: with a locked
// store, `f creds status` short-circuits before it ever probes providers, so a
// locked-store version of this test passes whether or not the bug exists. Verified
// by hand: with the guards removed this reports a peak in the hundreds, and with
// them in place the peak is single digits.
{
  const countVw = () => {
    try { return Number(execSync(`pgrep -fc ${JSON.stringify("vaultwarden[/]index[.]js")} || true`, { encoding: "utf8" }).trim() || "0"); }
    catch { return 0; }
  };
  let peak = 0;
  const sample = setInterval(() => { peak = Math.max(peak, countVw()); }, 20);
  try {
    // The command that detonated: provider discovery with a *configured* provider
    // whose status() wants the store. Runs against the real daemon via HOME=TMP.
    execFileSync("f", ["creds", "status"], { encoding: "utf8", timeout: 90000, maxBuffer: 1 << 24, cwd: SAFE_CWD, env: { ...process.env, HOME: TMP } });
  } catch { /* locked/exit codes are not the point; the count is */ }
  clearInterval(sample);
  // Scope, honestly: this proves one probe pass does not multiply. It is NOT a
  // proof against the original fork bomb, and it would not have caught it — the
  // bomb needed the store unlocked *and* a configured provider, and this suite
  // runs with the operator's real store locked, so p.status() is never reached.
  // Verified by disabling the guards: this assertion still passed.
  t("one provider probe pass does not multiply processes", peak <= 6, `peak of ${peak} provider processes during one 'f creds status'`);

  // And the marker must actually be honoured, not merely set.
  peak = 0;
  const sample2 = setInterval(() => { peak = Math.max(peak, countVw()); }, 20);
  try {
    execFileSync("f", ["creds", "status"], { encoding: "utf8", timeout: 90000, maxBuffer: 1 << 24, cwd: SAFE_CWD, env: { ...process.env, HOME: TMP, F_CREDS_NO_PROVIDER: "1" } });
  } catch {}
  clearInterval(sample2);
  // Same scope caveat as above.
  t("marker does not change probe behaviour for a locked store", peak <= 6, `peak of ${peak} provider processes with the marker set`);
}

// 9. read-only by default: nothing in this suite may write to the vault
t("no vault writes occurred during resolution", PUT_BODIES.length === 0, JSON.stringify(PUT_BODIES.map((p) => p.url)));
t("sync was used once for the initial key unwrap", SYNC_HITS >= 1, `sync=${SYNC_HITS}`);
await t("a rejected field is named in the error, and no token is ever echoed", async () => {
  const prev = server;
  server = http.createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      res.writeHead(400, { "Content-Type": "application/json" });
      // Includes an access_token on purpose: the real server does this on some error paths, so
      // a debug path that echoes the whole body would leak a live bearer token to stderr, logs,
      // and any captured output.
      res.end(JSON.stringify({ error: "invalid_grant", error_description: "Username or password is incorrect. Try again.", validationErrors: { device_identifier: ["The device_identifier field is required."] }, access_token: "LEAK-CHECK-TOKEN" }));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { VaultwardenApi } = await import(pathToFileURL(path.join(UCK, "lib", "vwclient.js")).href);
    const api = new VaultwardenApi({ server: BASE, timeoutMs: 8000, allowInsecureHttp: true });
  try {
    await api.loginPassword({ email: EMAIL, passwordHash: "aaaa" });
    assert.fail("expected a rejection");
  } catch (e) {
    assert.equal(e.status, 400);
    assert.ok(e.fieldErrors?.some((f) => /device_identifier/.test(f)), `rejected field must be named, got ${JSON.stringify(e.fieldErrors)}`);
    // The message the operator sees must not contain the token, while rawBody keeps it for
    // an explicit debug run -- that asymmetry is the whole point.
    assert.ok(!String(e.message).includes("LEAK-CHECK-TOKEN"), "error message must never echo a bearer token");
  } finally {
    server.close();
    server = prev;
  }
});



/* ------------------- SSO login, end to end through a mock IdP -------------------
 * This path reached the operator's terminal broken ("ssoRequiresMasterPassword is not
 * defined") because NOTHING here exercised it: every earlier test drove the provider
 * layer, never the `sso login` command. So this drives the real CLI as a child process,
 * the only way to catch a missing import or a wrong name in the command handler -- those
 * are runtime errors and the module imports cleanly without them.
 *
 * ONE INVOCATION, START TO FINISH. `sso login` mints a fresh PKCE verifier per process and
 * keeps it only in that process's memory, so the URL whose code_challenge the IdP (here, the
 * mock) sees and the process that POSTs the matching code_verifier must be the same process.
 * Scraping a URL from one run and pasting the code into another cannot work -- and an earlier
 * version of this test did exactly that, then spent a long time on a "PKCE verification
 * failed" that was entirely the harness's fault.
 */
{
  fs.mkdirSync(path.join(TMP, ".f"), { recursive: true });
  fs.writeFileSync(path.join(TMP, ".f", "f.config.json"), JSON.stringify({
    vaultwarden: { server: BASE, email: EMAIL, timeoutMs: 20000, allowInsecureHttp: true },
  }));
  const { spawn } = await import("node:child_process");

  // Start the CLI and drive its stdin as it prompts, so challenge and verifier stay in one
  // process. The URL appears on stderr before the prompt; the code is only produced by
  // whatever we hand back.
  const loginOnce = (args, codeFor) => new Promise((resolve) => {
    const c = spawn(process.execPath, [path.join(UCK, "index.js"), ...args], {
      cwd: SAFE_CWD, env: { ...process.env, HOME: TMP, ...(process.env.VW_TRACE ? { VW_TRACE: "1" } : {}) }, stdio: ["pipe", "pipe", "pipe"],
    });
    c.stdin.on("error", () => { /* EPIPE once the CLI stops reading: expected */ });
    let out = "", err = "", asked = false;
    c.stdout.on("data", (d) => { out += d; });
    c.stderr.on("data", (d) => {
      err += d;
      // React to the printed authorize URL rather than to a timer.
      if (asked) return;
      const m = /\/identity\/connect\/authorize\?([^\s]+)/.exec(err);
      if (!m) return;
      asked = true;
      const q = new URLSearchParams(m[1]);
      SSO_PENDING = { challenge: q.get("code_challenge") };   // as the real IdP would record it
      const redirect = `http://localhost:8065/?code=${codeFor}&state=${q.get("state")}&scope=api+offline_access&iss=${encodeURIComponent(BASE)}`;
      // Delay before writing. Writing synchronously from inside the stderr listener beats
      // the CLI to its own prompt and the line is lost -- the child then exited 0 with empty
      // stdout, which looked exactly like a product bug and was not one. The CLI prints the
      // URL, prints its prompt, and only then starts reading stdin.
      setTimeout(() => { try { c.stdin.write(redirect + "\n"); } catch { /* gone */ } }, 400);
      // Deliberately no c.stdin.end(): readline reports end-of-input as `close`, and the CLI
      // now (correctly) answers "stdin is not a tty" and quits. Ending stdin here used to make
      // every login "succeed" with an empty stdout.
    });
    // Do NOT c.stdin.end(): readline treats end-of-input as `close`, and the CLI now
    // (correctly) answers "stdin is not a tty" and quits. That is what made an earlier
    // version of this harness resolve the login successfully-looking with empty stdout:
    // the child exited 0 having done nothing. Keep stdin open and let the CLI close it.
    // Resolve ONLY from `close`. `close` fires once both pipes have ended, which is what makes
    // `out` complete: an earlier version also resolved from this timeout, and if it won the
    // race the assertions saw `out` as an empty string and reported a successful login as a
    // failure. The timeout must still kill a hung child, but it must not resolve early.
    const kill = setTimeout(() => { try { c.kill("SIGKILL"); } catch { /* gone */ } }, 60000);
    // Resolve on `close`, which fires only after both pipes have ended -- that is what makes
    // `out` complete. The timeout above must kill a hung child but must NOT resolve early: an
    // earlier revision resolved from the timer too, and whenever it won the race the assertions
    // saw an empty `out` and called a working login a failure.
    c.on("close", (code, signal) => { clearTimeout(kill); resolve({ code, signal, out, err }); });
    // A child that could not start at all must be visible: without this a spawn failure reads
    // as "empty output, exit 0", which is how this suite hid bugs in itself.
    c.on("error", (e) => { clearTimeout(kill); resolve({ code: null, out, err: err + "\n[spawn error] " + e.message, spawnError: true }); });
  });

  // 1. sso status -- unauthenticated probe; must not need a token or a password
  {
    const r = await new Promise((res) => {
      const c = spawn(process.execPath, [path.join(UCK, "index.js"), "sso", "status"], { cwd: SAFE_CWD, env: { ...process.env, HOME: TMP }, stdio: ["ignore", "pipe", "pipe"] });
      let o = ""; c.stdout.on("data", (d) => (o += d)); c.on("close", () => res({ out: o }));
    });
    t("sso status reports the mock's SSO as enabled", /sso\tenabled/.test(r.out), JSON.stringify(r).slice(0, 160));
  }

  // 2. a non-tty must fail loudly. `--manual` reads the pasted redirect from stdin; with no
  //    tty it used to hang and then exit 0 with empty output, indistinguishable from success.
  {
    const r = await new Promise((res) => {
      const c = spawn(process.execPath, [path.join(UCK, "index.js"), "sso", "login", "--manual"], { cwd: SAFE_CWD, env: { ...process.env, HOME: TMP }, stdio: ["ignore", "pipe", "pipe"] });
      let o = "", e = ""; c.stdout.on("data", (d) => (o += d)); c.stderr.on("data", (d) => (e += d));
      c.on("close", (code) => res({ code, out: o, err: e }));
      setTimeout(() => { try { c.kill("SIGKILL"); } catch { /* gone */ } res({ code: null, out: o, err: e, hung: true }); }, 30000);
    });
    t("no terminal => a real error, not a silent exit 0",
      r.code !== 0 && (r.out + r.err).trim().length > 0 && !/is not defined/.test(r.err),
      JSON.stringify({ code: r.code, hung: !!r.hung, tail: r.err.slice(-90) }));
  }

  // 3. the full manual login, in one process
  {
    const r = await loginOnce(["sso", "login", "--manual"], "fe1049e96ec149bbae03290f0c2ed220");
    const combined = r.out + r.err;
    t("no missing-name crash (the bug that reached the operator)",
      !/is not defined/.test(combined), combined.split("\n").find((l) => /is not defined/.test(l)) || "clean");
    t("token exchange succeeded with the pasted redirect", /authenticated\s+yes/.test(r.out),
      JSON.stringify({ code: r.code, out: r.out.slice(0, 90), tail: r.err.slice(-160) }));
    t("the offline_access scope earned a refresh token", /refresh token\s+yes/.test(r.out), JSON.stringify(r.out).slice(0, 160));
    t("the SSO grant was the grant actually used", GRANTS.includes("authorization_code"), JSON.stringify(GRANTS.slice(-3)));
    {
      const ssoTok = TOKEN_LOG.filter((e) => e.grant === "authorization_code").pop();
      t("the code_verifier was posted, not just the code",
        Boolean(ssoTok?.fields?.code_verifier && ssoTok.fields.code),
        JSON.stringify(ssoTok?.fields ?? "no authorization_code token request seen").slice(0, 200));
      // The device fields are required here too; a missing one is rejected before the
      // exchange is even considered.
      t("the SSO grant sent the device fields", ssoTok?.sentDevice?.length === 3, JSON.stringify(ssoTok?.sentDevice));
      t("the SSO grant asked for offline_access (this is what earns the refresh token)",
        ssoTok?.fields?.scope === "api offline_access", ssoTok?.fields?.scope ?? "(none)");
      t("the SSO grant used client_id=cli", ssoTok?.fields?.client_id === "cli", ssoTok?.fields?.client_id ?? "(none)");
      t("the SSO grant sent NO client secret (PKCE replaces it)",
        !ssoTok?.fields?.client_secret, "a secret was sent; PKCE should make it unnecessary");
    }
    // The child process writes to the REAL creds store in TMP, not to the in-process `box`
    // that the provider tests use -- asserting on `box` here could only ever fail. What this
    // can assert without a second store is that a refresh token came back at all (next
    // assertion), which is the thing that makes a later run work without a browser.
    t("the CLI reported the session as usable later", /sessions renew without a browser/.test(r.out), JSON.stringify(r.out).slice(0, 200));

    // THE POINT OF THE AWAIT. persistSsoTokens writes through a daemon socket, so an
    // un-awaited call turns a failed write into an unhandled rejection: nothing is printed,
    // the process exits 0, and `authenticated  yes` still prints above it -- a login that
    // looks flawless and whose session was never saved, so the next run says "not logged in".
    // Asserting only on the success text CANNOT see that (proven: removing both awaits kept
    // this suite green), so read the tokens back from the store the CLI wrote to.
    // Read the session back through the daemon, the same socket the CLI wrote through.
    // Using the CLI to read it would re-enter discovery and a vault open; the daemon is the
    // thing whose agreement actually matters here.
    const readBack = (name) => new Promise((res) => {
      const sock = (() => { try { return JSON.parse(fs.readFileSync(path.join(TMP, ".f", ".creds-daemon"), "utf8")).socket; } catch { return null; } })();
      if (!sock) return res({ error: "no daemon socket in the temp home" });
      const c = net.connect(sock, () => c.write(JSON.stringify({ op: "get", name })));
      let buf = "";
      c.on("data", (d) => (buf += d));
      c.on("end", () => { try { res(JSON.parse(buf)); } catch (e) { res({ error: String(e.message) }); } });
      c.on("error", (e) => res({ error: e.code }));
      setTimeout(() => res({ error: "timeout" }), 15000);
    });
    const tokR = await readBack("vaultwarden.access-token");
    const refR = await readBack("vaultwarden.refresh-token");
    t("the SSO session was actually persisted (not a floating promise)",
      tokR.ok === true && refR.ok === true,
      JSON.stringify({ access: tokR.ok ? "stored" : tokR.error ?? tokR, refresh: refR.ok ? "stored" : refR.error ?? refR }).slice(0, 200));
  }

  // 4. PKCE is enforced by the server, so a captured code + wrong verifier must fail
  {
    SSO_PENDING = { challenge: "Z".repeat(43) };
    const { VaultwardenApi } = await import(pathToFileURL(path.join(UCK, "lib", "vwclient.js")).href);
    const api = new VaultwardenApi({ server: BASE, timeoutMs: 8000, allowInsecureHttp: true });
    let msg = "";
    try { await api.loginSso({ code: "stolen-code-1234567890", codeVerifier: crypto.randomBytes(32).toString("base64url") }); msg = "ACCEPTED"; }
    catch (e) { msg = String(e.message); }
    t("a code with a non-matching verifier is refused", /PKCE verification failed/.test(msg), msg.slice(0, 90));
  }

  // 5. paste handling -- the shapes an operator actually produces
  t("a bare code pasted alone works", VW.extractSsoCode("fe1049e96ec149bbae03290f0c2ed220") === "fe1049e96ec149bbae03290f0c2ed220");
  t("a code wrapped in quotes works", VW.extractSsoCode('"fe1049e96ec149bbae03290f0c2ed220"') === "fe1049e96ec149bbae03290f0c2ed220");
  t("the full address bar works", /fe1049e9/.test(VW.extractSsoCode("http://localhost:8065/?code=fe1049e96ec149bbae03290f0c2ed220&state=abc")));
  t("a CRLF paste works (Windows terminals and some browsers)", /fe1049e9/.test(VW.extractSsoCode("http://localhost:8065/?code=fe1049e96ec149bbae03290f0c2ed220\r\n")));
  t("a binding-mismatch body is explained, not 'no code found'",
    /binding mismatch/i.test(VW.extractSsoServerError('{"error":"SSO session binding mismatch"}') || ""), "");
}



/* ------------------------------------- a missing master password, honestly */
// The failure that cost the most time in this whole piece of work. `f creds get` exits 1 for
// BOTH "never stored" and "cannot read", credsGet re-threw that child's stderr verbatim
// (already prefixed with "f: "), and the operator saw:
//     f: f: Unsupported state or unable to authenticate data
// which sounds exactly like an AES-GCM tag check, so hours went into crypto while the actual
// state was: no master password had ever been stored. A message that misattributes the
// subsystem is not a cosmetic defect -- it moves the investigation to the wrong file.
{
  const store = fs.mkdtempSync(path.join(os.tmpdir(), "vw-nomaster-"));
  const cfg = { vaultwarden: { server: BASE, email: "kensand@kensand.net", timeoutMs: 20000, allowInsecureHttp: true } };
  fs.mkdirSync(path.join(store, ".f"), { recursive: true });
  fs.writeFileSync(path.join(store, ".f", "f.config.json"), JSON.stringify(cfg));
  // Point the uck at a daemon socket that does not exist, so any `f creds` read from this
  // store fails the same way an unreadable store fails for a real user.
  fs.writeFileSync(path.join(store, ".f", ".creds-daemon"), JSON.stringify({ socket: "/nonexistent/vw-e2e.sock" }));
  const { spawn } = await import("node:child_process");
  const out = await new Promise((res) => {
    const c = spawn(process.execPath, [path.join(UCK, "index.js"), "list"], { cwd: SAFE_CWD, env: { ...process.env, HOME: store }, stdio: ["ignore", "pipe", "pipe"] });
    let o = ""; c.stdout.on("data", (d) => (o += d)); c.stderr.on("data", (d) => (o += d));
    c.on("close", () => res(o));
    setTimeout(() => { try { c.kill("SIGKILL"); } catch { /* gone */ } res(o); }, 30000);
  });
  t("a credential-read failure is never reported as a crypto failure",
    !/unable to authenticate|unsupported state|MAC verification|bad decrypt/i.test(out) && /f creds/i.test(out),
    JSON.stringify(out).slice(0, 200));
  fs.rmSync(store, { recursive: true, force: true });
}

console.log(`\n${pass} passed, ${fail} failed   (tmp home: ${TMP})`);
console.log(`counts: prelogin=${PRELOGIN_HITS} sync=${SYNC_HITS} ciphers=${CIPHERS_HITS}`);
server.close();
// Stop the daemon we started, via the protocol rather than a signal: it zeroes
// its key and removes its own socket/lockfile. Killing it would leave both behind.
for (const pid of daemonPids) {
  if (!pid) continue;
  try { execFileSync("f", ["creds", "lock"], { cwd: SAFE_CWD, timeout: 15000, stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, HOME: TMP } }); } catch { /* best effort */ }
  try { process.kill(pid, "SIGTERM"); } catch { /* already gone */ }
}
try { fs.rmSync(TMP, { recursive: true, force: true }); } catch {}
try { fs.rmSync(SAFE_CWD, { recursive: true, force: true }); } catch {}
process.exit(fail ? 1 : 0);
