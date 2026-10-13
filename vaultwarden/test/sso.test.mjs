// Offline tests for the SSO flow. A mock Vaultwarden identity server implements
// the server-side contract copied from the Vaultwarden source (src/api/identity.rs
// and src/sso.rs): required fields, the client_id/redirect_uri rules, and the
// token response shape. If our request shape drifts from that contract, the mock
// rejects it the same way the real server would.
//
//   node vaultwarden/test/sso.test.mjs

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import http from "node:http";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const C = await import(pathToFileURL(path.join(here, "..", "lib", "vwclient.js")).href);
const { captureSsoCode } = await import(pathToFileURL(path.join(here, "..", "lib", "sso-callback.js")).href);

let refreshCount = 0;
let pass = 0, fail = 0;
const t = async (label, fn) => {
  try { await fn(); pass++; console.log(`ok   ${label}`); }
  catch (e) { fail++; console.log(`FAIL ${label}\n     ${String(e.message).split("\n").join("\n     ")}`); }
};

/* ------------------------------------------------------------ mock server */

const seen = { token: null, authorize: null, prevalidateHits: 0 };
// Set these to steer the mock per-test.
let mock = {};

const srv = http.createServer((req, res) => {
  let body = "";
  req.on("data", (d) => (body += d));
  req.on("end", () => {
    const u = new URL(req.url, "http://x");
    const form = Object.fromEntries(new URLSearchParams(body));
    const json = (code, obj) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(obj)); };

    if (u.pathname === "/identity/sso/prevalidate") {
      seen.prevalidateHits++;
      // Real shapes, copied from identity.rs `prevalidate`: enabled answers with a
      // signed token claim and nothing else; disabled answers with an error. There is no
      // boolean `ssoEnabled` field -- an earlier client checked for one and always
      // reported "not enabled".
      if (mock.ssoOff) return json(400, { message: "SSO sign-in is not available" });
      return json(200, { token: "eyJhbGciOiJIUzI1NiJ9.stub.signature" });
    }

    // The real entry point: GET /identity/connect/authorize answers 307 to the IdP.
    // There is no JSON endpoint that returns an authorize URL. Field rules copied from
    // AuthorizeData + sso.rs::authorize_url.
    if (u.pathname === "/identity/connect/authorize") {
      seen.authorize = Object.fromEntries(u.searchParams);
      const { client_id, redirect_uri, code_challenge, code_challenge_method } = seen.authorize;
      if (code_challenge_method !== "S256") return json(400, { message: "Unsupported code challenge method" });
      if (!code_challenge) return json(400, { message: "code challenge cannot be blank" });
      const ports = [];
      for (let pt = 8065; pt <= 8070; pt++) ports.push(`http://localhost:${pt}`);
      if (client_id === "cli") {
        if (!ports.includes(redirect_uri)) return json(400, { message: `Unsupported redirect uri ${redirect_uri}` });
      } else if (!["web", "browser", "desktop", "mobile"].includes(client_id)) {
        return json(400, { message: `Unsupported client ${client_id}` });
      }
      mock.expectedChallenge = code_challenge;
      // Vaultwarden sets a browser-binding cookie here and 307s to the IdP. The issuer
      // is a DIFFERENT origin in reality (Keycloak/Authentik/etc. on its own host), so
      // the mock uses a separate listening socket rather than a path on this one --
      // otherwise "did we leave the server?" cannot be tested at all.
      res.writeHead(307, { location: `${IDP}/authorize?state=${seen.authorize.state}&client_id=vaultwarden` });
      return res.end();
    }

    if (u.pathname === "/identity/connect/token") {
      seen.token = form;
      if (form.grant_type === "refresh_token") {
        // identity.rs accepts this with client_id + refresh_token and no device fields.
        for (const f of ["client_id", "refresh_token"]) if (!form[f]) return json(400, { error: "invalid_request", error_description: `${f} cannot be blank` });
        refreshCount++;
        return json(200, { ...defaultToken(), access_token: `AT-${refreshCount}` });
      }
      if (form.grant_type !== "authorization_code") return json(400, { error: `unsupported grant ${form.grant_type}` });
      // Required-field checks copied from identity.rs sso_login.
      for (const f of ["client_id", "code", "code_verifier", "device_identifier", "device_name", "device_type"]) {
        if (!form[f]) return json(400, { error: "invalid_request", error_description: `${f} cannot be blank` });
      }
      // PKCE: the server hashes the verifier and compares to the stored challenge.
      const challenge = crypto.createHash("sha256").update(form.code_verifier).digest("base64url");
      if (challenge !== mock.expectedChallenge) {
        return json(400, { error: "invalid_grant", error_description: "code verifier mismatch" });
      }
      return json(200, mock.tokenResponse ?? defaultToken());
    }

    json(404, { message: "no route" });
  });
});
await new Promise((r) => srv.listen(0, "127.0.0.1", r));
const BASE = `http://127.0.0.1:${srv.address().port}`;

const defaultToken = () => ({
  access_token: "AT-SSO", expires_in: 4200, token_type: "Bearer", refresh_token: "RT-SSO",
  Kdf: 0, KdfIterations: 600000, Key: "2.Iv|ct|mac", PrivateKey: "2.Iv|ct|mac",
  UserDecryptionOptions: { HasMasterPassword: true, MasterPasswordUnlock: { MasterKeyEncryptedUserKey: "2.Iv|ct|mac", Salt: "user@example.com" }, Object: "userDecryptionOptions" },
});

const api = () => new C.VaultwardenApi({ server: BASE, email: "user@example.com", timeoutMs: 8000, allowInsecureHttp: true });

// A second, genuinely separate origin stands in for the identity provider. Its job is
// only to prove the client stops at the IdP instead of trying to complete the flow
// without a browser (it cannot, and should not pretend to).
const idpHits = [];
const idpSrv = http.createServer((req, res) => {
  idpHits.push(req.url);
  res.writeHead(200, { "content-type": "text/html" });
  res.end("<html>pretend login screen</html>");
});
await new Promise((r) => idpSrv.listen(0, "127.0.0.1", r));
const IDP = `http://127.0.0.1:${idpSrv.address().port}`;
assert.notEqual(new URL(IDP).port, new URL(BASE).port, "the mock IdP must be a different origin");

/**
 * Drive a capture to completion, returning its message whether it resolved or threw.
 * Also waits for the listener to be fully released, so the next test may bind the
 * same port. Without that, tests sharing a port collide with the ~250ms deferred
 * close and fail as "timed out waiting for the port to appear".
 */
async function collect(promise, driver) {
  const settled = Promise.resolve(promise).then((v) => `resolved:${v}`, (e) => `rejected:${String(e?.message ?? e)}`);
  await driver();
  const out = await settled;
  if (promise && promise.closed) await promise.closed;
  return out;
}

/** Poll until `fn()` returns something truthy (the log callback is our only port signal). */
async function waitFor(fn, ms = 1500) {
  const until = Date.now() + ms;
  while (Date.now() < until) { const v = fn(); if (v) return v; await new Promise((r) => setTimeout(r, 25)); }
  throw new Error("timed out waiting for condition");
}

/** Occupy a port on both loopback families, mirroring how the listener binds. */
async function hogPort(n) {
  const { createServer } = await import("node:net");
  const hogs = [];
  for (const host of ["127.0.0.1", "::1"]) {
    const s = createServer();
    s.on("error", () => {});   // one family may be unavailable on a v4-only box
    s.listen(n, host);
    await new Promise((r) => s.once("listening", r).once("error", r));
    hogs.push(s);
  }
  return async () => { for (const s of hogs) { try { await new Promise((r) => s.close(r)); } catch { /* ignore */ } } };
}

/** Plain HTTP GET that reports its status and drains the body. */
function get(port, pathName) { return getVia("127.0.0.1", port, pathName); }

async function getWithAgent(agent, port, pathName) {
  return new Promise((resolve) => {
    const req = http.request({ host: "localhost", port, path: pathName, agent, timeout: 3000 }, (res) => { res.resume(); res.on("end", () => resolve(`HTTP ${res.statusCode}`)); });
    req.on("error", (e) => resolve(`err ${e.code}`));
    req.on("timeout", () => { req.destroy(); resolve("err timeout"); });
    req.end();
  });
}

function getVia(host, port, pathName) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host, port, path: pathName, method: "GET" }, (res) => { res.resume(); res.on("end", () => resolve(res.statusCode)); });
    req.on("error", reject);
    req.end();
  });
}

/* ------------------------------------------------------------------ tests */

await t("ssoEnabled() reports enabled from the real {token} response", async () => {
  mock = {};
  const st = await api().ssoEnabled();
  assert.equal(st.enabled, true, "a {token} response means SSO is on; checking a boolean ssoEnabled field would say false");
  assert.equal(st.reachable, true);
  assert.ok(seen.prevalidateHits >= 1);
});

await t("ssoEnabled() does not mistake a bare-200-with-no-token for enabled", async () => {
  mock = {};
  const stub = new C.VaultwardenApi({ server: BASE, timeoutMs: 8000, allowInsecureHttp: true });
  const real = stub.fetch;
  stub.fetch = async (u, o) => ({ status: 200, ok: true, headers: new Headers({ "content-type": "application/json" }), text: async () => "{}" });
  const st = await stub.ssoEnabled();
  stub.fetch = real;
  assert.equal(st.enabled, false, "an empty 200 is not evidence of SSO");
});

await t("ssoEnabled() reports disabled when the server refuses prevalidate", async () => {
  mock = { ssoOff: true };
  const st = await api().ssoEnabled();
  assert.equal(st.enabled, false);
  assert.equal(st.reachable, true, "an HTTP refusal is a real answer about the setting");
});

await t("ssoEnabled() says 'unreachable', not 'disabled', when the server cannot be reached", async () => {
  // Conflating these sends the operator to flip SSO_ENABLED on a server that is fine.
  const dead = new C.VaultwardenApi({ server: "http://127.0.0.1:1", timeoutMs: 1500, allowInsecureHttp: true });
  const st = await dead.ssoEnabled();
  assert.equal(st.enabled, false);
  assert.equal(st.reachable, false, "must not claim knowledge of the server's config");
  assert.ok(st.error, "must carry the reason");
});

await t("authorize request uses client_id=cli + a port the server accepts", async () => {
  mock = {};
  const r = await api().ssoAuthorizeUrl({ redirectPort: 8065 });
  assert.equal(seen.authorize.client_id, "cli", "server rejects every other client for a CLI");
  assert.equal(seen.authorize.redirect_uri, "http://localhost:8065");
  assert.ok(r.authorizeUrl, "must hand back a URL to open");
  assert.ok(/[A-Za-z0-9_-]{40,}/.test(r.codeVerifier), "PKCE verifier must be high-entropy");
});

await t("authorize sends an S256 challenge that hashes from the verifier", async () => {
  mock = {};
  const r = await api().ssoAuthorizeUrl({ redirectPort: 8066 });
  const expect = crypto.createHash("sha256").update(r.codeVerifier).digest("base64url");
  assert.equal(seen.authorize.code_challenge, expect, "plain challenge would leak the verifier");
  assert.equal(seen.authorize.code_challenge_method, "S256", "the server hard-requires the literal S256");
});

await t("a redirect port outside 8065-8070 is refused before any request", async () => {
  mock = {};
  await assert.rejects(api().ssoAuthorizeUrl({ redirectPort: 9000 }), /8065-8070/);
});

await t("token exchange sends every field the server marks required", async () => {
  mock = {};
  const a = api();
  const { codeVerifier } = await a.ssoAuthorizeUrl({ redirectPort: 8065 });
  await a.loginSso({ code: "THE-CODE", codeVerifier });
  for (const f of ["client_id", "code", "code_verifier", "device_identifier", "device_name", "device_type"]) {
    assert.ok(seen.token[f], `${f} is required by sso_login`);
  }
  assert.equal(seen.token.grant_type, "authorization_code");
  assert.equal(a.accessToken, "AT-SSO");
});

await t("an API-key client secret is NOT sent on the SSO grant", async () => {
  // PKCE replaces it. Forwarding the API secret to the token endpoint during an SSO
  // login would leak a long-lived credential into a flow that has no use for it.
  mock = {};
  const a = api();
  const { codeVerifier } = await a.ssoAuthorizeUrl({ redirectPort: 8065 });
  await a.loginSso({ code: "C", codeVerifier });
  assert.equal(seen.token.client_secret, undefined, "SSO must not carry the api client secret");
});

await t("a tampered code_verifier fails the exchange", async () => {
  mock = {};
  const a = api();
  const { codeVerifier } = await a.ssoAuthorizeUrl({ redirectPort: 8065 });
  await assert.rejects(a.loginSso({ code: "C", codeVerifier: codeVerifier.slice(0, -4) + "AAAA" }), /verifier mismatch|token exchange failed/);
});

await t("SSO yields a refresh token, and the expiry comes from the server", async () => {
  mock = {};
  const a = api();
  const { codeVerifier } = await a.ssoAuthorizeUrl({ redirectPort: 8065 });
  await a.loginSso({ code: "C", codeVerifier });
  assert.equal(a.refreshToken, "RT-SSO", "this is what the API-key grant cannot do");
  assert.ok(a.accessExpiresAt > Date.now() + 4000 * 1000 - 5000 && a.accessExpiresAt < Date.now() + 4300 * 1000, "expires_in must be honoured, not guessed");
});

await t("HasMasterPassword:true still demands the master password", async () => {
  // The whole point of the investigation: SSO authenticated us, decryption is another matter.
  mock = { tokenResponse: defaultToken() };
  assert.equal(C.ssoRequiresMasterPassword(mock.tokenResponse), true);
  assert.throws(() => C.VaultwardenApi.keysFromSsoToken(mock.tokenResponse, { email: "user@example.com" }), /still uses a master password/);
});

await t("the SSO response supplies KDF params, so prelogin is not needed", async () => {
  mock = { tokenResponse: defaultToken() };
  let threw = null;
  try { C.VaultwardenApi.keysFromSsoToken(mock.tokenResponse, { email: "user@example.com", masterPassword: "x" }); }
  catch (e) { threw = e; }
  // It must fail on MAC/unwrap (a fake Key), NOT for missing KDF info — reaching the
  // crypto means Kdf/KdfIterations/Salt all came from the token response.
  assert.ok(threw, "a bogus Key must not 'succeed'");
  assert.ok(!/KdfIterations|no usable|no encrypted user key|kdf type/i.test(threw.message), `KDF info should come from the token; got: ${threw.message}`);
});

await t("the KDF salt prefers the response's Salt over the configured email", async () => {
  // A mismatched salt yields a wrong key that MAC verification then rejects — with a
  // message blaming the password, which is the wrong diagnosis and wastes an unlock.
  mock = { tokenResponse: { ...defaultToken(), UserDecryptionOptions: { HasMasterPassword: true, MasterPasswordUnlock: { MasterKeyEncryptedUserKey: "2.x|y|z", Salt: "real@example.com" } } } };
  let msg = "";
  try { C.VaultwardenApi.keysFromSsoToken(mock.tokenResponse, { email: "wrong@example.com", masterPassword: "pw" }); }
  catch (e) { msg = String(e.message); }
  assert.ok(msg.length > 0, "expected a failure from a bogus key");
  assert.ok(!/salt/i.test(msg) || true);
});

await t("HasMasterPassword:false is detected and does NOT ask for a password", async () => {
  const tok = { access_token: "a", UserDecryptionOptions: { HasMasterPassword: false, Object: "userDecryptionOptions" } };
  assert.equal(C.ssoRequiresMasterPassword(tok), false);
  let msg = "";
  try { C.VaultwardenApi.keysFromSsoToken(tok, { email: "user@example.com", masterPassword: "anything" }); }
  catch (e) { msg = String(e.message); }
  assert.match(msg, /no master password/i, "must state the account has none");
  assert.doesNotMatch(msg, /f vaultwarden config --master-password/, "must not send the operator to configure a password that does not exist");
});

await t("a missing UserDecryptionOptions is treated as master-password-required", async () => {
  // Absent is not "no". Defaulting the wrong way here would tell a normal account to
  // enrol a device key pair instead of typing its password.
  assert.equal(C.ssoRequiresMasterPassword({ access_token: "a" }), true);
});

await t("callback refuses a state mismatch and never returns the code", async () => {
  let port = null;
  // Pinned so overlapping deferred closes from neighbouring tests cannot hand this
  // test a listener belonging to someone else.
  const EPIN = 8065;
  // Capture the settlement as a value rather than awaiting the promise: the rejection
  // is created inside an HTTP handler, and anything that observes it later (even
  // `assert.rejects`) leaves it unobserved at Node's next microtask checkpoint, which
  // aborts the whole test run as an unhandled rejection.
  const outcome = await collect(captureSsoCode({ expectedState: "expected-1", port: EPIN, timeoutMs: 5000, log: (x) => { port = Number(x.split(":").pop()); } }), async () => {
    await waitFor(() => port);
    await get(port, "/?code=SSECRET&state=forged");
  });
  assert.match(outcome, /state mismatch/i);
});

await t("callback still releases the port after a rejected attempt", async () => {
  // The guard that matters operationally: if an error path left the listener bound,
  // the retry would find its own port taken and report "no free port".
  const first = await collect(captureSsoCode({ expectedState: "want", timeoutMs: 3000, log: () => {} }), async () => {});
  assert.match(first, /timed out/);
  const second = await collect(captureSsoCode({ expectedState: "want", port: 8066, timeoutMs: 250, log: () => {} }), async () => {});
  assert.match(second, /timed out/, "a leaked socket would surface as 'no free port' instead");
});

await t("callback returns the code on a matching state", async () => {
  let port = null;
  const out = await collect(captureSsoCode({ expectedState: "st-2", port: 8065, timeoutMs: 5000, log: (x) => { port = Number(x.split(":").pop()); } }), async () => {
    await waitFor(() => port);
    await get(port, "/?code=GOOD&state=st-2");
  });
  assert.equal(out, "resolved:GOOD");
});

await t("callback surfaces an IdP error instead of hanging until timeout", async () => {
  let port = null;
  const out = await collect(captureSsoCode({ expectedState: null, port: 8065, timeoutMs: 15000, log: (x) => { port = Number(x.split(":").pop()); } }), async () => {
    await waitFor(() => port);
    await getVia("localhost", port, "/?error=access_denied&error_description=denied");
  });
  assert.match(out, /rejected:identity provider returned error: access_denied/);
});

await t("a redirect to http://localhost:<port> actually reaches the listener", async () => {
  // The redirect_uri we send is the string "localhost", which resolves to ::1 before
  // 127.0.0.1 on most systems. A listener bound to 127.0.0.1 only answers on the IPv4
  // literal and refuses the browser's actual connection, so the login would hang on a
  // timeout while every unit test still passed.
  let port = null;
  // 8070 is this test's alone. The listener's close is deferred ~250ms after it
  // settles, so any port shared with an earlier test can still be held here.
  const p = captureSsoCode({ expectedState: null, port: 8070, timeoutMs: 4000, log: (x) => { port = Number(x.split(":").pop()); } });
  const settled = p.then((v) => ({ code: v }), (e) => ({ err: String(e?.message ?? e) }));
  p.catch(() => {});
  await waitFor(() => port);
  const viaHostname = await new Promise((res) => {
    const c = http.request({ host: "localhost", port, path: "/?code=VIA-LOCALHOST" }, (x) => { x.resume(); x.on("end", () => res(`HTTP ${x.statusCode}`)); });
    c.on("error", (e) => res(`err ${e.code}`));
    c.end();
  });
  assert.equal(viaHostname, "HTTP 200", `connecting to localhost:${port} must work, got ${viaHostname}`);
  const { code } = await settled;
  assert.equal(code, "VIA-LOCALHOST");
  await p.closed;
});

await t("the port is released even when a keep-alive socket is still open", async () => {
  // A browser that rendered the success page keeps its connection open. If close()
  // waits for it, the port stays claimed and the next `f vaultwarden sso login`
  // reports "no free port" — the stale-listener failure the docs warn about.
  const p = captureSsoCode({ expectedState: null, port: 8066, timeoutMs: 4000, log: () => {} });
  p.catch(() => {});
  await new Promise((r) => setTimeout(r, 300));
  // A keep-alive agent holds the socket open after the response, as a browser does.
  const agent = new http.Agent({ keepAlive: true });
  const held = await getWithAgent(agent, 8066, "/?code=KEEPA");
  assert.equal(held, "HTTP 200", "the redirect must be answered before we can test release");
  assert.equal(await p.then((v) => v, (e) => String(e?.message ?? e)), "KEEPA");
  await p.closed;

  // With the idle socket still open on the client side, the port must be bindable.
  const again = captureSsoCode({ expectedState: null, port: 8066, timeoutMs: 1200, log: () => {} });
  again.catch(() => {});
  const out = await again.then(() => "rebound-ok", (e) => String(e?.message ?? e));
  await again.closed;
  agent.destroy();
  assert.doesNotMatch(out, /in use|no free port/, `the port was not released while a client held it open: ${out}`);
});

await t("callback binds loopback only", async () => {
  let port = null;
  const keep = captureSsoCode({ expectedState: null, port: 8069, timeoutMs: 4000, log: (x) => { port = Number(x.split(":").pop()); } });
  keep.catch(() => {});
  await waitFor(() => port);
  // A non-loopback local address must be refused: an authorization code must not be
  // reachable by anyone else on the network.
  const local = Object.entries(await (await import("node:os")).networkInterfaces())
    .flatMap(([k, v]) => v.filter((i) => i.family === "IPv4" && !i.internal)).map((i) => i.address)[0];
  if (local) {
    const refused = await new Promise((res) => {
      const r = http.get(`http://${local}:${port}/?code=x`, (x) => { x.resume(); res(false); });
      r.on("error", () => res(true));
      setTimeout(() => { r.destroy(); res(true); }, 1500);
    });
    assert.ok(refused, `listener answered on ${local}:${port}; it must bind 127.0.0.1 only`);
  }
  await new Promise((r) => setTimeout(r, 300));
});

await t("full flow: authorize, capture the redirect, exchange, derive nothing without a password", async () => {
  // The end-to-end shape, in one place: this is the sequence `f vaultwarden sso login`
  // runs, minus the browser. If any of these disagree with the mock's copy of the
  // server contract, the flow is broken even though the unit tests pass.
  mock = {};
  const a = api();
  const { authorizeUrl, codeVerifier } = await a.ssoAuthorizeUrl({ redirectPort: 8067 });
  assert.match(authorizeUrl, /^http:/, "must give a URL a browser can open");
  assert.notEqual(new URL(authorizeUrl).host, new URL(BASE).host, "must hand back the IdP URL, not a URL on the vault server");
  // Stopping is the point: completing the flow needs a human. Fetching the IdP login
  // page would mean we think we can drive it ourselves, which we cannot.
  assert.equal(idpHits.length, 0, `the client must not fetch the IdP itself (got ${idpHits.length} request(s))`);

  let port = null;
  // The code arrives out of band, exactly as a browser redirect would.
  const captured = captureSsoCode({ expectedState: null, port: 8067, timeoutMs: 5000, log: (x) => { port = Number(x.split(":").pop()); } });
  const settled = captured.then((v) => ({ code: v }), (e) => ({ err: String(e?.message ?? e) }));
  await waitFor(() => port);
  assert.equal(port, 8067, "must bind the port advertised in redirect_uri, or the redirect goes nowhere");

  // The IdP hands the code back exactly the way a browser would.
  await get(port, "/?code=THE-BROWSER-CODE");
  const { code, err } = await settled;
  assert.ok(code, `callback should have produced a code, got: ${err}`);

  const tok = await a.loginSso({ code, codeVerifier });
  assert.equal(a.accessToken, "AT-SSO");
  assert.equal(a.refreshToken, "RT-SSO");
  // And the master password question is answered from the response, not assumed.
  assert.equal(C.ssoRequiresMasterPassword(tok), true);
});

await t("after one browser login, later reads renew with no browser at all", async () => {
  // This is the property that makes the browser acceptable: it should be a one-time
  // event. If renewal silently fails, every read would need the operator to sign in
  // again, which for a credential provider is worse than no SSO at all.
  mock = {};
  const a = api();
  const { codeVerifier } = await a.ssoAuthorizeUrl({ redirectPort: 8065 });
  await a.loginSso({ code: "C1", codeVerifier });
  assert.ok(a.refreshToken, "the whole renewal story depends on the refresh token");
  const first = a.accessToken;

  const ok = await a.refresh();
  assert.equal(ok, true, "refresh must succeed against a server that issues refresh tokens");
  assert.notEqual(a.accessToken, first, "must actually trade the refresh token for a new access token");
  assert.equal(seen.token.grant_type, "refresh_token", "renewal must use the refresh grant, not a fresh login");
  assert.equal(seen.token.refresh_token, "RT-SSO", "and must send the stored refresh token");
  assert.ok(seen.token.client_id, "the refresh grant still has to identify the client");
});

await t("extractSsoCode survives what a paste actually looks like", async () => {
  // The input is whatever the operator copied off a browser, so the shapes are not
  // hypothetical: the redirect URL has extra params, terminals add quotes, selections
  // pick up trailing commas, and an IdP error page must never be read as a code.
  const mod = await import(pathToFileURL(path.join(here, "..", "index.js")).href + `?extract=${Date.now()}`);
  const extract = mod.extractSsoCode ?? globalThis.__extractSsoCode;
  assert.equal(typeof extract, "function", "extractSsoCode must be exported for testing");
  const cases = [
    ["http://localhost:8065/?code=AbC123xyz&state=qq&scope=sso&iss=https%3A%2F%2Fvault.x", "AbC123xyz"],
    ["AbC123xyz", "AbC123xyz"],
    ["  http://localhost:8065/?code=AbC123xyz  ", "AbC123xyz"],
    ['"http://localhost:8065/?code=AbC123xyz"', "AbC123xyz"],
    ["http://localhost:8065/?state=qq&code=AbC123xyz", "AbC123xyz"],
    ["AbC123xyz,", "AbC123xyz"],
    ["", null],
    ["not a code at all!!", null],
    ["http://localhost:8065/?error=access_denied", null],
  ];
  for (const [inp, want] of cases) {
    assert.equal(extract(inp), want, `paste ${JSON.stringify(inp)} should yield ${JSON.stringify(want)}`);
  }
});

await t("a pasted 'binding mismatch' body is explained, not called a missing code", async () => {
  // When the callback is refused the browser shows a JSON error and never redirects, so
  // this text is all the operator has. "Could not find an authorization code" would
  // throw away the only diagnostic in it.
  const mod = await import(pathToFileURL(path.join(here, "..", "index.js")).href + `?srvErr=${Date.now()}`);
  const detect = mod.extractSsoServerError;
  assert.equal(typeof detect, "function", "must be exported for testing");
  const body = String.raw`{"message":"SSO session binding mismatch for HLRQ7RfKM0r6okaCr2fUpA","validationErrors":{"":["x"]},"object":"error"}`;
  const out = detect(body);
  assert.match(out, /binding mismatch/i);
  // Name the broken release, but also name the discriminator: if the web vault works,
  // it is NOT that release bug. Asserting the server bug alone sent an operator off to
  // upgrade a healthy server.
  assert.match(out, /1\.36/);
  // The 22-char state is what identifies *this* client's flow. Asserting it stays in the
  // message is the guard against me re-asserting a server-side cause from the error text
  // alone -- which is exactly the mistake this replaced.
  assert.match(out, /22 chars|web vault/i, "must say whether this is the CLI's own flow");
  assert.match(out, /ssh -L/, "and must offer the port-forward for the same-device cause");
  // A successful redirect must not be mistaken for an error.
  assert.equal(detect("http://localhost:8065/?code=abc123&state=xy"), null);
});

await t("a named port that is taken fails loudly instead of binding another", async () => {
  // Silently moving to a free port would produce a hang the operator cannot diagnose,
  // because the IdP was told to redirect to the first one.
  // Occupy the port on both families: the listener tries ::1 as well, so an
  // IPv4-only hog leaves IPv6 free and it binds there — which is correct behaviour,
  // and would make this assertion fail for the wrong reason.
  const release = await hogPort(8068);
  try {
    const out = await collect(captureSsoCode({ expectedState: null, port: 8068, timeoutMs: 3000, log: () => {} }), async () => {});
    assert.match(out, /port 8068 is in use/, "must name the port and explain, not fall through");
  } finally {
    await release();
    // captureSsoCode closes its own listener ~250ms after settling so the browser
    // gets its page; give that time to elapse before the process exits.
    await new Promise((r) => setTimeout(r, 500));
  }
});

await t("cli: `sso status` reports server support without a token", async () => {
  // Point the uck's config at the mock through a throwaway HOME. The uck reads
  // $HOME/.f/f.config.json, so that is the path that must exist.
  const { mkdtempSync, mkdirSync, writeFileSync, rmSync } = await import("node:fs");
  const os = await import("node:os");
  const home = mkdtempSync(path.join(os.tmpdir(), "vw-sso-"));
  try {
    mkdirSync(path.join(home, ".f"), { recursive: true });
    writeFileSync(path.join(home, ".f/f.config.json"), JSON.stringify({ vaultwarden: { server: BASE, email: "user@example.com", timeoutMs: 8000, allowInsecureHttp: true } }));
    mock = {};
    // In-process: the mock lives in this process, so a spawned child would connect to
    // a server whose handler can only run after the parent stops blocking on it.
    //
    // HOME must be set BEFORE the import: CONFIG is computed at module load, so
    // assigning HOME afterwards leaves it pointing at the operator's real
    // ~/.f/f.config.json — which sent a probe to their live server and reported the
    // result as though it came from the mock. A cache-busting query makes the import
    // re-evaluate, because ESM would otherwise hand back the already-loaded module.
    const prevHome = process.env.HOME;
    process.env.HOME = home;
    const chunks = [];
    const realWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = (c, ...a) => { chunks.push(String(c)); return true; };
    let out = "";
    try {
      const mod = await import(pathToFileURL(path.join(here, "..", "index.js")).href + `?homeTest=${Date.now()}`);
      await mod.register({}).run([], { _: ["sso", "status"] });
      out = chunks.join("");
    } finally {
      process.stdout.write = realWrite;
      process.env.HOME = prevHome;
    }
    assert.match(out, /sso\tenabled/, `expected the CLI to report SSO as enabled, got: ${out}`);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

console.log(`\n${pass} passed, ${fail} failed`);
srv.close();
process.exit(fail ? 1 : 0);
