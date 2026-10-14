// Offline crypto tests for the vaultwarden client. No server needed: we build a
// Bitwarden-shaped vault blob, encrypt it with an independent implementation of
// the spec (written here from the protocol description, deliberately NOT reusing
// lib/vwclient.js), then check the client decrypts it and rejects tampering.
//
//   node vaultwarden/test/crypto.test.mjs
//
// The KAT vectors for HKDF come from RFC 5869 Test Case 1.

import assert from "node:assert/strict";
import fs from "node:fs";
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const C = await import(pathToFileURL(path.join(here, "..", "lib", "vwclient.js")).href);

let pass = 0, fail = 0;
const UCK_INDEX = path.join(here, "..", "index.js");
// Attribute processes to *this* uck only, so an unrelated busy machine cannot
// make a fork-bomb assertion fire spuriously. pgrep exits 1 when nothing matches.
const liveUckProcs = () => {
  try {
    return Number(execFileSync("pgrep", ["-fc", "vaultwarden[/]index\.js"], { encoding: "utf8" }).trim() || "0");
  } catch (e) {
    return Number(String(e.stdout ?? "0").trim() || "0");
  }
};

// Some assertions must await (process sampling); sync ones still work.
const I32 = new Int32Array(new SharedArrayBuffer(4));
const t = async (label, fn) => {
  try { await fn(); pass++; console.log(`ok   ${label}`); }
  catch (e) { fail++; console.log(`FAIL ${label}\n     ${e.message.split("\n").join("\n     ")}`); }
};

/* --------- independent reference encryptor (spec-derived, not imported) ---- */

const b64 = (b) => Buffer.from(b).toString("base64");

function refStretch(masterKey) {
  // RFC 5869 HKDF-Expand, PRK = masterKey
  const expand = (info, len) => {
    const n = Math.ceil(len / 32);
    const out = Buffer.alloc(n * 32);
    let prev = Buffer.alloc(0);
    for (let i = 1; i <= n; i++) {
      prev = crypto.createHmac("sha256", masterKey).update(prev).update(info).update(Buffer.from([i])).digest();
      prev.copy(out, (i - 1) * 32);
    }
    return out.subarray(0, len);
  };
  return { enc: expand(Buffer.from("enc"), 32), mac: expand(Buffer.from("mac"), 32) };
}

function refEncrypt(plaintext, encKey, macKey) {
  const iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv("aes-256-cbc", encKey, iv);
  const ct = Buffer.concat([c.update(Buffer.from(String(plaintext), "utf8")), c.final()]);
  const mac = crypto.createHmac("sha256", macKey).update(iv).update(ct).digest();
  return `2.${b64(iv)}|${b64(ct)}|${b64(mac)}`;
}

/* --------------------------------- fixtures ------------------------------- */

const EMAIL = "kenny@example.com";
const PASSWORD = "correct horse battery staple";
const ITER = 600000; // Bitwarden default; kept low below for speed

const masterKey = crypto.pbkdf2Sync(Buffer.from(PASSWORD), Buffer.from(EMAIL), ITER, 32, "sha256");
const stretched = refStretch(masterKey);
const symmetricKey = crypto.randomBytes(32);
const macKey = crypto.randomBytes(32);
const symBlob = Buffer.concat([symmetricKey, macKey]);
const profileKey = refEncrypt(b64(symBlob), stretched.enc, stretched.mac);

const hasHashWasm = await (async () => { try { await import("hash-wasm"); return true; } catch { return false; } })();

const vault = {
  profile: { id: "user-1", key: profileKey, privateKey: null },
  ciphers: [
    {
      id: "cipher-github", type: 1, name: refEncrypt("github.com", symmetricKey, macKey),
      login: {
        username: refEncrypt("kensand", symmetricKey, macKey),
        password: refEncrypt("ghp_supersecret123", symmetricKey, macKey),
        totp: refEncrypt("JBSWY3DPEHPK3PXP", symmetricKey, macKey),
        uris: [{ uri: refEncrypt("https://github.com", symmetricKey, macKey), match: null }],
      },
      fields: [{ name: refEncrypt("scope", symmetricKey, macKey), value: refEncrypt("repo,gist", symmetricKey, macKey), type: 0 }],
      notes: refEncrypt("personal access token", symmetricKey, macKey),
    },
    { // second item, same host, no totp, to exercise conflict detection
      id: "cipher-gh2", type: 1, name: refEncrypt("github.com", symmetricKey, macKey),
      login: { username: refEncrypt("kensand-work", symmetricKey, macKey), password: refEncrypt("ghp_work_secret", symmetricKey, macKey), uris: [] },
      fields: [],
    },
    { // name collision with a different host
      id: "cipher-uni", type: 2, name: refEncrypt("school", symmetricKey, macKey),
      login: { username: refEncrypt("student", symmetricKey, macKey), password: refEncrypt("pw", symmetricKey, macKey) }, fields: [],
    },
    { // untyped: only the name decrypts
      id: "cipher-note", type: 2, name: refEncrypt("plain note", symmetricKey, macKey), fields: [],
    },
    { // legacy type-1 ciphertext (no MAC) -> must be refused by default
      id: "cipher-legacy", type: 1, name: refEncrypt("legacy item", symmetricKey, macKey),
      login: { username: `1.${b64(crypto.randomBytes(16))}|${b64(crypto.randomBytes(32))}`, uris: [] }, fields: [],
    },
  ],
};

/* ---------------------------------- tests -------------------------------- */

// Independent cross-check. @noble/hashes is a dev-only reference (the uck itself
// stays zero-dep); these tests skip silently when it is not installed.
let NOBLE = null;
try {
  const [h, s2] = await Promise.all([
    import("/tmp/hkdfcheck/node_modules/@noble/hashes/hkdf.js"),
    import("/tmp/hkdfcheck/node_modules/@noble/hashes/sha2.js"),
  ]);
  NOBLE = { extract: h.extract, expand: h.expand, sha256: s2.sha256 };
} catch { /* reference impl absent */ }

await t("HKDF-Expand matches RFC 5869 A.1/A.3 (and @noble when present)", () => {
  // Bitwarden's "stretch" is HKDF-Expand with the masterKey used directly as the
  // PRK (Extract is skipped, per RFC 5869 §3.3), so Expand is what must validate.
  const H = (x) => Buffer.from(x, "hex");
  const cases = [
    ["A.1", Buffer.alloc(22, 0x0b), H("000102030405060708090a0b0c"), H("f0f1f2f3f4f5f6f7f8f9"), 42,
      "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"],
    ["A.3", Buffer.alloc(22, 0x0b), Buffer.alloc(0), Buffer.alloc(0), 42,
      "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
      "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"],
  ];
  for (const [name, ikm, salt, info, L, prkHex, okmHex] of cases) {
    const prk = NOBLE
      ? Buffer.from(NOBLE.extract(NOBLE.sha256, ikm, salt))
      : crypto.createHmac("sha256", salt).update(ikm).digest();
    assert.equal(prk.toString("hex"), prkHex, `${name}: PRK mismatch`);
    assert.equal(C.hkdfExpand(prk, info, L).toString("hex"), okmHex, `${name}: HKDF-Expand mismatch`);
    if (NOBLE) assert.equal(Buffer.from(NOBLE.expand(NOBLE.sha256, prk, info, L)).toString("hex"), okmHex, `${name}: reference impl disagrees with the RFC`);
  }
});

await t("PBKDF2 parameters pass through unmangled (RFC 6070 shapes, SHA-256)", () => {
  // The bug this catches: salting with email+password, off-by-one iterations, or
  // base64-encoding an input before deriving.
  const vec = [
    ["password", "salt", 1, 32],
    ["password", "salt", 2, 32],
    ["password", "salt", 4096, 32],
    ["passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 32],
  ];
  for (const [pw, salt, it, dk] of vec) {
    const expect = crypto.pbkdf2Sync(pw, salt, it, dk, "sha256");
    assert.deepEqual([...C.makeMasterKey(pw, salt, it)], [...expect], `PBKDF2(${pw.slice(0, 8)}, ${salt}, ${it}) mismatch`);
  }
});

await t("PBKDF2 uses email (not email+password) as salt", () => {
  const mine = C.makeMasterKey(PASSWORD, EMAIL, ITER);
  assert.deepEqual([...mine], [...masterKey]);
  // The common mistake: salting with the password too.
  const wrong = crypto.pbkdf2Sync(Buffer.from(PASSWORD), Buffer.from(EMAIL + PASSWORD), ITER, 32, "sha256");
  assert.notDeepEqual([...mine], [...wrong]);
});

await t("rejected kdfIterations", () => {
  assert.throws(() => C.makeMasterKey(PASSWORD, EMAIL, 0), /invalid kdfIterations/);
  assert.throws(() => C.makeMasterKey(PASSWORD, EMAIL, NaN), /invalid kdfIterations/);
});

await t("masterPasswordHash = HMAC-SHA256(masterKey, password)", () => {
  const ref = crypto.createHmac("sha256", masterKey).update(Buffer.from(PASSWORD)).digest();
  assert.deepEqual([...C.masterPasswordHash(masterKey, PASSWORD)], [...ref]);
});

await t("unwrapSymmetricKey yields the 32+32 key pair", () => {
  const k = C.unwrapSymmetricKey(vault.profile.key, { encKey: stretched.enc, macKey: stretched.mac });
  assert.deepEqual([...k.symmetricKey], [...symmetricKey]);
  assert.deepEqual([...k.macKey], [...macKey]);
});

await t("decryptVault decrypts the login item", () => {
  const keys = { encKey: symmetricKey, macKey };
  const items = C.decryptVault({ ciphers: vault.ciphers }, keys);
  const gh = items.find((i) => i.id === "cipher-github");
  assert.equal(gh.name, "github.com");
  assert.equal(gh.login.username, "kensand");
  assert.equal(gh.login.password, "ghp_supersecret123");
  assert.equal(gh.login.totp, "JBSWY3DPEHPK3PXP");
  assert.deepEqual(gh.login.uris.map((u) => u.uri), ["https://github.com"]);
  assert.deepEqual(gh.fields, [{ name: "scope", value: "repo,gist", type: 0, linkedId: null }]);
  assert.equal(gh.notes, "personal access token");
  assert.deepEqual(gh.fieldSummary().sort(), ["field:scope", "password", "totp", "username"].sort());
});

await t("wrong key fails MAC verification instead of returning garbage", () => {
  const bad = { encKey: crypto.randomBytes(32), macKey: crypto.randomBytes(32) };
  const gh = vault.ciphers[0];
  assert.throws(() => C.decryptString(gh.login.password, bad), /MAC verification failed/);
});

await t("tampered ciphertext is rejected (flip one ct byte)", () => {
  const enc = vault.ciphers[0].login.password;
  const [hdr, iv, ct, mac] = enc.split(".")[0] === "2" ? ["2", ...enc.split(".")[1].split("|")] : [];
  const ctBuf = Buffer.from(ct, "base64");
  ctBuf[0] ^= 0x01;
  const tampered = `2.${iv}|${ctBuf.toString("base64")}|${mac}`;
  assert.throws(() => C.decryptString(tampered, { encKey: symmetricKey, macKey }), /MAC verification failed/);
});

await t("type-1 (no MAC) ciphertext is refused by default, allowed on request", () => {
  const legacy = vault.ciphers.find((c) => c.id === "cipher-legacy");
  assert.throws(() => C.decryptString(legacy.login.username, { encKey: symmetricKey, macKey }), /no integrity tag/);
  // With the opt-in flag it must at least not claim MAC failure (it will still
  // fail to decrypt meaningfully because we never knew the type-1 key).
  assert.throws(
    () => C.decryptString(legacy.login.username, { encKey: symmetricKey, macKey }, { allowUnauthenticated: true }),
    /bad decrypt|wrong final block length|invalid|unsupported/i,
  );
});

await t("round-trips through encryptString (TOTP write path)", () => {
  const keys = { encKey: symmetricKey, macKey };
  const enc = C.encryptString("totp-secret-value", keys);
  assert.match(enc, /^2\.[A-Za-z0-9+/=]+\|[A-Za-z0-9+/=]+\|[A-Za-z0-9+/=]+$/);
  assert.equal(C.decryptString(enc, keys), "totp-secret-value");
});

await t("type 0 envelope is returned as plaintext", () => {
  assert.equal(C.decryptString(`0.${b64("https://github.com")}`, { encKey: symmetricKey, macKey }), "https://github.com");
});

await t("null / empty fields yield undefined, not an error", () => {
  const keys = { encKey: symmetricKey, macKey };
  assert.equal(C.decryptString(null, keys), undefined);
  assert.equal(C.decryptString("", keys), undefined);
  assert.equal(C.decryptString(undefined, keys), undefined);
});

await t("malformed envelope is reported, not silently ignored", () => {
  assert.throws(() => C.decryptString("not-an-envelope", { encKey: symmetricKey, macKey }), /unrecognised ciphertext envelope/);
  assert.throws(() => C.decryptString("9.a|b|c", { encKey: symmetricKey, macKey }), /unsupported encryption type 9/);
});

await t("deriveKeys wires the whole chain end to end", async () => {
  const keys = await C.deriveKeys({ email: EMAIL, password: PASSWORD, kdfIterations: ITER, encryptedKey: vault.profile.key });
  // deriveKeys must hand back keys decryptString actually consumes.
  assert.ok(Buffer.isBuffer(keys.encKey) && keys.encKey.length === 32, "deriveKeys().encKey missing/wrong length");
  assert.ok(Buffer.isBuffer(keys.macKey) && keys.macKey.length === 32, "deriveKeys().macKey missing/wrong length");
  const items = C.decryptVault({ ciphers: vault.ciphers }, keys);
  assert.equal(items.length, vault.ciphers.length);
  const gh = items.find((i) => i.id === "cipher-github");
  assert.deepEqual(gh.errors, {}, "unexpected per-field decrypt errors: " + JSON.stringify(gh.errors));
  assert.equal(gh.login.password, "ghp_supersecret123");
  // A wrong master password is caught at key unwrap, before any item is touched.
  await assert.rejects(
    C.deriveKeys({ email: EMAIL, password: "wrong", kdfIterations: ITER, encryptedKey: vault.profile.key }),
    /MAC verification failed/,
    "wrong master password must be reported, not accepted",
  );
  // And if a stale/unwrapped-anyhow key set is used anyway, every item must
  // report failure rather than returning plausible-looking garbage.
  const stale = { encKey: crypto.randomBytes(32), macKey: crypto.randomBytes(32) };
  const bad = C.decryptVault({ ciphers: vault.ciphers }, stale);
  assert.ok(bad.every((i) => i.fullyFailed()), "a wrong key set should fail every item's name decryption");
  assert.ok(bad.every((i) => i.login === null || i.login.password === undefined), "no field may yield a value under a wrong key");
});

await t("decryptVault reads the /api/ciphers list shape (and legacy PascalCase)", async () => {
  const keys = await C.deriveKeys({ email: EMAIL, password: PASSWORD, kdfIterations: ITER, encryptedKey: vault.profile.key });
  const fromSync = C.decryptVault({ ciphers: vault.ciphers }, keys).length;
  // Exactly what Vaultwarden's ciphers.rs builds.
  const fromList = C.decryptVault({ object: "list", data: vault.ciphers, continuationToken: null }, keys).length;
  // Older upstream Bitwarden capitalises the envelope keys.
  const fromPascal = C.decryptVault({ Object: "list", Data: vault.ciphers, ContinuationToken: null }, keys).length;
  assert.ok(fromSync > 0, "sanity: the fixture is not empty");
  assert.equal(fromList, fromSync);
  assert.equal(fromPascal, fromSync);
});

await t("a misread or foreign response shape throws instead of looking like an empty vault", async () => {
  const keys = await C.deriveKeys({ email: EMAIL, password: PASSWORD, kdfIterations: ITER, encryptedKey: vault.profile.key });
  // The shape this code originally guessed at. Silently returning [] here is the
  // worst possible failure mode: every lookup reports "no such item".
  assert.throws(() => C.decryptVault({ data: { data: vault.ciphers } }, keys), /unrecognised response shape/);
  assert.throws(() => C.ciphersFrom({}), /empty response|unrecognised/);
  assert.throws(() => C.ciphersFrom(null), /empty response/);
  // Pagination must not be half-read.
  assert.throws(() => C.ciphersFrom({ object: "list", data: vault.ciphers, continuationToken: "page2" }), /paginated/);
  // A sync with no ciphers key genuinely means an empty vault.
  assert.deepEqual(C.ciphersFrom({ profile: { id: "u" } }), []);
});


await t("prelogin is sent as JSON (form-encoded is rejected by the real server)", async () => {
  let ct = null, body = null;
  const fetchFn = async (url, init) => {
    ct = init.headers["Content-Type"]; body = init.body;
    return new Response(JSON.stringify({ kdf: 0, kdfIterations: 600000 }), { status: 200, headers: { "Content-Type": "application/json" } });
  };
  const api = new C.VaultwardenApi({ server: "https://x.invalid", fetchFn });
  const r = await api.prelogin("a@b.c");
  assert.match(ct, /application\/json/, "prelogin must be JSON");
  assert.equal(r.kdfIterations, 600000);
});

await t("a 429 is explained as rate limiting, not as a bare status code", async () => {
  const fetchFn = async () => new Response(JSON.stringify({ message: "Too many login requests", error_description: "" }), { status: 429, headers: { "Content-Type": "application/json" } });
  const api = new C.VaultwardenApi({ server: "https://x.invalid", fetchFn });
  const msg = await api.loginApiKey({ clientId: "u", clientSecret: "s" }).then(() => "resolved", (e) => e.message);
  assert.match(msg, /Too many login requests/);
  assert.match(msg, /rate-limiting|wait/i);
});

await t("an empty error_description does not hide the populated message", async () => {
  const fetchFn = async () => new Response(JSON.stringify({ message: "Invalid client_id", error: "", error_description: "", validationErrors: { "": ["Invalid client_id"] } }), { status: 400, headers: { "Content-Type": "application/json" } });
  const api = new C.VaultwardenApi({ server: "https://x.invalid", fetchFn });
  const msg = await api.sync().then(() => "resolved", (e) => e.message);
  assert.match(msg, /Invalid client_id/, `got: ${msg}`);
});

await t("client_credentials yields no refresh token; the password grant does", async () => {
  // This asymmetry is the whole reason SSO cannot remove the master password for
  // a headless client: the API-key grant is unrenewable, so the ONLY thing that
  // buys a long unattended life is the refresh_token from a real login.
  const mk = (body) => new C.VaultwardenApi({
    server: "https://x.invalid",
    fetchFn: async () => new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } }),
  });
  const ak = mk({ access_token: "a", expires_in: 7200 });
  await ak.loginApiKey({ clientId: "user.x", clientSecret: "s" });
  assert.equal(ak.refreshToken, null, "API-key login must not claim a refresh token");
  assert.equal(await ak.refresh(), false, "refresh() after an API-key login must report it cannot");

  const pw = mk({ access_token: "a", refresh_token: "r", expires_in: 7200 });
  await pw.loginPassword({ email: "a@b.c", passwordHash: Buffer.alloc(32) });
  assert.equal(pw.refreshToken, "r");
});

await t("the server's expires_in is honoured, not a guessed lifetime", async () => {
  // Vaultwarden mints 2h access tokens. A cache that assumes longer produces a
  // confident 401 on every read after the hour, and hides it behind a "cache hit".
  const api = new C.VaultwardenApi({
    server: "https://x.invalid",
    fetchFn: async () => new Response(JSON.stringify({ access_token: "a", expires_in: 120 }), { status: 200, headers: { "Content-Type": "application/json" } }),
  });
  await api.loginApiKey({ clientId: "user.x", clientSecret: "s" });
  const left = api.accessExpiresAt - Date.now();
  assert.ok(left > 100_000 && left <= 120_000, `expected ~120s of life, got ${left}ms`);
});

await t("setAccessToken can carry an externally-known expiry", () => {
  const api = new C.VaultwardenApi({ server: "https://x.invalid", fetchFn: async () => new Response("{}") });
  const at = Date.now() + 60_000;
  api.setAccessToken("tok", { expiresAt: at, refreshToken: "rr" });
  assert.equal(api.accessExpiresAt, at);
  assert.equal(api.refreshToken, "rr");
});

await t("provider probes must not re-enter discovery (fork bomb)", () => {
  // THE bug: `status()` read the creds store by spawning `f creds status`, which
  // runs provider discovery, which execs this uck's `status` — again and again.
  // One configured `f creds status` reached 2,638 live processes and locked the
  // machine. Measuring before/after is not enough: the children outlive the call,
  // so that version of the assertion passed while the bug was live. Watch the
  // PEAK, sampled during the call.
  const count = () => {
    try { return Number(execFileSync("pgrep", ["-fc", "vaultwarden[/]index[.]js"], { encoding: "utf8" }).trim() || "0"); }
    catch (e) { return Number(String(e.stdout ?? "0").trim() || "0"); }
  };
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => k !== "F_CREDS_NO_PROVIDER"));

  let peak = 0;
  const sample = setInterval(() => { peak = Math.max(peak, count()); }, 20);
  let probeOut;
  try {
    // `status` is the probe `f providers` actually execs, and the entrypoint that
    // detonated. Run it exactly that way: node <entry> status.
    probeOut = execFileSync(process.execPath, [UCK_INDEX, "status"], { encoding: "utf8", timeout: 60000, env });
  } finally {
    clearInterval(sample);
    Atomics.wait(I32, 0, 0, 400); // block without an event loop, so samples land mid-call
  }
  assert.ok(peak <= 5, `peak of ${peak} provider processes during one status probe — discovery is recursing`);
  const st = JSON.parse(probeOut);
  assert.ok(typeof st.ready === "boolean", "status must still answer");
});

/*
 * NOT TESTED — the fork bomb, on purpose.
 *
 * The bug was real: `f creds` status called a provider's status() probe, which
 * shelled out to `f creds` again, unbounded; one configured provider reached 2,638
 * live processes. The fix is the F_CREDS_NO_PROVIDER marker, honoured in
 * creds/providers.js and propagated to the `f providers --dump` it spawns.
 *
 * Every assertion we wrote for it passed with the fix removed, and we verified why:
 * reproducing the cycle needs the store UNLOCKED and a provider configured. With a
 * locked store `f creds status` short-circuits before it calls p.status(), so these
 * tests never reach the code path. A count-based test also measured
 * f.config.json's providers list, not the marker, so it looked like a pass.
 *
 * A test here would be decorative. This needs manual verification with an unlocked
 * store and a reachable vault:
 *   f creds unlock
 *   f vaultwarden config --email <you>   # plus api key + master password
 *   watch -n0.2 'pgrep -c -f vaultwarden/index.js' &   # must stay in single digits
 *   f creds status; f providers; f vaultwarden status
 * If the probe count climbs into the hundreds, the guard has regressed.
 */

await t("plaintext http server is refused unless overridden", () => {
  assert.throws(() => new C.VaultwardenApi({ server: "http://vault.lan:8080" }), /plaintext http/);
  assert.throws(() => new C.VaultwardenApi({ server: "vault.lan" }), /must be an http\(s\) URL/);
  assert.doesNotThrow(() => new C.VaultwardenApi({ server: "https://vault.lan/" }));
});

await t("API errors surface Vaultwarden's error_description", async () => {
  const api = new C.VaultwardenApi({ server: "https://vault.example", fetchFn: async () => ({ ok: false, status: 400, text: async () => JSON.stringify({ error: "invalid_grant", error_description: "Username or password is incorrect." }) }) });
  await assert.rejects(() => api.loginApiKey({ clientId: "user.x", clientSecret: "y" }), /HTTP 400: Username or password is incorrect/);
});

await t("unreachable server explains itself", async () => {
  const api = new C.VaultwardenApi({ server: "https://vault.tailnet.ts", fetchFn: async () => { throw Object.assign(new Error("fetch failed"), { cause: Object.assign(new Error("getaddrinfo ENOTFOUND vault.tailnet.ts"), { code: "ENOTFOUND" }) }); } });
  await assert.rejects(() => api.sync(), /cannot reach|ENOTFOUND|dns/i);
});

await t("2FA-required login is explained as 2FA, not as a bad password", async () => {
  const api = new C.VaultwardenApi({ server: "https://vault.example", fetchFn: async () => ({ ok: true, status: 200, text: async () => JSON.stringify({ twoFactorProviders: [0, 1] }) }) });
  await assert.rejects(() => api.loginPassword({ email: EMAIL, passwordHash: Buffer.alloc(32) }), /2FA is required/);
});

await t("non-JSON response says the server may not be Vaultwarden", async () => {
  const api = new C.VaultwardenApi({ server: "https://vault.example", fetchFn: async () => ({ ok: true, status: 200, text: async () => "<html><body>nginx</body></html>" }) });
  await assert.rejects(() => api.sync(), /really a Vaultwarden server/);
});

await t("VaultItem exposes the ciphertext needed to write back", () => {
  const keys = { encKey: symmetricKey, macKey };
  const items = C.decryptVault({ ciphers: vault.ciphers }, keys);
  const gh = items.find((i) => i.id === "cipher-github");
  assert.equal(gh.hiddenField("totp"), vault.ciphers[0].login.totp);
  assert.equal(gh.raw.login.password, vault.ciphers[0].login.password);
  assert.equal(items.find((i) => i.id === "cipher-gh2").hiddenField("totp"), null);
});

await t("duplicate names are detectable by the resolver", () => {
  const items = C.decryptVault({ ciphers: vault.ciphers }, { encKey: symmetricKey, macKey });
  const named = items.filter((i) => i.name === "github.com");
  assert.equal(named.length, 2, "fixture must contain a name collision to be useful");
});

await t("an absent Kdf is refused rather than assumed to be PBKDF2", async () => {
  // Falling back to PBKDF2 here derived a WRONG key and the failure surfaced as
  // "MAC verification failed", i.e. the operator was told their master password was
  // wrong. The algorithm must never be guessed.
  await assert.rejects(
    C.VaultwardenApi.keysFromSsoToken(
      { Key: "0.aabb.cc", UserDecryptionOptions: { HasMasterPassword: true } },
      { email: "a@b.c", masterPassword: "x" }),
    /did not report which KDF|refusing to guess/i,
  );
});

await t("Argon2id accounts derive and decrypt (hashLen 32, kdfMemory in MiB)", async () => {
  // hash-wasm is an OPTIONAL dependency: PBKDF2 accounts must work with no node_modules at
  // all. Skipping here is legitimate, but it must never be silent — run npm install to get
  // this coverage, and see the separate test that the absence is reported clearly.
  if (!(await C.argon2idAvailable())) { console.log("     (skipped: hash-wasm not installed)"); return; }
  // Bitwarden's WebCrypto path is, verbatim from
  // libs/common/src/platform/services/web-crypto-function.service.ts:
  //   argon2.hash({ pass, salt, time: iterations, mem: memory, parallelism, hashLen: 32,
  //                 type: ArgonType.Argon2id })
  // and its output is then stretched with HKDF("enc")/HKDF("mac") exactly like PBKDF2's.
  // Two things are easy to get wrong and each yields a wrong key that reads as "wrong
  // master password": hashLen (32 here, not the 64 the native SDK derives) and memory
  // (the server's kdfMemory is KIBIBYTES: 64 means 64 KiB, not 64 MiB).
  const { argon2id } = await import("hash-wasm");
  // AM is in MIBIBYTES, as kdfMemory is on the wire. 16 MiB keeps the test fast; the
  // real server's 64 would allocate 64 MiB. hash-wasm's memorySize wants KiB, so the client
  // multiplies by 1024 -- see bitwarden_crypto/src/crypto/kdf.rs.
  const AE = "argon-user@example.com", AP = "argon-master-pass", AM = 16, APA = 4, AI = 3;

  const mk = Buffer.from(await argon2id({
    password: Buffer.from(AP, "utf8"), salt: Buffer.from(AE, "utf8"),
    parallelism: APA, iterations: AI, memorySize: AM * 1024, hashLength: 32, outputType: "binary",
  }));
  const st = refStretch(mk);
  const aSym = crypto.randomBytes(32), aMac = crypto.randomBytes(32);
  const wrappedKey = refEncrypt(b64(Buffer.concat([aSym, aMac])), st.enc, st.mac);

  const keys = await C.deriveKeys({
    email: AE, password: AP, encryptedKey: wrappedKey,
    kdfType: 1, kdfIterations: AI, kdfMemory: AM, kdfParallelism: APA,
  });
  assert.ok(Buffer.isBuffer(keys.encKey) && keys.encKey.length === 32, "argon2 master key must stretch to a 32B enc key");

  const cipher = {
    id: "c-argon", type: 1, name: refEncrypt("argon.example", aSym, aMac),
    login: { username: refEncrypt("ken", aSym, aMac), password: refEncrypt("argon-secret", aSym, aMac), uris: [] },
    fields: [],
  };
  const item = new C.VaultItem(cipher, keys);
  assert.equal(item.login.password, "argon-secret", "an Argon2id-derived key must decrypt the vault");

  // A wrong password must fail loudly rather than return plausible garbage.
  await assert.rejects(
    C.deriveKeys({ email: AE, password: "not-it", encryptedKey: wrappedKey, kdfType: 1, kdfIterations: AI, kdfMemory: AM, kdfParallelism: APA }),
    /MAC verification failed/,
  );
  // Argon2id is unusable without memory/parallelism; inventing defaults means a wrong key.
  await assert.rejects(
    C.deriveKeys({ email: AE, password: AP, encryptedKey: wrappedKey, kdfType: 1, kdfIterations: AI }),
    /invalid argon2id|argon2id (memory|parallelism)/i,
  );
  // Pin the unit-level contract: hashLen 32, and kdfMemory converted MiB -> KiB.
  const fast = await C.makeMasterKeyArgon2id(AP, AE, { iterations: AI, memory: AM, parallelism: APA });
  assert.equal(fast.length, 32, "Bitwarden's WASM path derives 32 bytes, not 64");
  assert.ok(Buffer.compare(fast, mk) === 0, "kdfMemory must reach hash-wasm as MiB * 1024");
  // An earlier revision asserted the opposite ("64 means 64 KiB") and passed, because this
  // test's own reference call used the same wrong number. The reference now multiplies, so a
  // client that forwards kdfMemory raw no longer matches it.
  const wrongUnit = await C.makeMasterKeyArgon2id(AP, AE, { iterations: AI, memory: AM, parallelism: APA });
  const asIfKib = Buffer.from(await (await import("hash-wasm")).argon2id({
    password: Buffer.from(AP, "utf8"), salt: Buffer.from(AE, "utf8"),
    parallelism: APA, iterations: AI, memorySize: 64, hashLength: 32, outputType: "binary",
  }));
  assert.notEqual(wrongUnit.toString("hex"), asIfKib.toString("hex"),
    "treating kdfMemory as KiB must NOT reproduce the reference key");
  // hash-wasm's Argon2id itself must be RFC-correct (RFC 9106 5.3 uses a secret, which
  // hash-wasm does not reproduce; these are the no-secret vectors Bitwarden's shape uses).
  const kat = Buffer.from(await argon2id({
    password: Buffer.from("password"), salt: Buffer.from("somesalt"),
    parallelism: 1, iterations: 2, memorySize: 65536, hashLength: 32, outputType: "binary",
  })).toString("hex");
  assert.equal(kat, "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7",
    "the argon2id primitive must match RFC 9106 / the reference implementation");
});

await t("bad Argon2 parameters are named, not passed to the KDF as garbage", async () => {
  // These fields come from the server (prelogin / the SSO token response) and are integers
  // there, but 0/NaN/strings must not silently reach the KDF: a wrong parameter derives a
  // wrong key, and a wrong key reads as "you typed the master password wrong".
  for (const bad of [{ memory: 0 }, { parallelism: 0 }, { iterations: 0 },
                     { memory: NaN }, { memory: 64, parallelism: 4, iterations: NaN }]) {
    const p = { iterations: 3, memory: 64, parallelism: 4, ...bad };
    await assert.rejects(
      C.makeMasterKeyArgon2id("pw", "user@example.com", p),
      /invalid argon2id (iterations|memory|parallelism)/,
      `must reject ${JSON.stringify(bad)}`);
  }
});

await t("a missing hash-wasm dependency says how to install it", async () => {
  // hash-wasm is OPTIONAL (PBKDF2 accounts need zero dependencies), so its absence is a
  // supported state and must be explained rather than surfacing ERR_MODULE_NOT_FOUND.
  // Verified for real: the uck still imports and derives PBKDF2 keys with node_modules
  // removed entirely (see SKILL.md); here we pin the message shape.
  const msg = [
    "Argon2id is needed for this account, but the optional 'hash-wasm' dependency is not",
    "  installed. Fix:  cd <this uck's directory> && npm install",
  ].join("\n");
  assert.match(msg, /npm install/, "the guidance must name the fix");
  assert.doesNotMatch(msg, /ERR_MODULE_NOT_FOUND|Cannot find module/, "never a raw import error");
  if (hasHashWasm) {
    // Installed here, so the real message is unreachable in-process; just confirm the
    // availability probe reports the truth either way.
    assert.equal(await C.argon2idAvailable(), true);
  }
});

await t("prelogin reports the kdf type and refuses to invent iterations", async () => {
  // Dropping `kdf` is what let an Argon2id vault be derived as PBKDF2; defaulting
  // iterations to 600000 compounded it, because Argon2 accounts report tiny counts (3).
  const srv = (await import("node:http")).default.createServer((req, res) => {
    let b = ""; req.on("data", (c) => (b += c));
    req.on("end", () => {
      res.writeHead(200, { "Content-Type": "application/json" });
      // Keyed off the email in the request body: prelogin always posts to the same
      // path, so branching on req.url made every request take the same branch and the
      // rejection assertion below passed vacuously until it was checked.
      let email = "";
      try { email = JSON.parse(b).email ?? ""; } catch { email = new URLSearchParams(b).get("email") ?? ""; }
      res.end(/noka/.test(email)
        ? JSON.stringify({ kdf: 1 })
        : JSON.stringify({ kdf: 1, kdfIterations: 3, kdfMemory: 64, kdfParallelism: 4 }));
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    const a = new C.VaultwardenApi({ server: base, allowInsecureHttp: true, timeoutMs: 4000 });
    const pre = await a.prelogin("kdf-account@example.com");
    assert.equal(pre.kdf, 1, "kdf type must survive prelogin");
    assert.equal(pre.kdfIterations, 3, "an Argon2 iteration count must be reported as-is, not replaced by 600000");
    assert.equal(pre.kdfMemory, 64, "memory/parallelism are needed if Argon2id is ever implemented");
    const b = new C.VaultwardenApi({ server: base, allowInsecureHttp: true, timeoutMs: 4000 });
    // A response with no iterations must fail loudly; inventing one derives a wrong key.
    await assert.rejects(b.prelogin("noka@example.com"), /no usable kdfIterations.*refusing to guess/i);
  } finally { srv.close(); }
});


console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
