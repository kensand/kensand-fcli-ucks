// Offline crypto tests for the vaultwarden client. No server needed: we build a
// Bitwarden-shaped vault blob, encrypt it with an independent implementation of
// the spec (written here from the protocol description, deliberately NOT reusing
// lib/vwclient.js), then check the client decrypts it and rejects tampering.
//
//   node vaultwarden/test/crypto.test.mjs
//
// The KAT vectors for HKDF come from RFC 5869 Test Case 1.

import assert from "node:assert/strict";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const C = await import(pathToFileURL(path.join(here, "..", "lib", "vwclient.js")).href);

let pass = 0, fail = 0;
const t = (label, fn) => {
  try { fn(); pass++; console.log(`ok   ${label}`); }
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

t("HKDF-Expand matches RFC 5869 A.1/A.3 (and @noble when present)", () => {
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

t("PBKDF2 parameters pass through unmangled (RFC 6070 shapes, SHA-256)", () => {
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

t("PBKDF2 uses email (not email+password) as salt", () => {
  const mine = C.makeMasterKey(PASSWORD, EMAIL, ITER);
  assert.deepEqual([...mine], [...masterKey]);
  // The common mistake: salting with the password too.
  const wrong = crypto.pbkdf2Sync(Buffer.from(PASSWORD), Buffer.from(EMAIL + PASSWORD), ITER, 32, "sha256");
  assert.notDeepEqual([...mine], [...wrong]);
});

t("rejected kdfIterations", () => {
  assert.throws(() => C.makeMasterKey(PASSWORD, EMAIL, 0), /invalid kdfIterations/);
  assert.throws(() => C.makeMasterKey(PASSWORD, EMAIL, NaN), /invalid kdfIterations/);
});

t("masterPasswordHash = HMAC-SHA256(masterKey, password)", () => {
  const ref = crypto.createHmac("sha256", masterKey).update(Buffer.from(PASSWORD)).digest();
  assert.deepEqual([...C.masterPasswordHash(masterKey, PASSWORD)], [...ref]);
});

t("unwrapSymmetricKey yields the 32+32 key pair", () => {
  const k = C.unwrapSymmetricKey(vault.profile.key, { encKey: stretched.enc, macKey: stretched.mac });
  assert.deepEqual([...k.symmetricKey], [...symmetricKey]);
  assert.deepEqual([...k.macKey], [...macKey]);
});

t("decryptVault decrypts the login item", () => {
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

t("wrong key fails MAC verification instead of returning garbage", () => {
  const bad = { encKey: crypto.randomBytes(32), macKey: crypto.randomBytes(32) };
  const gh = vault.ciphers[0];
  assert.throws(() => C.decryptString(gh.login.password, bad), /MAC verification failed/);
});

t("tampered ciphertext is rejected (flip one ct byte)", () => {
  const enc = vault.ciphers[0].login.password;
  const [hdr, iv, ct, mac] = enc.split(".")[0] === "2" ? ["2", ...enc.split(".")[1].split("|")] : [];
  const ctBuf = Buffer.from(ct, "base64");
  ctBuf[0] ^= 0x01;
  const tampered = `2.${iv}|${ctBuf.toString("base64")}|${mac}`;
  assert.throws(() => C.decryptString(tampered, { encKey: symmetricKey, macKey }), /MAC verification failed/);
});

t("type-1 (no MAC) ciphertext is refused by default, allowed on request", () => {
  const legacy = vault.ciphers.find((c) => c.id === "cipher-legacy");
  assert.throws(() => C.decryptString(legacy.login.username, { encKey: symmetricKey, macKey }), /no integrity tag/);
  // With the opt-in flag it must at least not claim MAC failure (it will still
  // fail to decrypt meaningfully because we never knew the type-1 key).
  assert.throws(
    () => C.decryptString(legacy.login.username, { encKey: symmetricKey, macKey }, { allowUnauthenticated: true }),
    /bad decrypt|wrong final block length|invalid|unsupported/i,
  );
});

t("round-trips through encryptString (TOTP write path)", () => {
  const keys = { encKey: symmetricKey, macKey };
  const enc = C.encryptString("totp-secret-value", keys);
  assert.match(enc, /^2\.[A-Za-z0-9+/=]+\|[A-Za-z0-9+/=]+\|[A-Za-z0-9+/=]+$/);
  assert.equal(C.decryptString(enc, keys), "totp-secret-value");
});

t("type 0 envelope is returned as plaintext", () => {
  assert.equal(C.decryptString(`0.${b64("https://github.com")}`, { encKey: symmetricKey, macKey }), "https://github.com");
});

t("null / empty fields yield undefined, not an error", () => {
  const keys = { encKey: symmetricKey, macKey };
  assert.equal(C.decryptString(null, keys), undefined);
  assert.equal(C.decryptString("", keys), undefined);
  assert.equal(C.decryptString(undefined, keys), undefined);
});

t("malformed envelope is reported, not silently ignored", () => {
  assert.throws(() => C.decryptString("not-an-envelope", { encKey: symmetricKey, macKey }), /unrecognised ciphertext envelope/);
  assert.throws(() => C.decryptString("9.a|b|c", { encKey: symmetricKey, macKey }), /unsupported encryption type 9/);
});

t("deriveKeys wires the whole chain end to end", () => {
  const keys = C.deriveKeys({ email: EMAIL, password: PASSWORD, kdfIterations: ITER, encryptedKey: vault.profile.key });
  // deriveKeys must hand back keys decryptString actually consumes.
  assert.ok(Buffer.isBuffer(keys.encKey) && keys.encKey.length === 32, "deriveKeys().encKey missing/wrong length");
  assert.ok(Buffer.isBuffer(keys.macKey) && keys.macKey.length === 32, "deriveKeys().macKey missing/wrong length");
  const items = C.decryptVault({ ciphers: vault.ciphers }, keys);
  assert.equal(items.length, vault.ciphers.length);
  const gh = items.find((i) => i.id === "cipher-github");
  assert.deepEqual(gh.errors, {}, "unexpected per-field decrypt errors: " + JSON.stringify(gh.errors));
  assert.equal(gh.login.password, "ghp_supersecret123");
  // A wrong master password is caught at key unwrap, before any item is touched.
  assert.throws(
    () => C.deriveKeys({ email: EMAIL, password: "wrong", kdfIterations: ITER, encryptedKey: vault.profile.key }),
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

t("decryptVault reads the /api/ciphers list shape (and legacy PascalCase)", () => {
  const keys = C.deriveKeys({ email: EMAIL, password: PASSWORD, kdfIterations: ITER, encryptedKey: vault.profile.key });
  const fromSync = C.decryptVault({ ciphers: vault.ciphers }, keys).length;
  // Exactly what Vaultwarden's ciphers.rs builds.
  const fromList = C.decryptVault({ object: "list", data: vault.ciphers, continuationToken: null }, keys).length;
  // Older upstream Bitwarden capitalises the envelope keys.
  const fromPascal = C.decryptVault({ Object: "list", Data: vault.ciphers, ContinuationToken: null }, keys).length;
  assert.ok(fromSync > 0, "sanity: the fixture is not empty");
  assert.equal(fromList, fromSync);
  assert.equal(fromPascal, fromSync);
});

t("a misread or foreign response shape throws instead of looking like an empty vault", () => {
  const keys = C.deriveKeys({ email: EMAIL, password: PASSWORD, kdfIterations: ITER, encryptedKey: vault.profile.key });
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


t("prelogin is sent as JSON (form-encoded is rejected by the real server)", async () => {
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

t("a 429 is explained as rate limiting, not as a bare status code", async () => {
  const fetchFn = async () => new Response(JSON.stringify({ message: "Too many login requests", error_description: "" }), { status: 429, headers: { "Content-Type": "application/json" } });
  const api = new C.VaultwardenApi({ server: "https://x.invalid", fetchFn });
  const msg = await api.loginApiKey({ clientId: "u", clientSecret: "s" }).then(() => "resolved", (e) => e.message);
  assert.match(msg, /Too many login requests/);
  assert.match(msg, /rate-limiting|wait/i);
});

t("an empty error_description does not hide the populated message", async () => {
  const fetchFn = async () => new Response(JSON.stringify({ message: "Invalid client_id", error: "", error_description: "", validationErrors: { "": ["Invalid client_id"] } }), { status: 400, headers: { "Content-Type": "application/json" } });
  const api = new C.VaultwardenApi({ server: "https://x.invalid", fetchFn });
  const msg = await api.sync().then(() => "resolved", (e) => e.message);
  assert.match(msg, /Invalid client_id/, `got: ${msg}`);
});

t("plaintext http server is refused unless overridden", () => {
  assert.throws(() => new C.VaultwardenApi({ server: "http://vault.lan:8080" }), /plaintext http/);
  assert.throws(() => new C.VaultwardenApi({ server: "vault.lan" }), /must be an http\(s\) URL/);
  assert.doesNotThrow(() => new C.VaultwardenApi({ server: "https://vault.lan/" }));
});

t("API errors surface Vaultwarden's error_description", async () => {
  const api = new C.VaultwardenApi({ server: "https://vault.example", fetchFn: async () => ({ ok: false, status: 400, text: async () => JSON.stringify({ error: "invalid_grant", error_description: "Username or password is incorrect." }) }) });
  await assert.rejects(() => api.loginApiKey({ clientId: "user.x", clientSecret: "y" }), /HTTP 400: Username or password is incorrect/);
});

t("unreachable server explains itself", async () => {
  const api = new C.VaultwardenApi({ server: "https://vault.tailnet.ts", fetchFn: async () => { throw Object.assign(new Error("fetch failed"), { cause: Object.assign(new Error("getaddrinfo ENOTFOUND vault.tailnet.ts"), { code: "ENOTFOUND" }) }); } });
  await assert.rejects(() => api.sync(), /cannot reach|ENOTFOUND|dns/i);
});

t("2FA-required login is explained as 2FA, not as a bad password", async () => {
  const api = new C.VaultwardenApi({ server: "https://vault.example", fetchFn: async () => ({ ok: true, status: 200, text: async () => JSON.stringify({ twoFactorProviders: [0, 1] }) }) });
  await assert.rejects(() => api.loginPassword({ email: EMAIL, passwordHash: Buffer.alloc(32) }), /2FA is required/);
});

t("non-JSON response says the server may not be Vaultwarden", async () => {
  const api = new C.VaultwardenApi({ server: "https://vault.example", fetchFn: async () => ({ ok: true, status: 200, text: async () => "<html><body>nginx</body></html>" }) });
  await assert.rejects(() => api.sync(), /really a Vaultwarden server/);
});

t("VaultItem exposes the ciphertext needed to write back", () => {
  const keys = { encKey: symmetricKey, macKey };
  const items = C.decryptVault({ ciphers: vault.ciphers }, keys);
  const gh = items.find((i) => i.id === "cipher-github");
  assert.equal(gh.hiddenField("totp"), vault.ciphers[0].login.totp);
  assert.equal(gh.raw.login.password, vault.ciphers[0].login.password);
  assert.equal(items.find((i) => i.id === "cipher-gh2").hiddenField("totp"), null);
});

t("duplicate names are detectable by the resolver", () => {
  const items = C.decryptVault({ ciphers: vault.ciphers }, { encKey: symmetricKey, macKey });
  const named = items.filter((i) => i.name === "github.com");
  assert.equal(named.length, 2, "fixture must contain a name collision to be useful");
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
