import assert from "node:assert/strict";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const C = await import(pathToFileURL(path.join(here, "..", "lib", "vwclient.js")).href);

let pass = 0, fail = 0;
const t = async (label, fn) => {
  try { await fn(); pass++; console.log(`ok   ${label}`); }
  catch (e) { fail++; console.log(`FAIL ${label}\n     ${e.message.split("\n").join("\n     ")}`); }
};

const CANDIDATES = [
  "/tmp/bw-oracle/package/node/bitwarden_wasm_internal.js",
  "@bitwarden/sdk-internal",
];

/** Load Bitwarden's wasm and PROVE it works by round-tripping through it. */
async function loadOracle() {
  let lastErr = "no candidate tried";
  for (const spec of CANDIDATES) {
    try {
      const m = await import(spec);
      const P = m.PureCrypto;
      // wasm-bindgen puts statics on the prototype, and the bindings distinguish text from
      // bytes: symmetric_encrypt_string takes `plain: string` (a Buffer reaches the wasm as a
      // Uint8Array and it dies on `arg.charCodeAt is not a function`), while
      // symmetric_encrypt_bytes takes Uint8Array. Probe with a REAL call -- an earlier revision
      // truthiness-checked a property, found it undefined, and registered ZERO tests while the
      // run looked like an ordinary pass.
      const need = ["symmetric_encrypt_bytes", "symmetric_decrypt_bytes", "symmetric_encrypt_string", "symmetric_decrypt_string"];
      const missing = need.filter((n) => typeof P?.[n] !== "function");
      if (missing.length) { lastErr = `${spec}: PureCrypto missing ${missing.join(", ")}`; continue; }

      // Round-trip BOTH paths; a binary payload through the string entry point is exactly the
      // confusion that produced the "unexpected symmetric key length" errors all session.
      const key = crypto.randomBytes(64), raw = crypto.randomBytes(64);
      const blob = P.symmetric_encrypt_bytes(raw, key);
      const back = Buffer.from(P.symmetric_decrypt_bytes(blob, key));
      if (!/^2\./.test(blob)) { lastErr = `${spec}: encrypt_bytes did not emit a type-2 envelope`; continue; }
      if (Buffer.compare(back, raw) !== 0) { lastErr = `${spec}: binary round-trip mismatch (${back.length} vs ${raw.length} bytes)`; continue; }
      const txt = P.symmetric_encrypt_string("round-trip", key);
      if (P.symmetric_decrypt_string(txt, key) !== "round-trip") { lastErr = `${spec}: string round-trip mismatch`; continue; }
      return { PureCrypto: P };
    } catch (e) {
      lastErr = `${spec}: ${String(e.message).split("\n")[0].slice(0, 70)}`;
    }
  }
  return { PureCrypto: null, lastErr };
}

const { PureCrypto, lastErr } = await loadOracle();

if (!PureCrypto) {
  console.log(`\nSKIPPING the Bitwarden cross-check — oracle did not load:\n  ${lastErr}`);
  console.log("THIS SUITE RAN ZERO TESTS. Fetch the oracle (header at the top of this file) before\n treating crypto changes as verified -- a green run here proves nothing without it.\n");
} else {
  const b64 = (b) => Buffer.from(b).toString("base64");
  const keyOf = () => crypto.randomBytes(64);              // enc(32) || mac(32) wire format
  const keysOf = (k) => ({ encKey: k.subarray(0, 32), macKey: k.subarray(32, 64) });
  const bodyOf = (enc) => enc.split(".").slice(1).join(".").split("|");

  await t("this client decrypts what Bitwarden's own crypto encrypts", () => {
    const key = keyOf(), keys = keysOf(key);
    const enc = PureCrypto.symmetric_encrypt_string("cross-impl-secret", key);
    assert.match(enc, /^2\./, "Bitwarden must emit a type-2 envelope");
    // Pin the segment ORDER, which a self-built fixture can never prove: the MAC covers both
    // buffers, so a swapped iv/data pair is not distinguishable from the tag alone. Lengths
    // are -- an IV is always 16 bytes.
    const lens = bodyOf(enc).map((s) => Buffer.from(s, "base64").length);
    assert.deepEqual(lens, [16, 32, 32], `expected iv(16)|data(32)|mac(32), got ${lens}`);
    assert.equal(C.decryptString(enc, keys), "cross-impl-secret");
  });

  await t("binary payloads survive Bitwarden's encrypt -> this client's decrypt", () => {
    // The defect class this whole file was written around: high bytes lost to a Buffer->string
    // hop. Random bytes, so roughly half are >= 0x80.
    //
    // Use decryptBytes, not decryptString: this client's decryptString returns a utf8 JS string
    // (matching Bitwarden's own *_string API), so pushing arbitrary binary through it is
    // expected to corrupt -- that is the API contract, not a bug. Binary payloads (the wrapped
    // user key being the important one) go through decryptBytes / unwrapSymmetricKey.
    const key = keyOf(), keys = keysOf(key);
    const raw = crypto.randomBytes(64);
    const enc = PureCrypto.symmetric_encrypt_bytes(raw, key);
    assert.ok(Buffer.compare(C.decryptBytes(enc, keys), raw) === 0,
      "a binary payload must come back byte for byte via decryptBytes");
  });

  await t("ciphertext produced here is readable by Bitwarden", () => {
    const key = keyOf(), keys = keysOf(key);
    const mine = C.encryptString("round-trip-back", keys);
    assert.match(mine, /^2\./);
    assert.equal(PureCrypto.symmetric_decrypt_string(mine, key), "round-trip-back",
      "Bitwarden must be able to read what this client writes");
  });

  await t("a reordered envelope is refused, never mis-decrypted", () => {
    for (const plaintext of ["short", "0123456789abcdef", "do-not-truncate-me"]) {
      const key = keyOf(), keys = keysOf(key);
      const [iv, data, mac] = bodyOf(PureCrypto.symmetric_encrypt_string(plaintext, key));
      assert.throws(() => C.decryptString(`2.${data}|${iv}|${mac}`, keys),
        /MAC verification failed|16-byte IV/,
        `reordered envelope for ${JSON.stringify(plaintext)} must raise, not mis-decrypt`);
    }
  });

  await t("a truncated type-2 envelope raises instead of returning short plaintext", () => {
    const key = keyOf(), keys = keysOf(key);
    const enc = PureCrypto.symmetric_encrypt_string("do-not-truncate-me", key);
    const [iv, data, mac] = bodyOf(enc);
    assert.equal(mac.length, 44, "Bitwarden emits a mac segment (32 bytes -> 44 b64 chars)");
    // Two refusals are equally correct -- reject the segment count, or reject the missing tag.
    // Pinning either wording would only make this break on a harmless refactor; what matters
    // is that it raises rather than returning 15 bytes of plausible-but-wrong text.
    let msg = "";
    try { const o = C.decryptString(`2.${iv}|${data}`, keys); msg = "RETURNED " + JSON.stringify(o).slice(0, 40); }
    catch (e) { msg = String(e.message); }
    assert.match(msg, /segments|MAC tag/, "must refuse a truncated type-2 envelope: " + msg);
    // The unauthenticated legacy form is refused on its own rule, not this one.
    assert.throws(() => C.decryptString(`1.${iv}|${data}`, keys), /no integrity tag/);
  });

  await t("a tampered mac is refused", () => {
    const key = keyOf(), keys = keysOf(key);
    const [iv, data, mac] = bodyOf(PureCrypto.symmetric_encrypt_string("tamper", key));
    const bad = Buffer.from(mac, "base64");
    bad[0] ^= 0xff;
    assert.throws(() => C.decryptString(`2.${iv}|${data}|${b64(bad)}`, keys), /MAC verification failed/);
  });

  await t("the full master-key chain interoperates with Bitwarden's key format", () => {
    // End to end, not one envelope: derive a master key with this client's PBKDF2, stretch it,
    // have Bitwarden's wasm encrypt the RAW 64-byte user key with the result, and unwrap it
    // here. If any constant drifted -- HKDF info strings, key layout, iteration handling --
    // Bitwarden's output would not open, or would open to different bytes.
    const email = "interop@example.com", pw = "correct horse battery staple", iter = 1000;
    const master = C.makeMasterKey(pw, email, iter);
    const stretched = C.stretchMasterKey(master);
    const wireKey = Buffer.concat([stretched.encKey, stretched.macKey]); // Bitwarden's key format

    const rawUserKey = crypto.randomBytes(64);
    const enc = PureCrypto.symmetric_encrypt_bytes(rawUserKey, wireKey);
    const unwrapped = C.unwrapSymmetricKey(enc, stretched);
    assert.equal(unwrapped.encKey.length, 32);
    assert.equal(unwrapped.macKey.length, 32);
    assert.ok(Buffer.compare(Buffer.from(rawUserKey.subarray(0, 32)), unwrapped.encKey) === 0,
      "the enc key must be exactly what Bitwarden encrypted");
    assert.ok(Buffer.compare(Buffer.from(rawUserKey.subarray(32, 64)), unwrapped.macKey) === 0,
      "the mac key must be exactly what Bitwarden encrypted");

    // And a vault item written by Bitwarden under that key decrypts through VaultItem.
    const item = new C.VaultItem({
      id: "c", type: 1, name: PureCrypto.symmetric_encrypt_string("interop-item", wireKey),
      login: {
        username: PureCrypto.symmetric_encrypt_string("ken", wireKey),
        password: PureCrypto.symmetric_encrypt_string("s3cret", wireKey),
        uris: [],
      },
      fields: [],
    }, { encKey: wireKey.subarray(0, 32), macKey: wireKey.subarray(32, 64) });
    assert.equal(item.login.password, "s3cret", "a Bitwarden-encrypted vault item must decrypt here");
  });
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
