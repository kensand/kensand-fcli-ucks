/**
 * Cross-implementation test against Bitwarden's own Rust/WASM crypto.
 *
 * Every other test in this suite checks the client against fixtures built under the same
 * assumptions the client implements, so a shared misunderstanding passes silently — which is
 * exactly how this client failed to read a real vault while all 36 crypto tests were green.
 * Here Bitwarden's REAL implementation encrypts and this client decrypts, and vice versa, so
 * agreement means agreement with Bitwarden rather than with ourselves.
 *
 *   node vaultwarden/test/bitwarden-wasm.test.mjs
 *
 * The oracle is @bitwarden/sdk-internal (~11 MB, not a dependency of this uck). To fetch it:
 *
 *   mkdir -p /tmp/bw-oracle && cd /tmp/bw-oracle
 *   curl -sSL https://registry.npmjs.org/@bitwarden/sdk-internal/-/sdk-internal-0.2.0-main.1116.tgz -o sdk.tgz
 *   tar xzf sdk.tgz
 *
 * When it is absent the file prints a loud SKIPPING banner and exits 0. It must not be
 * allowed to look like a pass: an earlier revision of this file probed
 * `PureCrypto.symmetric_encrypt_string`, which is undefined because wasm-bindgen puts statics
 * on the prototype, so it registered ZERO tests while reporting a clean run. The loader below
 * therefore verifies the oracle by round-tripping through it.
 */
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
      // wasm-bindgen statics live on the prototype: P.symmetric_encrypt_string is undefined
      // even when the class is perfectly usable. Probe with a real call instead.
      if (typeof P?.symmetric_encrypt_string !== "function" || typeof P?.symmetric_decrypt_string !== "function") {
        lastErr = `${spec}: PureCrypto has no callable symmetric_encrypt_string`;
        continue;
      }
      const probe = crypto.randomBytes(64);
      const blob = P.symmetric_encrypt_string("probe", probe);
      if (!/^2\./.test(blob) || P.symmetric_decrypt_string(blob, probe) !== "probe") {
        lastErr = `${spec}: round-trip probe failed`;
        continue;
      }
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
  console.log("THIS SUITE RAN ZERO TESTS. Fetch the oracle (header above) before treating\ncrypto changes as verified — a green run here proves nothing without it.\n");
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
    // are — an IV is always 16 bytes.
    const lens = bodyOf(enc).map((s) => Buffer.from(s, "base64").length);
    assert.deepEqual(lens, [16, 32, 32], `expected iv(16)|data(32)|mac(32), got ${lens}`);
    assert.equal(C.decryptString(enc, keys), "cross-impl-secret");
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
    // Without the guard below, dropping the mac segment truncates the ciphertext by a whole
    // 16-byte block and returns plausible-but-wrong text: corrupt data reported as success.
    let msg = "";
    try { C.decryptString(`2.${iv}|${data}`, keys); } catch (e) { msg = String(e.message); }
    assert.match(msg, /has 2 segments.*expected 3/, "must refuse and report the count it saw: " + msg);
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
    // End to end, not just one envelope: derive a master key with our PBKDF2, stretch it,
    // let Bitwarden encrypt a "profile.key"-shaped blob with the resulting 64-byte key, and
    // unwrap it here. If any constant (HKDF info strings, key layout, iteration handling)
    // drifted from the spec, Bitwarden's output would not open.
    const email = "interop@example.com", pw = "correct horse battery staple", iter = 1000;
    const master = C.makeMasterKey(pw, email, iter);
    const stretched = C.stretchMasterKey(master);
    const wireKey = Buffer.concat([stretched.encKey, stretched.macKey]);   // what Bitwarden calls the key
    const enc = PureCrypto.symmetric_encrypt_string(b64(crypto.randomBytes(64)), wireKey);
    const unwrapped = C.unwrapSymmetricKey(enc, stretched);
    assert.equal(unwrapped.encKey.length, 32);
    assert.equal(unwrapped.macKey.length, 32);
    // And a cipher item written by Bitwarden under that key decrypts through VaultItem.
    const item = new C.VaultItem({
      id: "c", type: 1, name: PureCrypto.symmetric_encrypt_string("interop-item", wireKey),
      login: { username: PureCrypto.symmetric_encrypt_string("ken", wireKey), password: PureCrypto.symmetric_encrypt_string("s3cret", wireKey), uris: [] },
      fields: [],
    }, { encKey: wireKey.subarray(0, 32), macKey: wireKey.subarray(32, 64) });
    assert.equal(item.login.password, "s3cret", "a Bitwarden-encrypted vault item must decrypt here");
  });
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
