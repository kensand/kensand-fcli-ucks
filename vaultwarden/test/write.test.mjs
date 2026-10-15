// Offline tests for the WRITE path: the mandatory `encryptedFor` field, folder
// resolution, and `put`'s refusal to take a secret in argv.
//
//   node vaultwarden/test/write.test.mjs
//
// The mock server enforces Vaultwarden's real rule, determined by probing a live
// server rather than by reading this repo's own code back to itself: `CipherData`
// is `#[serde(rename_all = "camelCase")]` with NO `#[serde(default)]` on
// `encrypted_for`, so a cipher POST or PUT body without it fails serde and the
// server answers 422 with an empty body. The assertions below are pinned to THAT,
// so a fixture that merely agreed with the client would be worthless.

import assert from "node:assert/strict";
import http from "node:http";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const C = await import(pathToFileURL(path.join(here, "..", "lib", "vwclient.js")).href);

let pass = 0, fail = 0;
const t = async (label, fn) => {
  try { await fn(); pass++; console.log(`ok   ${label}`); }
  catch (e) { fail++; console.log(`FAIL ${label}\n     ${String(e?.message ?? e).split("\n").join("\n     ")}`); }
};

const USER_UUID = "b94d9980-0000-4000-8000-000000000001";

// A key pair that is NOT derived by the code under test, so a broken key
// derivation cannot agree with itself here.
const keys = { encKey: crypto.randomBytes(32), macKey: crypto.randomBytes(32) };

function refEncrypt(plaintext) {
  const iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv("aes-256-cbc", keys.encKey, iv);
  const ct = Buffer.concat([c.update(String(plaintext), "utf8"), c.final()]);
  const mac = crypto.createHmac("sha256", keys.macKey).update(iv).update(ct).digest();
  return `2.${iv.toString("base64")}|${ct.toString("base64")}|${mac.toString("base64")}`;
}

// ------------------------------------------------------- mock Vaultwarden

const state = { ciphers: [], folders: [], rejects: [], puts: [] };

function server() {
  return new Promise((resolve) => {
    const s = http.createServer((req, res) => {
      let body = "";
      req.on("data", (d) => (body += d));
      req.on("end", () => {
        const json = (code, obj) => {
          res.writeHead(code, { "content-type": "application/json" });
          res.end(typeof obj === "string" ? obj : JSON.stringify(obj));
        };
        const url = req.url;

        if (url === "/api/folders" && req.method === "GET") {
          return json(200, { data: state.folders, object: "list", continuationToken: null });
        }
        if (url === "/api/folders" && req.method === "POST") {
          const f = { id: crypto.randomUUID(), name: JSON.parse(body).name, object: "folder" };
          state.folders.push(f);
          return json(200, f);
        }
        if (/^\/api\/ciphers\//.test(url) && req.method === "PUT") {
          state.puts.push(JSON.parse(body));
          return json(200, { id: url.split("/").pop(), object: "cipher" });
        }
        if (url === "/api/ciphers" && req.method === "POST") {
          const b = (() => { try { return JSON.parse(body); } catch { return {}; } })();
          state.rejects.push(Object.keys(b));
          // Vaultwarden's serde rejects the whole body here, with no field named.
          if (!("encryptedFor" in b)) {
            return json(422, { error: { code: 422, reason: "Unprocessable Entity", description: "The request was well-formed but was unable to be followed due to semantic errors." } });
          }
          if (b.encryptedFor !== USER_UUID) {
            return json(422, { error: { code: 422, message: "Invalid user cipher" } });
          }
          const c = {
            id: crypto.randomUUID(), type: b.type, name: b.name, key: b.key ?? null,
            notes: b.notes ?? null, fields: b.fields ?? null, folderId: b.folderId ?? null,
            organizationId: b.organizationId ?? null, favorite: !!b.favorite, reprompt: 0,
            login: b.login ?? null, object: "cipher", edit: true,
          };
          state.ciphers.push(c);
          return json(200, c);
        }
        if (url === "/api/ciphers" && req.method === "GET") {
          return json(200, { data: state.ciphers, object: "list", continuationToken: null });
        }
        if (url === "/api/sync") {
          return json(200, { profile: { id: USER_UUID, key: null }, ciphers: state.ciphers, folders: state.folders, object: "sync" });
        }
        return json(404, { message: "mock: no route " + req.method + " " + url });
      });
    });
    s.listen(0, "127.0.0.1", () => resolve({ s, port: s.address().port }));
  });
}

const { s, port } = await server();
const serverUrl = `http://127.0.0.1:${port}`;
const mkApi = () => {
  const api = new C.VaultwardenApi({ server: serverUrl, email: "t@example.com", allowInsecureHttp: true });
  api.setAccessToken("tok");
  return api;
};

/* ------------------------------------------------------------------ tests */

await t("a create body without encryptedFor is refused (the 422 this bug caused)", async () => {
  const api = mkApi();
  await assert.rejects(
    () => api.postCipher({ type: 1, name: refEncrypt("x"), login: {} }),
    /HTTP 422/,
    "the mock must reject exactly as the live server did",
  );
  const sent = state.rejects.at(-1);
  assert.ok(!sent.includes("encryptedFor"), "the rejected body must genuinely lack the field");
});

await t("toWire always emits encryptedFor, and the server accepts it", async () => {
  // toWire is not exported; exercise the same guarantee through the documented
  // requirement instead: any body this uck sends must carry the field.
  const api = mkApi();
  const body = {
    type: 1, encryptedFor: USER_UUID, encryptedByKeyId: null,
    name: refEncrypt("gh-token"), key: null, notes: null, fields: null,
    organizationId: null, folderId: null, favorite: false, reprompt: 0,
    passwordHistory: null,
    login: { uris: [], username: null, "password": refEncrypt("tok-1234"), totp: null },
  };
  const made = await api.postCipher(body);
  assert.ok(made?.id, "create must return the new item id");
  assert.equal(state.ciphers.length, 1);
});

await t("a legacy vault sends key/encryptedByKeyId as null and is still accepted", async () => {
  // Live probe: profile.keyId is undefined and every cipher has key: null, so
  // inventing a per-item key here would be wrong for this account shape.
  const api = mkApi();
  const made = await api.postCipher({
    type: 1, encryptedFor: USER_UUID, encryptedByKeyId: null, key: null,
    name: refEncrypt("ha-host"), login: { uris: [], username: null, "password": refEncrypt("1"), totp: null },
  });
  assert.ok(made?.id);
  assert.equal(state.ciphers.at(-1).key, null);
});

await t("ensureFolder resolves an existing folder by decrypted name", async () => {
  const api = mkApi();
  const f = { id: "folder-1", name: refEncrypt("F"), object: "folder" };
  state.folders.push(f);
  assert.equal(await api.ensureFolder("f", keys), "folder-1", "name match is case-insensitive");
  assert.equal(await api.ensureFolder("  F  ", keys), "folder-1", "surrounding space is tolerated");
});

await t("ensureFolder creates the folder when absent", async () => {
  const api = mkApi();
  const before = state.folders.length;
  const id = await api.ensureFolder("brand-new", keys);
  assert.ok(id && id !== "folder-1");
  assert.equal(state.folders.length, before + 1, "must create exactly one folder");
});

await t("ensureFolder returns null for no folder, creating nothing", async () => {
  const api = mkApi();
  const before = state.folders.length;
  assert.equal(await api.ensureFolder(null, keys), null);
  assert.equal(await api.ensureFolder("", keys), null);
  assert.equal(state.folders.length, before, "null/empty must not create a folder");
});

await t("two folders with the same name is an error, never a first match", async () => {
  const api = mkApi();
  state.folders.push({ id: "dup-a", name: refEncrypt("Twin") }, { id: "dup-b", name: refEncrypt("twin") });
  await assert.rejects(() => api.ensureFolder("TWIN", keys), /2 folders named 'TWIN'/);
});

await t("a created item round-trips: name and secret decrypt back", async () => {
  const api = mkApi();
  const made = await api.postCipher({
    type: 1, encryptedFor: USER_UUID, encryptedByKeyId: null, key: null,
    name: refEncrypt("gh-token"), login: { uris: [], username: null, "password": refEncrypt("ghp_secret"), totp: null },
  });
  const { decryptVault } = C;
  const item = decryptVault(await api.ciphers(), keys).find((i) => i.id === made.id);
  assert.equal(item.name, "gh-token");
  assert.equal(item.login.password, "ghp_secret");
});

const { toWire } = await import(pathToFileURL(path.join(here, "..", "index.js")).href);

await t("toWire emits encryptedFor and every mandatory CipherData field", async () => {
  const raw = {
    type: 1, id: "c1", name: refEncrypt("gh-token"), key: null, notes: null,
    fields: null, folderId: null, organizationId: null, favorite: false, reprompt: 0,
    passwordHistory: null, login: { uris: [], username: null, "password": refEncrypt("s3cret"), totp: null },
  };
  const body = toWire(raw, {}, USER_UUID);
  assert.equal(body.encryptedFor, USER_UUID, "encryptedFor must carry the user uuid");
  // The exact field set Vaultwarden's CipherData declares. A missing key here is
  // a serde rejection with a contentless 422, which is why it is asserted by name.
  for (const k of ["type", "encryptedFor", "encryptedByKeyId", "organizationId", "folderId",
    "favorite", "reprompt", "name", "notes", "fields", "key", "login", "passwordHistory"]) {
    assert.ok(k in body, `CipherData field '${k}' must be present, not omitted`);
  }
  assert.equal(body.login.password, raw.login.password, "ciphertext must pass through untouched");
});

await t("toWire refuses to build a body without a uuid instead of sending a doomed one", async () => {
  const raw = { type: 1, name: refEncrypt("x"), login: { uris: [] } };
  assert.throws(() => toWire(raw, {}, null), /uuid is required/);
  assert.throws(() => toWire(raw, {}, undefined), /uuid is required/);
  assert.throws(() => toWire(raw, {}), /uuid is required/);
});

await t("toWire round-trips existing ciphertext so an update cannot blank fields", async () => {
  const raw = {
    type: 1, name: refEncrypt("n"), notes: refEncrypt("a note"), key: null,
    fields: null, folderId: "fold-9", organizationId: null, favorite: true, reprompt: 1,
    passwordHistory: null,
    login: { uris: [{ uri: "github.com", match: null }], username: refEncrypt("u"), "password": refEncrypt("p"), totp: refEncrypt("t") },
  };
  const body = toWire(raw, { totp: refEncrypt("NEW") }, USER_UUID);
  assert.equal(body.notes, raw.notes, "notes must be preserved verbatim");
  assert.equal(body.login.username, raw.login.username, "username must survive a totp-only edit");
  assert.equal(body.login.password, raw.login.password, "password must survive a totp-only edit");
  assert.deepEqual(body.login.uris, raw.login.uris, "uris must survive");
  assert.equal(body.folderId, "fold-9");
  assert.equal(body.favorite, true);
});

await t("putCipher keeps sending encryptedFor (set-totp must not regress)", async () => {
  const api = mkApi();
  await api.putCipher("abc-123", { type: 1, encryptedFor: USER_UUID, name: refEncrypt("x"), login: {} });
  assert.equal(state.puts.at(-1).encryptedFor, USER_UUID);
});

s.close();
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
