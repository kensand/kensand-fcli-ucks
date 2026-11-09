// Regression test for `f fj POST /repos/<owner>/<repo>/pulls` failing with
// `f: API error [Head]: Required` no matter what payload shape was passed.
//
//   node fj/test/raw-call.test.mjs
//
// The mock server pins Forgejo's REAL create-PR contract, probed against a live
// instance rather than read back out of this repo's own code: the API binds a
// JSON body, and a request whose body is empty or is a JSON *string* is rejected
// with exactly `{"message":"[Head]: Required"}`. A body carrying `head`/`base`/
// `title` as object fields is accepted. So a client that puts those fields on
// the query string -- which is what the raw <METHOD> <path> path used to do --
// fails here for the same reason it fails in production, and no fixture can
// agree with a broken client.
//
// This test drives the uck through its real `register().run()` entrypoint (the
// same one `f` calls), against a local HTTP server, so it covers the argument
// marshalling end to end rather than just the helper.

import assert from "node:assert/strict";
import http from "node:http";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const uck = await import(pathToFileURL(path.join(here, "..", "index.js")).href);

let pass = 0, fail = 0;
const t = async (label, fn) => {
  try { await fn(); pass++; console.log(`ok   ${label}`); }
  catch (e) { fail++; console.log(`FAIL ${label}\n     ${String(e?.message ?? e).split("\n").join("\n     ")}`); }
};

// ---- Forgejo-shaped mock -----------------------------------------------------
// Records what actually went over the wire, and answers the way the real API
// does, so the assertions cannot be satisfied by a client that agrees with
// itself.
const seen = [];
const server = http.createServer((req, res) => {
  let raw = "";
  req.on("data", (c) => (raw += c));
  req.on("end", () => {
    const url = new URL(req.url, "http://127.0.0.1");
    const record = { method: req.method, path: url.pathname, query: Object.fromEntries(url.searchParams), raw };
    seen.push(record);

    if (url.pathname === "/api/v1/repos/o/r/pulls" && req.method === "POST") {
      // Forgejo: body must be a JSON OBJECT with head/base/title.
      let body;
      try { body = JSON.parse(raw || "null"); } catch { body = null; }
      if (!body || typeof body !== "object" || Array.isArray(body)) {
        return json(res, 422, { message: "[Head]: Required" });
      }
      if (!body.head) return json(res, 422, { message: "[Head]: Required" });
      if (!body.base) return json(res, 422, { message: "[Base]: Required" });
      if (!body.title) return json(res, 422, { message: "[Title]: Required" });
      return json(res, 201, { number: 999, title: body.title, html_url: "http://x/o/r/pulls/999" });
    }
    if (url.pathname === "/api/v1/repos/o/r/pulls" && req.method === "GET") {
      return json(res, 200, [{ number: 1, title: "existing" }]);
    }
    return json(res, 200, { ok: true });
  });
});
const json = (res, code, obj) => {
  res.writeHead(code, { "content-type": "application/json" });
  res.end(JSON.stringify(obj));
};
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${server.address().port}`;

// ---- drive the uck the way `f` does ------------------------------------------
const cmd = uck.register({});
// run(_argv, args, ctx) -- args._ is the positional list; ctx carries credsApi.
const ctx = { registry: { creds: { credsApi: { resolveCred: async () => null } } } };

async function run(_) {
  seen.length = 0;
  process.env.FORGEJO_URL = base;
  process.env.FORGEJO_TOKEN = "test-token";
  const out = [];
  const realWrite = process.stdout.write.bind(process.stdout);
  process.stdout.write = (c) => { out.push(String(c)); return true; };
  try {
    await cmd.run([], { _: _ }, ctx);
  } catch (e) {
    out.push("THREW:" + (e?.message ?? e));
  } finally {
    process.stdout.write = realWrite;
  }
  return { stdout: out.join(""), wire: seen[seen.length - 1] };
}

// ---- the bug -----------------------------------------------------------------
await t("raw POST with a FLAT json arg sends head/base/title in the body (was: query string -> [Head]: Required)", async () => {
  const { stdout, wire } = await run(["POST", "/repos/o/r/pulls", '{"title":"T","head":"feat","base":"main"}']);
  assert.ok(!stdout.includes("[Head]: Required"), `still hitting the bug:\n${stdout}`);
  assert.deepEqual(JSON.parse(wire.raw), { title: "T", head: "feat", base: "main" });
  assert.equal(wire.query.title, undefined, "head fields must not be duplicated onto the query string");
  assert.ok(stdout.includes("999"), `expected the created PR number in stdout:\n${stdout}`);
});

await t("raw POST with an explicit nested body still works (unchanged)", async () => {
  const { stdout, wire } = await run(["POST", "/repos/o/r/pulls", '{"body":{"title":"T","head":"feat","base":"main"}}']);
  assert.ok(!stdout.includes("[Head]: Required"), stdout);
  assert.deepEqual(JSON.parse(wire.raw), { title: "T", head: "feat", base: "main" });
});

await t("raw POST with key=value args sends them as the body", async () => {
  const { stdout, wire } = await run(["POST", "/repos/o/r/pulls", "title=T", "head=feat", "base=main"]);
  assert.ok(!stdout.includes("[Head]: Required"), stdout);
  assert.deepEqual(JSON.parse(wire.raw), { title: "T", head: "feat", base: "main" });
});

// ---- non-vacuity: the mock really does reject the old shape ------------------
await t("the mock rejects an empty body with [Head]: Required (test is not vacuous)", async () => {
  const res = await fetch(`${base}/api/v1/repos/o/r/pulls`, {
    method: "POST", headers: { "content-type": "application/json" }, body: "",
  });
  assert.equal((await res.json()).message, "[Head]: Required");
});

await t("a body sent as a JSON STRING is rejected by the mock, as Forgejo rejects it", async () => {
  const res = await fetch(`${base}/api/v1/repos/o/r/pulls`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ body: JSON.stringify({ title: "T", head: "feat", base: "main" }) }),
  });
  assert.equal((await res.json()).message, "[Head]: Required");
});

// ---- must not regress reads --------------------------------------------------
await t("raw GET still sends params as query, with an empty body", async () => {
  const { wire } = await run(["GET", "/repos/o/r/pulls", '{"state":"open","limit":5}']);
  assert.equal(wire.query.state, "open");
  assert.equal(wire.query.limit, "5");
  assert.equal(wire.raw, "");
});

server.close();
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
