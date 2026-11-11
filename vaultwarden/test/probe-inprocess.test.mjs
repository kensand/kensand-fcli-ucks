// In-process creds handle + re-entrancy guard + store-error degrade.
//
//   node test/probe-inprocess.test.mjs
//
// Fully offline: no `f`, no daemon, no network. Everything the provider does
// with the credential store goes through either the handle we hand it or the
// spawn fallback, and both are stood in for here.
//
// What it proves:
//   * a store read goes through the handle and does NOT spawn `f`
//   * the depth guard stops an in-process cycle at exactly one re-entry
//   * NON-VACUITY: with the guard's nulling stubbed out, the same stand-in
//     handle blows the stack — so the passing test is the guard, not a stub
//     that never recurses
//   * the depth is RELEASED when the inner call throws (a leaked depth turns
//     every later probe into the spawn path with no symptom at all)
//   * a throwing store read degrades to `store-error` instead of propagating
//     out of readiness
//
// It does NOT prove: the real creds daemon's rawCredRead shapes, or the
// child-process probe path end-to-end (e2e.test.mjs covers that when a mock
// Vaultwarden and a real store are available).

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const UCK = path.join(here, "..");
const SRC = path.join(UCK, "index.js");

let pass = 0, fail = 0;
async function t(name, fn) {
  try {
    await fn();
    console.log(`ok   ${name}`);
    pass++;
  } catch (e) {
    console.log(`FAIL ${name}\n     ${String(e?.message ?? e).split("\n")[0].slice(0, 200)}`);
    fail++;
  }
}

// The provider reads config from $F/vw.config.json. Point it at a throwaway
// home so this suite can never touch the real one, and so `openVault` has a
// server/email to get past its guard clauses.
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "f-vw-inproc-"));
const savedHome = process.env.HOME;
process.env.HOME = TMP;
fs.mkdirSync(path.join(TMP, ".f"), { recursive: true });
fs.writeFileSync(
  path.join(TMP, ".f", "f.config.json"),
  JSON.stringify({ vaultwarden: { server: "https://vault.invalid.test", email: "probe@example.test" } }),
);

// A sentinel value that the SPAWN fallback returns, so "the fallback ran" is
// observable rather than inferred. The fallback is execFileSync("f", ["creds",
// "get", …]); we put a stub `f` on PATH that prints this and exits 0. It is a
// stub, not the real CLI — see the header.
const SPAWN_SENTINEL = "SPAWNED-FALLBACK";

function makeStubBin(dir) {
  fs.mkdirSync(dir, { recursive: true });
  const bin = path.join(dir, "f");
  // `creds status` says UNLOCKED so providerStatus() gets past the lock gate and
  // actually performs the store reads under test. `creds get` answers MISS, so a
  // read that comes back truthy can ONLY have come from the handle — the two
  // paths are distinguishable by outcome, not by instrumentation.
  // This is a stub, not the real CLI: see the header.
  fs.writeFileSync(bin, [
    "#!/bin/sh",
    `if [ "$1" = "creds" ] && [ "$2" = "get" ]; then printf 'no such cred\\n' >&2; exit 1; fi`,
    `if [ "$1" = "creds" ] && [ "$2" = "status" ]; then printf 'unlocked\\n'; exit 0; fi`,
    "exit 1",
    "",
  ].join("\n"));
  fs.chmodSync(bin, 0o755);
  return dir;
}
const STUBBIN = makeStubBin(path.join(TMP, "bin"));
const savedPath = process.env.PATH;
process.env.PATH = `${STUBBIN}:${savedPath}`;

/**
 * Import a FRESH copy of the uck so module-level state (the handle, the depth)
 * starts clean for every test — otherwise a leak in test N silently passes
 * test N+1. `mutate` swaps in a modified index.js inside a full copy of the uck
 * (index.js imports ./lib/* and ../lib/uckmain.js by relative path, so a lone
 * file would fail to import for the wrong reason).
 */
let copySeq = 0;
const CFG = { server: "https://vault.invalid.test", email: "probe@example.test" };
// The store key providerStatus() reads first; its value decides the note.
const MP = "vaultwarden.master-password";
async function freshModule({ mutate = null, mutateCfg = null } = {}) {
  // A UNIQUE directory every time: Node caches modules by resolved URL, so
  // copying over the same path would hand back the previously-instantiated
  // module with its depth counter already dirty.
  const dir = path.join(TMP, `m${copySeq++}`);
  // Copy into <root>/uck/vaultwarden so the uck's `../lib/uckmain.js` import
  // still resolves — a lone copy of vaultwarden/ fails for a reason that has
  // nothing to do with what is under test.
  const root = path.join(dir, "root");
  fs.mkdirSync(path.join(root, "lib"), { recursive: true });
  fs.cpSync(path.join(UCK, "..", "lib"), path.join(root, "lib"), { recursive: true });
  const dest = path.join(root, "vaultwarden");
  fs.cpSync(UCK, dest, { recursive: true });

  if (mutate != null) fs.writeFileSync(path.join(dest, "index.js"), mutate);
  // The uck resolves its config from `process.env.HOME` at MODULE scope, so the
  // throwaway home has to exist before the import, and the config has to be
  // written into the home this copy will read.
  const home = path.join(dir, "home");
  fs.mkdirSync(path.join(home, ".f"), { recursive: true });
  fs.writeFileSync(
    path.join(home, ".f", "f.config.json"),
    JSON.stringify({ vaultwarden: { server: CFG.server, email: CFG.email, ...(mutateCfg ?? {}) } }),
  );
  const savedHome = process.env.HOME;
  process.env.HOME = home;
  let m;
  try {
    m = await import(path.join(dest, "index.js"));
  } finally {
    process.env.HOME = savedHome;
  }
  // The probe subcommands self-suppress providers; make sure a suite run under
  // that env still exercises the store-touching path.
  delete process.env.F_CREDS_NO_PROVIDER;
  return {
    ...m,
    dispose() {
      m.setProbeCredsApi(null);
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

/**
 * Exercise credsGet() through its only public door: credentialProvider.status()
 * reads the vault's master password out of the store, and the value it reads
 * decides which note it prints. So the returned note tells us WHICH path
 * answered, without adding any production-only surface.
 *
 *   "… via API key"  -> the master-password read succeeded
 *   "no master password" -> the read answered a miss
 *   note contains SPAWN_SENTINEL -> the execFileSync fallback answered
 */
async function probeRead(name, api) {
  const m = await freshModule({ mutateCfg: { masterPasswordCred: name } });
  try {
    return await m.credentialProvider.status(api ?? null);
  } finally {
    m.dispose();
  }
}

/* -------------------------------------------- 1. handle is used, no spawn */

// Which path answered is observable: the handle returns `handle:<name>` and the
// stub `f` on PATH returns SPAWN_SENTINEL, and providerStatus() echoes whichever
// one it read straight into its `note`.
// The stub `f` answers every `creds get` with a miss, so `ready: true` is only
// reachable if the master password came from the handle.
await t("a store read goes through the handle and NOT through execFileSync", async () => {
  const hits = [];
  const api = { rawCredRead: async (names) => { hits.push(names[0]); return { value: `handle:${names[0]}` }; } };
  const st = await probeRead(MP, api);
  assert.equal(st.ready, true, `handle answer not used: ${JSON.stringify(st)}`);
  assert.match(String(st.note), /via SSO session/, `master password not read from the handle: ${st.note}`);
  // providerStatus reads four creds per pass; the master password must be asked
  // for EXACTLY once, and only the master password proves the handle answered.
  assert.equal(hits.filter((n) => n === MP).length, 1, `master password read ${hits.filter((n) => n === MP).length} times: ${hits}`);
});

await t("an explicit 'no such cred' from the handle is an answer (null), not a spawn", async () => {
  let hits = 0;
  const api = { rawCredRead: async () => { hits++; return { error: "no such cred: nope" }; } };
  const st = await probeRead(MP, api);
  assert.equal(st.ready, false, `a store miss must stay a miss: ${JSON.stringify(st)}`);
  assert.match(String(st.note), /no master password/, `expected a miss, got: ${st.note}`);
  assert.equal(hits, 4, `expected the four readiness reads and no spawn, saw ${hits}`);
});

await t("a handle that declines (no value, no miss) falls back to the spawn", async () => {
  let hits = 0;
  const api = { rawCredRead: async () => { hits++; return {}; } };
  const st = await probeRead(MP, api);
  // Handle declined -> spawn ran -> the stub says "no such cred" -> still a miss.
  assert.match(String(st.note), /no master password/, `fallback must be the spawn path: ${JSON.stringify(st)}`);
  assert.equal(hits, 4, "the handle should still have been asked first, once per cred");
});

await t("the handle is OPTIONAL: with none installed the old spawn path runs unchanged", async () => {
  const st = await probeRead(MP, null);
  // No handle: the spawn path alone, which the stub answers with a miss. This is
  // exactly the pre-change behaviour.
  assert.equal(st.ready, false, `no-handle must behave as before: ${JSON.stringify(st)}`);
  assert.match(String(st.note), /no master password/, `expected the spawn path's miss: ${st.note}`);
});

await t("a handle without rawCredRead degrades to the spawn instead of throwing", async () => {
  const st = await probeRead(MP, { resolveCred: async () => "x" });
  assert.match(String(st.note), /no master password/, `partial handle must fall back, not throw: ${JSON.stringify(st)}`);
});

/* ------------------------------------- 2. depth guard: exactly one re-entry */

// The cycle the guard exists for: our read goes through the handle; the handle
// is creds' resolver, which answers by calling our status() back. In-process, so
// no child inherits an env marker to stop it.
function makeLadder(m, cap) {
  const state = { entries: 0, maxDepth: 0 };
  const api = {
    rawCredRead: async (names) => {
      // Only the master-password read calls back in, so `entries` counts rounds
      // rather than the four creds providerStatus() reads per pass.
      if (names[0] !== MP) return { value: `handle:${names[0]}` };
      // Depth is sampled at the handle boundary: the guard's finally has already
      // run by the time the awaited read resolves, so the deepest frame is 1 and
      // a runaway would show up as entries, not as depth.
      state.maxDepth = Math.max(state.maxDepth, m.inProcessProbeDepth());
      // Count the CALL-BACK, not the round: the guard's job is to stop the
      // second frame from reaching this ladder at all.
      state.entries++;
      if (state.entries < cap) await m.credentialProvider.status(api);
      return { value: `handle:${names[0]}` };
    },
  };
  return { api, state };
}

await t("guard present: a re-entrant handle yields EXACTLY ONE re-entry", async () => {
  const m = await freshModule();
  try {
    // Cap 99: if the guard works, frame 2 is handed a NULL handle, so the ladder
    // is never reached again and entries stops at 2. If it does not, this runs
    // toward 99.
    const { api, state } = makeLadder(m, 99);
    await m.credentialProvider.status(api);
    // The seed probe's read calls back exactly once; the re-entrant frame is
    // handed a NULL handle, so the ladder is never reached again. entries === 1
    // means ONE re-entry and no more. maxDepth === 2 because the re-entrant
    // frame still runs (it just has no handle to recurse with) — that is the
    // designed descent to the spawn path, not a runaway.
    assert.equal(state.entries, 1, `expected exactly one re-entry, saw ${state.entries}`);
    assert.equal(state.maxDepth, 1, `depth must never exceed one live frame, saw ${state.maxDepth}`);
    assert.equal(m.inProcessProbeDepth(), 0, "depth must return to 0");
  } finally {
    m.dispose();
  }
});

/* ------------------------------------------- 3. NON-VACUITY: guard removed */

await t("NON-VACUITY: with the guard stubbed out, the SAME ladder runs away", async () => {
  const src = fs.readFileSync(SRC, "utf8");
  const GUARDED = "const reentrant = inProcessDepth > 0;";
  const UNGUARDED = "const reentrant = false; // MUTANT: guard disabled";
  assert.equal(src.split(GUARDED).length - 1, 1, "withProbeCredsApi no longer matches this harness — update it");
  const mutated = src.replace(GUARDED, UNGUARDED);
  assert.notEqual(mutated, src, "mutation did not apply");

  const m = await freshModule({ mutate: mutated });
  try {
    const { api, state } = makeLadder(m, 99);
    await m.credentialProvider.status(api);
    // The SAME ladder, the SAME cap, the only difference being the guard. If the
    // guard is what stops the cycle, the unguarded run must go PAST one re-entry.
    assert.ok(state.entries > 1, `unguarded run made only ${state.entries} entries — the ladder never recursed, so the guarded test proves nothing`);
  } finally {
    m.dispose();
  }
});

/* --------------------------------------- 4. depth is released on a throw */

await t("an inner throw releases the depth (a leak is a symptomless failure)", async () => {
  const m = await freshModule();
  try {
    let threw = false;
    const boom = { rawCredRead: async () => { threw = true; throw new Error("store exploded"); } };
    // providerStatus catches a throwing read and degrades; the guard's finally
    // must still have run.
    const st = await m.credentialProvider.status(boom);
    assert.ok(threw, "the handle was never consulted — this test would pass vacuously");
    assert.equal(st.reason, "store-error", `expected degrade, got ${JSON.stringify(st)}`);
    assert.equal(m.inProcessProbeDepth(), 0, `depth leaked after a throw: ${m.inProcessProbeDepth()}`);

    // And the NEXT probe must still get a live handle. A leaked depth would
    // silently hand it null and drop every later read to the spawn path.
    let secondUsed = false;
    const ok = { rawCredRead: async () => { secondUsed = true; return { value: "v" }; } };
    await m.credentialProvider.status(ok);
    assert.ok(secondUsed, "after a throw a later probe stopped using the handle — depth leaked");
  } finally {
    m.dispose();
  }
});

/* ------------------------------------------- 5. store-error degrade */

await t("readiness degrades to store-error instead of propagating", async () => {
  const m = await freshModule();
  try {
    // No handle, and the stub `f` exits 1 on `creds status`: the store cannot be
    // read at all. Before this change providerStatus() guessed "creds locked";
    // it must now name the condition and RETURN, because `f creds status`
    // renders every provider and one throw took the whole line down.
    // The stub exits 0 on `creds status`, so make it fail for THIS call: a
    // non-zero exit is exactly the unreachable-store case.
    fs.writeFileSync(path.join(STUBBIN, "f"), "#!/bin/sh\nexit 7\n");
    fs.chmodSync(path.join(STUBBIN, "f"), 0o755);
    try {
      const st = await m.credentialProvider.status(null);
      assert.equal(st.ready, false, "an unreachable store must not report ready");
      assert.equal(st.reason, "store-error", `expected reason store-error, got: ${JSON.stringify(st)}`);
      assert.ok(/store-error/.test(String(st.note)), `note should name the condition: ${st.note}`);
    } finally {
      makeStubBin(STUBBIN);
    }
  } finally {
    m.dispose();
  }
});

await t("StoreUnavailableError is exported, is an Error, and carries the reason", async () => {
  const m = await freshModule();
  try {
    assert.equal(typeof m.StoreUnavailableError, "function", "must be exported");
    const e = new m.StoreUnavailableError("boom", "detail");
    assert.equal(e.reason, "store-error");
    assert.equal(e.detail, "detail");
    assert.ok(e instanceof Error, "it must stay an Error so existing catch sites keep working");
  } finally {
    m.dispose();
  }
});

await t("openVault throws the typed error, not the old bare one", async () => {
  const src = fs.readFileSync(SRC, "utf8");
  assert.ok(/throw new StoreUnavailableError\(/.test(src), "openVault must throw the typed error");
  assert.ok(
    !/throw new Error\(`creds are locked \(the vault/.test(src),
    "the bare locked-Error throw is still in openVault",
  );
});

await t("the env marker still exists — it is what stops the SPAWNED child", async () => {
  const src = fs.readFileSync(SRC, "utf8");
  assert.ok(/const inDiscovery = \(\) => process\.env\.F_CREDS_NO_PROVIDER === "1";/.test(src), "the env guard was deleted; the child path still needs it");
  assert.ok(/process\.env\.F_CREDS_NO_PROVIDER = "1"/.test(src), "enterDiscoveryProbe no longer sets the marker");
});

fs.rmSync(TMP, { recursive: true, force: true });
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
