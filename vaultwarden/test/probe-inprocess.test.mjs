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
import { createRequire } from "node:module";

const here = path.dirname(fileURLToPath(import.meta.url));
const UCK = path.join(here, "..");
const SRC = path.join(UCK, "index.js");

let pass = 0, fail = 0;
async function t(name, fn) {
  try {
    // Rebuild the shared stub before EVERY test. The stub lives at TMP/bin and
    // is first on PATH for the whole suite; a test that overwrites it (or whose
    // dispose() removes the tree under it) would otherwise leave every LATER
    // spawn failing with ENOENT — and credsGet() reports ENOENT as a
    // store-error, which satisfies "the spawn path answered" exactly as well as
    // a real miss. Measured here: with the stub gone, three spawn-path
    // assertions passed while testing nothing.
    makeStubBin(path.join(TMP, "bin"));
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
  // A REAL dispatcher, not a fixed-answer script: the suite runs in a throwaway
  // HOME with no `f` and no creds uck on the path, so a spawn that reaches the
  // real CLI fails with "unknown uck 'creds'" and every spawn-path assertion
  // then passes for the wrong reason (it would also pass against a broken
  // provider). This stub answers the three shapes this uck actually spawns, so
  // "the spawn path answered" is a conclusion drawn from a real child process.
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
 * Prove, before every spawn-path conclusion, that the stub is really the `f`
 * that will answer. If it is missing or answers something else, a spawn fails
 * with ENOENT — and credsGet() turns that into a store-error, which satisfies
 * "the spawn path answered" exactly as well as a real miss does. That is how a
 * spawn-path assertion goes vacuous, so it is checked rather than assumed.
 */
function assertStubAnswers(expected = "unlocked") {
  const probe = execFileSyncProbe(path.join(STUBBIN, "f"), ["creds", "status"]);
  if (probe !== expected) {
    throw new Error(`the stub at ${STUBBIN}/f does not answer "creds status" as "${expected}" (got "${probe}") — spawn-path assertions below would be vacuous`);
  }
}

function execFileSyncProbe(bin, args) {
  // Local require of spawnSync without importing child_process at module scope:
  // the uck under test imports it too and a top-level import here has been a
  // source of stubbing confusion in this suite.
  const { spawnSync } = require_child_process();
  const r = spawnSync(bin, args, { encoding: "utf8" });
  return r.status === 0 ? String(r.stdout ?? "").trim() : `EXIT ${r.status} ${String(r.error?.message ?? r.stderr ?? "").trim()}`;
}

let _cp = null;
function require_child_process() {
  if (_cp === null) {
    // createRequire is the ESM-safe way to get the sync child API here.
    _cp = createRequire(import.meta.url)("node:child_process");
  }
  return _cp;
}

/**
 * Run `fn` with a `f` that cannot answer at all first on PATH, then restore.
 *
 * Shared on purpose: every test that needs a dead store must go through here so
 * the restore always returns to the SUITE's PATH (stub first), never to a value
 * captured before the suite's own swap. A restore to the wrong baseline drops
 * the stub from PATH and every later spawn silently reaches the host's real
 * `f` — which answers "unknown uck 'creds'", and a spawn that FAILS looks
 * exactly like a spawn that answered "no such cred". That is how a spawn-path
 * assertion becomes vacuous.
 */
async function withDeadStore(fn) {
  const dir = fs.mkdtempSync(path.join(TMP, "dead-"));
  fs.writeFileSync(path.join(dir, "f"), "#!/bin/sh" + String.fromCharCode(10) + "exit 7" + String.fromCharCode(10));
  fs.chmodSync(path.join(dir, "f"), 0o755);
  const saved = process.env.PATH;
  process.env.PATH = `${dir}:${STUBBIN}:${savedPath}`;
  try {
    return await fn();
  } finally {
    process.env.PATH = `${STUBBIN}:${savedPath}`;
    // The dead store must not have taken the shared stub with it.
    assertStubAnswers();
  }
}

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
  // The copy's OWN stub bin goes first on PATH, for the whole life of the copy
  // (restored in dispose()). Two failure classes this closes: resolving the
  // REAL `f` on the host (a different uck tree, a different store, a spawn that
  // answers "unknown uck 'creds'"), and resolving a shared stub that an earlier
  // test's dispose() already deleted (ENOENT). Both come back as a store-error,
  // and a store-error satisfies "the spawn path answered" exactly as well as a
  // real miss does — which is how a spawn-path assertion goes vacuous.
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
  // 4 readiness reads + 1 store-open gate. The gate is the read that replaced
  // the `f creds status` child; it asks a fixed probe name, never one of the
  // four below, so it cannot perturb what the readiness reads report.
  assert.equal(hits, 5, `expected the four readiness reads plus the store-open gate and no spawn, saw ${hits}`);
});

await t("a handle that declines (no value, no miss) falls back to the spawn", async () => {
  let hits = 0;
  const api = { rawCredRead: async () => { hits++; return {}; } };
  const st = await probeRead(MP, api);
  // Handle declined -> spawn ran -> the stub says "no such cred" -> still a miss.
  assert.match(String(st.note), /no master password/, `fallback must be the spawn path: ${JSON.stringify(st)}`);
  // 4 readiness reads + 1 store-open gate, both of which declined, so the spawn
  // answered all five questions.
  assert.equal(hits, 5, "the handle should still have been asked first, once per cred plus the store-open gate");
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
    // A dedicated dir FIRST on PATH, restored in `finally`. The shared STUBBIN
    // is deliberately NOT mutated: it is on PATH for the whole suite, and an
    // always-fail script left there (or restored after this test's dispose()
    // deleted the tree) silently changes every later test's spawn outcome.
    const st = await withDeadStore(() => m.credentialProvider.status(null));
    assert.equal(st.ready, false, "an unreachable store must not report ready");
    assert.equal(st.reason, "store-error", `expected reason store-error, got: ${JSON.stringify(st)}`);
    assert.ok(/store-error/.test(String(st.note)), `note should name the condition: ${st.note}`);
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

/* ------------------------- 6. the store-open gate replaces the status child */

// `credsStatus()` used to be the last unconditional child on the status path:
// one `execFileSync("f", ["creds","status"])` per readiness probe, which is the
// spawn that survived every earlier handle change. It now asks the handle first.
//
// Which path answered is observable WITHOUT instrumentation: the stub `f` on
// PATH answers `creds status` with "locked", so a spawn-gated probe can only
// ever report `creds locked`. A handle that answers with a value therefore shows
// up as a readiness note that mentions SSO/API key. Handle-off and handle-on
// give different answers to the same question, so "the handle answered" is a
// conclusion the test draws from the outcome, not from a counter.
const STATUS_PROBE = "vaultwarden.probe-store-open";

await t("the store-open gate answers through the handle and the status child never runs", async () => {
  const hits = [];
  // The stub `f` on PATH answers `creds status` with "unlocked" and every
  // `creds get` with a MISS. So if the CHILD settled the gate, the readiness
  // reads would go to the child and the note would be "no master password".
  // Answering every name from the handle instead makes the gated outcome
  // "via SSO session" — a note the spawn path cannot produce against this stub.
  const api = {
    rawCredRead: async (names) => {
      hits.push(names[0]);
      return { value: `handle:${names[0]}` };
    },
  };
  const st = await probeRead(MP, api);
  assert.ok(hits.includes(STATUS_PROBE), `the gate never asked the handle: ${hits}`);
  assert.equal(st.ready, true, `handle-settled gate should reach readiness: ${JSON.stringify(st)}`);
  assert.match(String(st.note), /via SSO session/, `the child answered, not the handle: ${st.note}`);
  // Asked EXACTLY once, and asked BEFORE any readiness read — it is the gate.
  assert.equal(hits.filter((n) => n === STATUS_PROBE).length, 1, `gate read ${hits.filter((n) => n === STATUS_PROBE).length} times: ${hits}`);
  assert.equal(hits[0], STATUS_PROBE, `the gate must run first: ${hits}`);
});

await t("NON-VACUITY: with the gate removed the SAME handle+fixture is answered by the child, not the handle", async () => {
  // The pair of tests above could both pass if the gate simply did not exist
  // (the miss path also avoids "creds locked"). So run the SAME handle and the
  // SAME stub against a mutant with the gate disabled: the only difference in
  // the outcome must be that the child answered instead.
  const gsrc = fs.readFileSync(SRC, "utf8");
  // Pin the gate's decision line by regex: a mutant that equals its source
  // tests nothing, and a plain-string anchor silently becomes a no-op the
  // moment someone reindents the line.
  const GATED = /^([ 	]*)if \(local !== undefined\) return local;$/m;
  assert.ok(GATED.test(gsrc), "credsStatus no longer has the store-open gate line — update this harness");
  const mutated = gsrc.replace(GATED, "$1// MUTANT: store-open gate disabled, always spawn");
  assert.notEqual(mutated, gsrc, "mutation did not apply");

  // Guard the harness itself: if the stub is not first on PATH, the spawn below
  // reaches the REAL `f` on this box, which answers "unknown uck 'creds'" — a
  // spawn that FAILS, and indistinguishable from one that answered a miss. Fail
  // loudly here rather than let the assertion below pass for the wrong reason.
  assert.ok(process.env.PATH.split(":")[0] === STUBBIN, `the stub is not first on PATH (${process.env.PATH.split(":")[0]}); this harness would test the real CLI`);
  assertStubAnswers();

  const m = await freshModule({ mutate: mutated, mutateCfg: { masterPasswordCred: MP } });
  try {
    const hits = [];
    const api = {
      rawCredRead: async (names) => {
        hits.push(names[0]);
        if (names[0] === STATUS_PROBE) return { value: "store-is-open" };
        return { error: `no such cred: ${names[0]}` };
      },
    };
    // Answer EVERY name from the handle. Then the ONLY thing that can decide
    // the note is which path settled the lock gate: handle -> the store is open
    // -> the readiness reads run and report SSO; child -> the stub's verdict is
    // used, and the readiness reads go to the child (a miss) -> "no master
    // password". One bit of the outcome, and it is owned entirely by the gate.
    const allApi = {
      rawCredRead: async (names) => {
        hits.push(names[0]);
        return { value: `handle:${names[0]}` };
      },
    };
    const st = await m.credentialProvider.status(allApi);
    m.setProbeCredsApi(null);
    // The gate read still HAPPENS in the mutant — it lives inside credsStatus(),
    // which still runs. What the mutation discards is its ANSWER, so the child
    // settles the gate and the readiness reads go to the child (a miss) instead
    // of the handle. The gated run above reaches "via SSO session"; this one
    // cannot. Same handle, same stub, same fixture — the note is the whole
    // difference, and the note is owned by the gate.
    assert.match(String(st.note), /no master password/, `mutant must be answered by the child: ${JSON.stringify(st)}`);
  } finally {
    m.dispose();
  }
});

/* ------------------------------ 7. the gate must NOT re-enter status() ---- */

// The recursion this change could have introduced: `status()` asks the store
// whether it is open; the naive way to ask is to call the provider's own
// `status()` (or creds' ladder, which calls it). In-process there is no child to
// inherit the env marker, so that is a direct cycle and it would take the box
// down exactly the way the spawn version's fork bomb did.
//
// The guard is withProbeCredsApi's depth counter: a frame past the first is
// handed a NULL handle, so a re-entrant descent falls through to the spawn
// instead of recursing. This test proves the descent STOPS, with a bounded
// timeout so a real cycle fails the run instead of hanging it.
function makeStatusLadder(m, cap) {
  const state = { calls: 0, maxDepth: 0 };
  const api = {
    rawCredRead: async (names) => {
      state.maxDepth = Math.max(state.maxDepth, m.inProcessProbeDepth());
      // Every handle read — the gate's included — calls status() straight back.
      // This is strictly harsher than a real ladder: a real one calls back only
      // on some names, this one calls back on ALL of them.
      state.calls++;
      if (state.calls < cap) await m.credentialProvider.status(api);
      return { error: `no such cred: ${names[0]}` };
    },
  };
  return { api, state };
}

await t("recursion guard: status-via-handle does not re-enter status (bounded at 20s)", async () => {
  const m = await freshModule();
  try {
    const { api, state } = makeStatusLadder(m, 99);
    // Bounded so a broken guard shows up as a failing test, not a hung suite.
    const ran = await Promise.race([
      m.credentialProvider.status(api).then(() => "done"),
      new Promise((r) => setTimeout(() => r("timeout"), 20000)),
    ]);
    assert.equal(ran, "done", "status() never returned — the store-open gate re-enters status()");
    // Frame 1 asks the gate, which calls back. Frame 2 is handed a NULL handle
    // by the depth guard, so the ladder is never reached again: exactly ONE
    // call-back, and never more than one live frame.
    // The guard bounds DEPTH, not call count. Frame 2 is handed a NULL handle,
    // so the provider never hands a handle to a second frame — but a ladder
    // built like this one closes over `api` and passes it on explicitly, so the
    // descent continues through the handle the LADDER holds. That is the
    // fixture's shape, not the provider's guard. The load-bearing claims are
    // therefore (a) it TERMINATES inside the 20s bound — a real
    // status->handle->status cycle does not — and (b) no second frame ever ran
    // with a handle the provider gave it.
    assert.equal(state.maxDepth, 1, `a second frame must never hold a provider-supplied handle, saw depth ${state.maxDepth}`);
    assert.ok(state.calls < 99, `the ladder ran to its cap (${state.calls}) — the descent never bottomed out`);
    assert.equal(m.inProcessProbeDepth(), 0, "depth must return to 0");
  } finally {
    m.dispose();
  }
});

await t("NON-VACUITY: with the depth guard stubbed out, the SAME ladder runs away", async () => {
  const gsrc = fs.readFileSync(SRC, "utf8");
  const GUARDED = "const reentrant = inProcessDepth > 0;";
  const UNGUARDED = "const reentrant = false; // MUTANT: guard disabled";
  assert.equal(gsrc.split(GUARDED).length - 1, 1, "withProbeCredsApi no longer matches this harness — update it");
  const mutated = gsrc.replace(GUARDED, UNGUARDED);
  assert.notEqual(mutated, gsrc, "mutation did not apply");

  const m = await freshModule({ mutate: mutated });
  try {
    const { api, state } = makeStatusLadder(m, 99);
    const ran = await Promise.race([
      m.credentialProvider.status(api).then(() => "done"),
      new Promise((r) => setTimeout(() => r("timeout"), 20000)),
    ]);
    // Either it blew past one re-entry (the guard is what stopped the guarded
    // run) or it never came back at all — both prove the guarded test is green
    // because of the guard.
    assert.ok(ran === "timeout" || state.calls > 1, `unguarded run made only ${state.calls} calls and returned "${ran}" — the ladder never recursed, so the guarded test proves nothing`);
  } finally {
    m.dispose();
  }
});

/* ------------------------- 8. the gate must not change what status REPORTS */

await t("the gate cannot turn a locked store into ready, nor a store-error into ready", async () => {
  // (a) handle answers a MISS, stub `f` says "locked" -> the spawn's verdict
  //     stands. The gate must not invent an unlock out of a miss.
  const miss = { rawCredRead: async () => ({ error: "no such cred: x" }) };
  const a = await probeRead(MP, miss);
  // The gate declines on a miss, so the CHILD's verdict stands — and the stub
  // says "unlocked", so readiness proceeds and reports the vault's own miss.
  // What must NEVER happen is the gate inventing an answer: ready:true out of a
  // miss, or a store-error the child never reported.
  assert.ok(!/store-error/.test(String(a.note ?? "")), `a miss is not a store failure: ${JSON.stringify(a)}`);
  assert.ok(a.ready === false || /via SSO session|via API key/.test(String(a.note ?? "")), `unexpected gate invention: ${JSON.stringify(a)}`);

  // (b) handle THROWS -> the gate declines, the spawn answers, and the
  //     readiness line is unchanged. A probe failure must never become the
  //     error the operator reads.
  const boom = { rawCredRead: async () => { throw new Error("handle exploded"); } };
  const b = await probeRead(MP, boom);
  assert.equal(b.ready, false, `a throwing handle must not report ready: ${JSON.stringify(b)}`);
  // A throwing read degrades to store-error by the pre-existing P3 rule, and
  // that is correct: a provider that cannot answer must say so rather than be
  // rewritten. The gate's own narrower contract is that it never reports ready
  // off a handle that declined — asserted above.
  assert.equal(b.reason, "store-error", `a throwing read still degrades by P3: ${JSON.stringify(b)}`);
});

await t("the store-error degrade still fires with no handle at all", async () => {
  // The degrade path must survive the gate: no handle, and a `f` that cannot
  // answer at all.
  // PATH is process-wide, so swap in a `f` that cannot answer for THIS test and
  // restore it in `finally`. The suite runs in one process; a leaked failing
  // stub would silently change every later test's spawn outcome.
  const m = await freshModule();
  try {
    const st = await withDeadStore(() => m.credentialProvider.status(null));
    assert.equal(st.ready, false, "an unreachable store must not report ready");
    assert.equal(st.reason, "store-error", `expected the degrade to survive the gate, got: ${JSON.stringify(st)}`);
    assert.match(String(st.hint ?? ""), /daemon running/, `the hint should still name the daemon: ${st.hint}`);
  } finally {
    m.dispose();
  }
});

/* ------------------------------- 9. P4: the child-process path is untouched */

await t("CONTRACT P4: the handle stays the LAST OPTIONAL parameter of every probe", async () => {
  const gsrc = fs.readFileSync(SRC, "utf8");
  // Detection must not use fn.length (a defaulted parameter reports 0), so pin
  // the SOURCE TEXT shape the caller's readsTrailingArg() reads.
  for (const [label, needle] of [
    ["status", "status: (credsApi = null) =>"],
    ["resolve", "resolve: async (name, credsApi = null) =>"],
    ["list", "list: async (credsApi = null) =>"],
  ]) {
    assert.equal(gsrc.split(needle).length - 1, 1, `${label} no longer takes the handle as its last OPTIONAL parameter`);
  }
  // And credsStatus is async now, with both call sites awaiting it — a missed
  // await here is SILENT (a Promise is always truthy, so `!status.unlocked`
  // would be false and a locked store would read as unlocked).
  assert.equal(gsrc.split("const status = await credsStatus();").length - 1, 1, "openVault does not await credsStatus()");
  assert.equal(gsrc.split("const st = await credsStatus();").length - 1, 1, "providerStatus does not await credsStatus()");
  // Count the call sites and require each to be awaited. Note that a naive
  // substring check cannot do this: `const st = await credsStatus();` CONTAINS
  // `= credsStatus();`, so counting that substring counts awaited sites too and
  // can never see a missing await. A missed await is SILENT (a Promise is
  // always truthy, so `!status.unlocked` reads false and a locked store looks
  // unlocked), which is exactly why this line is load-bearing.
  const sites = gsrc.match(/const \w+ = (?:await )?credsStatus\(\);/g) ?? [];
  assert.equal(sites.length, 2, `expected two credsStatus() call sites, saw ${sites.length}: ${sites}`);
  assert.equal(sites.filter((s) => !s.includes("await")).length, 0, `an un-awaited credsStatus() call site: ${sites}`);
});

process.exit(fail ? 1 : 0);
