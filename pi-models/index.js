// f pi-models — carry pi's model providers (~/.pi/agent/models.json) between
// machines through the encrypted creds store.
//
// Thin wrapper over `f creds files`, which is the general mechanism: the key IS
// the destination, stored as `file:~/<path>` so one entry works on every host
// (/home/kenny is not /data/data/com.termux/files/home). This uck only adds the
// JSON validation and the legacy migrations. Zero deps; content never travels
// through argv (that put API keys in process lists before).

import { existsSync, readFileSync, writeFileSync, copyFileSync, chmodSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const REL = ".pi/agent/models.json";          // relative to $HOME on every host
const KEY = "file:~/" + REL;                  // what pack stores for that path
const LEGACY_CRED = "pi-models";              // old: whole file as one string cred
const tail = "/" + REL.split("/").slice(-1).join("");  // "/models.json"

const target = () => path.join(homedir(), REL);

/** Run `f creds …`. Returns { code, out, err } — no shell, no argv expansion. */
function creds(...args) {
  const r = spawnSync("f", ["creds", ...args], { encoding: "utf8" });
  if (r.error) throw new Error(`cannot run f creds: ${r.error.message}`);
  return { code: r.status, out: r.stdout ?? "", err: (r.stderr ?? "").trim() };
}

function needUnlocked() {
  const st = creds("status");
  if (!/unlocked/.test(st.out)) {
    console.error("pi-models: creds are locked — run 'f creds unlock' (passkey) first");
    process.exit(1);
  }
}

function readManifest() {
  const r = creds("files", "ls", "--json");
  if (r.code !== 0) return {};
  try {
    return JSON.parse(r.out) ?? {};
  } catch {
    return {};
  }
}

function validJson(text, where) {
  try {
    const j = JSON.parse(text);
    if (!j || typeof j !== "object" || !j.providers) throw new Error("no 'providers' key");
    return true;
  } catch (e) {
    console.error(`pi-models: ${where} is not a models.json (${e.message}) — refusing to touch it`);
    process.exit(1);
  }
}

/** Any legacy absolute key that points at a models.json (packed on another host). */
function legacyKeys(manifest) {
  return Object.keys(manifest).filter(
    (k) => k.startsWith("file:/") && k.endsWith(tail),
  );
}

function save() {
  const p = target();
  if (!existsSync(p)) {
    console.error(`pi-models: ${p} not found — nothing to save`);
    process.exit(1);
  }
  const raw = readFileSync(p, "utf8");
  validJson(raw, p);
  needUnlocked();
  const r = creds("files", "pack", p, "--force");
  process.stdout.write(r.out);
  if (r.code !== 0) { console.error(`pi-models: ${r.err}`); process.exit(1); }
}

function restore() {
  needUnlocked();
  const r = creds("files", "unpack", "~/" + REL, "--force");
  if (r.code !== 0) {
    const stuck = legacyKeys(readManifest());
    console.error(`pi-models: nothing packed at ${KEY} (${r.err || "no such cred"})`);
    if (stuck.length) console.error(`pi-models: found a legacy absolute key — run: f pi-models migrate`);
    else console.error("pi-models: run 'f pi-models save' on the machine that has the file");
    process.exit(1);
  }
  process.stdout.write(r.out);
  const p = target();
  validJson(readFileSync(p, "utf8"), p);
  console.log(`pi-models: ${p} restored and parses`);
}

/**
 * Move old shapes onto the portable key:
 *   1. legacy absolute manifest key (packed from another home)  -> relabel
 *   2. legacy string cred 'pi-models' (whole file in one value)  -> file + pack
 */
function migrate() {
  needUnlocked();
  const manifest = readManifest();
  let did = 0;

  for (const k of legacyKeys(manifest)) {
    if (k === KEY) continue;
    const r = creds("files", "relabel", k, "~/" + REL, "--force");
    if (r.code !== 0) { console.error(r.err); process.exit(1); }
    process.stdout.write(r.out);
    did++;
  }

  if (!did) {
    const g = creds("get", LEGACY_CRED, "--secrets");
    if (g.code === 0 && g.out.trim()) {
      validJson(g.out, `creds:${LEGACY_CRED}`);
      const p = target();
      if (existsSync(p)) copyFileSync(p, `${p}.bak`);
      writeFileSync(p, g.out, { mode: 0o600 });
      chmodSync(p, 0o600);
      const r = creds("files", "pack", p, "--force");
      process.stdout.write(r.out);
      if (r.code !== 0) { console.error(r.err); process.exit(1); }
      console.log(`pi-models: creds:${LEGACY_CRED} migrated to ${KEY}`);
      console.log(`pi-models: the old string cred is still there — drop it with: f creds rm ${LEGACY_CRED}`);
      did++;
    }
  }

  if (!did) console.log(`pi-models: nothing to migrate (${KEY} already portable, no legacy shapes found)`);
}

function status() {
  const open = /unlocked/.test(creds("status").out);
  const manifest = open ? readManifest() : {};
  const entry = manifest[KEY];
  const local = existsSync(target());
  const bits = !open
    ? "creds locked (f creds unlock)"
    : entry
    ? `packed ${entry.bytes}B mode ${(entry.mode ?? 420).toString(8)}${entry.root ? ` root ${entry.root}` : ""}${entry.host ? ` host ${entry.host}` : ""}`
    : "not packed";
  console.log(`${KEY}\t${bits}\tlocal ${local ? "present" : "absent"}`);
  const stuck = legacyKeys(manifest).filter((k) => k !== KEY);
  if (stuck.length) console.log(`legacy: ${stuck.join(" ")} — run: f pi-models migrate`);
}

export function register(_ctx) {
  return {
    name: "pi-models",
    desc: "move ~/.pi/agent/models.json across machines via 'f creds files' (key: file:~/)",
    run: (_argv, args) => {
      const cmd = args._?.[0];
      try {
        if (cmd === "save") return save();
        if (cmd === "restore") return restore();
        if (cmd === "migrate") return migrate();
        if (cmd === "status") return status();
      } catch (e) {
        console.error(`pi-models: ${e.message}`);
        process.exit(1);
      }
      console.error("usage: f pi-models <save|restore|migrate|status>");
      process.exit(2);
    },
    skills: [{ name: "f-pi-models", path: path.join(path.dirname(new URL(import.meta.url).pathname), "SKILL.md") }],
  };
}
export default { register };
