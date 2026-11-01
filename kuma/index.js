// f kuma — uptime-kuma service health as a cheap watch (public status page).
//
// Zero deps (node builtins + fetch, Node >= 20). JSON parsing is delegated to
// the system `jq` binary via spawnSync (house rule for this uck).
//
// NO CREDENTIALS. Only the two public tokenless endpoints are ever called:
//   GET <base>/api/status-page/heartbeat/status   per-monitor heartbeats
//   GET <base>/api/status-page/status             monitor id -> name
// Unauthenticated GETs of any OTHER path behind haproxy hit the SPA catch-all
// and return misleading 200 HTML — never probe others. `/metrics` exists but
// needs HTTP basic auth (API key as password); if a later increment needs it,
// the cred name is `kuma-token` — do not invent other cred names.
//
// Base resolution: --base flag > KUMA_URL env > https://uptime.kensand.net
//
// Commands:
//   f kuma watch [--json]    every monitor: UP/DOWN + last ping + summary (exit 0)
//   f kuma down  [--json]    only DOWN/PENDING/UNKNOWN monitors; exit 1 if any,
//                            silent clean exit 0 when all green (CI/watch-gateable)
//   f kuma raw               raw heartbeat JSON (debug)
//
// Exit codes: 0 ok · 1 down-detected or fetch/parse error · 2 usage.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_BASE = "https://uptime.kensand.net";
const TIMEOUT_MS = 15000;

const USAGE = `f kuma — uptime-kuma service health (public status page, tokenless)

usage:
  f kuma watch [--json]     one line per monitor: status, last ping, last check
                            (problems first) + "N/M UP" summary; exit 0
  f kuma down  [--json]     print only DOWN/PENDING/UNKNOWN monitors, exit 1;
                            all green = no output, exit 0 (use this in scripts)
  f kuma raw                raw heartbeat JSON (debug)

flags:
  --json          structured JSON records instead of text
  --base <url>    uptime-kuma base ($KUMA_URL, default ${DEFAULT_BASE})

exit: 0 ok · 1 down/error · 2 usage
`;

// jq does the join: heartbeat keys are monitor-id strings; the status page
// gives id->name. Problems sort before UP, then name. Fields: label, name,
// ping (bare int or ""), last-check time (seconds), msg.
const JQ = `
($hb[0].heartbeatList // {}) as $h
| ((($st[0].publicGroupList // []) | map(.monitorList // []) | add) // []) as $mons
| ($mons | map({key: (.id | tostring), value: .name}) | from_entries) as $names
| (([$h | keys[]] + [$mons[].id | tostring]) | unique) as $ids
| [ $ids[] | . as $id
    | (($h[$id] // []) | if length > 0 then last else null end) as $l
    | { id: ($id | tonumber? // $id),
        name: ($names[$id] // ("#" + $id)),
        code: (if $l == null then -1 else ($l.status // -1) end),
        ping: ($l.ping // null),
        time: (($l.time // "-") | split(".")[0]),
        msg: (($l.msg // "") | tostring) }
    | .label = (if .code == 1 then "UP" elif .code == 0 then "DOWN" elif .code == 2 then "PENDING" else "UNKNOWN" end) ]
| sort_by([(if .label == "UP" then 1 else 0 end), (.name | ascii_downcase)])
| .[] | [.label, .name, (if .ping == null then "" else ((.ping | round) | tostring) end), .time, .msg] | @tsv
`;

function fail(msg) {
  process.stderr.write(`f kuma: ${msg}\n`);
  process.exit(1);
}

function parseArgv(argv) {
  const flags = {};
  const pos = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-h" || a === "--help") { flags.help = true; continue; }
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      if (eq >= 0) { flags[a.slice(2, eq)] = a.slice(eq + 1); continue; }
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith("-")) { flags[key] = next; i++; }
      else flags[key] = true;
      continue;
    }
    pos.push(a);
  }
  return { flags, pos };
}

async function fetchJson(url) {
  let res;
  try {
    res = await fetch(url, { signal: AbortSignal.timeout(TIMEOUT_MS), headers: { accept: "application/json" } });
  } catch (e) {
    throw new Error(`${url}: ${e.cause?.message || e.message}`);
  }
  if (!res.ok) throw new Error(`HTTP ${res.status} from ${url}`);
  const text = await res.text();
  try { return JSON.parse(text); }
  catch { throw new Error(`non-JSON from ${url} (SPA catch-all HTML? wrong --base?)`); }
}

function joinRows(hb, st) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "f-kuma-"));
  try {
    const hbF = path.join(dir, "hb.json");
    const stF = path.join(dir, "st.json");
    fs.writeFileSync(hbF, JSON.stringify(hb));
    fs.writeFileSync(stF, JSON.stringify(st));
    const r = spawnSync("jq", ["-r", "-n", "--slurpfile", "hb", hbF, "--slurpfile", "st", stF, JQ], { encoding: "utf8" });
    if (r.error) {
      if (r.error.code === "ENOENT") fail("jq not found on PATH — this uck parses with jq (pacman -S jq / apt install jq)");
      throw r.error;
    }
    if (r.status !== 0) fail(`jq failed: ${(r.stderr || "").trim() || `exit ${r.status}`}`);
    return (r.stdout || "")
      .split("\n").filter(Boolean)
      .map((line) => {
        const [label, name, ping, time, msg] = line.split("\t");
        return { label, name, ping: ping === "" ? null : Number(ping), time, msg: msg || "" };
      });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function fmtRow(r, nameW) {
  const ping = r.ping === null ? "—" : `${r.ping}ms`;
  const extra = r.label === "UP" || !r.msg ? "" : `  ${r.msg}`;
  return `${r.label.padEnd(7)}  ${r.name.padEnd(nameW)}  ${ping.padStart(7)}  ${r.time}${extra}`;
}

async function gather(base) {
  let hb, st;
  try {
    [hb, st] = await Promise.all([
      fetchJson(`${base}/api/status-page/heartbeat/status`),
      fetchJson(`${base}/api/status-page/status`),
    ]);
  } catch (e) {
    fail(e.message);
  }
  if (!hb || typeof hb.heartbeatList !== "object" || hb.heartbeatList === null) fail("heartbeat JSON has no heartbeatList — wrong base URL?");
  if (!Array.isArray(st?.publicGroupList)) fail("status JSON has no publicGroupList — wrong base URL?");
  return joinRows(hb, st);
}

export function register(_ctx) {
  return {
    name: "kuma",
    desc: "uptime-kuma health: f kuma watch|down|raw (public status page, no token)",
    skills: [{ name: "f-kuma", path: path.join(here, "SKILL.md") }],
    run: async (argv, _args) => {
      const { flags, pos } = parseArgv(Array.isArray(argv) ? argv : []);
      const cmd = pos[0];
      if (flags.help || !cmd) { process.stdout.write(USAGE); return flags.help ? 0 : process.exit(2); }
      if (cmd === "watch" || cmd === "down" || cmd === "raw") {
        const base = String(flags.base || process.env.KUMA_URL || DEFAULT_BASE).replace(/\/+$/, "");
        if (cmd === "raw") {
          try { process.stdout.write(JSON.stringify(await fetchJson(`${base}/api/status-page/heartbeat/status`), null, 2) + "\n"); }
          catch (e) { fail(e.message); }
          return;
        }
        const rows = await gather(base);
        const bad = rows.filter((r) => r.label !== "UP");
        if (flags.json) {
          process.stdout.write(JSON.stringify(cmd === "down" ? bad : rows, null, 2) + "\n");
          if (cmd === "down" && bad.length) process.exit(1);
          return;
        }
        if (cmd === "watch") {
          const nameW = Math.max(...rows.map((r) => r.name.length), 5);
          for (const r of rows) console.log(fmtRow(r, nameW));
          const up = rows.length - bad.length;
          const probs = bad.length ? " — " + ["DOWN", "PENDING", "UNKNOWN"].map((l) => `${bad.filter((r) => r.label === l).length} ${l}`).filter((s) => !s.startsWith("0 ")).join(", ") : "";
          console.log(`${up}/${rows.length} UP${probs}`);
          return;
        }
        // down
        if (!bad.length) return; // clean exit, no output
        const nameW = Math.max(...bad.map((r) => r.name.length), 5);
        for (const r of bad) console.log(fmtRow(r, nameW));
        process.exit(1);
        return;
      }
      process.stderr.write(`f kuma: unknown command '${cmd}'\n`);
      process.stdout.write(USAGE);
      process.exit(2);
    },
  };
}
export default { register };
