// f ha — Home Assistant REST API: states, services, scenes, automations,
// history, weather, calendars, raw passthrough.
//
// Zero deps (node builtins + fetch, Node >= 20).
//
// Config: TWO creds (both optional per-instance; name them after the instance
// host, e.g. `ha.kensand.net`):
//   ha-host   the base url, e.g. `https://ha.kensand.net` (scheme optional)
//   ha-token  the long-lived access token
// A single cred `ha` holding `url|token` is also accepted as a combined form.
// Precedence: --url/--token flags and HA_URL/HA_TOKEN env win over creds.
// ha.baseUrl in f.config.json (project walked up, then global) is the
// last-resort base. Auth: `Authorization: Bearer <token>`.
//
// Commands:
//   f ha ls [query]            list entities, optionally filtered (substring
//                              match on entity_id/friendly_name, or
//                              domain prefix like `light`)
//   f ha ls <domain>           list entities of one domain
//   f ha state                 all states (entity  state  friendly_name)
//   f ha state <entity_id>     full state object (json)
//   f ha search <query>        = ls <query>
//   f ha call <domain> <service> [key=value ... | {json}]
//                               service call, e.g. f ha call light turn_on entity_id=light.kitchen
//   f ha scene <name>          turn on a scene (friendly name or scene.<id>)
//   f ha auto ls               list automations
//   f ha auto <name>           trigger an automation (friendly name or id)
//   f ha auto on|off <name>    set automation enabled state
//   f ha history <entity...> [-s start] [-e end] [--minimal]
//   f ha weather [entity]      current weather (default: weather.* first)
//   f ha cal [entity] [-s] [-e]  calendar events
//   f ha info                  /api/config summary
//   f ha urls                  resolved base + token source
//   f ha <METHOD> <path> [json] raw call, e.g. f ha GET /api/states/sensor.x
//
// Times: ISO 8601 or relative like 2h/1d/30m ago (bare `2h` means "ago").

import fs from "node:fs";
import path from "node:path";
import net from "node:net";
import { fileURLToPath as _f2p } from "node:url";
const _here = path.dirname(_f2p(import.meta.url));

const F = path.join(process.env.HOME ?? "", ".f");
const CRED_SOCKET = path.join(F, ".creds.sock");

// ---- output ----
function out(o) {
  if (o == null) return;
  if (typeof o === "string") { process.stdout.write(o.endsWith("\n") ? o : o + "\n"); return; }
  process.stdout.write(JSON.stringify(o, null, 2) + "\n");
}
function outLines(lines) {
  if (lines.length) process.stdout.write(lines.join("\n") + "\n");
}
function err(msg) {
  process.stderr.write("f ha: " + msg + "\n");
  process.exit(1);
}

// ---- time parsing ----
/** "2h" | "30m" | "1d" | "90s" | ISO 8601 | unix seconds -> ms epoch */
function parseTime(s, nowMs = Date.now()) {
  if (!s) return null;
  const rel = s.match(/^(\d+)([smhdw])$/);
  if (rel) {
    const n = Number(rel[1]);
    const mult = { s: 1000, m: 60000, h: 3600000, d: 86400000, w: 604800000 }[rel[2]];
    return nowMs - n * mult;
  }
  // ISO or date; Date.parse is lenient (accepts "2026-01-01", "2026-01-01T10:00", etc.)
  const t = Date.parse(s);
  if (Number.isFinite(t)) return t;
  const n = Number(s);
  if (Number.isFinite(n) && n > 1e9) return n * (n < 1e11 ? 1000 : 1);
  err(`cannot parse time: ${s} (use ISO 8601 or 30m/2h/1d/1w ago)`);
}

// ---- config resolution ----
function configBaseUrl() {
  const read = (p) => {
    try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch { return null; }
  };
  let dir = process.cwd();
  for (let i = 0; i < 8; i++) {
    const d = read(path.join(dir, "f.config.json"));
    if (d && d.ha && typeof d.ha.baseUrl === "string") return d.ha.baseUrl;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  const g = read(path.join(F, "f.config.json"));
  if (g && g.ha && typeof g.ha.baseUrl === "string") return g.ha.baseUrl;
  return null;
}

function resolveBaseUrl(flagUrl) {
  const raw = flagUrl || process.env.HA_URL || configBaseUrl();
  if (!raw) return null;
  let u = raw.replace(/\/+$/, "");
  if (!/^https?:\/\//.test(u)) u = "http://" + u;
  return u;
}

/** Parse a cred value: `url|token` (url without scheme gets http:// prepended),
 *  or a bare token (url part null). */
function splitCred(v) {
  const bar = v.indexOf("|");
  if (bar <= 0) return { url: null, token: v };
  let url = v.slice(0, bar).trim();
  const token = v.slice(bar + 1).trim();
  if (!/^https?:\/\//.test(url)) url = "http://" + url;
  return { url: url.replace(/\/+$/, ""), token };
}

function hostFromUrl(u) {
  try { return new URL(u).host; } catch { return u.replace(/^https?:\/\//, "").replace(/\/.*$/, ""); }
}

// ---- creds (same protocol as fj/pr ucks) ----
function daemonCall(req, socketPath) {
  return new Promise((resolve, reject) => {
    let buf = "";
    const client = net.connect(socketPath, () => { client.write(JSON.stringify(req)); });
    client.on("data", (d) => (buf += d));
    client.on("end", () => {
      try { resolve(JSON.parse(buf)); } catch { reject(new Error("bad daemon response: " + buf)); }
    });
    client.on("error", (e) => reject(e));
  });
}

function credsUnlocked() {
  let lf;
  try { lf = JSON.parse(fs.readFileSync(path.join(F, ".creds-daemon"), "utf8")); } catch { return null; }
  if (!lf || !lf.pid || !lf.start || !lf.ttl) return null;
  try { process.kill(lf.pid, 0); } catch { return null; }
  const remainingMs = lf.start + lf.ttl * 1000 - Date.now();
  return remainingMs > 0 ? { remainingMs, socket: lf.socket } : null;
}

/** Resolve {base, token, src, host, reason}.
 *
 *  Base: --url > HA_URL > ha.baseUrl config > host part of a combined cred.
 *  Token: --token > HA_TOKEN > combined-cred token part > `ha-token` cred
 *  (or `<host>-token` when the host is known). Never blocks by default;
 *  --wait opts into credsApi.wait for long jobs. */
async function resolveHa(flagUrl, flagToken, credsApi, opts = {}) {
  const base = resolveBaseUrl(flagUrl);
  const host = base ? hostFromUrl(base) : null;
  const hostNames = host && host.includes(":") ? [host, host.split(":")[0]] : host ? [host] : [];

  const state = credsUnlocked();
  const read = async (name) => {
    if (credsApi && typeof credsApi.get === "function") {
      try {
        return await credsApi.get(name);
      } catch (e) {
        if (e && /locked/i.test(e.message)) return { locked: true };
        return null;
      }
    }
    try {
      const r = await daemonCall({ op: "get", name }, state.socket || CRED_SOCKET);
      if (r && r.ok) return r.value;
      return null;
    } catch { return null; }
  };

  // combined cred (`ha` or host-named): `url|token`
  const combinedNames = [...new Set(["ha", ...hostNames])];
  let combined = null, combinedName = null, locked = false;
  for (const name of combinedNames) {
    const v = await read(name);
    if (v && v.locked) { locked = true; break; }
    if (v != null && v !== "") { combined = v; combinedName = name; break; }
  }
  const parts = combined ? splitCred(combined) : null;
  const provisionalBase = base || (parts && parts.url) || null;
  const provisionalHost = provisionalBase ? hostFromUrl(provisionalBase) : null;

  // separate host cred: `ha-host` or `<host>-host` (value = base url)
  let hostCred = null, hostCredName = null;
  if (state || opts.waitMs) {
    const hostCredNames = [...new Set(provisionalHost
      ? ["ha-host", provisionalHost + "-host", provisionalHost.split(":")[0] + "-host"]
      : ["ha-host", "ha"])];
    for (const name of hostCredNames) {
      if (combinedNames.includes(name)) continue; // combined form already matched
      const v = await read(name);
      if (v && v.locked) { locked = true; break; }
      if (v != null && v !== "") { hostCred = v; hostCredName = name; break; }
    }
  }

  let hostUrl = null;
  if (hostCred) {
    hostUrl = hostCred.replace(/\/+$/, "");
    if (!/^https?:\/\//.test(hostUrl)) hostUrl = "http://" + hostUrl;
  }

  const resolvedBase = base || hostUrl || (parts && parts.url) || null;
  const resolvedHost = resolvedBase ? hostFromUrl(resolvedBase) : null;

  let token = null, src = null;
  if (flagToken) { token = flagToken; src = "--token"; }
  else if (process.env.HA_TOKEN) { token = process.env.HA_TOKEN; src = "HA_TOKEN"; }
  else if (parts && parts.token) { token = parts.token; src = `creds:${combinedName}`; }
  else if (state || opts.waitMs) {
    const tokenNames = [...new Set(resolvedHost ? ["ha-token", resolvedHost + "-token", resolvedHost.split(":")[0] + "-token"] : ["ha-token", "ha"])];
    for (const name of tokenNames) {
      const v = await read(name);
      if (v && v.locked) { locked = true; break; }
      if (v != null && v !== "") { token = v; src = `creds:${name}`; break; }
    }
  }

  const failReason = !locked && !token && !resolvedBase
    ? "unset"
    : !locked && !token
      ? "no-token"
      : locked
        ? "locked"
        : null;

  return { base: resolvedBase, token, src, host: resolvedHost ?? hostNames[0] ?? "ha", reason: failReason, locked };
}

function needCred(ha) {
  if (ha.base && ha.token) return { base: ha.base, token: ha.token };
  if (ha.reason === "locked")
    err("creds are locked\n  unlock it: f creds unlock\n  or: f ha --token <tok> ...");
  const missing = [];
  if (!ha.base) missing.push("base url (f creds set <host>-host <url>, or --url, or HA_URL)");
  if (!ha.token) missing.push("token (f creds set <host>-token <token>, or --token, or HA_TOKEN)");
  err(
    `missing: ${missing.join(" + ")}\n` +
    `  store it: f creds set ${ha.host}-host <url>   and   f creds set ${ha.host}-token <token>\n` +
    `  or send them now: f ha ${ha.base ? "" : "--url <url> "}--token <tok> ...`,
  );
}

// ---- HTTP ----
async function haFetch(url, token, { method = "GET", body } = {}) {
  let res;
  try {
    res = await fetch(url, {
      method,
      headers: {
        Authorization: "Bearer " + token,
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(30000),
    });
  } catch (e) {
    err(`request to ${url} failed: ${e.message ?? e}`);
  }
  const text = await res.text();
  let data = null;
  if (text) {
    try { data = JSON.parse(text); } catch { data = text; }
  }
  if (!res.ok) {
    const msg = (data && typeof data === "object" && (data.message || data.msg)) || data || "";
    err(`HTTP ${res.status} ${msg}`.trim());
  }
  return data;
}

/** Make an authenticated request. path starts with /api. */
async function api(base, token, path, { method = "GET", body } = {}) {
  return haFetch(base.replace(/\/+$/, "") + (path.startsWith("/") ? path : "/" + path), token, { method, body });
}

// ---- arg helpers ----
function parseParams(tokens) {
  // one {json} token, else key=value pairs (JSON-parse values when they look like json)
  if (tokens.length === 1 && tokens[0].trim().startsWith("{")) {
    try { return JSON.parse(tokens[0]); } catch { err(`not valid JSON: ${tokens[0].slice(0, 80)}`); }
  }
  const params = {};
  for (const tok of tokens) {
    const eq = tok.indexOf("=");
    if (eq <= 0) err(`expected key=value, got: ${tok}`);
    const k = tok.slice(0, eq);
    const raw = tok.slice(eq + 1);
    let v = raw;
    if (raw !== "" && /^[[{\d-]|^(true|false|null)$/.test(raw)) {
      try { v = JSON.parse(raw); } catch { /* keep string */ }
    }
    params[k] = v;
  }
  return params;
}

function friendly(s) {
  return (s.attributes && (s.attributes.friendly_name || s.attributes.name)) || "";
}

// ---- entity commands ----
async function allStates(base, token) {
  const states = await api(base, token, "/api/states");
  if (!Array.isArray(states)) err("unexpected /api/states response");
  return states;
}

/** List entities: `entity_id  state  friendly_name` lines.
 *  Query semantics: exact domain (`light`), substring on id/friendly name,
 *  or `*`/empty for everything. */
function cmdList(query) {
  return async (base, token) => {
    const states = await allStates(base, token);
    const q = (query || "").toLowerCase();
    const isDomain = q !== "" && !q.includes(".") && !q.includes(" ");
    const rows = states.filter((s) => {
      if (!q) return true;
      const id = s.entity_id.toLowerCase();
      const fn = friendly(s).toLowerCase();
      if (isDomain) return id.startsWith(q + ".");
      if (q.includes("*")) {
        const re = new RegExp(q.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*"));
        return re.test(id) || re.test(fn);
      }
      return id.includes(q) || fn.includes(q);
    });
    outLines(rows.map((s) => {
      const fn = friendly(s);
      return `${s.entity_id}  ${s.state}${fn ? "  " + fn : ""}`;
    }));
  };
}

async function cmdState(base, token, entity) {
  if (!entity) {
    // all states, terse
    const states = await allStates(base, token);
    outLines(states.map((s) => {
      const fn = friendly(s);
      return `${s.entity_id}  ${s.state}${fn ? "  " + fn : ""}`;
    }));
    return;
  }
  const id = entity.includes(".") ? entity : null;
  if (!id) {
    // resolve via list (single match required)
    const states = await allStates(base, token);
    const hits = states.filter((s) => s.entity_id.toLowerCase().includes(entity.toLowerCase()) || friendly(s).toLowerCase().includes(entity.toLowerCase()));
    if (hits.length !== 1) err(`ambiguous entity '${entity}' (${hits.length} matches)`);
    const st = hits[0];
    out({ entity_id: st.entity_id, state: st.state, attributes: st.attributes, last_changed: st.last_changed, last_updated: st.last_updated });
    return;
  }
  const st = await api(base, token, `/api/states/${encodeURIComponent(id)}`);
  out(st);
}

async function cmdCall(base, token, domain, service, params) {
  const res = await api(base, token, `/api/services/${domain}/${service}`, { method: "POST", body: params });
  // res: array of entity_ids that changed
  if (Array.isArray(res) && res.length) outLines(res.map((e) => `changed  ${e}`));
  else out(`ok  ${domain}.${service}`);
}

async function findByNameOrId(base, token, domain, name) {
  // exact entity_id match first
  if (name.includes(".") && (name.startsWith(domain + ".") || !name.includes(" "))) {
    try {
      const st = await api(base, token, `/api/states/${encodeURIComponent(name)}`);
      if (st && st.entity_id) return st;
    } catch { /* fall through to name search */ }
  }
  const states = await allStates(base, token);
  const inDomain = states.filter((s) => s.entity_id.startsWith(domain + "."));
  const q = name.toLowerCase();
  const exact = inDomain.find((s) => friendly(s).toLowerCase() === q);
  if (exact) return exact;
  const partial = inDomain.filter((s) => friendly(s).toLowerCase().includes(q));
  if (partial.length === 1) return partial[0];
  if (partial.length > 1)
    err(`ambiguous '${name}' (${partial.length} matches): ` + partial.map((s) => s.entity_id).join(", "));
  err(`no ${domain} found matching '${name}'`);
}

async function cmdScene(base, token, name) {
  if (!name) {
    const states = (await allStates(base, token)).filter((s) => s.entity_id.startsWith("scene."));
    outLines(states.map((s) => `${s.entity_id}  ${friendly(s) || s.state}`));
    return;
  }
  const sc = await findByNameOrId(base, token, "scene", name);
  await api(base, token, "/api/services/scene/turn_on", { method: "POST", body: { entity_id: sc.entity_id } });
  out(`on  ${sc.entity_id}  ${friendly(sc)}`);
}

// ---- history ----
function flattenHistory(period, { minimal = false } = {}) {
  // period: array of arrays (one per entity). Flatten to rows.
  const rows = [];
  for (const entityHistory of period) {
    if (!Array.isArray(entityHistory)) continue;
    for (const st of entityHistory) {
      rows.push({
        entity_id: st.entity_id,
        state: st.state,
        last_changed: st.last_changed,
        attribute: minimal ? undefined : st.attributes ?? null,
      });
    }
  }
  return rows;
}

// ---- weather / calendar ----
function pickDefault(states, domain) {
  const c = states.filter((s) => s.entity_id.startsWith(domain + "."));
  if (!c.length) err(`no ${domain}.* entity found`);
  // prefer one not ending in .forecast/.tomorrow
  const base = c.filter((s) => !/\.(forecast|tomorrow)$/.test(s.entity_id));
  if (base.length === 1) return base[0];
  if (base.length > 1) err(`ambiguous default ${domain} (pass one): ` + base.map((s) => s.entity_id).join(", "));
  return c[0];
}

function relativeTimeLabel(iso) {
  if (!iso) return "";
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return iso;
  const s = Math.round((Date.now() - t) / 1000);
  const abs = Math.abs(s);
  const ago = s >= 0 ? " ago" : " ahead";
  if (abs < 90) return `${abs}s${ago}`;
  if (abs < 5400) return `${Math.round(abs / 60)}m${ago}`;
  if (abs < 172800) return `${(abs / 3600).toFixed(1)}h${ago}`;
  return `${Math.round(abs / 86400)}d${ago}`;
}

async function cmdWeather(base, token, entityArg) {
  const states = await allStates(base, token);
  let id = entityArg;
  if (!id) {
    const w = pickDefault(states, "weather");
    id = w.entity_id;
  } else if (!id.includes(".")) {
    const hits = states.filter((s) => s.entity_id.startsWith("weather.") && (s.entity_id.includes(id) || friendly(s).toLowerCase().includes(id.toLowerCase())));
    if (hits.length !== 1) err(`no single weather entity matching '${id}'`);
    id = hits[0].entity_id;
  }
  const st = await api(base, token, `/api/states/${encodeURIComponent(id)}`);
  const a = st.attributes ?? {};
  const rel = a && st.last_changed ? relativeTimeLabel(st.last_changed) : "";
  out({
    entity_id: st.entity_id,
    condition: st.state,
    temperature: a.temperature,
    temperature_unit: a.temperature_unit,
    apparent_temperature: a.apparent_temperature,
    humidity: a.humidity,
    wind_speed: a.wind_speed,
    wind_bearing: a.wind_bearing,
    pressure: a.pressure,
    precipitation: a.precipitation,
    visibility: a.visibility,
    updated: st.last_changed,
    updated_ago: rel || undefined,
  });
}

async function cmdCal(base, token, entityArg, start, end) {
  const states = await allStates(base, token);
  let id = entityArg;
  if (!id) {
    const c = states.filter((s) => s.entity_id.startsWith("calendar.") && !/\.events$/.test(s.entity_id));
    if (!c.length) err("no calendar.* entity found");
    if (c.length > 1) err(`ambiguous default calendar (pass one): ` + c.map((s) => s.entity_id).join(", "));
    id = c[0].entity_id;
  } else if (!id.includes(".")) {
    const hits = states.filter((s) => s.entity_id.startsWith("calendar.") && (s.entity_id.includes(id) || friendly(s).toLowerCase().includes(id.toLowerCase())));
    if (hits.length !== 1) err(`no single calendar entity matching '${id}'`);
    id = hits[0].entity_id;
  }
  const s = start ? new Date(parseTime(start)).toISOString() : new Date(Date.now() - 3600000).toISOString();
  const e = end ? new Date(parseTime(end)).toISOString() : new Date(Date.now() + 7 * 86400000).toISOString();
  const events = await api(base, token, `/api/calendars/${encodeURIComponent(id)}?start=${encodeURIComponent(s)}&end=${encodeURIComponent(e)}`);
  const list = Array.isArray(events) ? events : [];
  outLines(list.map((ev) => {
    const when = ev.start ? (ev.start.dateTime || ev.start.date) : "";
    const endw = ev.end ? (ev.end.dateTime || ev.end.date) : "";
    return `${when}  ${ev.summary || ev.title || ""}${endw ? "  -> " + endw : ""}`;
  }));
}

async function cmdInfo(base, token) {
  const cfg = await api(base, token, "/api/config");
  const states = await allStates(base, token);
  out({
    location_name: cfg.location_name,
    version: cfg.version,
    time_zone: cfg.time_zone,
    unit_system: cfg.unit_system,
    entities: states.length,
    by_state: Object.entries(
      states.reduce((acc, s) => {
        if (s.state === "unavailable" || s.state === "unknown") { acc.offline = (acc.offline || 0) + 1; }
        else acc.online = (acc.online || 0) + 1;
        return acc;
      }, {}),
    ).map(([k, v]) => `${k}=${v}`).join(" "),
  });
}

// ---- entry ----
function usage() {
  err(
    "usage: f ha <cmd>\n" +
    "  ls [query]                 list entities (domain, substring, or glob)\n" +
    "  state [entity]             all states, or one entity's full state (json)\n" +
    "  search <query>             = ls <query>\n" +
    "  call <domain> <service> [key=value ... | {json}]\n" +
    "                             service call, e.g. call light turn_on entity_id=light.kitchen\n" +
    "  scene [name]               list scenes, or turn one on (name or id)\n" +
    "  auto [ls|on <name>|off <name>|<name>]\n" +
    "                             list automations / toggle enabled / trigger\n" +
    "  history <entity...> [-s start] [-e end] [--minimal]\n" +
    "                             state changes (times: ISO or 30m/2h/1d/1w ago)\n" +
    "  weather [entity]           current weather\n" +
    "  cal [entity] [-s] [-e]     calendar events (default: last 1h .. +7d)\n" +
    "  info                       server summary\n" +
    "  urls                       resolved base url + token source\n" +
    "  <METHOD> <path> [json]     raw call, e.g. GET /api/states/sensor.x\n" +
    "  --url <base>               override base (default: HA_URL > ha.baseUrl > creds)\n" +
    "  --token <tok>              override token (default: HA_TOKEN > creds)\n" +
    "  --wait [sec]               block until creds appear (default 300s)\n" +
    "  creds: f creds set <host>-host <url>  and  f creds set <host>-token <token>"
  );
}

export function register(_ctx) {
  return {
    name: "ha",
    skills: [{ name: "f-ha", path: path.join(_here, "SKILL.md") }],
    desc: "Home Assistant: states, service calls, scenes, automations, history, weather, calendars; creds: <host>-host + <host>-token (or combined <host> = url|token)",
    run: async (_argv, args, ctx) => {
      const _ = args._ ?? [];
      let flagUrl = null;
      let flagToken = null;
      let waitSec = 0;
      const pos = [];
      for (let i = 0; i < _.length; i++) {
        const a = _[i];
        if (a === "--url") { flagUrl = _[++i]; continue; }
        if (a === "--token") { flagToken = _[++i]; continue; }
        if (a === "--wait") {
          const nxt = Number(_[i + 1]);
          waitSec = Number.isFinite(nxt) && nxt > 0 ? (_[++i], nxt) : 300;
          continue;
        }
        pos.push(a);
      }
      const [cmd, ...rest] = pos;
      const opts = { waitMs: waitSec * 1000 };
      const credsApi = (ctx && ctx.registry && ctx.registry.creds && ctx.registry.creds.credsApi) || null;

      if (!cmd || cmd === "help" || cmd === "--help" || cmd === "-h") return usage();

      const ha = await resolveHa(flagUrl, flagToken, credsApi, opts);

      if (cmd === "urls") {
        out({
          base: ha.base ?? "(none)",
          token: ha.token ? (ha.src + " (len " + String(ha.token).length + ")") : `(none: ${ha.reason ?? "missing"})`,
        });
        return;
      }
      const { base, token } = needCred(ha);

      if (cmd === "ls" || cmd === "search") {
        const fn = cmdList(rest.join(" "));
        return fn(base, token);
      }

      if (cmd === "state") return cmdState(base, token, rest[0]);

      if (cmd === "call") {
        const [domain, service, ...paramTokens] = rest;
        if (!domain || !service) err("call needs <domain> <service>, e.g. f ha call light turn_on");
        return cmdCall(base, token, domain, service, parseParams(paramTokens));
      }

      if (cmd === "scene") return cmdScene(base, token, rest[0]);

      if (cmd === "auto") {
        // `f ha auto <name>` triggers (toggle is on/off <name>); the service
        // is homeassistant.turn_on/turn_off with entity_id — the only way to
        // set enabled state over REST (automation.toggle requires websocket).
        const setEnabled = async (on, names) => {
          if (!names.length) err(`auto ${on} needs an automation name or id`);
          const target = await findByNameOrId(base, token, "automation", names.join(" "));
          await api(base, token, "/api/services/homeassistant/" + on, { method: "POST", body: { entity_id: target.entity_id } });
          out(`${on}  ${target.entity_id}  ${friendly(target)}`);
        };
        const trigger = async (sub) => {
          const target = await findByNameOrId(base, token, "automation", sub);
          await api(base, token, "/api/services/automation/trigger", { method: "POST", body: { entity_id: target.entity_id } });
          out(`triggered  ${target.entity_id}  ${friendly(target)}`);
        };
        const [sub, ...names] = rest;
        if (sub === "on" || sub === "off") return setEnabled(sub, names);
        if (!sub || sub === "ls") {
          const states = (await allStates(base, token)).filter((s) => s.entity_id.startsWith("automation."));
          outLines(states.map((s) => `${s.entity_id}  ${s.state}  ${friendly(s)}`));
          return;
        }
        return trigger(sub);
      }

      if (cmd === "history") {
        let start = null, end = null, minimal = false;
        const entities = [];
        for (let i = 0; i < rest.length; i++) {
          const a = rest[i];
          if (a === "-s") start = parseTime(rest[++i]);
          else if (a === "-e") end = parseTime(rest[++i]);
          else if (a === "--minimal") minimal = true;
          else entities.push(a);
        }
        if (!entities.length) err("history needs at least one entity (id or unique substring)");
        // resolve substrings
        const all = await allStates(base, token);
        const ids = [];
        for (const e of entities) {
          if (e.includes(".")) { ids.push(e); continue; }
          const hits = all.filter((s) => s.entity_id.toLowerCase().includes(e.toLowerCase()) || friendly(s).toLowerCase().includes(e.toLowerCase()));
          if (hits.length !== 1) err(`ambiguous entity '${e}' (${hits.length} matches)`);
          ids.push(hits[0].entity_id);
        }
        const q = new URLSearchParams();
        q.set("filter_entity_id", ids.join(","));
        if (start) q.set("start_time", new Date(start).toISOString());
        if (end) q.set("end_time", new Date(end).toISOString());
        if (minimal) q.set("minimal_response", "true");
        const period = await api(base, token, `/api/history/period?${q.toString()}`);
        const rows = flattenHistory(Array.isArray(period) ? period : [], { minimal });
        outLines(rows.map((r) => {
          const attr = r.attribute && Object.keys(r.attribute).length ? "  " + JSON.stringify(r.attribute) : "";
          return `${r.last_changed}  ${r.entity_id}  ${r.state}${attr}`;
        }));
        return;
      }

      if (cmd === "weather") return cmdWeather(base, token, rest[0]);

      if (cmd === "cal") {
        let start = null, end = null, entityArg = null;
        for (let i = 0; i < rest.length; i++) {
          const a = rest[i];
          if (a === "-s") start = rest[++i];
          else if (a === "-e") end = rest[++i];
          else entityArg = a;
        }
        return cmdCal(base, token, entityArg, start, end);
      }

      if (cmd === "info") return cmdInfo(base, token);

      // raw passthrough: <METHOD> <path> [json]
      const method = cmd.toUpperCase();
      if (/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/.test(method)) {
        const rawPath = rest[0];
        if (!rawPath) err(`${method} requires a path, e.g. ${method} /api/states`);
        let body;
        if (rest[1] && rest[1].trim().startsWith("{")) body = JSON.parse(rest[1]);
        const p = rawPath.startsWith("/") ? rawPath : "/" + rawPath;
        return out(await api(base, token, p, { method, body }));
      }

      usage();
    },
  };
}

export default { register };
