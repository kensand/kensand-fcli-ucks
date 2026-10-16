#!/usr/bin/env node
// f mqtt — MQTT broker client.
//
// Why this is its own uck: the broker is a separate service with its own
// credential (`mqtt`), and Home Assistant is merely one of its clients. Same
// boundary f fj / f gh / f ha already draw. HA-specific config CRUD stays in
// `f ha ws`, because that speaks HA's API with HA's token.
//
// MQTT 5 / 3.1.1 via mqtt.js. Like f fj and f gh, the dependency is declared in
// package.json and resolved by dynamic import from this uck's own node_modules,
// so we always get the declared version. node_modules/ is gitignored (see repo
// .gitignore); run `npm install --omit=dev` here on a fresh clone.
//
// Usage:
//   f mqtt urls                      resolved broker + cred provenance
//   f mqtt sub <topic> [n] [opts]    subscribe n messages
//   f mqtt pub <topic> <payload>     publish
//   f mqtt retained <topic>          one retained snapshot per topic
//   f mqtt xpg                       publish `$SYS/#`-style scan via wildcards
//   f mqtt disco [prefix]            parse retained MQTT-discovery configs
//   --host <h> --port <p> --user <u> --pass <p>
//
// Topic wildcards (+/#) are quoted by MQTT itself; shell-quote them.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath as _f2p } from "node:url";
import { resolveCred } from "../lib/credsresolve.js";

const _here = path.dirname(_f2p(import.meta.url));

let _mqtt = null;
async function mqttLib() {
  if (_mqtt) return _mqtt;
  const p = path.join(_here, "node_modules", "mqtt", "build", "index.js");
  if (!fs.existsSync(p))
    throw new Error(
      `mqtt.js is not installed for this uck\n  fix: cd ${_here} && npm install --omit=dev`
    );
  const m = await import(p);
  _mqtt = m.connect ? m : m.default;
  return _mqtt;
}

const DEFAULTS = { host: "10.1.5.4", port: 1883, user: "mqtt" };

// Retained scans need a window even with a done-signal, purely as a safety net
// for a half-reached broker. The correctness comes from MQTT5 Retain Available
// (see scanRetained), NOT from this number.
const RETAINED_WINDOW_MS = 12000;

function resolveBroker(args) {
  const host = args.host || process.env.MQTT_HOST || DEFAULTS.host;
  const port = Number(args.port || process.env.MQTT_PORT || DEFAULTS.port);
  const user = args.user || process.env.MQTT_USER || DEFAULTS.user;
  return { host, port, user };
}

async function resolvePass(args, ctx) {
  if (args.pass) return { pass: args.pass, src: "--pass" };
  if (process.env.MQTT_PASS) return { pass: process.env.MQTT_PASS, src: "env:MQTT_PASS" };
  const r = await resolveCred({
    names: ["mqtt", "mqtt-creds", "mosquitto"],
    credsApi: ctx?.registry?.creds?.credsApi,
  });
  if (r.token) return { pass: r.token, src: r.src };
  return { pass: null, reason: r.reason, detail: r.detail };
}

async function connect(args, ctx) {
  const { host, port, user } = resolveBroker(args);
  const { pass, src, reason, detail } = await resolvePass(args, ctx);
  if (!pass) {
    const why =
      reason === "locked"
        ? "creds are locked — unlock with: f creds unlock"
        : reason === "provider"
        ? `credential provider failed: ${detail || "unknown"}`
        : `no 'mqtt' cred — set it: f creds set mqtt <password>`;
    throw new Error(`mqtt auth needs a password.\n  ${why}`);
  }
  const lib = await mqttLib();
  // MQTT5 handshake so any retained-message capability the broker advertises is
  // visible. This broker advertises none (serverProperties is empty on v5 AND v4,
  // verified), so scanRetained falls back to its timed window. Negotiating 5 is
  // what makes that absence knowable rather than assumed. Publisher-side commands
  // do not depend on it.
  const client = await new Promise((resolve, reject) => {
    const c = lib.connect({
      protocolVersion: 5,
      host,
      port,
      username: user,
      password: pass,
      clientId: `f-mqtt-${process.pid}`,
      keepalive: 30,
      connectTimeout: 10000,
      reconnectPeriod: 0, // one shot; this uck is a CLI, not a daemon
      rejectUnauthorized: false,
    });
    const to = setTimeout(() => {
      try { c.end(true); } catch { /* ignore */ }
      reject(new Error(`connect timeout ${host}:${port}`));
    }, 12000);
    c.once("connect", () => { clearTimeout(to); resolve(c); });
    c.once("error", (e) => { clearTimeout(to); try { c.end(true); } catch { /* ignore */ } reject(e); });
  });
  return { client, host, port, user, credSrc: src };
}

/** topic match with MQTT wildcards, for client-side filtering. */
function topicMatch(filter, topic) {
  if (!filter || filter === "#") return true;
  const f = filter.split("/");
  const t = topic.split("/");
  for (let i = 0; i < f.length; i++) {
    if (f[i] === "#") return true;
    if (i >= t.length) return false;
    if (f[i] === "+") continue;
    if (f[i] !== t[i]) return false;
  }
  return f.length === t.length;
}

/** Resolve after n messages or the window, whichever comes first.
 *
 *  `n` must be a real count. It used to be called with Infinity to mean
 *  "collect everything", which is 1/0, so `got.length >= n` was never true and
 *  the promise could only settle on the timeout: every read of robot state came
 *  back empty while raw probes on the same broker returned values. Pass
 *  Number.POSITIVE_INFINITY only where the caller genuinely cannot early-exit
 *  (the `state` verb) and give it the full retained window. */
function collectN(client, { filter, n, ms }) {
  return new Promise((resolve) => {
    const got = [];
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve(got);
    };
    const timer = setTimeout(finish, ms);
    client.on("message", (topic, payload) => {
      if (!topicMatch(filter, topic)) return;
      got.push({ topic, value: showValue(payload) });
      if (got.length >= n) finish();
    });
  });
}

/** Render a payload for display.
 *
 *  A zero-length retained payload is MQTT's sentinel for "value currently
 *  unknown / cleared", NOT an empty string. mqtt.js also re-sends SUBSCRIBE on
 *  reconnect, and the broker replays retained messages with empty payloads in
 *  that case. Printing those as blank makes "cleaning" and "I don't know" look
 *  identical -- which is how an automation ends up firing on every cycle.
 *  Always annotate; never let a blank line mean two different things. */
const EMPTY_MARK = "<empty payload: value unknown or cleared>";

function showValue(payload) {
  const text = payload && typeof payload.toString === "function"
    ? payload.toString("utf8")
    : String(payload ?? "");
  if (text === "") return EMPTY_MARK;
  return text;
}

/** Read a retained snapshot deterministically.
 *
 *  MQTT5 `retain-handling: grant` + `rap: true`: the broker mirrors our
 *  subscription with the Retain-Available flag, CLEARED on the last retained
 *  message, so we learn when the snapshot is complete instead of guessing at a
 *  timeout. This replaces the timed-window approach that returned 8 / 13 / 20 /
 *  22 topics for one topic tree -- retained delivery is chunked with no per-chunk
 *  marker, so no fixed wait is reliable.
 *
 *  A broker that did not advertise retained_available_on falls back to the timed
 *  window and the footer says so, so a count is never silently suspect. */
async function scanRetained(client, filter, ms) {
  const caps = client.options?.serverProperties || {};
  const supportsRA = caps.retained_available_on === true;
  const byTopic = new Map();
  let subscribeError = null;

  await new Promise((resolve) => {
    const finish = () => { clearTimeout(timer); resolve(); };
    const timer = setTimeout(finish, ms);
    client.on("message", (topic, payload, packet) => {
      if (!packet?.retain) return; // live traffic, or our own rap-echoed ack
      const value = showValue(payload);
      byTopic.set(topic, { topic, value, retain: true });
      // reasonCode 0 = our subscription mirror, RA cleared => end of snapshot
      if (supportsRA && packet.reasonCode === 0) finish();
    });
    client
      .subscribeAsync(filter, { qos: 0, ...(supportsRA ? { rh: 1, rap: true } : {}) })
      .catch((e) => { subscribeError = e; finish(); });
  });

  return { topics: [...byTopic.values()], usedFallback: !supportsRA, error: subscribeError };
}

/** One truncation rule everywhere; `--full` means show everything.
 *  Written as .slice(limit) this silently yields "" for any short payload,
 *  which reads as "topic has no value" -- the exact confusion it causes is
 *  unreadable robot state during an incident. */
function clip(text, full) {
  return full || text.length <= 200 ? text : text.slice(0, 200) + "...";
}

/** Footer so a reader knows whether the count is authoritative. */
function noteFor(scan, ms) {
  if (scan.error) return `, subscribe error: ${scan.error.message || scan.error}`;
  return scan.usedFallback
    ? `, timed window ${ms}ms (broker lacks MQTT5 retain-available; count may be partial)`
    : ", snapshot complete";
}

function outLines(lines) {
  if (lines.length) process.stdout.write(lines.join("\n") + "\n");
}

// ---- discovery parsing ----
// MQTT discovery config payloads are JSON with ~5-8 keys each (name, state_topic,
// unique_id, availability, ...). Printing full JSON for every topic buries the
// answer, so summarise first and allow --full.
function summariseDiscovery(msgs) {
  const rows = [];
  for (const m of msgs) {
    if (!m.retain) continue;
    let cfg = null;
    try { cfg = JSON.parse(m.value); } catch { continue; }
    if (!cfg || typeof cfg !== "object") continue;
    const parts = m.topic.split("/");
    const comp = parts[0] === "homeassistant" ? parts[1] : parts.find((p) => /sensor|switch|number|select|button|light|fan|binary_sensor|cover|climate|scene|vacuum|update|text|lock|valve|water_heater|event/.test(p)) || "?";
    const name = cfg.name || cfg.friendly_name || cfg.unique_id || "";
    rows.push({ comp, name, topic: m.topic, state: cfg.state_topic || "", uid: cfg.unique_id || "", full: cfg });
  }
  return rows;
}

/** f gives ucks `{ _: tokens }` unless they declare `argv`, so parse flags by
 *  hand from args._ exactly like `f ha` and `f fj` do. Anything read off
 *  `args.<flag>` is silently undefined here -- that was a real bug: every flag
 *  (wait/host/full) was ignored and scans used the default window. */
function parseTokens(tokens) {
  const out = { _: [], host: null, port: null, user: null, pass: null, wait: null, full: false, retain: false };
  for (let i = 0; i < tokens.length; i++) {
    const a = tokens[i];
    const take = () => tokens[++i];
    if (a === "--host") { out.host = take(); continue; }
    if (a === "--port") { out.port = take(); continue; }
    if (a === "--user") { out.user = take(); continue; }
    if (a === "--pass") { out.pass = take(); continue; }
    if (a === "--wait") { out.wait = take(); continue; }
    if (a === "--full") { out.full = true; continue; }
    if (a === "--retain") { out.retain = true; continue; }
    // also accept --flag=value
    const eq = a.indexOf("=");
    if (a.startsWith("--") && eq > 0) {
      const k = a.slice(0, eq), v = a.slice(eq + 1);
      if (k === "--host") { out.host = v; continue; }
      if (k === "--port") { out.port = v; continue; }
      if (k === "--user") { out.user = v; continue; }
      if (k === "--pass") { out.pass = v; continue; }
      if (k === "--wait") { out.wait = v; continue; }
    }
    out._.push(a);
  }
  if (out.wait != null && !Number.isFinite(Number(out.wait)))
    throw new Error(`--wait needs milliseconds, got: ${out.wait}`);
  return out;
}

async function main(ctx, tokens) {
  const args = parseTokens(tokens);
  const cmd = args._[0];
  const rest = args._.slice(1);

  if (!cmd || cmd === "help" || cmd === "--help") return usage();

  if (cmd === "urls") {
    const b = resolveBroker(args);
    const p = await resolvePass(args, ctx);
    outLines([
      `broker=${b.host}:${b.port}`,
      `user=${b.user}`,
      `pass=${p.pass ? p.src : "MISSING (" + (p.reason || "unset") + ")"}`,
    ]);
    return;
  }

  const { client, host, port } = await connect(args, ctx);

  if (cmd === "sub") {
    const filter = rest[0] || "#";
    const n = Number(rest[1] || 1) || 1;
    const ms = args.wait ? Number(args.wait) : 8000;
    try {
      await client.subscribeAsync(filter, { qos: 0 });
      // Answer from complete values, not the first retained replay.
      const got = await collectN(client, { filter, n, ms });
      if (!got.length) outLines([`0 message(s) on ${filter} within ${ms}ms`]);
      else for (const g of got) outLines([`${g.topic}  ${clip(g.value, args.full)}`]);
    } finally { client.end(true); }
    return;
  }

  if (cmd === "state") {
    // "What is X right now": use the whole window and keep the best value per
    // topic, so a transient empty retained replay can never beat a real value.
    const filter = rest[0];
    if (!filter) throw new Error("state needs a topic filter, e.g. f mqtt state 'valetudo/<robot>/StatusStateAttribute/+'");
    // No early exit is possible when collecting every topic, so this needs the
    // full retained window; a short one silently reports "no message".
    const ms = args.wait ? Number(args.wait) : RETAINED_WINDOW_MS;
    try {
      await client.subscribeAsync(filter, { qos: 0 });
      const got = await collectN(client, { filter, n: Number.POSITIVE_INFINITY, ms });
      const best = new Map();
      for (const g of got) {
        const prev = best.get(g.topic);
        const complete = !g.value.startsWith(EMPTY_MARK);
        if (prev === undefined || (complete && prev.startsWith(EMPTY_MARK))) best.set(g.topic, g.value);
      }
      if (!best.size) { outLines([`no message on ${filter} within ${ms}ms`]); return; }
      for (const [t, v] of [...best.entries()].sort((a, b) => a[0].localeCompare(b[0])))
        outLines([`${t}  ${clip(v, args.full)}`]);
    } finally { client.end(true); }
    return;
  }

  if (cmd === "retained") {
    const filter = rest[0] || "#";
    const ms = args.wait ? Number(args.wait) : RETAINED_WINDOW_MS;
    try {
      const scan = await scanRetained(client, filter, ms);
      const seen = scan.topics;
      if (!seen.length) outLines([`0 retained message(s) under ${filter}`]);
      else for (const m of seen.sort((a, b) => a.topic.localeCompare(b.topic))) {
        outLines([`${m.topic}  ${clip(m.value, args.full)}`]);
      }
      outLines([`-- ${seen.length} retained topic(s)${noteFor(scan, ms)}`]);
    } finally { client.end(true); }
    return;
  }

  if (cmd === "topics") {
    const filter = rest[0] || "#";
    const ms = args.wait ? Number(args.wait) : RETAINED_WINDOW_MS;
    try {
      const scan = await scanRetained(client, filter, ms);
      const topics = scan.topics.map((m) => m.topic).sort();
      outLines(topics.length ? topics : [`0 retained topic(s) under ${filter}`]);
      if (topics.length) outLines([`-- ${topics.length} topic(s)${noteFor(scan, ms)}`]);
    } finally { client.end(true); }
    return;
  }

  if (cmd === "disco") {
    const prefix = rest[0] || "homeassistant";
    const ms = args.wait ? Number(args.wait) : RETAINED_WINDOW_MS;
    try {
      const scan = await scanRetained(client, `${prefix}/#`, ms);
      const all = scan.topics;
      const rows = summariseDiscovery(all);
      if (!rows.length) { outLines([`0 discovery configs under ${prefix}/#${noteFor(scan, ms)}`]); return; }
      if (args.full) { outLines([JSON.stringify(rows, null, 2)]); return; }
      const counts = {};
      for (const r of rows) counts[r.comp] = (counts[r.comp] || 0) + 1;
      outLines([`${rows.length} configs: ${Object.entries(counts).map(([k, v]) => `${k}=${v}`).join(" ")}`]);
      const byComp = {};
      for (const r of rows) (byComp[r.comp] ||= new Set()).add(r.name);
      for (const [comp, names] of Object.entries(byComp)) {
        outLines([`${comp} (${names.size}):`]);
        outLines([...names].sort().map((n) => `  ${n}`));
      }
      outLines([`-- ${all.length} retained config topic(s)${noteFor(scan, ms)}`]);
    } finally { client.end(true); }
    return;
  }

  if (cmd === "pub") {
    const topic = rest[0];
    const payload = rest.slice(1).join(" ");
    if (!topic) throw new Error("pub needs a topic");
    await client.publishAsync(topic, payload || "", { retain: !!args.retain, qos: 0 });
    outLines([`ok  published ${topic} (${(payload || "").length} bytes${args.retain ? ", retained" : ""})`]);
    client.end(true);
    return;
  }

  client.end(true);
  return usage();
}

function usage() {
  const t =
    "usage: f mqtt <cmd>\n" +
    "  urls                          resolved broker + credential provenance\n" +
    "  topics [filter]               retained topics (distinct)\n" +
    "  retained [filter]             topic + retained payload\n" +
    "  sub <topic> [n]               live msgs (default 1)\n" +
    "  state <topic>                 CURRENT value; window default 12s\n" +
    "  disco [prefix]                summary of MQTT discovery configs\n" +
    "  pub <topic> <payload>         publish (--retain to set retained)\n" +
    "  --host/--port/--user/--pass    overrides (default 10.1.5.4:1883, user mqtt)\n" +
    "  --wait <ms>                   collect window (sub 8s, state 12s)\n" +
    "  --full                        untruncated payloads / full JSON\n" +
    "  creds: f creds set mqtt <password>";
  process.stdout.write(t + "\n");
}

export function register(ctx) {
  return {
    name: "mqtt",
    desc: "MQTT broker client: topics/retained/sub/discovery-config summary/publish; cred `mqtt`",
    run: async (_argv, a) => {
      try {
        return await main(ctx, a._ ?? []);
      } catch (e) {
        process.stderr.write(`f mqtt: ${(e && e.message) || e}\n`);
        return 1;
      }
    },
  };
}

export default { register };
