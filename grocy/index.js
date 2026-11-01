// f grocy — self-hosted household stock / shopping / recipes / chores API.
//
// Zero deps (node builtins + fetch, Node >= 20).
//
// Config: TWO creds (both optional per-instance; name them after the instance
// host, e.g. `grocy.kensand.net`):
//   grocy-host   the base url, e.g. `https://grocy.kensand.net` (scheme optional)
//   grocy-token  the API key (create one in grocy: Settings → API keys)
// A single cred `grocy` holding `url|token` is also accepted as a combined form.
// Precedence: --url/--token flags and GROCY_URL/GROCY_TOKEN env win over creds.
// grocy.baseUrl in f.config.json (project walked up, then global) is the
// last-resort base. Auth: `Authorization: Token <key>` (note: Token, not Bearer).
//
// Commands:
//   f grocy info                       system info (version etc.)
//   f grocy stock [query]              current stock, filtered; flags:
//                                      --low (below min. stock) --due (due/overdue/expired)
//   f grocy product <name-or-id>       product details (stock, prices, dates)
//   f grocy add <product> <amount> [--location <n>] [--best-before <YYYY-MM-DD>]
//                                      increase stock (by barcode: add barcode:<code> <amount>)
//   f grocy consume <product> <amount> [location:<n> ...]
//   f grocy open <product> <amount>    mark as opened
//   f grocy inventory <product> <amount> [--location <n>]
//   f grocy transfer <product> <amount> <from-loc> <to-loc>
//   f grocy shopping [query]           list shopping list (flags: --all)
//   f grocy buy <product> <amount> [note]   add to shopping list
//   f grocy done <shopping-item-id>    mark item done
//   f grocy remove <product> <amount>  remove from shopping list
//   f grocy clear [--list <id>]        clear the (given) shopping list
//   f grocy recipes [query]            recipes with fulfillment (stock covers them?)
//   f grocy recipe <id>                one recipe + ingredients + fulfillment
//   f grocy cook <recipe-id>           consume in-stock ingredients
//   f grocy recipe-need <recipe-id>    add unfulfilled ingredients to shopping list
//   f grocy chores [query]             chores with next/last execution
//   f grocy chore <id>                 one chore
//   f grocy did <chore>                track a chore execution
//   f grocy tasks [query]              open tasks
//   f grocy task <id>                  one task (raw)
//   f grocy taskdone <id>              mark task done
//   f grocy batteries [query]          batteries with next charge time
//   f grocy battery <id>               one battery
//   f grocy charged <id>               track a charge cycle
//   f grocy calendar                   ical feed url (public sharing link)
//   f grocy obj <entity> [id]          generic GET /objects/<entity>[/<id>]
//   f grocy <METHOD> <path> [json]     raw call under /api/v1, e.g. GET /stock/volatile
//
// Products/chores/batteries may be addressed by id or (unique) name substring.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath as _f2p } from "node:url";
import { spawnSync } from "node:child_process";
const _here = path.dirname(_f2p(import.meta.url));

const F = path.join(process.env.HOME ?? "", ".f");

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
  process.stderr.write("f grocy: " + msg + "\n");
  process.exit(1);
}

// ---- config resolution ----
function configBaseUrl() {
  const read = (p) => {
    try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch { return null; }
  };
  let dir = process.cwd();
  for (let i = 0; i < 8; i++) {
    const d = read(path.join(dir, "f.config.json"));
    if (d && d.grocy && typeof d.grocy.baseUrl === "string") return d.grocy.baseUrl;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  const g = read(path.join(F, "f.config.json"));
  if (g && g.grocy && typeof g.grocy.baseUrl === "string") return g.grocy.baseUrl;
  return null;
}

function resolveBaseUrl(flagUrl) {
  const raw = flagUrl || process.env.GROCY_URL || configBaseUrl();
  if (!raw) return null;
  let u = raw.replace(/\/+$/, "");
  if (!/^https?:\/\//.test(u)) u = "https://" + u; // self-hosted boxes are almost always TLS
  return u;
}

/** Parse a cred value: `url|token`, or a bare token (url part null). */
function splitCred(v) {
  const bar = v.indexOf("|");
  if (bar <= 0) return { url: null, token: v };
  let url = v.slice(0, bar).trim();
  const token = v.slice(bar + 1).trim();
  if (!/^https?:\/\//.test(url)) url = "https://" + url;
  return { url: url.replace(/\/+$/, ""), token };
}

function hostFromUrl(u) {
  try { return new URL(u).host; } catch { return u.replace(/^https?:\/\//, "").replace(/\/.*$/, ""); }
}

// ---- creds (same protocol as ha/fj ucks) ----
/**
 * The one way grocy obtains a credential: ask the creds uck (CONTRACT.md §6.1).
 *
 * Grocy stores THREE things and any of them may come from the store, so this is
 * not a single lookup:
 *   `<host>` / `grocy`   -> a combined `url|api key` value
 *   `<host>-host`        -> the base URL alone
 *   `<host>-token`       -> the api key alone
 * Each is resolved with its own resolveCred call so the reason (locked vs
 * missing vs provider failure) is attributable to the name that failed. A
 * nested `f creds lookup` per name is gone: it spawned a process per name, and
 * its stderr was regexed for "locked" — string coupling that reported a vault
 * outage as "you never configured grocy".
 */
async function resolveGrocy(flagUrl, flagToken, credsApi, opts = {}) {
  const base = resolveBaseUrl(flagUrl);
  const host = base ? hostFromUrl(base) : null;
  const waitMs = opts.waitMs || 0;
  const envVars = process.env.GROCY_TOKEN ? { GROCY_TOKEN: process.env.GROCY_TOKEN } : {};

  if (!credsApi || typeof credsApi.resolveCred !== "function") {
    // No creds uck in this process. grocy needs url+key from somewhere, and the
    // only sanctioned path left is creds' own raw read; if that is absent too,
    // say "no store" rather than guessing from the filesystem.
    if (flagToken) return { base, token: flagToken, src: "--token", host: host ?? "grocy" };
    const read = credsApi && typeof credsApi.rawCredRead === "function"
      ? (names) => credsApi.rawCredRead(names)
      : async () => ({ token: null, reason: "no-store" });
    return { base, token: null, host: host ?? "grocy", ...(await read(["grocy", host].filter(Boolean))) };
  }

  const ask = (names) => credsApi.resolveCred({ names, waitMs });
  const fail = (res, hostName) => ({
    base: null, token: null, host: hostName ?? host ?? "grocy",
    reason: res.reason, detail: res.detail,
  });

  // 1. combined `url|token`
  const combined = await ask([...new Set(["grocy", host].filter(Boolean))]);
  if (combined.token == null && combined.reason && combined.reason !== "missing") {
    if (flagToken && base) return { base, token: flagToken, src: "--token", host: host ?? "grocy" };
    return fail(combined, combined.host);
  }
  const parts = combined.token ? splitCred(combined.token) : null;
  const provisionalBase = base || (parts && parts.url) || null;
  const provisionalHost = provisionalBase ? hostFromUrl(provisionalBase) : null;

  // 2. base url, if the combined cred did not carry one
  let resolvedBase = provisionalBase;
  let urlSrc = parts && parts.url ? `${combined.src} (url part)` : base ? "--url/env" : null;
  if (!resolvedBase) {
    const hostNames = [...new Set(provisionalHost
      ? ["grocy-host", provisionalHost + "-host", provisionalHost.split(":")[0] + "-host"]
      : ["grocy-host", "grocy"])];
    const r = await ask(hostNames);
    if (r.token != null) {
      resolvedBase = String(r.token).replace(/\/+$/, "");
      if (!/^https?:\/\//.test(resolvedBase)) resolvedBase = "https://" + resolvedBase;
      urlSrc = r.src;
    } else if (r.reason && r.reason !== "missing") {
      return fail(r, provisionalHost);
    }
  }
  const resolvedHost = resolvedBase ? hostFromUrl(resolvedBase) : provisionalHost;

  // 3. api key
  let token = parts && parts.token ? parts.token : null;
  let src = token ? `${combined.src} (token part)` : null;
  if (flagToken) { token = flagToken; src = "--token"; }
  else if (process.env.GROCY_TOKEN) { token = process.env.GROCY_TOKEN; src = "GROCY_TOKEN"; }
  if (!token) {
    const tokenNames = [...new Set(resolvedHost
      ? ["grocy-token", resolvedHost + "-token", resolvedHost.split(":")[0] + "-token"]
      : ["grocy-token", "grocy"])];
    const r = await ask(tokenNames);
    if (r.token != null) { token = r.token; src = r.src; }
    else if (r.reason && r.reason !== "missing") return fail(r, resolvedHost);
  }

  const reason = !token && !resolvedBase ? "missing" : !token ? "missing-token" : null;
  return {
    base: resolvedBase, token, src, host: resolvedHost ?? "grocy",
    reason, urlSrc, needHost: !resolvedBase,
  };
}

/** creds' own remediation text, with a local fallback for a process that has no
 *  creds uck (the message must still name the real kind, never "other"). */
function credsHintFor(res, name) {
  if (_credsApiRef && typeof _credsApiRef.credHint === "function") return _credsApiRef.credHint(res, { credName: name });
  // A hit has { token, src } and no reason; report its provenance. Deriving
  // state from a missing field is how creds' own helper briefly reported every
  // successful lookup as "unavailable (unknown)".
  if (res.token != null && res.token !== "") {
    return res.localOnly ? `${res.src} (read without the creds uck; a vault value would be invisible)` : res.src;
  }
  switch (res.reason) {
    case "locked":   return `creds are locked — unlock them: f creds unlock`;
    case "missing":  return `no credential named '${name}' — store it: f creds set ${name} <value>`;
    case "provider": return `a credential provider failed for '${name}': ${res.detail}`;
    case "no-store": return `the credential store could not be reached (no creds uck in this process) — check: f creds status`;
    case "timeout":  return `timed out waiting for '${name}' — set it elsewhere: f creds fill ${name}`;
    default:         return `credential '${name}' unavailable (${res.reason ?? "unknown"})`;
  }
}

// Set by run(): needCred() sits deep in a command and only needs creds for the
// remediation WORDING. Resolution itself always took credsApi as an argument.
let _credsApiRef = null;

function needCred(g) {
  if (g.base && g.token) return { base: g.base, token: g.token };
  // The store-side diagnosis is creds' own text, so grocy cannot disagree with
  // `f creds status` about locked vs missing vs a provider that is down.
  if (g.reason && g.reason !== "missing" && g.reason !== "missing-token")
    err(`no grocy credential\n  ${credsHintFor(g, g.host)}`);
  const missing = [];
  if (!g.base) missing.push("base url (f creds set <host>-host <url>, or --url, or GROCY_URL)");
  if (!g.token) missing.push("api key (f creds set <host>-token <key>, or --token, or GROCY_TOKEN)");
  err(
    `missing: ${missing.join(" + ")}\n` +
    `  store it: f creds set ${g.host}-host <url>   and   f creds set ${g.host}-token <key>\n` +
    `  (api key: grocy UI → Settings → API keys)\n` +
    `  or send them now: f grocy ${g.base ? "" : "--url <url> "}--token <key> ...`,
  );
}

// ---- HTTP ----
async function api(base, token, path, { method = "GET", body, query } = {}) {
  let p = path.startsWith("/") ? path : "/" + path;
  if (query) {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(query)) if (v != null) q.set(k, v);
    const qs = q.toString();
    if (qs) p += (p.includes("?") ? "&" : "?") + qs;
  }
  let res;
  try {
    res = await fetch(base.replace(/\/+$/, "") + "/api/v1" + p, {
      method,
      headers: {
        Authorization: "Token " + token, // grocy uses `Token`, not Bearer
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(30000),
    });
  } catch (e) {
    err(`request to ${base} failed: ${e.message ?? e}`);
  }
  const text = await res.text();
  let data = null;
  if (text) {
    try { data = JSON.parse(text); } catch { data = text; }
  }
  if (!res.ok) {
    const msg = (data && typeof data === "object" && (data.message || data.msg)) || (typeof data === "string" ? data : "");
    if (res.status === 401)
      err(`unauthorized (401)\n  check your api key: f creds set <host>-token <key>`);
    err(`HTTP ${res.status} ${msg}`.trim());
  }
  return data;
}

// ---- arg helpers ----
function parseParams(tokens) {
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

function daysLeft(dateStr) {
  if (!dateStr) return null;
  const d = Date.parse(dateStr);
  if (!Number.isFinite(d)) return null;
  const today = new Date(); today.setHours(0, 0, 0, 0);
  return Math.round((d - today.getTime()) / 86400000);
}

function relDays(dateStr) {
  const n = daysLeft(dateStr);
  if (n == null) return dateStr || "";
  if (n === 0) return "today";
  if (n === 1) return "1d";
  if (n === -1) return "1d ago";
  return n > 0 ? `${n}d` : `${-n}d ago`;
}

function num(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

// ---- product / name resolution ----
async function findProduct(base, token, q) {
  if (/^\d+$/.test(q)) {
    const p = await api(base, token, `/objects/products/${q}`);
    return p;
  }
  const all = await api(base, token, "/objects/products");
  const ql = q.toLowerCase();
  const hits = all.filter((p) => (p.name || "").toLowerCase().includes(ql));
  if (!hits.length) err(`no product matching '${q}'`);
  if (hits.length > 1)
    err(`ambiguous '${q}' (${hits.length} matches): ` + hits.map((p) => `${p.id} ${p.name}`).join(", "));
  return hits[0];
}

async function resolveProductId(base, token, q) {
  // `barcode:123456...` form: look up via the barcode endpoint
  if (q.startsWith("barcode:")) {
    const code = q.slice("barcode:".length);
    const d = await api(base, token, `/stock/products/by-barcode/${encodeURIComponent(code)}`);
    return d.product;
  }
  return findProduct(base, token, q);
}

async function findChore(base, token, q) {
  if (/^\d+$/.test(q)) {
    const c = await api(base, token, `/objects/chores/${q}`);
    return c;
  }
  const all = await api(base, token, "/objects/chores");
  const ql = q.toLowerCase();
  const hits = all.filter((c) => (c.name || "").toLowerCase().includes(ql));
  if (!hits.length) err(`no chore matching '${q}'`);
  if (hits.length > 1)
    err(`ambiguous '${q}' (${hits.length} matches): ` + hits.map((c) => `${c.id} ${c.name}`).join(", "));
  return hits[0];
}

async function findBattery(base, token, q) {
  if (/^\d+$/.test(q)) {
    const b = await api(base, token, `/objects/batteries/${q}`);
    return b;
  }
  const all = await api(base, token, "/objects/batteries");
  const ql = q.toLowerCase();
  const hits = all.filter((b) => (b.name || "").toLowerCase().includes(ql));
  if (!hits.length) err(`no battery matching '${q}'`);
  if (hits.length > 1)
    err(`ambiguous '${q}' (${hits.length} matches): ` + hits.map((b) => `${b.id} ${b.name}`).join(", "));
  return hits[0];
}

// ---- stock commands ----
async function cmdStock(base, token, query, flags) {
  const stock = await api(base, token, "/stock");
  let rows = (Array.isArray(stock) ? stock : []).map((r) => ({
    id: r.product_id,
    name: r.product?.name || `product ${r.product_id}`,
    amount: r.amount,
    unit: r.product?.quantity_unit_stock_name || "",
    min: num(r.product?.min_stock_amount),
    due: r.best_before_date,
  }));
  if (query) {
    const ql = query.toLowerCase();
    rows = rows.filter((r) => r.name.toLowerCase().includes(ql));
  }
  if (flags.low) rows = rows.filter((r) => r.amount < r.min);
  if (flags.due) rows = rows.filter((r) => {
    const n = daysLeft(r.due);
    return n != null && n <= 7; // due soon, overdue, or expired
  });
  rows.sort((a, b) => a.name.localeCompare(b.name));
  outLines(rows.map((r) => {
    const low = r.amount < r.min ? "  LOW" : "";
    const due = r.due ? `  due ${r.due} (${relDays(r.due)})` : "";
    return `${r.id}  ${r.name}  ${r.amount}${r.unit ? " " + r.unit : ""}${low}${due}`;
  }));
}

async function cmdProduct(base, token, q) {
  const product = await resolveProductId(base, token, q);
  const d = await api(base, token, `/stock/products/${product.id}`);
  const p = d.product || {};
  out({
    id: p.id,
    name: p.name,
    stock: d.stock_amount,
    opened: d.stock_amount_opened,
    unit: d.quantity_unit_stock?.name,
    min_stock: num(p.min_stock_amount),
    low: d.stock_amount != null && d.stock_amount < num(p.min_stock_amount),
    next_due: d.next_due_date || null,
    last_purchased: d.last_purchased || null,
    last_used: d.last_used || null,
    price: d.last_price != null ? d.last_price : null,
    avg_price: d.avg_price != null ? d.avg_price : null,
    barcodes: (d.product_barcodes || []).map((b) => b.barcode),
    userfields: p.userfields || undefined,
  });
}

async function cmdStockAction(base, token, action, rest) {
  const flags = {};
  const pos = [];
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a === "--location") flags.location = rest[++i];
    else if (a === "--best-before") flags.best_before_date = rest[++i];
    else pos.push(a);
  }
  const [productQ, amount] = pos;
  if (!productQ || !amount || !Number.isFinite(Number(amount)))
    err(`${action} needs <product> <amount>, e.g. f grocy ${action} eggs 6`);
  const product = await resolveProductId(base, token, productQ);
  const query = { amount: Number(amount) };
  if (flags.location != null) query.location_id = flags.location;
  if (flags.best_before_date != null) query.best_before_date = flags.best_before_date;
  const before = (await api(base, token, `/stock/products/${product.id}`)).stock_amount ?? 0;
  await api(base, token, `/stock/products/${product.id}/${action}`, { method: "POST", query });
  const after = (await api(base, token, `/stock/products/${product.id}`)).stock_amount ?? 0;
  out(`${action}  ${product.name}  ${Number(amount)} -> stock now ${after} (was ${before})`);
}

async function cmdTransfer(base, token, rest) {
  const [productQ, amount, fromLoc, toLoc] = rest;
  if (!productQ || !amount || !fromLoc || !toLoc)
    err("transfer needs <product> <amount> <from-location> <to-location> (locations: ids or names)");
  const product = await resolveProductId(base, token, productQ);
  const locs = await api(base, token, "/objects/locations");
  const resolveLoc = (q) => {
    if (/^\d+$/.test(q)) return locs.find((l) => l.id === Number(q));
    const hits = locs.filter((l) => (l.name || "").toLowerCase().includes(q.toLowerCase()));
    if (!hits.length) err(`no location matching '${q}'`);
    if (hits.length > 1) err(`ambiguous location '${q}': ` + hits.map((l) => `${l.id} ${l.name}`).join(", "));
    return hits[0];
  };
  const from = resolveLoc(fromLoc);
  const to = resolveLoc(toLoc);
  await api(base, token, `/stock/products/${product.id}/transfer`, {
    method: "POST",
    query: { amount: Number(amount), location_id_from: from.id, location_id_to: to.id },
  });
  out(`moved  ${product.name}  ${amount}  ${from.name} -> ${to.name}`);
}

// ---- shopping list ----
async function cmdShopping(base, token, query, flags) {
  const items = await api(base, token, "/objects/shopping_list");
  let rows = (Array.isArray(items) ? items : []).map((it) => ({
    id: it.id,
    productId: it.product_id,
    name: it.product_name || `product ${it.product_id}`,
    amount: it.amount,
    done: it.done === 1,
    note: it.note || "",
    due: it.due_date,
  }));
  if (!flags.all) rows = rows.filter((r) => !r.done);
  if (query) {
    const ql = query.toLowerCase();
    rows = rows.filter((r) => r.name.toLowerCase().includes(ql) || r.note.toLowerCase().includes(ql));
  }
  rows.sort((a, b) => Number(a.done) - Number(b.done) || a.name.localeCompare(b.name));
  outLines(rows.map((r) => {
    const done = r.done ? "  [x]" : "     ";
    const note = r.note ? `  # ${r.note}` : "";
    return `${done} ${r.id}  ${r.name}  ${r.amount}${note}`;
  }));
}

async function cmdBuy(base, token, rest) {
  const [productQ, amount, note] = rest;
  if (!productQ) err("buy needs <product> [amount] [note]");
  const product = await resolveProductId(base, token, productQ);
  const body = {
    shopping_list_id: 1,
    product_id: product.id,
    amount: amount != null && Number.isFinite(Number(amount)) ? Number(amount) : null,
    note: note || null,
  };
  const it = await api(base, token, "/stock/shoppinglist/add-product", { method: "POST", body });
  out(`added  ${product.name}  ${body.amount ?? "n/a"}  (item ${it?.id ?? "?"})`);
}

async function cmdDone(base, token, itemId) {
  if (!itemId) err("done needs the shopping item id (see: f grocy shopping)");
  const it = await api(base, token, `/objects/shopping_list/${itemId}`);
  it.done = it.done ? 0 : 1; // toggle, so a mistake is one tap back
  await api(base, token, `/objects/shopping_list/${itemId}`, { method: "PUT", body: it });
  out(`${it.done ? "done" : "undone"}  item ${itemId}  ${it.product_name || `product ${it.product_id}`}`);
}

async function cmdRemove(base, token, rest) {
  const [productQ, amount] = rest;
  if (!productQ) err("remove needs <product> [amount]");
  const product = await resolveProductId(base, token, productQ);
  const body = { shopping_list_id: 1, product_id: product.id };
  if (amount != null && Number.isFinite(Number(amount))) body.amount = Number(amount);
  const res = await api(base, token, "/stock/shoppinglist/remove-product", { method: "POST", body });
  out(`removed  ${product.name}  ${res?.removed_amount ?? body.amount ?? "all"}`);
}

async function cmdClear(base, token, rest) {
  let listId = 1;
  const i = rest.indexOf("--list");
  if (i >= 0) {
    listId = rest[i + 1];
    if (!listId) err("--list needs an id");
  }
  await api(base, token, "/stock/shoppinglist/clear", { method: "POST", body: { shopping_list_id: Number(listId) } });
  out(`cleared  shopping list ${listId}`);
}

// ---- recipes ----
async function cmdRecipes(base, token, query) {
  const recipes = await api(base, token, "/objects/recipes");
  const fulfill = await api(base, token, "/recipes/fulfillment");
  const byId = new Map((Array.isArray(fulfill) ? fulfill : []).map((f) => [f.recipe_id, f]));
  let rows = (Array.isArray(recipes) ? recipes : []);
  if (query) {
    const ql = query.toLowerCase();
    rows = rows.filter((r) => (r.name || "").toLowerCase().includes(ql));
  }
  rows.sort((a, b) => a.name.localeCompare(b.name));
  outLines(rows.map((r) => {
    const f = byId.get(r.id);
    const ok = f ? (f.need_fulfilled ? (f.need_fulfilled_with_shopping_list ? "need list" : "missing") : "ready") : "?";
    const missing = f?.missing_products_count ? `  ${f.missing_products_count} missing` : "";
    return `${r.id}  ${r.name}  [${ok}]${missing}`;
  }));
}

async function cmdRecipe(base, token, id) {
  if (!id || !/^\d+$/.test(id)) err("recipe needs a recipe id (see: f grocy recipes)");
  const recipe = await api(base, token, `/objects/recipes/${id}`);
  const fulfill = await api(base, token, `/recipes/${id}/fulfillment`);
  out({
    id: recipe.id,
    name: recipe.name,
    description: recipe.description || undefined,
    servings: recipe.servings || undefined,
    servings_unit: recipe.servings_unit || undefined,
    recipe_pos: (recipe.recipe_pos || []).map((p) => ({
      product: p.product_name,
      amount: p.amount,
      unit: p.quantity_unit_stock_name,
      in_stock: p.is_in_stock,
    })),
    fulfillment: {
      ready: fulfill?.need_fulfilled === false,
      ready_with_shopping_list: fulfill?.need_fulfilled_with_shopping_list === true,
      missing_products: fulfill?.missing_products_count ?? null,
      estimated_cost: fulfill?.costs ?? null,
    },
  });
}

async function cmdCook(base, token, id) {
  if (!id || !/^\d+$/.test(id)) err("cook needs a recipe id");
  const recipe = await api(base, token, `/objects/recipes/${id}`);
  await api(base, token, `/recipes/${id}/consume`, { method: "POST", body: { servings: 1 } });
  out(`consumed in-stock ingredients for  ${recipe.name}`);
}

async function cmdRecipeNeed(base, token, id) {
  if (!id || !/^\d+$/.test(id)) err("recipe-need needs a recipe id");
  const recipe = await api(base, token, `/objects/recipes/${id}`);
  const added = await api(base, token, `/recipes/${id}/add-not-fulfilled-products-to-shoppinglist`, {
    method: "POST",
    body: { shopping_list_id: 1, servings: 1 },
  });
  out(`added unfulfilled ingredients of  ${recipe.name}  to shopping list${added ? `  (${added})` : ""}`);
}

// ---- chores ----
async function cmdChores(base, token, query) {
  const current = await api(base, token, "/chores");
  let rows = (Array.isArray(current) ? current : []);
  if (query) {
    const ql = query.toLowerCase();
    rows = rows.filter((c) => (c.chore_name || "").toLowerCase().includes(ql));
  }
  rows.sort((a, b) => (a.next_estimated_execution_time || "").localeCompare(b.next_estimated_execution_time || ""));
  outLines(rows.map((c) => {
    const next = c.next_estimated_execution_time ? `${c.next_estimated_execution_time.slice(0, 10)} (${relDays(c.next_estimated_execution_time)})` : "manual";
    const last = c.last_tracked_time ? c.last_tracked_time.slice(0, 10) : "-";
    return `${c.chore_id}  ${c.chore_name}  next ${next}  last ${last}`;
  }));
}

async function cmdChore(base, token, q) {
  const c = await findChore(base, token, q);
  out(c);
}

async function cmdDid(base, token, q) {
  if (!q) err("did needs a chore (name or id)");
  const c = await findChore(base, token, q);
  await api(base, token, `/chores/${c.id}/execute`, { method: "POST", body: {} });
  out(`tracked  ${c.name}`);
}

// ---- tasks ----
async function cmdTasks(base, token, query) {
  const tasks = await api(base, token, "/tasks");
  let rows = (Array.isArray(tasks) ? tasks : []);
  if (query) {
    const ql = query.toLowerCase();
    rows = rows.filter((t) => (t.name || "").toLowerCase().includes(ql) || (t.description || "").toLowerCase().includes(ql));
  }
  rows.sort((a, b) => (a.due_date || "").localeCompare(b.due_date || ""));
  outLines(rows.map((t) => {
    const due = t.due_date ? `${t.due_date.slice(0, 10)} (${relDays(t.due_date)})` : "";
    const cat = t.category?.name || "";
    const desc = t.description ? `  ${t.description}` : "";
    return `${t.id}  ${t.name}${due ? "  due " + due : ""}${cat ? "  [" + cat + "]" : ""}${desc}`;
  }));
}

async function cmdTask(base, token, id) {
  if (!id || !/^\d+$/.test(id)) err("task needs a task id (see: f grocy tasks)");
  const tasks = await api(base, token, "/tasks");
  const t = (Array.isArray(tasks) ? tasks : []).find((x) => x.id === Number(id));
  if (!t) err(`task ${id} not found (done tasks are not returned by /tasks)`);
  out(t);
}

async function cmdTaskDone(base, token, id) {
  if (!id || !/^\d+$/.test(id)) err("taskdone needs a task id");
  await api(base, token, `/tasks/${id}/complete`, { method: "POST", body: {} });
  out(`done  task ${id}`);
}

// ---- batteries ----
async function cmdBatteries(base, token, query) {
  const current = await api(base, token, "/batteries");
  let rows = (Array.isArray(current) ? current : []);
  if (query) {
    const ql = query.toLowerCase();
    rows = rows.filter((b) => (b.battery?.name || "").toLowerCase().includes(ql));
  }
  rows.sort((a, b) => (a.next_estimated_charge_time || "").localeCompare(b.next_estimated_charge_time || ""));
  outLines(rows.map((b) => {
    const next = b.next_estimated_charge_time ? `${b.next_estimated_charge_time.slice(0, 10)} (${relDays(b.next_estimated_charge_time)})` : "no interval";
    const last = b.last_tracked_time ? b.last_tracked_time.slice(0, 10) : "-";
    return `${b.battery_id}  ${b.battery?.name || `battery ${b.battery_id}`}  next ${next}  last ${last}`;
  }));
}

async function cmdBattery(base, token, q) {
  const b = await findBattery(base, token, q);
  out(b);
}

async function cmdCharged(base, token, q) {
  if (!q) err("charged needs a battery (name or id)");
  const b = await findBattery(base, token, q);
  await api(base, token, `/batteries/${b.id}/charge`, { method: "POST", body: {} });
  out(`charged  ${b.name}`);
}

// ---- calendar ----
async function cmdCalendar(base, token) {
  const link = await api(base, token, "/calendar/ical/sharing-link");
  out({ ical_url: link?.public_link ?? link, note: "feed includes meal plan, chores, tasks; use in any calendar app" });
}

// ---- generic objects ----
async function cmdObj(base, token, rest) {
  const [entity, id] = rest;
  if (!entity) err("obj needs an entity, e.g. f grocy obj locations");
  const data = id != null
    ? await api(base, token, `/objects/${entity}/${id}`)
    : await api(base, token, `/objects/${entity}`);
  out(data);
}

// ---- entry ----
function usage() {
  err(
    "usage: f grocy <cmd>\n" +
    "  info                         system info (version, uptime)\n" +
    "  stock [query] [--low|--due]  current stock; --low below min stock, --due due/overdue/expired\n" +
    "  product <name-or-id>         product details (+ barcode:123 form)\n" +
    "  add <product> <amount> [--location <n>] [--best-before <date>]   increase stock\n" +
    "  consume <product> <amount>   decrease stock\n" +
    "  open <product> <amount>      mark as opened\n" +
    "  inventory <product> <amount> [--location <n>]   set stock to exactly\n" +
    "  transfer <product> <amount> <from-loc> <to-loc>\n" +
    "  shopping [query] [--all]     shopping list (default: open items)\n" +
    "  buy <product> <amount> [note]   add to shopping list\n" +
    "  done <item-id>               toggle shopping item done\n" +
    "  remove <product> [amount]    remove from shopping list\n" +
    "  clear [--list <id>]          clear shopping list\n" +
    "  recipes [query]              recipes + stock fulfillment\n" +
    "  recipe <id>                  recipe + ingredients + fulfillment\n" +
    "  cook <recipe-id>             consume in-stock ingredients\n" +
    "  recipe-need <recipe-id>      add missing ingredients to shopping list\n" +
    "  chores [query]               chores + next/last execution\n" +
    "  chore <name-or-id>           one chore (raw)\n" +
    "  did <chore>                  track chore execution\n" +
    "  tasks [query]                open tasks\n" +
    "  task <id>                    one task (raw)\n" +
    "  taskdone <id>                mark task done\n" +
    "  batteries [query]            batteries + next charge\n" +
    "  battery <name-or-id>         one battery (raw)\n" +
    "  charged <battery>            track charge cycle\n" +
    "  calendar                     ical sharing link (meal plan, chores, tasks)\n" +
    "  obj <entity> [id]            generic /objects/<entity> (products, locations, recipes, ...)\n" +
    "  <METHOD> <path> [json]       raw call under /api/v1, e.g. GET /stock/volatile\n" +
    "  --url <base>                 override base (default: GROCY_URL > grocy.baseUrl > creds)\n" +
    "  --token <key>                override api key (default: GROCY_TOKEN > creds)\n" +
    "  creds: f creds set <host>-host <url>  and  f creds set <host>-token <key>"
  );
}

export function register(_ctx) {
  return {
    name: "grocy",
    skills: [{ name: "f-grocy", path: path.join(_here, "SKILL.md") }],
    desc: "grocy: stock, shopping list, recipes, chores, tasks, batteries, calendar; creds: <host>-host + <host>-token",
    run: async (_argv, args, ctx) => {
      const _ = args._ ?? [];
      let flagUrl = null;
      let flagToken = null;
      const pos = [];
      const flags = {};
      for (let i = 0; i < _.length; i++) {
        const a = _[i];
        if (a === "--url") { flagUrl = _[++i]; continue; }
        if (a === "--token") { flagToken = _[++i]; continue; }
        if (a === "--low" || a === "--due" || a === "--all") { flags[a.slice(2)] = true; continue; }
        pos.push(a);
      }
      const [cmd, ...rest] = pos;
      const credsApi = (ctx && ctx.registry && ctx.registry.creds && ctx.registry.creds.credsApi) || null;
      _credsApiRef = credsApi;

      if (!cmd || cmd === "help" || cmd === "--help" || cmd === "-h") return usage();

      const g = await resolveGrocy(flagUrl, flagToken, credsApi);

      if (cmd === "urls") {
        out({
          base: g.base ?? "(none)",
          // creds' own wording, so this diagnostic cannot disagree with
          // `f creds status` (it used to print a bare `(none: locked)` with no
          // cause and no fix).
          token: g.token
            ? `${credsHintFor(g, g.host)} (len ${String(g.token).length})`
            : `(none: ${g.reason ?? "missing"} — ${credsHintFor(g, g.host).split("\n")[0]})`,
        });
        return;
      }
      const { base, token } = needCred(g);

      if (cmd === "info") {
        const i = await api(base, token, "/system/info");
        out({
          version: i.grocy_version,
          grocy_code: i.grocy_code || undefined,
          php: i.php_version,
          os: i.os,
          database: i.database_type || undefined,
        });
        return;
      }

      if (cmd === "stock") return cmdStock(base, token, rest.join(" "), flags);
      if (cmd === "product") return cmdProduct(base, token, rest.join(" "));
      if (cmd === "add" || cmd === "consume" || cmd === "open" || cmd === "inventory")
        return cmdStockAction(base, token, cmd, rest);
      if (cmd === "transfer") return cmdTransfer(base, token, rest);

      if (cmd === "shopping") return cmdShopping(base, token, rest.join(" "), flags);
      if (cmd === "buy") return cmdBuy(base, token, rest);
      if (cmd === "done") return cmdDone(base, token, rest[0]);
      if (cmd === "remove") return cmdRemove(base, token, rest);
      if (cmd === "clear") return cmdClear(base, token, rest);

      if (cmd === "recipes") return cmdRecipes(base, token, rest.join(" "));
      if (cmd === "recipe") return cmdRecipe(base, token, rest[0]);
      if (cmd === "cook") return cmdCook(base, token, rest[0]);
      if (cmd === "recipe-need") return cmdRecipeNeed(base, token, rest[0]);

      if (cmd === "chores") return cmdChores(base, token, rest.join(" "));
      if (cmd === "chore") return cmdChore(base, token, rest.join(" "));
      if (cmd === "did") return cmdDid(base, token, rest.join(" "));

      if (cmd === "tasks") return cmdTasks(base, token, rest.join(" "));
      if (cmd === "task") return cmdTask(base, token, rest[0]);
      if (cmd === "taskdone") return cmdTaskDone(base, token, rest[0]);

      if (cmd === "batteries") return cmdBatteries(base, token, rest.join(" "));
      if (cmd === "battery") return cmdBattery(base, token, rest.join(" "));
      if (cmd === "charged") return cmdCharged(base, token, rest.join(" "));

      if (cmd === "calendar") return cmdCalendar(base, token);

      if (cmd === "obj") return cmdObj(base, token, rest);

      // raw passthrough: <METHOD> <path> [json]
      const method = cmd.toUpperCase();
      if (/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/.test(method)) {
        const rawPath = rest[0];
        if (!rawPath) err(`${method} requires a path, e.g. ${method} /stock/volatile`);
        let body;
        const bodyTok = rest.findIndex((t, i) => i > 0 && /^[{[]/.test(t.trim()));
        if (bodyTok > 0) {
          const joined = rest.slice(bodyTok).join(" ");
          try {
            body = JSON.parse(joined);
          } catch (e) {
            err(`body is not valid JSON: ${e.message} — got: ${joined.slice(0, 80)}`);
          }
        } else if (rest.length > 1) {
          body = parseParams(rest.slice(1));
        }
        const p = rawPath.startsWith("/") ? rawPath : "/" + rawPath;
        return out(await api(base, token, p, { method, body }));
      }

      usage();
    },
  };
}

export default { register };
