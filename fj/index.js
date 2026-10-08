// f fj — call the Forgejo/Gitea REST API against the instance the current
// directory belongs to.
//
// Wraps the @llamaduck/forgejo-ts SDK (openapi-generated, covers the full
// /api/v1 surface: 491 endpoints). Endpoints are exposed by name (e.g.
// userGetCurrent, repoGet, repoListPullRequests). For anything the SDK doesn't
// name, a raw passthrough hits the path directly.
//
// Base URL: resolved from the git origin of the current directory (or any
// parent), so `f fj ...` inside a clone talks to the right instance.
//   - explicit --url or FORGEJO_URL env win over git origin.
//
// Auth token (in order): --token, FORGEJO_TOKEN env, then the `creds` uck
// (credsApi) using a cred named after the base-URL host as-is
// (e.g. `forgejo.kensand.net`).
// So: f creds set forgejo.kensand.net <token>   then f fj call userGetCurrent
//
// Commands:
//   f fj ls [query]            list/search endpoint names + signatures
//   f fj call <name> [json]    call a named endpoint; json = merged params
//   f fj call <name> -f file   read the json body/params from a file
//   f fj <METHOD> <path> [json]  raw call, e.g. f fj GET /repos/kensand.net/fcli-ucks
//   f fj whoami                call userGetCurrent (needs auth)
//   f fj version               call getVersion (no auth needed)
//   f fj urls                  show resolved base url (+ whether a token was found)
//
// json arg shape: flat keys map to path params and query params; a "body" key
// is sent as the request body. For named endpoints that's exactly what the
// SDK's options object looks like (path/query/body).

import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import net from "node:net";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const F = path.join(process.env.HOME ?? "", ".f");
const CRED_SOCKET = path.join(F, ".creds.sock");

// ---- SDK (lazy; only imported when we actually make a call) ----
let _sdk = null;
let _clientMod = null;
async function sdk() {
  if (_sdk) return _sdk;
  // Resolve relative to this uck's own dir (f runs it in place), so we always
  // get the version declared in package.json next to index.js.
  const here = (p) => path.join(__dirname, p);
  // The main entry exports the 491 endpoint fns. The client helpers live in a
  // subpath that isn't in package.json "exports", so load it by absolute file.
  const sdkMod = await import(here("node_modules/@llamaduck/forgejo-ts/dist/index.mjs"));
  const cm = await import(here("node_modules/@llamaduck/forgejo-ts/dist/client/index.mjs"));
  _clientMod = cm;
  _sdk = sdkMod;
  return sdkMod;
}

// ---- config resolution ----
function gitOriginUrl(cwd) {
  try {
    const out = execSync("git remote get-url origin", { cwd, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] }).trim();
    if (!out) return null;
    // For a repo clone the origin is <host>/<org>/<repo>.git. We only want the
    // instance origin (the Forgejo host root), so drop the org/repo path.
    if (out.includes("://")) {
      try { return new URL(out).origin; } catch { return null; }
    }
    // scp-like: [user@]host:org/repo.git -> host
    const m = out.match(/^(?:[\w.]+@)?([^:]+):/);
    if (m) return "https://" + m[1];
    return null;
  } catch {
    return null;
  }
}

function hostFromUrl(u) {
  try { return new URL(u).host; } catch { return u.replace(/^https?:\/\//, "").replace(/\/.*$/, ""); }
}

/** Resolve the base API URL: --url > FORGEJO_URL > git origin (walk up from cwd). */
function resolveBaseUrl(flagUrl) {
  if (flagUrl) return flagUrl.replace(/\/$/, "");
  const env = process.env.FORGEJO_URL;
  if (env) return env.replace(/\/$/, "");
  let dir = process.cwd();
  for (let i = 0; i < 8; i++) {
    const o = gitOriginUrl(dir);
    if (o) return o;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

function apiUrl(base) {
  // The SDK url templates are relative to /api/v1.
  return base ? base.replace(/\/$/, "") + "/api/v1" : null;
}

/** Read a cred from the creds daemon (same protocol as the creds uck uses). */
function daemonCall(req, socketPath) {
  return new Promise((resolve, reject) => {
    let buf = "";
    const client = net.connect(socketPath, () => {
      client.write(JSON.stringify(req));
    });
    client.on("data", (d) => (buf += d));
    client.on("end", () => {
      try { resolve(JSON.parse(buf)); } catch { reject(new Error("bad daemon response: " + buf)); }
    });
    client.on("error", (e) => reject(e));
  });
}

/** Resolve a token: --token > FORGEJO_TOKEN > creds daemon (host-keyed).
 *  The cred name is the base-URL host as-is (e.g. `forgejo.kensand.net`), with
 *  a port-stripped fallback when the host includes a port. */
async function resolveToken(flagToken, base) {
  if (flagToken) return { token: flagToken, src: "--token" };
  if (process.env.FORGEJO_TOKEN) return { token: process.env.FORGEJO_TOKEN, src: "FORGEJO_TOKEN" };
  // creds daemon: cred named after the host (try with-port first, then stripped)
  if (!base) return { token: null, src: null };
  const host = hostFromUrl(base);
  const names = host.includes(":") ? [host, host.split(":")[0]] : [host];
  try {
    for (const name of names) {
      const r = await daemonCall({ op: "get", name }, CRED_SOCKET);
      if (r && r.ok && r.value != null && r.value !== "") return { token: r.value, src: `creds:${name}` };
    }
  } catch {
    /* daemon not running or not unlocked — treat as no token */
  }
  return { token: null, src: null };
}

async function makeClient(url, token) {
  await sdk();
  const cfg = { baseURL: url };
  if (token) cfg.auth = token; // apiKey scheme -> sent as `Authorization: <token>`
  return _clientMod.createClient(_clientMod.createConfig(cfg));
}

// ---- arg helpers ----
function parseJsonArg(s) {
  if (!s) return {};
  try { return JSON.parse(s); } catch { throw new Error("json arg is not valid JSON: " + s.slice(0, 80)); }
}

/** Split a flat param object into { path, query, body } for the SDK. */
function splitParams(obj) {
  const path = {};
  const query = {};
  let body = obj.body;
  for (const [k, v] of Object.entries(obj)) {
    if (k === "body") continue;
    // keys that look like path params (owner, repo, index, id, ...) — we don't
    // know the schema, so: put "known-ish" scalar/ident keys in query, and let
    // the SDK's url template fill path params by name. Strategy: try path first
    // if the template has {k}; else query. We can't introspect the template
    // easily, so: heuristic — short identifier keys -> path, the rest -> query.
    // Simpler + robust: pass everything except `body` as query; also pass as
    // path so the template substitution picks up {owner}/{repo} etc.
    path[k] = v;
    query[k] = v;
  }
  return { path, query, body };
}

// ---- output ----
function out(o) {
  if (o == null) return;
  if (typeof o === "string") { process.stdout.write(o.endsWith("\n") ? o : o + "\n"); return; }
  process.stdout.write(JSON.stringify(o, null, 2) + "\n");
}

function err(msg) {
  process.stderr.write("f: " + msg + "\n");
  process.exit(1);
}

// ---- commands ----
function usage() {
  err(
    "usage: f fj <cmd>\n" +
    "  ls [query]               list/search endpoints (491)\n" +
    "  call <name> [json]       call a named endpoint; json = {key:val,..., body:{...}}\n" +
    "  call <name> -f file      read params from file\n" +
    "  <METHOD> <path> [json]   raw call, e.g. GET /repos/kensand.net/fcli-ucks\n" +
    "  whoami                   userGetCurrent (needs auth)\n" +
    "  version                  getVersion (no auth)\n" +
    "  urls                     show resolved base url + token source\n" +
    "  --url <base>             override base (default: git origin of cwd)\n" +
    "  --token <tok>            override token (default: FORGEJO_TOKEN, then creds)"
  );
}

/** Rank named endpoints by relevance to a query (name + camelCase words). */
function searchEndpoints(sdk, query) {
  const fns = Object.keys(sdk).filter((k) => typeof sdk[k] === "function");
  if (!query) return fns;
  const q = query.toLowerCase();
  const tokens = q.split(/[^a-z0-9]+/).filter(Boolean);
  const scored = [];
  for (const name of fns) {
    const lower = name.toLowerCase();
    // camel words
    const words = name.replace(/([A-Z])/g, " $1").toLowerCase().split(/\s+/);
    let score = 0;
    for (const t of tokens) {
      if (lower.startsWith(t)) score += 100;
      else if (lower.includes(t)) score += 40;
      if (words.some((w) => w === t)) score += 30;
      else if (words.some((w) => w.startsWith(t))) score += 12;
    }
    if (score > 0) scored.push({ name, score });
  }
  scored.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));
  return scored.map((s) => s.name);
}

/** Show signature-ish info: endpoint name + its path (scrape from the module). */
let _pathMap = null;
async function buildPathMap() {
  if (_pathMap) return _pathMap;
  _pathMap = new Map();
  try {
    const src = fs.readFileSync(path.join(__dirname, "node_modules/@llamaduck/forgejo-ts/dist/index.mjs"), "utf8");
    // Each endpoint: `var name = (options) => (options?.client ?? client).METHOD({ ..., url: "/x/{a}", ...})`
    // Walk blocks: find `var NAME = (options) =>` then the next `url:` and `responseType`/method call.
    const re = /var\s+([A-Za-z0-9_]+)\s*=\s*\(options\)\s*=>\s*\(options\?\.client\s*\?\?\s*client\)\.([a-z]+)\(\s*\{[\s\S]*?url:\s*"([^"]*)"/g;
    let m;
    while ((m = re.exec(src)) !== null) {
      const [, name, method, url] = m;
      if (!_pathMap.has(name)) _pathMap.set(name, { method: method.toUpperCase(), url });
    }
  } catch {
    // best-effort; map may be incomplete
  }
  return _pathMap;
}

async function cmdLs(query) {
  const mod = await sdk();
  const names = searchEndpoints(mod, query);
  const pm = await buildPathMap();
  const lines = names.map((n) => {
    const info = pm.get(n);
    return info ? `${info.method.padEnd(5)} ${n}  ${info.url}` : `${n}`;
  });
  process.stdout.write(lines.join("\n") + (lines.length ? "\n" : ""));
}

async function cmdCall(name, params, rawUrl, rawMethod) {
  const base = resolveBaseUrl(null);
  if (!base) err("no base url (not in a git clone; pass --url https://host)");
  const tok = await resolveToken(null, base);
  const url = apiUrl(base);
  await sdk();
  const client = await makeClient(url, tok.token);

  if (rawMethod) {
    // raw passthrough: client.<method>({ url: path, query/body, throwOnError:false })
    const { path: _ignore, query, body } = splitParams(params);
    const method = rawMethod.toLowerCase();
    const res = await client[method]({ url: rawUrl, query, body, throwOnError: false });
    return finish(res);
  }

  const fn = _sdk[name];
  if (typeof fn !== "function") err(`unknown endpoint '${name}'. Try: f fj ls ${name}`);
  const { path, query, body } = splitParams(params);
  const res = await fn({ client, path, query, body, throwOnError: false });
  return finish(res);
}

function finish(res) {
  if (res && res.error) {
    const e = res.error;
    const status = e.status ?? e.response?.status;
    const msg = e.response?.data?.message || e.message || e.code || "request failed";
    err(`API error ${status ?? ""} ${msg}`.trim());
  }
  out(res?.data !== undefined ? res.data : res);
}

// ---- entry ----
export function register(_ctx) {
  return {
    name: "fj",
    desc: "Forgejo/Gitea API via @llamaduck/forgejo-ts (ls/call/<METHOD> <path>); base from git origin, token from creds",
    run: async (_argv, args) => {
      const _ = args._ ?? [];
      // pull out global flags
      let flagUrl = null;
      let flagToken = null;
      const pos = [];
      for (let i = 0; i < _.length; i++) {
        const a = _[i];
        if (a === "--url") { flagUrl = _[++i]; continue; }
        if (a === "--token") { flagToken = _[++i]; continue; }
        pos.push(a);
      }
      const [cmd, ...rest] = pos;

      if (!cmd || cmd === "help" || cmd === "--help" || cmd === "-h") return usage();

      if (cmd === "ls") {
        return cmdLs(rest.join(" "));
      }

      if (cmd === "urls") {
        const base = resolveBaseUrl(flagUrl);
        const tok = await resolveToken(flagToken, base);
        out({
          base: base ?? "(none)",
          api: apiUrl(base),
          token: tok.token ? (tok.src + " (len " + String(tok.token).length + ")") : "(none)",
        });
        return;
      }

      if (cmd === "version") {
        const base = resolveBaseUrl(flagUrl) ?? process.env.FORGEJO_URL ?? "https://forgejo.kensand.net";
        const client = await makeClient(apiUrl(base), (await resolveToken(flagToken, base)).token);
        await sdk();
        const fn = _sdk.getVersion;
        const res = await fn({ client, throwOnError: false });
        return finish(res);
      }

      if (cmd === "whoami") {
        const base = resolveBaseUrl(flagUrl);
        if (!base) err("no base url (not in a git clone; pass --url)");
        const tok = await resolveToken(flagToken, base);
        if (!tok.token) err("no token found for " + hostFromUrl(base) + " — set one via: f creds set " + hostFromUrl(base) + " <token>");
        const client = await makeClient(apiUrl(base), tok.token);
        await sdk();
        const res = await _sdk.userGetCurrent({ client, throwOnError: false });
        return finish(res);
      }

      if (cmd === "call") {
        const name = rest[0];
        if (!name) err("call requires an endpoint name. Try: f fj ls <query>");
        // json param: last token that parses as json, or -f file
        let params = {};
        const fi = rest.indexOf("-f");
        if (fi !== -1) {
          const file = rest[fi + 1];
          if (!file) err("-f requires a file path");
          let raw;
          try {
            raw = fs.readFileSync(file, "utf8");
          } catch (e) {
            err("cannot read " + file + ": " + e.message);
          }
          try {
            params = JSON.parse(raw);
          } catch (e) {
            err("" + file + " is not valid JSON: " + e.message);
          }
          rest.splice(fi, 2);
        } else {
          const maybeJson = rest[1];
          if (maybeJson && maybeJson.trim().startsWith("{")) {
            params = parseJsonArg(maybeJson);
          }
        }
        const res = await cmdCall(name, params, null, null);
        return res;
      }

      // raw passthrough: <METHOD> <path> [json]
      const method = cmd.toUpperCase();
      if (/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/.test(method)) {
        const rawUrl = rest[0];
        if (!rawUrl) err(`${method} requires a path, e.g. ${method} /repos/kensand.net/fcli-ucks`);
        let params = {};
        const maybeJson = rest[1];
        if (maybeJson && maybeJson.trim().startsWith("{")) params = parseJsonArg(maybeJson);
        return cmdCall(null, params, rawUrl.startsWith("/") ? rawUrl : "/" + rawUrl, method);
      }

      usage();
    },
  };
}

export default { register };
