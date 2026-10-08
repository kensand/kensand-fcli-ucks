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
      // URL form: https://host/... or ssh://[user@]host/.... .origin is only
      // defined for http(s), so build the base from https:// + host (the API
      // is always https, even when the git remote is ssh://).
      try { const u = new URL(out); return u.host ? "https://" + u.host : null; } catch { return null; }
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

/** Read fj.defaultHost from f.config.json (project then global). Returns a
 *  string or null. Used as the last-resort base when not in a repo and no
 *  --url / FORGEJO_URL was given. */
function configDefaultHost() {
  const read = (p) => {
    try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch { return null; }
  };
  // project: walk up from cwd; global: ~/.f/f.config.json
  let dir = process.cwd();
  for (let i = 0; i < 8; i++) {
    const d = read(path.join(dir, "f.config.json"));
    if (d && d.fj && typeof d.fj.defaultHost === "string") return d.fj.defaultHost;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  const g = read(path.join(process.env.HOME ?? "", ".f", "f.config.json"));
  if (g && g.fj && typeof g.fj.defaultHost === "string") return g.fj.defaultHost;
  return null;
}

/** Resolve the base API URL: --url > FORGEJO_URL > git origin (walk up from cwd)
 *  > fj.defaultHost config (last resort, when not in a repo). */
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
  // Last resort: config default host (only reached when not in a git repo).
  const def = configDefaultHost();
  if (def) return def.replace(/\/$/, "");
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

/** Resolve a token: --token > FORGEJO_TOKEN > creds (host-keyed). When no flag
 *  or env token is set, uses credsApi.wait() to block up to `timeout` ms for the
 *  cred to be supplied in another terminal (also waits for unlock). The cred
 *  name is the base-URL host as-is (e.g. `forgejo.kensand.net`), with a
 *  port-stripped fallback when the host includes a port. */
async function resolveToken(flagToken, base, credsApi, timeout) {
  if (flagToken) return { token: flagToken, src: "--token" };
  if (process.env.FORGEJO_TOKEN) return { token: process.env.FORGEJO_TOKEN, src: "FORGEJO_TOKEN" };
  // creds: cred named after the host (try with-port first, then stripped)
  if (!base) return { token: null, src: null };
  const host = hostFromUrl(base);
  const names = host.includes(":") ? [host, host.split(":")[0]] : [host];
  // Prefer the blocking wait (via the creds uck) so the user can supply the
  // token in another terminal while f blocks. Fall back to a one-shot raw get
  // if the creds uck isn't available.
  const waitFor = async (name) => {
    if (credsApi && typeof credsApi.wait === "function") {
      return credsApi.wait(name, { timeout });
    }
    // fallback: immediate get (no blocking)
    try {
      const r = await daemonCall({ op: "get", name }, CRED_SOCKET);
      if (r && r.ok && r.value != null && r.value !== "") return r.value;
    } catch {}
    return null;
  };
  for (const name of names) {
    try {
      const v = await waitFor(name);
      if (v != null && v !== "") return { token: v, src: `creds:${name}` };
    } catch (e) {
      // timed out or daemon issue — keep trying the next name, then give up
      if (e && /timed out/.test(e.message)) return { token: null, src: null, error: e.message };
    }
  }
  return { token: null, src: null };
}

async function makeClient(url, token) {
  await sdk();
  const cfg = { baseURL: url };
  // Send the credential as an explicit Authorization header.
  //
  // NOT `cfg.auth = token`, which is what this used to do and which made every
  // authenticated call fail. Two independent reasons `auth` cannot work here:
  //
  //   1. `auth` is inert unless `security` is set on the request. In
  //      dist/client/index.js, beforeRequest() calls setAuthParams() only
  //      inside `if (opts.security)`, and createConfig() never sets
  //      `security`. So the token never reaches any request and every call
  //      goes out ANONYMOUSLY. The failure looked like a creds problem --
  //      "token is malformed: token contains an invalid number of segments /
  //      access token is empty" / "user does not exist [uid: 0]" -- while
  //      `f fj version` (no auth needed) worked fine, which is exactly what
  //      made it look like the token was bad rather than unsent.
  //   2. Even with `security` set, getAuthToken() prefixes `Bearer `/`Basic `
  //      only when the auth object declares a scheme; a bare string is sent
  //      raw, and Forgejo rejects a raw personal access token.
  //
  // Forgejo accepts both `token <pat>` (the Gitea-native spelling, and the
  // form the SDK's own README documents) and `Bearer <pat>`; verified against
  // this instance with each. `token` is used.
  if (token) cfg.headers = { Authorization: "token " + token };
  return _clientMod.createClient(_clientMod.createConfig(cfg));
}

// ---- arg helpers ----
function parseJsonArg(s) {
  if (!s) return {};
  try { return JSON.parse(s); } catch { throw new Error("json arg is not valid JSON: " + s.slice(0, 80)); }
}

/** Split a flat param object into { path, query, body } for the SDK.
 *
 *  `urlTemplate` is the endpoint's path template (e.g. "/repos/{owner}/{repo}")
 *  when known. It is required, not a convenience: the SDK fills `{placeholders}`
 *  from `path` using the names IN THE TEMPLATE, and the API's declared parameter
 *  names are not always those. repoGet's template is /repos/{owner}/{repo} while
 *  its parameters are ownerName/repoName, so a caller who passes
 *  ownerName=kensand.net repoName=foo fills nothing, the braces go out literally,
 *  and Forgejo answers by looking up a user literally named "{owner}" --
 *  GetUserByName. Renaming on our side is how the two halves are reconciled;
 *  guessing it from key shape (the previous heuristic here) cannot work, and
 *  leaking template-only keys into the query string is why `?ownerName=...` used
 *  to ride along on every call.
 */
function splitParams(obj, urlTemplate) {
  const path = {};
  const query = {};
  let body = obj.body;
  const wants = urlTemplate
    ? new Set([...urlTemplate.matchAll(/\{([^{}/]+?)(?:\*)?\}/g)].map((m) => m[1]))
    : null;
  for (const [k, v] of Object.entries(obj)) {
    if (k === "body") continue;
    if (!wants) {
      // No template (raw <METHOD> <path> calls): nothing to substitute, so
      // everything except body is a query param and `path` stays empty.
      query[k] = v;
      continue;
    }
    if (wants.has(k)) path[k] = v;
    else query[k] = v;
  }
  // Fail loudly on a template slot nobody filled: a literal "{owner}" in the
  // URL produces a confusing server-side lookup error, not a 404 on our side.
  if (wants) {
    // Template slot names and the API's declared parameter names disagree for
    // the whole /repos/{owner}/{repo} family: the template says `owner`/`repo`,
    // the operation's parameters are `ownerName`/`repoName`. So accept either
    // spelling for these two, and prefer whichever the caller actually gave.
    const aliases = { owner: ["owner", "ownerName"], repo: ["repo", "repoName"] };
    for (const [slot, names] of Object.entries(aliases)) {
      if (path[slot] !== undefined) continue;
      const hit = names.map((n) => [n, obj[n]]).find(([, v]) => v !== undefined);
      if (hit) {
        path[hit[0]] = hit[1];
        delete query[hit[0]]; // it is a path segment, not a query param
        // Rename onto the slot name so the serializer substitutes it. A caller
        // who wrote ownerName=... should not have to know the template differs.
        if (slot !== hit[0] && wants.has(slot)) {
          path[slot] = hit[1];
          delete path[hit[0]];
        }
      }
    }
    const missing = [...wants].filter((w) => path[w] === undefined);
    if (missing.length)
      err(
        `missing path parameter(s): ${missing.join(", ")} for ${urlTemplate}` +
          ` -- pass them as key=value (see: f fj ls <endpoint>)`,
      );
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
    "  --url <base>             override base (default: FORGEJO_URL > git origin > fj.defaultHost)\n" +
    "  --token <tok>            override token (default: FORGEJO_TOKEN, then creds)\n" +
    "  --timeout <sec>          creds wait window (default 300s); only used when\n" +
    "                           no --token/FORGEJO_TOKEN — fj blocks that long for\n" +
    "                           you to set the cred in another terminal"
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
    // Each endpoint is emitted as one of two spellings, and BOTH occur in the
    // shipped dist/index.mjs:
    //   var userGetCurrent = (options) => (options?.client ?? client).get({ ... })
    //   var repoGet        = (options) => (options.client  ?? client).get({ ... })
    // so the group is `(?:\?)?\.?` — optional `?`, optional `.`.
    //
    // It used to be `(?:\?\.)?`, which reads as "optionally the two-character
    // sequence ?." — that accepts `options?.client` and even `optionsclient`, but
    // REJECTS the plain `options.client` that repoGet/repoListPullRequests/
    // repoCreatePullRequest are generated with. Consequence: the map held 76 of
    // 491 endpoints, and a missing entry fails SILENTLY — cmdCall gets
    // urlTemplate=null and routes path params into the query string, so
    // `call repoGet ownerName=… repoName=…` requested
    // `/repos/{owner}/{repo}?ownerName=…` and Forgejo replied by looking up a
    // user literally named "{owner}": the unhelpful `GetUserByName` error.
    // `f fj ls` still printed 491 names, which is what hid this.
    //
    // If you touch this, print the parse count: it must equal the number of
    // endpoints `ls` lists (491 today), and spot-check a templated one such as
    // repoGet -> "/repos/{owner}/{repo}".
    const re =
      /var\s+([A-Za-z0-9_]+)\s*=\s*\(options\)\s*=>\s*\(options(?:\?)?\.?client\s*\?\?\s*client\)\.([a-z]+)\(\s*\{[\s\S]*?url:\s*"([^"]*)"/g;
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

async function cmdCall(name, params, rawUrl, rawMethod, credsApi, timeout) {
  const base = resolveBaseUrl(null);
  if (!base) err("no base url (not in a git clone; pass --url https://host or set fj.defaultHost)");
  const tok = await resolveToken(null, base, credsApi, timeout);
  const url = apiUrl(base);
  await sdk();
  const client = await makeClient(url, tok.token);

  if (rawMethod) {
    // raw passthrough: client.<method>({ url: path, query/body, throwOnError:false })
    // A caller-supplied path is already resolved, so there is no template here.
    const { path: _ignore, query, body } = splitParams(params, null);
    const method = rawMethod.toLowerCase();
    const res = await client[method]({ url: rawUrl, query, body, throwOnError: false });
    return finish(res);
  }

  const fn = _sdk[name];
  if (typeof fn !== "function") err(`unknown endpoint '${name}'. Try: f fj ls ${name}`);
  // Look up this endpoint's path template so path/query split by real name.
  const pm = await buildPathMap();
  const urlTemplate = pm.get(name)?.url || null;
  const { path, query, body } = splitParams(params, urlTemplate);
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
    run: async (_argv, args, ctx) => {
      const _ = args._ ?? [];
      // pull out global flags
      let flagUrl = null;
      let flagToken = null;
      let timeoutSec = 300; // default creds-wait window (5 min)
      const pos = [];
      for (let i = 0; i < _.length; i++) {
        const a = _[i];
        if (a === "--url") { flagUrl = _[++i]; continue; }
        if (a === "--token") { flagToken = _[++i]; continue; }
        if (a === "--timeout") { timeoutSec = Number(_[++i]); continue; }
        pos.push(a);
      }
      const [cmd, ...rest] = pos;
      const timeout = timeoutSec * 1000;
      // creds uck (for blocking wait), if available
      const credsApi = (ctx && ctx.registry && ctx.registry.creds && ctx.registry.creds.credsApi) || null;

      if (!cmd || cmd === "help" || cmd === "--help" || cmd === "-h") return usage();

      if (cmd === "ls") {
        return cmdLs(rest.join(" "));
      }

      if (cmd === "urls") {
        const base = resolveBaseUrl(flagUrl);
        // diagnostic — don't block on creds; just report what's immediately available
        const tok = await resolveToken(flagToken, base, null, timeout);
        out({
          base: base ?? "(none)",
          api: apiUrl(base),
          token: tok.token ? (tok.src + " (len " + String(tok.token).length + ")") : "(none)",
        });
        return;
      }

      if (cmd === "version") {
        const base = resolveBaseUrl(flagUrl);
        if (!base) err("no base url (not in a git clone, no --url/FORGEJO_URL, no fj.defaultHost)");
        const client = await makeClient(apiUrl(base), (await resolveToken(flagToken, base, credsApi, timeout)).token);
        await sdk();
        const fn = _sdk.getVersion;
        const res = await fn({ client, throwOnError: false });
        return finish(res);
      }

      if (cmd === "whoami") {
        const base = resolveBaseUrl(flagUrl);
        if (!base) err("no base url (not in a git clone; pass --url)");
        const tok = await resolveToken(flagToken, base, credsApi, timeout);
        if (!tok.token) {
          const detail = tok.error ? `\n${tok.error}` : "";
          err("no token found for " + hostFromUrl(base) + " — set one via: f creds set " + hostFromUrl(base) + " <token>" + detail);
        }
        const client = await makeClient(apiUrl(base), tok.token);
        await sdk();
        const res = await _sdk.userGetCurrent({ client, throwOnError: false });
        return finish(res);
      }

      if (cmd === "call") {
        const name = rest[0];
        if (!name) err("call requires an endpoint name. Try: f fj ls <query>");
        // json param: a {...} token, -f file, or repeated key=value pairs.
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
          } else {
            // key=value pairs. The usage string has always advertised
            // `call <name> [json = {key:val,...}]`, and `f fj ls` prints
            // templates like /repos/{owner}/{repo}, so a caller naturally types
            // `call repoGet ownerName=x repoName=y`. That form was never
            // implemented: params stayed {} and the call went out with its
            // {owner}/{repo} braces unsubstituted, which surfaced as the opaque
            // `GetUserByName` rather than "you passed no parameters".
            //
            // Values are JSON-parsed so numbers/bools/nested bodies work
            // (`index=3`, `merged=true`, `body={...}`); a value that is not
            // valid JSON is kept as the literal string, which is what `head=main`
            // needs (JSON.parse would otherwise reject it, not coerce it).
            for (const tok of rest.slice(1)) {
              const eq = tok.indexOf("=");
              if (eq <= 0) continue; // not key=value; ignore, like before
              const k = tok.slice(0, eq);
              const raw = tok.slice(eq + 1);
              let v = raw;
              if (raw !== "" && /^[[{\d-]|^(true|false|null)$/.test(raw)) {
                try { v = JSON.parse(raw); } catch { /* keep as string */ }
              }
              params[k] = v;
            }
          }
        }
        const res = await cmdCall(name, params, null, null, credsApi, timeout);
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
        return cmdCall(null, params, rawUrl.startsWith("/") ? rawUrl : "/" + rawUrl, method, credsApi, timeout);
      }

      usage();
    },
  };
}

export default { register };
