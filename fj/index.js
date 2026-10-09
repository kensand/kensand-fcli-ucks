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

/** True when the creds daemon is up with time left on its ttl.
 *
 * Reads the lockfile the creds uck writes (~/.f/.creds-daemon: {pid, start,
 * ttl, socket}) rather than asking the daemon, so this is a file read plus a
 * liveness check and never blocks. Same three conditions the creds uck itself
 * applies in unlockedState(): a live pid, and a ttl that has not elapsed. */
function credsUnlocked() {
  let lf;
  try {
    lf = JSON.parse(fs.readFileSync(path.join(F, ".creds-daemon"), "utf8"));
  } catch {
    return null;
  }
  if (!lf || !lf.pid || !lf.start || !lf.ttl) return null;
  try {
    process.kill(lf.pid, 0); // liveness only; throws if dead or not ours
  } catch {
    return null;
  }
  const remainingMs = lf.start + lf.ttl * 1000 - Date.now();
  return remainingMs > 0 ? { remainingMs, socket: lf.socket } : null;
}

/**
 * Resolve a token: --token > FORGEJO_TOKEN > creds (host-keyed). The cred name
 * is the base-URL host as-is (e.g. `forgejo.kensand.net`), with a port-stripped
 * fallback when the host includes a port.
 *
 * NEVER BLOCKS. It used to call credsApi.wait() for up to `timeout` (default
 * 300s) so the user could supply a token in another terminal while the command
 * sat there. That turned every credential problem into a five-minute hang, and
 * a hang is strictly worse than an error: nothing is printed, so "waiting for
 * you" is indistinguishable from "working", "found nothing" and "network stuck".
 * It fired on the most common failure of all -- the creds ttl is 10 minutes --
 * and `f fj version` answering instantly beside it made the token look rejected
 * rather than absent. `--wait` opts back in for the one case it helped: a
 * long-running job that wants to park until a human sets a cred.
 *
 * The three ways to get here are distinguished, because they need different
 * fixes and all three previously reported the same nothing:
 *   locked        store is not unlocked        -> `f creds unlock`
 *   unset         unlocked, cred absent        -> `f creds set <host> <token>`
 *   no creds uck  daemon unreachable outright  -> raw socket get also failed
 */
async function resolveToken(flagToken, base, credsApi, opts = {}) {
  if (flagToken) return { token: flagToken, src: "--token" };
  if (process.env.FORGEJO_TOKEN) return { token: process.env.FORGEJO_TOKEN, src: "FORGEJO_TOKEN" };
  if (!base) return { token: null, src: null, reason: "no-base" };
  const host = hostFromUrl(base);
  const names = host.includes(":") ? [host, host.split(":")[0]] : [host];

  const state = credsUnlocked();
  if (!state && !opts.waitMs) {
    return { token: null, src: null, reason: "locked", host };
  }

  // Opt-in blocking, and only via the creds uck: it owns the waiter registry
  // that `f creds waiters` / `f creds fill` read, so a hand-rolled poll loop
  // here would block invisibly with nothing for the other terminal to see.
  // With --wait and no creds uck we fall through to the one-shot reads below,
  // which is the old non-blocking behavior, not a silent lie about waiting.
  if (!state && opts.waitMs && credsApi && typeof credsApi.wait === "function") {
    try {
      for (const name of names) {
        const v = await credsApi.wait(name, { timeout: opts.waitMs });
        if (v != null && v !== "") return { token: v, src: `creds:${name} (waited)` };
      }
    } catch {
      /* timed out -- report the reason below rather than a stack */
    }
    return { token: null, src: null, reason: "wait-timeout", host };
  }

  // One-shot reads. Note `credsApi.get` throws "creds locked" on its own, which
  // is why the lockfile is consulted first: catching that exception would work
  // but cannot distinguish "locked" from "that cred is not set".
  const read = async (name) => {
    if (credsApi && typeof credsApi.get === "function") {
      try {
        return await credsApi.get(name);
      } catch (e) {
        // "not found" for this name is expected when the port-stripped host is
        // tried second; anything else is worth surfacing rather than swallowing.
        if (e && /locked/i.test(e.message)) return { locked: true };
        return null;
      }
    }
    try {
      const r = await daemonCall({ op: "get", name }, state.socket || CRED_SOCKET);
      if (r && r.ok) return r.value;
      return null;
    } catch {
      return null;
    }
  };

  for (const name of names) {
    const v = await read(name);
    if (v && v.locked) return { token: null, src: null, reason: "locked", host };
    if (v != null && v !== "") return { token: v, src: `creds:${name}` };
  }
  return { token: null, src: null, reason: "unset", host };
}

/**
 * A dead store or an absent cred must stop the command, not degrade it. The
 * check lives here rather than at each call site because a uck that calls the
 * API anonymously returns whatever the instance exposes publicly and looks
 * fine: `f fj whoami` reported `user does not exist [uid: 0]` for the whole
 * session that the token was never being sent. `urls` is the exception -- it
 * REPORTS the token state, so an empty one is its answer, not an error.
 */
function needToken(tok) {
  if (tok.token) return tok.token;
  if (tok.reason === "locked")
    err(
      `creds are locked (no token for ${tok.host})\n` +
        `  unlock it: f creds unlock\n` +
        `  or send one now: f fj --token <pat> ... / FORGEJO_TOKEN=...\n` +
        `  or wait for one to be set: f fj --wait ...`,
    );
  if (tok.reason === "unset" || tok.reason === "wait-timeout")
    err(
      tok.reason === "wait-timeout"
        ? `no credential for ${tok.host} appeared while waiting\n` +
            `  store it: f creds set ${tok.host} <pat>\n` +
            `  names already stored: f creds ls`
        : `no credential stored for ${tok.host}\n` +
            `  store it: f creds set ${tok.host} <pat>\n` +
            `  or send one now: f fj --token <pat> ... / FORGEJO_TOKEN=...\n` +
            `  names already stored: f creds ls`,
    );
  if (tok.reason === "no-base")
    err("no base url (not in a git clone; pass --url https://host or set fj.defaultHost)");
  err(`no token available (${tok.reason ?? "unknown"})`);
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

// Coerce a parsed param object when it came through as a single JSON string.
// Most common cause: the caller wrapped the payload in quotes, e.g.
// `f fj call ep '{"owner":...}'` or `-f "$(cat file.json)"`. The first
// JSON.parse then yields the string `{"owner":...}` rather than the object.
// Re-parsing that string restores the intended object; anything else stays
// a hard error.
function ensureJsonObject(obj, src) {
  if (obj && typeof obj === "object") return obj;
  if (typeof obj === "string") {
    try { return JSON.parse(obj); } catch {
      err("" + src + " did not yield a JSON object (got a string that is not itself valid JSON)");
    }
  }
  err("" + src + " did not yield a JSON object");
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
    if (k === "body") {
      // A body that arrived as a JSON string (quoted inline arg or -f file)
      // is the caller's intent to send the parsed object, not a raw string.
      if (typeof body === "string" && body.trim()) {
        try { body = JSON.parse(body); } catch { /* keep the string body */ }
      }
      continue;
    }
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
    "  --wait [sec]             block until a cred appears (default 300s). Off by\n" +
    "                           default: without a token fj fails immediately and\n" +
    "                           says whether creds are locked or simply unset.\n" +
    "  runs [newest|<run_id>]   list recent action runs (id status event sha ref) / show one\n" +
    "  runs <run_id> --joblogs [grep] [--job <n>] [--out dir]  download+grep a run's job logs\n" +
    "  joblogs <run_id> ...     same as `runs <run_id> --joblogs`\n" +
    "  --repo <owner>/<repo>    (runs/joblogs) target repo; default: git origin\n" +
    "  --timeout <sec>          deprecated alias for --wait <sec>"
  );
}

/** Rank named endpoints by relevance to a query.
 *
 * Scores the NAME and, since this was written, the URL TEMPLATE too. The name
 * alone made `f fj ls actions` and `ls Logs` return nothing useful even though
 * the SDK ships actionRun (/repos/{owner}/{repo}/actions/runs/{run_id}) and
 * listActionRuns -- you could not discover them by what they are for, so you
 * ended up guessing REST paths by hand and reading 404s as permission failures.
 * Paths are also what `ls` prints, so a query that cannot match them makes the
 * tool unable to answer its own output.
 * */
function searchEndpoints(sdk, query, pathMap) {
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
    // Path segments, scored below every name hit so "repoGet" still wins over a
    // endpoint that merely lives under /repos/. A segment match is what people
    // type when they know the URL but not the operation name.
    const url = pathMap?.get(name)?.url;
    if (url) {
      const segs = url.toLowerCase().replace(/[{}]/g, " ").split(/[^a-z0-9]+/).filter(Boolean);
      for (const t of tokens) {
        if (segs.some((s) => s === t)) score += 28;
        else if (segs.some((s) => s.startsWith(t))) score += 10;
        else if (url.toLowerCase().includes(t)) score += 6;
      }
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
  // Build the path map FIRST: ranking needs the URL templates, not just names.
  const pm = await buildPathMap();
  const names = searchEndpoints(mod, query, pm);
  if (query && !names.length) {
    // Silence was the bug. `ls <query>` printed nothing for a query matching no
    // endpoint, indistinguishable from "nothing found" -- the same failure shape
    // as a locked creds store printing nothing. Only claim a near miss when one
    // is real: dropping a suffix (repoListPullRequestFiles -> repoGetPullRequest)
    // is not a typo correction, and suggesting a query that also returns nothing
    // sends the caller in circles. So: report the empty result, and say plainly
    // that this SDK may simply not expose the operation.
    //
    // Genuinely absent from the 491 generated operations, verified: any Actions
    // *log* endpoint. `ls runs` finds listActionRuns/actionRun, but there is no
    // /logs path in the spec -- fetching a log means a raw GET (see the ACTIONS
    // note below), not a named endpoint.
    err(
      `no endpoint matches '${query}' among ${Object.keys(mod).filter((k) => typeof mod[k] === "function").length} generated operations.\n` +
        `  search by a path word instead (f fj ls runs | pulls | secrets | runners)\n` +
        `  some operations are absent from the spec -- Actions LOGS are: call the raw path instead\n` +
        `  (f fj GET /repos/<owner>/<repo>/actions/runs/<run_id>/logs, see 'f fj ls runs' for the run id)`,
    );
  }
  const lines = names.map((n) => {
    const info = pm.get(n);
    return info ? `${info.method.padEnd(5)} ${n}  ${info.url}` : `${n}`;
  });
  process.stdout.write(lines.join("\n") + (lines.length ? "\n" : ""));
}

/**
 * ACTIONS RUN ID -- read this before hand-writing an /actions/runs/... path.
 * Three different numbers identify one run, and mixing them up looks exactly
 * like a permissions failure:
 *
 *   listActionRuns[].id        3583   what /actions/runs/{run_id} and its /logs
 *                                     child endpoint accept. THIS is the one.
 *   listActionTasks[].id       43     per-ATTEMPT row id. Not a run id.
 *   listActionTasks[].run_number 10   what the WEB UI URL shows (/runs/10).
 *
 * /repos/{o}/{r}/actions/tasks is not in the 491 generated operations by that
 * name (listActionTasks is, and it is the same endpoint), and its `id` is the
 * trap: feeding it to /actions/runs/{run_id} returns
 *   {"message":"resource does not exist"}
 * with no status code (the SDK gives none), which reads as "your token cannot
 * read Actions" when it only means "wrong number". Resolve the id with
 * `f fj call listActionRuns owner=... repo=...` and use .id.
 *
 * Logs: GET /repos/{owner}/{repo}/actions/runs/{run_id}/logs returns a ZIP
 * (one <job>-<jobid>-attempt-N.log per job), not text. Per-job
 * /jobs/{id}/logs does NOT exist on this instance -- 404. There is no named
 * endpoint for logs at all, so it must be a raw GET.
 * */

// ---- actions (runs / joblogs) ----
//
// The run ids that appear in these commands are the listActionRuns[].id
// values (e.g. 3583). The web UI's /actions/runs/10 uses run_number (a
// different counter); /actions/tasks ids are per-attempt row ids. Only
// the former work with /actions/runs/{run_id}.

async function actionsBase(flagUrl) {
  const base = resolveBaseUrl(flagUrl);
  if (!base) err("no base url (not in a git clone; pass --url https://host or set fj.defaultHost)");
  return apiUrl(base);
}

async function actionsClient(flagUrl, flagToken, credsApi, opts) {
  const base = resolveBaseUrl(flagUrl);
  if (!base) err("no base url (not in a git clone; pass --url)");
  const tok = await resolveToken(flagToken, base, credsApi, opts);
  needToken(tok);
  await sdk();
  // A raw-path client: the actions endpoints we need (run listing, run detail,
  // run jobs, run logs) take the repo as ownerName/repoName in their declared
  // parameters, but the named SDK fns bind the TEMPLATE names {owner}/{repo},
  // so passing ownerName=... through splitParams leaves the braces unfilled
  // and Forgejo 404s looking up a user literally named "{owner}".
  return makeClient(apiUrl(base), tok.token);
}

function parseKvPairs(tokens) {
  const out = {};
  for (const t of tokens) {
    const eq = t.indexOf("=");
    if (eq <= 0) continue;
    const k = t.slice(0, eq);
    let v = t.slice(eq + 1);
    if (v !== "" && /^[[{\d-]|^(true|false|null)$/.test(v)) {
      try { v = JSON.parse(v); } catch { /* keep as string */ }
    }
    out[k] = v;
  }
  return out;
}

function parseRepoPath(p) {
  const m = p.match(/^\/repos\/([^/]+)\/([^/]+)\/?(.*)$/);
  if (!m) err(`expected /repos/<owner>/<repo>[/...] or <owner>/<repo>[/...]`);
  return { owner: m[1], repo: m[2], rest: m[3] || null };
}

function repoPathFromCwd() {
  // <owner>/<repo> from the git origin of the current directory.
  try {
    const out = execSync("git remote get-url origin", { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] }).trim();
    if (!out) err("no git origin in current directory; pass <owner>/<repo>");
    // https://host/owner/repo(.git) or [user@]host:owner/repo(.git)
    const m = out.match(/[:/]([^/:\s]+)\/([^/:\s]+?)(?:\.git)?$/);
    if (!m) err(`cannot parse owner/repo from git origin: ${out}`);
    return `${m[1]}/${m[2]}`;
  } catch {
    err("no git origin in current directory; pass <owner>/<repo>");
  }
}

function repoPathArg(rest) {
  // Explicit --repo value wins, else the first bare owner/repo token, else
  // the git origin of the current directory. Tokens with '=' or '-' are
  // key=value pairs or flags and are never candidates.
  const i = rest.indexOf("--repo");
  if (i !== -1) {
    const v = rest[i + 1];
    if (!v || v.includes("/")) return v;
    err("--repo needs <owner>/<repo>");
  }
  const p = rest.find((t) => !t.startsWith("-") && !t.includes("=") && t !== "newest" && !/^\d+$/.test(t) && t.includes("/"));
  return p ? p : repoPathFromCwd();
}

function runLine(r) {
  const sha = String(r.commit_sha || "").slice(0, 8);
  const ref = r.prettyref || r.head_branch || "";
  const concl = r.conclusion || r.status || "";
  const dur = r.duration ? ` ${Math.round(r.duration / 60000000000)}m` : "";
  const id = r.id != null ? r.id : "?";
  return `${id}\t${concl.padEnd(10)}\t${r.event || "".padEnd(14)}\t${sha}\t${ref}${dur}`;
}

async function cmdActionsRuns(sub, rest, flagUrl, flagToken, credsApi, opts) {
  const i = rest.indexOf("--joblogs");
  if (i !== -1) return cmdJoblogs(rest.filter((_, j) => j !== i), flagUrl, flagToken, credsApi, opts);
  if (i === -1 && sub === "joblogs") return cmdJoblogs(rest, flagUrl, flagToken, credsApi, opts);
  if (sub !== "runs" && sub !== "run") err("usage: f fj runs [newest|<run_id>] [--repo <owner>/<repo>] [--watch] [--joblogs] | f fj runs <run_id> --joblogs [--job <name>] [grep]");

  const repoPath = repoPathArg(rest);
  const { owner, repo } = parseRepoPath("/repos/" + repoPath);
  const client = await actionsClient(flagUrl, flagToken, credsApi, opts);
  await sdk();

  const idArg = rest.find((t) => /^\d+$/.test(t));
  const newest = rest.includes("newest") || !idArg;

  if (!newest) {
    const rRes = await client.get({ url: `/repos/${owner}/${repo}/actions/runs/${idArg}`, throwOnError: false });
    if (rRes?.error) return finish(rRes);
    const r = rRes.data;
    const jobsRes = await client.get({ url: `/repos/${owner}/${repo}/actions/runs/${idArg}/jobs`, throwOnError: false });
    if (jobsRes?.error && jobsRes.data?.message) {
      process.stderr.write("  (jobs: " + jobsRes.data.message + ")\n");
    } else {
      for (const j of jobsRes?.data || []) {
        process.stdout.write(`  job ${j.id}\t${(j.status || "").padEnd(10)}\t${j.name}\n`);
      }
    }
    return process.stdout.write(runLine(r) + "\n");
  }

  const fetchLatest = async () => {
    const res = await client.get({ url: `/repos/${owner}/${repo}/actions/runs`, query: { limit: 10 }, throwOnError: false });
    if (res?.error) return finish(res);
    return res.data?.workflow_runs || [];
  };

  if (rest.includes("--watch")) {
    const seen = new Set();
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const runs = await fetchLatest();
      for (const r of runs) {
        if (seen.has(r.id)) continue;
        seen.add(r.id);
        process.stdout.write(runLine(r) + "\n");
      }
      await new Promise((r) => setTimeout(r, 20000));
    }
  }

  const runs = await fetchLatest();
  for (const r of runs) process.stdout.write(runLine(r) + "\n");
}

async function cmdJoblogs(rest, flagUrl, flagToken, credsApi, opts) {
  // f fj joblogs <run_id> [--job <name|substring>] [grep] [--out <dir>]
  const idArg = rest.find((t) => /^\d+$/.test(t));
  if (!idArg) err("usage: f fj joblogs <run_id> [--job <name|substring>] [grep] [--out <dir>]");
  const jobI = rest.indexOf("--job");
  const jobFilter = jobI !== -1 ? rest[jobI + 1] : null;
  const outI = rest.indexOf("--out");
  const outDir = outI !== -1 ? rest[outI + 1] : null;
  const known = new Set([idArg, "--job", jobFilter, "--out", outDir]);
  const grep = rest.filter((t) => !known.has(t)).join(" ");
  if (!grep && !outDir) err("nothing to do: pass a grep pattern and/or --out <dir> to keep the raw logs");

  const repoPath = repoPathArg(rest);
  const { owner, repo } = parseRepoPath("/repos/" + repoPath);
  const client = await actionsClient(flagUrl, flagToken, credsApi, opts);

  const res = await client.get({
    url: `/repos/${owner}/${repo}/actions/runs/${idArg}/logs`,
    responseType: "arraybuffer",
    throwOnError: false,
  });
  if (res?.error) {
    const msg = res.error?.response?.data?.message || res.error?.message || "request failed";
    err(`log download failed: ${msg} (need read access to repo actions)`);
  }
  const buf = Buffer.from(res?.data ?? Buffer.alloc(0));
  // Minimal ZIP central-directory reader (stored + deflate entries via
  // node:zlib.inflateRawSync). The Actions logs endpoint returns a zip with
  // one <job>-<jobid>-attempt-N.log per job.
  const zlib = await import("node:zlib");
  const files = {};
  const end = buf.indexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  if (end < 0) err("log download is not a zip archive");
  const cdOff = buf.readUInt32LE(end + 16);
  let p = cdOff;
  while (p + 46 <= buf.length && buf.readUInt32LE(p) === 0x02014b50) {
    const method = buf.readUInt16LE(p + 10);
    const cSize = buf.readUInt32LE(p + 20);
    const nLen = buf.readUInt16LE(p + 28);
    const xLen = buf.readUInt16LE(p + 30);
    const cLen = buf.readUInt16LE(p + 32);
    const lOff = buf.readUInt32LE(p + 42);
    const name = buf.toString("utf8", p + 46, p + 46 + nLen);
    const nlLen = buf.readUInt16LE(lOff + 26);
    const xlLen = buf.readUInt16LE(lOff + 28);
    const dStart = lOff + 30 + nlLen + xlLen;
    const raw = buf.subarray(dStart, dStart + cSize);
    files[name] = method === 0 ? raw : zlib.inflateRawSync(raw);
    p += 46 + nLen + xLen + cLen;
  }
  const names = Object.keys(files);
  if (!names.length) err("log zip is empty");

  const jobFiles = jobFilter ? names.filter((n) => n.toLowerCase().includes(jobFilter.toLowerCase())) : names;
  if (jobFilter && !jobFiles.length) {
    process.stderr.write("matching jobs: " + names.join(" | ") + "\n");
    err(`no log matches --job '${jobFilter}'`);
  }

  if (outDir) {
    fs.mkdirSync(outDir, { recursive: true });
    for (const n of jobFiles) {
      fs.writeFileSync(path.join(outDir, n), files[n]);
      process.stdout.write(`saved ${n} -> ${path.join(outDir, n)}\n`);
    }
  }

  if (grep) {
    let re;
    try { re = new RegExp(grep, "i"); } catch { re = new RegExp(grep.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i"); }
    let hits = 0;
    for (const n of jobFiles) {
      const text = files[n].toString("utf8");
      text.split("\n").forEach((line, i) => {
        if (re.test(line)) {
          hits++;
          process.stdout.write(`${n}:${i + 1}:${line}\n`);
        }
      });
    }
    if (!hits) process.stderr.write(`no lines matching /${grep}/\n`);
  }
}

async function cmdCall(name, params, rawUrl, rawMethod, credsApi, opts = {}) {
  const base = resolveBaseUrl(null);
  if (!base) err("no base url (not in a git clone; pass --url https://host or set fj.defaultHost)");
  const tok = await resolveToken(null, base, credsApi, opts);
  const url = apiUrl(base);
  await sdk();
  const client = await makeClient(url, needToken(tok));

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
    // This SDK discards the status code: on error, `response` is an empty object
    // and the only fields are {message, url}. Everything below is therefore
    // keyed on message text and on whether data came back, NOT on status.
    //
    // A 204 needs no special case, because the SDK does not report it as an
    // error at all: measured against this instance, GET .../pulls/21/merge (a
    // merged PR) yields {error: false, data: ""} and the unmerged one yields
    // {error: true, message: "The target couldn't be found."}. An earlier
    // revision of this function carried a `status >= 200 && < 300` guard for
    // exactly that case; it could never fire, since `status` is always undefined
    // here. Verified by deleting the guard: the merged check still passed. It is
    // gone rather than commented, because a guard that cannot execute is worse
    // than none -- it advertises protection for a case that is actually handled
    // one branch up, by the `res.error` test itself.
    const msg = e.response?.data?.message || e.message || e.code || "request failed";
    err(`API error ${msg}`.trim());
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
      // Opt-in only. The default is a fast failure (see resolveToken); --wait
      // restores blocking so a long-running job can park until a human sets the
      // cred elsewhere. --timeout sets that window; 0 makes --wait a no-op.
      let waitSec = 0;
      const pos = [];
      for (let i = 0; i < _.length; i++) {
        const a = _[i];
        if (a === "--url") { flagUrl = _[++i]; continue; }
        if (a === "--token") { flagToken = _[++i]; continue; }
        if (a === "--wait") {
          // Accepts a bare --wait (block up to 300s) or --wait 600. A value is
          // only consumed if it is a number, so `f fj --wait push` does not eat
          // the subcommand as a timeout.
          const nxt = Number(_[i + 1]);
          waitSec = Number.isFinite(nxt) && nxt > 0 ? (_[++i], nxt) : 300;
          continue;
        }
        if (a === "--timeout") { waitSec = Number(_[++i]); continue; } // deprecated alias
        pos.push(a);
      }
      const [cmd, ...rest] = pos;
      const opts = { waitMs: waitSec * 1000 };
      // creds uck (for the opt-in blocking wait), if available
      const credsApi = (ctx && ctx.registry && ctx.registry.creds && ctx.registry.creds.credsApi) || null;

      if (!cmd || cmd === "help" || cmd === "--help" || cmd === "-h") return usage();

      if (cmd === "ls") {
        return cmdLs(rest.join(" "));
      }

      if (cmd === "urls") {
        const base = resolveBaseUrl(flagUrl);
        // Diagnostic: an absent token IS this command's answer, so it must not
        // error the way an API call would. It also never waits, even under
        // --wait, because its whole job is to report the current state.
        const tok = await resolveToken(flagToken, base, null, { waitMs: 0 });
        out({
          base: base ?? "(none)",
          api: apiUrl(base),
          token: tok.token ? (tok.src + " (len " + String(tok.token).length + ")") : `(none: ${tok.reason})`,
        });
        return;
      }

      if (cmd === "version") {
        const base = resolveBaseUrl(flagUrl);
        if (!base) err("no base url (not in a git clone, no --url/FORGEJO_URL, no fj.defaultHost)");
        const client = await makeClient(apiUrl(base), (await resolveToken(flagToken, base, credsApi, opts)).token);
        await sdk();
        const fn = _sdk.getVersion;
        const res = await fn({ client, throwOnError: false });
        return finish(res);
      }

      if (cmd === "whoami") {
        const base = resolveBaseUrl(flagUrl);
        if (!base) err("no base url (not in a git clone; pass --url)");
        const tok = await resolveToken(flagToken, base, credsApi, opts);
        if (!tok.token) return needToken(tok);
        const client = await makeClient(apiUrl(base), tok.token);
        await sdk();
        const res = await _sdk.userGetCurrent({ client, throwOnError: false });
        return finish(res);
      }

      if (cmd === "runs" || cmd === "joblogs") {
        return cmdActionsRuns(cmd, rest, flagUrl, flagToken, credsApi, opts);
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
          params = ensureJsonObject(params, file);
          rest.splice(fi, 2);
        } else {
          const maybeJson = rest[1];
          if (maybeJson && maybeJson.trim().startsWith("{")) {
            params = ensureJsonObject(parseJsonArg(maybeJson), "json arg");
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
        const res = await cmdCall(name, params, null, null, credsApi, opts);
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
        return cmdCall(null, params, rawUrl.startsWith("/") ? rawUrl : "/" + rawUrl, method, credsApi, opts);
      }

      usage();
    },
  };
}

export default { register };
