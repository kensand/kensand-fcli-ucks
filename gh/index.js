// f gh — GitHub REST API via @octokit/rest: repos, issues, PRs, releases,
// search, raw passthrough.
//
// Dep: @octokit/rest (installed in this uck's own node_modules; lazy-imported).
//
// Config:
//   Token (first that resolves): --token flag, GITHUB_TOKEN env, then the creds
//   uck / creds daemon using the cred `gh-token` (or `<host>-token` / `github-
//   token`). A combined `gh` cred `url|token` is also accepted.
//   Base: --url > GITHUB_URL env > gh.baseUrl in f.config.json > url part of a
//   combined cred. Defaults to https://api.github.com.
//   Repo: --repo <owner>/<repo>, else the git origin of the current directory.
//
// Commands:
//   f gh whoami                 current user (needs auth)
//   f gh ls [query]             list/search endpoint names (subset)
//   f gh repo [ls]              list repos (default: current repo)
//   f gh issue [ls|new|<n>]    list / create / show issues
//   f gh pr [ls|<n>]           list / show PRs
//   f gh release [ls|new]      list / create releases
//   f gh search <query>        code/repo search
//   f gh <METHOD> <path> [json] raw call, e.g. GET /repos/octocat/hello-world
//   f gh info                   rate limit + auth check

import fs from "node:fs";
import path from "node:path";
import net from "node:net";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const F = path.join(process.env.HOME ?? "", ".f");
const CRED_SOCKET = path.join(F, ".creds.sock");
const DEFAULT_BASE = "https://api.github.com";

// ---- output ----
function out(o) {
  if (o == null) return;
  if (typeof o === "string") { process.stdout.write(o.endsWith("\n") ? o : o + "\n"); return; }
  process.stdout.write(JSON.stringify(o, null, 2) + "\n");
}
function outLines(lines) { if (lines.length) process.stdout.write(lines.join("\n") + "\n"); }
function err(msg) { process.stderr.write("f gh: " + msg + "\n"); process.exit(1); }

// ---- octokit (lazy) ----
let _Octokit = null;
async function octokitCtor() {
  if (_Octokit) return _Octokit;
  // Bare specifier resolves from this uck's own node_modules (f runs it in place).
  const mod = await import("@octokit/rest");
  _Octokit = mod.Octokit;
  return _Octokit;
}
async function client(token, baseUrl) {
  const Octokit = await octokitCtor();
  return new Octokit({ auth: token, baseUrl });
}

// ---- config / creds (same pattern as ha/fj) ----
function configBase() {
  const read = (p) => { try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch { return null; } };
  let dir = process.cwd();
  for (let i = 0; i < 8; i++) {
    const d = read(path.join(dir, "f.config.json"));
    if (d && d.gh && typeof d.gh.baseUrl === "string") return d.gh.baseUrl;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  const g = read(path.join(F, "f.config.json"));
  if (g && g.gh && typeof g.gh.baseUrl === "string") return g.gh.baseUrl;
  return null;
}
function resolveBase(flagUrl) {
  const raw = flagUrl || process.env.GITHUB_URL || configBase();
  return (raw || DEFAULT_BASE).replace(/\/+$/, "");
}
function splitCred(v) {
  const bar = v.indexOf("|");
  if (bar <= 0) return { url: null, token: v };
  let url = v.slice(0, bar).trim(); const token = v.slice(bar + 1).trim();
  if (url && !/^https?:\/\//.test(url)) url = "http://" + url;
  return { url: url || null, token };
}
function daemonCall(req, socketPath) {
  return new Promise((resolve, reject) => {
    let buf = "";
    const c = net.connect(socketPath, () => { c.write(JSON.stringify(req)); });
    c.on("data", (d) => (buf += d));
    c.on("end", () => { try { resolve(JSON.parse(buf)); } catch { reject(new Error("bad daemon: " + buf)); } });
    c.on("error", (e) => reject(e));
  });
}
function credsUnlocked() {
  let lf; try { lf = JSON.parse(fs.readFileSync(path.join(F, ".creds-daemon"), "utf8")); } catch { return null; }
  if (!lf || !lf.pid || !lf.start || !lf.ttl) return null;
  try { process.kill(lf.pid, 0); } catch { return null; }
  const rem = lf.start + lf.ttl * 1000 - Date.now();
  return rem > 0 ? { remainingMs: rem, socket: lf.socket } : null;
}
async function resolveCreds(flagToken, flagUrl, credsApi, opts = {}) {
  const state = credsUnlocked();
  // Structural first (CredsError.kind from credsApi.version >= 1), message
  // fallback for older creds builds. Contract: never match message wording.
  const classify = (e) => {
    const k = e && e.kind;
    if (k === "locked") return "locked";
    if (k === "missing") return "missing";
    if (k === "provider" || k === "other") return "error";
    const m = (e && e.message) || String(e);
    if (/locked/i.test(m)) return "locked";
    if (/no such cred/i.test(m)) return "missing";
    return "error";
  };
  const read = async (name) => {
    if (credsApi && typeof credsApi.get === "function") {
      try { return await credsApi.get(name); } catch (e) { if (classify(e) === "locked") return { locked: true }; return null; }
    }
    try { const r = await daemonCall({ op: "get", name }, state.socket || CRED_SOCKET); if (r && r.ok) return r.value; return null; } catch { return null; }
  };
  if (flagToken) return { token: flagToken, src: "--token", base: resolveBase(flagUrl) };
  if (process.env.GITHUB_TOKEN) return { token: process.env.GITHUB_TOKEN, src: "GITHUB_TOKEN", base: resolveBase(flagUrl) };
  const names = ["gh-token", "github-token", "gh"];
  for (const name of names) {
    const v = await read(name);
    if (v && v.locked) return { token: null, src: null, reason: "locked" };
    if (v != null && v !== "") {
      const p = splitCred(v);
      if (p.token) return { token: p.token, src: `creds:${name}`, base: resolveBase(flagUrl) || p.url };
    }
  }
  if (!state) return { token: null, src: null, reason: "locked" };
  return { token: null, src: null, reason: "unset" };
}
function needToken(c) {
  if (c.token) return c;
  if (c.reason === "locked")
    err("creds are locked\n  unlock it: f creds unlock\n  or: f gh --token <tok> ... / GITHUB_TOKEN=...");
  err("no token (f creds set gh-token <token>, or --token <tok>, or GITHUB_TOKEN)\n  names tried: gh-token, github-token, gh");
}

// ---- repo from git origin ----
function repoFromCwd() {
  try {
    const o = execSync("git remote get-url origin", { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] }).trim();
    const m = o.match(/[:/]([^/:\s]+)\/([^/:\s]+?)(?:\.git)?$/);
    if (m) return `${m[1]}/${m[2]}`;
  } catch {}
  return null;
}

// ---- arg helpers ----
function parseParams(tokens) {
  if (tokens.length === 1 && tokens[0].trim().startsWith("{")) {
    try { return JSON.parse(tokens[0]); } catch { err("not valid JSON: " + tokens[0].slice(0, 80)); }
  }
  const p = {};
  for (const t of tokens) {
    const eq = t.indexOf("=");
    if (eq <= 0) err("expected key=value, got: " + t);
    const k = t.slice(0, eq); let v = t.slice(eq + 1);
    if (v !== "" && /^[[{\d-]|^(true|false|null)$/.test(v)) { try { v = JSON.parse(v); } catch {} }
    p[k] = v;
  }
  return p;
}
function repoArg(rest) {
  const i = rest.indexOf("--repo");
  if (i !== -1) return rest[i + 1];
  return repoFromCwd();
}

// ---- endpoint name catalogue (for `ls`) ----
// A pragmatic subset of the most-used @octokit/rest endpoint names. The raw
// passthrough covers everything else; this is for discovery.
const ENDPOINTS = {
  "repos.get": "GET /repos/{owner}/{repo}",
  "repos.list": "GET /user/repos",
  "repos.listForOrg": "GET /orgs/{org}/repos",
  "repos.create": "POST /user/repos",
  "issues.listForRepo": "GET /repos/{owner}/{repo}/issues",
  "issues.get": "GET /repos/{owner}/{repo}/issues/{issue_number}",
  "issues.create": "POST /repos/{owner}/{repo}/issues",
  "issues.update": "PATCH /repos/{owner}/{repo}/issues/{issue_number}",
  "issues.addComments": "GET /repos/{owner}/{repo}/issues/{issue_number}/comments",
  "issues.createComment": "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
  "pulls.list": "GET /repos/{owner}/{repo}/pulls",
  "pulls.get": "GET /repos/{owner}/{repo}/pulls/{pull_number}",
  "pulls.create": "POST /repos/{owner}/{repo}/pulls",
  "pulls.merge": "PUT /repos/{owner}/{repo}/pulls/{pull_number}/merge",
  "pulls.getFiles": "GET /repos/{owner}/{repo}/pulls/{pull_number}/files",
  "releases.list": "GET /repos/{owner}/{repo}/releases",
  "releases.getLatest": "GET /repos/{owner}/{repo}/releases/latest",
  "releases.create": "POST /repos/{owner}/{repo}/releases",
  "actions.listRuns": "GET /repos/{owner}/{repo}/actions/runs",
  "actions.getRun": "GET /repos/{owner}/{repo}/actions/runs/{run_id}",
  "actions.listJobs": "GET /repos/{owner}/{repo}/actions/runs/{run_id}/jobs",
  "actions.downloadJobLogs": "GET /repos/{owner}/{repo}/actions/jobs/{job_id}/logs",
  "search.issuesAndPullRequests": "GET /search/issues",
  "search.repos": "GET /search/repositories",
  "users.getAuthenticated": "GET /user",
  "orgs.get": "GET /orgs/{org}",
  "git.refs": "GET /repos/{owner}/{repo}/git/refs",
  "repos.getContent": "GET /repos/{owner}/{repo}/contents/{path}",
  "repos.createDispatchEvent": "POST /repos/{owner}/{repo}/dispatches",
};

// ---- commands ----
function cmdLs(query) {
  const q = (query || "").toLowerCase();
  const names = Object.keys(ENDPOINTS).filter((n) => !q || n.toLowerCase().includes(q));
  outLines(names.map((n) => `${n}  ${ENDPOINTS[n]}`));
}

async function cmdWhoami(c) {
  const ok = await client(c.token, c.base);
  const { data } = await ok.users.getAuthenticated();
  out({ login: data.login, id: data.id, name: data.name, public_repos: data.public_repos, followers: data.followers, following: data.following });
}

async function cmdRepo(rest, c) {
  const repo = repoArg(rest);
  const sub = rest.find((t) => !t.startsWith("-") && t !== repo && t !== "repo");
  const ok = await client(c.token, c.base);
  if (sub === "ls" || !sub) {
    // no repo → list user's repos; with repo → show repo
    if (!repo) {
      const { data } = await ok.repos.listForAuthenticatedUser({ affiliation: "owner", per_page: 100 });
      outLines(data.map((r) => `${r.owner.login}/${r.name}  ${r.private ? "private" : "public"}  ${r.description || ""}`.trimEnd()));
      return;
    }
    const [owner, name] = repo.split("/");
    const { data } = await ok.repos.get({ owner, repo: name });
    out({ full_name: data.full_name, default_branch: data.default_branch, private: data.private, stars: data.stargazers_count, forks: data.forks_count, open_issues: data.open_issues_count, description: data.description, updated: data.updated_at });
    return;
  }
  const [owner, name] = repo.split("/");
  const { data } = await ok.repos.get({ owner, repo: name });
  out({ full_name: data.full_name, default_branch: data.default_branch });
}

async function cmdIssue(rest, c) {
  const repo = repoArg(rest);
  if (!repo) err("issue needs a repo (pass --repo owner/name or run in a clone)");
  const [owner, name] = repo.split("/");
  const ok = await client(c.token, c.base);
  const sub = rest.find((t) => !t.startsWith("-") && t !== repo);
  const stateIdx = rest.indexOf("--state");
  const state = stateIdx !== -1 ? rest[stateIdx + 1] : "open";
  if (sub === "new" || sub === "create") {
    const params = parseParams(rest.filter((t, i) => t !== "new" && t !== "create" && t !== repo && t !== "--state" && t !== state));
    const { data } = await ok.issues.create({ owner, repo: name, title: params.title, body: params.body, labels: params.labels });
    out({ number: data.number, url: data.html_url, state: data.state });
    return;
  }
  if (sub && /^\d+$/.test(sub)) {
    const { data } = await ok.issues.get({ owner, repo: name, issue_number: Number(sub) });
    out({ number: data.number, title: data.title, state: data.state, is_pr: !!data.pull_request, author: data.user?.login, updated: data.updated_at, url: data.html_url });
    return;
  }
  // ls
  const { data } = await ok.issues.listForRepo({ owner, repo: name, state, per_page: 50 });
  outLines(data.map((i) => `#${i.number} ${i.state}  ${i.title}  ${i.pull_request ? "[pr]" : ""} ${i.user?.login || ""}`.trimEnd()));
}

async function cmdPr(rest, c) {
  const repo = repoArg(rest);
  if (!repo) err("pr needs a repo (pass --repo owner/name or run in a clone)");
  const [owner, name] = repo.split("/");
  const ok = await client(c.token, c.base);
  const sub = rest.find((t) => !t.startsWith("-") && t !== repo);
  if (sub && /^\d+$/.test(sub)) {
    const { data } = await ok.pulls.get({ owner, repo: name, pull_number: Number(sub) });
    out({ number: data.number, title: data.title, state: data.state, merged: !!data.merged, head: data.head?.ref, base: data.base?.ref, author: data.user?.login, url: data.html_url });
    return;
  }
  const stateIdx = rest.indexOf("--state");
  const state = stateIdx !== -1 ? rest[stateIdx + 1] : "open";
  const { data } = await ok.pulls.list({ owner, repo: name, state, per_page: 50 });
  outLines(data.map((p) => `#${p.number} ${p.state}  ${p.title}  ${p.head?.ref} -> ${p.base?.ref}  ${p.user?.login || ""}`.trimEnd()));
}

async function cmdRelease(rest, c) {
  const repo = repoArg(rest);
  if (!repo) err("release needs a repo (pass --repo owner/name or run in a clone)");
  const [owner, name] = repo.split("/");
  const ok = await client(c.token, c.base);
  const sub = rest.find((t) => !t.startsWith("-") && t !== repo);
  if (sub === "new" || sub === "create") {
    const params = parseParams(rest.filter((t, i) => t !== "new" && t !== "create" && t !== repo));
    const res = await ok.request("POST /repos/{owner}/{repo}/releases", { owner, repo: name, ...params, draft: !!params.draft, prerelease: !!params.prerelease });
    const data = res.data;
    out({ tag: data.tag_name, name: data.name, draft: data.draft, url: data.html_url });
    return;
  }
  const res = await ok.request("GET /repos/{owner}/{repo}/releases", { owner, repo: name, per_page: 20 });
  const data = res.data;
  outLines(data.map((r) => `${r.tag_name}  ${r.draft ? "draft" : r.prerelease ? "prerelease" : "release"}  ${r.name || ""}  ${r.published_at || ""}`.trimEnd()));
}

async function cmdSearch(rest, c) {
  const q = rest.find((t) => !t.startsWith("-"));
  if (!q) err("search needs a query");
  const kindIdx = rest.indexOf("--type");
  const kind = kindIdx !== -1 ? rest[kindIdx + 1] : "repos";
  const ok = await client(c.token, c.base);
  const { data } = kind === "code"
    ? await ok.search.issuesAndPullRequests({ q, per_page: 20 })
    : await ok.search.repos({ q, per_page: 20 });
  if (kind === "code") {
    outLines(data.items.map((i) => `#${i.number} ${i.state}  ${i.title}  ${i.repository_url.split("/repos/").pop()}`.trimEnd()));
  } else {
    outLines(data.items.map((r) => `${r.full_name}  ⭐${r.stargazers_count}  ${r.description || ""}`.trimEnd()));
  }
}

async function cmdInfo(c) {
  const ok = await client(c.token, c.base);
  let user = null;
  try { const { data } = await ok.users.getAuthenticated(); user = data.login; } catch { user = "(unauthenticated)"; }
  const { data: rl } = await ok.rateLimit.get();
  out({ authed_as: user, base: c.base, rate_limit: `${rl.resources.core.used}/${rl.resources.core.limit}`, reset: new Date(rl.resources.core.reset * 1000).toISOString() });
}

async function cmdRaw(method, pathStr, json, c) {
  const ok = await client(c.token, c.base);
  let body;
  if (json && json.trim().startsWith("{")) body = JSON.parse(json);
  const p = pathStr.startsWith("/") ? pathStr : "/" + pathStr;
  const res = await ok.request({ method, url: p, ...body });
  out(res.data);
}

function usage() {
  err(
    "usage: f gh <cmd>\n" +
    "  whoami                     current user\n" +
    "  info                       rate limit + auth\n" +
    "  ls [query]                 list/search endpoint names\n" +
    "  repo [ls]                  list repos / show current repo\n" +
    "  issue [ls|new|<n>]         list / create / show issues\n" +
    "  pr [ls|<n>]                list / show PRs\n" +
    "  release [ls|new]           list / create releases\n" +
    "  search <query> [--type repos|code]\n" +
    "  <METHOD> <path> [json]     raw call, e.g. GET /repos/octocat/hello-world\n" +
    "  --repo <owner>/<repo>      target repo (default: git origin)\n" +
    "  --url <base>               override API base (default: https://api.github.com)\n" +
    "  --token <tok>              override token (default: GITHUB_TOKEN, then creds:gh-token)"
  );
}

export function register(_ctx) {
  return {
    name: "gh",
    skills: [{ name: "f-gh", path: path.join(__dirname, "SKILL.md") }],
    desc: "GitHub API via @octokit/rest (whoami/repo/issue/pr/release/search/raw); token from creds (gh-token)",
    run: async (_argv, args, ctx) => {
      const _ = args._ ?? [];
      let flagUrl = null, flagToken = null;
      const pos = [];
      for (let i = 0; i < _.length; i++) {
        const a = _[i];
        if (a === "--url") { flagUrl = _[++i]; continue; }
        if (a === "--token") { flagToken = _[++i]; continue; }
        pos.push(a);
      }
      const [cmd, ...rest] = pos;
      const credsApi = (ctx && ctx.registry && ctx.registry.creds && ctx.registry.creds.credsApi) || null;
      if (!cmd || cmd === "help" || cmd === "--help" || cmd === "-h") return usage();
      const c = await resolveCreds(flagToken, flagUrl, credsApi);
      const base = (c.base || DEFAULT_BASE).replace(/\/+$/, "");

      if (cmd === "ls") return cmdLs(rest.join(" "));
      if (cmd === "whoami") return cmdWhoami({ token: needToken(c).token, base });
      if (cmd === "info") return cmdInfo({ token: c.token, base });
      if (cmd === "repo") return cmdRepo(rest, { token: needToken(c).token, base });
      if (cmd === "issue") return cmdIssue(rest, { token: needToken(c).token, base });
      if (cmd === "pr") return cmdPr(rest, { token: needToken(c).token, base });
      if (cmd === "release") return cmdRelease(rest, { token: needToken(c).token, base });
      if (cmd === "search") return cmdSearch(rest, { token: needToken(c).token, base });

      const method = cmd.toUpperCase();
      if (/^(GET|POST|PUT|PATCH|DELETE|HEAD)$/.test(method)) {
        if (!rest[0]) err(`${method} requires a path`);
        return cmdRaw(method, rest[0], rest[1], { token: needToken(c).token, base });
      }
      usage();
    },
  };
}
export default { register };
