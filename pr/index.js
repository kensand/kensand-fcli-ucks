// f pr — terse pull-request ops against the Forgejo/Gitea instance of the
// current git repo (base URL from git origin, token from the `creds` uck).
//
// Covers the things that get repeated in every PR workflow:
//   1. check whether a PR's CI passed (commit combined status)
//   2. merge an approved PR
//   3. list open PRs
//
// Commands:
//   f pr check [number]        PR + CI status (default: PR of head branch)
//   f pr merge [number] [-m squash|merge|rebase]   merge a PR (default squash)
//   f pr open                  open PRs for the current repo
//   f pr status <sha|ref>      commit CI status (e.g. HEAD, origin/main)
//
// Zero deps: git origin via node:child_process, token via the `creds` uck's
// credsApi when it is loaded (ctx.registry.creds), else a direct creds-daemon
// socket read (node:net), else FORGEJO_TOKEN.

import { execSync } from "node:child_process";
import net from "node:net";

const F = (process.env.HOME ?? "") + "/.f";
const CRED_SOCKET = F + "/.creds.sock";

function git(cwd, args) {
  try {
    return execSync(`git ${args}`, { cwd, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] }).trim();
  } catch {
    return null;
  }
}

function originUrl(cwd) {
  const origin = git(cwd, "remote get-url origin");
  if (!origin) return null;
  let s = origin.trim();
  if (!s.includes("://")) s = s.replace(/^(?:[^@/]+@)?([^:/]+):/, "https://$1/");
  try {
    const u = new URL(s);
    return { host: u.host, base: "https://" + u.host };
  } catch {
    return null;
  }
}

function originRepo(cwd) {
  const origin = git(cwd, "remote get-url origin");
  if (!origin) return null;
  let s = origin.trim();
  if (!s.includes("://")) s = s.replace(/^(?:[^@/]+@)?([^:/]+):/, "https://$1/");
  try {
    const u = new URL(s);
    const segs = u.pathname.split("/").filter(Boolean);
    if (segs.length < 2) return null;
    let last = segs[segs.length - 1];
    if (last.endsWith(".git")) last = last.slice(0, -4);
    return `${segs[segs.length - 2]}/${last}`;
  } catch {
    return null;
  }
}

function readCred(host) {
  return new Promise((resolve) => {
    const sock = net.connect(CRED_SOCKET);
    let buf = "";
    const done = (v) => {
      try { sock.end(); } catch {}
      resolve(v);
    };
    sock.on("connect", () => sock.write(`get ${host}\0`));
    sock.on("data", (d) => { buf += d.toString(); });
    sock.on("close", () => done(buf.replace(/\0+$/, "").split("\n").pop() || null));
    sock.on("error", () => done(null));
    setTimeout(() => done(buf ? buf : null), 5000);
  });
}

async function tokenFromCredsApi(credsApi, host) {
  if (!credsApi || typeof credsApi.get !== "function") return null;
  try {
    const v = await credsApi.get(host);
    return typeof v === "string" && v ? v : null;
  } catch {
    return null;
  }
}

async function api(base, token, method, path, body) {
  const url = new URL(`${base}/api/v1${path.startsWith("/") ? path : "/" + path}`);
  const payload = body ? JSON.stringify(body) : null;
  const res = await fetch(url, {
    method,
    headers: {
      ...(token ? { Authorization: `token ${token}` } : {}),
      ...(payload ? { "Content-Type": "application/json" } : {}),
    },
    body: payload,
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch {}
  return { status: res.status, data, text };
}

const icon = { success: "+", failure: "x", pending: "o", error: "x", cancelled: "-" };

async function check(base, token, repo, number) {
  const pr = await api(base, token, "GET", `/repos/${repo}/pulls/${number}`);
  if (pr.status !== 200) return `pr ${number}: not found (${pr.status})`;
  const d = pr.data;
  const lines = [`#${number} ${d.title} [${d.state}]`];
  const merge = d.merged ? "merged" : d.has_conflicts ? "CONFLICTS" : d.mergeable ? "mergeable" : "unknown";
  lines.push(`  merge: ${merge}`);
  const commits = await api(base, token, "GET", `/repos/${repo}/pulls/${number}/commits`);
  if (commits.status === 200 && Array.isArray(commits.data) && commits.data.length) {
    const head = commits.data[commits.data.length - 1].sha;
    const cs = await api(base, token, "GET", `/repos/${repo}/commits/${head}/status`);
    if (cs.status === 200 && cs.data) {
      const s = cs.data;
      const st = s.statuses ? s.statuses.map((x) => `${icon[x.status] ?? "?"} ${x.context || "?"}${x.description ? ` — ${x.description}` : ""}${x.target_url ? ` (${x.target_url})` : ""}`) : [];
      lines.push(`  ci: ${s.state}${st.length ? ` (${s.total_count} context${s.total_count === 1 ? "" : "s"})` : ""}`);
      for (const l of st) lines.push(`    ${l}`);
    }
  }
  return lines.join("\n");
}

async function merge(base, token, repo, number, style) {
  const r = await api(base, token, "PUT", `/repos/${repo}/pulls/${number}/merge`, {
    merge_style: style,
    run_status_checks: false,
  });
  if (r.status === 200 || r.status === 204) return `merged #${number} (${style})`;
  const detail = (r.data && (r.data.message || r.data.error)) || r.text || r.status;
  return `merge #${number} failed (${r.status}): ${detail}`;
}

async function commitStatus(base, token, repo, ref) {
  const sha = git(process.cwd(), `rev-parse --verify --quiet ${ref}^{commit}`) || ref;
  const cs = await api(base, token, "GET", `/repos/${repo}/commits/${sha}/status`);
  if (cs.status !== 200) return `status for ${sha.slice(0, 7)}: not found (${cs.status})`;
  const s = cs.data;
  const st = s.statuses
    ? s.statuses.map((x) => `${icon[x.status] ?? "?"} ${x.context || "?"}${x.description ? ` — ${x.description}` : ""}${x.target_url ? ` (${x.target_url})` : ""}`)
    : [];
  const lines = [`${sha.slice(0, 7)}: ${s.state}${st.length ? ` (${s.total_count} context${s.total_count === 1 ? "" : "s"})` : ""}`];
  for (const l of st) lines.push(`  ${l}`);
  return lines.join("\n");
}

async function open(base, token, repo) {
  const r = await api(base, token, "GET", `/repos/${repo}/pulls?state=open&limit=30`);
  if (r.status !== 200 || !Array.isArray(r.data)) return `list failed (${r.status})`;
  if (!r.data.length) return "no open PRs";
  return r.data.map((p) => `#${p.number} ${p.title} [${(p.head && p.head.label) || (p.head && p.head.ref)}]`).join("\n");
}

async function findPrByBranch(base, token, repo, branch) {
  const r = await api(base, token, "GET", `/repos/${repo}/pulls?state=open&limit=50`);
  if (r.status !== 200 || !Array.isArray(r.data)) return null;
  const hit = r.data.find((p) => p.head && (p.head.label === branch || p.head.ref === branch));
  return hit ? hit.number : null;
}

function usage(msg) {
  const line = msg ? `f pr: ${msg}\n` : "";
  process.stderr.write(
    line +
      "usage: f pr <cmd> [number] [flags]\n" +
      "  check [number]              PR + CI status (default: PR of head branch)\n" +
      "  merge [number] [-m squash|merge|rebase]\n" +
      "  status <sha|ref>            commit CI status (e.g. HEAD, origin/main)\n" +
      "  open                        list open PRs\n" +
      "runs against the git origin of the current directory; token from f creds or FORGEJO_TOKEN\n",
  );
  process.exit(1);
}

export async function run(_argv, _args, ctx) {
  const [cmd, ...rest] = _args._ ?? [];
  const cwd = process.cwd();
  const repo = originRepo(cwd);
  const origin = originUrl(cwd);
  if (!repo || !origin) return usage("no git origin found in current directory");
  const base = origin.base;
  const credsApi = (ctx && ctx.registry && ctx.registry.creds && ctx.registry.creds.credsApi) || null;
  let token = process.env.FORGEJO_TOKEN || null;
  if (!token) token = (await tokenFromCredsApi(credsApi, origin.host)) || (await readCred(origin.host));
  if (!token) return usage(`no token: run 'f creds set ${origin.host} <token>' or set FORGEJO_TOKEN`);

  let style = "squash";
  const pos = [];
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === "-m" || rest[i] === "--style") style = rest[++i];
    else pos.push(rest[i]);
  }
  let number = null;
  if (pos[0] && (cmd === "check" || cmd === "ci" || cmd === "merge" || cmd === "m")) {
    number = Number(pos[0]);
    if (!Number.isInteger(number)) return usage(`bad PR number: ${pos[0]}`);
  }

  const branch = git(cwd, "rev-parse --abbrev-ref HEAD");

  try {
    if (cmd === "check" || cmd === "ci") {
      if (!number) {
        if (!branch || branch === "HEAD") return usage("need a PR number or a checked-out branch");
        number = await findPrByBranch(base, token, repo, branch);
        if (!number) return `no open PR for branch ${branch} in ${repo}`;
      }
      process.stdout.write((await check(base, token, repo, number)) + "\n");
    } else if (cmd === "status") {
      const ref = pos[0] || "HEAD";
      process.stdout.write((await commitStatus(base, token, repo, ref)) + "\n");
    } else if (cmd === "merge" || cmd === "m") {
      if (!number) return usage("merge needs a PR number");
      process.stdout.write((await merge(base, token, repo, number, style)) + "\n");
    } else if (cmd === "open" || cmd === "ls") {
      process.stdout.write((await open(base, token, repo)) + "\n");
    } else {
      usage(`unknown command: ${cmd || "(none)"}`);
    }
  } catch (e) {
    process.stderr.write(`f pr: ${e.message}\n`);
    process.exit(1);
  }
}

export function register(_ctx) {
  return {
    name: "pr",
    desc: "PR CI check / merge / list for the Forgejo/Gitea instance of the current repo",
    run,
  };
}

export default { register };
