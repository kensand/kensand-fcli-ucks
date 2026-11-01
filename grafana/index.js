// f grafana — self-hosted Grafana (dashboards, datasources, PromQL queries).
//
// Zero deps (node builtins + fetch, Node >= 20).
//
// Config: creds (same protocol as ha/grocy/fj ucks, via `f creds lookup`):
//   grafana-host   base url, default https://grafana.kensand.net
//   grafana-token  service-account token (glsa_...) — Admin role recommended
// --url / --token flags and GRAFANA_URL / GRAFANA_TOKEN env win over creds.
// Auth: `Authorization: Bearer <token>`.
//
// Commands:
//   f grafana health                     /api/health (no token needed)
//   f grafana ds [name]                  datasources (or one by name/uid)
//   f grafana dash ls [query]            dashboards (uid, folder, title)
//   f grafana dash get <uid> [--json]    panel summary (or raw model JSON)
//   f grafana query '<promql>' [--ds N]  instant PromQL via datasource proxy
//                                        (--ds defaults to the prometheus ds; --json raw)
//   f grafana <METHOD> <path> [json]     raw call, e.g. GET /api/org

import { spawnSync } from "node:child_process";

const DEFAULT_HOST = "https://grafana.kensand.net";

const USAGE = `f grafana — Grafana API (https://grafana.kensand.net)

  f grafana health                     server health (no auth)
  f grafana ds [name]                  datasources
  f grafana dash ls [query]            dashboards
  f grafana dash get <uid> [--json]    panels of one dashboard
  f grafana query '<promql>' [--ds N]  instant PromQL (default ds: prometheus)
  f grafana <METHOD> <path> [json]     raw API call, e.g. GET /api/org

Creds: grafana-host, grafana-token (Admin service-account key) — or
--url/--token flags, GRAFANA_URL/GRAFANA_TOKEN env.`;

function out(o) {
  if (o == null) return;
  if (typeof o === "string") { process.stdout.write(o.endsWith("\n") ? o : o + "\n"); return; }
  process.stdout.write(JSON.stringify(o, null, 2) + "\n");
}
function err(msg) {
  process.stderr.write("f grafana: " + msg + "\n");
  process.exit(1);
}

// ---- creds (same protocol as ha/grocy ucks) ----
function lookupCred(names, timeoutMs = 20000) {
  if (!names.length) return null;
  let res;
  try {
    res = spawnSync("f", ["creds", "lookup", ...names, "--raw"], {
      encoding: "utf8", timeout: timeoutMs, stdio: ["ignore", "pipe", "pipe"],
      env: (() => { const e = { ...process.env }; delete e.F_CREDS_NO_PROVIDER; return e; })(),
    });
  } catch { return null; }
  if (!res || res.status !== 0) {
    const errText = (res?.stderr || "").trim().replace(/^f:\s*/gm, "").split("\n")[0] || "";
    if (/locked/i.test(errText) || res?.status === 3) return { locked: true };
    return null;
  }
  return (res.stdout || "").trim();
}

function resolve(argv) {
  let url = flag(argv, "--url") || process.env.GRAFANA_URL;
  let token = flag(argv, "--token") || process.env.GRAFANA_TOKEN;
  if (!url) {
    const c = lookupCred(["grafana-host"]);
    if (c && !c.locked) url = c;
    else if (c?.locked) err("creds store is locked — unlock with `f creds unlock`");
  }
  url = (url || DEFAULT_HOST).replace(/\/+$/, "");
  if (!/^https?:\/\//.test(url)) url = "https://" + url;
  if (!token) {
    const c = lookupCred(["grafana-token"]);
    if (c && !c.locked) token = c;
    else if (c?.locked) err("creds store is locked — unlock with `f creds unlock`");
  }
  return { url, token };
}

function flag(argv, name) {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] && !argv[i + 1].startsWith("--") ? argv[i + 1] : null;
}
function has(argv, name) { return argv.includes(name); }

async function api({ url, token }, path, { method = "GET", body, auth = true } = {}) {
  if (auth && !token) err("no grafana-token cred — create a service-account token (Admin) in Grafana and store it: f creds put grafana-token");
  const headers = { Accept: "application/json" };
  if (auth && token) headers.Authorization = "Bearer " + token;
  if (body != null) headers["Content-Type"] = "application/json";
  let res;
  try {
    res = await fetch(url + path, { method, headers, body: body != null ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(20000) });
  } catch (e) {
    err("request failed: " + (e?.cause?.code || e.message));
  }
  const text = await res.text();
  let data = null;
  try { data = JSON.parse(text); } catch { data = text; }
  if (!res.ok) {
    const detail = data?.message || (typeof data === "string" ? data.slice(0, 200) : res.statusText);
    err("HTTP " + res.status + " " + method + " " + path + ": " + detail);
  }
  return data;
}

const labels = (m) => Object.entries(m).filter(([k]) => k !== "__name__").map(([k, v]) => k + "=" + JSON.stringify(v)).join(",");

async function query({ url, token }, promql, dsName, asJson) {
  const dsList = await api({ url, token }, "/api/datasources");
  const want = (dsName || "prometheus").toLowerCase();
  const ds = dsList.find((d) => (d.name || "").toLowerCase() === want)
    || dsList.find((d) => (d.name || "").toLowerCase().includes(want))
    || dsList.find((d) => (d.typeName || d.type || "").toLowerCase() === want);
  if (!ds) err("no datasource matching " + JSON.stringify(dsName || "prometheus") + " — see `f grafana ds`");
  const r = await api({ url, token }, `/api/datasources/uid/${ds.uid}/resources/api/v1/query?query=${encodeURIComponent(promql)}`);
  const res = r?.data?.result;
  if (!Array.isArray(res)) return out(r);
  if (asJson) return out(r);
  if (!res.length) return out("(no series)");
  outLines_(res.map((s) => (labels(s.metric) || s.metric.__name__ || "?") + " => " + s.value[1]));
}
function outLines_(lines) { if (lines.length) process.stdout.write(lines.join("\n") + "\n"); }

export function register(_ctx) {
  return {
    name: "grafana",
    desc: "Grafana: health, datasources, dashboards, PromQL queries",
    skills: [{ name: "f-grafana", path: new URL("./SKILL.md", import.meta.url).pathname }],
    run: async (argv) => {
      if (!argv.length || argv[0] === "-h" || argv[0] === "--help") { out(USAGE); return; }
      const cfg = { url: null, token: null };
      const [cmd, ...rest] = argv;
      if (cmd === "health") {
        const h = await api(resolve(argv), "/api/health", { auth: false });
        return out(`database=${h.database} version=${h.version}`);
      }
      Object.assign(cfg, resolve(argv));
      if (cmd === "ds") {
        const all = await api(cfg, "/api/datasources");
        const q = rest[0];
        if (!q) return outLines_(all.map((d) => `${d.uid}  ${d.type}  ${d.name}  ${d.url || ""}  access=${d.access}`));
        const d = all.find((x) => x.uid === q || (x.name || "").toLowerCase().includes(q.toLowerCase()));
        return out(d || err("no datasource: " + q));
      }
      if (cmd === "dash") {
        const sub = rest[0];
        if (sub === "ls" || !sub) {
          const q = rest[1] || "";
          const r = await api(cfg, "/api/search?type=dash-db&query=" + encodeURIComponent(q));
          if (!r.length) return out("(no dashboards)");
          return outLines_(r.map((d) => `${d.uid}  [${d.folderTitle || "/"}]  ${d.title}`));
        }
        if (sub === "get") {
          const uid = rest[1] || err("usage: f grafana dash get <uid>");
          const d = await api(cfg, "/api/dashboards/uid/" + encodeURIComponent(uid));
          if (has(argv, "--json")) return out(d);
          const p = d.dashboard?.panels || [];
          const head = `uid=${uid} title=${JSON.stringify(d.dashboard?.title)} version=${d.dashboard?.version} panels=${p.length}`;
          return outLines_([head, ...p.map((x) => `  ${x.id}  ${x.type}  ${JSON.stringify(x.title)}`)]);
        }
        err("unknown dash subcommand: " + sub + " (want ls|get)");
      }
      if (cmd === "query") {
        const promql = rest[0] || err("usage: f grafana query '<promql>' [--ds name] [--json]");
        return query(cfg, promql, flag(argv, "--ds"), has(argv, "--json"));
      }
      if (/^(GET|POST|PUT|PATCH|DELETE)$/.test(cmd)) {
        const p = rest[0] || err("usage: f grafana " + cmd + " /api/path [json-body]");
        let body;
        if (rest[1]) { try { body = JSON.parse(rest[1]); } catch { body = JSON.parse(rest[1].replace(/'/g, "")); } }
        return out(await api(cfg, p, { method: cmd, body }));
      }
      err("unknown command: " + cmd + " — see `f grafana --help`");
    },
  };
}
export default { register };
