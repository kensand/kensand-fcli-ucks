// f ddg — search DuckDuckGo from the CLI (html.duckduckgo.com endpoint).
//
// Zero deps: fetch + regex parsing of the no-JS html/lite endpoints (the same
// ones the DDG CLI clients use). DDG aggressively rate-limits server-side
// clients: it answers HTTP 202 with an "anomaly" challenge page. This uck
// detects that, backs off, and retries; the cooldown is IP-based (usually a
// few minutes), not per-request, so repeated instant failures mean wait —
// more retries will not help.
//
// Commands:
//   f ddg <query...>            web results (numbered: title / url / snippet)
//   f ddg images <query...>     image-oriented search (DDG vertical via ?ia=images)
//   f ddg open <query...>       open the DDG results page in $BROWSER / xdg-open
// Options (before or after the query):
//   --json            print [{title,url,snippet}] instead of the list
//   --n <k>           max results (default 10)
//   --region <r>      kl region, e.g. us-en, de-de (default us-en)
//   --safe <0|1|2>    strictness: off / moderate (default) / strict
//   --lite            use lite.duckduckgo.com markup
//   --timeout <ms>    per-request timeout (default 15000)
//   --retries <k>     retries on 429/5xx/challenge with linear backoff (default 2)
//   --no-block        on DDG block: instead of failing, open the results page
//                     in the browser and print the URL (so the search still
//                     succeeds through the browser session)

import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));

const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0";

function fail(msg) {
  process.stderr.write("f ddg: " + msg + "\n");
  process.exit(1);
}

const USAGE =
  "f ddg — search DuckDuckGo\n" +
  "  f ddg <query...>          web results (numbered: title / url / snippet)\n" +
  "  f ddg images <query...>   image-oriented results\n" +
  "  f ddg open <query...>     open the results page in the browser\n" +
  "  options: --json  --n <k>  --region us-en  --safe 0|1|2  --lite\n" +
  "           --timeout ms  --retries <k>  --no-block (fallback: open in browser)\n" +
  "  note: DDG rate-limits server-side clients (HTTP 202 'anomaly' page);\n" +
  "        the cooldown is IP-based, usually a few minutes.\n";

function parseArgv(argv) {
  const flags = {}, pos = [];
  const bools = new Set(["json", "open", "lite", "no-block", "help", "images"]);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") { pos.push(...argv.slice(i + 1)); break; }
    if (a === "-h") { pos.push(a); continue; }
    if (a.startsWith("--")) {
      const k = a.slice(2);
      if (bools.has(k)) { flags[k] = true; continue; }
      if (i + 1 >= argv.length) fail(`--${k} needs a value`);
      flags[k] = argv[++i];
    } else pos.push(a);
  }
  return { flags, pos };
}

// ---- parsing ----
function decodeEntities(s) {
  return s
    .replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"').replace(/&#x27;|&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(+d))
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&nbsp;/g, " ");
}
const stripTags = (s) =>
  decodeEntities(s.replace(/<[^>]*>/g, "")).replace(/\s+/g, " ").trim();

// DDG wraps outbound urls as //duckduckgo.com/l/?uddg=<encoded>&rut=...
function realUrl(href) {
  href = decodeEntities(href);
  const m = href.match(/[?&]uddg=([^&]+)/);
  if (m) { try { return decodeURIComponent(m[1]); } catch { return m[1]; } }
  if (href.startsWith("//")) return "https:" + href;
  return href;
}

function isBlocked(html) {
  return /anomaly|challenge-form|detection/i.test(html) && !/result__(__)?a|class="result-link"/.test(html);
}

function parseResults(html, lite) {
  const out = [];
  if (lite) {
    // lite markup: <a rel="nofollow" href="url">title</a> in table rows,
    // snippets in <td class='result-snippet'>
    const re = /<a[^>]*rel="nofollow"[^>]*href="([^"]*)"[^>]*>([\s\S]*?)<\/a>[\s\S]*?(?:class=['"]result-snippet['"][^>]*>([\s\S]*?)<\/td>|)/g;
    let m;
    while ((m = re.exec(html))) {
      const url = realUrl(m[1]);
      const title = stripTags(m[2]);
      if (!title || !url || url.includes("duckduckgo.com")) continue;
      out.push({ title, url, snippet: m[3] ? stripTags(m[3]) : "" });
    }
    return out;
  }
  const re = /<a[^>]*class="result__a"[^>]*href="([^"]*)"[^>]*>([\s\S]*?)<\/a>([\s\S]*?)(?=<a[^>]*class="result__a"|<\/div>\s*<\/div>\s*<\/div>|$)/g;
  let m;
  while ((m = re.exec(html))) {
    const url = realUrl(m[1]);
    const title = stripTags(m[2]);
    const snip = m[3].match(/class="result__snippet"[^>]*>([\s\S]*?)<\/a>/);
    if (!title || !url || url.includes("duckduckgo.com")) continue;
    out.push({ title, url, snippet: snip ? stripTags(snip[1]) : "" });
  }
  return out;
}

// ---- request ----
async function searchOnce(query, opts) {
  const base = opts.lite
    ? "https://lite.duckduckgo.com/lite/"
    : "https://html.duckduckgo.com/html/";
  const body = new URLSearchParams({ q: query, kl: opts.region });
  if (opts.ia) { body.set("iax", opts.ia); body.set("ia", opts.ia); }
  if (opts.safe !== undefined) body.set("kp", String(opts.safe));
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), opts.timeout);
  try {
    const res = await fetch(base, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": UA,
        Accept: "text/html",
      },
      body,
      signal: ctl.signal,
    });
    const text = await res.text().catch(() => "");
    if (res.status === 202 || isBlocked(text)) {
      const e = new Error("DDG_BLOCK"); e.ddgBlock = true; throw e;
    }
    if (!res.ok) {
      const e = new Error(`HTTP ${res.status} from DuckDuckGo`);
      e.retryable = res.status === 429 || res.status >= 500;
      throw e;
    }
    return parseResults(text, opts.lite);
  } catch (e) {
    if (e.ddgBlock || e.retryable !== undefined) throw e;
    if (e.name === "AbortError") { const x = new Error(`timed out after ${opts.timeout}ms`); x.retryable = true; throw x; }
    const x = new Error(e.message); x.retryable = true; throw x;
  } finally {
    clearTimeout(t);
  }
}

async function search(query, opts) {
  let last = null;
  for (let attempt = 0; attempt <= opts.retries; attempt++) {
    if (attempt > 0) await new Promise((r) => setTimeout(r, 1500 * attempt));
    try {
      return await searchOnce(query, opts);
    } catch (e) {
      last = e;
      if (e.ddgBlock) break; // IP cooldown: retrying immediately is useless
      if (!e.retryable) break;
    }
  }
  if (last?.ddgBlock) {
    const e = new Error(
      "blocked by DuckDuckGo rate limit (HTTP 202 anomaly page). The cooldown is IP-based and can last tens of minutes to hours from a datacenter IP; wait, or use --no-block to open the search in your browser instead."
    );
    e.ddgBlock = true;
    throw e;
  }
  throw last ?? new Error("request failed");
}

function resultsUrl(query, opts) {
  const u = new URL("https://duckduckgo.com/");
  u.searchParams.set("q", query);
  if (opts.ia) { u.searchParams.set("iax", opts.ia); u.searchParams.set("ia", opts.ia); }
  return u.toString();
}

async function openBrowser(url) {
  const { spawnSync } = await import("node:child_process");
  const r = process.env.BROWSER
    ? spawnSync(process.env.BROWSER, [url], { stdio: "ignore", shell: true })
    : spawnSync("xdg-open", [url], { stdio: "ignore" });
  return !r.error && r.status === 0;
}

function printResults(top, flags) {
  if (flags.json) { process.stdout.write(JSON.stringify(top, null, 2) + "\n"); return; }
  const lines = [];
  top.forEach((r, i) => {
    lines.push(`${i + 1}. ${r.title}`);
    lines.push(`   ${r.url}`);
    if (r.snippet) lines.push(`   ${r.snippet}`);
  });
  process.stdout.write(lines.join("\n") + "\n");
}

export function register(_ctx) {
  return {
    name: "ddg",
    desc: "search DuckDuckGo: f ddg [images|open] <query> [--json --n --region --no-block]",
    skills: [{ name: "f-ddg", path: path.join(here, "SKILL.md") }],
    run: async (argv, _args) => {
      const { flags, pos } = parseArgv(Array.isArray(argv) ? argv : []);
      if (flags.help || pos.includes("-h") || pos.includes("--help")) {
        process.stdout.write(USAGE);
        return;
      }
      const opts = {
        region: flags.region ?? "us-en",
        n: Math.max(1, parseInt(flags.n ?? "10", 10) || 10),
        timeout: parseInt(flags.timeout ?? "15000", 10) || 15000,
        retries: Math.max(0, parseInt(flags.retries ?? "2", 10) || 0),
        safe: flags.safe !== undefined ? parseInt(flags.safe, 10) : undefined,
        lite: !!flags.lite,
        ia: null,
      };
      let mode = "web";
      if (pos[0] === "images" || flags.images) {
        mode = "images"; opts.ia = "images";
        if (pos[0] === "images") pos.shift();
      } else if (pos[0] === "open" || flags.open) {
        mode = "open";
        if (pos[0] === "open") pos.shift();
      }
      const query = pos.join(" ").trim();
      if (!query) {
        process.stderr.write("f ddg: no query\n");
        process.stdout.write(USAGE);
        process.exit(1);
      }

      if (mode === "open") {
        const url = resultsUrl(query, opts);
        if (!(await openBrowser(url))) fail("could not open browser ($BROWSER / xdg-open)");
        process.stdout.write(url + "\n");
        return;
      }

      try {
        const results = await search(query, opts);
        if (!results.length)
          fail("no results parsed (DDG layout change?) — try --lite");
        printResults(results.slice(0, opts.n), flags);
      } catch (e) {
        if (e.ddgBlock && flags["no-block"]) {
          const url = resultsUrl(query, opts);
          if (await openBrowser(url)) {
            process.stdout.write("blocked (HTTP 202); opened in browser: " + url + "\n");
            return;
          }
        }
        fail(e.message);
      }
    },
  };
}
export default { register };
