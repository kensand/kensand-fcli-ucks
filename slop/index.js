// f slop — catch and repair LLM slop in prose.
//
// Zero deps. Scans text files for the tells of model-generated prose
// (pompous filler, chatbot residue, hype vocabulary, decorative emoji,
// em-dashes, bold-lead bullets) and, with --fix, applies the
// deterministic rewrites in place: phrase substitutions, whole-sentence
// cuts for chatbot residue, em-dash downgrade, and emoji stripping.
// Flag-only rules are reported but never auto-fixed.
//
// Commands:
//   f slop [paths...]     scan files/dirs; no paths = changed text files
//                         in the current git repo (diff HEAD + untracked)
//   f slop -              scan stdin
//   f slop --fix ...      apply deterministic fixes in place
// Options:
//   --all       scan the whole repo (git ls-files), not just changed files
//   --code      also scan source files (comments count as prose too)
//   --json      machine-readable output
//   --max n     cap printed hits per file (default 25)
//   --rules     list rule names and exit
//   -h, --help  usage
// Exit: 0 clean · 1 slop found (or remaining after --fix) · 2 usage error

import { readFileSync, writeFileSync, statSync, readdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));

const TEXT_SRC = "(?:md|markdown|txt|rst|org|adoc)";
const CODE_SRC = "(?:js|ts|tsx|jsx|mjs|cjs|py|go|rs|c|h|rb|sh|zsh|yaml|yml)";
const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", "target", "vendor", "__pycache__", ".venv", "venv", ".cache", ".next", "coverage"]);
const MAX_BYTES = 2 * 1024 * 1024;

// ---- rules ---------------------------------------------------------------
// subs: deterministic in-place rewrites (applied first)
const SUBS = [
  ["vocab:utilize", /\butili[sz]e\b/gi, "use"],
  ["vocab:utilizes", /\butili[sz]es\b/gi, "uses"],
  ["vocab:utilized", /\butili[sz]ed\b/gi, "used"],
  ["vocab:utilizing", /\butili[sz]ing\b/gi, "using"],
  ["vocab:leverage", /\bleverag(?:e|es|d|ing)\b/gi, (m) => ({ leverage: "use", leverages: "uses", leveraged: "used", leveraging: "using" })[m.toLowerCase()] ?? "use"],
  ["vocab:delve", /\bdelve[sd]?\b/gi, (m) => ({ delve: "dig", delves: "digs", delved: "dug" })[m.toLowerCase()] ?? "dig"],
  ["vocab:delving", /\bdelving\b/gi, "digging"],
  ["vocab:boasts", /\bboasts\b/gi, "has"],
  ["pomp:in-order-to", /\bin order to\b/gi, "to"],
  ["pomp:due-to-fact", /\bdue to the fact that\b/gi, "because"],
  ["pomp:in-the-event", /\bin the event that\b/gi, "if"],
  ["pomp:wide-range", /\ba wide range of\b/gi, "many"],
  ["pomp:various-different", /\bvarious different\b/gi, "various"],
  ["pomp:majority", /\bthe vast majority of\b/gi, "most"],
  ["pomp:each-every", /\beach and every\b/gi, "every"],
  ["pomp:absolutely-essential", /\babsolutely essential\b/gi, "essential"],
  ["pomp:completely-eliminate", /\bcompletely eliminate\b/gi, "eliminate"],
  ["pomp:end-result", /\bend result\b/gi, "result"],
  ["pomp:past-history", /\bpast history\b/gi, "history"],
  ["filler:furthermore", /\bfurthermore\b/gi, "also"],
  ["filler:moreover", /\bmoreover\b/gi, "also"],
  ["filler:additionally", /\badditionally\b/gi, "also"],
  ["pomp:important-to-note", /\bit'?s (?:important to|worth) noting?,? that\b|\bit should be noted,? that\b/gi, "note that"],
  ["pomp:belt-and-braces", /\bbelt-and-(?:braces?|suspenders?)\b/gi, "redundant"], // hyphenated adjectival use only
  ["fmt:em-dash", /\s*—\s*/g, " - "],
  ["intensity:very", /\bvery (unique|perfect|essential|critical|important)\b/gi, (m) => m.replace(/^very\s+/i, "")],
];

// dels: chatbot residue — cut the whole sentence containing the match
const DELS = [
  ["chat:hope-helps", /\bi hope this helps\b/i],
  ["chat:reach-out", /\bfeel free to (?:reach out|ask|contact|let me know)\b/i],
  ["chat:let-me-know", /\blet me know if\b/i],
  ["chat:hesitate", /\bdon'?t hesitate to\b/i],
  ["chat:interjection", /\b(?:great question|certainly|of course|absolutely)\s*[!.]/i],
  ["chat:ai-self", /\bas an ai\b|\bas a (?:large )?language model\b|\bmy knowledge cutoff\b|\bas of my last (?:update|training)\b/i],
  ["pomp:today-world", /\bin today'?s (?:rapidly |constantly |increasingly |fast[- ])?(?:changing|paced|evolving)[^,.]*?world\b|\bin an? ever[- ](?:changing|evolving|growing|evolving)\b/i],
  ["pomp:end-of-day", /\bat the end of the day\b/i],
  ["pomp:conclusion", /\bin conclusion\b|\bto sum(?:e|) ?(?:it )?up\b|\bto summarize\b/i],
  ["pomp:whether-youre", /\bwhether you'?re\b/i],
  ["pomp:navigate-complex", /\bnavigat\w* the (?:complexit|intric|nuance|world)/i],
  ["pomp:unlock", /\bunlock\w* the (?:power|potential|secret|possibilit|world)/i],
  ["pomp:testament", /\bit'?s a testament to\b/i],
  ["pomp:dive", /\blet'?s (?:dive|explore|unpack|discover|take a (?:closer )?look)|\bdive deep\b|\bdeep dive into\b/i],
  ["pomp:looking-for", /\bif you'?re looking for\b/i],
];

// flags: report only — a human decides
const FLAGS = [
  ["pomp:tapestry", /\b(?:rich )?tapestr(?:y|ies)\b/i],
  ["pomp:landscape", /\b(?:evolving|ever[- ]changing|dynamic|shifting|complex|new) landscape\b/i],
  ["pomp:game-changer", /\bgame[- ]chang(?:er|ing)\b/i],
  ["pomp:cutting-edge", /\bcutting[- ]edge\b/i],
  ["pomp:sota", /\bstate[- ]of[- ]the[- ]art\b/i],
  ["pomp:revolutionize", /\brevolutioni[sz]\w*\b|\bparadigm shift\b/i],
  ["pomp:journey", /\bjourney (?:toward|to|of|into)\b|\bembark\w*\b/i],
  ["pomp:final-boss", /\b(?:final|ultimate) boss\b/i],
  ["pomp:belt-and-braces", /\bbelt[ -]and[ -](?:braces?|suspenders?)\b/i], // unhyphenated/noun use — human decides
  ["hype:seamless", /\bseamless(?:ly)?\b/i],
  ["hype:robust", /\brobust\b/i],
  ["hype:elevate", /\belevat(?:e|es|ed|ing|ion)\b/i],
  ["hype:empower", /\bempower\w*\b/i],
  ["hype:foster", /\bfoster\w*\b/i],
  ["hype:holistic", /\bholistic\w*\b/i],
  ["hype:synergy", /\bsynerg\w*\b/i],
  ["hype:supercharge", /\b(?:supercharge|turbo[- ]?charg|unleash)\w*\b/i],
  ["hype:crucial-role", /\b(?:crucial|vital|pivotal) role\b/i],
  ["fmt:bold-lead", /^\s*(?:[-*]|\d+\.)\s+\*\*[^*]+\*\*/],
];

// decorative emoji: flagged and stripped by --fix (status glyphs like ✅❌ are kept)
const SLOP_EMOJI = ["✨", "🚀", "🔥", "💡", "🌟", "🎉", "🤖", "👋", "🎯", "⚡"];
const EMOJI_RE = new RegExp("[" + SLOP_EMOJI.map((e) => e.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("") + "]+", "g");

function fail(msg, code = 2) {
  process.stderr.write("f slop: " + msg + "\n");
  process.exit(code);
}

const USAGE =
  "f slop — catch and repair LLM slop\n" +
  "  f slop [paths...]   scan files/dirs (no paths: git-changed text files)\n" +
  "  f slop -            scan stdin\n" +
  "  f slop --fix [paths]  apply deterministic rewrites in place\n" +
  "  options: --all  --code  --json  --max n  --rules  -h\n" +
  "  fixable: phrase subs (em-dashes→' - ', belt-and-braces→redundant, …),\n" +
  "           chatbot-residue sentence cuts, decorative emoji\n" +
  "  flag-only: hype vocab (seamless, 'final boss', …), bold-lead bullets\n" +
  "  exit: 0 clean · 1 slop found · 2 usage error\n";

function parseArgv(argv) {
  const flags = {}, pos = [];
  const bools = new Set(["fix", "all", "code", "json", "rules", "help", "h"]);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") { pos.push(...argv.slice(i + 1)); break; }
    if (a === "-h") { flags.help = true; continue; }
    if (a.startsWith("--")) {
      const k = a.slice(2);
      if (bools.has(k)) { flags[k] = true; continue; }
      if (i + 1 >= argv.length) fail(`--${k} needs a value`);
      flags[k] = argv[++i];
    } else pos.push(a);
  }
  return { flags, pos };
}

// ---- scanning ------------------------------------------------------------

function keepCase(match, repl) {
  const out = typeof repl === "function" ? repl(match) : repl;
  if (typeof repl === "string" && repl.startsWith("$")) return out;
  if (/^[A-Z]/.test(match) && /^[a-z]/.test(out)) return out[0].toUpperCase() + out.slice(1);
  return out;
}

// expand a match to its enclosing sentence within the line (never past a
// leading list marker, so "- I hope this helps! Keep." keeps its "- ")
function sentenceSpan(line, start, end) {
  const bm = line.match(/^\s*(?:[-*+]|\d+\.)\s+/);
  const floor = bm ? bm[0].length : 0;
  let s = floor;
  for (let i = start - 1; i >= floor; i--) {
    if (/[.!?]/.test(line[i])) { s = i + 1; break; }
  }
  let e = line.length;
  for (let i = end; i < line.length; i++) {
    if (/[.!?]/.test(line[i])) {
      e = i + 1;
      if (/["')\]]/.test(line[i + 1] ?? "")) e++;
      break;
    }
  }
  return [s, e];
}

const isJunk = (l) =>
  /^[\s\-*>#•]*$/.test(l) ||
  /^\s*(?:[-*]|\d+\.)\s+(?:[-—:]|\s)*$/.test(l) ||
  /^\s*(?:\*\*)?(?:note|important|tip|reminder|pro tip|key takeaways?|conclusion|summary)(?:\*\*)?\s*[:：]?\s*(?:\*\*)?\s*$/i.test(l);

// scanLine returns { hits, fixedLine } — hits: {line,rule,text,action,fix}
function scanLine(line, lineNo) {
  const hits = [];
  let out = line;

  for (const [rule, re, repl] of SUBS) {
    re.lastIndex = 0;
    const m = out.match(re);
    if (!m) continue;
    hits.push({ line: lineNo, rule, text: m[0].trim() || m[0], action: "fix", fix: keepCase(m[0], typeof repl === "function" ? repl(m[0].toLowerCase()) : repl) });
    out = out.replace(re, (x) => keepCase(x, repl));
  }

  for (const [rule, re] of DELS) {
    const m = out.match(re);
    if (!m) continue;
    hits.push({ line: lineNo, rule, text: m[0], action: "fix", fix: "(cut sentence)" });
    const [s, e] = sentenceSpan(out, m.index, m.index + m[0].length);
    out = out.slice(0, s) + out.slice(e);
  }

  if (EMOJI_RE.test(out)) {
    EMOJI_RE.lastIndex = 0;
    const m = out.match(EMOJI_RE);
    hits.push({ line: lineNo, rule: "fmt:emoji", text: m.join(""), action: "fix", fix: "(strip)" });
    out = out.replace(EMOJI_RE, "");
  }

  for (const [rule, re] of FLAGS) {
    const m = out.match(re);
    if (!m) continue;
    hits.push({ line: lineNo, rule, text: m[0].trim(), action: "flag" });
  }

  if (out !== line && out.trim() !== "") {
    out = out.replace(/\s{2,}/g, " ").replace(/\s+([,.;:!?])/g, "$1").replace(/\s+$/, "");
    if (!/^\s/.test(line)) out = out.replace(/^ +/, ""); // no phantom indent on flush-left lines
  }
  if (out !== line && isJunk(out)) out = null; // whole line collapses
  return { hits, fixedLine: out ?? "" , dropped: out === null };
}

function scanText(text) {
  const lines = text.split("\n");
  const allHits = [];
  const fixed = [];
  let changed = false;
  for (let i = 0; i < lines.length; i++) {
    const { hits, fixedLine, dropped } = scanLine(lines[i], i + 1);
    allHits.push(...hits);
    const f = dropped ? null : fixedLine;
    if (dropped || f !== lines[i]) changed = true;
    fixed.push(f);
  }
  let text2 = fixed.filter((l) => l !== null).join("\n");
  text2 = text2.replace(/\n{3,}/g, "\n\n"); // collapse blanks left by dropped lines
  if (text.endsWith("\n") && !text2.endsWith("\n")) text2 += "\n";
  return { hits: allHits, fixed: changed ? text2 : null };
}

// ---- file discovery ------------------------------------------------------

function walk(dir, extRe, acc) {
  let ents;
  try { ents = readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of ents) {
    if (e.name.startsWith(".") && e.isDirectory()) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) walk(p, extRe, acc); }
    else if (extRe.test(e.name)) acc.push(p);
  }
}

function git(args) {
  try {
    return execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] })
      .split("\n").map((s) => s.trim()).filter(Boolean);
  } catch { return null; }
}

function discover(pos, flags) {
  const extRe = flags.code ? new RegExp(`\\.(?:${TEXT_SRC}|${CODE_SRC})$`, "i") : new RegExp(`\\.(?:${TEXT_SRC})$`, "i");
  if (pos.length) {
    const out = [];
    for (const p of pos) {
      let st;
      try { st = statSync(p); } catch { fail(`no such path: ${p}`); }
      if (st.isDirectory()) walk(p, extRe, out);
      else out.push(p); // explicit files always scanned
    }
    return out;
  }
  if (git(["rev-parse", "--show-toplevel"]) === null) {
    const out = []; walk(".", extRe, out); return out;
  }
  let files;
  if (flags.all) files = git(["ls-files"]);
  else files = [...(git(["diff", "--name-only", "HEAD"]) ?? []), ...(git(["ls-files", "--others", "--exclude-standard"]) ?? [])];
  if (files === null) fail("git failed");
  return files.filter((f) => { try { return extRe.test(f) && statSync(f).isFile(); } catch { return false; } });
}

// ---- run -----------------------------------------------------------------

export function register(_ctx) {
  return {
    name: "slop",
    desc: "catch and repair LLM slop in prose (scan, --fix)",
    skills: [{ name: "f-slop", path: path.join(here, "SKILL.md") }],
    run: (argv, _args) => {
      const { flags, pos } = parseArgv(Array.isArray(argv) ? argv : []);
      if (flags.help) { process.stdout.write(USAGE); return; }
      if (flags.rules) {
        for (const [r] of SUBS) process.stdout.write(r + "\tfix\n");
        for (const [r] of DELS) process.stdout.write(r + "\tfix\n");
        process.stdout.write("fmt:emoji\tfix\n");
        for (const [r] of FLAGS) process.stdout.write(r + "\tflag\n");
        return;
      }
      const max = Number(flags.max ?? 25);
      if (!Number.isInteger(max) || max < 1) fail("--max must be a positive integer");

      const stdin = pos.length === 1 && pos[0] === "-";
      if (stdin && flags.fix) fail("--fix cannot rewrite stdin");

      const targets = stdin ? [{ name: "<stdin>", text: readFileSync(0, "utf8") }]
        : discover(pos, flags).map((f) => {
            try {
              if (statSync(f).size > MAX_BYTES) return null;
              const t = readFileSync(f, "utf8");
              if (t.includes("\0")) return null; // binary
              return { name: f, text: t };
            } catch { return null; }
          }).filter(Boolean);

      if (!targets.length) {
        process.stdout.write("no text files to scan (pass paths, --all, or stage changes)\n");
        return;
      }

      const results = targets.map((t) => {
        const { hits, fixed } = scanText(t.text);
        if (flags.fix && fixed !== null && t.name !== "<stdin>") {
          writeFileSync(t.name, fixed);
        }
        return { name: t.name, hits, fixed: flags.fix ? fixed !== null : false };
      });

      const total = results.reduce((n, r) => n + r.hits.length, 0);
      const fixable = results.reduce((n, r) => n + r.hits.filter((h) => h.action === "fix").length, 0);
      const remainingFlagOnly = (rs) => rs.reduce((n, r) => n + (r.fixed ? r.hits.filter((h) => h.action === "flag").length : r.hits.length), 0);

      if (flags.json) {
        process.stdout.write(JSON.stringify(results.filter((r) => r.hits.length), null, 1) + "\n");
      } else {
        for (const r of results) {
          if (!r.hits.length) continue;
          process.stdout.write(r.name + (r.fixed ? "  (fixed)" : "") + "\n");
          for (const h of r.hits.slice(0, max)) {
            const t = h.text.length > 50 ? h.text.slice(0, 47) + "…" : h.text;
            process.stdout.write(`  ${String(h.line).padStart(4)}  ${h.rule}  "${t}"${h.action === "fix" ? (flags.fix && !r.name.startsWith("<stdin>") ? "" : "  → " + h.fix) : ""}\n`);
          }
          if (r.hits.length > max) process.stdout.write(`       +${r.hits.length - max} more\n`);
        }
        if (!total) process.stdout.write("clean — no slop in " + targets.length + " file" + (targets.length === 1 ? "" : "s") + "\n");
        else if (flags.fix) {
          const left = remainingFlagOnly(results);
          process.stdout.write(`${total} hits · ${total - left} fixed · ${left} flag-only left\n`);
        } else {
          process.stdout.write(`${total} hits in ${results.filter((r) => r.hits.length).length} file${results.filter((r) => r.hits.length).length === 1 ? "" : "s"} · ${fixable} fixable (--fix)\n`);
        }
      }

      const remaining = flags.fix ? remainingFlagOnly(results) : total;
      process.exit(remaining > 0 ? 1 : 0);
    },
  };
}
export default { register };
