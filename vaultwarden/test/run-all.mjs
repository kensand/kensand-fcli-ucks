// Single entry point for both test suites.
//   node test/run-all.mjs
// Exits non-zero if either suite fails. Both are fully offline.
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const suites = ["crypto.test.mjs", "e2e.test.mjs"];
let bad = 0;
for (const f of suites) {
  process.stdout.write(`\n── ${f} ${"─".repeat(Math.max(0, 58 - f.length))}\n`);
  const r = spawnSync(process.execPath, [path.join(here, f)], { stdio: "inherit" });
  if (r.status !== 0) bad++;
}
process.stdout.write(`\n${bad ? `${bad} of ${suites.length} suites FAILED` : `all ${suites.length} suites passed`}\n`);
process.exit(bad ? 1 : 0);
