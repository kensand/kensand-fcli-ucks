// Single entry point for the test suites.
//   node test/run-all.mjs
// Exits non-zero if any suite fails. Both are fully offline.
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
// bitwarden-wasm.test.mjs verifies this client against Bitwarden's own Rust/WASM crypto.
// It is offline but OPTIONAL (fetches nothing; needs the oracle at /tmp/bw-oracle -- see that
// file's header) and prints a loud SKIPPING banner when absent, because a cross-implementation
// check that silently registers zero tests is worse than none: for a while every fixture here
// was built from the same assumptions the client implements, so a shared misunderstanding
// looked green while the client could not read a single real vault.
const suites = ["crypto.test.mjs", "bitwarden-wasm.test.mjs", "e2e.test.mjs"];
let bad = 0;
for (const f of suites) {
  process.stdout.write(`\n── ${f} ${"─".repeat(Math.max(0, 58 - f.length))}\n`);
  const r = spawnSync(process.execPath, [path.join(here, f)], { stdio: "inherit" });
  if (r.status !== 0) bad++;
}
process.stdout.write(`\n${bad ? `${bad} of ${suites.length} suites FAILED` : `all ${suites.length} suites passed`}\n`);
process.exit(bad ? 1 : 0);
