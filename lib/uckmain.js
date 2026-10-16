// uckmain — tiny shared guard so a uck's index.js can double as a CLI entry
// point when Node runs it directly, without firing when the `f` harness imports
// it. Needed by credential providers: `f creds` probes them by running
// `node <uck>/index.js resolve <name>` in a child process, so importing a
// provider must stay side-effect-free while direct execution must do work.
//
//   #!/usr/bin/env node
//   import { uckMain } from "../uckmain/index.js";
//   export function register(ctx) { return { name: "myuck", run: main, … }; }
//   async function main(argv, args) { … }
//   uckMain(import.meta.url, main);           // runs main() only if executed
//
// Zero deps.

import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";

export function isMain(metaUrl, argv = process.argv) {
  const self = argv[1];
  if (!self) return false;
  try {
    return pathToFileURL(realpathSync(self)).href === metaUrl;
  } catch {
    return false;
  }
}

/**
 * If this file is the process entry point, call `fn(process.argv.slice(2))`.
 * Errors go to stderr as one line and exit 1; `fn`'s own exit codes are
 * respected (return a number to set one).
 */
export function uckMain(metaUrl, fn, argv = process.argv) {
  if (!isMain(metaUrl, argv)) return;
  Promise.resolve()
    .then(() => fn(argv.slice(2)))
    .then((code) => {
      if (typeof code === "number" && code !== 0) process.exitCode = code;
    })
    .catch((e) => {
      process.stderr.write(`f: ${e?.message ?? e}\n`);
      process.exitCode = 1;
    });
}

export default { isMain, uckMain };
