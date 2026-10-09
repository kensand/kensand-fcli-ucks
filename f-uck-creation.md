---
name: f-uck-creation
description: Create and publish new f ucks. Trigger: a command has been used multiple times and has no covering uck.
---

# Creating ucks

An **uck** is a directory with an `index.js` that exports `register(ctx)`. It is only a word when prefixed with `f-`.

## When to make one

A command is needed a second time in a session (or is clearly repeated in scripts/CI) and `f help` has no covering uck. Make the uck, not a copy-paste.

## Where it lives (this machine)

- Personal bucket: `https://forgejo.kensand.net/kensand.net/kensand-fcli-ucks.git` — already a source in `~/.f/f.config.json`, installed as clone bucket `~/.f/ucks/kensand-fcli-ucks/`.
- Edit the repo (or the bucket directly): add `<name>/index.js`, then publish with:

```
f uck push <name>     # or: f uck push   (all dirty ucks in the bucket)
```

`f uck` commits, rebases, and pushes the store bucket to its own origin. No push target needed for the clone bucket (bucket name = target name).

## Skeleton

```js
// myuck/index.js — zero deps unless you add a package.json
import { execSync } from "node:child_process";

export function register(_ctx) {
  return {
    name: "myuck",
    desc: "what it does (terse)",        // shown in f help
    run: (_argv, args) => {
      const rest = args._ ?? [];          // CLI args after the uck name
      const out = execSync(`some command ${rest.join(" ")}`, { encoding: "utf8" });
      process.stdout.write(out);
    },
    // skills: [{ name: "myuck", path: "./SKILL.md" }]  // optional: export a skill
  };
}
export default { register };
```

## Rules

- `register(ctx)` runs once at load; `run(argv, args, ctx)` runs per invocation. Interop via `ctx.registry` (other ucks' exported objects) at run time only.
- Keep output terse: one fact per line, no banners. Errors: one line + the fix.
- Prefer node builtins (`node:fs`, `node:path`, `node:child_process`) over deps. If a dep is needed, `npm install` inside the uck dir; `node_modules` is never pushed by `f uck push`.
- Name the uck after the thing, not the verb pile: `f deploy`, not `f do-the-deploy-thing`.
- After publishing, `f <name> --help` (or the uck's usage path) must print a usable usage; `f help` should show the new desc.

## Publishing checklist

1. `f uck repo ls` — confirm the bucket is a clone with the right origin.
2. Add `myuck/index.js` in the bucket (`~/.f/ucks/kensand-fcli-ucks/myuck/`) or the repo checkout.
3. Publish. Note: for NEW (untracked) uck dirs, `f uck push` only commits dirty TRACKED files, so it can say "nothing to do" — in that case commit directly in the bucket:
   ```
   git -C ~/.f/ucks/kensand-fcli-ucks add myuck && git -C ~/.f/ucks/kensand-fcli-ucks commit -m "add myuck uck" && git -C ~/.f/ucks/kensand-fcli-ucks push
   ```
   (For changes to already-tracked ucks, `f uck push myuck` works as-is.)
4. `f myuck --help` — sanity check.
5. If the uck is non-trivial, add a skill (this one, or a `myuck` skill) and register it: `f skills add myuck /path/to/skill.md` (use `-g` for global).
