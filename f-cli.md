---
name: f-cli
description: Use the `f` token-efficient CLI (ucks) instead of raw commands. Prefer f whenever an uck covers the task; create a uck when a command is repeated.
---

# f CLI

`f` is a token-efficient CLI. Ucks are units of functionality; output is terse, one fact per line, no boilerplate.

## When to use f instead of a raw command

| Raw command | f equivalent |
| --- | --- |
| `ls` (for a machine-readable list) | `f ls` |
| `which <bin>` | `f w <bin>` |
| `curl -H "Authorization: Bearer $TOKEN" https://<forgejo>/api/v1/...` | `f fj call <endpoint> {…}` (in a clone of that instance) |
| `curl -H "Authorization: Bearer $HA_TOKEN" https://ha/api/...` | `f ha <cmd>` (states/call/scene/auto/history/weather/cal) |
| echo secrets into env / files | `f creds set <name> <value>` |
| listing installed skills/instructions | `f skills ls` / `f skills show <name>` |

## Orientation (cheap, run once)

- `f help` — every available uck with a one-line desc.
- `f <uck> --help` — the uck's own usage text.
- `f v` — f version.

## Built-in ucks

- `f ls [path]` — terse file listing, one entry per line.
- `f w <bin>` — locate a binary (alias for `which`).
- `f config [-g] <get|set|add|remove|list> <jsonpath> [value]` — edit f.config.json via JSONPath. `-g` targets global `~/.f/f.config.json`; default is project `f.config.json`.
- `f skills [-g] <op>` — manage local skill entries (markdown pointers) in f.config.json:
  - `f skills` — show the default skill
  - `f skills search <query>` — find skills by name + content
  - `f skills ls` — list skills (name + path)
  - `f skills show <name>` — print a skill's markdown
  - `f skills add <name> <path>` — register a skill (path to a local .md)
  - `f skills rm <name>` — remove a skill
- `f creds` — see the `f-creds` skill.
- `f fj` — see the `f-fj` skill.
- `f ha` — see the `f-ha` skill.
- `f uck` — see the `f-uck-creation` skill.

## The rule

If you are about to run a command for the **second time** in a session (or you already see it repeated in a script/CI file), check `f help` for a covering uck first; if none exists, create one (skill `f-uck-creation`) instead of repeating the raw command.
