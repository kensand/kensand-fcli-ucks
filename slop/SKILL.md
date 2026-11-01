---
name: f-slop
description: Catch and repair LLM-generated slop in prose with `f slop` (scan files/dirs/git changes, --fix deterministic rewrites) instead of eyeballing "delve" and "I hope this helps".
---
# f slop

`f slop` finds model-generated prose tells — pompous filler ("in today's
fast-paced world"), chatbot residue ("I hope this helps!"), hype vocabulary
("seamless", "robust", "leverage"), decorative emoji, em-dash piles — and
repairs the deterministic ones.

## Usage

```
f slop [paths...]        scan files/dirs; no paths = git-changed text files
f slop -                 scan stdin
f slop --fix [paths...]  apply deterministic fixes in place
f slop --all             whole repo (git ls-files), not just changed files
f slop --code            also scan source files (comments)
f slop --json            machine-readable hits
f slop --rules           list rule names (fix|flag)
```

Exit codes: 0 clean · 1 slop found (or flag-only left after `--fix`) · 2
usage error — usable as a pre-commit/CI gate.

## What --fix does (deterministic)

- **Substitutions:** utilize→use, leverage→use, delve→dig, furthermore/
  moreover/additionally→also, "in order to"→"to", "a wide range of"→"many",
  "due to the fact that"→"because", belt-and-braces→redundant (hyphenated
  adjectival use only), etc. Case is preserved.
- **Em-dash downgrade:** every `—` becomes ` - ` — spaced pairs, unspaced
  joins ("Moscow—Berlin"), and dash-attribution lines. En-dash ranges
  (2020–2024), table separators, and setext underlines are untouched.
- **Sentence cuts:** chatbot residue ("I hope this helps", "Feel free to
  reach out", "Certainly!", "As an AI", "Whether you're…") — the whole
  enclosing sentence is deleted; lines that collapse to a bare bullet or a
  dangling "Note:" are dropped.
- **Emoji strip:** decorative ✨🚀🔥💡🌟🎉🤖👋🎯⚡ only; status glyphs (✅❌)
  are kept.

## Flag-only (human decides)

Hype words (seamless, robust, elevate, empower, foster, tapestry, "game-
changer", "cutting-edge", "final/ultimate boss"), "crucial role",
"journey toward/embark", unhyphenated "belt and braces/suspenders" (noun
use — rewrite by hand: "redundant" or "redundancy"), bold-lead bullets
(`- **Thing:** …`). These are often legitimate — read before rewriting.

## Typical flows

- Reviewing AI-drafted docs before committing:
  `f slop docs/ --fix && f slop docs/` (second pass shows flag-only).
- Gating your own agent output: `f slop --all || true` before a PR; keep
  CI red on flag-only only if the project wants that rigor.
- Quick check of pasted text: `pbpaste | f slop -`.

## Notes

- Only `.md/.markdown/.txt/.rst/.org/.adoc` are auto-scanned; explicit file
  args bypass the filter. Binaries and files >2 MB are skipped.
- `--fix` rewrites files with no backup — run it in a git tree (default
  target discovery already assumes one).
- Sentence-cut spans from the previous `[.!?]` to the next one; a sentence
  containing the phrase is removed wholesale. That is intentional: half-cut
  chatbot sentences still read like slop.
