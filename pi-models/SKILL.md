---
name: f-pi-models
description: Save/restore ~/.pi/agent/models.json in the f creds store. Use when a new machine needs pi's local model providers, or before the local file is destroyed.
---

# f pi-models

The pi model providers (LAN LLM boxes) are machine-local and not in dotfiles.
`f pi-models` moves them through the encrypted creds store:

- `f pi-models save` — read `~/.pi/agent/models.json`, store as creds `pi-models` (JSON-validated first)
- `f pi-models restore` — pull `pi-models` from creds, write to `~/.pi/agent/models.json` (validates, backs up the existing file to `models.json.bak`)
- `f pi-models status` — which side has what

Notes:

- Requires an unlocked creds daemon (`f creds unlock`) — restore blocks on `f creds request` if it is locked.
- Works across machines: save on one host, unlock creds on another (same store), restore.
- Nothing here touches `auth.json`, `mcp.json`, or session state.
