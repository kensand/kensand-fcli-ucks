---
name: f-pi-models
description: Move pi's model providers (~/.pi/agent/models.json) between machines through the f creds store. Use when a new machine needs pi's local providers, or before the local file is destroyed.
---

# f pi-models

The pi model providers (LAN LLM boxes, API keys) are machine-local and not in
dotfiles. `f pi-models` carries them through the encrypted creds store by delegating
to `f creds files`, where **the key is the destination** — `file:~/.pi/agent/models.json`
resolves against whatever `$HOME` is on the host (`/home/kenny` on the desktop,
`/data/data/com.termux/files/home` on Termux).

```
f pi-models save       # validate the local JSON, then pack it
f pi-models restore    # unpack over the local file (.bak written first), then re-validate
f pi-models status     # which side has what, incl. the machine it was packed on
f pi-models migrate    # move old shapes onto the portable key (see below)
```

- Needs an unlocked daemon: `f creds unlock` (passkey). `f creds request` if you are waiting on someone else.
- Nothing travels through argv — the old version shelled `f creds set pi-models $(cat models.json)`, which put API keys in every process list on the box.
- Only `models.json` moves. `auth.json`, `mcp.json` and session state stay put.

## Migrations

`migrate` is idempotent and handles the two pre-portable shapes:

1. **legacy absolute manifest key** — `file:/home/kenny/.pi/agent/models.json`
   packed from another machine. `f creds files relabel <that> ~/.pi/agent/models.json`
   renames it in place, content untouched.
2. **legacy string cred `pi-models`** — the whole file stored as one cred value.
   It gets written out (0600, existing file backed up) and re-packed; remove the
   old cred yourself with `f creds rm pi-models` once you have checked.

`f creds files ls` flags any absolute key outside the current `$HOME`; that is the
same condition `status` reports as `legacy:`.
