---
name: f-kuma
description: Check uptime-kuma service health from the CLI with `f kuma` (watch/down/raw) instead of curling the status-page API. No token needed.
---

# f kuma

Uptime-kuma (default `https://uptime.kensand.net`) as a cheap health watch.
Uses ONLY the two public tokenless endpoints — no creds, no API key:

- `f kuma watch` — one line per monitor (status, last ping, last-check time), problems first, `N/M UP` summary. Exit 0 whenever the fetch succeeded.
- `f kuma down` — prints only DOWN/PENDING/UNKNOWN monitors and exits 1; all green = no output + exit 0. This is the scripted check / watcher primitive — use this, not `watch`, in scripts and heartbeat monitors.
- `f kuma raw` — raw heartbeat JSON (debug).
- `--json` on watch/down emits structured records `{id,name,label,ping,time,msg}`.
- `--base <url>` / `KUMA_URL` point at another instance.

Rules:

- Never curl other status-page paths unauthenticated: the SPA catch-all returns 200 HTML for everything except `/api/status-page/heartbeat/status` and `/api/status-page/status` — misleading. Verified 2026-10-21.
- `/metrics` needs HTTP basic auth (API key as password). Not used here; if a later increment needs it, the cred name is `kuma-token` in `f creds`.
- Requires `jq` on PATH — parsing is delegated to it.
- `UNKNOWN` = monitor on the status page with no heartbeat data yet; `down` treats it (and PENDING) as not-green.
- Exit codes: 0 ok · 1 down-detected or fetch/parse error · 2 usage.
