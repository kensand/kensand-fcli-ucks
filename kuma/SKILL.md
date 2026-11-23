---
name: f-kuma
description: Check uptime-kuma service health from the CLI with `f kuma` (watch/down/raw) instead of curling the status-page API. No token needed.
---

# f kuma

Uptime-kuma (default `https://uptime.kensand.net`) as a cheap health watch.
Uses ONLY the two public tokenless endpoints — no creds, no API key:

- `f kuma watch` — one line per monitor (status, last ping, last-check time), problems first, `N/M UP` summary. Exit 0 whenever the fetch succeeded.
- `f kuma down` — prints only DOWN/PENDING/UNKNOWN monitors and exits 1; all green = no output + exit 0. This is the scripted check / watcher primitive — use this, not `watch`, in scripts and heartbeat monitors. **Silence + exit 0 means ALL GREEN, not a failure**, and exit 1 with rows is a real signal.
- `f kuma raw [endpoint]` — raw JSON for debugging: `heartbeats` (default) or `status` (monitor id → name). Anything else is rejected; the uck only ever reaches those two endpoints, because other uptime-kuma paths return misleading 200 HTML.

## Exit codes vs machine output

`--json` **always exits 0** — the payload carries the verdict (`.label`, and `.code` 0/1/2), so
`f kuma down --json | jq` never looks like a crash. Only the **bare** `f kuma down` is an
exit-code signal. Never treat a non-zero exit as "the command broke" or a zero exit as "all
green" once `--json` is involved, and never trust `$?` straight after a pipe.
- `--json` on watch/down emits structured records `{id,name,label,ping,time,msg}`.
- `--base <url>` / `KUMA_URL` point at another instance.

Rules:

- Never curl other status-page paths unauthenticated: the SPA catch-all returns 200 HTML for everything except `/api/status-page/heartbeat/status` and `/api/status-page/status` — misleading. Verified 2026-10-21.
- `/metrics` needs HTTP basic auth (API key as password). Not used here; if a later increment needs it, the cred name is `kuma-token` in `f creds`.
- Requires `jq` on PATH — parsing is delegated to it.
- `UNKNOWN` = monitor on the status page with no heartbeat data yet; `down` treats it (and PENDING) as not-green.
- Exit codes: 0 ok · 1 down-detected or fetch/parse error · 2 usage.
