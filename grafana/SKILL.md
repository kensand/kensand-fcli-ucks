---
name: f-grafana
description: "Query and control the self-hosted Grafana (health, datasources, dashboards, PromQL through the datasource proxy) via `f grafana` instead of curling /api with a hand-rolled bearer."
---

# f grafana

Grafana at `https://grafana.kensand.net` from the CLI. Token comes from the
`f creds` store — never paste it into a curl by hand.

## Creds

| cred | what |
|---|---|
| `grafana-host` | base url (optional; defaults to `https://grafana.kensand.net`) |
| `grafana-token` | service-account token (`glsa_...`), Admin role |

Store once: `f creds put grafana-token` (reads stdin, never echoes).
Overrides: `--url` / `--token` flags, `GRAFANA_URL` / `GRAFANA_TOKEN` env.
Auth is `Authorization: Bearer <token>` (service-account keys, not API keys).

## Commands

```
f grafana health                      # database=ok version=... (no token needed)
f grafana ds [name]                   # datasources: uid type name url access
f grafana dash ls [query]             # uid [folder] title
f grafana dash get <uid> [--json]     # panel id/type/title summary, or raw model
f grafana query 'up' [--ds prometheus] [--json]   # instant PromQL, default ds = prometheus
f grafana GET /api/org                # raw call: METHOD /path [json-body]
```

`query` resolves `--ds` by exact name, substring, then type match against
`/api/datasources`, then calls the datasource proxy
`/api/datasources/uid/<uid>/resources/api/v1/query` — so it works for any
Prometheus-compatible datasource without touching the TSDB port.

## Gotchas

- A locked creds store exits with `creds store is locked` — run
  `f creds unlock` first (vault-backed; see f-creds skill).
- Service-account tokens must be created in the UI (Administration → Service
  accounts → Add token); they are shown once. A `Viewer` token only answers
  read calls; dashboards/datasource writes need Editor/Admin.
- `f uck check` wants `package.json` present (rule N2) — it is; don't delete it.
