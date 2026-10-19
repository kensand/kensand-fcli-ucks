---
name: f-ddg
description: Search DuckDuckGo from the CLI with `f ddg` (web/image results, JSON, browser fallback) instead of curling html.duckduckgo.com.
---

# f ddg

`f ddg` posts to DuckDuckGo's no-JS endpoints (`html.duckduckgo.com`, or
`lite.` with `--lite`) and prints parsed results. Zero deps.

## Commands

```
f ddg <query...>            numbered web results: title / url / snippet
f ddg images <query...>     image-oriented search (DDG images vertical)
f ddg open <query...>       open the results page in $BROWSER / xdg-open
```

## Options

- `--json` — `[{title,url,snippet}]` instead of the list
- `--n <k>` — max results (default 10)
- `--region <r>` — kl region, e.g. `us-en` (default), `de-de`
- `--safe <0|1|2>` — moderation: off / moderate / strict
- `--lite` — use `lite.duckduckgo.com` markup
- `--timeout <ms>`, `--retries <k>` (default 2, linear backoff)
- `--no-block` — if DDG blocks, open the results page in the browser and print the URL instead of failing

## The 202 gotcha (read before debugging)

DuckDuckGo rate-limits server-side clients hard. A blocked request returns
**HTTP 202 with an "anomaly" challenge page**, not a 4xx. Key facts:

- The cooldown is **IP-based**, not per-request: once you trip it, *every*
  DDG endpoint (html, lite, i.js JSON API) stays blocked for a long window
  (observed from a datacenter IP: 30+ min after a short burst of requests;
  a lone request from a fresh IP usually just works). Retrying faster or
  with different params does nothing.
- A single request usually succeeds; a burst trips the block. Keep a
  minute-ish spacing between invocations in scripts.
- The uck detects 202/anomaly pages and reports `blocked by DuckDuckGo
  rate limit` immediately (no useless retries). Use `--no-block` to fall
  back to the browser (browser sessions have their own cookies/reputation).
- The JSON image API (`duckduckgo.com/i.js`) needs a `vqd` token from a seed
  page and still gets challenged from server IPs — that's why image search
  here uses the HTML vertical, not `i.js`.

If results ever come back empty without a block message, DDG changed the
markup: check `curl -s 'https://html.duckduckgo.com/html/?q=test' | grep
result__a` and update the regexes in `index.js`.
