---
name: f-grocy
description: Query and control a grocy instance (stock, shopping list, recipes, chores, tasks, batteries, calendar) via `f grocy` instead of curling /api/v1.
---

# f grocy — household stock, shopping, recipes, chores, chores

## Credentials

Creds (first hit wins; flags/env override):

- Combined: `f creds set grocy <url>|<api-key>` (or the host name, e.g. `grocy.kensand.net`)
- Separate: `f creds set <host>-host <url>` + `f creds set <host>-token <api-key>`
- Env: `GROCY_URL`, `GROCY_TOKEN`; flags: `--url`, `--token`
- Last resort: `grocy.baseUrl` in `f.config.json` (base only)

The api key comes from the grocy UI: Settings → API keys. Auth is
`Authorization: Token <key>` — NOT Bearer.

## Common workflows

```
f grocy stock --low            # everything below min stock
f grocy stock --due            # due within 7d, overdue, expired
f grocy shopping               # open shopping list items
f grocy buy oat-milk 2         # add to shopping list
f grocy done 42                # mark item 42 done (toggles)
f grocy add milk 2 --best-before 2026-08-01   # stock in
f grocy consume milk 1         # stock out
f grocy transfer milk 1 fridge pantry
f grocy recipes                # which recipes are cookable now?
f grocy recipe-need 7          # missing ingredients of recipe 7 -> shopping list
f grocy did dishes             # track chore
f grocy chores                 # what's next
f grocy tasks                  # open tasks
f grocy batteries              # what needs charging
f grocy calendar               # ical sharing link (meal plan + chores + tasks)
```

## Addressing

- Products/chores/batteries accept an id or a unique name substring
  (`f grocy consume oat milk 1`).
- `barcode:123456789` works as a product anywhere a product is expected.
- Shopping `done` works on the shopping-item id shown in `f grocy shopping`
  (not the product id).
- Ambiguous matches list the candidates — pass the id.

## Raw escape hatch

```
f grocy obj locations              # any generic entity
f grocy GET /stock/volatile        # raw /api/v1 passthrough
f grocy POST /chores/3/execute     # raw mutation
```
