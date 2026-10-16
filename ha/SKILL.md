---
name: f-ha
description: Query and control Home Assistant via `f ha` (states, service calls, scenes, automations, history, weather, calendars) instead of curl against /api.
---

# f ha — Home Assistant

Token-efficient wrapper around the Home Assistant REST API. Output is terse: one fact per line, entities as `entity_id  state  friendly_name`.

## Setup (once)

Two creds (or a combined one):

```
f creds set ha-host   https://ha.kensand.net
f creds set ha-token  <long-lived-access-token>
```

Combined alternative: `f creds set ha "https://ha.kensand.net|<token>"`.
Precedence: `--url`/`--token` flags > `HA_URL`/`HA_TOKEN` env > `ha.baseUrl` in f.config.json > creds.
`f ha urls` shows what resolved. If creds are locked: `f creds unlock`.

## Commands

```
f ha ls [query]            entities: domain (light), substring, or glob
f ha state [entity]        all states terse, or one entity's full state (json)
f ha search <query>        = ls <query>
f ha call <domain> <svc> [key=value ...] | {json}
                           e.g. f ha call light turn_on entity_id=light.kitchen
f ha scene [name]          list scenes / turn one on (name or id)
f ha auto                  list automations (id, state, friendly name)
f ha auto on|off <name>    enable/disable an automation
f ha auto <name>           trigger an automation
f ha history <e...> [-s start] [-e end] [--minimal]
                           times: ISO 8601 or 30m/2h/1d/1w (bare = "ago")
f ha weather [entity]      current weather (default: single weather.*)
f ha cal [entity] [-s] [-e]  calendar events (default: last 1h .. +7d)
f ha info                  server summary (version, tz, entity counts)
f ha conf [type]           list automations/scripts/scenes with their config id
f ha conf get <type> <id>  full config JSON (needed to copy or edit one)
f ha conf set <type> <id> '<json>'
                           replace config; id is the config id from `conf ls`
f ha conf new <type> '<json>'
                           create with a generated id; prints the new id
f ha conf rm <type> <id>   delete a .storage (UI/API-created) entry
f ha conf validate '<json>'
                           check without touching anything
f ha ws whoami             confirm auth over WebSocket (user, is_owner)
f ha ws types              which WS message types this HA build accepts
f ha ws raw '<json>'       any WS message, e.g. '{"type":"config/device_registry/list"}'
f ha ws sub <event_type> [n]
                           watch live events (e.g. call_service, state_changed)
f ha ws helper ls <type>   list helper entities of one type
f ha ws helper ls-all      list every helper type
f ha ws helper new <type> <name> ['<json>']
                           create a helper; `name` becomes the entity slug
f ha ws helper update <type> <name> '<json>'
                           full-schema update (see Notes)
f ha ws helper rm <type> <name>
                           delete a helper
f ha <METHOD> <path> [json]  raw call, e.g. f ha GET /api/states/sensor.x
```

## Examples

- "what's the thermostat doing" → `f ha ls climate` then `f ha state climate.thermostat_kitchen`
- "turn the kitchen lights on" → `f ha call light turn_on entity_id=light.kitchen`
- "turn off all lights" → `f ha call light turn_off` (no entity_id = whole domain)
- "how warm has it been" → `f ha history climate.thermostat_kitchen -s 6h`
- "is the water-leak automation armed" → `f ha auto | grep leak`
- service data as JSON: `f ha call climate set_temperature entity_id=climate.x '{"temperature":72}'`

## Notes

- Entity args accept full ids or unique substrings; `state`, `auto`, `scene`, `weather`, `cal` resolve by id first, then friendly name.
- `call` prints the entity_ids HA reports as changed; `ok <domain>.<service>` when nothing changed.
- Times: `2h` means "2 hours ago"; `end` also accepts the future as an ISO datetime.
- Errors are one line + the fix (missing cred, ambiguous entity, HTTP status + HA message).
- `auto on/off` uses `homeassistant.turn_on/turn_off` with the automation's entity_id (the only REST path for enabling/disabling).

### conf — editing automations without the UI

`conf ls` marks each entry `editable` or `yaml-only`. Only `editable` ones (those carrying a
config id, i.e. stored in `.storage`) can be changed via `conf get/set/rm`; YAML-defined
entries have no id and are invisible to this API.

Ids are opaque strings, not one format: HA-generated ones are epoch milliseconds
(`1762124343715`), while `conf new` generates 32 hex chars. Treat them as opaque and always
copy from `conf ls` output rather than reconstructing one — a hand-copied id that is one
character short is a 404 with no hint of the true id.

Create and update are asymmetric, which is the usual source of 404s: `POST` to the bare
`/api/config/<type>/config` does not exist, so creating must name an id —
`/api/config/automation/config/<id>`. `conf new` generates one and prints it; write
it down, it is the only handle for later `get/set/rm`.

Always `conf get` before `conf set`. `set` replaces the whole config, so editing blind
drops every field you did not resend (mode, variables, triggers you did not quote).

`template` is not a loaded integration on this instance, so `conf` accepts only
`automation`, `script`, `scene`. The `POST /api/template` endpoint still works for
rendering, and its field is named `template`, not `source` — the wrong key returns a bare
500 with no hint.

### ws — what REST cannot reach

Helpers (`timer`, `counter`, `schedule`, `input_*`) have no REST config endpoint on this
build: `/api/config/timer/config/<id>` and the `input_datetime` equivalent both 404. They
are creatable only over WebSocket, which is what `ws helper` wraps. Use
`f ha ws helper new timer my_timer '{"duration":"12:00:00"}'`.

Message types are `timer/list`, `timer/create`, ... — that is `<domain>/<verb>`, **not**
`helper/timer/create`. `ws types` probes what the running build accepts rather than
assuming; on this instance `config/automation/list`, `config/area/list` and
`config/label/list` are absent even though automations are fully manageable over REST, so
availability is genuinely per-build and per-domain.

`helper update` requires the full schema: it keys on `<domain>_id` (not `object_id`) and
revalidates every field, so `name` must be resent or the update is rejected. Passing a
partial config is the most common failure.

The WebSocket client must handle the HTTP/1.1 101 response via `req.on("upgrade")`. Using
the `https.request` response callback looks right and silently never fires, because Node
routes 101s away from that callback — it presents as "connection hangs" with no error.

### Verified working

End-to-end on this instance: WebSocket auth as the owning user, `timer` creation, and an
automation triggered by an injected error that delivered two phone notifications (alert,
then all-clear).
