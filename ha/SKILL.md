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
