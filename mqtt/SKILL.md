---
name: f-mqtt
description: Read and publish MQTT with `f mqtt` (retained topics, live subscribe, current value, discovery configs) instead of mosquitto_sub/curl; reads the `mqtt` cred so the broker password never lands in shell history.
---

# f mqtt — MQTT broker

Terse wrapper over an MQTT broker using `mqtt.js`. One fact per line: `topic  payload`.

The password lives in the `mqtt` cred (`f creds`), never in argv or history. `f mqtt urls`
shows what resolved and where the password came from; it never prints the password itself.

## Setup (once)

```
f creds set mqtt <broker-password>
```

Defaults are host `10.1.5.4`, port `1883`, user `mqtt`. Override per-invocation with
`--host`, `--port`, `--user`, `--pass`, or via env `MQTT_HOST` / `MQTT_PORT` /
`MQTT_USER` / `MQTT_PASS`. To change the defaults permanently, edit `DEFAULTS` in
`index.js` — host/port/user are not read from creds (only the password is).
If creds are locked: `f creds unlock`.

## Commands

```
f mqtt urls                          broker + user + credential provenance
f mqtt state <topic>                 CURRENT value  <- usually what you want
f mqtt sub <topic> [n]               next n messages (default 1)
f mqtt retained [filter]             topic + retained payload ("#" for everything)
f mqtt topics [filter]               distinct retained topics only
f mqtt disco [prefix]                summarise HA discovery configs (default homeassistant)
f mqtt pub <topic> <payload>         publish; --retain to make it retained
```

`--wait <ms>` sets the collect window (`sub` 8s, `state`/`retained`/`topics`/`disco` 12s).
`--full` disables the 200-char payload truncation (`disco --full` emits JSON).

Examples:

```
f mqtt state 'valetudo/FrankShamelessCrocodile/StatusStateAttribute/+'
f mqtt retained 'valetudo/#' --wait 14000
f mqtt disco
```

Wildcards are MQTT's, not the shell's: only `+` (one level) and `#` (tail). `*` silently
matches nothing, which reads as "topic is empty" rather than "my filter was invalid".
Quote filters so the shell does not expand them.

## Reading values: `state` vs `sub`

`state` answers "what is X right now" — it uses the whole window and keeps the best value
per topic. `sub` counts messages and returns the first n, which is wrong for anything that
is only *published on change* and retained: a robot sitting idle publishes nothing, so
`sub` waits out its window and reports zero. Use `sub` for watching transitions, `state`
for asking a question.

A retained payload of zero length is MQTT's sentinel for "value currently unknown", not an
empty string. Those print as `<empty payload: value unknown or cleared>` so "docked" and
"unknown" can never look alike.

## Retained counts are timed, not signalled

MQTT 5 has a Retain-Available flag that tells a subscriber the retained snapshot is
complete. This broker returns **no** server properties at all (verified:
`client.options.serverProperties` is empty), so that signal is unavailable and retained
scans fall back to a time window. Output says which mode it used — `snapshot complete` or
`timed window 12000ms (count may be partial)`. Trust the footer before acting on a count.

## Debugging gotchas

These cost real time; they are properties of this code, not of the broker.

- `n: Infinity` in `collectN` means "never satisfied": `Infinity` is `1/0`, so
  `got.length >= n` is never true and the promise can only settle on timeout. Reads looked
  like the broker was slow or flaky when the collection condition simply could not fire.
- A command that reports values must actually `subscribeAsync`. A missing subscribe yields
  "no message" forever with no error, while a raw probe on the same broker works fine.
- Truncation must be `.slice(0, limit)`. `.slice(limit)` passes it as *start*, so any payload
  shorter than the limit renders as `""` — indistinguishable from "topic has no value".
- Before theorising about broker behaviour, add one line that prints the value received. It
  ended a long wrong investigation in one run.

## Home Assistant notes

`f mqtt disco` lists what HA is told to create; HA then owns those entities. HA's own MQTT
config entry is `single_instance`, so there is no UI/API path to add a hand-written sensor
to it — either the device publishes a discovery config, or the sensor has to be a HA
template entity fed by `mqtt:` topics in YAML.
