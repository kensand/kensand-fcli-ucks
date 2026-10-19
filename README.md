# kensand-fcli-ucks

Personal ucks for f. Each uck is a `<name>/index.js` module (plus any
supporting files). This repo is a source in `~/.f/f.config.json`; f installs
every uck dir here into `~/.f/ucks/kensand-fcli-ucks/<name>/`.

## Ucks in here

| uck | what it does |
|---|---|
| `f vaultwarden` | read secrets from a Vaultwarden vault; a credential provider for `f creds`. Zero-dep native client. See [`vaultwarden/README.md`](./vaultwarden/README.md). |
| `f fj` | Forgejo/Gitea API (issues, PRs, pipelines) |
| `f gh` | GitHub API (repos, issues, PRs, releases, search) |
| `f ha` | Home Assistant (states, service calls, scenes, calendars, automations, WebSocket helpers). See [`ha/SKILL.md`](./ha/SKILL.md). |
| `f mqtt` | MQTT broker (retained topics, live subscribe, current value, HA discovery configs). See [`mqtt/SKILL.md`](./mqtt/SKILL.md). |
| `f ssh` | ssh/scp/rsync with a private key from the creds store; loads it into ssh-agent so it never hits disk. See [`ssh/SKILL.md`](./ssh/SKILL.md). |
| `f ddg` | Search DuckDuckGo from the CLI (web + image results, `--json`), zero deps, via the no-JS html/lite endpoints. See [`ddg/SKILL.md`](./ddg/SKILL.md). |

## Adding a uck

```
myuck/
  index.js
```

```js
// myuck/index.js
export function register(_ctx) {
  return {
    name: "myuck",
    desc: "what it does (terse)",
    run: (_argv, args) => {
      console.log("hello", args._.join(" "));
    },
  };
}
export default { register };
```

Then `git push` and `f up` (or it loads on next run).
