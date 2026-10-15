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
| `f ha` | Home Assistant (states, service calls, scenes, calendars) |

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
