# kensand-fcli-ucks

Personal ucks for f. Each uck is a `<name>/index.js` module (plus any
supporting files). This repo is a source in `~/.f/f.config.json`; f installs
every uck dir here into `~/.f/ucks/kensand-fcli-ucks/<name>/`.

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
