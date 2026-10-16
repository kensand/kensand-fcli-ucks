---
name: f-ssh
description: Run ssh/scp/rsync with a private key that lives in the `f creds` store (default cred `ssh`) instead of ~/.ssh. Loads it into ssh-agent over stdin so no key material touches disk. Also installs a stable IdentityFile so plain ssh/git-over-ssh work unwrapped.
---

# f ssh — the key lives in the creds store, not on disk

The private key is a credential, so it is stored like one (`f creds`, or the vault
behind it). The usual alternative — "write it to a temp file, chmod 600, delete it
afterwards" — leaves a live copy of the key on disk on every single use. This uck
pipes the stored value into `ssh-add` on **stdin** instead, so the key ends up only
in the agent's memory.

> `ssh-add -` really does accept a key on stdin (`Identity added: (stdin) …`). It
> cannot *prompt* for a passphrase that way, so a passphrase-protected key has to be
> stored unencrypted (or unlocked interactively once).

## The two ways to use it

**1. Set it up once, then use ssh normally (recommended).**

```
f ssh setup        # writes IdentityFile ~/.ssh/f-ssh/id_ed25519 into ~/.ssh/config
ssh host           # works, and so does scp, rsync, git clone ssh://… , vscode, rsync
f ssh teardown     # remove the include again
```

`setup` materialises the key from the store into that one path and points
`~/.ssh/config` at it. Nothing wraps your commands, and every program that speaks
ssh picks the key up. Cost: the key *is* on disk at that path (mode 0600, under a
0700 dir), which is the trade for convenience.

**2. Per-command, nothing on disk.**

```
f ssh host                      # ssh with the key injected via ssh-agent
f ssh host -- uptime -h          # command args go after --
f ssh scp a.h:/etc/hostname b.h:/tmp/
f ssh rsync -av src/ host:/dst/
f ssh --no-agent host -- true    # never touch the agent: temp 0600 keyfile, removed on exit
```

`f ssh setup` also gives you the agent without the config file:

```
eval "$(f ssh env)"              # exports SSH_AUTH_SOCK for your shell
f ssh agent git push             # one command with the agent wired up
f ssh load                       # put the key in the agent, leave it there
f ssh list                       # ssh-add -l
```

## Where the key comes from

First hit wins; `--cred <name>` / `--cred=<name>` pins a name but does **not**
filter — the defaults below are still tried behind it, so a stale pinned name
cannot lock you out of every host:

1. `--cred` / `F_SSH_CRED`
2. `ssh.cred` in `f.config.json` (`f config` … or edit the file)
3. `ssh.key.<host>` — per-host key, host taken from the destination
4. `file:~/.ssh/f-ssh/id_ed25519` — a packed file (`f creds files pack <path>`)
5. `ssh.key`, `ssh`, `id_ed25519`

Store one:

```
cat ~/.ssh/id_ed25519 | f creds set ssh      # via stdin: the key never sits in argv
f creds files pack ~/.ssh/id_ed25519         # or as a packed file entry
```

A name containing `::` (e.g. `ssh::password`) is provider vocabulary and is
resolved through the credential-provider ladder.

## Rules this uck follows

- **Never prints the key.** `f ssh add` refuses without `F_SSH_SHOW_SECRET=1`, and is
  only there for migration — the agent path never needs the key printed.
- **Secrets never go in argv** (readable from `ps` by any process): reads come from
  the daemon socket or stdin.
- **The store is read over its unix socket, not via a nested `f`.** ~1ms per name.
  A nested `f creds get` re-installs every local uck source at startup (~0.7s alone,
  and far worse as a child of another `f`), so doing that per candidate name is what
  made early versions of this take a minute. `f`-spawning is reserved for names that
  genuinely need it (`file:` entries, `::field`).
- **A creds read never goes through `f creds get` without `F_CREDS_NO_PROVIDER=1`** —
  that flag is how the vaultwarden provider avoids recursing back into `f creds`.
- **Flags are separated by `--`.** `f ssh`'s own flags (`--cred`, `--no-agent`) come
  first; anything for ssh/scp/rsync goes after `--`. Leading flags are rejected with
  a hint instead of being misread as a subcommand.
- **rsync takes ssh options via `-e`, not `-o`**: `f ssh rsync -a -e 'ssh -o
  StrictHostKeyChecking=accept-new' src host:/dst`. Passing bare `-o …` makes rsync
  treat the option as a *filename* (`link_stat "...BatchMode=yes" failed`); only `-e`
  reaches ssh. Our identity rides in a generated `-F` config, so your own `-e` and it
  compose instead of fighting.
- **`scp` needs `-F`, not `-o`**: scp does not forward general ssh options to ssh, so
  `scp -o IdentitiesOnly=yes` errors with `keyword identitiesonly not supported above`
  *before* the config is read — and the whole IdentityFile gets dropped, so scp falls
  back to the default keys and fails authentication while looking like it ran. The
  injected config is therefore passed as `-F` (which includes your `~/.ssh/config`).
- **`BatchMode=yes` + `IdentitiesOnly=yes` on the injected path**: the key we were
  asked to use either works or you get a clear failure, with no silent fallback to
  some other identity. `assertIdentityUsable()` proves the identity loads before the
  real command runs.

## Gotchas worth knowing

- **A PEM needs its trailing newline.** `printf '%s' "$KEY" | ssh-add -` fails with
  `invalid format` on OpenSSH 10.6. The creds daemon trims stored values, so the uck
  re-adds it (`normalizePem`). Hand-copying a key out of the store will bite you here.
- **The creds daemon answers one JSON line with NO trailing newline**, then closes.
  Read until end-of-stream, not until `\n`, or every lookup burns your whole timeout.
- **The current published `f` gives ucks `ctx = { fVersion, ucks, self }` — no
  `registry`.** So `ctx.registry.creds.credsApi` is always null, which is why
  `f ha`/`f fj` quietly miss their creds. This uck talks to the daemon socket
  directly and does not depend on that handoff.
- **`f ssh setup` writes plaintext key material** to `~/.ssh/f-ssh/id_ed25519`. If you
  do not want that, use `f ssh load` / `f ssh agent` / the wrapper instead.
- **`f up` resets buckets to their remote**, so unpushed uck edits here are lost.

## Commands

| command | what it does |
|---|---|
| `f ssh status` | creds state, key source + type, keyfile, ssh-config include, agent + identities |
| `f ssh setup` / `teardown` | install / remove the `IdentityFile` include in `~/.ssh/config` |
| `f ssh load [dest]` | load the key into the long-lived agent (`dest` picks `ssh.key.<host>`) |
| `f ssh list` | identities in the agent |
| `f ssh env` | `export SSH_AUTH_SOCK=…` for `eval "$(...)"` |
| `f ssh agent <cmd…>` | run one command with the agent in its env |
| `f ssh <host> [args]` | ssh with the identity injected |
| `f ssh scp\|rsync\|sftp <args>` | same, for those tools |
| `f ssh add` | print the PEM (needs `F_SSH_SHOW_SECRET=1`; migration only) |

Agent socket: `~/.ssh/f-ssh/agent.sock` (override: `F_SSH_AGENT_SOCKET`). Tool
overrides for tests: `F_SSH_SSH`, `F_SSH_SCP`, `F_SSH_RSYNC`.
