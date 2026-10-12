---
name: f-ssh
description: Manage ssh hosts, config and authorized_keys via `f ssh` instead of hand-editing ~/.ssh. Carries config between machines through `f creds files`; refuses to pack private keys.
---

# f ssh — ssh hosts, config, authorized_keys

Terse ssh management. One fact per line. Reimplements neither git nor the creds store: `f ssh pack|unpack|status` is a thin, validating wrapper over `f creds files`, where the key IS the destination (`file:~/.ssh/config`) so one entry resolves on every host.

## Commands

```
f ssh ls                        hosts (alias, host, user, port, key, jump)
f ssh show <host>               config block + effective `ssh -G` values
f ssh check [host] [--connect]  resolve, then probe publickey auth
f ssh run <host> [cmd...]       non-interactive ssh; prompts can never hang
f ssh keys                      local public keys + fingerprints
f ssh agents                    ssh-agent state and held keys
f ssh authorized [ls|add|rm]    this machine's authorized_keys
f ssh pack [config|authorized-keys]
f ssh unpack [config|authorized-keys] [--force]
f ssh status                    local vs packed
f ssh keys pack --i-know-what-im-doing
```

`pack`/`unpack`/`status` need the creds daemon: `f creds unlock`.

## Why private keys are not packed

`f ssh keys pack` refuses unless you pass `--i-know-what-im-doing`. A private key is a bearer credential — packing it puts **every host reachable with it** behind one store passkey, and packing is also how a key lands on a machine you didn't choose. Prefer per-machine `IdentityFile` paths or an agent. The opt-in exists because the tradeoff is sometimes right; it is never the default.

## authorized_keys safety

Termux cannot run sshd, so on-device this manages a file for the machines you unpack it onto. The guards matter there:

- `rm` matches the **comment, exactly**. `f ssh authorized rm ed25519` matches nothing, because matching key material is how you revoke the wrong key. Use `--substr` deliberately.
- Ambiguous matches list the keys and stop; `--force` is required to remove several.
- Removing **every** authorized key is refused, and `--force` does **not** override it. `--force` means "I meant those matches", not "lock me out". Edit the file by hand if that is genuinely intended.
- Successful writes back up to `authorized_keys.bak` and force mode `600`.
- `add` dedupes on key material, not comment, and validates structure + base64 round-trip, so a truncated key fails here instead of at login.
- Empty files are never packed: a blank `authorized_keys` is the absence of one, and packing it would overwrite a populated file elsewhere with nothing.

## Non-interactive by construction

`check --connect` and `run` force `BatchMode=yes`, disable password/keyboard-interactive, and set `NumberOfPasswordPrompts=0`. The classic scripted-ssh failure is hanging silently on a prompt; these make it report instead. Tune with `SSH_CONNECT_TIMEOUT` (default 8s).

Note `ssh -G` reads the invoking **user's** real `~/.ssh/config`, resolved from the passwd entry rather than `$HOME`.

## Not covered

No keygen/ssh-copy-id/revocation, no ProxyJump orchestration, no jump-host scripting. `f ssh run` passes your command through unchanged.
