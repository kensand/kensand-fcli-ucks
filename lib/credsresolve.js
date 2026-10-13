// Shared credential resolution for f ucks that authenticate (f fj, f gh, f ha, …).
//
// Why this exists: every uck that needs a token had rolled its own creds lookup
// as "a one-shot socket read, and never block". That deliberately fast path is
// also blind — it could not see the provider layer that `f creds get` now runs
// on a local miss, so a host whose credential lives only in Vaultwarden looked
// identical to "not configured". This helper gives one code path with provenance
// and an explicit reason, so callers can report what actually happened.
//
// Contract:
//   resolveCred({ names, flagToken, envVars, credsApi, waitMs, localOnly })
//     -> { token, src }                          success
//     -> { token: null, reason, host?, detail? } failure, with a reason that
//                                                 names the fix
//
// reasons:
//   no-names    nothing to look up (bad/absent base URL)
//   locked      creds store is locked            -> `f creds unlock`
//   unset       unlocked, no local value, no provider hit -> `f creds set <name> <value>` or add the item to the vault
//   wait-timeout --wait elapsed without a value
//   provider    a provider was reachable but errored (vault locked, dns, 2FA) —
//               `detail` carries its message; do NOT report this as "unset"
//
// It never blocks unless waitMs is given, and it never prints.

import fs from "node:fs";
import net from "node:net";
import path from "node:path";

const F = path.join(process.env.HOME ?? "", ".f");

/** Unlocked-and-has-time-left state, from the lockfile (never blocks). */
export function credsUnlocked() {
  let lf;
  try {
    lf = JSON.parse(fs.readFileSync(path.join(F, ".creds-daemon"), "utf8"));
  } catch {
    return null;
  }
  if (!lf?.pid || !lf?.start || !lf?.ttl) return null;
  try {
    process.kill(lf.pid, 0); // liveness only
  } catch {
    return null;
  }
  const remainingMs = lf.start + lf.ttl * 1000 - Date.now();
  return remainingMs > 0 ? { remainingMs, socket: lf.socket } : null;
}

/** Raw daemon read over the socket — used when the creds uck is unavailable. */
function rawSocketGet(name, socketPath) {
  return new Promise((resolve) => {
    const client = net.connect(socketPath ?? path.join(F, ".creds.sock"), () => {
      client.write(JSON.stringify({ op: "get", name }));
    });
    let buf = "";
    client.on("data", (c) => (buf += c));
    client.on("end", () => {
      try {
        const r = JSON.parse(buf);
        resolve(r.ok ? (r.value ?? null) : null);
      } catch {
        resolve(null);
      }
    });
    client.on("error", () => resolve(null));
  });
}

/**
 * Look a credential up by each candidate name, in order.
 *
 * Prefers the creds uck's own API (which runs the provider ladder and mirrors
 * hits); falls back to a direct socket read, which sees only local values — in
 * that case `src` is marked "(local only)" so a miss is not mistaken for "the
 * vault has nothing".
 */
export async function resolveCred({ names, flagToken, envVars = {}, credsApi, waitMs = 0, localOnly = false, timeoutMs = 20000 }) {
  if (typeof flagToken === "string" && flagToken) return { token: flagToken, src: "--token" };
  for (const [env, val] of Object.entries(envVars)) {
    if (val) return { token: val, src: env };
  }
  const list = (Array.isArray(names) ? names : [names]).filter(Boolean);
  if (!list.length) return { token: null, src: null, reason: "no-names" };

  const state = credsUnlocked();
  if (!state) {
    if (waitMs && credsApi && typeof credsApi.wait === "function") {
      try {
        for (const name of list) {
          const v = await credsApi.wait(name, { timeout: waitMs });
          if (v != null && v !== "") return { token: v, src: `creds:${name} (waited)` };
        }
      } catch {
        return { token: null, src: null, reason: "wait-timeout", host: list[0] };
      }
      return { token: null, src: null, reason: "wait-timeout", host: list[0] };
    }
    return { token: null, src: null, reason: "locked", host: list[0] };
  }

  // Fast path: the creds uck, which knows about providers.
  if (!localOnly && credsApi && typeof credsApi.resolve === "function") {
    let providerError = null;
    for (const name of list) {
      try {
        const r = await withTimeout(credsApi.resolve(name), timeoutMs, `creds lookup '${name}'`);
        if (r?.value != null && r.value !== "") return { token: r.value, src: r.source ?? `creds:${name}`, warning: r.warning };
      } catch (e) {
        const msg = e?.message ?? String(e);
        // Distinguish "a provider choked" from "nothing has this name", so the
        // caller cannot tell the user to set a cred that does exist in the vault.
        if (/provider .* failed/.test(msg)) providerError = { host: name, detail: msg };
        /* try the next candidate name */
      }
    }
    if (providerError) return { token: null, src: null, reason: "provider", ...providerError };
    // credsApi.resolve throws on a plain miss; reach the value only above.
    return { token: null, src: null, reason: "unset", host: list[0] };
  }

  // Fallback: local-only socket read.
  for (const name of list) {
    const v = await rawSocketGet(name, state.socket);
    if (v != null && v !== "") return { token: v, src: `creds:${name} (local only)`, localOnly: true };
  }
  return { token: null, src: null, reason: "unset", host: list[0], localOnly: true };
}

function withTimeout(promise, ms, what) {
  let timer;
  return Promise.race([
    Promise.resolve(promise).finally(() => clearTimeout(timer)),
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`${what} timed out after ${ms}ms`)), ms);
    }),
  ]);
}

/** Strip protocol + path from a base URL, keeping any port. */
export function hostFromUrl(url) {
  if (!url) return null;
  try {
    return new URL(url).host || null;
  } catch {
    return String(url).replace(/^[a-z]+:\/\//, "").split("/")[0] || null;
  }
}

/** Candidate cred names for a base URL: host:port first, then bare host. */
export function credNamesFor(base) {
  const host = hostFromUrl(base);
  if (!host) return [];
  return host.includes(":") ? [host, host.split(":")[0]] : [host];
}

/** One-line remediation text for a failure, phrased per reason. */
export function credHint(res, { credName, envName } = {}) {
  const name = credName ?? res.host ?? "<name>";
  switch (res.reason) {
    case "locked":
      return `creds are locked — unlock them: f creds unlock`;
    case "unset":
      return res.localOnly
        ? `no cred named '${name}' (checked the local store only — a provider lookup was not possible from this uck)`
        : `no cred named '${name}' — store it: f creds set ${name} <token>\n` +
          `  or serve it from the vault: f vaultwarden list --search ${name} (see 'f vaultwarden map' if the item exists under another name)`;
    case "provider":
      return `a credential provider was reachable but failed for '${name}':\n  ${res.detail}\n  fix that first — the value may exist in the vault already`;
    case "wait-timeout":
      return `timed out waiting for '${name}' — set it in another terminal: f creds fill ${name}`;
    case "no-names":
      return "nothing to look up — no base URL/hostname was resolved";
    default:
      return `credential '${name}' unavailable (${res.reason})`;
  }
}

export default { resolveCred, credsUnlocked, hostFromUrl, credNamesFor, credHint };
