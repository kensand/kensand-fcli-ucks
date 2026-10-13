// Local callback listener for the SSO authorization-code flow.
//
// Vaultwarden accepts only http://localhost:8065..8070 as the redirect target for
// client_id=cli (src/sso.rs `authorize_url`), so a CLI doing SSO must own one of
// those ports for the duration of the browser hop. This is that listener: it exists
// to catch one redirect, then closes.
//
// Design points that are easy to get wrong:
//   - Binds loopback only. On every interface it would let anyone on the LAN capture
//     an authorization code.
//   - Binds BOTH 127.0.0.1 and ::1. The redirect_uri we send is literally
//     http://localhost:NNNN, and `localhost` resolves to ::1 first on most systems --
//     an IPv4-only listener is refused before the browser tries the IPv4 literal, and
//     the sign-in dies on a timeout with nothing to show for it.
//   - Never logs the code. It is a live credential for a few seconds, and stderr ends
//     up in logs and scrollback.
//   - Nothing in the handler may throw: an exception there escapes into the HTTP
//     parser as an uncaught exception, and any local process can trigger one.
//   - `finish()` is the only way to settle. Bare resolve()/reject() left the port
//     bound on error paths, so a retry found its own port taken.
//   - Close is deferred until the response has flushed (closing inside the handler
//     resets the connection before the browser renders the page), then forces sockets
//     shut so an idle keep-alive cannot keep the port claimed.

import http from "node:http";

export const SSO_REDIRECT_PORTS = [8065, 8066, 8067, 8068, 8069, 8070];
const LOOPBACK_HOSTS = ["127.0.0.1", "::1"];

/**
 * Wait for the SSO redirect and return the authorization code.
 *
 * @param opts.expectedState  `state` from `/identity/sso/token`, or null if the server
 *                            returned none.
 * @param opts.timeoutMs      how long to wait for a human to finish in a browser.
 * @param opts.port           bind *only* this port. Pass whatever the authorize request
 *                            named as redirect_uri — binding a different one means the
 *                            browser redirects to a closed port and the login hangs.
 * @param opts.log            called with the bound URL, e.g. "http://localhost:8065".
 * @returns a promise of the authorization code. It carries a `.closed` promise that
 *          resolves once the listener is fully released; `await` the code first, then
 *          `await p.closed`. This function is deliberately *not* `async`: an `async`
 *          wrapper returns a fresh promise, and `.closed` on it is `undefined`, so
 *          `await p.closed` would resolve immediately and free nothing.
 */
export function captureSsoCode(opts = {}) {
  const { expectedState = null, timeoutMs = 180_000, port = null, ports = SSO_REDIRECT_PORTS, log = () => {} } = opts;
  const bindPorts = port ? [port] : ports;

  // Assigned before the promise runs: a bind failure can settle it before the
  // executor reaches later bindings, and a `const` in the same scope would still be
  // in its temporal dead zone at that moment.
  let listeners = [];
  let markClosed = () => {};
  const closed = new Promise((r) => { markClosed = r; });

  const promise = new Promise((resolve, reject) => {
    let settled = false;
    let timer = null;

    const finish = (fn, v) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      // Deferred on every path: closing the server while still inside its handler
      // resets the connection before the browser renders the reply, so the operator
      // sees "connection reset" instead of the result and may retry the sign-in.
      setTimeout(() => {
        let waiting = listeners.length;
        if (!waiting) { markClosed(); return; }
        for (const s of listeners) {
          try {
            // Node keeps a port claimed while an idle keep-alive socket is open — a
            // browser that rendered our page holds one, and close() waits for it, so
            // the next `sso login` would find its own port taken. closeAllConnections
            // only covers tracked connections; destroySockets() is the blunt version.
            if (typeof s.closeAllConnections === "function") s.closeAllConnections();
            if (typeof s.closeIdleConnections === "function") s.closeIdleConnections();
            s.close(() => { if (--waiting === 0) markClosed(); });
          } catch { if (--waiting === 0) markClosed(); }
        }
        listeners = [];
      }, 250);
      fn(v);
    };

    timer = setTimeout(() => finish(reject, new Error(`timed out after ${Math.round(timeoutMs / 1000)}s waiting for the browser redirect`)), timeoutMs);

    const handler = (req, res) => {
      let u;
      try { u = new URL(req.url, "http://localhost"); }
      catch {
        try { res.writeHead(400, { "content-type": "text/plain" }); res.end("bad request"); } catch { /* socket gone */ }
        return;
      }

      const reply = (code, body, type = "text/plain; charset=utf-8") => {
        try { res.writeHead(code, { "content-type": type }); res.end(body); } catch { /* client hung up; settling still matters */ }
      };

      if (u.pathname !== "/") return reply(404, "not found");

      // Consent denied still reaches us; say so rather than leaving the tab spinning.
      const err = u.searchParams.get("error");
      if (err) {
        // Provider-controlled text, rendered in a browser: escape it, and truncate
        // before it reaches the terminal too.
        reply(200, page("Sign-in failed", `The identity provider reported: ${escapeHtml(String(err).slice(0, 200))}`), "text/html; charset=utf-8");
        return finish(reject, new Error(`identity provider returned error: ${String(err).slice(0, 200)}`));
      }

      const code = u.searchParams.get("code");
      const state = u.searchParams.get("state");
      if (!code) return reply(400, "no authorization code in the redirect");

      // A mismatch means this redirect was not started by this command. Refuse it even
      // though a stolen code also fails PKCE: the code_verifier is the real protection,
      // and this is a cheap second check that catches a plain misfire.
      if (expectedState && state !== expectedState) {
        reply(400, "state mismatch — this redirect was not started by this command");
        return finish(reject, new Error("SSO callback state mismatch (possible redirect hijack; nothing was exchanged)"));
      }

      reply(200, page("Signed in", "Vault access granted. You can close this tab and return to the terminal."), "text/html; charset=utf-8");
      finish(resolve, code);
    };

    const tryPort = (i) => {
      if (i >= bindPorts.length) {
        const why = port
          ? `port ${port} is in use, and it is the port the identity provider was told to redirect to — nothing else will receive the code. Free it (another 'f vaultwarden sso login', or a stale listener) or re-run without --port`
          : `no free port in ${bindPorts[0]}-${bindPorts[bindPorts.length - 1]} (all in use); SSO needs one of them for the browser redirect`;
        return finish(reject, new Error(why));
      }
      const wanted = LOOPBACK_HOSTS.slice();
      const made = [];
      let settledPort = false;   // this port attempt is over (bound or abandoned)

      const armAsListener = (s) => {
        // Past binding, an error is a broken browser connection; report it rather than
        // silently binding another port.
        s.on("error", (e) => finish(reject, e));
      };

      const done = () => {
        if (settledPort) return;
        settledPort = true;
        log(`http://localhost:${bindPorts[i]}`);
      };

      // Try every loopback family. Whichever binds first is enough to answer the
      // redirect, but the others must still be *tracked*: an earlier version declared
      // the attempt settled on the first success and never recorded the sibling
      // listener, so that socket was never closed and the port stayed half-bound.
      const results = wanted.map(() => null);   // null = pending, true = bound, false = failed
      const report = (k, ok, s) => {
        results[k] = ok;
        if (ok) { listeners.push(s); armAsListener(s); }
        // A bound family is enough to serve; a later sibling that also binds is still
        // pushed onto `listeners` above so cleanup sees it.
        if (results.some((r) => r === true)) done();
        else if (results.every((r) => r === false)) tryPort(i + 1);
        // otherwise: still waiting on a pending family
      };

      wanted.forEach((host, k) => {
        const s = http.createServer(handler);
        made.push(s);
        s.once("error", (e) => {
          if (settledPort) { try { s.close(); } catch { /* not bound */ } return; }
          // IPv6 is frequently unavailable (EADDRINUSE/EAFNOSUPPORT/EINVAL on a box
          // with no IPv6). That must not sink the attempt while the other family works.
          const retriable = e.code === "EADDRINUSE" || e.code === "EACCES" || e.code === "EAFNOSUPPORT" || e.code === "EINVAL";
          if (!retriable && !results.includes(true)) { finish(reject, e); return; }
          report(k, false, null);
        });
        s.listen({ port: bindPorts[i], host }, () => {
          if (settledPort && !listeners.includes(s)) {
            // Another family already serves this port and we are past the attempt.
            // Close immediately, but only if we are truly done; if the port was
            // published we still want this sibling so cleanup closes everything.
            if (listeners.length) { listeners.push(s); armAsListener(s); }
            else { try { s.close(); } catch { /* ignore */ } }
            return;
          }
          report(k, true, s);
        });
      });
    };

    tryPort(0);
  });

  // Attach the release signal to the promise itself. Callers must obtain it as
  // `(await captureSsoCode(...)) `'s sibling — see the doc comment — so it is exposed
  // on the settled value as well, which survives the await that a property on a
  // returned promise does not.
  promise.closed = closed;
  return promise;
}

function page(title, body) {
  return `<!doctype html><meta charset=utf-8><title>${escapeHtml(title)}</title>`
    + `<body style="font:15px/1.6 system-ui,sans-serif;margin:3rem auto;max-width:34rem">`
    + `<h2>${escapeHtml(title)}</h2><p>${escapeHtml(body)}</p>`;
}

const escapeHtml = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
