// f ha-ws — Home Assistant WebSocket API bridge.
//
// WHY THIS EXISTS
//   HA's REST API (/api/...) has no automation CRUD. The generic config view
//   registers ONLY `/api/config/<component>/<config_type>/{config_key}`
//   (homeassistant/components/config/view.py) — there is no collection route,
//   so `GET/POST /api/config/automation/config` is a 404 and you cannot
//   CREATE an automation over REST. Creating/updating lives on the WebSocket
//   API, which is what the HA frontend itself uses.
//
// TOKEN
//   Reuses f's own creds resolution (ctx.registry.creds.credsApi), the same
//   path `f ha` uses. credsApi.get() returns the REAL token, so no secret
//   needs to appear in argv, on disk, in shell history, or in logs.
//
// Usage:
//   f ha-ws whoami
//   f ha-ws list                            automations (id + alias)
//   f ha-ws get <automation_id>
//   f ha-ws put <automation_id> '<yaml-or-json-config>'
//   f ha-ws del <automation_id>
//   f ha-ws raw '<message-json>'            arbitrary command minus "id"
//   f ha-ws call <domain>.<service> '<json>'  via ws, returns response_data
//   --url <base> --token <tok>              overrides, same as f ha

import path from "node:path";
import { fileURLToPath as _f2p } from "node:url";

const _here = path.dirname(_f2p(import.meta.url));

const DEFAULT_BASE = "https://ha.kensand.net";

function parseBase(raw) {
  if (!raw) return null;
  let u = String(raw).replace(/\/+$/, "");
  if (!/^https?:\/\//.test(u)) u = "https://" + u;
  return u;
}

function wsUrl(base) {
  const u = new URL(base);
  return (u.protocol === "http:" ? "ws://" : "wss://") + u.host + "/api/websocket";
}

/** Read a line-delimited JSON frame stream until we get the reply for `id`. */
async function recvFor(ws, id) {
  for (;;) {
    const frame = JSON.parse(await ws.recv());
    if (frame.id === id) return frame;
    // ignore async events (state_changed / service_called / ...)
  }
}

/** Minimal RFC6455 client over node:https / node:http. Zero deps. */
function connect(url) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const mod = u.protocol === "wss:" ? require0("node:https") : require0("node:http");
    const crypto = require0("node:crypto");
    const key = crypto.randomBytes(16).toString("base64");

    const req = mod.request(
      {
        hostname: u.hostname,
        port: u.port || (u.protocol === "wss:" ? 443 : 80),
        path: u.pathname + (u.search || ""),
        method: "GET",
        headers: {
          Connection: "Upgrade",
          Upgrade: "websocket",
          "Sec-WebSocket-Key": key,
          "Sec-WebSocket-Version": "13",
          Host: u.host,
        },
      },
      (res) => {
        if (res.statusCode !== 101) {
          reject(new Error(`upgrade failed: HTTP ${res.statusCode}`));
          return;
        }
        const sock = res.socket;
        sock.setNoDelay(true);
        resolve(makeSocket(sock));
      }
    );
    req.on("error", reject);
    req.setTimeout(25000, () => req.destroy(new Error("ws connect timeout")));
    req.end();
  });
}

// node:crypto etc. — this file is ESM, so use dynamic import synchronously
// via createRequire. Populated by initRequire().
let _require = null;
function require0(name) {
  if (!_require) throw new Error("require not initialised");
  return _require(name);
}
async function initRequire() {
  if (_require) return;
  const { createRequire } = await import("node:module");
  _require = createRequire(import.meta.url);
}

/** Wrap a raw TLS/plain socket in the handful of WS ops we need. */
function makeSocket(sock) {
  let buf = Buffer.alloc(0);
  const waiters = [];

  sock.on("data", (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    drain();
  });
  sock.on("error", (e) => {
    for (const w of waiters) w.reject(e);
    waiters.length = 0;
  });

  function drain() {
    for (;;) {
      if (buf.length < 2) return;
      const fin = (buf[0] & 0x80) !== 0;
      const opcode = buf[0] & 0x0f;
      let masked = (buf[1] & 0x80) !== 0;
      let len = buf[1] & 0x7f;
      let off = 2;
      if (len === 126) {
        if (buf.length < off + 2) return;
        len = buf.readUInt16BE(off);
        off += 2;
      } else if (len === 127) {
        if (buf.length < off + 8) return;
        len = Number(buf.readBigUInt64BE(off));
        off += 8;
      }
      let maskKey = null;
      if (masked) {
        if (buf.length < off + 4) return;
        maskKey = buf.subarray(off, off + 4);
        off += 4;
      }
      if (buf.length < off + len) return;
      let payload = buf.subarray(off, off + len);
      if (masked) {
        const out = Buffer.allocUnsafe(len);
        for (let i = 0; i < len; i++) out[i] = payload[i] ^ maskKey[i & 3];
        payload = out;
      }
      buf = buf.subarray(off + len);
      // server frames are unmasked; fin matters only for fragmentation
      const w = waiters.shift();
      if (fin && opcode === 0x1) w && w.resolve(payload.toString("utf8"));
      else if (opcode === 0x8) {
        sock.destroy();
        w && w.reject(new Error("server closed websocket"));
      } else if (opcode === 0x9) {
        sendRaw(0xa, payload); // pong
        waiters.unshift(w);
      } else {
        w && w.resolve(payload.toString("utf8"));
      }
    }
  }

  function sendRaw(opcode, payload) {
    const mask = require0("node:crypto").randomBytes(4);
    const len = payload.length;
    let header;
    if (len < 126) {
      header = Buffer.alloc(2);
      header[1] = 0x80 | len;
    } else if (len < 65536) {
      header = Buffer.alloc(4);
      header[1] = 0x80 | 126;
      header.writeUInt16BE(len, 2);
    } else {
      header = Buffer.alloc(10);
      header[1] = 0x80 | 127;
      header.writeBigUInt64BE(BigInt(len), 2);
    }
    header[0] = 0x80 | opcode;
    const masked = Buffer.allocUnsafe(len);
    for (let i = 0; i < len; i++) masked[i] = payload[i] ^ mask[i & 3];
    sock.write(Buffer.concat([header, mask, masked]));
  }

  return {
    send(text) {
      sendRaw(0x1, Buffer.from(text, "utf8"));
    },
    recv() {
      return new Promise((resolve, reject) => waiters.push({ resolve, reject }));
    },
    close() {
      try {
        sendRaw(0x8, Buffer.alloc(0));
      } catch {
        /* ignore */
      }
      sock.destroy();
    },
  };
}

async function withHa(flagUrl, flagToken, credsApi, fn) {
  const base =
    parseBase(flagUrl) || parseBase(process.env.HA_URL) || parseBase(process.env.HA_BASE) || parseBase(DEFAULT_BASE);
  let token = flagToken || process.env.HA_TOKEN || null;
  if (!token && credsApi && typeof credsApi.get === "function") {
    let host = null;
    try {
      host = new URL(base).host;
    } catch {
      host = String(base).replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    }
    const names = [];
    if (host) {
      names.push(host.includes(":") ? host : host, host.split(":")[0]);
    }
    for (const n of [...names.filter(Boolean), undefined]) {
      for (const suffix of ["-token", ""]) {
        const name = n ? `${n}${suffix}` : null;
        if (!name) continue;
        try {
          const v = await credsApi.get(name);
          if (typeof v === "string" && v.trim()) {
            token = v.trim();
            break;
          }
        } catch {
          /* keep looking */
        }
      }
      if (token) break;
    }
    if (!token) {
      try {
        const combined = await credsApi.get("ha");
        if (typeof combined === "string" && combined.includes("|")) token = combined.split("|").slice(1).join("|").trim();
      } catch {
        /* fallthrough */
      }
    }
  }
  if (!token) throw new Error("no HA token: set ha-token cred, HA_TOKEN, or --token");

  const ws = await connect(wsUrl(base));
  try {
    const hello = JSON.parse(await ws.recv());
    if (hello.type !== "auth_required") throw new Error(`unexpected first frame: ${hello.type}`);
    ws.send(JSON.stringify({ type: "auth", access_token: token }));
    const auth = JSON.parse(await ws.recv());
    if (auth.type !== "auth_ok") throw new Error(`auth failed: ${JSON.stringify(auth)}`);
    let id = 0;
    const call = async (type, extra = {}) => {
      const mid = ++id;
      ws.send(JSON.stringify({ id: mid, type, ...extra }));
      return recvFor(ws, mid);
    };
    return await fn(call, base);
  } finally {
    ws.close();
  }
}

function usage() {
  return (
    "f ha-ws: usage: f ha-ws <cmd>\n" +
    "  whoami                        who the token is (admin/owner?)\n" +
    "  list                          list automations (id + alias)\n" +
    "  get <id>                      one automation's config\n" +
    "  put <id> <json>               create/update automation config\n" +
    "  del <id>                      delete automation\n" +
    "  raw <json>                    arbitrary ws message (no id)\n" +
    "  call <domain>.<service> <json>  call action, print response_data\n" +
    "  --url <base> --token <tok>      overrides"
  );
}

export function register(_ctx) {
  return {
    name: "ha-ws",
    desc: "Home Assistant WebSocket API: automation/config CRUD that REST lacks (create/update/delete automations, config validation, fire events)",
    run: async (_argv, args, ctx) => {
      await initRequire();
      const _ = args._ ?? [];
      let flagUrl = null;
      let flagToken = null;
      const pos = [];
      for (let i = 0; i < _.length; i++) {
        if (_[i] === "--url") { flagUrl = _[++i]; continue; }
        if (_[i] === "--token") { flagToken = _[++i]; continue; }
        pos.push(_[i]);
      }
      const credsApi = (ctx && ctx.registry && ctx.registry.creds && ctx.registry.creds.credsApi) || null;
      const [cmd, ...rest] = pos;
      if (!cmd) return usage();

      try {
        return await withHa(flagUrl, flagToken, credsApi, async (call) => {
          if (cmd === "whoami") {
            const r = await call("auth/current_user");
            const u = r.result || {};
            return `user=${u.name} id=${u.id} is_admin=${u.is_admin} is_owner=${u.is_owner}`;
          }

          if (cmd === "list") {
            // No config/automation/list command exists in HA. Enumerate via the
            // state machine: UI automations carry a numeric-ish `.storage` id.
            const r = await call("config/automation/list");
            if (r.success) {
              const items = r.result?.automations ?? r.result ?? [];
              return items.map((a) => `  ${a.id}  ${a.alias ?? ""}`).join("\n") || "no automations";
            }
            // fallback: entity registry ids from states
            const st = await call("get_states");
            const autos = (st.result || []).filter((s) => s.entity_id.startsWith("automation."));
            return (
              `${autos.length} automations (via states; config/automation/list unsupported:\n` +
              `  ${r.error?.message || "?"})\n` +
              autos.map((s) => `  ${s.attributes?.id ?? "?"}  ${s.entity_id}  ${s.state}`).join("\n")
            );
          }

          if (cmd === "get") {
            const id = rest[0];
            if (!id) return "get requires an automation id";
            const r = await call("config/automation/get", { automation_id: id });
            return r.success ? JSON.stringify(r.result, null, 2) : JSON.stringify(r.error, null, 2);
          }

          if (cmd === "put") {
            const id = rest[0];
            const body = rest.slice(1).join(" ");
            if (!id) return "put requires an automation id";
            let cfg;
            try {
              cfg = JSON.parse(body);
            } catch (e) {
              return `config must be JSON: ${e.message}`;
            }
            const r = await call("config/automation/create_update", { automation_id: id, ...cfg });
            return r.success ? `saved ${id}` : JSON.stringify(r.error, null, 2);
          }

          if (cmd === "del") {
            const id = rest[0];
            if (!id) return "del requires an automation id";
            const r = await call("config/automation/delete", { automation_id: id });
            return r.success ? `deleted ${id}` : JSON.stringify(r.error, null, 2);
          }

          if (cmd === "call") {
            const svc = rest[0];
            const body = rest.slice(1).join(" ") || "{}";
            if (!svc || !svc.includes(".")) return "call requires <domain>.<service>";
            const [domain, service] = svc.split(".", 2);
            let data;
            try {
              data = JSON.parse(body);
            } catch (e) {
              return `data must be JSON: ${e.message}`;
            }
            const r = await call("call_service", { domain, service, ...data });
            return r.success ? `ok ${domain}.${service}\n${JSON.stringify(r.result ?? {}, null, 2)}` : JSON.stringify(r.error, null, 2);
          }

          if (cmd === "raw") {
            let msg;
            try {
              msg = JSON.parse(rest.join(" "));
            } catch (e) {
              return `json required: ${e.message}`;
            }
            const t = msg.type;
            delete msg.type;
            const r = await call(t, msg);
            return JSON.stringify(r, null, 2);
          }

          return usage();
        });
      } catch (e) {
        return `f ha-ws: ${e.message ?? e}`;
      }
    },
  };
}

export default { register };
