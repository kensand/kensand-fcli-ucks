import fs from "node:fs"; import os from "node:os"; import path from "node:path";
import { execFileSync } from "node:child_process";
const { default: C } = await import("../lib/vwclient.js");
const cfg = JSON.parse(fs.readFileSync(path.join(os.homedir(), ".f/f.config.json"), "utf8")).vaultwarden || {};
const read = (n) => { try { return execFileSync("f", ["creds","get",n,"--secrets"], { encoding:"utf8", timeout:60000 }).trim().split("\n").pop(); } catch { return ""; } };
const api = new C.VaultwardenApi({ server: cfg.server, clientId: "device", clientSecret: "", timeoutMs: 30000 });
api.setAccessToken(read("vaultwarden.access-token"), { refreshToken: read("vaultwarden.refresh-token") });
let s = await api.sync().catch((e) => null);
if (!s) { console.log("session spent — needs a fresh: f vaultwarden sso login"); process.exit(2); }
const key = s.profile.key, parts = key.split("."), p0 = parts[1], p1 = parts[2];
const d = (x) => Buffer.from(x, "base64").length;
console.log("segments:", parts.length, "(type " + parts[0] + ")");
console.log("  field1:", p0.length, "chars ->", d(p0), "bytes");
console.log("  field2:", p1.length, "chars ->", d(p1), "bytes");
console.log("  mac   :", parts[3] === undefined ? "(none)" : d(parts[3]) + " bytes");
console.log("");
console.log("A 64-byte key must be 88 chars / 64 bytes after PKCS#7 it is an 80-byte (108-char) ciphertext.");
const A = d(p0), B = d(p1);
const guess = A === 16 && B === 80 ? "iv(16)|data(80, padded from 64)|mac  -> OUR current reading" :
              A === 80 && B === 16 ? "data(80)|iv(16)|mac            -> segments ARE swapped" :
              `neither (${A},${B})  -> a different key format, needs a look`;
console.log("  =>", guess);
