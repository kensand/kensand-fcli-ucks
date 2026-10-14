import fs from "node:fs"; import os from "node:os"; import path from "node:path";
import { execFileSync } from "node:child_process";
const { default: C } = await import("../lib/vwclient.js");
const cfg = JSON.parse(fs.readFileSync(path.join(os.homedir(), ".f/f.config.json"), "utf8")).vaultwarden || {};
const read = (n) => { try { return execFileSync("f", ["creds","get",n,"--secrets"], { encoding:"utf8", timeout:60000 }).trim().split("\n").pop(); } catch { return ""; } };
const pw = read("vaultwarden.master-password");
if (!pw) { console.log("no stored master password (that is fine, say so)"); process.exit(3); }
const api = new C.VaultwardenApi({ server: cfg.server, clientId: "device", clientSecret: "", timeoutMs: 30000 });
const pre = await api.prelogin(cfg.email);
console.log("kdf:", JSON.stringify(pre));
const r = await api.loginPassword({ email: cfg.email, masterPassword: pw })
  .then((j) => ({ ok: true, has: !!j?.access_token }))
  .catch((e) => ({ ok: false, status: e.status, msg: String(e.message).split("\n")[0].slice(0, 160), body: e.body && JSON.stringify(e.body).slice(0, 200) }));
console.log("password grant ->", JSON.stringify(r));
