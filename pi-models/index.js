import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { execSync } from "node:child_process";

const CRED = "pi-models";
const target = () => path.join(homedir(), ".pi", "agent", "models.json");

export function register(_ctx) {
  return {
    name: "pi-models",
    desc: "save/restore ~/.pi/agent/models.json in the f creds store (cred: pi-models)",
    run: (_argv, args) => {
      const cmd = args._?.[0];
      if (cmd === "save" || cmd === "restore" || cmd === "status") {
        if (cmd === "save") {
          const p = target();
          if (!existsSync(p)) {
            console.error(`pi-models: ${p} not found — nothing to save`);
            process.exit(1);
          }
          const raw = readFileSync(p, "utf8");
          try {
            JSON.parse(raw);
          } catch {
            console.error(`pi-models: ${p} is not valid JSON — refusing to save`);
            process.exit(1);
          }
          execSync(`f creds set ${CRED} $(cat '${p}')`, { stdio: "inherit" });
          console.log(`pi-models: saved to creds:${CRED}`);
          return;
        }
        if (cmd === "restore") {
          let raw;
          try {
            raw = execSync(`f creds get ${CRED} --secrets`, { encoding: "utf8" });
          } catch (e) {
            console.error("pi-models: no creds:pi-models — run 'f pi-models save' on a machine that has it (needs creds unlocked)");
            process.exit(1);
          }
          try {
            JSON.parse(raw);
          } catch {
            console.error("pi-models: creds:pi-models is not valid JSON — refusing to write");
            process.exit(1);
          }
          const p = target();
          mkdirSync(path.dirname(p), { recursive: true });
          if (existsSync(p)) {
            const bak = `${p}.bak`;
            writeFileSync(bak, readFileSync(p, "utf8"));
            console.log(`pi-models: existing file backed up to ${bak}`);
          }
          writeFileSync(p, raw);
          console.log(`pi-models: restored to ${p}`);
          return;
        }
        // status
        const local = existsSync(target());
        let cred = false;
        try {
          execSync(`f creds get ${CRED}`, { stdio: "ignore" });
          cred = true;
        } catch {}
        console.log(`creds:${CRED} ${cred ? "set" : "missing"}; local ${local ? "present" : "absent"}`);
        return;
      }
      console.error("usage: f pi-models <save|restore|status>");
      process.exit(2);
    },
    skills: [{ name: "f-pi-models", path: path.join(path.dirname(new URL(import.meta.url).pathname), "SKILL.md") }],
  };
}
export default { register };
