#!/usr/bin/env node
// f blender — control a headless Blender instance over TCP.
//
// Server:  blender --background --python <this-dir>/blender_server.py serve
// Client:  f blender <command> [args...]   (talks to 127.0.0.1:9876 directly)

import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";

const here = path.dirname(fileURLToPath(import.meta.url));
const SERVER = path.join(here, "blender_server.py");
const HOST = "127.0.0.1";
const PORT = 9876;
const PID_FILE = path.join(os.tmpdir(), "f_blender_server.pid");
const LOG_FILE = path.join(os.tmpdir(), "f_blender_server.log");

function isUp() {
  return new Promise((resolve) => {
    const s = net.connect({ host: HOST, port: PORT, timeout: 1500 });
    s.on("connect", () => { s.end(); resolve(true); });
    s.on("error", () => resolve(false));
    s.on("timeout", () => { s.destroy(); resolve(false); });
  });
}

async function cmdStart() {
  if (await isUp()) return { ok: true, data: "already running on " + HOST + ":" + PORT };
  const r = spawnSync("which", ["blender"], { encoding: "utf8" });
  const bin = r.stdout.trim();
  if (!bin) return { ok: false, error: "blender binary not found in PATH" };
  const log = fs.openSync(LOG_FILE, "a");
  const child = spawn(bin, ["--background", "--python", SERVER, "serve"], {
    stdio: ["ignore", log, log],
    detached: true,
  });
  child.unref();
  fs.writeFileSync(PID_FILE, String(child.pid));
  for (let i = 0; i < 30; i++) {
    await new Promise((res) => setTimeout(res, 1000));
    if (await isUp()) return { ok: true, data: `started (pid ${child.pid}), log: ${LOG_FILE}` };
  }
  return { ok: false, error: `server did not come up in 30s — check ${LOG_FILE}` };
}

async function cmdStop() {
  const pids = [];
  if (fs.existsSync(PID_FILE)) pids.push(fs.readFileSync(PID_FILE, "utf8").trim());
  try {
    const p = spawnSync("pgrep", ["-f", "blender_server.py"], { encoding: "utf8" });
    p.stdout.split("\n").forEach((x) => x && !pids.includes(x) && pids.push(x));
  } catch {}
  if (!pids.length) return { ok: true, data: "not running" };
  pids.forEach((p) => { try { process.kill(+p, "SIGKILL"); } catch {} });
  try { fs.unlinkSync(PID_FILE); } catch {}
  return { ok: true, data: `stopped (${pids.join(", ")})` };
}

async function cmdStatus() {
  const up = await isUp();
  const pid = fs.existsSync(PID_FILE) ? fs.readFileSync(PID_FILE, "utf8").trim() : null;
  return { ok: true, data: up ? `running (pid ${pid || "?"}) on ${HOST}:${PORT}` : `stopped (log: ${LOG_FILE})` };
}

// One JSON request/response over a fresh TCP connection. Blender is single-threaded
// per command, so a short-lived connection per call is correct and simple.
function request(cmd, args, timeoutMs = 600_000) {
  return new Promise((resolve, reject) => {
    const s = net.connect({ host: HOST, port: PORT, timeout: timeoutMs });
    let buf = "";
    const fail = (msg) => { s.destroy(); reject(new Error(msg)); };
    s.on("error", (e) => fail(e.code === "ECONNREFUSED"
      ? `no blender server on ${HOST}:${PORT}\n  start: blender --background --python ${SERVER} serve`
      : e.message));
    s.on("timeout", () => fail(`timeout after ${timeoutMs}ms`));
    s.on("connect", () => {
      try { s.write(JSON.stringify({ cmd, args }) + "\n"); }
      catch (e) { fail(e.message); }
    });
    s.on("data", (d) => { buf += d.toString(); });
    s.on("close", () => {
      if (buf) {
        try { resolve(JSON.parse(buf)); }
        catch (e) { fail(`bad response: ${buf.slice(0, 200)}`); }
      } else fail("connection closed with no response");
    });
  });
}

const USAGE = `usage: f blender <command> [args...]

commands:
  ping                          health check
  add <type> [name] [extra]     cube|sphere|cylinder|cone|plane|torus|light|camera|empty
  list [TYPE]                   list objects (MESH|LIGHT|CAMERA|EMPTY)
  objects                       full detail
  set <obj> <prop> <json>       loc/rot/scale/hide or any bpy prop
  move <obj> "[dx,dy,dz]"       relative translate
  rotate <obj> "[rx,ry,rz]"     relative rotate (degrees)
  look_at <obj> <target> [pos]  point camera/light at target
  duplicate <obj> [name]
  delete <obj>
  material <name> "[r,g,b]" [metallic] [roughness]
  assign <obj> <material>
  texture <obj> <image.png>
  uv <obj>
  smooth <obj>
  modifier <obj> <TYPE> [param] BEVEL|SUBSURF|ARRAY|SOLIDIFY|MIRROR
  apply_mod <obj> [mod_name]
  world "[r,g,b]" [strength]
  light <obj> <prop> <value>    energy|color|size|spot_size
  render <path.png> [EEVEE|CYCLES]
  keyframe <obj> <frame>
  play <fps> [start] [end] [prefix]
  save <file.blend>
  open <file.blend>
  export <obj> <fmt> [path]     glb|gltf|fbx|obj|stl
  2020box <W> <D> <H> [prefix] [recess] [pt]  parametric 2020 frame + 6 panels (inner dims mm)
  info
  version
  scene <prop> [val]             units|frame_start|frame_end|fps|resolution|engine

start server: f blender start
`;

export function register(_ctx) {
  return {
    name: "blender",
    desc: "control headless Blender (TCP 127.0.0.1:9876)",
    run: async (_argv, args) => {
      const rest = args._ ?? [];
      if (!rest.length || rest[0] === "--help" || rest[0] === "-h") {
        process.stdout.write(USAGE);
        return;
      }
      const [cmd, ...cmdArgs] = rest;
      try {
        let r;
        if (cmd === "start") r = await cmdStart();
        else if (cmd === "stop") r = await cmdStop();
        else if (cmd === "status") r = await cmdStatus();
        else r = await request(cmd, cmdArgs);
        process.stdout.write(JSON.stringify(r, null, 2) + "\n");
        if (r.ok === false) process.exitCode = 1;
      } catch (e) {
        process.stderr.write(`blender: ${e.message}\n`);
        process.exitCode = 1;
      }
    },
    skills: [
      { name: "f-blender", path: path.join(here, "SKILL.md") },
    ],
  };
}
export default { register };
