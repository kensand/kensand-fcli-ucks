#!/usr/bin/env node
// f blender — control a headless Blender instance over TCP (synchronous).
//
// Server:  blender --background --python ~/fuck-blender/fuck.py serve
// Client:  f blender <command> [args...]

import { execSync } from "node:child_process";

const FUCK = "/home/kenny/fuck-blender/fuck";

export function register(_ctx) {
  return {
    name: "blender",
    desc: "control headless Blender (TCP 127.0.0.1:9876)",
    run: (_argv, args) => {
      const rest = args._ ?? [];
      if (!rest.length || rest[0] === "--help" || rest[0] === "-h") {
        process.stdout.write(`usage: f blender <command> [args...]

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
  box <W> <D> <H> [prefix] [recess] [pt]  parametric 2020 frame + 6 panels (inner dims mm)
  info
  version
  scene <prop> [val]             units|frame_start|frame_end|fps|resolution|engine

server: blender --background --python ~/fuck-blender/fuck.py serve
`);
        return;
      }
      try {
        const out = execSync(`${FUCK} ${rest.map((a) => `"${a}"`).join(" ")}`, {
          encoding: "utf8",
          timeout: 600_000,
        });
        // pretty-print JSON
        try {
          process.stdout.write(JSON.stringify(JSON.parse(out), null, 2) + "\n");
        } catch {
          process.stdout.write(out);
        }
      } catch (e) {
        process.stderr.write(`blender: ${e.stderr?.toString().trim() || e.message}\n`);
        process.exitCode = 1;
      }
    },
    skills: [
      { name: "f-blender", path: new URL("./SKILL.md", import.meta.url).pathname },
    ],
  };
}
export default { register };
