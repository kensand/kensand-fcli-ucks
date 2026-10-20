---
name: f-blender
description: Control a headless Blender 5.x instance. Trigger - any 3D modelling, scene building, rendering, or export task.
---

# f blender

Control a headless Blender instance over TCP.

## Start the server

```bash
blender --background --python ~/fuck-blender/fuck.py serve
```

## Common workflows

### Build a scene

```bash
f blender add cube mybox
f blender set mybox scale "[2,1,3]"
f blender move mybox "[10,0,5]"
f blender material Red "[1,0.2,0.1]" 0.8 0.3
f blender assign mybox Red
f blender add camera cam
f blender look_at cam "[0,0,5]" "[50,-50,40]"
f blender add light sun SUN
f blender light sun energy 2000
```

### Render

```bash
f blender render /tmp/out.png          # EEVEE
f blender render /tmp/out.png CYCLES   # Cycles
```

### 2020 extrusion frames

Each 2020 profile is a 20x20mm cross-section. Use `add cube` + `set scale` to
create extrusions of the right length, position at the edge midpoint.

```bash
# 100x80x60 box, 20mm profiles
# Posts (20x20x60) at 4 corners
f blender add cube v1 && f blender set v1 scale "[1,1,3]" && f blender set v1 loc "[-40,-30,30]"
# ... etc for v2-v4, then edges between posts
```

### Export

```bash
f blender export mybox glb /tmp/model.glb
f blender export mybox obj /tmp/model.obj
f blender export mybox fbx /tmp/model.fbx
```

## Gotchas

- Base cube is 2x2x2 (half-extent 1), not 20mm. Scale accordingly.
- `set rot` takes degrees, `look_at` computes rotation automatically.
- Delete default scene objects (Cube, Light, Camera) before building.
- One command per TCP connection — fast for individual ops, slow for batch.
