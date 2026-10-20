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

### 2020 extrusion frames (parametric)

`2020box` builds a full frame + 6 panels from **inner cavity** dims. 20mm profile,
3mm panels, 13.5mm panel recess by default. All parts touch (verified).

```bash
f blender 2020box 200 200 200 box        # 200x200x200 inner, prefix "box"
f blender 2020box 200 100 300 box 13.5 3  # custom recess + panel thickness
```

Gives: 4 posts + 8 rails + 6 panels (18 objects), all named `<prefix>.*`.
Rebuilding with the same prefix replaces the old parts.

Export the unique parts for printing:
```bash
f blender 2020box 200 200 200 box
# then export post/rail/panel STLs
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
