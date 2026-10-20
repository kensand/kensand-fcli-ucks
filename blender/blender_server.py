#!/usr/bin/env python3
"""fuck — a CLI controller for Blender.

Usage:
  blender --background --python fuck.py serve    # in Blender (headless)
  ./fuck <command> [args...]
"""
import json
import math
import os
import socket

import bpy
import bmesh
from mathutils import Matrix

HOST = "127.0.0.1"
PORT = 9876


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _scene():
    return bpy.context.scene or (bpy.data.scenes[0] if bpy.data.scenes else bpy.data.scenes.new("FuckScene"))


def _obj(name):
    if name not in bpy.data.objects:
        raise ValueError(f"object not found: {name}")
    return bpy.data.objects[name]


def _vec(s):
    v = json.loads(s)
    if not isinstance(v, (list, tuple)) or len(v) < 3:
        raise ValueError(f"expected 3-element vec, got {s}")
    return (float(v[0]), float(v[1]), float(v[2]))


def _mat4(s):
    m = json.loads(s)
    if not isinstance(m, (list, tuple)) or len(m) != 16:
        raise ValueError("expected 16-element 4x4 matrix (row-major)")
    # Blender Matrix() expects column-major; input is row-major
    return Matrix((
        (m[0],  m[4],  m[8],  m[12]),
        (m[1],  m[5],  m[9],  m[13]),
        (m[2],  m[6],  m[10], m[14]),
        (m[3],  m[7],  m[11], m[15]),
    ))


# ---------------------------------------------------------------------------
# object commands
# ---------------------------------------------------------------------------
def cmd_add(args):
    scene = _scene()
    kind = args[0].lower()
    name = args[1] if len(args) > 1 else None

    if kind == "cube":
        mesh = bpy.data.meshes.new(name or "Cube")
        # 20mm cube (2020 profile default)
        h = 10.0
        mesh.from_pydata(
            [(-h, -h, -h), (h, -h, -h), (h, h, -h), (-h, h, -h),
             (-h, -h, h), (h, -h, h), (h, h, h), (-h, h, h)],
            [],
            [(0, 1, 2, 3), (7, 6, 5, 4), (0, 4, 5, 1),
             (1, 5, 6, 2), (2, 6, 7, 3), (3, 7, 4, 0)],
        )
        mesh.update()
        obj = bpy.data.objects.new(name or "Cube", mesh)
    elif kind == "sphere":
        segs = int(args[2]) if len(args) > 2 else 32
        mesh = bpy.data.meshes.new(name or "Sphere")
        bm = bmesh.new()
        bmesh.ops.create_uvsphere(bm, u_segments=segs, v_segments=segs // 2, radius=1.0)
        bm.to_mesh(mesh)
        bm.free()
        obj = bpy.data.objects.new(name or "Sphere", mesh)
    elif kind == "cylinder":
        segs = int(args[2]) if len(args) > 2 else 32
        mesh = bpy.data.meshes.new(name or "Cylinder")
        bm = bmesh.new()
        bmesh.ops.create_cone(bm, cap_ends=True, segments=segs, radius1=1, radius2=1, depth=2)
        bm.to_mesh(mesh)
        bm.free()
        obj = bpy.data.objects.new(name or "Cylinder", mesh)
    elif kind == "plane":
        mesh = bpy.data.meshes.new(name or "Plane")
        bm = bmesh.new()
        bmesh.ops.create_grid(bm, x_segments=1, y_segments=1, size=1)
        bm.to_mesh(mesh)
        bm.free()
        obj = bpy.data.objects.new(name or "Plane", mesh)
    elif kind == "torus":
        mesh = bpy.data.meshes.new(name or "Torus")
        bm = bmesh.new()
        # build torus manually
        major_r, minor_r = 1.0, 0.3
        u_segs, v_segs = 32, 16
        verts = []
        for i in range(u_segs):
            u = 2 * math.pi * i / u_segs
            for j in range(v_segs):
                v = 2 * math.pi * j / v_segs
                x = (major_r + minor_r * math.cos(v)) * math.cos(u)
                y = (major_r + minor_r * math.cos(v)) * math.sin(u)
                z = minor_r * math.sin(v)
                verts.append((x, y, z))
        faces = []
        for i in range(u_segs):
            for j in range(v_segs):
                i2 = (i + 1) % u_segs
                j2 = (j + 1) % v_segs
                v0 = i * v_segs + j
                v1 = i2 * v_segs + j
                v2 = i2 * v_segs + j2
                v3 = i * v_segs + j2
                faces.append((v0, v1, v2, v3))
        mesh.from_pydata(verts, [], faces)
        mesh.update()
        obj = bpy.data.objects.new(name or "Torus", mesh)
    elif kind == "cone":
        segs = int(args[2]) if len(args) > 2 else 32
        mesh = bpy.data.meshes.new(name or "Cone")
        bm = bmesh.new()
        bmesh.ops.create_cone(bm, cap_ends=True, segments=segs, radius1=1, radius2=0, depth=2)
        bm.to_mesh(mesh)
        bm.free()
        obj = bpy.data.objects.new(name or "Cone", mesh)
    elif kind == "light":
        ltype = args[2].upper() if len(args) > 2 else "POINT"
        if ltype not in ("POINT", "SUN", "SPOT", "AREA"):
            raise ValueError(f"light type must be POINT/SUN/SPOT/AREA, got {ltype}")
        data = bpy.data.lights.new(name or "Light", type=ltype)
        data.energy = 1000
        obj = bpy.data.objects.new(name or "Light", data)
    elif kind == "camera":
        data = bpy.data.cameras.new(name or "Camera")
        obj = bpy.data.objects.new(name or "Camera", data)
    elif kind == "empty":
        obj = bpy.data.objects.new(name or "Empty", None)
        obj.empty_display_type = "PLAIN_AXES"
    else:
        raise ValueError(f"unknown primitive: {kind}")

    if name:
        obj.name = name
    scene.collection.objects.link(obj)
    return obj.name


def cmd_set(args):
    target, prop, value = args[0], args[1], args[2]
    obj = _obj(target)
    v = json.loads(value)
    prop_map = {
        "loc": "location", "position": "location",
        "rot": "rotation_euler", "rotation": "rotation_euler",
        "scale": "scale",
        "hide": "hide_render", "visible": "hide_render",
    }
    prop = prop_map.get(prop, prop)
    if prop in ("location", "rotation_euler", "scale"):
        if not isinstance(v, (list, tuple)) or len(v) < 3:
            raise ValueError(f"{prop} expects 3-element array")
        setattr(obj, prop, tuple(float(x) for x in v[:3]))
    elif prop == "hide_render":
        obj.hide_render = bool(v)
    else:
        setattr(obj, prop, v)
    return None


def cmd_move(args):
    obj = _obj(args[0])
    dx, dy, dz = (float(x) for x in json.loads(args[1]))
    obj.location = (obj.location.x + dx, obj.location.y + dy, obj.location.z + dz)
    return [obj.location.x, obj.location.y, obj.location.z]


def cmd_rotate(args):
    obj = _obj(args[0])
    rx, ry, rz = (math.radians(float(x)) for x in json.loads(args[1]))
    obj.rotation_euler = (
        obj.rotation_euler.x + rx,
        obj.rotation_euler.y + ry,
        obj.rotation_euler.z + rz,
    )
    return list(obj.rotation_euler)


def cmd_transform(args):
    obj = _obj(args[0])
    mat = _mat4(args[1])
    obj.matrix_world = mat
    return None


def cmd_look_at(args):
    """Point a camera/light at a target point."""
    obj_name = args[0]
    target = _vec(args[1])
    obj = _obj(obj_name)
    obj.location = _vec(args[2]) if len(args) > 2 else obj.location
    # Compute rotation to point -Z at target
    direction = (target[0] - obj.location.x, target[1] - obj.location.y, target[2] - obj.location.z)
    norm = math.sqrt(direction[0]**2 + direction[1]**2 + direction[2]**2)
    direction = tuple(d / norm for d in direction)
    # Convert to Euler rotation (camera looks down -Z)
    track_quat = (-direction[2], -direction[1], -direction[0]).normalized() if hasattr((-direction[2], -direction[1], -direction[0]), 'normalized') else None
    # Use mathutils
    from mathutils import Vector
    d = Vector(direction)
    rot_quat = d.to_track_quat('Z', 'Y')
    obj.rotation_euler = rot_quat.to_euler()
    return list(obj.rotation_euler)


def cmd_delete(args):
    obj = _obj(args[0])
    obj.users_collection[0].objects.unlink(obj)
    bpy.data.objects.remove(obj)
    return None


def cmd_duplicate(args):
    src = _obj(args[0])
    new_name = args[1] if len(args) > 1 else src.name + ".copy"
    obj = src.copy()
    if src.data:
        obj.data = src.data.copy()
    obj.name = new_name
    obj.data.name = new_name
    _scene().collection.objects.link(obj)
    return new_name


def cmd_list(args):
    filter_type = args[0].upper() if args else None
    result = []
    for o in _scene().objects:
        if filter_type and o.type != filter_type:
            continue
        entry = {
            "name": o.name,
            "type": o.type,
            "loc": [round(o.location.x, 3), round(o.location.y, 3), round(o.location.z, 3)],
            "scale": [round(o.scale.x, 3), round(o.scale.y, 3), round(o.scale.z, 3)],
        }
        if o.data and hasattr(o.data, "materials"):
            entry["mats"] = [m.name for m in o.data.materials if m]
        result.append(entry)
    return result


# ---------------------------------------------------------------------------
# material commands
# ---------------------------------------------------------------------------
def cmd_material(args):
    name = args[0]
    r, g, b = (float(x) for x in json.loads(args[1]))
    if len(args) > 2:
        metal, rough = float(args[2]), float(args[3])
    else:
        metal, rough = 0.0, 0.5

    if name in bpy.data.materials:
        mat = bpy.data.materials[name]
    else:
        mat = bpy.data.materials.new(name)
    mat.use_nodes = True
    bsdf = mat.node_tree.nodes.get("Principled BSDF")
    if bsdf:
        bsdf.inputs["Base Color"].default_value = (r, g, b, 1.0)
        bsdf.inputs["Metallic"].default_value = metal
        bsdf.inputs["Roughness"].default_value = rough
    return name


def cmd_assign(args):
    obj_name, mat_name = args[0], args[1]
    obj = _obj(obj_name)
    if mat_name not in bpy.data.materials:
        raise ValueError(f"material not found: {mat_name}")
    mat = bpy.data.materials[mat_name]
    if obj.data and hasattr(obj.data, "materials"):
        if not obj.data.materials:
            obj.data.materials.append(mat)
        else:
            obj.data.materials[0] = mat
    return mat_name


def cmd_texture(args):
    obj_name, img_path = args[0], os.path.expanduser(args[1])
    if not os.path.isfile(img_path):
        raise ValueError(f"image not found: {img_path}")
    obj = _obj(obj_name)
    if obj.data not in bpy.data.materials and not obj.data.materials:
        mat = bpy.data.materials.new(obj.name + "_Mat")
        obj.data.materials.append(mat)
    mat = obj.data.materials[0]
    mat.use_nodes = True
    nt = mat.node_tree
    tex_node = nt.nodes.new("ShaderNodeTexImage")
    tex_node.image = bpy.data.images.load(img_path)
    tex_node.location = (-400, 0)
    bsdf = nt.nodes.get("Principled BSDF")
    if bsdf:
        nt.links.new(tex_node.outputs["Color"], bsdf.inputs["Base Color"])
    return tex_node.image.name


def cmd_uv(args):
    obj = _obj(args[0])
    mesh = obj.data
    if not mesh.uv_layers:
        mesh.uv_layers.new(name="UVMap")
    bm = bmesh.new()
    bm.from_mesh(mesh)
    bmesh.ops.unwrap_uvs(bm, faces=bm.faces[:])
    bm.to_mesh(mesh)
    bm.free()
    mesh.update()
    return "unwrapped"


def cmd_smooth(args):
    obj = _obj(args[0])
    for poly in obj.data.polygons:
        poly.use_smooth = True
    obj.data.update()
    return "smoothed"


# ---------------------------------------------------------------------------
# modifier commands
# ---------------------------------------------------------------------------
def cmd_modifier(args):
    obj = _obj(args[0])
    mtype = args[1].upper()
    m = obj.modifiers.new(name="Mod_" + mtype, type=mtype)

    if mtype == "BEVEL":
        m.width = float(args[2]) if len(args) > 2 else 0.1
    elif mtype in ("SUBSURF",):
        m.levels = int(args[2]) if len(args) > 2 else 2
    elif mtype == "ARRAY":
        m.count = int(args[2]) if len(args) > 2 else 3
    elif mtype == "MIRROR":
        m.use_axis = (len(args) > 2 and "x" in args[2].lower(),
                      len(args) > 2 and "y" in args[2].lower(),
                      len(args) > 2 and "z" in args[2].lower())
    elif mtype == "SOLIDIFY":
        m.thickness = float(args[2]) if len(args) > 2 else 0.1
    elif mtype == "SIMPLE_DEFORM":
        pass
    elif mtype not in ("SUBSURF", "SUBSURF_SIMPLE"):
        if mtype not in obj.modifiers[0].__class__.__mro__[0].__name__:
            pass  # just accept it, blender will error if wrong

    return m.name


def cmd_apply_modifier(args):
    obj = _obj(args[0])
    mod_name = args[1] if len(args) > 1 else obj.modifiers[0].name
    if mod_name not in [m.name for m in obj.modifiers]:
        raise ValueError(f"modifier not found: {mod_name}")
    obj.modifiers[0].name = mod_name  # ensure order
    # use bpy.context to apply
    bpy.context.view_layer.objects.active = obj
    obj.select_set(True)
    bpy.ops.object.modifier_apply(modifier=mod_name)
    return "applied"


# ---------------------------------------------------------------------------
# world / lighting
# ---------------------------------------------------------------------------
def cmd_world(args):
    scene = _scene()
    if scene.world is None:
        scene.world = bpy.data.worlds.new("World")
    world = scene.world
    world.use_nodes = True
    bg = world.node_tree.nodes.get("Background")
    if bg:
        r, g, b = (float(x) for x in json.loads(args[0]))
        strength = float(args[1]) if len(args) > 1 else 1.0
        bg.inputs[0].default_value = (r, g, b, 1.0)
        bg.inputs[1].default_value = strength
    return world.name


def cmd_light_set(args):
    obj = _obj(args[0])
    if obj.type != "LIGHT":
        raise ValueError(f"{args[0]} is not a light")
    prop = args[1]
    val = json.loads(args[2])
    if prop == "energy":
        obj.data.energy = float(val)
    elif prop == "color":
        r, g, b = (float(x) for x in val)
        obj.data.color = (r, g, b)
    elif prop == "spot_size":
        obj.data.spot_size = math.radians(float(val))
    elif prop == "size":
        obj.data.size = float(val)
    else:
        raise ValueError(f"unknown light prop: {prop}")
    return None


# ---------------------------------------------------------------------------
# render / animation
# ---------------------------------------------------------------------------
def cmd_render(args):
    scene = _scene()
    path = os.path.expanduser(args[0])
    # auto-append .png if no image extension
    if not any(path.lower().endswith(e) for e in (".png", ".jpg", ".jpeg", ".bmp", ".exr", ".tif", ".tiff")):
        path += ".png"
    # resolve to absolute; keep the user's dir, but ensure it exists
    path = os.path.abspath(path)
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        raise ValueError(f"directory does not exist: {d}")
    engine = args[1].upper() if len(args) > 1 else "BLENDER_EEVEE"
    if engine == "CYCLES":
        engine = "CYCLES"
    elif engine == "EEVEE":
        engine = "BLENDER_EEVEE"

    # use the scene's camera if set, otherwise pick the first one
    if scene.camera is None:
        cams = [o for o in scene.objects if o.type == "CAMERA"]
        if cams:
            cam = cams[0]
            if all(v == 0 for v in cam.rotation_euler):
                cam.location = (8, 8, 5)
                cam.rotation_euler = (math.radians(60), 0, math.radians(45))
            scene.camera = cam

    scene.render.engine = engine
    scene.render.filepath = path
    scene.render.resolution_x = 1920
    scene.render.resolution_y = 1080
    bpy.ops.render.render(write_still=True)
    return path


def cmd_keyframe(args):
    obj = _obj(args[0])
    frame = int(args[1])
    scene = _scene()
    scene.frame_set(frame)
    obj.keyframe_insert(data_path="location", frame=frame)
    obj.keyframe_insert(data_path="rotation_euler", frame=frame)
    obj.keyframe_insert(data_path="scale", frame=frame)
    return frame


def cmd_play(args):
    scene = _scene()
    fps = int(args[0]) if args else 24
    scene.render.fps = fps
    start = int(args[1]) if len(args) > 1 else scene.frame_start
    end = int(args[2]) if len(args) > 2 else scene.frame_end
    scene.frame_start = start
    scene.frame_end = end
    # render animation
    scene.render.filepath = args[3] if len(args) > 3 else "/tmp/fuck_anim_"
    scene.render.image_settings.file_format = "PNG"
    bpy.ops.render.render(animation=True)
    return f"frames {start}-{end}"


# ---------------------------------------------------------------------------
# file I/O
# ---------------------------------------------------------------------------
def cmd_save(args):
    path = os.path.expanduser(args[0])
    bpy.ops.wm.save_as_mainfile(filepath=path)
    return path


def cmd_open(args):
    path = os.path.expanduser(args[0])
    if not os.path.isfile(path):
        raise ValueError(f"file not found: {path}")
    bpy.ops.wm.open_mainfile(filepath=path)
    return path


def cmd_export(args):
    obj_name = args[0]
    fmt = args[1].lower()
    path = os.path.expanduser(args[2]) if len(args) > 2 else f"/tmp/export.{fmt}"
    obj = _obj(obj_name)

    # select only this object
    for o in bpy.context.selected_objects:
        o.select_set(False)
    obj.select_set(True)
    bpy.context.view_layer.objects.active = obj

    if fmt in ("gltf", "glb"):
        bpy.ops.export_scene.gltf(filepath=path, use_selection=True)
    elif fmt == "fbx":
        bpy.ops.export_scene.fbx(filepath=path, use_selection=True)
    elif fmt in ("obj", "wavefront"):
        bpy.ops.wm.obj_export(filepath=path, export_selected_objects=True)
    elif fmt == "stl":
        bpy.ops.wm.stl_export(filepath=path, export_selected_objects=True)
    else:
        raise ValueError(f"unsupported export format: {fmt}")
    return path


# ---------------------------------------------------------------------------
# info / debug
# ---------------------------------------------------------------------------
def cmd_info(args):
    scene = _scene()
    return {
        "blender_version": bpy.app.version_string,
        "scene": scene.name,
        "frame": scene.frame_current,
        "frames": f"{scene.frame_start}-{scene.frame_end}",
        "fps": scene.render.fps,
        "engine": scene.render.engine,
        "resolution": [scene.render.resolution_x, scene.render.resolution_y],
        "objects": len(scene.objects),
        "materials": len(bpy.data.materials),
        "world": scene.world.name if scene.world else None,
    }


def cmd_box(args):
    """Build a parametric 2020 frame + 6 panels.
    args: W D H (INNER box dims in mm — the inner edge of each rail) [prefix] [panel_recess] [panel_thick]
    """
    w, d, h = (float(x) for x in args[:3])
    prefix = args[3] if len(args) > 3 else "x"
    t = 20.0                      # profile size
    recess = float(args[4]) if len(args) > 4 else 13.5
    pt = float(args[5]) if len(args) > 5 else 3.0
    if min(w, d, h) <= 0:
        raise ValueError("inner dims must be positive")

    scene = _scene()
    # remove old objects with this prefix
    for o in [o for o in scene.objects if o.name.startswith(prefix + ".")]:
        o.users_collection[0].objects.unlink(o)
        bpy.data.objects.remove(o)

    made = []

    # place a solid box by its explicit world-space bounds (1 unit = 1 mm).
    # base cube is 2 units wide (half-extent 1), so scale = size/2, center = midpoint.
    def put(name, x0, x1, y0, y1, z0, z1):
        mesh = bpy.data.meshes.new(name)
        mesh.from_pydata(
            [(-1, -1, -1), (1, -1, -1), (1, 1, -1), (-1, 1, -1),
             (-1, -1, 1), (1, -1, 1), (1, 1, 1), (-1, 1, 1)],
            [],
            [(0, 1, 2, 3), (7, 6, 5, 4), (0, 4, 5, 1),
             (1, 5, 6, 2), (2, 6, 7, 3), (3, 7, 4, 0)],
        )
        mesh.update()
        o = bpy.data.objects.new(name, mesh)
        o.location = ((x0 + x1) / 2, (y0 + y1) / 2, (z0 + z1) / 2)
        o.scale = ((x1 - x0) / 2, (y1 - y0) / 2, (z1 - z0) / 2)
        scene.collection.objects.link(o)
        made.append(name)
        return o

    hw, hd = w / 2, d / 2                 # inner half extents
    ot = t / 2                             # outer face offset from inner (profile/2)
    # Inner cavity faces at ±hw, ±hd, 0, h.  Posts/rails sit just outside.
    # Post outer faces at ±(hw+t), ±(hd+t); posts occupy [hw, hw+t] etc.
    H = h + 2 * t                          # full outer height (rails add t top+bottom)

    # 4 vertical posts: 20mm square, from z=0 to z=H, at each corner
    for i, (sx, sy) in enumerate(((-1, -1), (1, -1), (-1, 1), (1, 1))):
        ax0, ax1 = (hw, hw + t) if sx > 0 else (-(hw + t), -hw)
        ay0, ay1 = (hd, hd + t) if sy > 0 else (-(hd + t), -hd)
        put(f"{prefix}.post{i+1}", ax0, ax1, ay0, ay1, 0, H)
    # 8 horizontal rails (20mm square), spanning between posts
    for zs, z0, z1 in (("b", 0, t), ("t", H - t, H)):
        # front/back: run along X at the front/back, between the two posts' inner faces
        for sy in (-1, 1):
            y0, y1 = (hd, hd + t) if sy > 0 else (-(hd + t), -hd)
            put(f"{prefix}.{'b' if sy>0 else 'f'}b_{zs}", -hw, hw, y0, y1, z0, z1)
        # left/right: run along Y at the sides, between the two posts' inner faces
        for sx in (-1, 1):
            x0, x1 = (hw, hw + t) if sx > 0 else (-(hw + t), -hw)
            put(f"{prefix}.{'r' if sx>0 else 'l'}_{zs}", x0, x1, -hd, hd, z0, z1)

    # 6 panels: on each outer face, 3mm thick (outward), edges recessed `recess` from the outer corner
    OX, OY, OZ = hw + t, hd + t, H        # outer bounding half-extents (X,Y) and top Z
    put(f"{prefix}.p_front",    -OX + recess, OX - recess, -(OY + pt), -OY,          recess, OZ - recess)
    put(f"{prefix}.p_back",     -OX + recess, OX - recess,  OY,           OY + pt,    recess, OZ - recess)
    put(f"{prefix}.p_left",     -(OX + pt), -OX,            -OY + recess, OY - recess, recess, OZ - recess)
    put(f"{prefix}.p_right",    OX,            OX + pt,     -OY + recess, OY - recess, recess, OZ - recess)
    put(f"{prefix}.p_top",      -OX + recess, OX - recess,  -OY + recess, OY - recess, OZ, OZ + pt)
    put(f"{prefix}.p_bottom",   -OX + recess, OX - recess,  -OY + recess, OY - recess, -pt, 0)

    # assign material if present
    if "Alu" in bpy.data.materials:
        for n in made:
            o = bpy.data.objects[n]
            if not o.data.materials:
                o.data.materials.append(bpy.data.materials["Alu"])
    return {"inner": [w, d, h], "outer": [2 * OX, 2 * OY, OZ],
            "objects": len(made)}


def cmd_version(args):
    return bpy.app.version_string


def cmd_scene(args):
    """Set scene properties. e.g. scene units mm"""
    scene = _scene()
    prop = args[0]
    val = args[1] if len(args) > 1 else None
    if prop == "units":
        scene.unit_settings.system = "METRIC"
        scene.unit_settings.scale_length = 0.001  # mm
        scene.unit_settings.length_unit = "MILLIMETERS"
    elif prop == "frame_start":
        scene.frame_start = int(val)
    elif prop == "frame_end":
        scene.frame_end = int(val)
    elif prop == "fps":
        scene.render.fps = int(val)
    elif prop == "resolution":
        w, h = (int(x) for x in json.loads(val))
        scene.render.resolution_x = w
        scene.render.resolution_y = h
    elif prop == "engine":
        scene.render.engine = val.upper()
    else:
        raise ValueError(f"unknown scene prop: {prop}")
    return None


def cmd_objects(args):
    """List all objects with full detail."""
    return [
        {
            "name": o.name,
            "type": o.type,
            "location": list(o.location),
            "rotation_euler": list(o.rotation_euler),
            "scale": list(o.scale),
            "materials": [m.name for m in o.data.materials if m] if o.data and hasattr(o.data, "materials") else [],
            "modifiers": [m.name for m in o.modifiers] if o.data else [],
            "verts": len(o.data.vertices) if o.data and hasattr(o.data, "vertices") else None,
        }
        for o in _scene().objects
    ]


# ---------------------------------------------------------------------------
# dispatch table
# ---------------------------------------------------------------------------
HANDLERS = {
    # object
    "add": cmd_add,
    "list": cmd_list,
    "set": cmd_set,
    "move": cmd_move,
    "rotate": cmd_rotate,
    "transform": cmd_transform,
    "delete": cmd_delete,
    "duplicate": cmd_duplicate,
    # materials
    "material": cmd_material,
    "assign": cmd_assign,
    "texture": cmd_texture,
    "uv": cmd_uv,
    "smooth": cmd_smooth,
    # modifiers
    "modifier": cmd_modifier,
    "apply_mod": cmd_apply_modifier,
    # world / light
    "world": cmd_world,
    "light": cmd_light_set,
    # render / animation
    "render": cmd_render,
    "keyframe": cmd_keyframe,
    "play": cmd_play,
    "look_at": cmd_look_at,
    # file I/O
    "save": cmd_save,
    "open": cmd_open,
    "export": cmd_export,
    # info
    "info": cmd_info,
    "version": cmd_version,
    "objects": cmd_objects,
    "box": cmd_box,
    "2020box": cmd_box,
    "scene": cmd_scene,
    # misc
    "ping": lambda a: "pong",
}

# minimum required args per command (for usage errors)
USAGE = {
    "add": 1, "set": 3, "move": 2, "rotate": 2, "transform": 2, "delete": 1,
    "duplicate": 1, "material": 2, "assign": 2, "texture": 2, "uv": 1,
    "smooth": 1, "modifier": 2, "apply_mod": 1, "light": 3, "render": 1,
    "keyframe": 2, "play": 1, "look_at": 2, "save": 1, "open": 1,
    "export": 2, "box": 3, "2020box": 3, "scene": 1,
}


def main():
    if not bpy.data.scenes:
        bpy.data.scenes.new("FuckScene")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(16)
    print(f"[fuck] listening on {HOST}:{PORT}", flush=True)

    while True:
        conn, addr = server.accept()
        try:
            # read one line directly from the socket (no makefile buffering issues)
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
            if not buf:
                continue
            cmd = json.loads(buf.decode())
            name = cmd.get("cmd")
            args = cmd.get("args", [])
            if name not in HANDLERS:
                raise ValueError(f"unknown command: {name}")
            need = USAGE.get(name, 0)
            if len(args) < need:
                raise ValueError(f"{name} needs {need} arg(s), got {len(args)} — run `f blender --help`")
            out = {"ok": True, "data": HANDLERS[name](args)}
        except Exception as e:
            out = {"ok": False, "error": str(e)}
        try:
            conn.sendall((json.dumps(out) + "\n").encode())
        finally:
            conn.close()
        print(f"[server] {name}: {out}", flush=True)


if __name__ == "__main__":
    main()
