from __future__ import annotations

import html
import math
import textwrap
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

from .core import enabled_transitions


THEMES = {
    "report": {
        "background": "#FFFFFF",
        "grid": "#E9EDF2",
        "ink": "#162033",
        "muted": "#667085",
        "place": "#FFFFFF",
        "transition": "#172033",
        "goal": "#2563EB",
        "enabled": "#0F9F6E",
        "token": "#111827",
        "accent": "#D97706",
    },
    "classic": {
        "background": "#FFFFFF",
        "grid": "#DDDDDD",
        "ink": "#111111",
        "muted": "#555555",
        "place": "#FFFFFF",
        "transition": "#000000",
        "goal": "#000000",
        "enabled": "#000000",
        "token": "#000000",
        "accent": "#000000",
    },
}


def _wrap(label: str, width: int = 24, lines: int = 4) -> list[str]:
    chunks = textwrap.wrap(str(label), width=width, break_long_words=False) or [""]
    if len(chunks) > lines:
        chunks = chunks[:lines]
        chunks[-1] = chunks[-1].rstrip(" .") + "…"
    return chunks


def _node_maps(project: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], set[str], set[str]]:
    nodes = {
        item["id"]: item
        for item in project.get("places", []) + project.get("transitions", [])
    }
    return (
        nodes,
        {item["id"] for item in project.get("places", [])},
        {item["id"] for item in project.get("transitions", [])},
    )


def calculate_layout(
    project: dict[str, Any], width: int = 1800, height: int | None = None
) -> tuple[dict[str, tuple[float, float]], int, int]:
    nodes, place_ids, transition_ids = _node_maps(project)
    explicit = {
        node_id: (float(node["x"]), float(node["y"]))
        for node_id, node in nodes.items()
        if isinstance(node.get("x"), (int, float)) and isinstance(node.get("y"), (int, float))
    }
    if len(explicit) == len(nodes) and explicit:
        min_x = min(x for x, _ in explicit.values())
        max_x = max(x for x, _ in explicit.values())
        min_y = min(y for _, y in explicit.values())
        max_y = max(y for _, y in explicit.values())
        scale_x = (width - 360) / max(max_x - min_x, 1)
        requested_height = height or max(900, int((max_y - min_y) * scale_x + 320))
        scale_y = (requested_height - 300) / max(max_y - min_y, 1)
        scale = min(scale_x, scale_y)
        positions = {
            node_id: (180 + (x - min_x) * scale, 190 + (y - min_y) * scale)
            for node_id, (x, y) in explicit.items()
        }
        return positions, width, requested_height

    adjacency: dict[str, list[str]] = defaultdict(list)
    indegree: dict[str, int] = defaultdict(int)
    for arc in project.get("arcs", []):
        source, target = arc["source"], arc["target"]
        adjacency[source].append(target)
        indegree[target] += 1

    # Prefer longest predecessor distance in acyclic scenarios. This keeps a
    # prerequisite that is available from the start (for example USB access)
    # aligned with the later action that also needs an intermediate attack state.
    working_indegree = {node_id: indegree[node_id] for node_id in nodes}
    topo = deque(sorted(node_id for node_id in nodes if working_indegree[node_id] == 0))
    level: dict[str, int] = {node_id: 0 for node_id in topo}
    visited: set[str] = set()
    while topo:
        source = topo.popleft()
        visited.add(source)
        for target in adjacency[source]:
            level[target] = max(level.get(target, 0), level[source] + 1)
            working_indegree[target] -= 1
            if working_indegree[target] == 0:
                topo.append(target)

    # Cyclic components cannot be topologically ranked. Attach them by shortest
    # distance from already ranked nodes and keep the renderer deterministic.
    if len(visited) < len(nodes):
        queue: deque[str] = deque(sorted(visited or nodes))
        seen = set(queue)
        while queue:
            source = queue.popleft()
            for target in adjacency[source]:
                if target not in seen:
                    level[target] = level.get(source, 0) + 1
                    seen.add(target)
                    queue.append(target)
        for node_id in nodes:
            level.setdefault(node_id, 0)

    # Petri graphs alternate by construction. Compress empty levels but retain order.
    existing_levels = sorted(set(level.values()))
    remap = {old: new for new, old in enumerate(existing_levels)}
    layers: dict[int, list[str]] = defaultdict(list)
    for node_id in sorted(nodes):
        layers[remap[level[node_id]]].append(node_id)

    max_layer_size = max((len(values) for values in layers.values()), default=1)
    computed_height = max(950, 340 + max_layer_size * 190)
    if height is not None:
        computed_height = max(700, height)
    left, right, top, bottom = 160, width - 160, 185, computed_height - 220
    layer_count = max(len(layers) - 1, 1)
    positions: dict[str, tuple[float, float]] = {}
    for layer, values in sorted(layers.items()):
        x = left + (right - left) * layer / layer_count
        if len(values) == 1:
            ys = [(top + bottom) / 2]
        else:
            ys = [top + (bottom - top) * i / (len(values) - 1) for i in range(len(values))]
        # Places before transitions gives stable, recognizable diagrams.
        values = sorted(values, key=lambda value: (value in transition_ids, value))
        for node_id, y in zip(values, ys):
            positions[node_id] = (x, y)
    return positions, width, computed_height


def _boundary_point(
    center: tuple[float, float],
    toward: tuple[float, float],
    is_place: bool,
) -> tuple[float, float]:
    x, y = center
    tx, ty = toward
    dx, dy = tx - x, ty - y
    length = math.hypot(dx, dy) or 1
    if is_place:
        distance = 31
    else:
        distance = min(40 / max(abs(dy / length), 0.15), 12 / max(abs(dx / length), 0.15))
    return x + dx / length * distance, y + dy / length * distance


def _svg_text(
    x: float,
    y: float,
    lines: list[str],
    color: str,
    *,
    anchor: str = "middle",
    size: int = 16,
    weight: int = 400,
) -> str:
    spans = []
    for index, line in enumerate(lines):
        dy = 0 if index == 0 else int(size * 1.25)
        spans.append(
            f'<tspan x="{x:.1f}" dy="{dy}">{html.escape(line)}</tspan>'
        )
    return (
        f'<text x="{x:.1f}" y="{y:.1f}" text-anchor="{anchor}" '
        f'font-family="Inter, Arial, sans-serif" font-size="{size}" '
        f'font-weight="{weight}" fill="{color}">' + "".join(spans) + "</text>"
    )


def render_svg(
    project: dict[str, Any],
    marking: dict[str, int],
    output_path: Path,
    *,
    title: str | None = None,
    subtitle: str | None = None,
    theme: str = "report",
    show_grid: bool = True,
    last_transition: str | None = None,
    width: int = 1800,
    height: int | None = None,
) -> Path:
    colors = THEMES.get(theme, THEMES["report"])
    positions, width, height = calculate_layout(project, width, height)
    nodes, place_ids, transition_ids = _node_maps(project)
    enabled = set(enabled_transitions(project, marking))
    goals = set(project.get("goals", []))
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        "<defs>",
        f'<pattern id="grid" width="30" height="30" patternUnits="userSpaceOnUse"><path d="M 30 0 L 0 0 0 30" fill="none" stroke="{colors["grid"]}" stroke-width="1"/></pattern>',
        f'<marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="{colors["ink"]}"/></marker>',
        "</defs>",
        f'<rect width="100%" height="100%" fill="{colors["background"]}"/>',
    ]
    if show_grid:
        parts.append(f'<rect x="70" y="130" width="{width - 140}" height="{height - 230}" fill="url(#grid)" rx="12"/>')
    parts.append(_svg_text(80, 58, [title or project.get("title", "Сеть Петри")], colors["ink"], anchor="start", size=28, weight=700))
    if subtitle:
        parts.append(_svg_text(80, 91, [subtitle], colors["muted"], anchor="start", size=16))

    for arc in project.get("arcs", []):
        source, target = arc["source"], arc["target"]
        if source not in positions or target not in positions:
            continue
        p1 = _boundary_point(positions[source], positions[target], source in place_ids)
        p2 = _boundary_point(positions[target], positions[source], target in place_ids)
        dx = p2[0] - p1[0]
        if abs(dx) < 30:
            bend = 75 if p1[1] <= p2[1] else -75
            path = f"M {p1[0]:.1f} {p1[1]:.1f} C {p1[0] + bend:.1f} {p1[1]:.1f}, {p2[0] + bend:.1f} {p2[1]:.1f}, {p2[0]:.1f} {p2[1]:.1f}"
        else:
            c1 = p1[0] + dx * 0.42
            c2 = p2[0] - dx * 0.42
            path = f"M {p1[0]:.1f} {p1[1]:.1f} C {c1:.1f} {p1[1]:.1f}, {c2:.1f} {p2[1]:.1f}, {p2[0]:.1f} {p2[1]:.1f}"
        parts.append(f'<path d="{path}" fill="none" stroke="{colors["ink"]}" stroke-width="2.4" marker-end="url(#arrow)"/>')
        if arc.get("weight", 1) != 1:
            mx, my = (p1[0] + p2[0]) / 2, (p1[1] + p2[1]) / 2
            parts.append(_svg_text(mx, my - 8, [str(arc["weight"])], colors["ink"], size=15, weight=700))

    for place in project.get("places", []):
        node_id = place["id"]
        x, y = positions[node_id]
        stroke = colors["goal"] if node_id in goals else colors["ink"]
        stroke_width = 4 if node_id in goals else 3
        parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="29" fill="{colors["place"]}" stroke="{stroke}" stroke-width="{stroke_width}"/>')
        if node_id in goals:
            parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="23" fill="none" stroke="{stroke}" stroke-width="1.5"/>')
        tokens = marking.get(node_id, 0)
        if tokens == 1:
            parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="7" fill="{colors["token"]}"/>')
        elif 2 <= tokens <= 3:
            offsets = [(-8, 0), (8, 0), (0, -9)][:tokens]
            for ox, oy in offsets:
                parts.append(f'<circle cx="{x + ox:.1f}" cy="{y + oy:.1f}" r="5.5" fill="{colors["token"]}"/>')
        elif tokens > 3:
            parts.append(_svg_text(x, y + 6, [str(tokens)], colors["token"], size=17, weight=700))
        parts.append(_svg_text(x, y + 55, [node_id], colors["muted"], size=13, weight=700))
        parts.append(_svg_text(x, y + 75, _wrap(place.get("label", node_id)), colors["ink"], size=15))

    for transition in project.get("transitions", []):
        node_id = transition["id"]
        x, y = positions[node_id]
        fill = colors["accent"] if node_id == last_transition else colors["enabled"] if node_id in enabled else colors["transition"]
        parts.append(f'<rect x="{x - 9:.1f}" y="{y - 39:.1f}" width="18" height="78" rx="2" fill="{fill}"/>')
        parts.append(_svg_text(x, y + 57, [node_id], colors["muted"], size=13, weight=700))
        parts.append(_svg_text(x, y + 77, _wrap(transition.get("label", node_id)), colors["ink"], size=15))

    legend_y = height - 55
    parts.extend(
        [
            f'<circle cx="90" cy="{legend_y}" r="11" fill="#fff" stroke="{colors["ink"]}" stroke-width="2"/>',
            _svg_text(112, legend_y + 5, ["позиция"], colors["muted"], anchor="start", size=14),
            f'<rect x="225" y="{legend_y - 14}" width="8" height="28" fill="{colors["transition"]}"/>',
            _svg_text(245, legend_y + 5, ["переход"], colors["muted"], anchor="start", size=14),
            f'<circle cx="365" cy="{legend_y}" r="4" fill="{colors["token"]}"/>',
            _svg_text(382, legend_y + 5, ["маркер"], colors["muted"], anchor="start", size=14),
            f'<rect x="485" y="{legend_y - 14}" width="8" height="28" fill="{colors["enabled"]}"/>',
            _svg_text(505, legend_y + 5, ["разрешённый переход"], colors["muted"], anchor="start", size=14),
        ]
    )
    parts.append("</svg>")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(parts), encoding="utf-8")
    return output_path


def _load_font(size: int, bold: bool = False):
    from PIL import ImageFont

    candidates = [
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf" if bold else "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "C:/Windows/Fonts/arialbd.ttf" if bold else "C:/Windows/Fonts/arial.ttf",
    ]
    for candidate in candidates:
        try:
            return ImageFont.truetype(candidate, size)
        except OSError:
            pass
    return ImageFont.load_default()


def _hex(value: str) -> tuple[int, int, int]:
    value = value.lstrip("#")
    return tuple(int(value[i : i + 2], 16) for i in (0, 2, 4))


def _arrow(draw, points: list[tuple[float, float]], fill, width: int = 4) -> None:
    draw.line(points, fill=fill, width=width, joint="curve")
    (x1, y1), (x2, y2) = points[-2], points[-1]
    angle = math.atan2(y2 - y1, x2 - x1)
    size = 15
    left = (x2 - size * math.cos(angle - 0.55), y2 - size * math.sin(angle - 0.55))
    right = (x2 - size * math.cos(angle + 0.55), y2 - size * math.sin(angle + 0.55))
    draw.polygon([(x2, y2), left, right], fill=fill)


def _draw_centered_multiline(draw, xy, lines, font, fill, spacing=4):
    text = "\n".join(lines)
    bbox = draw.multiline_textbbox((0, 0), text, font=font, align="center", spacing=spacing)
    width = bbox[2] - bbox[0]
    draw.multiline_text((xy[0] - width / 2, xy[1]), text, font=font, fill=fill, align="center", spacing=spacing)


def render_png(
    project: dict[str, Any],
    marking: dict[str, int],
    output_path: Path,
    *,
    title: str | None = None,
    subtitle: str | None = None,
    theme: str = "report",
    show_grid: bool = True,
    last_transition: str | None = None,
    width: int = 1800,
    height: int | None = None,
) -> Path:
    try:
        from PIL import Image, ImageDraw
    except ImportError as exc:
        raise RuntimeError(
            "PNG export requires Pillow. Install with: python3 -m pip install Pillow"
        ) from exc

    colors = {key: _hex(value) for key, value in THEMES.get(theme, THEMES["report"]).items()}
    positions, width, height = calculate_layout(project, width, height)
    nodes, place_ids, transition_ids = _node_maps(project)
    enabled = set(enabled_transitions(project, marking))
    goals = set(project.get("goals", []))
    image = Image.new("RGB", (width, height), colors["background"])
    draw = ImageDraw.Draw(image)
    if show_grid:
        for x in range(70, width - 69, 30):
            draw.line((x, 130, x, height - 100), fill=colors["grid"], width=1)
        for y in range(130, height - 99, 30):
            draw.line((70, y, width - 70, y), fill=colors["grid"], width=1)

    title_font = _load_font(28, bold=True)
    label_font = _load_font(16)
    small_font = _load_font(13, bold=True)
    token_font = _load_font(17, bold=True)
    draw.text((80, 38), title or project.get("title", "Сеть Петри"), font=title_font, fill=colors["ink"])
    if subtitle:
        draw.text((80, 82), subtitle, font=label_font, fill=colors["muted"])

    for arc in project.get("arcs", []):
        source, target = arc["source"], arc["target"]
        if source not in positions or target not in positions:
            continue
        p1 = _boundary_point(positions[source], positions[target], source in place_ids)
        p2 = _boundary_point(positions[target], positions[source], target in place_ids)
        dx = p2[0] - p1[0]
        points: list[tuple[float, float]] = []
        for i in range(25):
            t = i / 24
            if abs(dx) < 30:
                bend = 75 if p1[1] <= p2[1] else -75
                c1 = (p1[0] + bend, p1[1])
                c2 = (p2[0] + bend, p2[1])
            else:
                c1 = (p1[0] + dx * 0.42, p1[1])
                c2 = (p2[0] - dx * 0.42, p2[1])
            mt = 1 - t
            x = mt**3 * p1[0] + 3 * mt**2 * t * c1[0] + 3 * mt * t**2 * c2[0] + t**3 * p2[0]
            y = mt**3 * p1[1] + 3 * mt**2 * t * c1[1] + 3 * mt * t**2 * c2[1] + t**3 * p2[1]
            points.append((x, y))
        _arrow(draw, points, colors["ink"], 4)
        if arc.get("weight", 1) != 1:
            mx, my = points[len(points) // 2]
            draw.text((mx, my - 20), str(arc["weight"]), font=small_font, fill=colors["ink"])

    for place in project.get("places", []):
        node_id = place["id"]
        x, y = positions[node_id]
        stroke = colors["goal"] if node_id in goals else colors["ink"]
        draw.ellipse((x - 29, y - 29, x + 29, y + 29), fill=colors["place"], outline=stroke, width=4 if node_id in goals else 3)
        if node_id in goals:
            draw.ellipse((x - 23, y - 23, x + 23, y + 23), outline=stroke, width=2)
        tokens = marking.get(node_id, 0)
        if tokens == 1:
            draw.ellipse((x - 7, y - 7, x + 7, y + 7), fill=colors["token"])
        elif 2 <= tokens <= 3:
            offsets = [(-8, 0), (8, 0), (0, -9)][:tokens]
            for ox, oy in offsets:
                draw.ellipse((x + ox - 5, y + oy - 5, x + ox + 5, y + oy + 5), fill=colors["token"])
        elif tokens > 3:
            bbox = draw.textbbox((0, 0), str(tokens), font=token_font)
            draw.text((x - (bbox[2] - bbox[0]) / 2, y - 10), str(tokens), font=token_font, fill=colors["token"])
        _draw_centered_multiline(draw, (x, y + 48), [node_id], small_font, colors["muted"])
        _draw_centered_multiline(draw, (x, y + 70), _wrap(place.get("label", node_id)), label_font, colors["ink"])

    for transition in project.get("transitions", []):
        node_id = transition["id"]
        x, y = positions[node_id]
        fill = colors["accent"] if node_id == last_transition else colors["enabled"] if node_id in enabled else colors["transition"]
        draw.rounded_rectangle((x - 9, y - 39, x + 9, y + 39), radius=2, fill=fill)
        _draw_centered_multiline(draw, (x, y + 50), [node_id], small_font, colors["muted"])
        _draw_centered_multiline(draw, (x, y + 72), _wrap(transition.get("label", node_id)), label_font, colors["ink"])

    legend_y = height - 55
    draw.ellipse((79, legend_y - 11, 101, legend_y + 11), fill=(255, 255, 255), outline=colors["ink"], width=2)
    draw.text((112, legend_y - 9), "позиция", font=label_font, fill=colors["muted"])
    draw.rectangle((225, legend_y - 14, 233, legend_y + 14), fill=colors["transition"])
    draw.text((245, legend_y - 9), "переход", font=label_font, fill=colors["muted"])
    draw.ellipse((361, legend_y - 4, 369, legend_y + 4), fill=colors["token"])
    draw.text((382, legend_y - 9), "маркер", font=label_font, fill=colors["muted"])
    draw.rectangle((485, legend_y - 14, 493, legend_y + 14), fill=colors["enabled"])
    draw.text((505, legend_y - 9), "разрешённый переход", font=label_font, fill=colors["muted"])
    output_path.parent.mkdir(parents=True, exist_ok=True)
    image.save(output_path, format="PNG", optimize=True)
    return output_path
