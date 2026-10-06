from __future__ import annotations

import json
import os
import sys
import traceback
from pathlib import Path
from typing import Any, Callable

from . import __version__
from .core import (
    PetriError,
    analyze_reachability,
    build_attack_project,
    load_project,
    normalize_project,
    save_project,
    simulate,
    validate_project,
)
from .render import render_png, render_svg
from .report import export_report_bundle
from .visualpetri import (
    capture_visualpetri,
    draw_project_in_visualpetri,
    launch_visualpetri,
)


PROTOCOL_VERSION = "2024-11-05"


def default_root() -> Path:
    configured = os.environ.get("PETRI_MCP_HOME")
    return Path(configured).expanduser().resolve() if configured else Path(__file__).resolve().parents[1] / "workspace"


def _project_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "required": ["project_id", "title", "enterprise", "threats", "places", "transitions", "arcs", "initial_marking", "goals"],
        "properties": {
            "project_id": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$"},
            "title": {"type": "string"},
            "description": {"type": "string"},
            "enterprise": {
                "type": "object",
                "description": "Small-enterprise description for assignment 5.3.1: description, rooms, equipment, protected_information, staff.",
            },
            "threats": {
                "type": "array",
                "description": "Complete threat matrix. Every row needs name, asset, detection, frequency, consequences, prevention.",
                "items": {
                    "type": "object",
                    "required": ["name", "asset", "detection", "frequency", "consequences", "prevention"],
                },
            },
            "places": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["id", "label"],
                    "properties": {
                        "id": {"type": "string"},
                        "label": {"type": "string"},
                        "description": {"type": "string"},
                        "x": {"type": "number"},
                        "y": {"type": "number"},
                    },
                },
            },
            "transitions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["id", "label"],
                    "properties": {
                        "id": {"type": "string"},
                        "label": {"type": "string"},
                        "description": {"type": "string"},
                        "x": {"type": "number"},
                        "y": {"type": "number"},
                    },
                },
            },
            "arcs": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["source", "target"],
                    "properties": {
                        "source": {"type": "string"},
                        "target": {"type": "string"},
                        "weight": {"type": "integer", "minimum": 1},
                    },
                },
            },
            "initial_marking": {"type": "object", "additionalProperties": {"type": "integer", "minimum": 0}},
            "goals": {"type": "array", "items": {"type": "string"}},
            "goal_mode": {"type": "string", "enum": ["any", "all"], "default": "any"},
        },
    }


TOOLS: list[dict[str, Any]] = [
    {
        "name": "petri_create_project",
        "description": "Create/update a complete Petri-net project for methodological assignment 5.3 (page 82): enterprise, full threat matrix, places, transitions, arcs, marking and goals.",
        "inputSchema": _project_schema(),
    },
    {
        "name": "petri_build_attack_project",
        "description": "Build a Petri net automatically from one or more attacker paths. Each step becomes a transition (attacker action) and each result becomes a place (state). Saves the project.",
        "inputSchema": {
            "type": "object",
            "required": ["project_id", "title", "enterprise", "threats", "attack_paths"],
            "properties": {
                "project_id": {"type": "string"},
                "title": {"type": "string"},
                "description": {"type": "string"},
                "enterprise": {"type": "object"},
                "threats": {"type": "array", "items": {"type": "object"}},
                "attack_paths": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["steps"],
                        "properties": {
                            "id": {"type": "string"},
                            "entry_conditions": {"type": "array", "items": {"type": "string"}},
                            "goal": {"type": "boolean"},
                            "steps": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "required": ["action", "result"],
                                    "properties": {
                                        "action": {"type": "string"},
                                        "result": {"type": "string"},
                                        "description": {"type": "string"},
                                        "prerequisites": {"type": "array", "items": {"type": "string"}},
                                        "preserve_prerequisites": {"type": "boolean"},
                                    },
                                },
                            },
                        },
                    },
                },
                "goal_mode": {"type": "string", "enum": ["any", "all"]},
            },
        },
    },
    {
        "name": "petri_get_project",
        "description": "Read a saved project including the current marking and firing trace.",
        "inputSchema": {"type": "object", "required": ["project_id"], "properties": {"project_id": {"type": "string"}}},
    },
    {
        "name": "petri_validate_project",
        "description": "Validate assignment completeness and Petri-net correctness: threat fields, bipartite arcs, IDs, marking, goal places, isolated nodes and always-enabled transitions.",
        "inputSchema": {"type": "object", "required": ["project_id"], "properties": {"project_id": {"type": "string"}}},
    },
    {
        "name": "petri_analyze_reachability",
        "description": "Explore reachable markings, find a shortest firing sequence to the attack goal, deadlocks, never-enabled transitions and possible unbounded growth.",
        "inputSchema": {
            "type": "object",
            "required": ["project_id"],
            "properties": {
                "project_id": {"type": "string"},
                "max_states": {"type": "integer", "minimum": 1, "maximum": 50000, "default": 5000},
                "max_depth": {"type": "integer", "minimum": 1, "maximum": 500, "default": 80},
                "max_tokens_per_place": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 50},
            },
        },
    },
    {
        "name": "petri_simulate",
        "description": "Fire transitions step by step, reset marking, or automatically execute the shortest trace to a goal. Persists current marking for later screenshots.",
        "inputSchema": {
            "type": "object",
            "required": ["project_id"],
            "properties": {
                "project_id": {"type": "string"},
                "transition_sequence": {"type": "array", "items": {"type": "string"}},
                "reset": {"type": "boolean", "default": False},
                "auto_to_goal": {"type": "boolean", "default": False},
            },
        },
    },
    {
        "name": "petri_render",
        "description": "Render a clean report-ready diagram in SVG or PNG. Supports initial, current and shortest-goal markings, labels, grid and VisualPetri-like classic styling.",
        "inputSchema": {
            "type": "object",
            "required": ["project_id"],
            "properties": {
                "project_id": {"type": "string"},
                "state": {"type": "string", "enum": ["initial", "current", "goal"], "default": "current"},
                "format": {"type": "string", "enum": ["png", "svg"], "default": "png"},
                "theme": {"type": "string", "enum": ["report", "classic"], "default": "report"},
                "show_grid": {"type": "boolean", "default": True},
                "output_path": {"type": "string", "description": "Optional absolute or working-directory-relative path."},
            },
        },
    },
    {
        "name": "petri_export_report_bundle",
        "description": "Export everything required by assignment 5.3: enterprise text, full threat matrix CSV/Markdown, position/transition descriptions, reachability proof, initial/goal PNG+SVG and optional step frames.",
        "inputSchema": {
            "type": "object",
            "required": ["project_id"],
            "properties": {
                "project_id": {"type": "string"},
                "output_dir": {"type": "string"},
                "include_trace_frames": {"type": "boolean", "default": True},
                "theme": {"type": "string", "enum": ["report", "classic"], "default": "report"},
            },
        },
    },
    {
        "name": "visualpetri_launch",
        "description": "Launch the original VisualPetri.exe on Windows or through Wine. The executable can be supplied or configured via VISUALPETRI_EXE.",
        "inputSchema": {"type": "object", "properties": {"executable_path": {"type": "string"}}},
    },
    {
        "name": "visualpetri_draw_project",
        "description": "On a visible Windows desktop, reproduce a saved MCP project in the original VisualPetri v1.0 through Win32 UI automation and optionally save a .vpn file.",
        "inputSchema": {
            "type": "object",
            "required": ["project_id"],
            "properties": {
                "project_id": {"type": "string"},
                "executable_path": {"type": "string"},
                "save_as": {"type": "string"},
                "clear_existing": {"type": "boolean", "default": True},
            },
        },
    },
    {
        "name": "visualpetri_capture",
        "description": "Capture the visible original VisualPetri window as PNG on Windows.",
        "inputSchema": {"type": "object", "required": ["output_path"], "properties": {"output_path": {"type": "string"}}},
    },
]

TOOL_TITLES = {
    "petri_create_project": "Создать проект сети Петри",
    "petri_build_attack_project": "Построить сеть по путям атаки",
    "petri_get_project": "Получить проект",
    "petri_validate_project": "Проверить проект",
    "petri_analyze_reachability": "Проанализировать достижимость",
    "petri_simulate": "Выполнить переходы",
    "petri_render": "Отрисовать сеть",
    "petri_export_report_bundle": "Собрать материалы для отчёта",
    "visualpetri_launch": "Запустить VisualPetri",
    "visualpetri_draw_project": "Нарисовать проект в VisualPetri",
    "visualpetri_capture": "Снять окно VisualPetri",
}
READ_ONLY_TOOLS = {
    "petri_get_project",
    "petri_validate_project",
    "petri_analyze_reachability",
}
for _tool in TOOLS:
    _tool["title"] = TOOL_TITLES[_tool["name"]]
    _tool["annotations"] = {
        "readOnlyHint": _tool["name"] in READ_ONLY_TOOLS,
        "destructiveHint": False,
        "openWorldHint": False,
    }


ASSIGNMENT_PROMPT = """Выполни практическое задание 5.3 методички (стр. 82) через MCP VisualPetri:
1. Опиши малое предприятие: помещения, оборудование, защищаемая информация, персонал.
2. Составь полную матрицу угроз. Для каждой угрозы обязательно заполни: чему угрожает, как обнаруживается, частота, последствия, предотвращение.
3. Выбери наиболее критичный информационный ресурс и разработай сценарий атаки. Позиции должны быть состояниями/условиями, переходы — действиями нарушителя или событиями. Задай начальную маркировку и конечные цели.
4. Создай проект, проверь его, выполни анализ достижимости и исправь ошибки/предупреждения по существу.
5. Экспортируй report bundle. В отчёт используй petri_initial.png, petri_goal_reached.png, threat_matrix.md, petri_elements.md и reachability_conclusion.md.
Не заявляй недостижимость, если анализ truncated=true. Для схемы с несколькими целями явно выбери goal_mode any или all."""


class PetriServer:
    def __init__(self, root: Path | None = None):
        self.root = (root or default_root()).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "petri_create_project":
            project = normalize_project(arguments)
            validation = validate_project(project)
            if not validation["valid"]:
                raise PetriError("Project was not saved: " + "; ".join(validation["errors"]))
            path = save_project(self.root, project)
            return {"project_id": project["project_id"], "path": str(path), "validation": validation}
        if name == "petri_build_attack_project":
            project = build_attack_project(arguments)
            validation = validate_project(project)
            if not validation["valid"]:
                raise PetriError("Generated project is invalid: " + "; ".join(validation["errors"]))
            path = save_project(self.root, project)
            return {"project_id": project["project_id"], "path": str(path), "validation": validation}

        project_id = arguments.get("project_id")
        if name in {
            "petri_get_project",
            "petri_validate_project",
            "petri_analyze_reachability",
            "petri_simulate",
            "petri_render",
            "petri_export_report_bundle",
            "visualpetri_draw_project",
        }:
            project = load_project(self.root, project_id)
        if name == "petri_get_project":
            return project
        if name == "petri_validate_project":
            return validate_project(project)
        if name == "petri_analyze_reachability":
            return analyze_reachability(
                project,
                max_states=arguments.get("max_states", 5000),
                max_depth=arguments.get("max_depth", 80),
                max_tokens_per_place=arguments.get("max_tokens_per_place", 50),
            )
        if name == "petri_simulate":
            result = simulate(
                project,
                arguments.get("transition_sequence"),
                reset=arguments.get("reset", False),
                auto_to_goal=arguments.get("auto_to_goal", False),
            )
            save_project(self.root, project)
            return result
        if name == "petri_render":
            state = arguments.get("state", "current")
            extension = arguments.get("format", "png")
            if state == "initial":
                marking = project["initial_marking"]
                subtitle = "Начальная маркировка"
                last_transition = None
            elif state == "goal":
                analysis = analyze_reachability(project)
                if not analysis["goal_reachable"]:
                    raise PetriError("A reachable goal marking was not found")
                marking = analysis["goal_marking"]
                subtitle = "Конечная цель атаки достигнута"
                last_transition = analysis["shortest_goal_trace"][-1] if analysis["shortest_goal_trace"] else None
            else:
                marking = project["current_marking"]
                subtitle = "Текущая маркировка"
                last_transition = project.get("trace", [])[-1] if project.get("trace") else None
            output = arguments.get("output_path")
            path = Path(output).expanduser() if output else self.root / "exports" / project_id / f"petri_{state}.{extension}"
            if not path.is_absolute():
                path = (Path.cwd() / path).resolve()
            renderer: Callable[..., Path] = render_png if extension == "png" else render_svg
            renderer(
                project,
                marking,
                path,
                title=project.get("title"),
                subtitle=subtitle,
                theme=arguments.get("theme", "report"),
                show_grid=arguments.get("show_grid", True),
                last_transition=last_transition,
            )
            return {"path": str(path), "state": state, "format": extension, "marking": marking}
        if name == "petri_export_report_bundle":
            output = arguments.get("output_dir")
            path = Path(output).expanduser() if output else self.root / "exports" / project_id / "report_bundle"
            if not path.is_absolute():
                path = (Path.cwd() / path).resolve()
            return export_report_bundle(
                project,
                path,
                include_trace_frames=arguments.get("include_trace_frames", True),
                theme=arguments.get("theme", "report"),
            )
        if name == "visualpetri_launch":
            return launch_visualpetri(arguments.get("executable_path"))
        if name == "visualpetri_draw_project":
            return draw_project_in_visualpetri(
                project,
                executable_path=arguments.get("executable_path"),
                save_as=arguments.get("save_as"),
                clear_existing=arguments.get("clear_existing", True),
            )
        if name == "visualpetri_capture":
            return capture_visualpetri(arguments["output_path"])
        raise PetriError(f"Unknown tool: {name}")

    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        method = message.get("method")
        request_id = message.get("id")
        if request_id is None:
            return None
        if method == "initialize":
            requested = message.get("params", {}).get("protocolVersion")
            version = requested if requested in {"2024-11-05", "2025-03-26", "2025-06-18"} else PROTOCOL_VERSION
            result = {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}, "prompts": {"listChanged": False}},
                "serverInfo": {"name": "visualpetri-mcp", "version": __version__},
                "instructions": "Use the complete-assignment-5-3 prompt or the Petri tools. Always validate and analyze before export.",
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            params = message.get("params", {})
            try:
                payload = self.call_tool(params.get("name", ""), params.get("arguments") or {})
                result = {
                    "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False, indent=2)}],
                    "structuredContent": payload,
                    "isError": False,
                }
            except Exception as exc:
                result = {
                    "content": [{"type": "text", "text": f"{type(exc).__name__}: {exc}"}],
                    "isError": True,
                }
        elif method == "prompts/list":
            result = {
                "prompts": [
                    {
                        "name": "complete-assignment-5-3",
                        "description": "Workflow for the practical assignment that begins on methodological guide page 76 and is specified on page 82.",
                        "arguments": [],
                    }
                ]
            }
        elif method == "prompts/get":
            name = message.get("params", {}).get("name")
            if name != "complete-assignment-5-3":
                return self._error(request_id, -32602, f"Unknown prompt: {name}")
            result = {"description": "Задание 5.3, стр. 82", "messages": [{"role": "user", "content": {"type": "text", "text": ASSIGNMENT_PROMPT}}]}
        else:
            return self._error(request_id, -32601, f"Method not found: {method}")
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    @staticmethod
    def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def main() -> None:
    server = PetriServer()
    for raw_line in sys.stdin.buffer:
        if not raw_line.strip():
            continue
        try:
            message = json.loads(raw_line)
            response = server.handle(message)
            if response is not None:
                sys.stdout.write(json.dumps(response, ensure_ascii=False, separators=(",", ":")) + "\n")
                sys.stdout.flush()
        except Exception as exc:
            traceback.print_exc(file=sys.stderr)
            request_id = message.get("id") if isinstance(locals().get("message"), dict) else None
            if request_id is not None:
                response = server._error(request_id, -32603, f"Internal error: {exc}")
                sys.stdout.write(json.dumps(response, ensure_ascii=False, separators=(",", ":")) + "\n")
                sys.stdout.flush()


if __name__ == "__main__":
    main()
