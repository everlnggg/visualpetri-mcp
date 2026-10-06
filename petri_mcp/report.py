from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .core import analyze_reachability, write_csv
from .render import render_png, render_svg


THREAT_COLUMNS = [
    "id",
    "name",
    "asset",
    "detection",
    "frequency",
    "consequences",
    "prevention",
    "likelihood",
    "impact",
    "priority",
    "loss",
]


def _md_cell(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        value = "; ".join(map(str, value))
    return str(value or "").replace("|", "\\|").replace("\n", "<br>")


def markdown_table(rows: list[dict[str, Any]], columns: list[tuple[str, str]]) -> str:
    header = "| " + " | ".join(title for _, title in columns) + " |"
    separator = "| " + " | ".join("---" for _ in columns) + " |"
    body = [
        "| " + " | ".join(_md_cell(row.get(key, "")) for key, _ in columns) + " |"
        for row in rows
    ]
    return "\n".join([header, separator, *body])


def threat_matrix_markdown(project: dict[str, Any]) -> str:
    columns = [
        ("id", "ID"),
        ("name", "Угроза"),
        ("asset", "Чему угрожает"),
        ("detection", "Как обнаруживается"),
        ("frequency", "Частота"),
        ("consequences", "Последствия"),
        ("prevention", "Как предотвращается"),
    ]
    return "# Полная матрица угроз\n\n" + markdown_table(project.get("threats", []), columns) + "\n"


def elements_markdown(project: dict[str, Any]) -> str:
    place_rows = []
    for place in project.get("places", []):
        place_rows.append(
            {
                **place,
                "tokens": project.get("initial_marking", {}).get(place["id"], 0),
                "goal": "да" if place["id"] in project.get("goals", []) else "нет",
            }
        )
    transition_rows = project.get("transitions", [])
    arc_rows = project.get("arcs", [])
    return "\n".join(
        [
            "# Структура разработанной сети Петри",
            "",
            "## Позиции",
            "",
            markdown_table(
                place_rows,
                [
                    ("id", "ID"),
                    ("label", "Название состояния или условия"),
                    ("description", "Подробное описание"),
                    ("tokens", "Начальная маркировка"),
                    ("goal", "Конечная цель"),
                ],
            ),
            "",
            "## Переходы",
            "",
            markdown_table(
                transition_rows,
                [
                    ("id", "ID"),
                    ("label", "Действие нарушителя или событие"),
                    ("description", "Подробное описание"),
                ],
            ),
            "",
            "## Дуги",
            "",
            markdown_table(
                arc_rows,
                [("source", "Источник"), ("target", "Приёмник"), ("weight", "Вес")],
            ),
            "",
        ]
    )


def enterprise_markdown(project: dict[str, Any]) -> str:
    enterprise = project.get("enterprise", {})
    rooms = enterprise.get("rooms", [])
    equipment = enterprise.get("equipment", [])
    information = enterprise.get("protected_information", [])
    staff = enterprise.get("staff", [])
    lines = [
        "# Структура малого предприятия",
        "",
        str(enterprise.get("description", project.get("description", ""))),
        "",
    ]
    sections = [
        ("Помещения", rooms),
        ("Оборудование для обработки защищаемой информации", equipment),
        ("Защищаемая информация", information),
        ("Персонал и нарушители", staff),
    ]
    for title, values in sections:
        lines.extend([f"## {title}", ""])
        if values:
            for value in values:
                if isinstance(value, dict):
                    name = value.get("name") or value.get("id") or "Элемент"
                    description = value.get("description", "")
                    lines.append(f"- **{name}** — {description}" if description else f"- {name}")
                else:
                    lines.append(f"- {value}")
        else:
            lines.append("- Не указано")
        lines.append("")
    return "\n".join(lines)


def analysis_markdown(project: dict[str, Any], analysis: dict[str, Any]) -> str:
    labels = {t["id"]: t.get("label", t["id"]) for t in project.get("transitions", [])}
    place_labels = {p["id"]: p.get("label", p["id"]) for p in project.get("places", [])}
    goals = ", ".join(f"{goal} — {place_labels.get(goal, goal)}" for goal in project.get("goals", [])) or "не заданы"
    if analysis["goal_reachable"]:
        conclusion = "Конечная цель атаки достижима."
        trace = " → ".join(
            f"{transition_id} ({labels.get(transition_id, transition_id)})"
            for transition_id in analysis["shortest_goal_trace"]
        ) or "цель присутствует уже в начальной маркировке"
    elif analysis["truncated"]:
        conclusion = "В исследованной части пространства состояний цель не достигнута; анализ ограничен заданными пределами."
        trace = "не найден в пределах анализа"
    else:
        conclusion = "Конечная цель атаки недостижима из заданной начальной маркировки."
        trace = "не существует"
    return "\n".join(
        [
            "# Анализ достижимости конечных целей атаки",
            "",
            f"**Целевые позиции:** {goals}.",
            "",
            f"**Вывод:** {conclusion}",
            "",
            f"**Кратчайшая последовательность запусков:** {trace}.",
            "",
            f"Исследовано маркировок: {analysis['states_explored']}; максимальная глубина: {analysis['max_depth_reached']}; тупиковых маркировок: {analysis['deadlock_count']}.",
            "",
            "Переходы, которые ни разу не были разрешены: "
            + (", ".join(analysis["never_enabled_transitions"]) or "нет")
            + ".",
            "",
            "Анализ был усечён установленными пределами: "
            + ("да" if analysis["truncated"] else "нет")
            + ".",
            "",
        ]
    )


def export_report_bundle(
    project: dict[str, Any],
    output_dir: Path,
    *,
    include_trace_frames: bool = True,
    theme: str = "report",
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    analysis = analyze_reachability(project)
    files: list[Path] = []

    project_file = output_dir / "project.json"
    project_file.write_text(json.dumps(project, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    files.append(project_file)
    analysis_json = output_dir / "reachability.json"
    analysis_json.write_text(json.dumps(analysis, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    files.append(analysis_json)

    documents = {
        "enterprise.md": enterprise_markdown(project),
        "threat_matrix.md": threat_matrix_markdown(project),
        "petri_elements.md": elements_markdown(project),
        "reachability_conclusion.md": analysis_markdown(project, analysis),
    }
    for filename, content in documents.items():
        path = output_dir / filename
        path.write_text(content, encoding="utf-8")
        files.append(path)

    threat_csv = output_dir / "threat_matrix.csv"
    write_csv(threat_csv, project.get("threats", []), THREAT_COLUMNS)
    files.append(threat_csv)

    initial = project["initial_marking"]
    for extension, renderer in (("svg", render_svg), ("png", render_png)):
        path = output_dir / f"petri_initial.{extension}"
        renderer(
            project,
            initial,
            path,
            title=project.get("title"),
            subtitle="Начальная маркировка",
            theme=theme,
        )
        files.append(path)

    if analysis["goal_reachable"] and analysis["goal_marking"] is not None:
        goal_marking = analysis["goal_marking"]
        last_transition = analysis["shortest_goal_trace"][-1] if analysis["shortest_goal_trace"] else None
        trace_text = " → ".join(analysis["shortest_goal_trace"]) or "цель в начальной маркировке"
        for extension, renderer in (("svg", render_svg), ("png", render_png)):
            path = output_dir / f"petri_goal_reached.{extension}"
            renderer(
                project,
                goal_marking,
                path,
                title=project.get("title"),
                subtitle=f"Конечная цель достигнута: {trace_text}",
                theme=theme,
                last_transition=last_transition,
            )
            files.append(path)

    if include_trace_frames and analysis["goal_reachable"]:
        frames_dir = output_dir / "trace_frames"
        frames_dir.mkdir(exist_ok=True)
        for index, marking in enumerate(analysis["trace_markings"]):
            transition_id = analysis["shortest_goal_trace"][index - 1] if index else None
            path = frames_dir / f"step_{index:02d}.png"
            render_png(
                project,
                marking,
                path,
                title=project.get("title"),
                subtitle="Начальная маркировка" if index == 0 else f"Шаг {index}: {transition_id}",
                theme=theme,
                last_transition=transition_id,
            )
            files.append(path)

    manifest = {
        "project_id": project["project_id"],
        "goal_reachable": analysis["goal_reachable"],
        "shortest_goal_trace": analysis["shortest_goal_trace"],
        "files": [str(path.resolve()) for path in files],
        "report_mapping": {
            "assignment_5_3_1_enterprise": str((output_dir / "enterprise.md").resolve()),
            "assignment_5_3_2_threat_matrix": str((output_dir / "threat_matrix.md").resolve()),
            "assignment_5_3_3_scenario_and_runs": [
                str((output_dir / "petri_initial.png").resolve()),
                str((output_dir / "petri_goal_reached.png").resolve()) if analysis["goal_reachable"] else None,
                str(analysis_json.resolve()),
            ],
            "assignment_5_3_4_elements_and_conclusion": [
                str((output_dir / "petri_elements.md").resolve()),
                str((output_dir / "reachability_conclusion.md").resolve()),
            ],
        },
    }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    manifest["files"].append(str(manifest_path.resolve()))
    return manifest

