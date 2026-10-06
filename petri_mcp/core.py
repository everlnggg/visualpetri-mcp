from __future__ import annotations

import csv
import hashlib
import json
import re
from collections import Counter, defaultdict, deque
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


PROJECT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
THREAT_REQUIRED_FIELDS = (
    "name",
    "asset",
    "detection",
    "frequency",
    "consequences",
    "prevention",
)


class PetriError(ValueError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def safe_project_id(value: str) -> str:
    if not isinstance(value, str) or not PROJECT_ID_RE.fullmatch(value):
        raise PetriError(
            "project_id must match [A-Za-z0-9][A-Za-z0-9_.-]{0,63}"
        )
    return value


def project_path(root: Path, project_id: str) -> Path:
    return root / "projects" / safe_project_id(project_id) / "project.json"


def canonical_marking(marking: dict[str, int], place_ids: Iterable[str]) -> dict[str, int]:
    ids = list(place_ids)
    result: dict[str, int] = {}
    unknown = set(marking) - set(ids)
    if unknown:
        raise PetriError(f"Unknown places in marking: {sorted(unknown)}")
    for place_id in ids:
        value = marking.get(place_id, 0)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise PetriError(f"Marking for {place_id!r} must be a non-negative integer")
        result[place_id] = value
    return result


def normalize_project(spec: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(spec, dict):
        raise PetriError("Project specification must be a JSON object")
    project = deepcopy(spec)
    project["project_id"] = safe_project_id(project.get("project_id", ""))
    project["title"] = str(project.get("title") or project["project_id"])
    project.setdefault("description", "")
    project.setdefault("enterprise", {})
    project.setdefault("threats", [])
    project.setdefault("places", [])
    project.setdefault("transitions", [])
    project.setdefault("arcs", [])
    project.setdefault("goals", [])
    project.setdefault("goal_mode", "any")
    project.setdefault("layout", {"direction": "LR"})

    for place in project["places"]:
        place.setdefault("label", place.get("id", ""))
        place.setdefault("description", "")
        place.setdefault("kind", "state")
    for transition in project["transitions"]:
        transition.setdefault("label", transition.get("id", ""))
        transition.setdefault("description", "")
        transition.setdefault("kind", "action")
    for arc in project["arcs"]:
        arc.setdefault("weight", 1)
    for index, threat in enumerate(project["threats"], start=1):
        threat.setdefault("id", f"TH{index}")

    place_ids = [str(place.get("id", "")) for place in project["places"]]
    project["initial_marking"] = canonical_marking(
        project.get("initial_marking", {}), place_ids
    )
    current = project.get("current_marking", project["initial_marking"])
    project["current_marking"] = canonical_marking(current, place_ids)
    project.setdefault("trace", [])
    project.setdefault("created_at", utc_now())
    project["updated_at"] = utc_now()
    return project


def save_project(root: Path, project: dict[str, Any]) -> Path:
    normalized = normalize_project(project)
    path = project_path(root, normalized["project_id"])
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        history_dir = path.parent / ".history"
        history_dir.mkdir(exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        (history_dir / f"{stamp}.json").write_bytes(path.read_bytes())
    path.write_text(
        json.dumps(normalized, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return path


def load_project(root: Path, project_id: str) -> dict[str, Any]:
    path = project_path(root, project_id)
    if not path.exists():
        raise PetriError(f"Project {project_id!r} does not exist")
    return json.loads(path.read_text(encoding="utf-8"))


def _ids(items: list[dict[str, Any]], kind: str) -> tuple[list[str], list[str]]:
    values: list[str] = []
    errors: list[str] = []
    for index, item in enumerate(items):
        value = item.get("id")
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{kind}[{index}] has no non-empty id")
            continue
        values.append(value)
    duplicates = sorted(k for k, count in Counter(values).items() if count > 1)
    if duplicates:
        errors.append(f"Duplicate {kind} ids: {duplicates}")
    return values, errors


def validate_project(project: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    places = project.get("places", [])
    transitions = project.get("transitions", [])
    arcs = project.get("arcs", [])
    threats = project.get("threats", [])
    enterprise = project.get("enterprise", {})

    if not places:
        errors.append("The net has no places")
    if not transitions:
        errors.append("The net has no transitions")
    place_ids, id_errors = _ids(places, "place")
    errors.extend(id_errors)
    transition_ids, id_errors = _ids(transitions, "transition")
    errors.extend(id_errors)
    overlap = sorted(set(place_ids) & set(transition_ids))
    if overlap:
        errors.append(f"Ids are shared by places and transitions: {overlap}")

    place_set = set(place_ids)
    transition_set = set(transition_ids)
    node_set = place_set | transition_set
    degree: Counter[str] = Counter()
    for index, arc in enumerate(arcs):
        source, target = arc.get("source"), arc.get("target")
        weight = arc.get("weight", 1)
        if source not in node_set:
            errors.append(f"arc[{index}] has unknown source {source!r}")
        if target not in node_set:
            errors.append(f"arc[{index}] has unknown target {target!r}")
        if (source in place_set and target in place_set) or (
            source in transition_set and target in transition_set
        ):
            errors.append(
                f"arc[{index}] violates Petri bipartiteness: {source!r} -> {target!r}"
            )
        if isinstance(weight, bool) or not isinstance(weight, int) or weight <= 0:
            errors.append(f"arc[{index}] weight must be a positive integer")
        if source in node_set:
            degree[source] += 1
        if target in node_set:
            degree[target] += 1

    isolated = sorted(node_set - set(degree))
    if isolated:
        warnings.append(f"Isolated nodes: {isolated}")

    try:
        canonical_marking(project.get("initial_marking", {}), place_ids)
    except PetriError as exc:
        errors.append(str(exc))
    goals = project.get("goals", [])
    unknown_goals = sorted(set(goals) - place_set)
    if unknown_goals:
        errors.append(f"Unknown goal places: {unknown_goals}")
    if not goals:
        warnings.append("No goal places are defined; reachability cannot answer the assignment")
    if project.get("goal_mode", "any") not in {"any", "all"}:
        errors.append("goal_mode must be 'any' or 'all'")

    if not isinstance(enterprise, dict):
        errors.append("enterprise must be an object")
    else:
        for field in ("description", "rooms", "equipment", "protected_information"):
            if not enterprise.get(field):
                errors.append(f"enterprise.{field} is required by assignment 5.3.1")

    for index, threat in enumerate(threats):
        missing = [field for field in THREAT_REQUIRED_FIELDS if not threat.get(field)]
        if missing:
            errors.append(
                f"threat[{index}] is incomplete; missing assignment fields: {missing}"
            )
    if not threats:
        errors.append("Threat matrix is empty; assignment 5.3.2 requires a complete threat set")

    incoming: Counter[str] = Counter()
    outgoing: Counter[str] = Counter()
    for arc in arcs:
        if arc.get("target") in node_set:
            incoming[arc["target"]] += 1
        if arc.get("source") in node_set:
            outgoing[arc["source"]] += 1
    source_transitions = sorted(t for t in transition_set if incoming[t] == 0)
    if source_transitions:
        warnings.append(
            f"Transitions without input places are always enabled: {source_transitions}"
        )
    sink_transitions = sorted(t for t in transition_set if outgoing[t] == 0)
    if sink_transitions:
        warnings.append(f"Transitions without output places: {sink_transitions}")

    return {
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "summary": {
            "places": len(places),
            "transitions": len(transitions),
            "arcs": len(arcs),
            "threats": len(threats),
            "goals": len(goals),
        },
    }


@dataclass(frozen=True)
class NetIndex:
    place_ids: tuple[str, ...]
    transition_ids: tuple[str, ...]
    inputs: dict[str, dict[str, int]]
    outputs: dict[str, dict[str, int]]


def index_net(project: dict[str, Any]) -> NetIndex:
    place_ids = tuple(place["id"] for place in project["places"])
    transition_ids = tuple(transition["id"] for transition in project["transitions"])
    place_set, transition_set = set(place_ids), set(transition_ids)
    inputs: dict[str, dict[str, int]] = {t: defaultdict(int) for t in transition_ids}
    outputs: dict[str, dict[str, int]] = {t: defaultdict(int) for t in transition_ids}
    for arc in project["arcs"]:
        source, target, weight = arc["source"], arc["target"], arc.get("weight", 1)
        if source in place_set and target in transition_set:
            inputs[target][source] += weight
        elif source in transition_set and target in place_set:
            outputs[source][target] += weight
    return NetIndex(place_ids, transition_ids, inputs, outputs)


def enabled_transitions(
    project: dict[str, Any], marking: dict[str, int]
) -> list[str]:
    index = index_net(project)
    return [
        transition_id
        for transition_id in index.transition_ids
        if all(marking.get(place_id, 0) >= weight for place_id, weight in index.inputs[transition_id].items())
    ]


def fire_transition(
    project: dict[str, Any], marking: dict[str, int], transition_id: str
) -> dict[str, int]:
    index = index_net(project)
    if transition_id not in index.transition_ids:
        raise PetriError(f"Unknown transition {transition_id!r}")
    if transition_id not in enabled_transitions(project, marking):
        missing = {
            place_id: weight - marking.get(place_id, 0)
            for place_id, weight in index.inputs[transition_id].items()
            if marking.get(place_id, 0) < weight
        }
        raise PetriError(f"Transition {transition_id!r} is not enabled; missing tokens: {missing}")
    result = dict(marking)
    for place_id, weight in index.inputs[transition_id].items():
        result[place_id] -= weight
    for place_id, weight in index.outputs[transition_id].items():
        result[place_id] += weight
    return result


def _state(marking: dict[str, int], place_ids: tuple[str, ...]) -> tuple[int, ...]:
    return tuple(marking.get(place_id, 0) for place_id in place_ids)


def _marking(state: tuple[int, ...], place_ids: tuple[str, ...]) -> dict[str, int]:
    return dict(zip(place_ids, state))


def goal_satisfied(project: dict[str, Any], marking: dict[str, int]) -> bool:
    goals = project.get("goals", [])
    if not goals:
        return False
    tests = [marking.get(place_id, 0) > 0 for place_id in goals]
    return all(tests) if project.get("goal_mode", "any") == "all" else any(tests)


def analyze_reachability(
    project: dict[str, Any],
    *,
    max_states: int = 5000,
    max_depth: int = 80,
    max_tokens_per_place: int = 50,
) -> dict[str, Any]:
    validation = validate_project(project)
    if not validation["valid"]:
        raise PetriError("Invalid project: " + "; ".join(validation["errors"]))
    index = index_net(project)
    initial_marking = canonical_marking(project["initial_marking"], index.place_ids)
    initial = _state(initial_marking, index.place_ids)
    queue = deque([initial])
    depth = {initial: 0}
    parent: dict[tuple[int, ...], tuple[tuple[int, ...], str]] = {}
    transition_fired_count: Counter[str] = Counter()
    transition_enabled_count: Counter[str] = Counter()
    deadlocks: list[tuple[int, ...]] = []
    first_goal: tuple[int, ...] | None = initial if goal_satisfied(project, initial_marking) else None
    reached_goal_places: set[str] = {
        goal for goal in project.get("goals", []) if initial_marking.get(goal, 0) > 0
    }
    truncated = False
    bound_exceeded = False
    possible_unbounded = False

    while queue:
        state = queue.popleft()
        marking = _marking(state, index.place_ids)
        enabled = enabled_transitions(project, marking)
        transition_enabled_count.update(enabled)
        if not enabled:
            deadlocks.append(state)
        if depth[state] >= max_depth:
            if enabled:
                truncated = True
            continue
        for transition_id in enabled:
            transition_fired_count[transition_id] += 1
            next_marking = fire_transition(project, marking, transition_id)
            if any(value > max_tokens_per_place for value in next_marking.values()):
                bound_exceeded = True
                truncated = True
                continue
            next_state = _state(next_marking, index.place_ids)
            if next_state in depth:
                continue
            ancestor = state
            while ancestor in parent:
                if all(a <= b for a, b in zip(ancestor, next_state)) and any(
                    a < b for a, b in zip(ancestor, next_state)
                ):
                    possible_unbounded = True
                    break
                ancestor = parent[ancestor][0]
            parent[next_state] = (state, transition_id)
            depth[next_state] = depth[state] + 1
            for goal in project.get("goals", []):
                if next_marking.get(goal, 0) > 0:
                    reached_goal_places.add(goal)
            if first_goal is None and goal_satisfied(project, next_marking):
                first_goal = next_state
            queue.append(next_state)
            if len(depth) >= max_states:
                truncated = True
                queue.clear()
                break

    trace: list[str] = []
    trace_markings: list[dict[str, int]] = [initial_marking]
    goal_marking: dict[str, int] | None = None
    if first_goal is not None:
        cursor = first_goal
        reversed_steps: list[tuple[str, tuple[int, ...]]] = []
        while cursor != initial:
            prev, transition_id = parent[cursor]
            reversed_steps.append((transition_id, cursor))
            cursor = prev
        for transition_id, state in reversed(reversed_steps):
            trace.append(transition_id)
            trace_markings.append(_marking(state, index.place_ids))
        goal_marking = _marking(first_goal, index.place_ids)

    labels = {t["id"]: t.get("label", t["id"]) for t in project["transitions"]}
    goals = set(project.get("goals", []))
    result = {
        "states_explored": len(depth),
        "max_depth_reached": max(depth.values(), default=0),
        "truncated": truncated,
        "token_bound_exceeded": bound_exceeded,
        "possible_unbounded": possible_unbounded,
        "goal_reachable": first_goal is not None,
        "goal_mode": project.get("goal_mode", "any"),
        "reachable_goal_places": sorted(reached_goal_places),
        "unreachable_goal_places": sorted(goals - reached_goal_places),
        "shortest_goal_trace": trace,
        "shortest_goal_trace_labels": [labels[t] for t in trace],
        "goal_marking": goal_marking,
        "trace_markings": trace_markings,
        "initially_enabled": enabled_transitions(project, initial_marking),
        "deadlock_count": len(deadlocks),
        "deadlocks_sample": [
            _marking(state, index.place_ids) for state in deadlocks[:20]
        ],
        "never_enabled_transitions": sorted(
            set(index.transition_ids) - set(transition_enabled_count)
        ),
        "never_fired_transitions": sorted(
            set(index.transition_ids) - set(transition_fired_count)
        ),
        "limits": {
            "max_states": max_states,
            "max_depth": max_depth,
            "max_tokens_per_place": max_tokens_per_place,
        },
    }
    payload = json.dumps(result, ensure_ascii=False, sort_keys=True).encode("utf-8")
    result["analysis_sha256"] = hashlib.sha256(payload).hexdigest()
    return result


def simulate(
    project: dict[str, Any],
    transition_sequence: list[str] | None = None,
    *,
    reset: bool = False,
    auto_to_goal: bool = False,
) -> dict[str, Any]:
    if reset:
        project["current_marking"] = dict(project["initial_marking"])
        project["trace"] = []
    marking = dict(project.get("current_marking", project["initial_marking"]))
    sequence = list(transition_sequence or [])
    if auto_to_goal:
        analysis = analyze_reachability(project)
        if not analysis["goal_reachable"]:
            raise PetriError("No goal marking is reachable within the analysis limits")
        sequence.extend(analysis["shortest_goal_trace"])
    frames = [dict(marking)]
    fired: list[str] = []
    for transition_id in sequence:
        marking = fire_transition(project, marking, transition_id)
        fired.append(transition_id)
        frames.append(dict(marking))
    project["current_marking"] = marking
    project.setdefault("trace", []).extend(fired)
    project["updated_at"] = utc_now()
    return {
        "fired": fired,
        "marking": marking,
        "frames": frames,
        "enabled_transitions": enabled_transitions(project, marking),
        "goal_reached": goal_satisfied(project, marking),
    }


def build_attack_project(spec: dict[str, Any]) -> dict[str, Any]:
    """Create a valid net from attack paths while retaining human-readable semantics."""
    project_id = safe_project_id(spec.get("project_id", ""))
    places: list[dict[str, Any]] = []
    transitions: list[dict[str, Any]] = []
    arcs: list[dict[str, Any]] = []
    initial_marking: dict[str, int] = {}
    label_to_place: dict[str, str] = {}

    def slug(prefix: str, value: str, number: int) -> str:
        ascii_part = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").lower()
        return f"{prefix}_{ascii_part[:28] or number}"

    def ensure_place(label: str, *, kind: str = "state", initial_tokens: int = 0) -> str:
        key = label.strip().casefold()
        if key in label_to_place:
            place_id = label_to_place[key]
            initial_marking[place_id] = max(initial_marking.get(place_id, 0), initial_tokens)
            return place_id
        candidate = slug("p", label, len(places) + 1)
        used = {place["id"] for place in places}
        place_id = candidate
        suffix = 2
        while place_id in used:
            place_id = f"{candidate}_{suffix}"
            suffix += 1
        places.append({"id": place_id, "label": label, "kind": kind})
        initial_marking[place_id] = initial_tokens
        label_to_place[key] = place_id
        return place_id

    goals: list[str] = []
    paths = spec.get("attack_paths", [])
    if not paths:
        raise PetriError("attack_paths must contain at least one path")
    for path_index, path in enumerate(paths, start=1):
        previous_places = [
            ensure_place(str(label), kind="resource", initial_tokens=1)
            for label in path.get("entry_conditions", ["Нарушитель готов к атаке"])
        ]
        steps = path.get("steps", [])
        if not steps:
            raise PetriError(f"attack_paths[{path_index - 1}] has no steps")
        for step_index, step in enumerate(steps, start=1):
            action = str(step.get("action") or f"Шаг {step_index}")
            result = str(step.get("result") or f"Результат шага {step_index}")
            transition_id = f"t{path_index}_{step_index}"
            transitions.append(
                {
                    "id": transition_id,
                    "label": action,
                    "description": str(step.get("description", "")),
                    "path": str(path.get("id", path_index)),
                }
            )
            prerequisites = [
                ensure_place(str(label), kind="condition", initial_tokens=1)
                for label in step.get("prerequisites", [])
            ]
            for place_id in dict.fromkeys(previous_places + prerequisites):
                arcs.append({"source": place_id, "target": transition_id, "weight": 1})
            result_place = ensure_place(
                result, kind="goal" if step_index == len(steps) else "state"
            )
            arcs.append({"source": transition_id, "target": result_place, "weight": 1})
            if step.get("preserve_prerequisites", True):
                for place_id in prerequisites:
                    arcs.append({"source": transition_id, "target": place_id, "weight": 1})
            previous_places = [result_place]
        final_place = previous_places[0]
        if path.get("goal", True):
            goals.append(final_place)

    project = {
        "project_id": project_id,
        "title": spec.get("title", "Сценарий действий нарушителя"),
        "description": spec.get("description", ""),
        "enterprise": spec.get("enterprise", {}),
        "threats": spec.get("threats", []),
        "places": places,
        "transitions": transitions,
        "arcs": arcs,
        "initial_marking": initial_marking,
        "goals": list(dict.fromkeys(goals)),
        "goal_mode": spec.get("goal_mode", "any"),
        "layout": {"direction": spec.get("direction", "LR")},
    }
    return normalize_project(project)


def write_csv(path: Path, rows: list[dict[str, Any]], columns: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
