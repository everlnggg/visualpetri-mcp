from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from petri_mcp.core import (
    PetriError,
    analyze_reachability,
    build_attack_project,
    enabled_transitions,
    fire_transition,
    load_project,
    normalize_project,
    save_project,
    validate_project,
)
from petri_mcp.report import export_report_bundle
from petri_mcp.server import PetriServer


REPO = Path(__file__).resolve().parents[1]


class PetriCoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec = json.loads((REPO / "examples" / "insider_attack.json").read_text(encoding="utf-8"))

    def test_demo_is_valid_and_goal_reachable(self):
        project = normalize_project(self.spec)
        validation = validate_project(project)
        self.assertTrue(validation["valid"], validation)
        analysis = analyze_reachability(project)
        self.assertTrue(analysis["goal_reachable"])
        self.assertEqual(analysis["shortest_goal_trace"], ["t1", "t2", "t3"])
        self.assertEqual(analysis["goal_marking"]["p7"], 1)
        self.assertFalse(analysis["truncated"])

    def test_transition_rule(self):
        project = normalize_project(self.spec)
        self.assertEqual(enabled_transitions(project, project["initial_marking"]), ["t1"])
        marking = fire_transition(project, project["initial_marking"], "t1")
        self.assertEqual(marking["p4"], 1)
        with self.assertRaises(PetriError):
            fire_transition(project, marking, "t1")

    def test_invalid_same_type_arc(self):
        project = normalize_project(self.spec)
        project["arcs"].append({"source": "p1", "target": "p2", "weight": 1})
        validation = validate_project(project)
        self.assertFalse(validation["valid"])
        self.assertTrue(any("bipartiteness" in value for value in validation["errors"]))

    def test_save_load_and_bundle(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project = normalize_project(self.spec)
            save_project(root, project)
            loaded = load_project(root, project["project_id"])
            self.assertEqual(loaded["title"], project["title"])
            manifest = export_report_bundle(loaded, root / "bundle", include_trace_frames=True)
            self.assertTrue(manifest["goal_reachable"])
            expected = [
                "petri_initial.png",
                "petri_goal_reached.png",
                "threat_matrix.md",
                "petri_elements.md",
                "reachability_conclusion.md",
            ]
            for filename in expected:
                path = root / "bundle" / filename
                self.assertTrue(path.exists(), filename)
                self.assertGreater(path.stat().st_size, 100)

    def test_mcp_handshake_and_tools(self):
        with tempfile.TemporaryDirectory() as temp:
            server = PetriServer(Path(temp))
            initialize = server.handle(
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}}
            )
            self.assertEqual(initialize["result"]["serverInfo"]["name"], "visualpetri-mcp")
            tools = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
            names = {tool["name"] for tool in tools["result"]["tools"]}
            self.assertIn("petri_export_report_bundle", names)
            self.assertIn("visualpetri_draw_project", names)

    def test_high_level_attack_builder(self):
        project = build_attack_project(
            {
                "project_id": "builder_demo",
                "title": "Автоматически построенный путь атаки",
                "enterprise": self.spec["enterprise"],
                "threats": self.spec["threats"],
                "attack_paths": [
                    {
                        "id": "remote",
                        "entry_conditions": ["Есть доступ в Интернет"],
                        "steps": [
                            {"action": "Отправить фишинговое письмо", "result": "Пользователь открыл вложение"},
                            {"action": "Запустить вредоносный код", "result": "АРМ скомпрометировано"},
                        ],
                    }
                ],
            }
        )
        self.assertTrue(validate_project(project)["valid"])
        self.assertTrue(analyze_reachability(project)["goal_reachable"])


if __name__ == "__main__":
    unittest.main()
