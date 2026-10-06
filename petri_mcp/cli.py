from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .core import analyze_reachability, load_project, normalize_project, save_project, validate_project
from .report import export_report_bundle
from .server import default_root


def main() -> None:
    parser = argparse.ArgumentParser(description="VisualPetri MCP companion CLI")
    parser.add_argument("--root", type=Path, default=default_root(), help="MCP data root")
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create", help="Create a project from JSON")
    create.add_argument("spec", type=Path)
    validate = subparsers.add_parser("validate", help="Validate a saved project")
    validate.add_argument("project_id")
    analyze = subparsers.add_parser("analyze", help="Analyze reachability")
    analyze.add_argument("project_id")
    export = subparsers.add_parser("export", help="Export a report bundle")
    export.add_argument("project_id")
    export.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    root = args.root.expanduser().resolve()

    if args.command == "create":
        project = normalize_project(json.loads(args.spec.read_text(encoding="utf-8")))
        validation = validate_project(project)
        if not validation["valid"]:
            raise SystemExit(json.dumps(validation, ensure_ascii=False, indent=2))
        output = {"path": str(save_project(root, project)), "validation": validation}
    elif args.command == "validate":
        output = validate_project(load_project(root, args.project_id))
    elif args.command == "analyze":
        output = analyze_reachability(load_project(root, args.project_id))
    elif args.command == "export":
        output = export_report_bundle(load_project(root, args.project_id), args.output_dir.resolve())
    else:
        raise SystemExit(2)
    print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

