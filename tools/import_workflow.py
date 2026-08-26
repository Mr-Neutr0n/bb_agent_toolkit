#!/usr/bin/env python3
"""Workflow importer — convert portable workflow JSON to BountyHarness playbook YAML.

Supports:
  - open-kritt-workflow v2 (kind: open-kritt-workflow, version: 2, levels[].steps[])
  - open-kritt-workflow v1 (flat steps[])
  - Generic steps[] fallback

Output is a harness playbook following planner/playbook_schema.yaml (id, version,
name, phases with safety_tier). Steps are mapped to phases by depth.

Usage:
    import_workflow.py --input workflow.json --output planner/playbooks/imported.yaml --name my-import
    import_workflow.py --input workflow.json --dry-run
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

import yaml


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    print(f"[{now_iso()}] {msg}", file=sys.stderr)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def normalize_workflow(data: dict) -> tuple[str, list[dict], dict | None]:
    """Returns (name, levels, meta). Handles v2 levels, v1 steps, and raw workflow."""
    # Direct workflow object
    if "workflow" in data and isinstance(data["workflow"], dict):
        wf = data["workflow"]
        name = wf.get("name", "imported-workflow")
        if "levels" in wf:
            return name, wf["levels"], wf
        if "steps" in wf:
            # v1 flat steps -> single level
            return name, [{"depth": 0, "steps": wf["steps"], "outputFormat": wf.get("outputFormat", {})}], wf

    # Top-level levels
    if "levels" in data:
        return data.get("name", "imported-workflow"), data["levels"], data

    # Flat steps
    if "steps" in data and isinstance(data["steps"], list):
        return data.get("name", "imported-workflow"), [{"depth": 0, "steps": data["steps"]}], data

    raise ValueError(f"Unrecognized workflow format: keys={list(data.keys())}")


def map_depth_to_phase(depth: int, steps: list[dict], output_format: dict | None) -> dict:
    is_last = False
    # Heuristic: last depth is one that would have isLastStep in Kritt terms
    # We cannot know globally; caller passes max_depth context.
    return {
        "id": f"depth-{depth}",
        "name": f"Imported depth {depth} ({len(steps)} step(s))",
        "safety_tier": "passive",
        "steps": [
            {
                "id": f"depth-{depth}-step-{i}",
                "skill": "auto-research",
                "workflow": "import-candidate",
                "inputs": {"prompt": s.get("content", s.get("prompt", ""))[:500]},
                "outputs": output_format or {},
            }
            for i, s in enumerate(steps)
        ],
    }


def convert(data: dict, name_override: str | None = None) -> dict:
    name, levels, meta = normalize_workflow(data)
    if name_override:
        name = name_override

    # Determine max depth to mark terminal
    depths = [lvl.get("depth", i) for i, lvl in enumerate(levels)]
    max_depth = max(depths) if depths else 0

    playbook = {
        "id": name.lower().replace(" ", "-").replace("_", "-")[:40],
        "version": "1.0",
        "name": name,
        "description": meta.get("description", f"Imported from open-kritt workflow: {name}") if meta else f"Imported workflow: {name}",
        "source": {
            "kind": data.get("kind", "unknown"),
            "version": data.get("version", 1),
            "imported_at": now_iso(),
        },
        "phases": [],
    }

    for lvl in sorted(levels, key=lambda x: x.get("depth", 0)):
        depth = lvl.get("depth", 0)
        steps = lvl.get("steps", [])
        output_format = lvl.get("outputFormat", lvl.get("output_format", {}))
        phase = map_depth_to_phase(depth, steps, output_format)
        if depth == max_depth:
            phase["name"] += " [terminal]"
        playbook["phases"].append(phase)

    return playbook


def main() -> None:
    p = argparse.ArgumentParser(description="Workflow importer (open-kritt-workflow v2 -> playbook YAML)")
    p.add_argument("--input", "-i", required=True, help="Input JSON file (open-kritt-workflow)")
    p.add_argument("--output", "-o", default=None, help="Output YAML path (default: planner/playbooks/<name>.yaml)")
    p.add_argument("--name", default=None, help="Override playbook name")
    p.add_argument("--dry-run", action="store_true", help="Validate and print without writing")
    p.add_argument("--playbooks-dir", default=".claude/skills/planner/playbooks", help="Playbooks directory for default output")
    args = p.parse_args()

    src = Path(args.input)
    if not src.exists():
        log(f"ERROR: input not found: {src}")
        sys.exit(1)

    if src.stat().st_size > 2 * 1024 * 1024:
        log("ERROR: file exceeds 2MB import limit")
        sys.exit(1)

    try:
        data = load_json(src)
    except json.JSONDecodeError as e:
        log(f"ERROR: invalid JSON: {e}")
        sys.exit(1)

    try:
        playbook = convert(data, name_override=args.name)
    except ValueError as e:
        log(f"ERROR: {e}")
        sys.exit(1)

    output = Path(args.output) if args.output else Path(args.playbooks_dir) / f"{playbook['id']}.yaml"

    if args.dry_run:
        print(yaml.safe_dump(playbook, sort_keys=False))
        log(f"Dry run: {len(playbook['phases'])} phases, would write to {output}")
        print(json.dumps({"phases": len(playbook["phases"]), "id": playbook["id"], "would_write": str(output)}))
        return

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(yaml.safe_dump(playbook, sort_keys=False), encoding="utf-8")
    log(f"Imported {playbook['id']} ({len(playbook['phases'])} phases) -> {output}")
    print(json.dumps({"imported": str(output), "id": playbook["id"], "phases": len(playbook["phases"])}))


if __name__ == "__main__":
    main()
