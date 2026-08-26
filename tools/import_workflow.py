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
import re
import sys
from pathlib import Path
from datetime import datetime, timezone

import yaml

MAX_LEVELS = 20
MAX_STEPS_PER_LEVEL = 100
MAX_TOTAL_STEPS = 500
MAX_PROMPT_LEN = 2000


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    print(f"[{now_iso()}] {msg}", file=sys.stderr)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sanitize_id(name: str) -> str:
    """Make id safe for filesystem: only a-z0-9-, no traversal."""
    safe = re.sub(r"[^a-z0-9-]", "-", name.lower())
    safe = re.sub(r"-+", "-", safe).strip("-")[:40] or "imported-workflow"
    if not re.match(r"^[a-z0-9-]{1,40}$", safe):
        safe = "imported-workflow"
    return safe


def normalize_workflow(data: dict) -> tuple[str, list[dict], dict | None]:
    """Returns (name, levels, meta). Handles v2 levels, v1 steps, and raw workflow."""
    # Direct workflow object
    if "workflow" in data and isinstance(data["workflow"], dict):
        wf = data["workflow"]
        name = wf.get("name", "imported-workflow")
        if "levels" in wf:
            levels = wf["levels"]
            if not isinstance(levels, list):
                raise ValueError("workflow.levels must be a list")
            return name, levels, wf
        if "steps" in wf:
            steps = wf["steps"]
            if not isinstance(steps, list):
                raise ValueError("workflow.steps must be a list")
            return name, [{"depth": 0, "steps": steps, "outputFormat": wf.get("outputFormat", {})}], wf

    # Top-level levels
    if "levels" in data:
        levels = data["levels"]
        if not isinstance(levels, list):
            raise ValueError("levels must be a list")
        return data.get("name", "imported-workflow"), levels, data

    # Flat steps
    if "steps" in data and isinstance(data["steps"], list):
        return data.get("name", "imported-workflow"), [{"depth": 0, "steps": data["steps"]}], data

    raise ValueError(f"Unrecognized workflow format: keys={list(data.keys())}")


def map_depth_to_phase(depth: int, steps: list[dict], output_format: dict | None) -> dict:
    mapped = []
    for i, s in enumerate(steps):
        if not isinstance(s, dict):
            log(f"WARN: step {i} at depth {depth} is not an object, skipping")
            continue
        raw_prompt = s.get("content", s.get("prompt", ""))
        if not isinstance(raw_prompt, str):
            raw_prompt = str(raw_prompt)
        prompt = raw_prompt[:MAX_PROMPT_LEN]
        if len(raw_prompt) > MAX_PROMPT_LEN:
            log(f"WARN: truncated prompt at depth {depth} step {i} from {len(raw_prompt)} to {MAX_PROMPT_LEN}")
            prompt = prompt + "..."
        mapped.append(
            {
                "id": f"depth-{depth}-step-{i}",
                "skill": "auto-research",
                "workflow": "import-candidate",
                "inputs": {"prompt": prompt},
                "outputs": output_format or {},
            }
        )
    return {
        "id": f"depth-{depth}",
        "name": f"Imported depth {depth} ({len(mapped)} step(s))",
        "safety_tier": "passive",
        "steps": mapped,
    }


def convert(data: dict, name_override: str | None = None) -> dict:
    name, levels, meta = normalize_workflow(data)
    if name_override:
        name = name_override

    if len(levels) > MAX_LEVELS:
        raise ValueError(f"Too many levels: {len(levels)} > {MAX_LEVELS}")
    total_steps = sum(len(lvl.get("steps", [])) for lvl in levels if isinstance(lvl, dict))
    if total_steps > MAX_TOTAL_STEPS:
        raise ValueError(f"Too many total steps: {total_steps} > {MAX_TOTAL_STEPS}")

    # Determine max depth to mark terminal
    depths = [lvl.get("depth", i) if isinstance(lvl, dict) else i for i, lvl in enumerate(levels)]
    max_depth = max(depths) if depths else 0

    playbook = {
        "id": sanitize_id(name),
        "version": "1.0",
        "name": name,
        "description": (meta.get("description", f"Imported from open-kritt workflow: {name}") if isinstance(meta, dict) else f"Imported workflow: {name}"),
        "source": {
            "kind": data.get("kind", "unknown"),
            "version": data.get("version", 1),
            "imported_at": now_iso(),
        },
        "phases": [],
    }

    seen_ids: set[str] = set()
    for lvl in sorted(levels, key=lambda x: x.get("depth", 0) if isinstance(x, dict) else 0):
        if not isinstance(lvl, dict):
            log(f"WARN: level is not an object, skipping: {lvl}")
            continue
        depth = lvl.get("depth", 0)
        steps = lvl.get("steps", [])
        if not isinstance(steps, list):
            raise ValueError(f"steps at depth {depth} must be a list")
        if len(steps) > MAX_STEPS_PER_LEVEL:
            raise ValueError(f"Too many steps at depth {depth}: {len(steps)} > {MAX_STEPS_PER_LEVEL}")
        output_format = lvl.get("outputFormat", lvl.get("output_format", {}))
        if output_format is not None and not isinstance(output_format, dict):
            raise ValueError(f"outputFormat at depth {depth} must be an object")
        phase = map_depth_to_phase(depth, steps, output_format)
        # dedupe phase id if duplicate depth values exist
        base_id = phase["id"]
        suffix = 0
        while phase["id"] in seen_ids:
            suffix += 1
            phase["id"] = f"{base_id}-{suffix}"
        seen_ids.add(phase["id"])
        if depth == max_depth:
            phase["name"] += " [terminal]"
            phase["terminal"] = True
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
