#!/usr/bin/env python3
"""Model overrides helper — apply per-depth model selection to a plan.

Kritt-style model_overrides lets depth 0 use a cheap model and depth 2 use Opus.
This helper reads a plan.json and a model_overrides JSON file, and annotates each
plan item with the selected model. No LLM calls — just deterministic mapping.

Usage:
    model_overrides.py --plan output/planner/plan.json --overrides overrides.json --output output/planner/plan.with_models.json
    Overrides JSON format: {"0": "gpt-4o-mini", "2": "claude-opus", "default": "gpt-4o"}
"""

import argparse
import json
import sys
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Apply per-depth model overrides to a plan")
    parser.add_argument("--plan", required=True, help="Input plan.json")
    parser.add_argument("--overrides", required=True, help="JSON file with depth->model mapping")
    parser.add_argument("--output", "-o", required=True, help="Output plan JSON path")
    args = parser.parse_args()

    plan_path = Path(args.plan)
    overrides_path = Path(args.overrides)

    if not plan_path.exists():
        print(f"ERROR: plan not found: {plan_path}", file=sys.stderr)
        sys.exit(1)
    if not overrides_path.exists():
        print(f"ERROR: overrides not found: {overrides_path}", file=sys.stderr)
        sys.exit(1)

    import sys

    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    overrides = json.loads(overrides_path.read_text(encoding="utf-8"))

    default_model = overrides.get("default", "gpt-4o-mini")
    for item in plan.get("plan_items", plan.get("items", [])):
        depth = str(item.get("depth", 0))
        item["model_override"] = overrides.get(depth, overrides.get(str(int(depth)), default_model))

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(plan, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(out), "items": len(plan.get("plan_items", plan.get("items", []))), "models": list(set(overrides.values()))}))


if __name__ == "__main__":
    main()
