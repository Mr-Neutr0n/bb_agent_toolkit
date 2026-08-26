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
import re
import sys
from pathlib import Path

MAX_JSON_BYTES = 2 * 1024 * 1024
ALLOWED_MODEL_RE = re.compile(r"^[a-z0-9._-]{1,64}$")


def main() -> None:
    parser = argparse.ArgumentParser(description="Apply per-depth model overrides to a plan")
    parser.add_argument("--plan", required=True, help="Input plan.json")
    parser.add_argument("--overrides", required=True, help="JSON file with depth->model mapping")
    parser.add_argument("--output", "-o", required=True, help="Output plan JSON path")
    args = parser.parse_args()

    plan_path = Path(args.plan)
    overrides_path = Path(args.overrides)
    out_path = Path(args.output)

    for p, label in [(plan_path, "plan"), (overrides_path, "overrides")]:
        if not p.exists():
            print(f"ERROR: {label} not found: {p}", file=sys.stderr)
            sys.exit(1)
        if p.is_symlink():
            print(f"ERROR: {label} must not be a symlink: {p}", file=sys.stderr)
            sys.exit(1)
        if p.stat().st_size > MAX_JSON_BYTES:
            print(f"ERROR: {label} too large (>2MB): {p}", file=sys.stderr)
            sys.exit(1)

    # Output must be under OUTDIR or cwd to prevent arbitrary writes
    outdir = Path.cwd().resolve()
    # Allow OUTDIR env if set (harness context)
    import os

    env_outdir = os.environ.get("OUTDIR")
    if env_outdir:
        try:
            outdir = Path(env_outdir).resolve()
        except Exception:
            pass
    try:
        # If output is absolute, ensure it is under outdir or cwd; if relative, it will be under cwd
        resolved_out = (Path.cwd() / out_path).resolve() if not out_path.is_absolute() else out_path.resolve()
        # Allow if under outdir or under cwd
        allowed = False
        for base in [outdir, Path.cwd().resolve()]:
            try:
                if resolved_out.is_relative_to(base):
                    allowed = True
                    break
            except Exception:
                continue
        if not allowed and not str(resolved_out).startswith(str(Path.cwd().resolve())):
            # Fallback strict: require output to be under output/ directory
            if "output" not in str(resolved_out):
                print(f"ERROR: output must be under output/ or $OUTDIR: {resolved_out}", file=sys.stderr)
                sys.exit(1)
    except Exception:
        pass

    try:
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"ERROR: invalid plan JSON: {e}", file=sys.stderr)
        sys.exit(1)
    try:
        overrides = json.loads(overrides_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"ERROR: invalid overrides JSON: {e}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(overrides, dict):
        print("ERROR: overrides must be a JSON object", file=sys.stderr)
        sys.exit(1)

    # Validate model names
    for k, v in list(overrides.items()):
        if not isinstance(v, str) or not ALLOWED_MODEL_RE.match(v):
            print(f"WARN: invalid model name for depth {k}: {v!r}, using default", file=sys.stderr)
            overrides[k] = "gpt-4o-mini"

    default_model = overrides.get("default", "gpt-4o-mini")

    for item in plan.get("plan_items", plan.get("items", [])):
        raw_depth = item.get("depth", 0)
        depth_str = str(raw_depth).strip()
        # Safe lookup: try exact, then int-normalized, then default
        model = overrides.get(depth_str)
        if model is None:
            try:
                # Handle float strings like "1.0" and numeric strings
                normalized = str(int(float(depth_str)))
                model = overrides.get(normalized, default_model)
            except (ValueError, TypeError):
                model = default_model
        item["model_override"] = model

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(out_path), "items": len(plan.get("plan_items", plan.get("items", []))), "models": list(set(overrides.values()))}))


if __name__ == "__main__":
    main()
