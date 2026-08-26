#!/usr/bin/env python3
"""Workflow inheritance resolver — handle extends + override for skill.yaml.

Supports:
  extends: base-skill-name  (e.g., extends: recon)
  override:
    workflows:
      mode: replace|prepend|append|merge
      replace: [workflow names to remove]
      workflows: {name: workflow}  # to merge/append

Usage:
    workflow_inheritance.py --skill my-skill --resolve
"""

import argparse
import sys
from pathlib import Path

import yaml


def _safe_skill_path(name: str) -> Path:
    import re
    if not re.match(r"^[a-z0-9_-]{1,64}$", name):
        print(f"ERROR: invalid skill name: {name}", file=sys.stderr)
        sys.exit(1)
    p = (Path(".claude/skills") / name / "skill.yaml").resolve()
    root = Path(".claude/skills").resolve()
    if not p.is_relative_to(root):
        print("ERROR: skill path escapes", file=sys.stderr)
        sys.exit(1)
    return p

def load_skill(skill_name: str) -> dict:
    path = _safe_skill_path(skill_name)
    if not path.exists():
        print(f"ERROR: base skill not found: {skill_name}", file=sys.stderr)
        sys.exit(1)
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def resolve_inheritance(skill_name: str) -> dict:
    skill_path = _safe_skill_path(skill_name)
    data = yaml.safe_load(skill_path.read_text(encoding="utf-8"))
    extends = data.get("extends")
    if not extends:
        return data

    base = load_skill(extends)
    override = data.get("override", {})

    # Merge workflows based on mode
    mode = override.get("workflows", {}).get("mode", "merge") if isinstance(override.get("workflows"), dict) else "merge"
    base_workflows = base.get("workflows", {}) or {}
    child_workflows = data.get("workflows", {}) or {}

    if mode == "replace":
        # Child replaces base entirely
        merged = child_workflows
    elif mode == "prepend":
        merged = {**child_workflows, **base_workflows}
    elif mode == "append":
        merged = {**base_workflows, **child_workflows}
    else:  # merge
        merged = dict(base_workflows)
        for k, v in child_workflows.items():
            if k in merged:
                # Merge workflow fields, child overrides
                merged[k] = {**merged[k], **v}
            else:
                merged[k] = v
        # Handle explicit removes
        for rm in (override.get("workflows", {}).get("remove", []) if isinstance(override.get("workflows"), dict) else []):
            merged.pop(rm, None)

    # Merge other top-level fields: child overrides base
    result = {**base, **data}
    result["workflows"] = merged
    # Remove inheritance keys from result to avoid recursion
    result.pop("extends", None)
    result.pop("override", None)
    return result


def main():
    parser = argparse.ArgumentParser(description="Workflow inheritance resolver")
    parser.add_argument("--skill", required=True, help="Skill name to resolve")
    parser.add_argument("--resolve", action="store_true", help="Print resolved skill.yaml")
    parser.add_argument("--output", help="Output path for resolved YAML")
    args = parser.parse_args()

    resolved = resolve_inheritance(args.skill)
    output = yaml.safe_dump(resolved, sort_keys=False)
    if args.resolve:
        print(output)
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Resolved -> {args.output}")


if __name__ == "__main__":
    main()
