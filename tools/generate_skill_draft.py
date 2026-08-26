#!/usr/bin/env python3
"""Skill draft generator — turn natural language request into a validated skill.yaml skeleton.

Supports heuristic drafting (no API key) and optional LLM drafting when OPENAI_API_KEY is set.
Validates against tools/schemas/skill.schema.json and writes to drafts/.

Usage:
    generate_skill_draft.py --request "add a skill that checks for prototype pollution in JS" --output drafts/pollution.yaml
    generate_skill_draft.py --request "file upload bypass via double extension" --llm --output drafts/upload.yaml
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    print(f"[{now_iso()}] {msg}", file=sys.stderr)


def sanitize_slug(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:30] or "new-skill"
    if not re.match(r"^[a-z][a-z0-9-]*$", slug):
        slug = "skill-" + slug
    return slug


def heuristic_draft(request: str) -> dict:
    slug = sanitize_slug(request[:40])
    return {
        "name": slug,
        "version": "0.1.0",
        "description": f"Draft skill for: {request[:120]}",
        "bounded_context": "DraftContext",
        "safety_tier": "passive",
        "owasp_wstg": [],
        "owasp_api_top10": [],
        "severity_range": ["info", "low", "medium"],
        "tools_required": ["python3"],
        "input_files": [],
        "workflows": {
            "draft-check": {
                "description": f"Heuristic draft for: {request[:80]}",
                "safety_tier": "passive",
                "inputs": ["OUTDIR"],
                "command": f"mkdir -p $OUTDIR/{slug} && echo 'Draft for {request[:40]}' > $OUTDIR/{slug}/draft.txt",
                "outputs": [f"$OUTDIR/{slug}/draft.txt"],
                "evidence_dir": f"$OUTDIR/{slug}/evidence/",
                "detection_signals": [f"draft output for {slug}"],
                "false_positives": [],
                "next": {"if_findings": None, "if_no_findings": None},
            }
        },
        "evidence_templates": {"draft": "Draft output"},
    }


def llm_draft(request: str) -> dict:
    try:
        from openai import OpenAI  # type: ignore
    except ImportError:
        raise RuntimeError("openai not installed")
    import os

    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    system = "You are a BountyHarness skill designer. Output JSON matching the skill schema: name (kebab-case), version, description, bounded_context, safety_tier passive/active-safe, 1-2 workflows with command using $OUTDIR, evidence_dir. Only output JSON."
    resp = client.chat.completions.create(
        model=os.environ.get("DRAFT_MODEL", "gpt-4o-mini"),
        messages=[{"role": "system", "content": system}, {"role": "user", "content": request[:2000]}],
        temperature=0.3,
    )
    content = resp.choices[0].message.content or "{}"
    m = re.search(r"\{.*\}", content, re.DOTALL)
    if not m:
        raise RuntimeError("LLM returned no JSON")
    data = json.loads(m.group(0))
    # Minimal validation
    if "name" not in data or "workflows" not in data:
        raise RuntimeError("LLM draft missing name/workflows")
    data["name"] = sanitize_slug(data["name"])
    return data


def validate_against_schema(data: dict) -> list[str]:
    schema_path = Path("tools/schemas/skill.schema.json")
    if not schema_path.exists():
        return []
    try:
        import jsonschema  # type: ignore

        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.validate(data, schema)
        return []
    except ImportError:
        # Fallback: minimal checks
        errs = []
        if not re.match(r"^[a-z][a-z0-9-]*$", data.get("name", "")):
            errs.append("name must match ^[a-z][a-z0-9-]*$")
        if not data.get("workflows"):
            errs.append("workflows required")
        return errs
    except Exception as e:
        return [str(e)]


def main() -> None:
    parser = argparse.ArgumentParser(description="Skill draft generator")
    parser.add_argument("--request", required=True, help="Natural language request")
    parser.add_argument("--output", "-o", required=True, help="Output YAML path (e.g., drafts/my-skill.yaml)")
    parser.add_argument("--llm", action="store_true", help="Use LLM for drafting")
    parser.add_argument("--dry-run", action="store_true", help="Print without writing")
    args = parser.parse_args()

    if args.llm and "OPENAI_API_KEY" in __import__("os").environ:
        try:
            draft = llm_draft(args.request)
            log("LLM draft generated")
        except Exception as e:
            log(f"LLM draft failed ({e}), falling back to heuristic")
            draft = heuristic_draft(args.request)
    else:
        if args.llm:
            log("WARN: --llm requested but OPENAI_API_KEY not set, using heuristic")
        draft = heuristic_draft(args.request)

    errs = validate_against_schema(draft)
    if errs:
        log(f"WARN: draft validation issues: {errs}")

    output = Path(args.output)
    if args.dry_run:
        print(yaml.safe_dump(draft, sort_keys=False))
        print(json.dumps({"draft": str(output), "errors": errs, "workflows": list(draft.get("workflows", {}).keys())}))
        return

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(yaml.safe_dump(draft, sort_keys=False), encoding="utf-8")
    log(f"Draft written -> {output} (workflows: {list(draft.get('workflows', {}).keys())})")
    if errs:
        log(f"Validation warnings: {errs}")
    print(json.dumps({"draft": str(output), "name": draft.get("name"), "workflows": list(draft.get("workflows", {}).keys()), "errors": errs}))


if __name__ == "__main__":
    main()
