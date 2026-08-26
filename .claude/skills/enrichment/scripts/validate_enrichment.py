#!/usr/bin/env python3
"""Validate enrichment output — ensure required keys and types."""

import argparse
import json
import sys
from pathlib import Path

ALLOWED_KEYS = {"_reserved_report", "_reserved_poc"}
CHIP_PREFIX = "_chip_"


def validate_file(path: Path) -> dict:
    if not path.exists():
        return {"valid": False, "error": f"not found: {path}"}
    errors = []
    count = 0
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        count += 1
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as e:
            errors.append(f"line {i}: invalid JSON: {e}")
            continue
        out = rec.get("output", {})
        if not isinstance(out, dict):
            errors.append(f"line {i}: output not an object")
            continue
        for k, v in out.items():
            if k in ALLOWED_KEYS:
                if not isinstance(v, str):
                    errors.append(f"line {i}: {k} must be string")
            elif k.startswith(CHIP_PREFIX):
                if not isinstance(v, str):
                    errors.append(f"line {i}: {k} must be string")
                if len(v) > 100:
                    errors.append(f"line {i}: {k} too long (>100)")
            elif k not in ("note", "error"):
                errors.append(f"line {i}: unexpected key {k}")

    return {"valid": len(errors) == 0, "count": count, "errors": errors}


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate enrichment output")
    parser.add_argument("--enrichments", required=True, help="Enrichments JSONL file")
    args = parser.parse_args()

    result = validate_file(Path(args.enrichments))
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["valid"] else 1)


if __name__ == "__main__":
    main()
