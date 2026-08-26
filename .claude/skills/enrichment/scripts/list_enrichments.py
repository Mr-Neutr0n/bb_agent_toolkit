#!/usr/bin/env python3
"""List enrichments and their status."""

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="List enrichments")
    parser.add_argument("--enrichments", required=True, help="Enrichments JSONL file")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    p = Path(args.enrichments)
    if not p.exists():
        print("No enrichments file found")
        return

    rows = []
    for line in p.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                rows.append(json.loads(line))
            except Exception:
                continue

    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        if not rows:
            print("No enrichments")
            return
        print(f"Enrichments ({len(rows)}):")
        for r in rows:
            fid = r.get("finding_id", "?")[:8]
            ps = r.get("post_script", "?")
            keys = list(r.get("output", {}).keys())
            print(f"  {fid}  {ps:20}  {keys}")

    # Summary
    by_script = {}
    for r in rows:
        by_script[r.get("post_script", "?")] = by_script.get(r.get("post_script", "?"), 0) + 1
    if not args.json:
        print(f"\nBy post-script: {by_script}")


if __name__ == "__main__":
    main()
