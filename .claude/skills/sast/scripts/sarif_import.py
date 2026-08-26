#!/usr/bin/env python3
import argparse, json, sys
from pathlib import Path
def main():
    p = argparse.ArgumentParser(description="SARIF import")
    p.add_argument("--workspace", required=True)
    p.add_argument("--sarif", required=True)
    p.add_argument("--output", required=True)
    args = p.parse_args()
    data = json.loads(Path(args.sarif).read_text(encoding="utf-8"))
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for run in data.get("runs", []):
        for r in run.get("results", []):
            lvl = r.get("level", "note")
            sev = {"error": "high", "warning": "medium", "note": "low"}.get(lvl, "info")
            counts[sev] += 1
    out = {"workspace": args.workspace, "total": sum(counts.values()), **counts}
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(out, indent=2))
    print(json.dumps(out))
if __name__ == "__main__":
    main()
