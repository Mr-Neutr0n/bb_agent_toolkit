#!/usr/bin/env python3
"""workflow_inject_scan.py — Static scan of GitHub Actions workflows for injection and secret-exfil patterns.

Scans a local checkout of `.github/workflows/` (or any directory) for:
  - script injection via github.event.* / github.head_ref in run: blocks
  - pull_request_target with checkout of PR head
  - secrets referenced in run:/env: blocks
  - self-hosted runners on pull triggers
  - unpinned actions (uses: owner/repo@main or @vN tag)
  - overly broad permissions (contents/packages write)

Passive: only reads local files.

Usage:
  python3 workflow_inject_scan.py --dir /path/to/repo
  python3 workflow_inject_scan.py --dir . --json
  python3 workflow_inject_scan.py --help
"""

import argparse
import json
import re
import sys
from pathlib import Path

INJECTABLE_CONTEXTS = re.compile(
    r"\$\{\{\s*(?:github\.(?:event\.(?:pull_request|issue|comment|review|discussion|inputs)|head_ref|event\.inputs)"
    r"[^}]*)\s*\}\}",
    re.I,
)


def scan_file(path: Path) -> list:
    findings = []
    try:
        lines = path.read_text(errors="replace").splitlines()
    except Exception as e:
        return [{"file": str(path), "rule": "read-error", "line": 0, "detail": str(e)}]

    in_run = False
    for i, line in enumerate(lines, 1):
        low = line.lower()
        # Injection contexts
        for m in INJECTABLE_CONTEXTS.finditer(line):
            findings.append({
                "file": str(path), "rule": "expression-injection", "line": i,
                "detail": f"attacker-controlled context interpolated: {m.group(0).strip()[:120]}",
            })
        # pull_request_target
        if "pull_request_target" in low:
            findings.append({"file": str(path), "rule": "pull-request-target", "line": i,
                             "detail": "workflow runs with base-repo secrets on PR events"})
        # checkout of PR head
        if re.search(r"head\.sha|head_ref", low) and "checkout" in low:
            findings.append({"file": str(path), "rule": "checkout-untrusted-head", "line": i,
                             "detail": "checkout references PR-controlled ref"})
        # secrets in run: / env: lines
        if re.search(r"echo\s+.*secrets\.|cat\s+.*secrets\.|\$\{\{\s*secrets\.", low):
            findings.append({"file": str(path), "rule": "secret-in-run", "line": i,
                             "detail": "secret referenced in shell context — possible log leak"})
        # self-hosted runner
        if "runs-on" in low and "self-hosted" in low:
            findings.append({"file": str(path), "rule": "self-hosted-runner", "line": i,
                             "detail": "self-hosted runner may execute fork code"})
        # unpinned action
        m = re.search(r"uses:\s*([^\s#]+)", low)
        if m and ("@" not in m.group(1) or re.search(r"@(main|master|latest|v\d+)\b", m.group(1))):
            findings.append({"file": str(path), "rule": "unpinned-action", "line": i,
                             "detail": f"action not pinned to commit SHA: {m.group(1)}"})
        # broad permissions
        if re.search(r"permissions:\s*$", low):
            j = i
            while j < min(i + 6, len(lines)):
                if re.search(r"contents:\s*write|packages:\s*write", lines[j].lower()):
                    findings.append({"file": str(path), "rule": "broad-permissions", "line": j,
                                     "detail": lines[j].strip()})
                j += 1
    return findings


def main() -> int:
    ap = argparse.ArgumentParser(description="Scan GitHub Actions workflows for injection and secret-exfil patterns.")
    ap.add_argument("--dir", required=True, help="Repo root or workflows directory")
    ap.add_argument("--json", action="store_true", help="Emit JSON")
    args = ap.parse_args()

    root = Path(args.dir)
    if not root.is_dir():
        print(f"ERROR: not a directory: {root}", file=sys.stderr)
        return 2

    if root.name == "workflows" or (root / ".github").exists():
        wf_dir = root if root.name == "workflows" else root / ".github" / "workflows"
    else:
        wf_dir = root / ".github" / "workflows"
    if not wf_dir.is_dir():
        print(f"ERROR: no .github/workflows found under {root}", file=sys.stderr)
        return 1

    all_findings = []
    for path in sorted(wf_dir.rglob("*.y*ml")):
        all_findings.extend(scan_file(path))

    if args.json:
        print(json.dumps(all_findings, indent=2))
    else:
        print(f"[*] Scanned {wf_dir} — {len(all_findings)} potential issues")
        for f in all_findings:
            print(f"[{f['rule']}] {f['file']}:{f['line']} — {f['detail']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
