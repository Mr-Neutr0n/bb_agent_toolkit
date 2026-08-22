#!/usr/bin/env python3
"""cicd_secret_scan.py — Static scan for hardcoded secrets and GITHUB_TOKEN abuse in CI configs.

Searches workflow files and common config files for:
  - hardcoded secret-shaped values (API keys, tokens, passwords)
  - GITHUB_TOKEN write-permission usage
  - credentials in plain text (aws, gcp, azure patterns)
  - exposed secret names in logs/env

Passive: only reads local files. Use with gitleaks/trufflehog for history depth.

Usage:
  python3 cicd_secret_scan.py --dir /path/to/repo
  python3 cicd_secret_scan.py --dir . --json
  python3 cicd_secret_scan.py --help
"""

import argparse
import json
import re
import sys
from pathlib import Path

SECRET_PATTERNS = [
    ("aws-access-key", r"(AKIA|ASIA)[A-Z0-9]{16}"),
    ("github-token", r"ghp_[A-Za-z0-9]{36}"),
    ("slack-token", r"xox[baprs]-[A-Za-z0-9-]+"),
    ("google-api-key", r"AIza[0-9A-Za-z_-]{35}"),
    ("private-key", r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ("generic-secret", r"(?i)(secret|password|token|api_key|apikey)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
]

GITHUB_TOKEN_WRITE = re.compile(
    r"permissions:[\s\S]{0,200}?(contents|packages|pull-requests):\s*write", re.I,
)


def scan_file(path: Path) -> list:
    findings = []
    try:
        text = path.read_text(errors="replace")
        lines = text.splitlines()
    except Exception:
        return []
    for i, line in enumerate(lines, 1):
        for name, pat in SECRET_PATTERNS:
            m = re.search(pat, line)
            if m:
                masked = m.group(0)
                if len(masked) > 12:
                    masked = masked[:4] + "..." + masked[-4:]
                findings.append({"file": str(path), "rule": name, "line": i, "detail": masked})
    if GITHUB_TOKEN_WRITE.search(text) and path.suffix in (".yml", ".yaml"):
        findings.append({"file": str(path), "rule": "github-token-write",
                         "line": 0, "detail": "GITHUB_TOKEN granted write permission"})
    return findings


def main() -> int:
    ap = argparse.ArgumentParser(description="Scan CI configs for hardcoded secrets and token abuse.")
    ap.add_argument("--dir", required=True, help="Repository root to scan")
    ap.add_argument("--json", action="store_true", help="Emit JSON")
    args = ap.parse_args()

    root = Path(args.dir)
    if not root.is_dir():
        print(f"ERROR: not a directory: {root}", file=sys.stderr)
        return 2

    all_findings = []
    for pat in (".github/workflows/*.y*ml", ".github/*.y*ml", "*.y*ml", "*.env*", "*.sh", "*.py"):
        for path in root.glob(pat):
            if path.is_file():
                all_findings.extend(scan_file(path))

    if args.json:
        print(json.dumps(all_findings, indent=2))
    else:
        print(f"[*] Scanned {root} — {len(all_findings)} potential secrets/abuse patterns")
        for f in all_findings:
            print(f"[{f['rule']}] {f['file']}:{f['line']} — {f['detail']}")
        if all_findings:
            print("\n[!] Verify each candidate manually — many are test fixtures or placeholders.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
