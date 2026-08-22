#!/usr/bin/env python3
"""chain_validity.py — Check a finding against the conditionally-valid chain-required table.

Findings in these classes are only reportable once the listed chain is proven
end to end. Outputs the required chain and the valid result for each match.

Usage:
  python3 chain_validity.py --finding-dir findings/<name>
  python3 chain_validity.py --finding-dir findings/<name> --output out/chain.md
  python3 chain_validity.py --help
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

CHAINS = [
    ("Open redirect", ["open redirect"], "OAuth redirect_uri → auth code theft", "ATO (Critical)"),
    ("Clickjacking", ["clickjacking"], "Sensitive action + working PoC", "Medium"),
    ("CORS wildcard", ["cors wildcard"], "Credentialed request exfils user PII", "High"),
    ("CSRF", ["csrf"], "Sensitive action (transfer funds, change email, delete account)", "High"),
    ("Rate limit bypass", ["rate limit"], "OTP/reset token brute force succeeds", "Medium/High"),
    ("SSRF DNS-only", ["ssrf", "dns callback", "dns only"], "Internal service access + data returned", "Medium"),
    ("Host header injection", ["host header"], "Password reset email uses injected host", "High"),
    ("Prompt injection", ["prompt injection"], "Reads other user's data (IDOR)", "High"),
    ("S3 bucket listing", ["s3 bucket", "bucket listing"], "JS bundles contain API keys or OAuth secrets", "Medium/High"),
    ("Self-XSS", ["self-xss", "self xss"], "CSRF to trigger it on victim without their knowledge", "Medium"),
    ("Subdomain takeover", ["subdomain takeover"], "OAuth redirect_uri registered at that subdomain", "Critical"),
    ("GraphQL introspection", ["graphql introspection"], "Auth bypass mutation or IDOR on node()", "High"),
]


def _load_text(finding_dir: Path) -> str:
    parts = []
    for name in ("description.txt", "notes.md", "README.md"):
        p = finding_dir / name
        if p.exists():
            parts.append(p.read_text(errors="replace"))
    jl = finding_dir / "findings.jsonl"
    if jl.exists():
        for line in jl.read_text(errors="replace").splitlines()[:20]:
            try:
                rec = json.loads(line)
                parts.append(json.dumps(rec))
            except Exception:
                pass
    return "\n".join(parts).lower()


def main() -> int:
    ap = argparse.ArgumentParser(description="Check a finding against the conditionally-valid chain table.")
    ap.add_argument("--finding-dir", required=True, help="Directory with description/notes files")
    ap.add_argument("--output", default="-", help="Output markdown path (default: stdout)")
    args = ap.parse_args()

    finding_dir = Path(args.finding_dir)
    if not finding_dir.is_dir():
        print(f"ERROR: finding dir not found: {finding_dir}", file=sys.stderr)
        return 2
    text = _load_text(finding_dir)
    hits = [c for c in CHAINS if any(sig in text for sig in c[1])]

    lines = []
    lines.append("# Conditionally-Valid Chain Check")
    lines.append("")
    lines.append(f"- Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"- Finding dir: `{finding_dir}`")
    lines.append("")
    if hits:
        lines.append("| Standalone Finding | Chain Required | Valid Result |")
        lines.append("|--------------------|----------------|--------------|")
        for name, _, chain, result in hits:
            lines.append(f"| {name} | {chain} | {result} |")
        lines.append("")
        lines.append("**Build the chain first, prove it end to end, THEN report.**")
    else:
        lines.append("_No conditionally-valid class matched — the finding is either directly")
        lines.append("valid or on the never-submit list._")
    lines.append("")
    report = "\n".join(lines)

    if args.output == "-":
        print(report)
    else:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report)
        print(f"Chain report written to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
