#!/usr/bin/env python3
"""Report Quality Gate — validates a bug bounty report is submission-ready before sending.

Checks:
  - Required sections present (summary, steps, PoC, impact)
  - Evidence artifacts exist (request.txt, response.txt, screenshot)
  - CVSS score present
  - Reproduction steps are numbered
  - No placeholder text (TODO, TBD, XXX)
  - Minimum word counts for key sections
  - No leaked secrets in report body

Usage:
    quality_gate.py check --report $OUTDIR/reports/report.md --finding-dir evidence/finding_001
    quality_gate.py check --report report.md --json
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


REQUIRED_SECTIONS = {
    "summary": ["## summary", "# summary", "## executive summary"],
    "steps": ["## steps to reproduce", "## reproduction", "### steps to reproduce"],
    "poc": ["## proof of concept", "## poc", "### proof of concept"],
    "impact": ["## impact", "## impact assessment"],
}

PLACEHOLDER_PATTERNS = [
    (re.compile(r"\bTODO\b", re.I), "TODO marker found"),
    (re.compile(r"\bTBD\b", re.I), "TBD marker found"),
    (re.compile(r"\bFIXME\b", re.I), "FIXME marker found"),
    (re.compile(r"\bXXX\b"), "XXX placeholder found"),
    (re.compile(r"<your[_-]?(?:name|token|key|value|here)>", re.I), "template placeholder <your_*>"),
    (re.compile(r"lorem ipsum", re.I), "Lorem ipsum filler text"),
    (re.compile(r"\[insert .*?\]", re.I), "[insert ...] placeholder"),
]

SECRET_PATTERNS = [
    (re.compile(r"sk_live_[A-Za-z0-9]{20,}"), "live Stripe key pattern"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "GitHub token pattern"),
    (re.compile(r"AKIA[A-Z0-9]{16}"), "AWS access key pattern"),
    (re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY-----"), "private key block"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "Slack token pattern"),
]

MIN_WORD_COUNTS = {
    "summary": 30,
    "steps": 20,
    "impact": 40,
}


def section_word_count(content: str, markers: list) -> int:
    lines = content.splitlines()
    collecting = False
    words = 0
    for line in lines:
        lower = line.lower().strip()
        if any(lower.startswith(m) for m in markers):
            collecting = True
            continue
        if collecting:
            if line.strip().startswith("#"):
                break
            words += len(line.split())
    return words


def run_checks(report_path: str, finding_dir: str | None) -> dict:
    checks: list[dict] = []
    errors = 0
    warnings = 0

    p = Path(report_path)
    if not p.exists():
        return {"status": "error", "reason": f"report not found: {report_path}", "checks": [], "pass": False}
    content = p.read_text(encoding="utf-8")
    lower_content = content.lower()

    def add(name: str, passed: bool, level: str, detail: str = "") -> None:
        nonlocal errors, warnings
        checks.append({"check": name, "passed": passed, "level": level, "detail": detail})
        if not passed:
            if level == "error":
                errors += 1
            else:
                warnings += 1

    # Required sections
    for name, markers in REQUIRED_SECTIONS.items():
        found = any(m in lower_content for m in markers)
        add(f"section:{name}", found, "error", "" if found else "missing required section")

    # Section depth (word counts)
    for name, minimum in MIN_WORD_COUNTS.items():
        markers = REQUIRED_SECTIONS.get(name, [])
        wc = section_word_count(content, markers)
        add(
            f"depth:{name}",
            wc >= minimum,
            "warning",
            f"{wc} words (minimum {minimum})",
        )

    # Placeholders
    for pat, msg in PLACEHOLDER_PATTERNS:
        m = pat.search(content)
        add(f"placeholder:{msg}", not bool(m), "error", msg if m else "")

    # Secrets leaked into report
    for pat, msg in SECRET_PATTERNS:
        m = pat.search(content)
        add(f"secret-leak:{msg}", not bool(m), "error", "REDACT before submitting" if m else "")

    # Numbered repro steps heuristic
    steps_found = any(re.search(rf"{m}\n\s*(?:1\.|\d\.)", lower_content) for m in REQUIRED_SECTIONS["steps"])
    add("steps:numbered", steps_found, "warning", "reproduction steps should be numbered")

    # CVSS presence
    has_cvss = bool(re.search(r"(?:cvss|CVSS).{0,10}(?:\d{1,2}\.\d)", content))
    add("cvss:present", has_cvss, "warning", "include CVSS score for faster triage")

    # Evidence artifacts
    if finding_dir:
        d = Path(finding_dir)
        for artifact in ("request.txt", "response.txt"):
            exists = (d / artifact).exists()
            add(f"evidence:{artifact}", exists, "warning", f"missing {artifact} in finding dir")
        has_visual = any((d / n).exists() for n in ("screenshot.png", "screenshot.jpg", "demo.mp4"))
        add("evidence:screenshot-or-video", has_visual, "warning", "visual proof recommended")

    return {
        "status": "checked",
        "report": report_path,
        "checked_at": now_iso(),
        "total_checks": len(checks),
        "errors": errors,
        "warnings": warnings,
        "pass": errors == 0,
        "checks": checks,
    }


def main():
    parser = argparse.ArgumentParser(description="Report Quality Gate")
    sub = parser.add_subparsers(dest="command")

    p_check = sub.add_parser("check", help="Validate a report for submission readiness")
    p_check.add_argument("--report", required=True)
    p_check.add_argument("--finding-dir", default=None)
    p_check.add_argument("--json", action="store_true", help="JSON output")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    result = run_checks(args.report, args.finding_dir)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"=== Report Quality Gate: {result['report']} ===")
        for c in result["checks"]:
            icon = "+" if c["passed"] else ("!" if c["level"] == "error" else "-")
            detail = f" ({c['detail']})" if c["detail"] else ""
            print(f" [{icon}] {'PASS' if c['passed'] else 'FAIL'} {c['check']}{detail}")
        print()
        verdict = "READY TO SUBMIT" if result["pass"] else "NOT READY — fix errors above"
        print(f"errors={result['errors']} warnings={result['warnings']}")
        print(verdict)

    sys.exit(0 if result["pass"] else 1)


if __name__ == "__main__":
    main()
