#!/usr/bin/env python3
"""triage_gate.py — Run the 7-Question Gate and the 4 pre-submission gates on a finding.

Non-interactive gate runner for the triage-validation skill. Reads a finding
directory (description.txt, request.txt, response.txt) and writes a markdown
gate report with the 7-Question Gate, the identity check, and the 4 gates,
each rendered with a pass/fail placeholder the hunter fills in.

Usage:
  python3 triage_gate.py --finding-dir findings/<name>
  python3 triage_gate.py --finding-dir findings/<name> --output out/gate_result.md
  python3 triage_gate.py --help
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

QUESTIONS = [
    ("Q1", "Attacker can use it RIGHT NOW step by step (setup/request/result/impact/cost template complete)"),
    ("Q2", "Impact is on the program's accepted impact list (not an exclusion)"),
    ("Q3", "Root cause is in an in-scope, production asset (not third-party/staging)"),
    ("Q4", "Does NOT require privileged access an attacker cannot realistically get"),
    ("Q5", "Not already known or accepted behavior (disclosures/issues/docs searched)"),
    ("Q6", "Impact proven beyond technically-possible (data/cookie/account shown)"),
    ("Q7", "Not a known-invalid bug class from the never-submit list (or chain built)"),
]

GATES = [
    ("Gate 0", "Reality Check", [
        "Bug is REAL — confirmed with actual HTTP requests, not code reading alone",
        "Bug is IN SCOPE — checked program scope page explicitly",
        "Reproducible from scratch — can reproduce starting from fresh session",
        "Evidence ready — screenshot, response body, or video",
    ]),
    ("Gate 1", "Impact Validation", [
        'Can answer: "What can attacker DO that they could not before?"',
        "Answer is more than see non-sensitive data (unless program pays for info disclosure)",
        "Real victim: another user's data, company's data, financial loss",
        "Not relying on victim doing something unlikely",
    ]),
    ("Gate 2", "Deduplication Check", [
        "Searched HackerOne Hacktivity for this program + similar bug title/endpoint",
        "Searched GitHub issues for target repo",
        "Read most recent 5 disclosed reports for this program",
        "Not a known issue in their changelog or public docs",
        'Google: "TARGET_NAME ENDPOINT_NAME bug bounty"',
    ]),
    ("Gate 3", "Report Quality", [
        "Title: [Bug Class] in [Endpoint] allows [actor] to [impact]",
        "Steps to Reproduce: copy-pasteable HTTP request",
        "Evidence: screenshot/video of actual impact (not just 200 status)",
        "Severity: matches CVSS 3.1 score AND program's severity definitions",
        "Remediation: 1-2 sentences of concrete fix",
        'NEVER used "could potentially" or "may allow"',
    ]),
]

IDENTITY_CHECKS = [
    "Session ID: [12-char BBHUNT_SESSION_ID hash from audit.jsonl]",
    "Identity: [low-priv user A / high-priv user B / API key / etc.]",
    "Anonymous repro: does the same request work with NO auth header?",
    "Cross-identity: does it work under session B with the same data scope?",
    "Stale-cred repro: does a logged-out / expired session still get the data?",
]


def _load_finding(finding_dir: Path) -> dict:
    files = {"description": "description.txt", "request": "request.txt", "response": "response.txt"}
    out = {}
    for key, name in files.items():
        p = finding_dir / name
        if p.exists():
            out[key] = p.read_text(errors="replace")[:4000]
        else:
            out[key] = ""
    jl = finding_dir / "findings.jsonl"
    if jl.exists():
        for line in jl.read_text(errors="replace").splitlines()[:10]:
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if "description" in rec and not out.get("description"):
                out["description"] = str(rec["description"])[:4000]
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Run the 7-Question Gate and 4 pre-submission gates on a finding.")
    ap.add_argument("--finding-dir", required=True, help="Directory with description.txt / request.txt / response.txt")
    ap.add_argument("--output", default="-", help="Output markdown path (default: stdout)")
    args = ap.parse_args()

    finding_dir = Path(args.finding_dir)
    if not finding_dir.is_dir():
        print(f"ERROR: finding dir not found: {finding_dir}", file=sys.stderr)
        return 2
    finding = _load_finding(finding_dir)

    lines = []
    lines.append("# Triage & Validation Gate Report")
    lines.append("")
    lines.append(f"- Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"- Finding dir: `{finding_dir}`")
    lines.append("")
    lines.append("## Finding Description")
    lines.append("")
    lines.append(finding["description"] or "_no description.txt found — add one before running the gate_")
    lines.append("")
    lines.append("## 7-Question Gate")
    lines.append("")
    lines.append("| # | Question | Verdict (`PASS`/`FAIL`) |")
    lines.append("|---|----------|-------------------------|")
    for qid, question in QUESTIONS:
        lines.append(f"| {qid} | {question} | `[ ]` |")
    lines.append("")
    lines.append("**Rule: one FAIL = STOP, kill the finding, move on.**")
    lines.append("")
    lines.append("## Identity Check (auth findings)")
    lines.append("")
    for check in IDENTITY_CHECKS:
        lines.append(f"- [ ] {check}")
    lines.append("")
    lines.append("## 4 Pre-Submission Gates")
    lines.append("")
    for gid, gname, items in GATES:
        lines.append(f"### {gid}: {gname}")
        lines.append("")
        for item in items:
            lines.append(f"- [ ] {item}")
        lines.append("")
    lines.append("## Verdict")
    lines.append("")
    lines.append("- All 7 questions PASS: `[ ]`")
    lines.append("- All 4 gates PASS: `[ ]`")
    lines.append("- Decision: `SUBMIT` / `KILL` / `CHAIN REQUIRED`")
    lines.append("")
    report = "\n".join(lines)

    if args.output == "-":
        print(report)
    else:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report)
        print(f"Gate report written to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
