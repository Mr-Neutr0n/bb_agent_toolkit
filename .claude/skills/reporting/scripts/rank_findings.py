#!/usr/bin/env python3
"""Severity ranker — apply composable markdown ranker rules to findings.

Kritt-style rankers are plain markdown describing severity policy. This script
reads one or more ranker markdown files plus a findings JSONL, then uses
deterministic keyword heuristics to re-rank findings by bounty impact.

If an LLM is available (OPENAI_API_KEY / ANTHROPIC_API_KEY), pass --llm to
delegate ranking to the model with the ranker markdown as system prompt.
Otherwise falls back to local heuristic ranking.

Usage:
    rank_findings.py --findings output/acme/verified.jsonl --ranker rankers/bug-bounty.md --output ranked.jsonl
    rank_findings.py --findings findings.jsonl --ranker rankers/*.md --llm --output ranked.jsonl
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "informational": 4}
REVERSE_ORDER = {v: k for k, v in SEVERITY_ORDER.items()}

IMPACT_KEYWORDS = {
    "critical": [r"\brce\b", r"remote code", r"account takeover", r"ato\b", r"auth.*bypass", r"privilege escalation.*admin", r"ssrf.*metadata", r"sql injection.*rce"],
    "high": [r"\bsqli\b", r"\bssrf\b", r"\bidor\b.*\bpii\b", r"xss.*stored", r"file upload.*rce", r"xxe\b", r"path traversal"],
    "medium": [r"\bxss\b.*reflected", r"\bcsrf\b", r"\bcors\b", r"host header", r"open redirect", r"idor.*low"],
    "low": [r"clickjacking", r"information disclosure.*low", r"verbose error", r"missing header"],
}

DEFAULT_RANKER = """# Default severity ranker

Critical: reachable RCE, full account takeover without user interaction, authentication bypass to admin, SSRF to cloud metadata.
High: SQLi, SSRF to internal services, stored XSS in privileged context, IDOR exposing PII at scale, file upload to RCE.
Medium: reflected XSS, CSRF on state-changing endpoints, CORS misconfig with credentials, host header injection with cache impact, open redirect chaining to account effects.
Low: clickjacking on non-sensitive pages, verbose errors, missing security headers without direct exploit, email enumeration.
Informational: best-practice deviations, theoretical vectors without reachable trigger.
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    print(f"[{now_iso()}] {msg}", file=sys.stderr)


def load_ranker(paths: list[str]) -> str:
    if not paths:
        return DEFAULT_RANKER
    parts: list[str] = []
    for p in paths:
        for expanded in Path().glob(p) if any(c in p for c in "*?[]") else [Path(p)]:
            if isinstance(expanded, str):
                expanded = Path(expanded)
            if expanded.exists():
                parts.append(expanded.read_text(encoding="utf-8"))
            else:
                log(f"WARN: ranker not found: {p}")
    return "\n\n".join(parts) if parts else DEFAULT_RANKER


def heuristic_severity(finding: dict, ranker_text: str) -> str:
    text = " ".join([
        finding.get("title", ""),
        finding.get("summary", ""),
        finding.get("description", ""),
        finding.get("vulnerability_type", ""),
        finding.get("type", ""),
        finding.get("impact", ""),
    ]).lower()

    for sev in ["critical", "high", "medium", "low"]:
        for pat in IMPACT_KEYWORDS[sev]:
            if re.search(pat, text):
                return sev
    # fallback to declared severity
    declared = (finding.get("severity") or finding.get("bounty_rank_impact_level") or "medium").lower()
    if declared in SEVERITY_ORDER:
        return declared
    return "medium"


def rank_findings(findings: list[dict], ranker_text: str, use_llm: bool = False) -> list[dict]:
    if use_llm and os.environ.get("OPENAI_API_KEY", ""):
        try:
            return llm_rank(findings, ranker_text)
        except Exception as e:
            log(f"LLM ranking failed ({e}), falling back to heuristic")
    elif use_llm:
        log("WARN: --llm requested but OPENAI_API_KEY not set, using heuristic")

    enriched = []
    for f in findings:
        sev = heuristic_severity(f, ranker_text)
        enriched.append({**f, "ranked_severity": sev, "rank_order": SEVERITY_ORDER[sev]})

    enriched.sort(key=lambda x: (x["rank_order"], -(x.get("cvss") or x.get("base_score") or 0)))

    for i, f in enumerate(enriched):
        f["bounty_rank"] = i + 1
        f["bounty_rank_impact_level"] = f["ranked_severity"]
        f.pop("rank_order", None)

    return enriched


def llm_rank(findings: list[dict], ranker_text: str) -> list[dict]:
    try:
        from openai import OpenAI  # type: ignore
    except ImportError:
        raise RuntimeError("openai package not installed (pip install openai)")

    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    prompt = f"""You are a bug-bounty triager. Rank these findings by bounty impact using this policy:

{ranker_text}

Return JSON array of objects with fields: id (original index), ranked_severity (critical/high/medium/low/info), reason (one line).
Findings:
{json.dumps([{i: findings[i].get('title', findings[i].get('summary', ''))[:200]} for i in range(len(findings))], indent=2)}
"""
    resp = client.chat.completions.create(
        model=os.environ.get("RANKER_MODEL", "gpt-4o-mini"),
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
    )
    content = resp.choices[0].message.content or "[]"
    # extract JSON array
    m = re.search(r"\[.*\]", content, re.DOTALL)
    if not m:
        raise RuntimeError("LLM returned no JSON array")
    ranked = json.loads(m.group(0))
    sev_map = {r["id"]: r["ranked_severity"].lower() for r in ranked if "id" in r}
    enriched = []
    for i, f in enumerate(findings):
        sev = sev_map.get(i, heuristic_severity(f, ranker_text))
        if sev not in SEVERITY_ORDER:
            sev = "medium"
        enriched.append({**f, "ranked_severity": sev, "rank_order": SEVERITY_ORDER[sev], "rank_reason": next((r.get("reason", "") for r in ranked if r.get("id") == i), "")})

    enriched.sort(key=lambda x: (x["rank_order"], -(x.get("cvss") or 0)))
    for i, f in enumerate(enriched):
        f["bounty_rank"] = i + 1
        f["bounty_rank_impact_level"] = f["ranked_severity"]
        f.pop("rank_order", None)
    return enriched


def main() -> None:
    p = argparse.ArgumentParser(description="Severity ranker - apply markdown ranker rules to findings")
    p.add_argument("--findings", required=True, help="Findings JSONL (verified.jsonl)")
    p.add_argument("--ranker", nargs="*", default=[], help="Ranker markdown file(s), glob supported")
    p.add_argument("--output", "-o", required=True, help="Output ranked JSONL")
    p.add_argument("--llm", action="store_true", help="Use OpenAI LLM for ranking (requires OPENAI_API_KEY)")
    p.add_argument("--dry-run", action="store_true", help="Print ranking without writing")
    args = p.parse_args()

    src = Path(args.findings)
    if not src.exists():
        log(f"ERROR: findings file not found: {src}")
        sys.exit(1)

    findings: list[dict] = []
    for line in src.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    if not findings:
        log("No findings to rank")
        sys.exit(0)

    ranker_text = load_ranker(args.ranker)
    ranked = rank_findings(findings, ranker_text, use_llm=args.llm)

    if args.dry_run:
        print(json.dumps([{"rank": f["bounty_rank"], "severity": f["bounty_rank_impact_level"], "title": f.get("title", "")[:80]} for f in ranked], indent=2))
        return

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        for f in ranked:
            fh.write(json.dumps(f) + "\n")

    summary = {}
    for f in ranked:
        summary[f["bounty_rank_impact_level"]] = summary.get(f["bounty_rank_impact_level"], 0) + 1
    log(f"Ranked {len(ranked)} findings -> {out} {summary}")
    print(json.dumps({"ranked": str(out), "counts": summary, "total": len(ranked)}))


if __name__ == "__main__":
    main()
