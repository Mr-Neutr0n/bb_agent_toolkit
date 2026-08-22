#!/usr/bin/env python3
"""Bounty Range Estimator — estimates payout range from severity, vuln class, and program tier.

Uses published program data patterns (HackerOne/Bugcrowd public tables) as heuristics.
Output is an estimate, never a guarantee. Programs set their own payouts.

Usage:
    bounty_estimator.py estimate --severity critical --vuln-type rce --program-tier top
    bounty_estimator.py estimate --cvss-score 9.1 --impact-class account_takeover --platform hackerone
"""

import argparse
import json
import sys
from datetime import datetime, timezone

# Base ranges (USD) by severity, per platform heuristics from public program tables
BASE_RANGES = {
    "critical": {"low": 3000, "high": 15000},
    "high": {"low": 1000, "high": 5000},
    "medium": {"low": 250, "high": 1500},
    "low": {"low": 50, "high": 400},
    "info": {"low": 0, "high": 50},
}

# Multipliers by vulnerability class (relative to base)
VULN_CLASS_MULTIPLIERS = {
    "rce": 2.5,
    "sqli": 2.0,
    "account_takeover": 2.4,
    "auth_bypass": 1.8,
    "tenant_break": 2.2,
    "ssrf": 1.6,
    "xxe": 1.5,
    "idor": 1.4,
    "xss_stored": 1.3,
    "privilege_escalation": 1.7,
    "financial_loss": 2.6,
    "data_exposure_pii": 1.9,
    "race_condition": 1.3,
    "csrf_state_changing": 0.8,
    "xss_reflected": 0.6,
    "open_redirect": 0.3,
    "info_disclosure": 0.4,
}

# Program tier multipliers
TIER_MULTIPLIERS = {
    # top: FAANG-scale, mature programs with big tables
    "top": 2.0,
    # established: large companies, well-funded programs
    "established": 1.3,
    # standard: typical HackerOne/Bugcrowd public programs
    "standard": 1.0,
    # small: startups, low-table programs
    "small": 0.5,
    # vdp: no bounty, recognition only
    "vdp": 0.0,
}


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def estimate(
    severity: str | None = None,
    cvss_score: float | None = None,
    vuln_type: str = "",
    impact_class: str = "",
    program_tier: str = "standard",
    platform: str = "hackerone",
) -> dict:
    # Derive severity from CVSS if provided
    if cvss_score is not None and not severity:
        if cvss_score >= 9.0:
            severity = "critical"
        elif cvss_score >= 7.0:
            severity = "high"
        elif cvss_score >= 4.0:
            severity = "medium"
        elif cvss_score > 0.0:
            severity = "low"
        else:
            severity = "info"

    severity = (severity or "medium").lower()
    if severity not in BASE_RANGES:
        return {"status": "error", "reason": f"unknown severity '{severity}'"}

    base = BASE_RANGES[severity]
    low = float(base["low"])
    high = float(base["high"])

    # Apply vuln class multiplier (prefer explicit impact_class, fall back to vuln_type)
    cls_key = (impact_class or "").lower()
    if cls_key not in VULN_CLASS_MULTIPLIERS:
        cls_key = (vuln_type or "").lower()
    multiplier_cls = VULN_CLASS_MULTIPLIERS.get(cls_key, 1.0)

    tier_mult = TIER_MULTIPLIERS.get(program_tier.lower(), 1.0)

    est_low = round(low * multiplier_cls * tier_mult)
    est_high = round(high * multiplier_cls * tier_mult)

    # Platform nuance: bugcrowd VRT tends to pay slightly lower mid-range than H1 severity tables
    if platform.lower() == "bugcrowd" and severity in ("medium", "high"):
        est_low = round(est_low * 0.9)

    return {
        "status": "estimated",
        "estimated_at": now_iso(),
        "inputs": {
            "severity": severity,
            "cvss_score": cvss_score,
            "vuln_type": vuln_type or impact_class,
            "class_multiplier": multiplier_cls,
            "program_tier": program_tier,
            "tier_multiplier": tier_mult,
            "platform": platform,
        },
        "bounty_range_usd": {
            "low": est_low,
            "high": est_high,
            "display": f"${est_low:,} - ${est_high:,}" if est_high > 0 else "$0 (VDP / kudos)",
        },
        "disclaimer": "Heuristic estimate only. Actual payouts are set by each program's own table and triage.",
    }


def main():
    parser = argparse.ArgumentParser(description="Bounty Range Estimator")
    sub = parser.add_subparsers(dest="command")

    p_est = sub.add_parser("estimate", help="Estimate bounty range")
    p_est.add_argument("--severity", choices=list(BASE_RANGES.keys()))
    p_est.add_argument("--cvss-score", type=float, default=None)
    p_est.add_argument("--vuln-type", default="")
    p_est.add_argument("--impact-class", default="")
    p_est.add_argument("--program-tier", default="standard",
                       choices=list(TIER_MULTIPLIERS.keys()))
    p_est.add_argument("--platform", default="hackerone", choices=["hackerone", "bugcrowd", "intigriti", "yeswehack"])

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    result = estimate(
        severity=args.severity,
        cvss_score=args.cvss_score,
        vuln_type=args.vuln_type,
        impact_class=args.impact_class,
        program_tier=args.program_tier,
        platform=args.platform,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
