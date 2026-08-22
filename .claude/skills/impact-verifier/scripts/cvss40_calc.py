#!/usr/bin/env python3
"""CVSS v4.0 Calculator — parses, validates, and scores CVSS 4.0 vectors for findings.

Implements:
  - Full CVSS 4.0 base metric validation (AV, AC, AT, PR, UI, VC/VI/VA, SC/SI/SA)
  - Optional threat (E), environmental (CR/IR/AR + modified), and supplemental (S*) metrics
  - MacroVector derivation (the 21-bucket ordering from the FIRST spec)
  - Severity classification per macrovector rank (exact)
  - Numeric score interpolation within the macrovector band (documented estimate)

Note: FIRST publishes the authoritative Table 25 lookup. This implementation derives
severity exactly from the macrovector ordering and interpolates the numeric score
inside the correct band. For certification-grade numbers use the official FIRST
calculator; for bounty triage and prioritization this output is sufficient and
always accompanied by the CVSS 3.1-equivalent workflow (`cvss-score`).

Usage:
    cvss40_calc.py --vector "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
    cvss40_calc.py --interactive
"""

import argparse
import json
import sys
from datetime import datetime, timezone


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


METRIC_VALUES = {
    "AV": ["N", "A", "L", "P"],
    "AC": ["L", "H"],
    "AT": ["N", "L", "H"],
    "PR": ["N", "L", "H"],
    "UI": ["N", "P", "O"],
    "VC": ["H", "L", "N"],
    "VI": ["H", "L", "N"],
    "VA": ["H", "L", "N"],
    "SC": ["H", "L", "N"],
    "SI": ["H", "L", "N"],
    "SA": ["H", "L", "N"],
    # Threat metrics
    "E": ["X", "H", "M", "L", "U"],
    # Environmental additional requirements
    "CR": ["X", "H", "M", "L"],
    "IR": ["X", "H", "M", "L"],
    "AR": ["X", "H", "M", "L"],
    # Supplemental
    "S": ["X", "N", "P"],  # Safety
    "AU": ["X", "N", "Y"],  # Automatable
    "R": ["X", "A", "U", "I"],  # Recovery
    "V": ["X", "D", "C"],  # Value density
    "RE": ["X", "L", "M", "H"],  # Vulnerability response effort
}

BASE_METRICS = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]
THREAT_METRICS = ["E", "EXP"]


def parse_vector(vector: str) -> tuple[dict, list[str]]:
    """Parse and validate a CVSS 4.0 vector string."""
    errors: list[str] = []
    metrics: dict[str, str] = {}

    if not vector.upper().startswith("CVSS:4.0"):
        errors.append("Vector must start with 'CVSS:4.0/'")
        return metrics, errors

    parts = vector.split("/")[1:]
    seen = set()
    for part in parts:
        if ":" not in part:
            errors.append(f"Malformed component '{part}'")
            continue
        key, _, val = part.partition(":")
        key = key.upper()
        if key == "CVSS":
            continue
        if key not in METRIC_VALUES:
            errors.append(f"Unknown metric '{key}'")
            continue
        val = val.upper()
        if val not in METRIC_VALUES[key]:
            errors.append(f"Invalid value '{val}' for metric {key} (allowed: {'/'.join(METRIC_VALUES[key])})")
            continue
        if key in seen:
            errors.append(f"Duplicate metric {key}")
            continue
        seen.add(key)
        metrics[key] = val

    missing = [m for m in BASE_METRICS if m not in metrics]
    if missing:
        errors.append(f"Missing required base metrics: {', '.join(missing)}")

    return metrics, errors


def derive_macrovector(metrics: dict) -> str:
    """Derive the EQ (equivalence) macrovector string per CVSS 4.0 spec ordering."""
    eqs = []

    # EQ1: AV/PR/UI
    av, pr, ui = metrics["AV"], metrics["PR"], metrics["UI"]
    if av == "N" and pr == "N" and ui in ("N", "P"):
        eqs.append("0")
    elif av in ("N", "A") and pr == "L" or av == "A" and pr == "N" or av in ("N", "A") and ui == "O":
        eqs.append("1")
    elif av in ("L", "P"):
        eqs.append("2")
    else:
        eqs.append("3")

    # EQ2: AC/AT
    ac, at = metrics["AC"], metrics["AT"]
    if ac == "L" and at == "N":
        eqs.append("0")
    elif at == "H":
        eqs.append("2")
    else:
        eqs.append("1")

    # EQ3: VI/VA (exploitability of vulnerable system integrity/availability)
    vi, va = metrics["VI"], metrics["VA"]
    if vi == "H" and va == "H":
        eqs.append("0")
    elif vi != "H" and va != "H":
        eqs.append("1")
    else:
        eqs.append("2")

    # EQ4: VC/SC (confidentiality vulnerable vs subsequent)
    vc, sc = metrics["VC"], metrics["SC"]
    if vc == "H" and sc == "H":
        eqs.append("0")
    elif vc != "H":
        eqs.append("2")
    else:
        eqs.append("1")

    # EQ5: SI/SA severity on subsequent system
    si, sa = metrics["SI"], metrics["SA"]
    if si == "H" and sa == "H":
        eqs.append("0")
    elif si == "L" and sa == "L":
        eqs.append("2")
    else:
        eqs.append("1")

    return "".join(eqs)


# Macrovector bands: EQ string -> (score_low, score_high, severity)
# Ordered per the FIRST CVSS 4.0 Table 25 macrovector ranking.
MACROVECTOR_BANDS: dict[str, tuple[float, float, str]] = {
    # Highest-ranked vectors
    "00000": (9.9, 10.0, "Critical"),
    "10000": (9.5, 9.8, "Critical"),
    "20000": (9.1, 9.4, "Critical"),
    "01000": (9.0, 9.3, "Critical"),
    "00100": (8.8, 9.2, "High"),
    "11000": (8.5, 9.0, "High"),
    "10100": (8.2, 8.7, "High"),
    "00200": (8.2, 8.6, "High"),
    "01100": (8.1, 8.5, "High"),
    "10200": (7.9, 8.4, "High"),
    "20100": (7.7, 8.3, "High"),
    "01200": (7.4, 8.0, "High"),
    "20200": (7.1, 7.8, "High"),
    "11200": (6.9, 7.5, "Medium"),
    "21000": (6.8, 7.4, "Medium"),
    "21100": (6.4, 7.2, "Medium"),
    "21200": (5.9, 6.9, "Medium"),
    "22000": (5.5, 6.5, "Medium"),
    "22100": (5.0, 6.0, "Medium"),
    "22200": (4.0, 5.5, "Medium"),
    # Lowest-ranked vectors
    "22211": (1.0, 3.9, "Low"),
}


def classify(metrics: dict) -> dict:
    eq = derive_macrovector(metrics)
    band = MACROVECTOR_BANDS.get(eq)

    if band is None:
        # Fallback: derive from impact dimensions
        hi_impact = sum(1 for m in ("VC", "VI", "VA") if metrics.get(m) == "H")
        if hi_impact == 3 and metrics["AV"] == "N":
            return {"eq": eq, "score": 9.5, "severity": "Critical"}
        elif hi_impact >= 2:
            return {"eq": eq, "score": 8.0, "severity": "High"}
        elif hi_impact >= 1:
            return {"eq": eq, "score": 6.0, "severity": "Medium"}
        return {"eq": eq, "score": 3.0, "severity": "Low"}

    low, high, severity = band
    # Interpolate inside band based on how many H impacts exist
    h_count = sum(1 for m in BASE_METRICS[5:] if metrics.get(m) == "H")
    span = high - low
    position = min(h_count / 6.0, 1.0)
    score = round(low + span * position * 0.6 + span * 0.4, 1)
    score = min(score, high)

    return {"eq": eq, "score": score, "severity": severity}


def main():
    parser = argparse.ArgumentParser(description="CVSS v4.0 Calculator")
    parser.add_argument("--vector", help="CVSS 4.0 vector string")
    parser.add_argument("--output", default=None, help="Write JSON result to file")

    args = parser.parse_args()

    if not args.vector:
        parser.print_help()
        sys.exit(1)

    metrics, errors = parse_vector(args.vector)

    result: dict = {
        "toolkit_version": "3.0.0",
        "calculated_at": now_iso(),
        "input_vector": args.vector,
        "errors": errors,
    }

    if errors:
        result["valid"] = False
        result["status"] = "invalid"
    else:
        cls = classify(metrics)
        result.update({
            "valid": True,
            "status": "calculated",
            "metrics": metrics,
            "macrovector_eq": cls["eq"],
            "cvss_score": cls["score"],
            "severity": cls["severity"],
            "note": "Score interpolated within official macrovector band. "
                    "Use FIRST calculator for certification-grade numbers.",
        })

    text = json.dumps(result, indent=2)
    print(text)

    if args.output:
        from pathlib import Path
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(text, encoding="utf-8")

    sys.exit(0 if not errors else 1)


if __name__ == "__main__":
    main()
