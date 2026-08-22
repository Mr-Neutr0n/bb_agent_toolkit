#!/usr/bin/env python3
"""Impact Narrative Generator — produces structured impact text from finding evidence.

Reads a finding's evidence directory (request.txt, response.txt, metadata) plus
impact class and generates:
  - Impact narrative (what an attacker achieves)
  - Attack scenario walkthrough
  - Business risk framing
  - CVSS metric suggestions inferred from evidence

Usage:
    impact_narrative.py generate --finding-dir evidence/finding_001 --impact-class account_takeover --output impact.md
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


IMPACT_NARRATIVES = {
    "account_takeover": {
        "narrative": (
            "An unauthenticated or low-privilege attacker can fully compromise arbitrary user "
            "accounts. This grants complete control over victim data: profile information, "
            "authentication credentials, session tokens, payment methods, and any functionality "
            "available to the legitimate account owner."
        ),
        "scenario": [
            "1. Attacker identifies the vulnerable endpoint or flow.",
            "2. Attacker supplies the crafted input shown in the PoC.",
            "3. The application grants attacker-controlled access to another user's account.",
            "4. Attacker now operates as the victim: reading data, changing credentials, and locking out the real owner.",
        ],
        "cvss_hints": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C"},
        "typical_bounty_severity": "critical",
    },
    "tenant_break": {
        "narrative": (
            "An authenticated tenant can read or modify data belonging to other tenants. In "
            "multi-tenant systems this is a trust-boundary failure with regulatory implications "
            "(GDPR, SOC 2, HIPAA depending on data classes)."
        ),
        "scenario": [
            "1. Attacker registers a legitimate tenant account.",
            "2. Attacker replays requests while substituting object identifiers from another tenant.",
            "3. Application returns or mutates cross-tenant records without authorization checks.",
        ],
        "cvss_hints": {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "C"},
        "typical_bounty_severity": "high",
    },
    "data_exposure": {
        "narrative": (
            "Sensitive data is disclosed to unauthorized parties. Depending on the data classes "
            "observed in the response (PII, credentials, tokens, health or financial records), this "
            "may constitute a reportable breach under applicable regulation."
        ),
        "scenario": [
            "1. Attacker sends the request shown in the PoC.",
            "2. Response contains fields that should be redacted or access-restricted.",
            "3. Data can be harvested at scale by enumerating identifiers.",
        ],
        "cvss_hints": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U"},
        "typical_bounty_severity": "medium",
    },
    "privilege_escalation": {
        "narrative": (
            "A user with limited privileges can elevate to a more powerful role, gaining "
            "administrative capabilities reserved for trusted operators."
        ),
        "scenario": [
            "1. Attacker authenticates with a standard-privilege account.",
            "2. Attacker invokes the privileged action via parameter tampering or mass assignment.",
            "3. Application accepts the elevated operation without verifying role authorization.",
        ],
        "cvss_hints": {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U"},
        "typical_bounty_severity": "high",
    },
    "financial_loss": {
        "narrative": (
            "The vulnerability enables direct monetary loss: fraudulent transactions, price "
            "manipulation, refund abuse, or bypassing payment obligations."
        ),
        "scenario": [
            "1. Attacker initiates the affected financial workflow.",
            "2. Attacker manipulates state (race, replay, parameter tampering) per the PoC.",
            "3. Transaction completes on terms favorable to the attacker.",
        ],
        "cvss_hints": {"AV": "N", "AC": "H", "PR": "L", "UI": "N", "S": "U"},
        "typical_bounty_severity": "critical",
    },
    "rce": {
        "narrative": (
            "Remote code execution allows an attacker to run arbitrary commands on the server, "
            "fully compromising confidentiality, integrity, and availability of the system and any "
            "connected infrastructure reachable from it."
        ),
        "scenario": [
            "1. Attacker delivers the payload to the vulnerable parser or executor.",
            "2. Payload executes with application privileges.",
            "3. Attacker pivots using the foothold (credential theft, lateral movement).",
        ],
        "cvss_hints": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C"},
        "typical_bounty_severity": "critical",
    },
    "ssrf": {
        "narrative": (
            "Server-side request forgery lets the application make attacker-directed requests. "
            "Depending on network position this exposes internal services, cloud metadata "
            "endpoints, and credential stores."
        ),
        "scenario": [
            "1. Attacker submits a URL or resource reference controlled by them.",
            "2. Server fetches the resource from its privileged network position.",
            "3. Attacker reads internal responses directly or exfiltrates via OOB callbacks.",
        ],
        "cvss_hints": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C"},
        "typical_bounty_severity": "high",
    },
}

DEFAULT = IMPACT_NARRATIVES["data_exposure"]


PII_FIELD_RE = re.compile(
    r'"(?:email|phone|ssn|dob|address|first_name|last_name|full_name|'
    r'credit_card|card_number|token|password_hash|api_key)"',
    re.I,
)


def load_evidence(finding_dir: str) -> dict:
    d = Path(finding_dir)
    ev = {"response_body": "", "has_request": False, "has_response": False}
    if not d.exists():
        return ev
    resp = d / "response.txt"
    if resp.exists():
        ev["response_body"] = resp.read_text(encoding="utf-8", errors="replace")
        ev["has_response"] = True
    req = d / "request.txt"
    if req.exists():
        ev["has_request"] = True
    return ev


def detect_pii_fields(response_body: str) -> list[str]:
    return sorted(set(m.group(1).strip('"') for m in PII_FIELD_RE.finditer(response_body)))


def generate(finding_dir: str, impact_class: str, target_url: str = "") -> dict:
    tpl = IMPACT_NARRATIVES.get(impact_class, DEFAULT)
    ev = load_evidence(finding_dir)

    pii_fields = detect_pii_fields(ev["response_body"]) if ev["response_body"] else []

    narrative_lines = [tpl["narrative"], ""]
    narrative_lines.append("## Attack Scenario")
    narrative_lines.extend(tpl["scenario"])

    if pii_fields:
        narrative_lines.append("")
        narrative_lines.append("## Observed Data Classes")
        narrative_lines.append(
            f"Response evidence contains sensitive fields: {', '.join(f'`{f}`' for f in pii_fields)}."
        )
        narrative_lines.append(
            "This elevates impact beyond theoretical exposure: the response body itself "
            "demonstrates unauthorized disclosure of regulated or private data."
        )

    if ev["has_response"]:
        narrative_lines.append("")
        narrative_lines.append("## Evidence Strength")
        narrative_lines.append(
            "Full HTTP response captured in `response.txt`. Impact claim is backed by raw "
            "application output rather than inference."
        )
    else:
        narrative_lines.append("")
        narrative_lines.append("## Evidence Gaps")
        narrative_lines.append(
            "No `response.txt` captured. Capture the full response before submission; "
            "reports claiming impact without raw evidence face duplicate/N/A risk."
        )

    result = {
        "generated_at": now_iso(),
        "impact_class": impact_class,
        "target_url": target_url,
        "pii_fields_observed": pii_fields,
        "cvss_suggested_metrics": tpl["cvss_hints"],
        "suggested_severity": tpl["typical_bounty_severity"],
        "narrative_markdown": "\n".join(narrative_lines),
    }
    return result


def main():
    parser = argparse.ArgumentParser(description="Impact Narrative Generator")
    sub = parser.add_subparsers(dest="command")

    p_gen = sub.add_parser("generate", help="Generate impact narrative")
    p_gen.add_argument("--finding-dir", required=True)
    p_gen.add_argument("--impact-class", required=True, help="e.g. account_takeover, data_exposure, rce")
    p_gen.add_argument("--target-url", default="")
    p_gen.add_argument("--output", required=True)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    result = generate(args.finding_dir, args.impact_class, args.target_url)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(result["narrative_markdown"], encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "narrative_markdown"}, indent=2))
    print(f"narrative written to {args.output}")


if __name__ == "__main__":
    main()
