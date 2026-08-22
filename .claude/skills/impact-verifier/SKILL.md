# Impact Verifier

## Overview
The final gate before reporting. Converts candidate findings into confirmed bounty-grade reports only when impact is proven. Enforces evidence completeness, false-positive checks, impact classification, and report readiness scoring.

## Quick Reference
- **Skill**: impact-verifier
- **Version**: 1.1.0
- **Bounded Context**: ImpactContext
- **Required tools**: `python3`, `jq`, `curl`
- **Risk tier**: passive (validates, does not test)

## Workflow Selection
- Collect: `collect-candidates` from all skill output directories.
- Classify: `classify-impact` to determine impact class.
- Verify: Run the specific verify workflow for the impact class.
- Gate: `false-positive-gate` and `report-readiness` before reporting.
- Score: `cvss4-score` for CVSS 4.0 severity, then `impact-narrative` for the impact write-up.

## Available Workflows
| Workflow | Purpose |
|---|---|
| `collect-candidates` | Aggregate candidate findings from all skill outputs. |
| `classify-impact` | Determine impact class for a candidate finding. |
| `verify-data-exposure` | Prove actual data exposure from unauthorized access. |
| `verify-privilege-escalation` | Prove role/permission boundary was broken. |
| `verify-account-takeover` | Prove full account takeover path. |
| `verify-tenant-break` | Prove cross-tenant data access. |
| `false-positive-gate` | Run automated false-positive checks. |
| `report-readiness` | Score finding readiness for submission. |
| `cvss4-score` | Calculate CVSS 4.0 score, macrovector, and severity from a vector. |
| `impact-narrative` | Generate impact narrative with attack scenario and PII detection. |

## Workflow Selection Notes
- `cvss4-score` needs `CVSS4_VECTOR` in context (full vector string starting with `CVSS:4.0/`).
- `impact-narrative` needs `FINDING_DIR` (evidence directory with `response.txt`) and
  `IMPACT_CLASS` (e.g. `account_takeover`, `data_exposure`, `tenant_break`, `rce`).
- The narrative auto-detects sensitive fields (`email`, `token`, `card_number`, ...)
  in the captured response and strengthens the evidence section accordingly.

## Evidence Required
- Impact class confirmation with proof artifacts.
- False-positive checklist completed.
- Report readiness score >= 80.
- All standard evidence artifacts present.
- CVSS 4.0 vector string with metric breakdown (`cvss4.json`).
- Impact narrative with attack scenario and observed data classes (`impact.md`).
- Redact credentials, session cookies, bearer tokens, and auth headers from all collected evidence before reporting. Evidence stays local-only under `$OUTDIR/impact-verifier` and is never committed; sanitize requests/responses (gitignore evidence directories) so no secrets leak into reports.

## References
- Bugcrowd VRT 1.18
- FIRST CVSS v4.0 specification (macrovector bands)
- OWASP ASVS V4 (Access Control)
- OWASP Reporting guidelines