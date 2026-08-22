# Runbook: CVSS 4.0 Scoring

## When
Run `impact-verifier cvss4-score` after `report-readiness`, once impact is confirmed
and you can describe the vulnerability in CVSS 4.0 terms.

```bash
CVSS4_VECTOR="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H" \
bin/bb-run impact-verifier cvss4-score
```

## Building the Vector

Base metrics (all required):
| Metric | Question | Values |
|---|---|---|
| AV | Where can the attacker reach it from? | N network / A adjacent / L local / P physical |
| AC | Does success depend on luck or conditions? | L low / H high |
| AT | Any preconditions beyond the vuln itself? | N none / L low / H high |
| PR | Privileges needed before attacking? | N none / L low / H high |
| UI | Victim action required? | N none / P passive / O active |
| VC/VI/VA | Impact on the vulnerable system? | H / L / N |
| SC/SI/SA | Impact on subsequent systems? | H / L / N |

Common bug-bounty anchors:
- Unauth RCE, full compromise: `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` (10.0 Critical)
- Authenticated IDOR to other tenants' data: `AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:L/SI:N/SA:N`
- Stored XSS with admin victim: add UI:P and consider SI:H for session theft.

## Output Interpretation
- `severity`: Critical / High / Medium / Low — derived from the macrovector band (exact per spec ordering).
- `cvss_score`: interpolated inside the official band; good for triage, use the FIRST
  calculator if a program demands a certification-grade number.
- `macrovector_eq`: equivalence string, useful when comparing two findings of the same class.

## Chaining
Follow with `impact-narrative` using the same finding directory; the narrative's
`suggested_severity` should agree with this score. If they disagree, re-check your metrics.
