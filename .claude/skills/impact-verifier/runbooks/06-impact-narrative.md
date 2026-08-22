# Runbook: Impact Narrative Generation

## When
Run `impact-verifier impact-narrative` after `cvss4-score`, right before moving to the
`reporting` skill. It converts raw evidence into the impact section triagers actually read.

```bash
FINDING_DIR=$EVIDENCE_DIR/finding_001 IMPACT_CLASS=account_takeover \
bin/bb-run impact-verifier impact-narrative
```

Inputs:
- `FINDING_DIR`: evidence directory containing `response.txt` (and ideally `request.txt`).
- `IMPACT_CLASS`: one of account_takeover, tenant_break, data_exposure,
  privilege_escalation, financial_loss, rce, ssrf.
- `TARGET_URL`: optional, embedded in output metadata.

## What You Get
1. **Narrative** — what an attacker concretely achieves, tuned to the impact class.
2. **Attack scenario** — numbered walkthrough from attacker position to impact.
3. **Observed data classes** — the script regexes `response.txt` for sensitive fields
   (`email`, `token`, `card_number`, `password_hash`, ...). Hits strengthen the report:
   you are showing regulated-data disclosure, not claiming it.
4. **Evidence strength/gaps** — flags missing `response.txt` before you submit a claim
   that will get closed as N/A.
5. **CVSS hints + suggested severity** — cross-check against your cvss4 result.

## Editing Guidance
The narrative is a strong starting point, not a final draft. Before submitting:
- Replace generic wording with target-specific object names and real values (redacted).
- Keep the PII field list; delete any field names that turned out to be false positives.
- If evidence gaps were flagged, go capture the missing artifact first.

## Anti-Patterns
- Submitting the template verbatim: triagers recognize boilerplate and deprioritize it.
- Claiming classes the response does not show: kills credibility for the whole report.
- Skipping this step because "the PoC speaks for itself": it does not; impact framing
  is what separates bounty-paid reports from informative closures.
