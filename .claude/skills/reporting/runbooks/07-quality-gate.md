# Runbook: Quality Gate

## When
Run `reporting quality-check` after rendering a report and before submitting it anywhere.

```bash
bin/bb-run reporting quality-check
```

Set `REPORT_FILE` if your report lives somewhere other than `$OUTDIR/reports/report_hackerone.md`,
and `FINDING_DIR` so the gate can check evidence artifacts.

## What the Gate Blocks On (errors)
- Missing required sections: Summary, Steps to Reproduce, Proof of Concept, Impact.
- Placeholder text: TODO, TBD, FIXME, `[insert ...]`, `<your_name>`, lorem ipsum.
- Leaked secret patterns in the report body: live Stripe keys, GitHub tokens,
  AWS access keys, private key blocks, Slack tokens.

## What the Gate Warns On (advisory)
- Thin sections: summary < 30 words, steps < 20, impact < 40.
- No numbered reproduction steps detected.
- No CVSS score mentioned in the report.
- Missing `request.txt` / `response.txt` / screenshot in the finding directory.

## Triage Flow
1. Errors present: fix the report, re-run. Never submit with errors.
2. Warnings only: judge case by case. A missing screenshot on a config issue may be fine;
   a thin impact section is usually worth fixing because it drives triage speed.
3. Save `quality_report.json` next to the report as submission provenance.

## Exit Codes
- 0: no errors, safe to submit (warnings possible).
- 1: one or more errors, do not submit.
