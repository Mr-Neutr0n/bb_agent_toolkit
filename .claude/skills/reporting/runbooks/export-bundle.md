# Export Bundle

## Overview
Package findings into a single share-safe ZIP with manifest. Mirrors Kritt's finding export: canonical findings, structured data, post-processing output, reports, and PoCs in one archive with a manifest. Completed scans produce complete bundles; stopped or failed scans with findings produce clearly marked partial bundles. Attacker-influenced report and PoC source is kept as plain text.

## Quick Reference
- Command: `python3 .claude/skills/reporting/scripts/export_bundle.py --outdir $OUTDIR --output $OUTDIR/reports/bundle.zip`
- Partial: add `--partial-reason "stopped by operator"`
- Safety: passive (local file packaging, no network)

## Workflow

```bash
# Complete bundle from a finished engagement
python3 .claude/skills/reporting/scripts/export_bundle.py \
  --outdir output/acme.com/2024-01-15_1000 \
  --output output/acme.com/2024-01-15_1000/reports/bundle.zip

# Partial bundle (interrupted scan that still found something)
python3 .claude/skills/reporting/scripts/export_bundle.py \
  --outdir output/acme.com/2024-01-15_1000 \
  --output /tmp/bundle.zip \
  --partial-reason "stopped by operator after rate limit"
```

## Output ZIP layout

```
manifest.json               # toolkit, version, target, counts, kind (complete/partial)
findings.json               # canonical findings array (sanitized plain text)
structured/<skill>/*.jsonl  # original JSONL sources
reports/**                  # any report*.md files
evidence/**                 # evidence files
PARTIAL.txt                 # present only when kind=partial
```

`manifest.json` is share-safe. PoC and report fields that may contain attacker
input are plain text (see `sanitize_text` - control chars stripped). Do not
render those fields as HTML without additional sanitization.

## Evidence Required
- `bundle.zip` with matching `manifest.json` findings_count
- `partial` bundles must include PARTIAL.txt and a non-empty reason
