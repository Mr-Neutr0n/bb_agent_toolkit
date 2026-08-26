# List Enrichments

## Overview
Inspect existing enrichments without running anything.

## Command
```bash
python3 .claude/skills/enrichment/scripts/list_enrichments.py --enrichments output/acme/enrichment/enrichments.jsonl
python3 .claude/skills/enrichment/scripts/list_enrichments.py --enrichments output/acme/enrichment/enrichments.jsonl --json
```

## Output
- Human-readable: count and per-enrichment post_script + output keys
- JSON: full array when `--json` is passed

## Use
Check which findings have been enriched and with which post-scripts before deciding to run `supplemental`.
