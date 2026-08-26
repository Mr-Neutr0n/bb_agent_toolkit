# Enrich - run post-script on next finding

```bash
bin/bb-run enrichment enrich
# or
python3 .claude/skills/enrichment/scripts/enrich.py enrich --findings output/acme/impact-verifier/verified.jsonl --post-script .claude/skills/enrichment/payloads/report_template.md --output .bb/enrichments.jsonl
```
