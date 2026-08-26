# Enrichment

## Overview
Post-processing that enriches verified findings with report drafts, proof-of-concept diffs, and triage chips. Inspired by Kritt's post-scripts: each enrichment is a focused prompt that receives a single finding's context (vulnerability fields, trigger flow, file path) plus scan context, and produces typed output that is stored separately from the finding itself.

## Quick Reference
- Skill: `enrichment`
- Severity range: `info`, `low`, `medium`, `high`, `critical`
- Required tools: `python3`, `jq`
- Expected input files: `output/*/impact-verifier/verified.jsonl` or `reports/ranked.jsonl`
- Scope check: passive enrichment (local file transformation, no network unless `--llm` is set).

## Workflow Selection
- Start with `enrich` to run a post-script on the next unenriched finding.
- Use `supplemental` to re-run a different post-script on previously enriched findings (additive, history preserved).
- Use `list-enrichments` to inspect existing enrichments without running anything.
- Runbooks: `runbooks/` and select the closest phase when workflow names do not map 1:1.

## Available Workflows
| Workflow | Purpose | Script paths | Primary outputs | Evidence |
| --- | --- | --- | --- | --- |
| `enrich` | Run a post-script on the next unenriched finding | `.claude/skills/enrichment/scripts/enrich.py` | `$OUTDIR/enrichment/enrichments.jsonl` | `$OUTDIR/enrichment/evidence/` |
| `supplemental` | Re-run a post-script on a previously enriched finding (additive) | `.claude/skills/enrichment/scripts/enrich.py` | `$OUTDIR/enrichment/enrichments.jsonl` | `$OUTDIR/enrichment/evidence/` |
| `list-enrichments` | List enrichments and their status | `.claude/skills/enrichment/scripts/list_enrichments.py` | stdout | — |

## Evidence Required
- Store the finding's original `bounty_rank` and `vulnerability_type` alongside the enrichment
- Keep `post_script` name, prompt template, and output JSON in `$OUTDIR/enrichment/enrichments.jsonl` (and `.bb/enrichments.jsonl` if you use that path via symlink)
- `_reserved_report` output is markdown for the report tab; `_reserved_poc` is a git diff for the PoC tab; `_chip_*` outputs are short tags aggregated from all enrichments
- Redact tokens and PII before sharing enrichments; evidence stays local-only

## References
- Source of truth: `skill.yaml`
- Runbooks: `runbooks/`
- Kritt post-scripts: `open-kritt` `docs-site/post-scripts/*.mdx` (reserved keys, supplemental runs)
