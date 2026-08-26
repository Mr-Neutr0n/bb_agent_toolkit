# Import Workflow

## Overview
Convert a portable `open-kritt-workflow` v2 JSON export into a BountyHarness playbook YAML.

## Quick Reference
- Input: `open-kritt-workflow` v2 JSON with `levels[].steps[]`, `outputFormat`, `depth`, `multiOutput`
- Command: `python3 tools/import_workflow.py --input workflow.json --output playbooks/imported.yaml`
- Dry run: add `--dry-run` to print YAML without writing
- Safety: passive (local file conversion, no network)

## Workflow

```bash
# From a Kritt export
python3 tools/import_workflow.py \
  --input /tmp/open-kritt-workflow.json \
  --output .claude/skills/planner/playbooks/imported.yaml \
  --name "Imported Kritt Workflow"

# Via skill workflow
WORKFLOW_JSON=/tmp/open-kritt-workflow.json \
  PLAYBOOK_OUT=.claude/skills/planner/playbooks/imported.yaml \
  bin/bb-run planner import-workflow

# Dry run validation
python3 tools/import_workflow.py --input workflow.json --dry-run
```

## Mapping

- `levels[].depth` -> `phases[].id` (`depth-N`)
- `levels[].steps[].content` -> `phases[].steps[].inputs.prompt` (truncated to 500 chars)
- `levels[].outputFormat` -> `phases[].steps[].outputs`
- `kind`/`version` preserved in `playbook.source` header with `imported_at` timestamp

## Evidence Required
- Input JSON kept under `output/` or `.bb/` if it contains private prompts
- Output playbook validated via `bin/bb-run planner validate-playbook`

## Limits

- File size limit 2MB (Kritt's own limit)
- Steps are mapped to `auto-research/import-candidate` as placeholder skill; remap to specific skills after import
- `boundSourceStepId` routing is noted but not yet translated to explicit skill dependencies - review the generated playbook before execution
