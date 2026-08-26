# Apply Model Overrides

## Overview
Kritt-style per-depth model selection: cheap model for shallow recon, stronger model for deep vuln analysis.

## Quick Reference
- Payload: `.claude/skills/planner/payloads/model_overrides_example.json`
- Command: `python3 .claude/skills/planner/scripts/model_overrides.py --plan plan.json --overrides overrides.json --output plan.with_models.json`

## Workflow

```bash
# Use example overrides
bin/bb-run planner apply-model-overrides

# Custom overrides
MODEL_OVERRIDES=my-overrides.json bin/bb-run planner apply-model-overrides
```

Overrides JSON maps depth (as string) to model name, with `default` fallback:

```json
{
  "0": "gpt-4o-mini",
  "2": "claude-opus-4",
  "default": "gpt-4o-mini"
}
```

## Evidence Required
- `plan.with_models.json` with `model_override` per plan item
