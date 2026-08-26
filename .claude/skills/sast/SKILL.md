# SAST

## Overview
SAST integration that parses SARIF (Semgrep, Trivy, Bearer) and imports findings.

## Quick Reference
- Skill: `sast`
- Required tools: `python3`, `jq`
- Risk tier: passive

## Workflow Selection
- Start with `import-sarif` to parse a SARIF file.

## Available Workflows
| Workflow | Purpose | Script paths | Primary outputs | Evidence |
| --- | --- | --- | --- | --- |
| `import-sarif` | Import SARIF and count by severity | `.claude/skills/sast/scripts/sarif_import.py` | `$OUTDIR/sast/sarif_findings.json` | `$OUTDIR/sast/evidence/` |

## Evidence Required
- SARIF file path and workspace name
- Output JSON with counts

## References
- Source of truth: `skill.yaml`
