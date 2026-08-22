# THIRD_PARTY.md — triage-validation skill

Content integrated from the **Claude Bug Bounty Hunter Toolkit** (MIT License).

- Source repo: `output/scratch/compare-shuvonsec/repo` (integrated 2026-08-15)
- Source path: `skills/triage-validation/SKILL.md` (7-Question Gate, 4 pre-submission
  gates, NEVER SUBMIT list, conditionally-valid chain table, CVSS 3.1 quick reference,
  kill-fast rules, anti-patterns) and `rules/hunting.md` + `rules/reporting.md`
  (referenced in `references/shuvonsec-rules/`).

## What was copied

| Adapted file | Source |
|---|---|
| `SKILL.md` | `skills/triage-validation/SKILL.md` (restructured to BountyHarness skill format) |
| `runbooks/run-gate.md` | Q1 template, 4 gates, kill-fast rules, anti-patterns |
| `runbooks/check-never-submit.md` | NEVER SUBMIT list + N/A kill signals |
| `runbooks/chain-validity.md` | Conditionally-valid chain-required table |
| `runbooks/cvss-quick-reference.md` | CVSS 3.1 quick reference + severity decision guide |
| `scripts/never_submit_check.py` | NEVER SUBMIT list + kill-signal table, machine-readable |
| `scripts/chain_validity.py` | Conditionally-valid table, machine-readable |
| `scripts/triage_gate.py` | Gate checklist content (new script, content adapted from source) |

## MIT License notice

Copyright (c) 2026 Claude Bug Bounty Hunter Contributors. Licensed under the MIT
License (https://opensource.org/licenses/MIT). The above files are redistributed
and/or adapted under that license. Permission is hereby granted, free of charge,
to any person obtaining a copy of this software and associated documentation
files, to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software.
