# THIRD_PARTY.md — web3-audit skill

Content integrated from the **Claude Bug Bounty Hunter Toolkit** (MIT License).

- Source repo: `output/scratch/compare-shuvonsec/repo` (integrated 2026-08-15)
- Source paths: `skills/web3-audit/SKILL.md` and `tools/token_scanner.py`.

## What was copied

| Adapted file | Source |
|---|---|
| `SKILL.md` | `skills/web3-audit/SKILL.md` (restructured to BountyHarness skill format) |
| `scripts/token_scanner.py` | `tools/token_scanner.py` (adapted: `tools.banner` import replaced with an inline banner function) |
| `scripts/sol_pattern_scan.py` | New script; grep patterns from SKILL.md sections 1-10 |
| `runbooks/bug-classes.md` | SKILL.md sections 1-10 grep patterns + root causes |
| `runbooks/foundry-poc.md` | SKILL.md Foundry PoC template + cheatcodes |
| `runbooks/kill-signals.md` | SKILL.md pre-dive kill signals + target scoring |
| `runbooks/audit-checklist.md` | Derived from SKILL.md structure |
| `payloads/*.txt` | Vulnerable pattern snippets + cheatcode list from SKILL.md |

## MIT License notice

Copyright (c) 2026 Claude Bug Bounty Hunter Contributors. Licensed under the MIT
License (https://opensource.org/licenses/MIT). The above files are redistributed
and/or adapted under that license. Permission is hereby granted, free of charge,
to any person obtaining a copy of this software and associated documentation
files, to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software.
