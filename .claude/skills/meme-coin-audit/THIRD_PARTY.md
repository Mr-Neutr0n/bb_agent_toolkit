# THIRD_PARTY.md — meme-coin-audit skill

Content integrated from the **Claude Bug Bounty Hunter Toolkit** (MIT License).

- Source repo: `output/scratch/compare-shuvonsec/repo` (integrated 2026-08-15)
- Source paths: `skills/meme-coin-audit/SKILL.md` and `tools/token_scanner.py`.

## What was copied

| Adapted file | Source |
|---|---|
| `SKILL.md` | `skills/meme-coin-audit/SKILL.md` (restructured to BountyHarness skill format) |
| `scripts/token_scanner.py` | `tools/token_scanner.py` (adapted: `tools.banner` import replaced with an inline banner function) |
| `scripts/authority_check.py` | New script; patterns from SKILL.md bug classes 1-8 |
| `runbooks/token-scan.md` | SKILL.md "AUTOMATED SCANNER" section |
| `runbooks/onchain-checks.md` | SKILL.md "SOLANA QUICK CHECKS" section |
| `runbooks/token-exploit-poc.md` | SKILL.md Foundry PoC template |
| `runbooks/kill-signals.md` | SKILL.md "PRE-DIVE KILL SIGNALS" section |
| `payloads/*.txt` | Grep patterns and rug vectors from SKILL.md bug classes |

## MIT License notice

Copyright (c) 2026 Claude Bug Bounty Hunter Contributors. Licensed under the MIT
License (https://opensource.org/licenses/MIT). The above files are redistributed
and/or adapted under that license. Permission is hereby granted, free of charge,
to any person obtaining a copy of this software and associated documentation
files, to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software.
