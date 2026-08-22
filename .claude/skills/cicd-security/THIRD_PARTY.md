# THIRD_PARTY.md — cicd-security skill

Content integrated from the **Claude Bug Bounty Hunter Toolkit** (MIT License).

- Source repo: `output/scratch/compare-shuvonsec/repo` (integrated 2026-08-15)
- Source path: `skills/cicd-security/SKILL.md` and `tools/cicd_scanner.sh`.

## What was copied

| Adapted file | Source |
|---|---|
| `SKILL.md` | `skills/cicd-security/SKILL.md` (restructured to BountyHarness skill format) |
| `scripts/cicd_scanner.sh` | `tools/cicd_scanner.sh` (unmodified, self-contained) |
| `scripts/workflow_inject_scan.py` | New static scanner; pattern set derived from SKILL.md sections 2-6 |
| `scripts/cicd_secret_scan.py` | New static scanner; pattern set derived from SKILL.md section 4 |
| `runbooks/*.md` | SKILL.md sections 2-7 (injection, pull_request_target, secrets, runners, supply chain, chaining) |
| `payloads/*.txt` | Injectable context examples + PoC payloads from SKILL.md sections 2-4 |

## MIT License notice

Copyright (c) 2026 Claude Bug Bounty Hunter Contributors. Licensed under the MIT
License (https://opensource.org/licenses/MIT). The above files are redistributed
and/or adapted under that license. Permission is hereby granted, free of charge,
to any person obtaining a copy of this software and associated documentation
files, to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software.
