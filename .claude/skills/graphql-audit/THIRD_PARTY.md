# THIRD_PARTY.md — graphql-audit skill

Content integrated from the **Claude Bug Bounty Hunter Toolkit** (MIT License).

- Source repo: `output/scratch/compare-shuvonsec/repo` (integrated 2026-08-15)
- Source path: `skills/graphql-audit/SKILL.md` and `tools/graphql_audit.sh`.

## What was copied

| Adapted file | Source |
|---|---|
| `SKILL.md` | `skills/graphql-audit/SKILL.md` (restructured to BountyHarness skill format) |
| `scripts/graphql_audit.sh` | `tools/graphql_audit.sh` — full multi-phase sweep. Adapted: inlined `_have()` and `print_banner()` helpers to remove `external_arsenal.sh` / `banner.sh` sourcing (install-time dependencies) |
| `scripts/gql_introspection.py` | Introspection probes + bypass techniques from SKILL.md section 2 |
| `scripts/gql_batch_probe.py` | Batching/alias timing probes from SKILL.md section 4 |
| `scripts/gql_idor_aliasing.py` | IDOR-via-aliases probes from SKILL.md section 5 |
| `runbooks/*.md` | SKILL.md sections 2-6, 9, 13, 14 (introspection, field suggestions, batching, IDOR, injection, chaining, report template) |
| `payloads/*.txt` | Probe queries from SKILL.md sections 2-6 |

## MIT License notice

Copyright (c) 2026 Claude Bug Bounty Hunter Contributors. Licensed under the MIT
License (https://opensource.org/licenses/MIT). The above files are redistributed
and/or adapted under that license. Permission is hereby granted, free of charge,
to any person obtaining a copy of this software and associated documentation
files, to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software.
