# shuvonsec-rules — Attribution README

Rules documents integrated from the **Claude Bug Bounty Hunter Toolkit**
(MIT License) into the BountyHarness reference library.

- Source repo: `output/scratch/compare-shuvonsec/repo` (integrated 2026-08-15)
- Source path: `rules/hunting.md` and `rules/reporting.md` — "always active"
  hunting discipline and report quality rules used by the source toolkit.

## Files

| File | Source | Content |
|---|---|---|
| `hunting.md` | `rules/hunting.md` | 20 critical hunting rules: scope-first, 7-question gate, 5-minute rule, sibling rule, A→B signal method, follow-the-money, CI/CD + SAML attack surface notes |
| `reporting.md` | `rules/reporting.md` | 12 report quality rules: no theoretical language, PoC requirements, CVSS accuracy, never-submit list, two-account IDOR testing, platform formats, title formula |

These rules are referenced by the `triage-validation` skill (`run-gate`,
`check-never-submit` workflows) as the human-facing discipline behind the
automated gates.

## MIT License notice

Copyright (c) 2026 Claude Bug Bounty Hunter Contributors. Licensed under the MIT
License (https://opensource.org/licenses/MIT). The files above are redistributed
and/or adapted under that license. Permission is hereby granted, free of charge,
to any person obtaining a copy of this software and associated documentation
files, to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software.
