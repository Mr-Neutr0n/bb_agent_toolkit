# shuvonsec-arsenal — Attribution README

Reference documents integrated from the **Claude Bug Bounty Hunter Toolkit**
(MIT License) into the BountyHarness reference library.

- Source repo: `output/scratch/compare-shuvonsec/repo` (integrated 2026-08-15)
- Source path: `skills/security-arsenal/REFERENCES.md` and
  `skills/security-arsenal/METHODOLOGY_CHEATSHEET.md`.

## Files

| File | Source | Content |
|---|---|---|
| `REFERENCES.md` | `skills/security-arsenal/REFERENCES.md` | Curated external reference library: methodology repos, disclosed-report collections, tool catalogues, dorking/OSINT sources, subdomain-takeover fingerprints, API key verification |
| `METHODOLOGY_CHEATSHEET.md` | `skills/security-arsenal/METHODOLOGY_CHEATSHEET.md` | Per-vuln quick checks (IDOR, XSS, SSRF, open redirect, SQLi, CSRF, OAuth, race, file upload, takeover, MFA bypass), high-EV recon one-liners, always-check paths |

The cheatsheet complements BountyHarness `technique-kb` and `standard-catalog`
with condensed hunting-order checklists; `REFERENCES.md` mirrors the
`references/` directory of this repo (awesome-pentest, hacktricks, owasp,
payloads-all-the-things, report-corpus, rfcs).

## MIT License notice

Copyright (c) 2026 Claude Bug Bounty Hunter Contributors. Licensed under the MIT
License (https://opensource.org/licenses/MIT). The files above are redistributed
and/or adapted under that license. Permission is hereby granted, free of charge,
to any person obtaining a copy of this software and associated documentation
files, to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software.
