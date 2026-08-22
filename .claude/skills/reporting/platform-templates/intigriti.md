# Intigriti Report Template

Extracted from the Claude Bug Bounty Hunter Toolkit `skills/report-writing/SKILL.md`
(MIT License, see THIRD_PARTY.md). HackerOne/generic templates already exist in
`scripts/platform_templates.py`; this file covers Intigriti-specific structure.

```markdown
# [Bug Class]: [Exact Impact] in [Endpoint/Feature]

## Description

[Impact-first paragraph. Start with what an attacker can do, not with how you found it.
Include: endpoint, method, parameter, data exposed, required privileges.]

## Steps to Reproduce

**Environment:**
- Attacker: email=attacker@test.com (standard account, no special role)
- Victim: email=victim@test.com
- Tested: [date]

**Reproduction steps:**

1. [Login as attacker / visit URL / send request]

2. Send the following HTTP request:

```http
METHOD /endpoint HTTP/1.1
Host: target.com
Authorization: Bearer ATTACKER_TOKEN
Content-Type: application/json

{"param": "victim_id_here"}
```

3. Observe response contains victim's private data:

```json
{"email": "victim@test.com", "address": "123 Main St", ...}
```

## Impact

[Specific, quantified impact. What data, how many users, what can attacker do.]

CVSS 3.1 Score: X.X ([Severity]) — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N

## Remediation

[1-3 sentence concrete fix. Include code if helpful.]

## Attachments

[Screenshot or Loom video showing the impact — Intigriti triagers prefer video for complex bugs]
```

## Intigriti-specific notes

- Title format: `[Bug Class]: [One-line impact]` (no formula required, but keep it specific)
- Severity is set by you: Critical/High/Medium/Low/Exceptional
- CVSS 3.1 is standard (CVSS 4.0 also accepted on newer programs)
- PoC video is valued much more than screenshot alone — record with Loom
- Safe harbor: Intigriti enforces it, be comfortable going slightly aggressive with testing
