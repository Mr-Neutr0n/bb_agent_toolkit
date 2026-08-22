# Bugcrowd Report Template

Extracted from the Claude Bug Bounty Hunter Toolkit `skills/report-writing/SKILL.md`
(MIT License, see THIRD_PARTY.md). HackerOne/generic templates already exist in
`scripts/platform_templates.py`; this file covers Bugcrowd-specific structure.

```markdown
# [IDOR] User order history accessible without authorization via /api/users/{id}/orders

**VRT Category:** Broken Access Control > IDOR > P2

## Description

[Impact-first paragraph: what the bug is, where it is, what an attacker can do.
Include: endpoint, method, parameter, data exposed, required access level.]

## Steps to Reproduce

[Structured steps — exact HTTP requests, exact responses]

## Proof of Concept

[Screenshot/video showing the actual impact]

## Expected vs Actual Behavior

**Expected:** 403 Forbidden when user_id does not match authenticated user
**Actual:** 200 OK with victim's full order data

## Severity Justification

P2 (High) — Direct read access to other users' PII. Affects all user accounts.
No user interaction required. Exploitable by any authenticated user.
Automated enumeration could exfil all [N] user records in minutes.

## Remediation

Add ownership verification: `if order.user_id != current_user.id: raise 403`
```

## Bugcrowd-specific notes

- Title includes the VRT category (`Broken Access Control > IDOR > P2`).
- Priority tiers: P1 (Critical), P2 (High), P3 (Medium), P4 (Low).
- "Expected vs Actual Behavior" is a required section — always include it.
- Proof of Concept must show the actual impact, not just a 200 status code.
