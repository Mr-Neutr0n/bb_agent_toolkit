# Immunefi Report Template

Extracted from the Claude Bug Bounty Hunter Toolkit `skills/report-writing/SKILL.md`
(MIT License, see THIRD_PARTY.md). HackerOne/generic templates already exist in
`scripts/platform_templates.py`; this file covers Immunefi-specific structure
for smart contract findings.

```markdown
# [Bug Class] — [Protocol Name] — [Severity]

## Summary

[One paragraph with: root cause, affected function, economic impact, attack cost.
Include numbers where possible: "attacker can drain $X in Y transactions."]

## Vulnerability Details

**Contract:** `VulnerableContract.sol`
**Function:** `claimRedemption()`
**Bug Class:** Accounting State Desynchronization
**Severity:** Critical

### Root Cause

[Exact code snippet showing the vulnerable code with comments]

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// Foundry PoC — run: forge test --match-test test_exploit -vvvv

contract ExploitTest is Test {
    // ... full working exploit
}
```

## Impact

[Quantified: "Attacker can drain X% of TVL = $Y at current rates.
Requires $Z gas. Attack is repeatable."]

## Recommended Fix

[Specific code change with before/after]
```

## Immunefi-specific notes

- Root cause in code is mandatory — Immunefi triagers verify against the source.
- Impact must be quantified in dollars where possible (TVL at risk).
- Foundry PoC is the expected standard for Critical/High findings.
- Payout tiers depend on the program's smart-contract severity matrix; scope
  the bug class against the program's coverage before submitting.
