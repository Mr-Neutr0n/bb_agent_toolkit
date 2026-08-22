# Bug Classes — Grep Patterns

Run `scripts/sol_pattern_scan.py` for the automated sweep, then verify each hit
manually. The key greps per class:

## 1. Accounting desync (#1 Critical — 28%)

```bash
grep -rn "totalSupply\|totalShares\|totalAssets\|totalDebt\|cumulativeReward\|rewardPerShare" contracts/
grep -rn "\breturn\b" contracts/ -B3 | grep -B3 "if\b"   # early returns skip state updates
```

Variants: phantom yield (decrement before transfer), fast path early return,
update in wrong order (shares calculated before assets added).

## 2. Access control (19% of Criticals)

```bash
grep -rn "function vote\|function poke\|function reset\|function claim\|function harvest" contracts/ -A2
grep -rn "_requireOwned\|ownerOf\|_checkAuthorized" contracts/ -B5   # existence vs ownership
grep -rn "modifier\b" contracts/ -A8 | grep -B3 "if (" | grep -v "require\|revert"  # silent modifiers
grep -rn "function initialize\b" contracts/ -A3; grep -rn "_disableInitializers()" contracts/
```

## 3. Incomplete code path (17% of Criticals)

Function family comparison test: list state changes in A (deposit/place/create),
check B (withdraw/update/cancel) reverses each one. Missing refund on price
decrease, partial-fill refund of wrong asset, mint() bypassing deposit() checks.

## 4. Off-by-one (22% of Highs)

```bash
grep -rn "Period\|Epoch\|Round\|Deadline" contracts/ -A3 | grep "[<>][^=]"
grep -rn "\bbreak\b" contracts/ -B10
grep -rn "\.length\s*-\s*1\|i\s*<=\s*.*\.length\b" contracts/
```

Mental test: for every `if (A > B)` — "what happens when A == B?"

## 5. Oracle (12% of reports, largest payouts)

Missing staleness check on latestRoundData, missing confidence interval on Pyth,
TWAP shorter than 1800s, single-source Uniswap spot price (flash-loan
manipulatable). `grep -rn "latestRoundData\|getPriceUnsafe\|secondsAgo\|slot0" contracts/ -A5`

## 6-10. ERC4626 / reentrancy / flash loan / signatures / proxy

```bash
grep -rn "function transfer\|function deposit\|function mint\|function withdraw\|function redeem" contracts/ -A10
grep -rn "\.call{value\|safeTransfer\|transfer(" contracts/ -B10 | grep -v "require\|revert"
grep -rn "ecrecover\|ECDSA\.recover" contracts/ -B20   # nonce + chainId in hash?
grep -rn "delegatecall\b" contracts/ -B3 -A5
grep -rn "0x360894\|EIP1967\|_IMPLEMENTATION_SLOT" contracts/
```

First-depositor attack: deposit 1 wei → donate → victim rounds down to 0 shares.
