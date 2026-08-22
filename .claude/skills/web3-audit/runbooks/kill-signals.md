# Pre-Dive Kill Signals

Check BEFORE any code review. ZKsync lesson: $322M TVL + OZ audit + 750K LOC
+ 5 sessions = 0 findings. Large well-audited bridges are extremely hard.

## Hard kills

1. TVL < $500K → max payout capped too low for effort
2. 2+ top-tier audits (Halborn, ToB, Cyfrin, OpenZeppelin) on simple protocol
3. Protocol < 500 lines, single A→B→C flow → minimal attack surface
4. `max_realistic_payout = min(10% × TVL, program_cap)` — if < $10K, skip

## Soft kill

OZ/ToB/Cyfrin audit on current version + codebase > 500K LOC → expect 40+
hours for maybe 1 finding. Only proceed if bounty floor > $50K AND you have
protocol-specific expertise.

## Target scoring (go if >= 6/10)

| Signal | Points |
|---|---|
| TVL > $10M | +2 |
| Immunefi Critical >= $50K | +2 |
| No top-tier audit on current version | +2 |
| < 30 days since deploy | +1 |
| Protocol you've hunted before | +1 |
| Source code + natspec comments | +1 |
| Upgradeable proxies | +1 |
