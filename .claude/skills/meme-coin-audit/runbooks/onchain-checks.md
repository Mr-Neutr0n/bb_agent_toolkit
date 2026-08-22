# On-Chain Quick Checks (Intrusive — requires authorization)

When you don't have source code, check on-chain. This is intrusive testing —
confirm scope and program authorization first.

```
1. MINT AUTHORITY → solana account <MINT> --output json | check mint_authority
   - Should be null
   - If Some(pubkey) → CRITICAL: can mint infinite tokens

2. FREEZE AUTHORITY → same as above, check freeze_authority
   - Should be null
   - If Some(pubkey) → CRITICAL: honeypot

3. LP STATUS → Check Raydium/Orca pool
   - LP burned? (tokens sent to 1111...1111)
   - LP locked? (in verified locker with no backdoor)
   - LP held by deployer? → CRITICAL: instant rug

4. TOP HOLDERS → Birdeye/Solscan holders tab
   - Top 10 < 30% of supply (excluding pools)
   - Creator wallets (check first transactions)

5. PROGRAM UPGRADEABILITY
   - Is the program upgradeable? → can change any logic
   - Upgrade authority should be None for immutable programs

6. TOKEN-2022 EXTENSIONS
   - Any transfer hook? → potential honeypot
   - Permanent delegate? → CRITICAL
```

## EVM equivalents

- Contract verification: Etherscan "Contract" tab
- Deployer history: Etherscan deployer address page
- LP lock: Unicrypt/PinkLock check
- Ownership: `owner()` + ownership transfer history (Etherscan internal txs)
