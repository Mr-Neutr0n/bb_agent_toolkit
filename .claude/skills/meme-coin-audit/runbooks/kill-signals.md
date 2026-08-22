# Pre-Dive Kill Signals

Check BEFORE reading a single line of code.

## Hard kills (skip immediately)

- **Contract not verified** on Etherscan/Solscan → cannot trust source
- **Deployer wallet** has history of rug pulls
- **Token age < 1 hour** AND no known team
- **Mint authority retained** (Solana) AND no cap → infinite mint = certain rug
- **Freeze authority retained** (Solana) on meme coin → honeypot confirmed
- **Transfer hook present** (Token-2022) with mutable hook program
- **Permanent delegate** extension (Token-2022) → can steal all holder tokens

## Soft kills (proceed with extreme caution)

- Top holder > 20% of supply (excluding DEX pools)
- LP not burned or locked in verified contract
- Contract is upgradeable / proxy with retained admin
- Less than $5K liquidity in the pool
- No social presence / anonymous deployer with no history

## The one rule

> **"Check ALL authorities and owner functions. The retained authority IS the rug vector."**
>
> Every rug pull requires a privileged operation: mint, blacklist, fee change,
> LP removal, or authority abuse. If you find the privilege, you found the bug.
