# Token Scan — Scanner Usage and Limits

## Run

```bash
# EVM token
python3 .claude/skills/meme-coin-audit/scripts/token_scanner.py contracts/Token.sol

# Solana program
python3 .claude/skills/meme-coin-audit/scripts/token_scanner.py programs/token/ --chain solana --recursive

# Full directory scan with report
python3 .claude/skills/meme-coin-audit/scripts/token_scanner.py src/ --recursive --output findings/token-report.md
```

## What the scanner catches (all 8 bug classes)

- Direct mint/balance manipulation
- Blacklist and transfer restriction patterns
- Unbounded fee setters
- LP migration and emergency withdraw functions
- Fake renounce overrides
- Zero slippage auto-swaps
- All Solana authority patterns
- Token-2022 dangerous extensions

## What the scanner does NOT check (do manually)

- On-chain state — use Etherscan/Solscan for authority verification
- Holder distribution — use DEXTools/Birdeye
- LP lock status — use Unicrypt/PinkLock/Solscan
- Deployer wallet history — manual check

## Quick greps per class

```bash
# Hidden mint
grep -rn "function mint\|_mint(\|_balances\[.*\] +=" src/ --include="*.sol" | grep -v "test\|lib"

# Honeypot
grep -rn "blacklist\|isBlacklisted\|_bots\|maxTxAmount\|tradingEnabled" src/ --include="*.sol"

# Fee manipulation
grep -rn "setFee\|setSellFee\|_taxFee\|_sellFee" src/ --include="*.sol"
grep -rn "function set.*Fee" -A5 src/ --include="*.sol" | grep -v "require\|MAX\|<="

# LP drain / fake renounce / sandwich
grep -rn "migrateLP\|emergencyWithdraw\|\.sync()\|setPair\|setRouter" src/ --include="*.sol"
grep -rn "renounceOwnership.*override\|_shadowAdmin\|_backupOwner\|selfdestruct" src/ --include="*.sol"
grep -rn "swapExactTokensForETH" -A5 src/ --include="*.sol" | grep "0,"
```
