# Web3 Audit Checklist

## Before you start

- [ ] Confirm the program (Immunefi/Code4rena) and the contract is in scope
- [ ] Note TVL, audit history, deploy date — run kill-signal scoring
- [ ] Get the exact audited commit hash; diff against current main

## Static review (passive)

- [ ] Run `sol_pattern_scan.py` — group hits by class
- [ ] Read ALL sibling functions — missing modifier on sibling IS the bug
- [ ] For every `if (A > B)`: what happens when A == B?
- [ ] List state changes per function family; check reversals exist
- [ ] Check oracle staleness, confidence, TWAP length, single-source
- [ ] Check ecrecover hashes include nonce + chainId + contract address
- [ ] Check initialize() has initializer protection (proxy + implementation)
- [ ] Check CEI order in all external calls

## On-chain verification (intrusive — needs authorization)

- [ ] Confirm program explicitly allows fork tests / PoC execution
- [ ] Run Foundry PoC on a fork, never on mainnet directly
- [ ] Collect: fork block, tx hashes, before/after balances

## Report (Immunefi format)

- [ ] Root cause in code with line numbers
- [ ] Quantified impact in USD (TVL at risk)
- [ ] Foundry PoC attached
- [ ] Recommended fix with before/after code
