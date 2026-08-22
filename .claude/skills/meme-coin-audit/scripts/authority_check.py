#!/usr/bin/env python3
"""authority_check.py — Static scan for retained authority / rug-pull vectors in token contracts.

Scans Solidity and Rust (Anchor/SPL) source for mint/blacklist/fee/LP/authority
patterns — the privileged operations behind every meme coin rug. Pairs with
token_scanner.py for the full 8 bug-class check.

Passive: only reads local source files. On-chain authority verification
(Solscan/Etherscan) is an intrusive step performed manually.

Usage:
  python3 authority_check.py --dir src/
  python3 authority_check.py --dir programs/ --json
  python3 authority_check.py --help
"""

import argparse
import json
import re
import sys
from pathlib import Path

PATTERNS = [
    ("evm-hidden-mint", r"function mint\b|_mint\(|_balances\[.*\] \+="),
    ("evm-honeypot", r"blacklist|isBlacklisted|_bots|maxTxAmount|tradingEnabled"),
    ("evm-fee", r"setFee|setSellFee|_taxFee|_sellFee|function set.*Fee"),
    ("evm-lp", r"migrateLP|emergencyWithdraw|\.sync\(\)|setPair|setRouter"),
    ("evm-fake-renounce", r"renounceOwnership|_shadowAdmin|_backupOwner|selfdestruct"),
    ("evm-mev", r"swapExactTokensForETH|swapThreshold|_rebase|mandatoryPool"),
    ("solana-authority", r"mint_authority|freeze_authority|update_authority|close_authority|set_authority"),
    ("solana-hook", r"freeze_authority|transfer_hook|TransferHook|permanent_delegate"),
    ("solana-mint", r"MintTo|mint_to|mint_authority"),
    ("bonding-curve", r"virtualReserve|setCurve|graduate|bonding_curve"),
]


def scan_dir(root: Path) -> list:
    findings = []
    files = [p for p in root.rglob("*")
             if p.suffix in (".sol", ".rs") and "test" not in p.name.lower()
             and "lib/" not in str(p) and "node_modules" not in str(p)]
    for path in files:
        try:
            lines = path.read_text(errors="replace").splitlines()
        except Exception:
            continue
        for i, line in enumerate(lines, 1):
            for cls, pat in PATTERNS:
                if re.search(pat, line):
                    findings.append({"file": str(path), "vector": cls, "line": i,
                                     "code": line.strip()[:150]})
    return findings


def main() -> int:
    ap = argparse.ArgumentParser(description="Scan token contracts for retained-authority rug vectors.")
    ap.add_argument("--dir", required=True, help="Source directory (Solidity or Rust/Anchor)")
    ap.add_argument("--json", action="store_true", help="Emit JSON")
    args = ap.parse_args()

    root = Path(args.dir)
    if not root.is_dir():
        print(f"ERROR: not a directory: {root}", file=sys.stderr)
        return 2

    findings = scan_dir(root)
    if args.json:
        print(json.dumps(findings, indent=2))
        return 0

    by_vec = {}
    for f in findings:
        by_vec.setdefault(f["vector"], []).append(f)
    print(f"[*] Scanned {root} — {len(findings)} authority/rug-vector hits")
    for vec in sorted(by_vec):
        print(f"  {vec}: {len(by_vec[vec])} hits")
    print()
    print("Hard kills if confirmed on-chain: retained mint authority, freeze")
    print("authority, permanent delegate, or transfer hook on a meme token.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
