#!/usr/bin/env python3
"""sol_pattern_scan.py — Static grep-pattern audit for Solidity contracts.

Runs the class-specific grep patterns from the web3-audit methodology
(accounting desync, access control, incomplete paths, off-by-one, oracle,
ERC4626, reentrancy, flash loan, signature replay, proxy) over a contracts
directory and groups hits by bug class for manual review.

Passive: only reads local source files.

Usage:
  python3 sol_pattern_scan.py --dir contracts/
  python3 sol_pattern_scan.py --dir contracts/ --json
  python3 sol_pattern_scan.py --help
"""

import argparse
import json
import re
import sys
from pathlib import Path

CLASS_PATTERNS = [
    ("accounting-desync", r"totalSupply|totalShares|totalAssets|totalDebt|cumulativeReward|rewardPerShare"),
    ("access-control", r"function (vote|poke|reset|update|claim|harvest|split)\b|_requireOwned|ownerOf|modifier\b|function initialize\b|_disableInitializers"),
    ("incomplete-path", r"function (place_|create_|add_|open_|update_|modify_|cancel_|deposit|mint|withdraw|redeem)\b|safeApprove\b|delete\b"),
    ("off-by-one", r"Period\b|Epoch\b|Round\b|Deadline\b|\.length\s*-\s*1|i\s*<=\s*.*\.length\b|break\b"),
    ("oracle", r"latestRoundData|getPriceUnsafe|getPrice\b|secondsAgo|TWAP|cardinality|getReserves|getAmountsOut|slot0\b"),
    ("erc4626", r"function (transfer|transferFrom|deposit|mint|withdraw|redeem)\b|_decimalsOffset"),
    ("reentrancy", r"\.call\{value|safeTransfer|transfer\(|nonReentrant|ReentrancyGuard|_notEntered"),
    ("signature-replay", r"ecrecover|ECDSA\.recover|nonce|_nonces|nonces\[|block\.chainid"),
    ("proxy", r"delegatecall\b|0x360894|EIP1967|_IMPLEMENTATION_SLOT|function initialize\b"),
]


def scan_dir(root: Path) -> list:
    findings = []
    sol_files = [p for p in root.rglob("*.sol") if "node_modules" not in str(p) and "lib/" not in str(p)]
    for path in sol_files:
        try:
            lines = path.read_text(errors="replace").splitlines()
        except Exception:
            continue
        for i, line in enumerate(lines, 1):
            for cls, pat in CLASS_PATTERNS:
                if re.search(pat, line):
                    findings.append({"file": str(path), "bug_class": cls, "line": i,
                                     "code": line.strip()[:150]})
    return findings


def main() -> int:
    ap = argparse.ArgumentParser(description="Grep-pattern audit of Solidity contracts by bug class.")
    ap.add_argument("--dir", required=True, help="Contracts directory to scan")
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

    by_class = {}
    for f in findings:
        by_class.setdefault(f["bug_class"], []).append(f)
    print(f"[*] Scanned {root} — {len(findings)} pattern hits across {len(by_class)} bug classes")
    print()
    for cls in sorted(by_class):
        print(f"=== {cls} ({len(by_class[cls])} hits) ===")
        for f in by_class[cls][:8]:
            print(f"  {f['file']}:{f['line']}  {f['code']}")
        if len(by_class[cls]) > 8:
            print(f"  ... and {len(by_class[cls]) - 8} more")
        print()
    print("Manual review required — patterns flag candidates, not vulnerabilities.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
