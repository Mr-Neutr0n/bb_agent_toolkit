#!/usr/bin/env python3
"""CT index enumeration via crt.name - fast passive subdomain discovery with first-seen dates.

crt.name reads the CT firehose (Chrome + Apple log programs, static CT and RFC 6962),
plus retired logs, Common Crawl, CZDS, Chaos, and DNS blocklists into a single
(apex, subdomain, first_seen) index. Free, no token: 1000 requests per IP per day.

Why a dedicated source when subfinder/crt.sh exist:
  - Sub-second responses where crt.sh frequently returns 502/timeouts
  - first-seen timestamps enable new-asset detection (asset-graph delta,
    scheduled recon) that plain subdomain lists cannot provide

Usage:
    ct_index_enum.py --target example.com --context $OUTDIR/recon/ctindex
    ct_index_enum.py --target example.com --context ... --new-days 7   # flag assets first seen recently
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

API = "https://crt.name/v1/search"
UA = "Mozilla/5.0 (Security Research; BountyHarness)"


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    print(f"[{now_iso()}] {msg}", file=sys.stderr)


def write_lines(path: Path, lines) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(sorted(lines)) + "\n", encoding="utf-8")


def fetch_index(target: str, timeout: int = 30) -> tuple[list[dict], int]:
    """Return list of {sub, first_seen} entries plus HTTP status."""
    url = f"{API}?apex={urllib.parse.quote(target, safe='')}&format=json&dates=1"
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read(50_000_000).decode("utf-8", errors="replace"))
            return (data if isinstance(data, list) else []), resp.status
    except urllib.error.HTTPError as e:
        if e.code == 429:
            log("rate limited (1000/day free tier); falling back to cached results only")
        else:
            log(f"HTTP {e.code} from crt.name")
        return [], e.code
    except Exception as e:
        log(f"crt.name error: {str(e)[:120]}")
        return [], 0


def main() -> None:
    parser = argparse.ArgumentParser(description="crt.name CT-index subdomain enumeration")
    parser.add_argument("--target", "-t", required=True, help="Apex domain (eTLD+1)")
    parser.add_argument("--context", "-c", default=".", help="Output directory")
    parser.add_argument("--new-days", type=int, default=0,
                        help="If set, also emit subs with first_seen within N days to new_assets.txt")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    ctx = Path(args.context)
    ctx.mkdir(parents=True, exist_ok=True)

    if args.dry_run:
        log(f"DRY-RUN: GET {API}?apex={args.target}&format=json&dates=1")
        print(json.dumps({"source": "crtname", "count": 0, "dry_run": True}))
        return

    import urllib.parse
    entries, status = fetch_index(args.target, args.timeout)

    subs = []
    findings = []
    for e in entries:
        sub = (e.get("sub") or "").strip().lower()
        if not sub:
            continue
        subs.append(sub)
        findings.append({
            "value": sub,
            "type": "subdomain",
            "source": "crtname",
            "first_seen": e.get("first_seen"),
            "timestamp": now_iso(),
        })

    write_lines(ctx / "subs_ctindex.txt", subs)

    new_count = 0
    if args.new_days > 0:
        cutoff = datetime.now(timezone.utc).timestamp() - args.new_days * 86400
        recent = []
        for e in entries:
            fs = e.get("first_seen") or ""
            try:
                ts = datetime.fromisoformat(fs.replace("Z", "+00:00")).timestamp()
            except Exception:
                continue
            if ts >= cutoff:
                s = (e.get("sub") or "").strip().lower()
                if s:
                    recent.append(s)
        write_lines(ctx / "new_assets.txt", recent)
        new_count = len(recent)

    meta = {
        "run_id": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
        "tool": "ct_index_enum",
        "service": "crt.name",
        "http_status": status,
        "target": args.target,
        "completed": now_iso(),
        "count": len(subs),
        "new_assets_days": args.new_days,
        "new_assets_count": new_count,
        "files": {
            "subs_ctindex": str(ctx / "subs_ctindex.txt"),
            **({"new_assets": str(ctx / "new_assets.txt")} if args.new_days > 0 else {}),
        },
    }
    (ctx / "ctindex_metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    findings_path = ctx / "findings.jsonl"
    with open(findings_path, "a", encoding="utf-8") as fh:
        for f in findings:
            fh.write(json.dumps(f) + "\n")

    print(json.dumps({"source": "crtname", "count": len(subs),
                      "new_assets": new_count, "output": str(ctx)}))


if __name__ == "__main__":
    main()
