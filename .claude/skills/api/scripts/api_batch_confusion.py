#!/usr/bin/env python3
"""REST batch-endpoint route confusion prober - detection for the
wp2shell-class bug (CVE-2026-63030 lineage) generalized beyond WordPress.

Batch API routes that dispatch sub-requests by REST route name can be confused:
a batch entry naming an internal/admin route executes with the outer request's
auth context, or route normalization differences let /wp/v2/... style paths
resolve to unintended handlers on ANY framework with batch endpoints.

Detection-only: probes use harmless GET routes and canary params; never sends
state-changing sub-requests.

Usage:
    api_batch_confusion.py --target https://example.com --output findings.jsonl
    api_batch_confusion.py --target https://example.com --batch-path /api/batch --dry-run
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime

RATE_LIMIT = float(os.environ.get("RATE_LIMIT", "5"))
UA = "Mozilla/5.0 (Security Research; BountyHarness)"

# Common batch endpoint locations across frameworks
BATCH_PATHS = [
    "/wp-json/batch/v1",            # WordPress REST batch (wp2shell)
    "/wp-json/",
    "/api/batch",
    "/batch",
    "/$batch",                       # OData
    "/graphql",                      # some gateways alias batching here
    "/v1/batch",
]

# Sub-request bodies: GET-only, safe handlers that should NOT be reachable
PROBE_ROUTES = [
    ("wp-style", {"methods": ["GET"], "path": "/wp/v2/users",
                  "note": "WordPress users enumeration via batch"}),
    ("internal-users", {"methods": ["GET"], "path": "/internal/users",
                        "note": "internal namespace confusion"}),
    ("admin-ping", {"methods": ["GET"], "path": "/admin/ping",
                    "note": "admin namespace reachability via batch context"}),
]


def now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    print(f"[{now_iso()}] {msg}", file=sys.stderr)


def throttle() -> None:
    time.sleep(1.0 / max(RATE_LIMIT, 0.1))


def post_json(url: str, body: dict, timeout: int = 12) -> tuple[int, str]:
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"User-Agent": UA, "Content-Type": "application/json"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(200_000).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:
        return 0, str(e)[:100]


def discover_batch_endpoint(target: str) -> list[str]:
    found = []
    base = target.rstrip("/")
    for p in BATCH_PATHS:
        throttle()
        # WordPress-style: OPTIONS reveals batch route support; POST with empty
        # body is the universal detector - a real batch endpoint answers 200/207
        # with validation errors rather than 404/405.
        status, _ = post_json(f"{base}{p}", {"requests": []})
        if status in (200, 207):
            found.append(f"{base}{p}")
            log(f"batch endpoint candidate: {base}{p} (HTTP {status})")
        elif status in (400, 422):
            found.append(f"{base}{p}")
            log(f"batch endpoint candidate (validation response): {base}{p}")
    return found


def probe_route_confusion(endpoint: str) -> dict:
    results = []
    for label, cfg in PROBE_ROUTES:
        throttle()
        body = {
            "requests": [
                {"method": "GET", "path": cfg["path"]},
            ]
        }
        status, resp = post_json(endpoint, body)
        interesting = status in (200, 207) and resp and "rest_no_route" not in resp and "no_route" not in resp.lower()
        results.append({
            "route_style": label,
            "sub_path": cfg["path"],
            "status": status,
            "response_len": len(resp),
            "candidate_confusion": bool(interesting),
            "note": cfg["note"] if interesting else "",
        })
        if interesting:
            log(f"INTERESTING: {label} -> {cfg['path']} answered {status} inside batch")
    return {
        "endpoint": endpoint,
        "checked_at": now_iso(),
        "probes": results,
        "any_candidates": any(r["candidate_confusion"] for r in results),
    }


def main():
    parser = argparse.ArgumentParser(description="Batch endpoint route-confusion prober (detection-only)")
    parser.add_argument("--target", required=True)
    parser.add_argument("--batch-path", default=None, help="Skip discovery, probe this exact endpoint")
    parser.add_argument("--output", required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.dry_run:
        print(json.dumps({"status": "dry-run", "endpoints": BATCH_PATHS}))
        return

    if args.batch_path:
        endpoints = [args.batch_path if args.batch_path.startswith("http") else f"{args.target.rstrip('/')}{args.batch_path}"]
    else:
        endpoints = discover_batch_endpoint(args.target)

    all_results = [probe_route_confusion(ep) for ep in endpoints]
    out = {
        "tool": "api_batch_confusion",
        "target": args.target,
        "checked_at": now_iso(),
        "safety_note": "GET-only sub-requests; no state changes attempted.",
        "results": all_results,
    }
    from pathlib import Path
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(out, indent=2))
    hits = sum(1 for r in all_results if r["any_candidates"])
    print(json.dumps({"endpoints_tested": len(endpoints), "with_candidates": hits, "output": args.output}))


if __name__ == "__main__":
    main()
