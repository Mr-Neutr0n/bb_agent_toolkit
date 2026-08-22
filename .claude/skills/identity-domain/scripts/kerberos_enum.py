#!/usr/bin/env python3
"""Kerberos username enumeration wrapper — runs ONLY when port 88 is confirmed in scope.

Prefers `kerbrute` binary. Never sprays passwords; AS-REQ username diff only
(no lockout risk per design). Aborts unless --port88-in-scope is passed, which
the caller must set only after confirming scope with scope-manager.

Usage:
    kerberos_enum.py userenum --host dc.example.com --users users.txt --port88-in-scope --output kerb.json
"""

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def userenum(host: str, users_file: str, in_scope_ack: bool, rate: int, output_path: str) -> dict:
    if not in_scope_ack:
        return {
            "status": "refused",
            "reason": (
                "Port 88 scope not acknowledged. Confirm KDC/88/tcp is inside program scope "
                "(run bin/bb-run scope-manager validate-url first), then re-run with "
                "--port88-in-scope."
            ),
        }
    binary = shutil.which("kerbrute")
    if not binary:
        return {
            "status": "tool_missing",
            "tool": "kerbrute",
            "install": "go install github.com/ropnop/kerbrute@latest or brew-based equivalent; see tools/registry",
            "reason": "Refusing to hand-roll raw Kerberos traffic; wrapper exists only for governed use.",
        }
    cmd = [binary, "userenum", "--dc", host, "-d", host.split(".", 1)[-1],
           "--delay", str(max(1, 1000 // max(rate, 1))), users_file]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        valid = [
            line.split()[0].strip()
            for line in r.stdout.splitlines()
            if "VALID USERNAME" in line.upper()
        ]
        realm = next((l.split(":")[-1].strip() for l in r.stdout.splitlines()
                      if l.lower().startswith("realm")), host.split(".", 1)[-1].upper())
        out = {
            "status": "done", "tool": "kerbrute", "host": host, "realm": realm,
            "tested_at": now_iso(), "valid_users_count": len(valid),
            "valid_users_sample": valid[:50], "note": "AS-REQ diff only; no passwords sent.",
        }
    except subprocess.TimeoutExpired:
        out = {"status": "timeout", "host": host}
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(out, indent=2))
    return {k: v for k, v in out.items() if k != "valid_users_sample"} | {"output": output_path}


def main():
    parser = argparse.ArgumentParser(description="Kerberos user enumeration (governed)")
    sub = parser.add_subparsers(dest="command")

    u = sub.add_parser("userenum")
    u.add_argument("--host", required=True, help="KDC host (FQDN)")
    u.add_argument("--users", required=True, help="Username candidates file")
    u.add_argument("--rate", type=int, default=int(__import__("os").environ.get("RATE_LIMIT", "5")))
    u.add_argument("--port88-in-scope", action="store_true",
                   help="Explicit acknowledgement that 88/tcp on this host is in scope")
    u.add_argument("--output", required=True)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    print(json.dumps(userenum(args.host, args.users, args.port88_in_scope, args.rate, args.output), indent=2))


if __name__ == "__main__":
    main()
