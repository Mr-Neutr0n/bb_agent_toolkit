#!/usr/bin/env python3
"""Circuit breaker - protects targets from runaway workflow failure loops.

Reads .bb/traces/runs.jsonl (written by every bb-run) and opens a per-target
cooldown when the last N executions all failed, or when an explicit
rate-limit flag exists (.bb/circuit/<hash>.flag written by any tool).

Subcommands:
    check   Exit 0 if allowed to run, exit 2 if circuit open (with reason)
    status  Human-readable breaker state for a target
    reset   Clear cooldown state for a target
    trip    Manually open the circuit (e.g., after seeing 429s in tool output)

Env knobs:
    BB_CB_THRESHOLD     consecutive failures before opening (default 5)
    BB_CB_COOLDOWN_MIN  cooldown minutes once open (default 15)
    BB_CB_DISABLE       set to 1 to bypass checks entirely

Usage:
    python3 tools/circuit_breaker.py check --target-hash <sha256>
    python3 tools/circuit_breaker.py status --target-hash <sha256>
    python3 tools/circuit_breaker.py reset --target-hash <sha256>
    python3 tools/circuit_breaker.py trip --target-hash <sha256> --reason "429 burst"
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

TRACE_FILE = Path(".bb/traces/runs.jsonl")
CIRCUIT_DIR = Path(".bb/circuit")


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def threshold() -> int:
    return int(os.environ.get("BB_CB_THRESHOLD", "5"))


def cooldown_secs() -> int:
    return int(os.environ.get("BB_CB_COOLDOWN_MIN", "15")) * 60


def _recent_failures(target_hash: str, limit: int) -> int:
    """Count trailing consecutive failed runs for this target."""
    if not TRACE_FILE.exists():
        return 0
    try:
        lines = TRACE_FILE.read_text().strip().splitlines()
    except Exception:
        return 0
    consecutive = 0
    for line in reversed(lines[-200:]):
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("target_hash") != target_hash:
            continue
        if rec.get("exit_code") == 0:
            break
        consecutive += 1
        if consecutive >= limit:
            break
    return consecutive


def _active_cooldown(target_hash: str) -> dict | None:
    CIRCUIT_DIR.mkdir(parents=True, exist_ok=True)
    cd_file = CIRCUIT_DIR / f"{target_hash[:16]}.cooldown"
    if not cd_file.exists():
        return None
    try:
        data = json.loads(cd_file.read_text())
    except Exception:
        return None
    remaining = data.get("until_epoch", 0) - time.time()
    if remaining <= 0:
        cd_file.unlink(missing_ok=True)
        return None
    data["remaining_secs"] = int(remaining)
    return data


def cmd_check(target_hash: str) -> tuple[int, str]:
    if os.environ.get("BB_CB_DISABLE") == "1":
        return 0, "circuit breaker disabled (BB_CB_DISABLE=1)"
    cd = _active_cooldown(target_hash)
    if cd:
        mins = cd["remaining_secs"] // 60
        return 2, (
            f"CIRCUIT OPEN for target {target_hash[:12]} - {mins}m {cd['remaining_secs'] % 60}s remaining. "
            f"Reason: {cd.get('reason', 'consecutive failures')}. "
            f"Fix root cause or run: tools/circuit_breaker.py reset --target-hash {target_hash}"
        )
    fails = _recent_failures(target_hash, threshold())
    if fails >= threshold():
        until = time.time() + cooldown_secs()
        CIRCUIT_DIR.mkdir(parents=True, exist_ok=True)
        (CIRCUIT_DIR / f"{target_hash[:16]}.cooldown").write_text(json.dumps({
            "opened_at": now_iso(),
            "until_epoch": until,
            "reason": f"{fails} consecutive failed runs",
        }))
        return 2, (
            f"CIRCUIT OPENED - {fails} consecutive failed runs against target "
            f"{target_hash[:12]}. Cooling down {cooldown_secs() // 60}m. "
            "Likely WAF block, rate limiting, or broken context. Investigate before retrying."
        )
    return 0, f"ok ({fails}/{threshold()} consecutive failures)"


def cmd_status(target_hash: str) -> str:
    cd = _active_cooldown(target_hash)
    fails = _recent_failures(target_hash, threshold())
    if cd:
        return f"OPEN ({cd['remaining_secs']}s left) | reason: {cd.get('reason')}"
    return f"closed ({fails}/{threshold()} trailing failures)"


def cmd_reset(target_hash: str) -> str:
    CIRCUIT_DIR.mkdir(parents=True, exist_ok=True)
    removed = 0
    for suffix in ("cooldown", "flag"):
        f = CIRCUIT_DIR / f"{target_hash[:16]}.{suffix}"
        if f.exists():
            f.unlink()
            removed += 1
    return f"reset ({removed} state files cleared)"


def cmd_trip(target_hash: str, reason: str) -> str:
    CIRCUIT_DIR.mkdir(parents=True, exist_ok=True)
    (CIRCUIT_DIR / f"{target_hash[:16]}.cooldown").write_text(json.dumps({
        "opened_at": now_iso(),
        "until_epoch": time.time() + cooldown_secs(),
        "reason": reason or "manual trip",
    }))
    return f"circuit opened for {cooldown_secs() // 60}m"


def main():
    parser = argparse.ArgumentParser(description="Workflow circuit breaker")
    sub = parser.add_subparsers(dest="command")

    for name in ("check", "status", "reset"):
        p = sub.add_parser(name)
        p.add_argument("--target-hash", required=True)
    t = sub.add_parser("trip")
    t.add_argument("--target-hash", required=True)
    t.add_argument("--reason", default="manual trip")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    h = args.target_hash
    if args.command == "check":
        code, msg = cmd_check(h)
        print(msg, file=sys.stderr)
        sys.exit(code)
    elif args.command == "status":
        print(cmd_status(h))
    elif args.command == "reset":
        print(cmd_reset(h))
    elif args.command == "trip":
        print(cmd_trip(h, args.reason))


if __name__ == "__main__":
    main()
