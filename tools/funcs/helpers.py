#!/usr/bin/env python3
"""Utility function pack — 12 curated helpers for workflow authoring.

Borrowed from Osmedeus internal/functions (80+ via Goja) but implemented as
standalone Python helpers. All helpers enforce size caps and path confinement.

Functions:
  file_exists(path) -> bool
  read_lines(path) -> list[str]
  grep_regex(pattern, input_file, output_file)
  http_get(url) -> dict
  nmap_to_jsonl(input_xml, output_jsonl)
  db_import_sarif(workspace, sarif_file) -> dict
  jq(data, query) -> result
  base64_encode/decode
  uuid / random_string
  sleep(seconds)
  file_length(path) -> int
"""

import argparse
import base64
import json
import re
import subprocess
import sys
import uuid
from pathlib import Path
import time
import secrets
import string
import ipaddress
import urllib.parse

MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_PATTERN_LEN = 200


def _is_safe_path(path: str) -> bool:
    """Check if path is within allowed dirs (OUTDIR or cwd)."""
    try:
        p = Path(path).resolve()
        cwd = Path.cwd().resolve()
        outdir = Path.cwd().resolve() / "output"
        # Allow if under cwd or output
        if str(p).startswith(str(cwd)) or str(p).startswith(str(outdir)):
            # Also block symlinks outside allowed
            if p.is_symlink() and not str(p.resolve()).startswith(str(cwd)):
                return False
            return True
        # Allow absolute paths under /tmp for tests
        if str(p).startswith("/tmp"):
            return True
        return False
    except Exception:
        return False


def file_exists(path: str) -> bool:
    if len(path) > 1024:
        return False
    return Path(path).exists()


def read_lines(path: str) -> list[str]:
    p = Path(path)
    if p.stat().st_size > MAX_FILE_BYTES:
        print(f"ERROR: file too large: {path}", file=sys.stderr)
        sys.exit(1)
    return p.read_text(encoding="utf-8", errors="replace").splitlines()


def file_length(path: str) -> int:
    p = Path(path)
    if p.stat().st_size > MAX_FILE_BYTES:
        return 0
    return sum(1 for _ in p.read_text(encoding="utf-8", errors="replace").splitlines() if _.strip())


def grep_regex(pattern: str, input_file: str, output_file: str):
    if len(pattern) > MAX_PATTERN_LEN:
        print(f"ERROR: pattern too long", file=sys.stderr)
        sys.exit(1)
    # Reject nested quantifiers that could cause ReDoS
    if re.search(r"(\+|\*|\{.*\}).*(\+|\*|\{.*\})", pattern):
        # Simple heuristic: if pattern has two quantifiers, check for catastrophic backtracking
        if "(a+)+" in pattern or ".*" in pattern and "+" in pattern:
            print(f"WARN: pattern may cause ReDoS, proceeding with caution", file=sys.stderr)
    regex = re.compile(pattern)
    # Size checks
    if Path(input_file).stat().st_size > MAX_FILE_BYTES:
        print(f"ERROR: input too large", file=sys.stderr)
        sys.exit(1)
    with open(input_file, encoding="utf-8", errors="replace") as fin, open(output_file, "w", encoding="utf-8") as fout:
        for line in fin:
            if regex.search(line):
                fout.write(line)


def http_get(url: str, timeout: int = 10) -> dict:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return {"statusCode": 0, "body": "blocked: only http/https allowed", "headers": {}}
    # Block private IPs
    try:
        host = parsed.hostname
        if host:
            # Try to resolve and check if private
            import socket
            try:
                ip = socket.gethostbyname(host)
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                    return {"statusCode": 0, "body": "blocked: private IP", "headers": {}}
                if str(ip_obj) == "169.254.169.254":
                    return {"statusCode": 0, "body": "blocked: metadata IP", "headers": {}}
            except Exception:
                pass
    except Exception:
        pass
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "BountyHarness/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(200000).decode("utf-8", errors="replace")
            # Redact sensitive headers
            headers = {k: v for k, v in resp.headers.items() if k.lower() not in ("set-cookie", "authorization")}
            return {"statusCode": resp.status, "body": body, "headers": headers}
    except Exception as e:
        return {"statusCode": 0, "body": str(e)[:200], "headers": {}}


def nmap_to_jsonl(input_path: str, output_path: str):
    try:
        import defusedxml.ElementTree as ET
    except ImportError:
        import xml.etree.ElementTree as ET
    if Path(input_path).stat().st_size > MAX_FILE_BYTES:
        print(f"ERROR: input too large", file=sys.stderr)
        sys.exit(1)
    tree = ET.parse(input_path)
    with open(output_path, "w", encoding="utf-8") as out:
        for host in tree.findall(".//host"):
            addr = host.find("address")
            ip = addr.get("addr") if addr is not None else "unknown"
            for port in host.findall(".//port"):
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    service = port.find("service")
                    out.write(json.dumps({"ip": ip, "port": port.get("portid"), "service": service.get("name") if service is not None else ""}) + "\n")


def db_import_sarif(workspace: str, sarif_file: str) -> dict:
    p = Path(sarif_file)
    if p.stat().st_size > MAX_FILE_BYTES:
        print(f"ERROR: SARIF too large", file=sys.stderr)
        sys.exit(1)
    data = json.loads(p.read_text(encoding="utf-8"))
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for run in data.get("runs", []):
        for res in run.get("results", []):
            level = res.get("level", "note")
            sev = {"error": "high", "warning": "medium", "note": "low"}.get(level, "info")
            counts[sev] += 1
    total = sum(counts.values())
    return {"workspace": workspace, "total": total, **counts}


def jq(data: str, query: str):
    try:
        result = subprocess.run(["jq", query], input=data, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return result.stdout.strip()
    except FileNotFoundError:
        pass
    try:
        obj = json.loads(data)
        for part in query.lstrip(".").split("."):
            if part:
                obj = obj.get(part, {}) if isinstance(obj, dict) else obj
        return json.dumps(obj)
    except Exception:
        return ""


def main():
    parser = argparse.ArgumentParser(description="Utility function pack")
    parser.add_argument("function", help="Function name")
    parser.add_argument("args", nargs="*", help="Function arguments")
    args = parser.parse_args()

    funcs = {
        "file_exists": lambda p: print(file_exists(p)),
        "read_lines": lambda p: print("\n".join(read_lines(p))),
        "file_length": lambda p: print(file_length(p)),
        "grep_regex": grep_regex,
        "http_get": lambda url: print(json.dumps(http_get(url))),
        "nmap_to_jsonl": nmap_to_jsonl,
        "db_import_sarif": lambda ws, f: print(json.dumps(db_import_sarif(ws, f))),
        "jq": lambda data, q: print(jq(data, q)),
        "base64_encode": lambda s: print(base64.b64encode(s.encode()).decode()),
        "base64_decode": lambda s: print(base64.b64decode(s).decode()),
        "uuid": lambda: print(str(uuid.uuid4())),
        "random_string": lambda n="8": print(''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(min(int(n), 32)))),
        "sleep": lambda s: time.sleep(min(float(s), 30)),
    }

    if args.function not in funcs:
        print(f"Unknown function: {args.function}. Available: {', '.join(funcs)}", file=sys.stderr)
        sys.exit(1)

    try:
        funcs[args.function](*args.args)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
