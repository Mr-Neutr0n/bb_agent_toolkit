#!/usr/bin/env python3
"""Utility function pack — 12 curated helpers for workflow authoring.

Borrowed from Osmedeus internal/functions (80+ via Goja) but implemented as
standalone Python helpers that can be invoked directly or via bb-run.

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
  exec_cmd(cmd)
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
import random
import string


def file_exists(path: str) -> bool:
    return Path(path).exists()


def read_lines(path: str) -> list[str]:
    return Path(path).read_text(encoding="utf-8", errors="replace").splitlines()


def file_length(path: str) -> int:
    return sum(1 for _ in Path(path).read_text(encoding="utf-8", errors="replace").splitlines() if _.strip())


def grep_regex(pattern: str, input_file: str, output_file: str):
    regex = re.compile(pattern)
    with open(input_file, encoding="utf-8", errors="replace") as fin, open(output_file, "w", encoding="utf-8") as fout:
        for line in fin:
            if regex.search(line):
                fout.write(line)


def http_get(url: str, timeout: int = 10) -> dict:
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "BountyHarness/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return {"statusCode": resp.status, "body": resp.read(200000).decode("utf-8", errors="replace"), "headers": dict(resp.headers)}
    except Exception as e:
        return {"statusCode": 0, "body": str(e), "headers": {}}


def nmap_to_jsonl(input_path: str, output_path: str):
    # Minimal nmap XML to JSONL: extract hosts with open ports
    import xml.etree.ElementTree as ET
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
    # Stub that counts SARIF results by severity
    data = json.loads(Path(sarif_file).read_text(encoding="utf-8"))
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for run in data.get("runs", []):
        for res in run.get("results", []):
            level = res.get("level", "note")
            sev = {"error": "high", "warning": "medium", "note": "low"}.get(level, "info")
            counts[sev] += 1
    total = sum(counts.values())
    # In real harness, would upsert to database; here just report
    return {"workspace": workspace, "total": total, **counts}


def jq(data: str, query: str):
    # Thin wrapper around jq if available, else python fallback for simple queries
    try:
        result = subprocess.run(["jq", query], input=data, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return result.stdout.strip()
    except FileNotFoundError:
        pass
    # Fallback: try simple json path
    try:
        obj = json.loads(data)
        # very simple: .key or .key.subkey
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
        "random_string": lambda n="8": print(''.join(random.choices(string.ascii_letters + string.digits, k=int(n)))),
        "sleep": lambda s: time.sleep(float(s)),
        "exec_cmd": lambda c: print(subprocess.run(c, shell=True, capture_output=True, text=True, timeout=30).stdout),
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
