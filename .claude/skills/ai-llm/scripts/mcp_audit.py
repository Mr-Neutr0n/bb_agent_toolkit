#!/usr/bin/env python3
"""MCP server integrity auditor - rug-pull diffing and description-injection scans.

Complements mcp_fuzzer.py (which tests tool behavior). This script audits tool
DEFINITIONS over time:

  snapshot   Fetch tools/list and store a hashed definition manifest
  audit      Scan a manifest (or live server) for hidden-unicode instruction
             smuggling in descriptions; flag anonymous listing on remote servers
  diff       Compare two manifests -> report added/removed/CHANGED tools (rug pulls)

Usage:
    mcp_audit.py snapshot --url https://mcp.example.com/sse --manifest .bb/mcp/manifest.json
    mcp_audit.py diff --old old.json --new new.json
    mcp_audit.py audit --url https://mcp.example.com/sse --manifest out.json
"""

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

RATE_LIMIT = float(__import__("os").environ.get("RATE_LIMIT", "5"))
UA = "Mozilla/5.0 (Security Research; BountyHarness)"

# Unicode classes abused to hide instructions inside tool descriptions
HIDDEN_CHARS = {
    "zero-width-space": "\u200b",
    "zero-width-nonjoiner": "\u200c",
    "zero-width-joiner": "\u200d",
    "left-to-right-mark": "\u200e",
    "right-to-left-mark": "\u200f",
    "bidi-override-lre": "\u202a",
    "bidi-override-rle": "\u202b",
    "bidi-override-pdf": "\u202c",
    "bidi-isolate-lri": "\u2066",
    "bidi-isolate-rli": "\u2067",
    "bidi-first-strong-isolate": "\u2068",
    "pop-directional-isolate": "\u2069",
    "variation-selector": "\ufe0f",
    "tag-characters": "\U000e0001",
}

# STDIO launch defaults copied verbatim from SDK quickstarts - a known footgun
STDIO_RISKY_DEFAULTS = [
    (r"npx\s+-y\s+\S+", "npx -y auto-installs unvetted packages at agent start"),
    (r"uvx\s+\S+", "uvx runs package without lock/pin"),
    (r"curl[^|]*\|\s*(?:ba)?sh", "pipe-to-shell bootstrap"),
]


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    print(f"[{now_iso()}] {msg}", file=sys.stderr)


def throttle() -> None:
    time.sleep(1.0 / max(RATE_LIMIT, 0.1))


def jsonrpc_list_tools(url: str, timeout: int = 15) -> tuple[int, dict | str]:
    """Best-effort JSON-RPC tools/list against streamable-http or SSE-style endpoints."""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}).encode()
    req = urllib.request.Request(
        url, data=body,
        headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(2_000_000).decode("utf-8", errors="replace")
            status = resp.status
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:
        return 0, str(e)

    # SSE wrappers embed the JSON-RPC payload in event lines
    if "text/event-stream" in raw[:200] or raw.startswith("event:") or "\ndata:" in raw[:500]:
        pass  # handled by extractor below
    try:
        return status, json.loads(raw)
    except json.JSONDecodeError:
        m = re.search(r"data:\s*(\{.*\})", raw, re.S)
        if m:
            try:
                return status, json.loads(m.group(1))
            except json.JSONDecodeError:
                pass
    return status, raw


def extract_tools(payload) -> list[dict]:
    if isinstance(payload, dict):
        return payload.get("result", {}).get("tools", []) or []
    return []


def scan_description(text: str) -> list[str]:
    hits = []
    for name, ch in HIDDEN_CHARS.items():
        if ch in text:
            hits.append(f"hidden-{name}")
    # whitespace-encoded steganography (double spaces / tabs between words can encode bits)
    if re.search(r"\w {3,}\w", text):
        hits.append("excessive-whitespace-runs")
    # imperative instruction patterns unusual in API descriptions
    if re.search(r"\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b", text, re.I):
        hits.append("instruction-override-text")
    if re.search(r"\b(?:exfiltrate|send[s]?|post[s]?|forward[s]?).{0,30}(?:api[\s_-]?key|token|secret|credentials)\b", text, re.I):
        hits.append("credential-exfil-instruction")
    return hits


def build_manifest(url: str) -> dict:
    throttle()
    status, payload = jsonrpc_list_tools(url)
    tools = extract_tools(payload)
    entries = {}
    for t in tools:
        name = t.get("name", "?")
        blob = json.dumps(t, sort_keys=True)
        entries[name] = {
            "hash": hashlib.sha256(blob.encode()).hexdigest()[:16],
            "description_hits": scan_description(str(t.get("description", ""))),
        }
    return {
        "url": url,
        "taken_at": now_iso(),
        "http_status": status,
        "anonymous_listing": status == 200 and bool(tools),
        "tool_count": len(tools),
        "tools": entries,
    }


def cmd_snapshot(args) -> dict:
    manifest = build_manifest(args.url)
    Path(args.manifest).parent.mkdir(parents=True, exist_ok=True)
    Path(args.manifest).write_text(json.dumps(manifest, indent=2))
    log(f"manifest written: {manifest['tool_count']} tools")
    return {"status": "snapshotted", "tools": manifest["tool_count"],
            "anonymous_listing": manifest["anonymous_listing"], "output": args.manifest}


def cmd_audit(args) -> dict:
    manifest = build_manifest(args.url)
    findings = []
    if manifest["anonymous_listing"]:
        findings.append({"type": "anonymous-tool-listing", "severity": "medium",
                         "detail": "tools/list succeeds without auth on remote endpoint"})
    for name, meta in manifest["tools"].items():
        for hit in meta["description_hits"]:
            findings.append({"type": "description-smuggling", "severity": "high",
                             "tool": name, "detail": hit})
    result = {"status": "audited", "url": args.url, "checked_at": now_iso(),
              "findings_count": len(findings), "findings": findings}
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(result, indent=2))
    return result


def cmd_diff(args) -> dict:
    old = json.loads(Path(args.old).read_text())
    new = json.loads(Path(args.new).read_text())
    ot, nt = old.get("tools", {}), new.get("tools", {})
    changes = []
    for name in sorted(set(ot) | set(nt)):
        o, n = ot.get(name), nt.get(name)
        if o and not n:
            changes.append({"tool": name, "change": "removed"})
        elif n and not o:
            changes.append({"tool": name, "change": "added",
                            "description_hits": n["description_hits"]})
        elif o["hash"] != n["hash"]:
            changes.append({"tool": name, "change": "RUG-PULL-REDEFINED",
                            "old_hash": o["hash"], "new_hash": n["hash"],
                            "description_hits": n["description_hits"]})
    result = {
        "status": "diffed",
        "compared_at": now_iso(),
        "old_taken": old.get("taken_at"),
        "new_taken": new.get("taken_at"),
        "changed_count": len(changes),
        "changes": changes,
    }
    out = args.output or ".bb/mcp/rugpull_diff.json"
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(json.dumps(result, indent=2))
    return result


def cmd_stdio_scan(args) -> dict:
    """Scan local MCP client configs for risky launch defaults."""
    findings = []
    cfg = Path(args.config)
    files = [f for f in cfg.rglob("*") if f.is_file()] if cfg.is_dir() else ([cfg] if cfg.exists() else [])
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for pat, why in STDIO_RISKY_DEFAULTS:
            for m in re.finditer(pat, text):
                line = text[: m.start()].count("\n") + 1
                findings.append({"file": str(f), "line": line, "match": m.group(0)[:80], "why": why})
    return {"status": "scanned", "files_scanned": len(files), "findings": findings}


def main():
    parser = argparse.ArgumentParser(description="MCP definition integrity auditor")
    sub = parser.add_subparsers(dest="command")

    s = sub.add_parser("snapshot")
    s.add_argument("--url", required=True)
    s.add_argument("--manifest", required=True)

    a = sub.add_parser("audit")
    a.add_argument("--url", required=True)
    a.add_argument("--output", required=True)

    d = sub.add_parser("diff")
    d.add_argument("--old", required=True)
    d.add_argument("--new", required=True)
    d.add_argument("--output", default=None)

    st = sub.add_parser("stdio-scan")
    st.add_argument("--config", required=True, help="Path to MCP client config dir/file")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    fn = {"snapshot": cmd_snapshot, "audit": cmd_audit, "diff": cmd_diff, "stdio-scan": cmd_stdio_scan}
    print(json.dumps(fn[args.command](args), indent=2))


if __name__ == "__main__":
    main()
