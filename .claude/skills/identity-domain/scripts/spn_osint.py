#!/usr/bin/env python3
"""SPN OSINT — hunt leaked service principal names in JS bundles, headers, and text.

Scans files/directories (typically recon js_downloads/ output) for SPN-shaped
strings (MSSQLSvc/host:1433, HTTP/host, cifs/host, termsrv, ...) plus
WWW-Authenticate Negotiate realm leaks. Passive: reads local files only,
optionally fetches a URL's headers.

Usage:
    spn_osint.py scan --path $OUTDIR/recon/js/js_downloads --output spns.json
    spn_osint.py header --url https://example.com --output spns.json
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

SPN_RE = re.compile(
    r"\b((?:MSSQLSvc|HTTP|HOST|cifs|termsrv|RPCSS|WSMAN|ldap|DMS|vpn|www)"
    r"/[A-Za-z0-9._\-]+(?::\d{1,5})?)",
)
REALM_RE = re.compile(r"(?:Negotiate|NTLM)[^\r\n]*realm=\"?([A-Za-z0-9.\-_]+)\"?", re.I)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def scan_path(root: str) -> dict:
    findings = []
    p = Path(root)
    files = [f for f in p.rglob("*") if f.is_file()] if p.is_dir() else ([p] if p.is_file() else [])
    for f in files:
        try:
            if f.stat().st_size > 5_000_000:
                continue
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for m in SPN_RE.finditer(text):
            line = text[: m.start()].count("\n") + 1
            findings.append({"file": str(f), "line": line, "spn": m.group(1)})
        for m in REALM_RE.finditer(text):
            line = text[: m.start()].count("\n") + 1
            findings.append({"file": str(f), "line": line, "realm_hint": m.group(1)})
    deduped = {(x.get("spn"), x.get("realm_hint")) for x in findings}
    return {
        "checked_at": now_iso(),
        "files_scanned": len(files),
        "hits": len(findings),
        "unique": len({d for d in deduped if any(d)}),
        "findings": findings[:200],
    }


def check_header(url: str) -> dict:
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Security Research)"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            www_auth = resp.headers.get("WWW-Authenticate", "")
    except Exception as e:
        return {"checked_at": now_iso(), "url": url, "error": str(e)[:120]}
    out = {"checked_at": now_iso(), "url": url, "www_authenticate": www_auth[:200]}
    for m in REALM_RE.finditer(www_auth):
        out["realm_hint"] = m.group(1)
    return out


def main():
    parser = argparse.ArgumentParser(description="SPN OSINT scanner")
    sub = parser.add_subparsers(dest="command")

    s = sub.add_parser("scan")
    s.add_argument("--path", required=True)
    s.add_argument("--output", required=True)

    h = sub.add_parser("header")
    h.add_argument("--url", required=True)
    h.add_argument("--output", default=None)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    result = scan_path(args.path) if args.command == "scan" else check_header(args.url)
    print(json.dumps(result, indent=2))
    if getattr(args, "output", None):
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
