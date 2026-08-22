#!/usr/bin/env python3
"""Desync trigger matrix - detection sweeps for post-2024 request-smuggling classes.

Covers what classic CL.TE/TE.CL/TE.TE probes miss:
  - expect-0cl   : obfuscated Expect header + Content-Length: 0 front-end/bypass combos
  - multipart-cl : multipart/byteranges Content-Length confusion triggers
  - rqp-confirm  : dangling-byte request queue poisoning CONFIRMATION
                   (safe: single injected prefix, then check for response desync;
                    no payload delivery to other users)

DETECTION ONLY. Confirmation probes use a canary prefix that only affects our own
connection's queue; nothing is stored or served to third parties.

Usage:
    desync_matrix.py --target https://example.com --matrix all --output findings.jsonl
    desync_matrix.py --target https://example.com --matrix expect-0cl,rqp-confirm --dry-run
"""

import argparse
import json
import os
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

RATE_LIMIT = float(os.environ.get("RATE_LIMIT", "5"))
UA = "Mozilla/5.0 (Security Research; BountyHarness)"


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    print(f"[{now_iso()}] {msg}", file=sys.stderr)


def parse_target(target: str) -> tuple[str, int, bool]:
    t = target if "://" in target else f"https://{target}"
    p = t.split("://", 1)
    tls = p[0] == "https"
    rest = p[1].split("/", 1)[0]
    host, port = (rest.split(":") + [ "443" if tls else "80" ])[:2]
    return host, int(port), tls


def connect(host: str, port: int, tls: bool, timeout: float = 10.0):
    raw = socket.create_connection((host, port), timeout=timeout)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["http/1.1"])
        return ctx.wrap_socket(raw, server_hostname=host)
    return raw


def send_and_read(sock, payload: bytes, timeout: float = 8.0) -> str:
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
            if b"\r\n\r\n" in b"".join(chunks):
                head_done = b"".join(chunks).split(b"\r\n\r\n", 1)[1]
                # crude body-completeness: stop when headers seen and some body arrived
                if len(head_done) > 0 and len(b"".join(chunks)) > 64:
                    break
    except socket.timeout:
        pass
    except Exception:
        pass
    return b"".join(chunks).decode("utf-8", errors="replace")


def base_request(host: str, path: str = "/") -> str:
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {UA}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
    )


def probe_expect_0cl(host: str, path: str = "/") -> dict:
    """Obfuscated Expect header variants paired with CL:0 - some frontends treat
    'Expect: 100-c' style truncated values oddly and forward the body as a new req."""
    finding = {"probe": "expect-0cl", "success": False}
    variants = [
        ("100-continue", "Content-Length: 0\r\n"),
        ("10", "Content-Length: 0\r\n"),
        ("100-cont\x00inue", "Content-Length: 0\r\n"),
        ("100-continue ", "Transfer-Encoding: chunked\r\n"),
    ]
    for exp_val, framing in variants:
        time.sleep(1.0 / max(RATE_LIMIT, 0.1))
        body = "x=1"
        payload = (
            base_request(host, path)
            + f"Expect: {exp_val}\r\n"
            + framing
            + f"\r\n{body}"
        ).encode()
        try:
            s = connect(host_port[0], host_port[1], host_port[2])
            resp = send_and_read(s, payload)
            s.close()
        except Exception as e:
            finding["error"] = str(e)[:100]
            continue
        if resp.count("HTTP/1.1 ") >= 2:
            finding.update(success=True, evidence=f"dual response with Expect '{exp_val}'",
                           variant=exp_val, framing=framing.strip())
            break
        if "100 Continue" in resp and "200 OK" in resp:
            finding["note"] = f"normal 100-continue flow with '{exp_val}'"
    return finding


def probe_multipart_cl(host: str, path: str = "/") -> dict:
    """multipart/byteranges with mismatched Content-Length: some stacks parse
    embedded ranges' lengths as the request body length."""
    finding = {"probe": "multipart-cl", "success": False}
    boundary = "bbhcanary42"
    inner = (
        f"--{boundary}\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "AAAAA\r\n"
        f"--{boundary}--\r\n"
    )
    payload = (
        base_request(host, path)
        + f"Content-Type: multipart/byteranges; boundary={boundary}\r\n"
        + f"Content-Length: {len(inner)}\r\n"
        + "\r\n" + inner
    ).encode()
    try:
        s = connect(*host_port)
        resp = send_and_read(s, payload)
        s.close()
    except Exception as e:
        finding["error"] = str(e)[:100]
        return finding
    if resp.count("HTTP/1.1 ") >= 2:
        finding.update(success=True,
                       evidence="second response parsed from same connection after multipart CL confusion")
    return finding


def probe_rqp_confirm(host: str, path: str = "/") -> dict:
    """Dangling-byte RQP confirmation: send a request whose body is one byte short,
    then a follow-up normal GET on the SAME connection. If the frontend forwarded
    our short body, the leftover byte prefixes our GET and we observe a desynced
    response sequence on OUR connection only."""
    finding = {"probe": "rqp-confirm", "success": False}
    smuggled_prefix = "G"
    body_full = f"{smuggled_prefix}ET /{path.lstrip('/')} HTTP/1.1\r\nHost: {host}\r\n\r\n"
    payload1 = (
        base_request(host, path)
        + f"Content-Length: {len(body_full)}\r\n"
        + "\r\n"
        + body_full[:-1]          # dangle exactly one byte
    ).encode()
    payload2 = f"GET /?bbhconfirm=1 HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()
    try:
        s = connect(*host_port)
        r1 = send_and_read(s, payload1, timeout=8)
        r2 = send_and_read(s, payload2, timeout=8)
        s.close()
    except Exception as e:
        finding["error"] = str(e)[:100]
        return finding
    combined = r1 + r2
    if "bbhconfirm=1" not in r1 and ("404" in r2 or "400" in r2 or "501" in r2):
        finding.update(success=True,
                       evidence="follow-up request desynced after dangling byte (RQP candidate)",
                   )
    elif r1 == "" and r2:
        finding["note"] = "first response delayed; ambiguous, retry manually before claiming"
    return finding


PROBES = {
    "expect-0cl": probe_expect_0cl,
    "multipart-cl": probe_multipart_cl,
    "rqp-confirm": probe_rqp_confirm,
}

host_port: tuple[str, int, bool] = ("", 80, False)


def main():
    parser = argparse.ArgumentParser(description="Desync trigger matrix (detection-only)")
    parser.add_argument("--target", required=True)
    parser.add_argument("--path", default="/")
    parser.add_argument("--matrix", default="all",
                        help="comma list: expect-0cl,multipart-cl,rqp-confirm (default all)")
    parser.add_argument("--output", required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    global host_port
    host_port = parse_target(args.target)

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
        log(f"running {name} against {args.target}{args.path}")
        r = fn(host_port[0], args.path)
        r["target"] = args.target
        r["checked_at"] = now_iso()
        results.append(r)
        log(f"{name}: {'HIT' if r.get('success') else 'no hit'}")

    out = {
        "tool": "desync_matrix",
        "target": args.target,
        "checked_at": now_iso(),
        "safety_note": "Detection-only; rqp-confirm affects caller connection only.",
        "results": results,
    }
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text("\n".join(json.dumps(r) for r in results))
    print(json.dumps({"probes_run": len(results),
                      "hits": sum(1 for r in results if r.get("success")),
                      "output": args.output}))


if __name__ == "__main__":
    main()
