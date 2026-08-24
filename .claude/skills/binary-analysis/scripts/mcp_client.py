#!/usr/bin/env python3
"""MCP client for x64dbg-mcp-server - drive a running x64dbg debugger session
programmatically over Streamable HTTP (JSON-RPC 2.0) with bearer auth.

The plugin exposes ~71 tools. Tool names are discovered at runtime via
tools/list; this client provides intent-based wrappers so workflows do not
hardcode names:

    mcp_client.py tools --url http://localhost:9094 --token-file .bb/x64dbg.token
    mcp_client.py call  --intent registers   ...
    mcp_client.py call  --intent modules     ...
    mcp_client.py call  --intent strings     ...
    mcp_client.py call  --name ExactToolName --args '{"arg":1}'

Safety: this is LOCAL dynamic analysis of binaries you already possess.
It never touches remote target infrastructure. Bearer token lives in
.bb/ and is gitignored.
"""

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

# Intent -> regex matched against discovered tool names
INTENTS = {
    "registers": r"get.*(?:all)?registers",
    "modules": r"(?:module|peb).*(?:list|head)",
    "threads": r"thread.*list|getthread",
    "strings": r"(?:snap|string).*(?:string|refs)|string.*scan",
    "patterns": r"pattern|find.*pattern",
    "xrefs": r"xref",
    "breakpoint": r"(?:set|delete).*(?:bp|breakpoint)",
    "step": r"^step|^run$|resume|go\b",
    "memory-read": r"read.*mem|dump.*mem|mem.*read",
    "disassemble": r"disassembl",
    "callstack": r"call.?stack|stacktrace",
    "pe-analysis": r"pe\s*analysis|analyze.*pe|oep",
}


def now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_token(token_file: str | None, explicit_token: str | None) -> str:
    if explicit_token:
        return explicit_token
    if token_file and Path(token_file).exists():
        return Path(token_file).read_text().strip()
    # conventional location
    default = Path(".bb/x64dbg.token")
    if default.exists():
        return default.read_text().strip()
    print("ERROR: no bearer token. Pass --token or --token-file (.bb/x64dbg.token).", file=sys.stderr)
    sys.exit(1)


def rpc(url: str, token: str, method: str, params: dict | None = None, timeout: int = 30,
        session_id: str | None = None) -> tuple[int, dict | str, str | None]:
    """Single JSON-RPC POST against the MCP streamable endpoint."""
    body = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params:
        body["params"] = params
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {token}",
    }
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(4_000_000).decode("utf-8", errors="replace")
            sid = resp.headers.get("Mcp-Session-Id")
            status = resp.status
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")[:500], None
    except Exception as e:
        return 0, str(e)[:200], None

    try:
        return status, json.loads(raw), sid
    except json.JSONDecodeError:
        # SSE-wrapped response: extract data: line payload(s)
        payloads = []
        for m in re.finditer(r"data:\s*(\{.*\})", raw):
            try:
                payloads.append(json.loads(m.group(1)))
            except json.JSONDecodeError:
                continue
        if payloads:
            merged = next((p for p in payloads if p.get("id") == 1), payloads[-1])
            return status, merged, sid
        return status, raw[:500], sid


def ensure_initialized(url: str, token: str) -> str | None:
    """MCP requires an initialize handshake before other calls."""
    status, resp, sid = rpc(
        url, token, "initialize",
        params={
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "bountyharness-binary-analysis", "version": "1.0.0"},
        },
    )
    if status != 200 or isinstance(resp, str):
        print(f"initialize failed: {status} {str(resp)[:200]}", file=sys.stderr)
        sys.exit(1)
    # notification/initialized per spec
    rpc(url, token, "notifications/initialized", session_id=sid)
    return sid


def list_tools(url: str, token: str) -> list[dict]:
    sid = ensure_initialized(url, token)
    status, resp, _ = rpc(url, token, "tools/list", session_id=sid)
    if isinstance(resp, dict):
        return resp.get("result", {}).get("tools", [])
    return []


def match_tools(tools: list[dict], pattern: str) -> list[str]:
    rx = re.compile(pattern, re.I)
    return [t.get("name", "") for t in tools if rx.search(t.get("name", ""))]


def main():
    parser = argparse.ArgumentParser(description="x64dbg MCP client (local dynamic analysis)")
    sub = parser.add_subparsers(dest="command")

    p_tools = sub.add_parser("tools", help="List available debugger tools")
    p_tools.add_argument("--url", default="http://localhost:9094/")
    p_tools.add_argument("--token", default=None)
    p_tools.add_argument("--token-file", default=".bb/x64dbg.token")

    p_call = sub.add_parser("call", help="Call one tool by name or intent")
    p_call.add_argument("--url", default="http://localhost:9094/")
    p_call.add_argument("--token", default=None)
    p_call.add_argument("--token-file", default=".bb/x64dbg.token")
    p_call.add_argument("--name", help="Exact tool name")
    p_call.add_argument("--intent", choices=sorted(INTENTS.keys()), help="Fuzzy-match a tool role")
    p_call.add_argument("--args", default="{}", help="JSON arguments object")
    p_call.add_argument("--output", default=None)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    token = load_token(getattr(args, "token_file", None), getattr(args, "token", None))

    if args.command == "tools":
        tools = list_tools(args.url, token)
        out = {"count": len(tools),
               "tools": [{"name": t.get("name"), "description": str(t.get("description", ""))[:100]} for t in tools]}
        print(json.dumps(out, indent=2))
        sys.exit(0)

    if args.command == "call":
        tools = list_tools(args.url, token)
        if args.name:
            matches = [args.name]
        elif args.intent:
            matches = match_tools(tools, INTENTS[args.intent])
        else:
            print("Provide --name or --intent", file=sys.stderr)
            sys.exit(1)

        if not matches:
            print(json.dumps({"status": "no_match", "intent_or_name": args.intent or args.name,
                              "available_count": len(tools)}))
            sys.exit(2)

        chosen = matches[0]
        try:
            call_args = json.loads(args.args)
        except json.JSONDecodeError:
            print("invalid --args JSON", file=sys.stderr)
            sys.exit(1)

        sid = ensure_initialized(args.url, token)
        status, resp, _ = rpc(args.url, token, "tools/call",
                              params={"name": chosen, "arguments": call_args}, session_id=sid)
        result = {
            "called_at": now_iso(),
            "tool": chosen,
            "matched_candidates": matches[:5],
            "http_status": status,
            "result": resp if isinstance(resp, dict) else str(resp)[:400],
        }
        text = json.dumps(result, indent=2)
        if args.output:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            Path(args.output).write_text(text)
        print(text)


if __name__ == "__main__":
    main()
