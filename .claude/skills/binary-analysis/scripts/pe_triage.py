#!/usr/bin/env python3
"""Static PE triage - first-pass analysis of Windows binaries before any
dynamic session. Pure stdlib, no dependencies.

Answers the bounty-relevant questions about a downloadable target:
  - What is it? (arch, subsystem, compile timestamp, signatures present)
  - Is it packed? (section entropy + known packer section names)
  - What does it talk to? (imported networking/crypto APIs, embedded URLs)
  - Where are the interesting hooks? (dynamic-analysis watchlist matches)

Usage:
    pe_triage.py --file target.exe --output triage.json
    pe_triage.py --dir downloads/ --output-dir triage/     # batch mode
"""

import argparse
import json
import math
import re
import struct
import sys
from datetime import UTC, datetime
from pathlib import Path

# APIs that indicate interesting behavior for security analysis
WATCHLIST = {
    "network": ["WinHttpSendRequest", "InternetOpenUrl", "WSAStartup", "connect", "send",
                "WinHttpOpen", "InternetReadFile", "URLDownloadToFile", "socket", "recv"],
    "crypto": ["CryptStringToBinary", "CryptDecrypt", "BCryptDecrypt", "CryptUnprotectData",
               "BCryptOpenAlgorithmProvider", "CryptAcquireContext", "CryptEncrypt"],
    "process": ["CreateProcess", "WinExec", "ShellExecute", "SetWindowsHookEx",
                "WriteProcessMemory", "VirtualAllocEx", "CreateRemoteThread"],
    "anti_analysis": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugString",
                      "NtQueryInformationProcess", "GetTickCount", "QueryPerformanceCounter"],
}

PACKER_SECTIONS = {"upx0", "upx1", "upx2", ".aspack", ".adata", ".themida", ".vmp0", ".vmp1",
                   ".nsp0", ".nsp1", ".petite", "pec2", ".mpress1", ".mpress2", ".enigma1", ".enigma2"}

URL_RE = re.compile(rb"(https?://[\x20-\x7e]{6,200})")
IP_RE = re.compile(rb"\b((?:\d{1,3}\.){3}\d{1,3})\b")


def now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    ent = 0.0
    n = len(data)
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 3)


def parse_pe(data: bytes) -> dict:
    out: dict = {"valid_pe": False}
    if len(data) < 64 or data[:2] != b"MZ":
        return out
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return out

    machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    timestamp = struct.unpack_from("<I", data, e_lfanew + 8)[0]
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    opt_off = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt_off)[0]
    subsystem = struct.unpack_from("<H", data, opt_off + (68 if magic == 0x20B else 68))[0]

    arch = {0x14C: "x86", 0x8664: "x64", 0xAA64: "arm64"}.get(machine, hex(machine))
    subsys = {2: "GUI", 3: "console", 1: "native"}.get(subsystem, f"sub{subsystem}")
    try:
        compiled = datetime.utcfromtimestamp(timestamp).isoformat()
    except Exception:
        compiled = None

    # Section table
    sec_off = opt_off + opt_size
    sections = []
    packer_hits = set()
    high_entropy = []
    for i in range(min(num_sections, 96)):
        base = sec_off + i * 40
        if base + 40 > len(data):
            break
        name = data[base : base + 8].split(b"\x00")[0].decode("ascii", errors="replace")
        vsize = struct.unpack_from("<I", data, base + 8)[0]
        raw_size = struct.unpack_from("<I", data, base + 16)[0]
        raw_ptr = struct.unpack_from("<I", data, base + 20)[0]
        chars = struct.unpack_from("<I", data, base + 36)[0]
        ent_val = entropy(data[raw_ptr : raw_ptr + min(raw_size, 1_000_000)]) if raw_size else 0.0
        exec_flag = bool(chars & 0x20000000)
        writable = bool(chars & 0x80000000)
        sections.append({"name": name, "virtual_size": vsize, "raw_size": raw_size,
                         "entropy": ent_val, "executable": exec_flag, "writable": writable})
        if name.lower().lstrip(".") in PACKER_SECTIONS or name.lower() in PACKER_SECTIONS:
            packer_hits.add(name)
        if exec_flag and ent_val > 7.2 and raw_size > 4096:
            high_entropy.append({"name": name, "entropy": ent_val})

    # Import names: scan the whole file for ASCII strings matching watchlist
    text_blob = data
    found_apis = {}
    for cat, apis in WATCHLIST.items():
        hits = [a for a in apis if a.encode() in text_blob]
        if hits:
            found_apis[cat] = hits

    # Embedded indicators
    urls = sorted({m.group(0).decode("ascii", errors="replace") for m in URL_RE.finditer(text_blob)})[:40]
    ips = sorted({m.group(1).decode("ascii") for m in IP_RE.finditer(text_blob)
                  if all(int(o) <= 255 for o in m.group(1).split(b"."))})[:20]

    out.update({
        "valid_pe": True,
        "arch": arch,
        "subsystem": subsys,
        "compiled_at": compiled,
        "sections_count": len(sections),
        "sections": sections,
        "packer_section_names": sorted(packer_hits),
        "high_entropy_exec_sections": high_entropy,
        "likely_packed": bool(packer_hits or high_entropy),
        "watchlist_import_hits": found_apis,
        "embedded_urls_sample": urls,
        "embedded_ips_sample": ips,
    })
    return out


def triage_file(path: Path) -> dict:
    try:
        data = path.read_bytes()
    except Exception as e:
        return {"file": str(path), "error": str(e)[:120]}
    result = {
        "file": str(path),
        "size_bytes": len(data),
        "sha256_prefix": __import__("hashlib").sha256(data).hexdigest()[:16],
        "triaged_at": now_iso(),
    }
    result.update(parse_pe(data))
    return result


def main():
    parser = argparse.ArgumentParser(description="Static PE triage (stdlib-only)")
    parser.add_argument("--file", help="Single binary to analyze")
    parser.add_argument("--dir", help="Directory of binaries (batch)")
    parser.add_argument("--output", help="JSON output file (single mode)")
    parser.add_argument("--output-dir", default=".", help="Directory for batch JSONL output")
    args = parser.parse_args()

    if not args.file and not args.dir:
        parser.print_help()
        sys.exit(1)

    from pathlib import Path as P

    if args.file:
        r = triage_file(P(args.file))
        text = json.dumps(r, indent=2)
        if args.output:
            P(args.output).parent.mkdir(parents=True, exist_ok=True)
            P(args.output).write_text(text)
            print(f"wrote {args.output}: valid_pe={r.get('valid_pe')} packed={r.get('likely_packed')}")
        else:
            print(text)

    if args.dir:
        d = P(args.dir)
        out_dir = P(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / "pe_triage.jsonl"
        count = 0
        with open(out_path, "w") as fh:
            for f in sorted(d.rglob("*")):
                if f.is_file() and f.suffix.lower() in (".exe", ".dll", ".sys"):
                    fh.write(json.dumps(triage_file(f)) + "\n")
                    count += 1
        print(json.dumps({"batch_files": count, "output": str(out_path)}))


if __name__ == "__main__":
    main()
