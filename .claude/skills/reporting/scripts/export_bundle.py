#!/usr/bin/env python3
"""Export bundle builder — package findings into a share-safe ZIP with manifest.

Produces either a complete bundle (all steps finished) or a clearly marked
partial bundle (stopped/failed scan that still has findings). Attacker-controlled
fields (report/PoC source) are kept as plain text and never rendered as HTML.

Usage:
    export_bundle.py --outdir output/acme.com/2024-01-15_1000 --output /tmp/bundle.zip
    export_bundle.py --outdir output/acme.com/2024-01-15_1000 --output /tmp/bundle.zip --partial-reason "stopped by operator"
    export_bundle.py --scan-dir .bb/scans/scan-123 --output /tmp/bundle.zip
    export_bundle.py --outdir output/acme.com --output /tmp/bundle.zip --dry-run
"""

import argparse
import hashlib
import json
import os
import re
import sys
import unicodedata
import zipfile
from datetime import datetime, timezone
from pathlib import Path

MAX_FINDINGS_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BUNDLE_BYTES = 100 * 1024 * 1024
MAX_EVIDENCE_FILES = 1000
MAX_SINGLE_FILE_BYTES = 10 * 1024 * 1024


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    safe = "".join(c for c in msg if c == "\n" or c == "\t" or 32 <= ord(c) <= 126)
    print(f"[{now_iso()}] {safe[:500]}", file=sys.stderr)


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def collect_findings(outdir: Path) -> list[dict]:
    findings: list[dict] = []
    candidates = [
        outdir / "impact-verifier" / "verified.jsonl",
        outdir / "reports" / "ranked.jsonl",
        outdir / "reports" / "findings.jsonl",
        outdir / "reporting" / "findings.jsonl",
        outdir / "reports" / "findings" / "findings.jsonl",
    ]
    # Walk reports/findings dir if it exists
    findings_dir = outdir / "reports" / "findings"
    if findings_dir.exists():
        for jf in sorted(findings_dir.glob("*.jsonl")):
            candidates.append(jf)
    for src in candidates:
        if not src.exists():
            continue
        if src.stat().st_size > MAX_FINDINGS_FILE_BYTES:
            log(f"WARN: skipping large findings file {src} ({src.stat().st_size} bytes)")
            continue
        try:
            text = src.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            log(f"WARN: cannot read {src}: {e}")
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                findings.append({"raw": line[:2000], "source": str(src)})
    return findings


def sanitize_text(s: str) -> str:
    """Keep attacker-influenced text as plain text. Strip control, format, bidi chars."""
    out = []
    for c in s:
        if c in ("\n", "\t"):
            out.append(c)
            continue
        cat = unicodedata.category(c)
        # Cc control, Cf format (includes bidi overrides, zero-width), Zl/Zp line/para separators
        if cat in ("Cc", "Cf", "Zl", "Zp"):
            continue
        # Explicit bidi range still catch under Cf but keep belt
        if "\u202a" <= c <= "\u202e" or "\u2066" <= c <= "\u2069":
            continue
        if 32 <= ord(c) <= 126 or 160 <= ord(c) <= 55295:
            out.append(c)
        elif ord(c) > 55295:
            out.append(c)
    return "".join(out)


def build_manifest(outdir: Path, findings: list[dict], partial_reason: str | None) -> dict:
    if partial_reason is not None:
        partial_reason = sanitize_text(partial_reason)[:500]
        if not partial_reason.strip():
            partial_reason = None

    # Empty findings always partial regardless of caller
    if not findings and partial_reason is None:
        partial_reason = "no findings collected"

    ctx_file = Path(".bb/context.json")
    context = {}
    if ctx_file.exists():
        try:
            context = json.loads(ctx_file.read_text(encoding="utf-8"))
        except Exception:
            pass

    trace_file = Path(".bb/traces/runs.jsonl")
    trace_count = 0
    if trace_file.exists():
        try:
            trace_count = sum(1 for _ in trace_file.read_text(encoding="utf-8").splitlines() if _.strip())
        except Exception:
            pass

    complete = partial_reason is None
    return {
        "toolkit": "bounty-harness",
        "version": Path("VERSION").read_text(encoding="utf-8").strip() if Path("VERSION").exists() else "unknown",
        "exported_at": now_iso(),
        "bundle_kind": "complete" if complete else "partial",
        "partial_reason": partial_reason,
        "target": context.get("target") or os.environ.get("TARGET", "unknown"),
        "program": context.get("program") or os.environ.get("PROGRAM", "unknown"),
        "outdir": outdir.name,
        "findings_count": len(findings),
        "trace_count": trace_count,
        "findings_summary": [
            {
                "title": str(f.get("title") or f.get("summary") or f.get("name") or "Unnamed")[:120],
                "severity": str(f.get("severity") or f.get("bounty_rank_impact_level") or "unknown"),
                "type": str(f.get("vulnerability_type") or f.get("type") or "unknown"),
            }
            for f in findings
        ],
        "share_safe_note": "PoC and report source fields are plain text; do not render as HTML without sanitization.",
    }


def is_safe_path(path: Path, base: Path) -> bool:
    try:
        # Resolve without following symlink if it is a symlink
        if path.is_symlink():
            return False
        resolved = path.resolve()
        return resolved.is_relative_to(base.resolve())
    except Exception:
        return False


def build_bundle(outdir: Path, output: Path, partial_reason: str | None = None, dry_run: bool = False) -> Path:
    outdir = outdir.resolve()
    if not outdir.exists():
        log(f"ERROR: outdir does not exist: {outdir}")
        sys.exit(1)

    findings = collect_findings(outdir)
    manifest = build_manifest(outdir, findings, partial_reason)

    if dry_run:
        print(json.dumps(manifest, indent=2))
        log(f"Dry run: would create {output} ({manifest['bundle_kind']}, {len(findings)} findings)")
        return output

    output.parent.mkdir(parents=True, exist_ok=True)

    file_count = 0
    total_bytes = 0
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))

        findings_json = json.dumps(findings, indent=2, ensure_ascii=False)
        zf.writestr("findings.json", sanitize_text(findings_json))

        for src in [outdir / "impact-verifier" / "verified.jsonl", outdir / "reports" / "ranked.jsonl", outdir / "reporting" / "findings.jsonl"]:
            if src.exists() and src.stat().st_size <= MAX_FINDINGS_FILE_BYTES and is_safe_path(src, outdir):
                if src.stat().st_size > MAX_TOTAL_BUNDLE_BYTES:
                    continue
                zf.write(src, arcname=f"structured/{src.parent.name}_{src.name}")

        for report in sorted(outdir.rglob("report*.md")):
            if file_count >= MAX_EVIDENCE_FILES:
                log("WARN: evidence file count limit reached")
                break
            if report.is_symlink() or not is_safe_path(report, outdir):
                continue
            if report.stat().st_size > MAX_SINGLE_FILE_BYTES:
                continue
            if total_bytes > MAX_TOTAL_BUNDLE_BYTES:
                break
            arc = f"reports/{report.relative_to(outdir)}"
            zf.write(report, arcname=arc)
            file_count += 1
            total_bytes += report.stat().st_size

        for ev in sorted(outdir.rglob("evidence/*")):
            if file_count >= MAX_EVIDENCE_FILES:
                break
            if not ev.is_file() or ev.is_symlink() or not is_safe_path(ev, outdir):
                continue
            if ev.stat().st_size > MAX_SINGLE_FILE_BYTES:
                continue
            if total_bytes > MAX_TOTAL_BUNDLE_BYTES:
                break
            try:
                arc = f"evidence/{ev.relative_to(outdir)}"
                zf.write(ev, arcname=arc)
                file_count += 1
                total_bytes += ev.stat().st_size
            except Exception:
                continue

        if manifest["bundle_kind"] == "partial":
            safe_reason = sanitize_text(manifest["partial_reason"] or "")[:500]
            zf.writestr("PARTIAL.txt", f"This bundle is PARTIAL: {safe_reason}\nExported at {manifest['exported_at']}\n")

    size = output.stat().st_size
    h = sha256_file(output)
    log(f"Bundle {manifest['bundle_kind']}: {output} ({size} bytes, sha256:{h[:12]}...) with {len(findings)} findings")
    if manifest["bundle_kind"] == "partial":
        log(f"Partial reason: {sanitize_text(manifest['partial_reason'] or '')[:200]}")
    print(json.dumps({"bundle": str(output), "kind": manifest["bundle_kind"], "findings": len(findings), "sha256": h, "size": size}))
    return output


def build_args() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Finding export bundle builder")
    p.add_argument("--outdir", required=True, help="OUTDIR containing impact-verifier/reporting findings")
    p.add_argument("--output", "-o", required=True, help="Output ZIP path")
    p.add_argument("--partial-reason", default=None, help="If set, marks bundle as partial with this reason")
    p.add_argument("--scan-dir", default=None, help="Alternative scan directory (alias for --outdir)")
    p.add_argument("--dry-run", action="store_true", help="Validate and print manifest without writing ZIP")
    return p


def main() -> None:
    args = build_args().parse_args()
    outdir = Path(args.scan_dir) if args.scan_dir else Path(args.outdir)
    build_bundle(outdir, Path(args.output), args.partial_reason, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
