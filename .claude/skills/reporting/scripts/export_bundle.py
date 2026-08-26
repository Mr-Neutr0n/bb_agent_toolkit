#!/usr/bin/env python3
"""Export bundle builder — package findings into a share-safe ZIP with manifest.

Produces either a complete bundle (all steps finished) or a clearly marked
partial bundle (stopped/failed scan that still has findings). Attacker-controlled
fields (report/PoC source) are kept as plain text and never rendered as HTML.

Usage:
    export_bundle.py --outdir output/acme.com/2024-01-15_1000 --output /tmp/bundle.zip
    export_bundle.py --outdir output/acme.com/2024-01-15_1000 --output /tmp/bundle.zip --partial-reason "stopped by operator"
    export_bundle.py --scan-dir .bb/scans/scan-123 --output /tmp/bundle.zip
"""

import argparse
import hashlib
import json
import os
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    print(f"[{now_iso()}] {msg}", file=sys.stderr)


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
        outdir / "reporting" / "findings.jsonl",
        outdir / "reports" / "findings.jsonl",
    ]
    for src in candidates:
        if not src.exists():
            continue
        for line in src.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                findings.append({"raw": line, "source": str(src)})
    return findings


def sanitize_text(s: str) -> str:
    """Keep attacker-influenced text as plain text - strip control chars that could affect ZIP readers."""
    return "".join(c for c in s if c == "\n" or c == "\t" or (32 <= ord(c) <= 126) or ord(c) >= 160)


def build_manifest(outdir: Path, findings: list[dict], partial_reason: str | None) -> dict:
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
        trace_count = sum(1 for _ in trace_file.read_text(encoding="utf-8").splitlines() if _.strip())

    complete = partial_reason is None
    return {
        "toolkit": "bounty-harness",
        "version": Path("VERSION").read_text(encoding="utf-8").strip() if Path("VERSION").exists() else "unknown",
        "exported_at": now_iso(),
        "bundle_kind": "complete" if complete else "partial",
        "partial_reason": partial_reason,
        "target": context.get("target") or os.environ.get("TARGET", "unknown"),
        "program": context.get("program") or os.environ.get("PROGRAM", "unknown"),
        "outdir": str(outdir),
        "findings_count": len(findings),
        "trace_count": trace_count,
        "findings_summary": [
            {
                "title": f.get("title") or f.get("summary") or f.get("name") or "Unnamed",
                "severity": f.get("severity") or f.get("bounty_rank_impact_level") or "unknown",
                "type": f.get("vulnerability_type") or f.get("type") or "unknown",
            }
            for f in findings
        ],
        "share_safe_note": "PoC and report source fields are plain text; do not render as HTML without sanitization.",
    }


def build_bundle(outdir: Path, output: Path, partial_reason: str | None = None) -> Path:
    outdir = outdir.resolve()
    if not outdir.exists():
        log(f"ERROR: outdir does not exist: {outdir}")
        sys.exit(1)

    findings = collect_findings(outdir)
    manifest = build_manifest(outdir, findings, partial_reason)

    if not findings and partial_reason is None:
        log("WARNING: no findings collected - bundle will be marked partial")
        manifest["bundle_kind"] = "partial"
        manifest["partial_reason"] = "no findings collected"

    output.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # manifest
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))

        # canonical findings (sanitized)
        findings_json = json.dumps(findings, indent=2, ensure_ascii=False)
        zf.writestr("findings.json", sanitize_text(findings_json))

        # structured data: copy any findings.jsonl as-is (already JSON lines)
        for src in [outdir / "impact-verifier" / "verified.jsonl", outdir / "reporting" / "findings.jsonl"]:
            if src.exists():
                zf.write(src, arcname=f"structured/{src.parent.name}_{src.name}")

        # reports (if generated)
        for report in sorted(outdir.rglob("report*.md")):
            arc = f"reports/{report.relative_to(outdir)}"
            zf.write(report, arcname=arc)

        # evidence manifests (plain text copies)
        for ev in sorted(outdir.rglob("evidence/*")):
            if ev.is_file():
                try:
                    # copy as stored bytes to preserve screenshots; text files still plain text
                    zf.write(ev, arcname=f"evidence/{ev.relative_to(outdir)}")
                except Exception:
                    continue

        # marker for partial bundles (visible at unzip -l)
        if manifest["bundle_kind"] == "partial":
            zf.writestr("PARTIAL.txt", f"This bundle is PARTIAL: {manifest['partial_reason']}\nExported at {manifest['exported_at']}\n")

    size = output.stat().st_size
    h = sha256_file(output)
    log(f"Bundle {manifest['bundle_kind']}: {output} ({size} bytes, sha256:{h[:12]}...) with {len(findings)} findings")
    if manifest["bundle_kind"] == "partial":
        log(f"Partial reason: {manifest['partial_reason']}")
    print(json.dumps({"bundle": str(output), "kind": manifest["bundle_kind"], "findings": len(findings), "sha256": h, "size": size}))
    return output


def build_args() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Finding export bundle builder")
    p.add_argument("--outdir", required=True, help="OUTDIR containing impact-verifier/reporting findings")
    p.add_argument("--output", "-o", required=True, help="Output ZIP path")
    p.add_argument("--partial-reason", default=None, help="If set, marks bundle as partial with this reason")
    p.add_argument("--scan-dir", default=None, help="Alternative scan directory (alias for --outdir)")
    return p


def main() -> None:
    args = build_args().parse_args()
    outdir = Path(args.scan_dir) if args.scan_dir else Path(args.outdir)
    build_bundle(outdir, Path(args.output), args.partial_reason)


if __name__ == "__main__":
    main()
