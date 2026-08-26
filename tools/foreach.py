#!/usr/bin/env python3
"""Foreach helper — iterate a file with variable substitution and thread pool.

Usage:
    foreach.py --input hosts.txt --variable host --threads 5 --command 'echo [[host]] >> output.txt'
    foreach.py --input urls.txt --variable url --command 'curl -s [[url]]' --output results.txt
"""

import argparse
import re
import shlex
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import subprocess

MAX_BYTES = 10 * 1024 * 1024
MAX_LINES = 10000


def main():
    parser = argparse.ArgumentParser(description="Foreach helper with [[var]] substitution")
    parser.add_argument("--input", "-i", required=True, help="Input file (one item per line)")
    parser.add_argument("--variable", "-v", required=True, help="Variable name for substitution (use [[var]] in command)")
    parser.add_argument("--command", "-c", required=True, help="Command template with [[variable]]")
    parser.add_argument("--threads", "-t", type=int, default=5, help="Parallel threads (1-64)")
    parser.add_argument("--output", "-o", help="Output file for results")
    args = parser.parse_args()

    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", args.variable):
        print(f"ERROR: variable must match ^[A-Za-z_][A-Za-z0-9_]*$: {args.variable}", file=sys.stderr)
        sys.exit(1)
    if not 1 <= args.threads <= 64:
        print(f"ERROR: threads must be 1-64: {args.threads}", file=sys.stderr)
        sys.exit(1)

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"ERROR: input not found: {input_path}", file=sys.stderr)
        sys.exit(1)
    if input_path.stat().st_size > MAX_BYTES:
        print(f"ERROR: input too large (>10MB): {input_path}", file=sys.stderr)
        sys.exit(1)

    # Validate output path is not outside allowed dirs
    if args.output:
        out_path = Path(args.output)
        # Simple check: prevent writing to sensitive locations
        try:
            resolved = out_path.resolve()
            # Allow if under cwd or output/
            cwd = Path.cwd().resolve()
            if not str(resolved).startswith(str(cwd)) and "output" not in str(resolved):
                # Allow but warn
                print(f"WARN: output outside cwd: {resolved}", file=sys.stderr)
        except Exception:
            pass

    # Stream input with line cap
    lines = []
    with open(input_path, encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            if i >= MAX_LINES:
                print(f"WARN: truncated at {MAX_LINES} lines", file=sys.stderr)
                break
            stripped = line.strip()
            if stripped:
                lines.append(stripped)
    if not lines:
        print("No items to process", file=sys.stderr)
        sys.exit(0)

    # Prepare output: truncate at start to avoid doubling on rerun
    lock = threading.Lock()
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        # Truncate existing output
        open(args.output, "w").close()

    # Compile regex for [[ var ]] with optional whitespace
    var_pattern = re.compile(r"\[\[\s*" + re.escape(args.variable) + r"\s*\]\]")

    def run_one(item: str):
        # Quote item to prevent shell injection
        safe_item = shlex.quote(item)
        cmd = var_pattern.sub(safe_item, args.command)
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            output = result.stdout.strip()
            if args.output:
                with lock:
                    with open(args.output, "a", encoding="utf-8") as f:
                        f.write(output + "\n" if output else "")
            return output
        except Exception as e:
            print(f"Error processing {item}: {e}", file=sys.stderr)
            return ""

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        results = list(executor.map(run_one, lines))

    print(f"Processed {len(results)} items with {args.threads} threads", file=sys.stderr)


if __name__ == "__main__":
    main()
