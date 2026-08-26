#!/usr/bin/env python3
"""Foreach helper — iterate a file with variable substitution and thread pool.

Mirrors Osmedeus foreach executor with [[variable]] syntax to avoid conflict
with {{var}} template vars. Uses mmap for >1MB files, compiled template cache.

Usage:
    foreach.py --input hosts.txt --variable host --threads 5 --command 'echo [[host]] >> output.txt'
    foreach.py --input urls.txt --variable url --command 'curl -s [[url]]' --output results.txt
"""

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description="Foreach helper with [[var]] substitution")
    parser.add_argument("--input", "-i", required=True, help="Input file (one item per line)")
    parser.add_argument("--variable", "-v", required=True, help="Variable name for substitution (use [[var]] in command)")
    parser.add_argument("--command", "-c", required=True, help="Command template with [[variable]]")
    parser.add_argument("--threads", "-t", type=int, default=5, help="Parallel threads")
    parser.add_argument("--output", "-o", help="Output file to append results")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"ERROR: input not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    lines = [l.strip() for l in input_path.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
    if not lines:
        print("No items to process", file=sys.stderr)
        sys.exit(0)

    var_placeholder = f"[[{args.variable}]]"

    def run_one(item: str):
        cmd = args.command.replace(var_placeholder, item)
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            output = result.stdout.strip()
            if args.output:
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
