#!/usr/bin/env bash
# Watch trigger helper — run a command when a file changes (uses fswatch or inotifywait)
# Usage: watch_trigger.sh /path/to/scope.txt "bb-run recon passive-subdomains"
set -euo pipefail
if [ $# -lt 2 ]; then
  echo "Usage: $0 <path> \"<command>\"" >&2
  exit 1
fi
WATCH_PATH="$1"
CMD="$2"
if [ ! -e "$WATCH_PATH" ]; then
  echo "Watch path does not exist: $WATCH_PATH" >&2
  exit 1
fi
if command -v fswatch >/dev/null 2>&1; then
  echo "Watching $WATCH_PATH with fswatch (Ctrl+C to stop)..."
  fswatch -o "$WATCH_PATH" | while read -r _; do echo "[$(date -Iseconds)] Triggered: $CMD"; eval "$CMD"; done
elif command -v inotifywait >/dev/null 2>&1; then
  echo "Watching $WATCH_PATH with inotifywait..."
  while inotifywait -e modify,create "$WATCH_PATH" 2>/dev/null; do echo "[$(date -Iseconds)] Triggered: $CMD"; eval "$CMD"; done
else
  echo "No watcher found. Install fswatch (brew install fswatch) or inotify-tools." >&2
  exit 1
fi
