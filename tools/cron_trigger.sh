#!/usr/bin/env bash
# Cron trigger helper — schedule a workflow via system cron
# Usage: cron_trigger.sh "0 2 * * *" "bb-run recon passive-subdomains"
set -euo pipefail
if [ $# -lt 2 ]; then
  echo "Usage: $0 \"<cron-expr>\" \"<command>\" [comment]" >&2
  exit 1
fi
CRON_EXPR="$1"
CMD="$2"
COMMENT="${3:-bounty-harness cron}"
if [[ "$CMD" == *$'\n'* || "$COMMENT" == *$'\n'* ]]; then
  echo "Command/comment must not contain newlines" >&2
  exit 1
fi
if ! echo "$CRON_EXPR" | grep -Eq '^([^ ]+ +){4}[^ ]+$'; then
  echo "Invalid cron expression: $CRON_EXPR" >&2
  exit 1
fi
# Use flock to avoid TOCTOU race
(
  flock -n 200 || { echo "Another cron update in progress" >&2; exit 1; }
  ( crontab -l 2>/dev/null; echo "$CRON_EXPR $CMD # $COMMENT" ) | crontab -
) 200>/tmp/bb-cron.lock
echo "Installed cron: $CRON_EXPR $CMD"
