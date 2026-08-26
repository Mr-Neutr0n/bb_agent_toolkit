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
# Validate cron expression has 5 fields
if ! echo "$CRON_EXPR" | grep -Eq '^([^ ]+ +){4}[^ ]+$'; then
  echo "Invalid cron expression: $CRON_EXPR" >&2
  exit 1
fi
# Install via crontab
( crontab -l 2>/dev/null; echo "$CRON_EXPR $CMD # $COMMENT" ) | crontab -
echo "Installed cron: $CRON_EXPR $CMD"
