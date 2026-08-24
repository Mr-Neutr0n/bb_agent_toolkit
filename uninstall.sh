#!/bin/sh
# BountyHarness uninstaller.
#
# Usage:
#   ./uninstall.sh            # remove PATH symlinks only
#   PURGE=1 ./uninstall.sh    # also delete the install tree
#   sh -s -- --purge          # pipe-form equivalent

set -eu

REPO_NAME="bounty-harness"
BIN_NAMES="bb-init bb-validate bb-run bb-hunt bb-tools"

# Locate the tree: env override > script location (repo clone) > default
if [ -n "${INSTALL_DIR:-}" ]; then
  TREE="$INSTALL_DIR"
elif [ -f "$(dirname "$0")/bin/bb-run" ]; then
  TREE="$(cd "$(dirname "$0")" && pwd)"
else
  TREE="$HOME/$REPO_NAME"
fi

removed=0
for d in "$HOME/.local/bin" /usr/local/bin; do
  for b in $BIN_NAMES; do
    if [ -L "$d/$b" ]; then
      rm -f "$d/$b"
      removed=$((removed + 1))
      echo "removed $d/$b"
    fi
  done
done
echo "==> removed $removed symlink(s)"

if [ "${PURGE:-0}" = "1" ] || [ "${1:-}" = "--purge" ]; then
  if [ -d "$TREE/.git" ] && echo "$TREE" | grep -q "$REPO_NAME"; then
    rm -rf "$TREE"
    echo "==> purged $TREE"
  else
    echo "refusing to purge '$TREE': not recognized as a bounty-harness clone" >&2
    exit 1
  fi
else
  echo "install tree kept at $TREE (set PURGE=1 to delete)"
fi

echo "NOTE: engagement data lives inside the tree (.bb/, output/, engagements/)."
echo "Purge removes it. Copy it out first if you need the history."
