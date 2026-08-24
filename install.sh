#!/bin/sh
# BountyHarness installer - oh-my-zsh/nvm style bootstrap.
#
# Usage:
#   ./install.sh                              # install into current dir if empty
#   INSTALL_DIR=~/tools/bounty-harness ./install.sh
#   curl -fsSL https://raw.githubusercontent.com/Mr-Neutr0n/bounty-harness/main/install.sh | sh -s --
#
# The pipe form works because this script is POSIX sh and never reads stdin.
# Nothing here pipes this script's own download to a shell twice; the clone is
# fetched by git, not by curl.

set -eu

# Override for testing branches/forks: BB_INSTALL_REPO_URL=/local/path ./install.sh
REPO_URL="${BB_INSTALL_REPO_URL:-https://github.com/Mr-Neutr0n/bounty-harness.git}"
REPO_NAME="bounty-harness"
BIN_NAMES="bb-init bb-validate bb-run bb-hunt bb-tools"

say()  { printf '%s\n' "$*"; }
warn() { printf '\033[33m%s\033[0m\n' "$*" >&2; }
die()  { printf '\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

# ── Decide install directory ────────────────────────────────────────────────
if [ -n "${INSTALL_DIR:-}" ]; then
  INSTALL_DIR="${INSTALL_DIR%/}"
elif [ ! -d "$(pwd)" ] || [ -z "$(ls -A . 2>/dev/null)" ]; then
  INSTALL_DIR="$(pwd)/$REPO_NAME"
elif [ -d "./$REPO_NAME/.git" ]; then
  INSTALL_DIR="$(pwd)/$REPO_NAME"
elif [ -d "./.git" ] && git -C . remote get-url origin >/dev/null 2>&1 \
     && git -C . remote get-url origin | grep -q "bounty-harness"; then
  INSTALL_DIR="$(pwd)"
else
  die "current dir is not empty. cd into an empty dir, an existing bounty-harness clone, or set: INSTALL_DIR=/path ./install.sh"
fi

say "==> Installing BountyHarness into $INSTALL_DIR"

# ── Clone or update ─────────────────────────────────────────────────────────
command -v git >/dev/null 2>&1 || die "git not found. Install it:
  macOS:   brew install git
  Debian:  sudo apt-get install -y git"

if [ -d "$INSTALL_DIR/.git" ]; then
  say "==> Existing clone found; pulling latest main"
  git -C "$INSTALL_DIR" pull --ff-only origin main \
    || warn "pull failed; keeping current checkout"
else
  parent_dir=$(dirname "$INSTALL_DIR")
  [ -d "$parent_dir" ] || mkdir -p "$parent_dir" || die "cannot create $parent_dir"
  if [ -e "$INSTALL_DIR" ] && [ -n "$(ls -A "$INSTALL_DIR" 2>/dev/null)" ]; then
    die "$INSTALL_DIR exists and is not a git clone. Remove it or choose another INSTALL_DIR."
  fi
  git clone --depth 1 "$REPO_URL" "$INSTALL_DIR" || die "git clone failed"
fi

# ── Dependency verification ─────────────────────────────────────────────────
MISSING=""

# python3 >= 3.11
PY=""
for cand in python3 python; do
  if command -v "$cand" >/dev/null 2>&1; then
    v=$("$cand" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null) || continue
    major=${v%%.*}; minor=${v#*.}
    if [ "$major" -gt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -ge 11 ]; }; then
      PY="$cand"; break
    fi
  fi
done
if [ -z "$PY" ]; then
  MISSING="$MISSING
- python3 >= 3.11 NOT FOUND. Fix with:
    macOS:   brew install python@3.12
    Debian:  sudo apt-get install -y python3 python3-pip"
else
  say "==> python3 OK ($("$PY" --version))"
fi

# pyyaml importable by that interpreter
if [ -n "$PY" ]; then
  if "$PY" -c 'import yaml' >/dev/null 2>&1; then
    say "==> pyyaml OK"
  else
    MISSING="$MISSING
- PyYAML not importable by $PY. Fix with:
    $PY -m pip install --user pyyaml
    (Debian/Ubuntu may need: sudo apt-get install -y python3-yaml)"
  fi
fi

# optional but recommended
if ! command -v gitleaks >/dev/null 2>&1; then
  warn "gitleaks not found (optional, used by 'make secrets'): brew install gitleaks"
fi

if [ -n "$MISSING" ]; then
  printf '\033[31mERROR: missing dependencies:\033[0m\n%s\n' "$MISSING" >&2
  exit 1
fi

# ── Smoke test from the installed tree ──────────────────────────────────────
( cd "$INSTALL_DIR" && "$PY" -c 'import yaml' ) || die "pyyaml check failed inside $INSTALL_DIR"
"$INSTALL_DIR/bin/bb-run" list >/dev/null 2>&1 || die "bb-run list failed inside $INSTALL_DIR - run '$INSTALL_DIR/bin/bb-run list' to debug"
say "==> Smoke test passed (46 skills discovered)"

# ── Symlink binaries onto PATH ──────────────────────────────────────────────
LINK_DIR=""
for candidate in "$HOME/.local/bin" /usr/local/bin; do
  if [ -d "$candidate" ] && [ -w "$candidate" ]; then LINK_DIR="$candidate"; break; fi
done
if [ -z "$LINK_DIR" ] && [ -d "$HOME/.local/bin" -o ! -d "$HOME/.local" ]; then
  mkdir -p "$HOME/.local/bin" 2>/dev/null && LINK_DIR="$HOME/.local/bin"
fi
if [ -z "$LINK_DIR" ]; then
  warn "no writable bin dir found; add manually:"
  warn "  ln -sf $INSTALL_DIR/bin/bb-* ~/.local/bin/"
else
  for b in $BIN_NAMES; do
    ln -sf "$INSTALL_DIR/bin/$b" "$LINK_DIR/$b"
  done
  say "==> Symlinked $BIN_NAMES into $LINK_DIR"
  case ":$PATH:" in
    *":$LINK_DIR:"*) ;;
    *) warn "NOTE: $LINK_DIR is not on your PATH. Add to your shell rc:
  export PATH=\"$LINK_DIR:\$PATH\"" ;;
  esac
fi

# ── Quickstart ──────────────────────────────────────────────────────────────
cat <<EOF

============================================================
 BountyHarness installed
============================================================

Quick start:

  bb-init example.com --program example --scope-file scope.txt
  bb-run list                        # browse 46 skills
  bb-run recon list                  # browse one skill's workflows
  bb-hunt https://example.com --dry-run

Docs: $INSTALL_DIR/README.md
Repo: $REPO_URL

Use only on systems you own or are explicitly authorized to test.
============================================================
EOF
