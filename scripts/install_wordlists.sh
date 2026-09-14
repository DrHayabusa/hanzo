#!/usr/bin/env bash
# Install wordlists for the HANZO command launcher.
#
# Preference order:
#   1. Kali package  : sudo apt-get install -y seclists  -> /usr/share/seclists
#   2. System clone  : /opt/SecLists                     (needs write access to /opt)
#   3. Project clone : ./wordlists/SecLists              (never committed)
#
# Discovery reads whatever actually exists; this script only adds real files.
set -euo pipefail
trap 'echo "Wordlist installation stopped at line $LINENO. Nothing further was installed." >&2' ERR

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="https://github.com/danielmiessler/SecLists.git"
MODE="${1:---auto}"

case "$MODE" in
  --auto|--apt|--opt|--project) ;;
  *)
    echo "Usage: bash scripts/install_wordlists.sh [--auto|--apt|--opt|--project]" >&2
    exit 2
    ;;
esac

command -v git >/dev/null || { echo "Install prerequisite: git" >&2; exit 1; }

clone_into() {
  local target="$1"
  if [[ -d "$target/.git" ]]; then
    echo "SecLists already present at $target. Updating..."
    git -C "$target" pull --ff-only --depth 1 || echo "Update skipped; keeping the existing checkout."
  elif [[ -e "$target" ]]; then
    echo "$target already exists and is not a git checkout. Preserving it; nothing installed." >&2
    return 1
  else
    echo "Cloning SecLists into $target (this downloads roughly 1 GB)..."
    git clone --depth 1 "$REPO" "$target"
  fi
  echo "Wordlists available at $target"
}

if [[ "$MODE" == "--apt" || "$MODE" == "--auto" ]]; then
  if command -v apt-get >/dev/null; then
    echo "Installing the seclists package. This needs sudo and may prompt."
    if sudo apt-get install -y seclists; then
      echo "seclists installed. Discovery reads /usr/share/seclists and /usr/share/wordlists."
      exit 0
    fi
    echo "apt-get could not install seclists; falling back to a git clone."
  elif [[ "$MODE" == "--apt" ]]; then
    echo "apt-get is not available on this host. Use --opt or --project." >&2
    exit 1
  fi
fi

if [[ "$MODE" == "--opt" ]] || { [[ "$MODE" == "--auto" ]] && [[ -w /opt ]]; }; then
  clone_into "/opt/SecLists" && exit 0
  echo "Falling back to a project-local clone."
fi

mkdir -p "$PROJECT_DIR/wordlists"
clone_into "$PROJECT_DIR/wordlists/SecLists"
echo
echo "Next: open Security tools, pick a command with a wordlist argument, and choose"
echo "a list from the dropdown. Use HANZO_WORDLIST_DIRS to add your own directories."
