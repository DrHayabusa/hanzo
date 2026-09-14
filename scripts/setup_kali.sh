#!/usr/bin/env bash
set -euo pipefail
trap 'echo "HANZO setup stopped at line $LINENO. Review the error above; installation is not complete." >&2' ERR
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"
export PATH="$PROJECT_DIR/tools/bin:$PROJECT_DIR/.venv311/bin:$PATH"
export VAPT_PYTHON="$PROJECT_DIR/.venv311/bin/python"
if (( $# > 1 )); then
  echo "Usage: bash scripts/setup_kali.sh [--core|--all-sources]" >&2
  exit 2
fi
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Run this bootstrap on your Kali/Linux worker. For macOS use the existing environment."
  exit 1
fi
case "${1:---core}" in
  --core|--all-sources) PROFILE="${1:---core}" ;;
  *) echo "Usage: bash scripts/setup_kali.sh [--core|--all-sources]"; exit 2 ;;
esac
for dependency in git curl; do
  command -v "$dependency" >/dev/null || { echo "Install prerequisite: $dependency"; exit 1; }
done
if [[ ! -x .venv311/bin/python ]]; then
  if [[ -e .venv311 ]]; then
    echo "Existing .venv311 is incomplete. Preserve it before recreating the environment." >&2
    exit 1
  fi
  if command -v python3.11 >/dev/null; then
    python3.11 -m venv .venv311 || {
      echo "Python 3.11 venv support is missing. Install python3.11-venv, or use uv with Python 3.11." >&2
      exit 1
    }
  elif command -v uv >/dev/null; then
    uv venv --python 3.11 --seed .venv311
  else
    echo "Python 3.11 is required for the current proxy dependencies."
    echo "On Kali: sudo apt-get install -y pipx && pipx install uv"
    echo 'Then: export PATH="$HOME/.local/bin:$PATH" and rerun this script.'
    exit 1
  fi
fi
.venv311/bin/python -c 'import sys; assert sys.version_info[:2] == (3, 11), "Existing .venv311 is not Python 3.11; preserve it and create a Python 3.11 environment"'
.venv311/bin/python -m pip install -r requirements-core.txt
.venv311/bin/python -m pip check
if [[ "$PROFILE" == "--all-sources" ]]; then
  bash scripts/install_integrations.sh --all
else
  bash scripts/install_integrations.sh --core
fi
.venv311/bin/python -m unittest discover -s tests -q
.venv311/bin/python scripts/doctor.py
echo "HANZO core installed. Next:"
echo "  bash scripts/install_kali_arsenal.sh --core"
echo "  bash start_vapt_agent.sh"
echo "  Open http://127.0.0.1:8888 on Kali"
echo "Source-only frameworks, missing executables, LLMs and optional services remain separate setup steps."
