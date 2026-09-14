#!/usr/bin/env bash
set -euo pipefail
trap 'echo "Integration installation failed at line $LINENO. Core adapters have NOT passed validation." >&2' ERR
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST_DIR="${HANZO_INTEGRATIONS_DIR:-$PROJECT_DIR/.integrations}"
PYTHON_BIN="${VAPT_PYTHON:-$PROJECT_DIR/.venv311/bin/python}"
export PATH="$PROJECT_DIR/tools/bin:$PROJECT_DIR/.venv311/bin:$PATH"
export HANZO_INTEGRATIONS_DIR="$DEST_DIR"
if (( $# > 1 )); then
  echo "Usage: $0 [--core|--all]" >&2
  exit 2
fi
case "${1:---core}" in
  --core) SYNC_ARGS=() ;;
  --all) SYNC_ARGS=(--all) ;;
  *) echo "Usage: $0 [--core|--all]"; exit 2 ;;
esac
if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "Run bash scripts/setup_kali.sh first (or create .venv311 with Python 3.11)."
  exit 1
fi
"$PYTHON_BIN" -c 'import sys; assert sys.version_info[:2] == (3, 11), "Use a Python 3.11 core environment"'
command -v git >/dev/null || { echo "git is required." >&2; exit 1; }
"$PYTHON_BIN" "$PROJECT_DIR/scripts/sync_integrations.py" "${SYNC_ARGS[@]}"
for integration in cve-mcp-server claude-bughunter; do
  adapter_python="$DEST_DIR/$integration/.venv/bin/python"
  if [[ -e "$DEST_DIR/$integration/.venv" ]]; then
    [[ -x "$adapter_python" ]] || { echo "$integration: existing .venv is incomplete; preserve it before recreating." >&2; exit 1; }
    "$adapter_python" -c 'import sys; assert sys.version_info[:2] == (3, 11), "Preserve the existing adapter environment and recreate it with Python 3.11"'
  else
    "$PYTHON_BIN" -m venv "$DEST_DIR/$integration/.venv"
  fi
done
"$DEST_DIR/cve-mcp-server/.venv/bin/python" -m pip install "mcp>=1.7,<2" -e "$DEST_DIR/cve-mcp-server"
"$DEST_DIR/claude-bughunter/.venv/bin/python" -m pip install -e "$DEST_DIR/claude-bughunter[http]"
"$DEST_DIR/cve-mcp-server/.venv/bin/python" -m pip check
"$DEST_DIR/claude-bughunter/.venv/bin/python" -m pip check
# Explicit paths also work with older runtime revisions that predate the shared root.
export CVE_MCP_DIR="${CVE_MCP_DIR:-$DEST_DIR/cve-mcp-server}"
export CLAUDE_BUGHUNTER_DIR="${CLAUDE_BUGHUNTER_DIR:-$DEST_DIR/claude-bughunter}"
"$PYTHON_BIN" "$PROJECT_DIR/scripts/validate_integrations.py"
echo "Core adapters installed. Optional sources require their own supported runtime and credentials."
