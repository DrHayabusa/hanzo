#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

echo "VAPT Agent will stay available while this Terminal window remains open."
echo "Open http://127.0.0.1:8888/ in your browser."
echo "Press Control-C here to stop the server."
echo

exec ./start_vapt_agent.sh
