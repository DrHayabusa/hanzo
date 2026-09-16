#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${VAPT_PYTHON:-$PROJECT_DIR/.venv311/bin/python}"
HOST="${VAPT_HOST:-127.0.0.1}"
PORT="${VAPT_PORT:-8888}"
OLLAMA_BIN="$PROJECT_DIR/tools/ollama/ollama"
OLLAMA_URL="${OLLAMA_URL:-http://127.0.0.1:11434}"
OLLAMA_MODEL="${OLLAMA_MODEL:-qwen3:1.7b}"

export PATH="$PROJECT_DIR/tools/bin:$HOME/.local/bin:$PATH"
export OLLAMA_URL OLLAMA_MODEL

if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "VAPT Agent environment not found at $PYTHON_BIN"
  echo "Create it with: python3.11 -m venv .venv311"
  echo "Then install: .venv311/bin/pip install -r requirements-core.txt"
  exit 1
fi

cd "$PROJECT_DIR"

OLLAMA_PID=""
SERVER_PID=""
cleanup() {
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
  [[ -n "$OLLAMA_PID" ]] && kill "$OLLAMA_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM


# Wait for Ollama, and say plainly when it does not come up. A stale process can
# hold 11434 without serving, which otherwise looks like a silent hang.
wait_for_ollama() {
  local label="$1"
  for _ in {1..30}; do
    curl -fsS --max-time 1 "$OLLAMA_URL/api/tags" >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "Warning: $label did not answer on $OLLAMA_URL within 30s." >&2
  if lsof -nP -iTCP:11434 -sTCP:LISTEN >/dev/null 2>&1; then
    echo "  Something is already listening on 11434 but not serving the API." >&2
    echo "  Stop it and start HANZO again:" >&2
    echo "    pkill -f 'ollama serve' || kill -9 \$(lsof -tnP -iTCP:11434 -sTCP:LISTEN)" >&2
  else
    echo "  Check ollama.log for the reason. The AI assistant will show as offline." >&2
  fi
  return 1
}

if [[ "${HANZO_SKIP_OLLAMA:-0}" != "1" && "$OLLAMA_URL" == "http://127.0.0.1:11434" ]] && ! curl -fsS --max-time 2 "$OLLAMA_URL/api/tags" >/dev/null 2>&1; then
  if [[ -x "$OLLAMA_BIN" ]]; then
    echo "Starting project-local AI ($OLLAMA_MODEL)..."
    OLLAMA_MODELS="$PROJECT_DIR/models" OLLAMA_HOST="127.0.0.1:11434" \
      "$OLLAMA_BIN" serve >> "$PROJECT_DIR/ollama.log" 2>&1 &
    OLLAMA_PID=$!
    wait_for_ollama "project-local Ollama"
  elif command -v ollama >/dev/null 2>&1; then
    echo "Starting system Ollama ($OLLAMA_MODEL)..."
    OLLAMA_HOST="127.0.0.1:11434" ollama serve >> "$PROJECT_DIR/ollama.log" 2>&1 &
    OLLAMA_PID=$!
    wait_for_ollama "system Ollama"
  fi
fi

if curl -fsS --max-time 2 "$OLLAMA_URL/api/tags" >/dev/null 2>&1; then
  echo "Ollama API reachable. Check model availability and inference in AI assistant."
else
  echo "Local Ollama is offline. VAPT Agent will still start."
  echo "Use Groq, OpenRouter, or another OpenAI-compatible API in AI Copilot."
fi
echo "Starting VAPT Agent at http://$HOST:$PORT"
"$PYTHON_BIN" hexstrike_server.py --host "$HOST" --port "$PORT" "$@" &
SERVER_PID=$!
wait "$SERVER_PID"
