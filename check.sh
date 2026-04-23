#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${VENV_DIR:-.venv}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

if [[ ! -d "$VENV_DIR" ]]; then
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

VENV_PYTHON="$VENV_DIR/bin/python"
if [[ ! -x "$VENV_PYTHON" ]]; then
  echo "ERROR: venv python not found at $VENV_PYTHON"
  exit 2
fi

"$VENV_PYTHON" -m pip install -U pip >/dev/null
"$VENV_PYTHON" -m pip install -r requirements.txt pytest ruff >/dev/null

echo "[lint] ruff"
"$VENV_PYTHON" -m ruff check .

echo "[smoke] list profiles"
"$VENV_PYTHON" main.py --list-profiles >/dev/null

echo "[smoke] list checks"
"$VENV_PYTHON" main.py --list-checks >/dev/null

echo "[tests] pytest"
"$VENV_PYTHON" -m pytest -q

if command -v gitleaks >/dev/null 2>&1; then
  echo "[security] gitleaks working tree"
  gitleaks dir --redact . >/dev/null
else
  echo "[security] gitleaks not installed; skipped"
fi
