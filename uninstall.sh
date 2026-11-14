#!/usr/bin/env bash
set -Eeuo pipefail
BASE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PROXYPILOT_PYTHON:-$(command -v python3 || true)}"
if [[ -z "$PYTHON" ]]; then
  printf '%s\n' 'Python 3 was not found. No files were changed.' >&2
  exit 1
fi
EXTRA_PYTHONPATH="$BASE/src:$BASE"
if [[ -n "${PYTHONPATH:-}" ]]; then EXTRA_PYTHONPATH="$EXTRA_PYTHONPATH:$PYTHONPATH"; fi
export PYTHONPATH="$EXTRA_PYTHONPATH"
exec "$PYTHON" -m proxypilot_app.uninstall "$@"
