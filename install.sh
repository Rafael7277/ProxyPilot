#!/usr/bin/env bash
set -Eeuo pipefail
BASE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PROXYPILOT_PYTHON:-$(command -v python3 || true)}"
if [[ -z "$PYTHON" ]]; then
  printf '%s\n' 'Python 3 was not found. Install Python 3 and retry.' >&2
  exit 1
fi
exec "$PYTHON" "$BASE/scripts/install.py" "$@"
