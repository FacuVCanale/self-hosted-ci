#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 0 ]]; then
  printf 'usage: %s\n' "$0" >&2
  exit 2
fi

readonly collector="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/collect-wsl-jit-semantic-observations.py"
exec /usr/bin/python3 "${collector}"
