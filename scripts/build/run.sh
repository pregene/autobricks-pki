#!/usr/bin/env bash
set -euo pipefail

if [[ $(uname -s) != Linux ]]; then
    echo "Only Linux is supported." >&2
    exit 1
fi
if (( $# == 0 )); then
    echo "Usage: scripts/build/run.sh COMMAND [ARG ...]" >&2
    exit 2
fi
command -v python3 >/dev/null
command -v flock >/dev/null
command -v "$1" >/dev/null

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd -- "$project_root"
exec 9>.version.lock
flock -x 9

python3 - <<'PYTHON'
from pathlib import Path
import re

path = Path('VERSION')
current = path.read_text().strip()
match = re.fullmatch(r'1\.0\.([0-9]{3,})', current)
if not match:
    raise SystemExit('VERSION must use the format 1.0.NNN.')
updated = f"1.0.{int(match.group(1)) + 1:03d}\n"
path.write_text(updated)
PYTHON

export AUTOBRICKS_PKI_VERSION
AUTOBRICKS_PKI_VERSION=$(<VERSION)
printf 'Building Autobricks PKI Server %s\n' "$AUTOBRICKS_PKI_VERSION"
"$@"
