#!/usr/bin/env bash
set -euo pipefail

case $(uname -s) in Linux|Darwin) ;; *) echo "Unsupported build host." >&2; exit 1 ;; esac
keep_version=0
if [[ ${1:-} == --keep-version ]]; then
    keep_version=1
    shift
fi
if (( $# == 0 )); then
    echo "Usage: scripts/build/run.sh [--keep-version] COMMAND [ARG ...]" >&2
    exit 2
fi
command -v python3 >/dev/null
if [[ $(uname -s) == Linux ]]; then command -v flock >/dev/null; fi
command -v "$1" >/dev/null

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd -- "$project_root"
exec 9>.version.lock
if [[ $(uname -s) == Linux ]]; then
    flock -x 9
else
    # macOS has no flock command; hold the same advisory lock around this runner.
    if [[ ${ABPKI_BUILD_LOCKED:-} != 1 ]]; then
        exec python3 - "$0" "$keep_version" "$@" <<'LOCK'
import fcntl
import os
import subprocess
import sys
with open(".version.lock", "a") as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    env = dict(os.environ, ABPKI_BUILD_LOCKED="1")
    args = [sys.argv[1]]
    if sys.argv[2] == "1":
        args.append("--keep-version")
    sys.exit(subprocess.call(args + sys.argv[3:], env=env))
LOCK
    fi
fi

if (( keep_version == 0 )); then
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
fi

export AUTOBRICKS_PKI_VERSION
AUTOBRICKS_PKI_VERSION=$(<VERSION)
printf 'Building Autobricks PKI Server %s\n' "$AUTOBRICKS_PKI_VERSION"
"$@"
