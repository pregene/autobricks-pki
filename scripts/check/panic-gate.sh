#!/usr/bin/env bash
set -euo pipefail
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd -- "$project_root"
if [[ ${ABPKI_DISTRIBUTION_OPENSSL:-} != 1 ]]; then
    exec ./scripts/build/distribution.sh "$0" "$@"
fi

cargo fmt --all --check
./scripts/build/run.sh cargo clippy --locked --lib --bins -- \
    -D warnings -D clippy::unwrap_used -D clippy::expect_used \
    -D clippy::panic -D clippy::todo -D clippy::unimplemented -D clippy::unreachable
./scripts/build/run.sh cargo test --locked

PYTHONDONTWRITEBYTECODE=1 python3 tests/package_namespace.py
PYTHONDONTWRITEBYTECODE=1 python3 tests/package_setup.py
