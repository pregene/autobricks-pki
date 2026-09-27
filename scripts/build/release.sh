#!/usr/bin/env bash
set -euo pipefail

if [[ -z ${AUTOBRICKS_PKI_VERSION:-} ]]; then
    echo "Use ./scripts/build/run.sh ./scripts/build/release.sh" >&2
    exit 2
fi

if [[ ${ABPKI_DISTRIBUTION_OPENSSL:-} != 1 ]]; then
    exec ./scripts/build/distribution.sh "$0" "$@"
fi

cargo build --release --locked --target-dir target
install -d bin build
install -m 0755 target/release/abpkid bin/abpkid
install -m 0755 target/release/abpki-cli bin/abpki-cli
