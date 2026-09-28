#!/usr/bin/env bash
set -euo pipefail

if [[ -z ${AUTOBRICKS_PKI_VERSION:-} ]]; then
    echo "Use ./scripts/build/run.sh ./scripts/build/release.sh" >&2
    exit 2
fi

if [[ ${ABPKI_DISTRIBUTION_OPENSSL:-} != 1 ]]; then
    exec ./scripts/build/distribution.sh "$0" "$@"
fi

target_args=()
artifact_dir=target/release
if [[ -n ${ABPKI_RUST_TARGET:-} ]]; then
    target_args=(--target "$ABPKI_RUST_TARGET")
    artifact_dir="target/$ABPKI_RUST_TARGET/release"
fi
cargo build --release --locked --target-dir target "${target_args[@]}"
install -d bin build
install -m 0755 "$artifact_dir/abpkid" bin/abpkid
install -m 0755 "$artifact_dir/abpki-cli" bin/abpki-cli
