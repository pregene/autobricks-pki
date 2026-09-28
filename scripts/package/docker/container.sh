#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends ca-certificates curl build-essential pkg-config libssl-dev python3 dpkg-dev util-linux xz-utils
if [[ $ABPKI_DEB_ARCH == arm64 ]]; then
    dpkg --add-architecture arm64
    python3 - <<'PY'
from pathlib import Path
p = Path('/etc/apt/sources.list')
if p.exists():
    p.write_text(p.read_text().replace('deb http', 'deb [arch=amd64] http'))
for p in Path('/etc/apt/sources.list.d').glob('*.sources'):
    p.write_text(p.read_text().replace('Types: deb', 'Architectures: amd64\nTypes: deb'))
PY
    . /etc/os-release
    printf 'deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports %s main universe\n' "$VERSION_CODENAME" "$VERSION_CODENAME-updates" "$VERSION_CODENAME-security" > /etc/apt/sources.list.d/arm64.list
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends gcc-aarch64-linux-gnu libc6-dev-arm64-cross libssl-dev:arm64
fi
curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs -o /tmp/rustup.sh
sh /tmp/rustup.sh -y --profile minimal --default-toolchain 1.98.1
export PATH=/root/.cargo/bin:$PATH
mkdir /work
cp /source/Cargo.toml /source/Cargo.lock /source/VERSION /source/LICENSE /work/
for doc in /source/*.md; do
    [[ $(basename "$doc") == AGENTS.md ]] || cp "$doc" /work/
done
cp -R /source/src /source/scripts /source/packaging /source/licenses /work/
cd /work
if [[ $ABPKI_DEB_ARCH == arm64 ]]; then
    export ABPKI_RUST_TARGET=aarch64-unknown-linux-gnu
    rustup target add "$ABPKI_RUST_TARGET"
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
    export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
    export AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar
    mkdir -p /tmp/abpki-openssl/openssl
    cp -R /usr/include/openssl/. /tmp/abpki-openssl/openssl/
    cp -R /usr/include/aarch64-linux-gnu/openssl/. /tmp/abpki-openssl/openssl/
    export OPENSSL_LIB_DIR=/usr/lib/aarch64-linux-gnu
    export OPENSSL_INCLUDE_DIR=/tmp/abpki-openssl OPENSSL_STATIC=0 ABPKI_DISTRIBUTION_OPENSSL=1
fi
scripts/package/build.sh
scripts/package/docker/verify.sh
cp build/*.deb /output/
chown "$ABPKI_HOST_UID:$ABPKI_HOST_GID" /output/*.deb
