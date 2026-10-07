#!/usr/bin/env bash
set -euo pipefail
[[ -n ${AUTOBRICKS_PKI_VERSION:-} ]] || { echo 'Use scripts/build/run.sh --keep-version scripts/package/macos.sh' >&2; exit 2; }
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd -- "$project_root"
if [[ $(uname -s) == Darwin ]]; then
    builder=(cargo build)
else
    command -v cargo-zigbuild >/dev/null
    command -v zig >/dev/null
    [[ -d ${SDKROOT:-} ]] || { echo 'Set SDKROOT to an extracted macOS SDK.' >&2; exit 2; }
    export ABPKI_MACOS_ZIG
    ABPKI_MACOS_ZIG=$(command -v zig)
    export CARGO_ZIGBUILD_ZIG_PATH="$project_root/scripts/build/macos-zig.sh"
    builder=(cargo zigbuild)
fi
export MACOSX_DEPLOYMENT_TARGET=11.0
export RUSTFLAGS="${RUSTFLAGS:-} -C metadata=abpki_macos_11"
staging=$(mktemp -d "$project_root/build/macos-package.XXXXXX")
trap 'rm -rf -- "$staging"; rm -f -- "$project_root/.intentionally-empty-file.o"' EXIT
for architecture in arm64 x86_64; do
    target=aarch64-apple-darwin
    [[ $architecture != x86_64 ]] || target=x86_64-apple-darwin
    "${builder[@]}" --release --locked --no-default-features --bin abpki-cli --target "$target" --target-dir target
    package="autobricks-pki-cli-${AUTOBRICKS_PKI_VERSION}-macos-${architecture}"
    mkdir -p "$staging/$package"
    install -m 0755 "target/$target/release/abpki-cli" "$staging/$package/abpki-cli"
    install -m 0755 packaging/macos/install.sh packaging/macos/uninstall.sh "$staging/$package/"
    install -m 0644 packaging/macos/com.autobricks.pki.client.plist VERSION LICENSE "$staging/$package/"
    install -m 0644 docs/macos-client.md "$staging/$package/README.md"
    cp -R licenses "$staging/$package/licenses"
    printf '%s\n' "$architecture" > "$staging/$package/ARCH"
    tar -czf "$staging/$package.tar.gz" -C "$staging" "$package"
done
python3 scripts/package/verify_macos.py "$staging"
for architecture in arm64 x86_64; do
    package="autobricks-pki-cli-${AUTOBRICKS_PKI_VERSION}-macos-${architecture}.tar.gz"
    mv "$staging/$package" "build/$package"
done
python3 - <<'PY'
import hashlib
from pathlib import Path
version = Path('VERSION').read_text().strip()
paths = [Path('build') / f'autobricks-pki-cli-{version}-macos-{arch}.tar.gz' for arch in ('arm64', 'x86_64')]
Path('build/macos-SHA256SUMS').write_text(''.join(f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n' for path in paths))
PY
