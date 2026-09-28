#!/usr/bin/env bash
set -euo pipefail
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
cd -- "$project_root"
: "${AUTOBRICKS_PKI_VERSION:?Use scripts/build/run.sh scripts/package/docker/build.sh}"
version=$AUTOBRICKS_PKI_VERSION
[[ $(<VERSION) == "$version" ]]
docker info >/dev/null
host_uid=${SUDO_UID:-$(id -u)}
host_gid=${SUDO_GID:-$(id -g)}
stage=$(mktemp -d "$PWD/build/package-matrix.XXXXXX")
container="abpki-package-$$"
cleanup() {
    docker rm -f "$container" >/dev/null 2>&1 || true
    rm -rf -- "$stage"
}
trap cleanup EXIT
for ubuntu in 22.04 24.04; do
    for arch in amd64 arm64; do
        docker run --rm --name "$container" --platform linux/amd64 \
            -e "AUTOBRICKS_PKI_VERSION=$version" -e "ABPKI_DEB_ARCH=$arch" \
            -e "ABPKI_HOST_UID=$host_uid" -e "ABPKI_HOST_GID=$host_gid" \
            -v "$PWD:/source:ro" -v "$stage:/output" \
            "ubuntu:$ubuntu" bash /source/scripts/package/docker/container.sh
    done
done
python3 - "$version" "$stage" <<'PY'
from pathlib import Path
import hashlib
import shutil
import sys
version, stage = sys.argv[1:]
output = Path('build')
expected = {f'{name}-{version}-ubuntu-{ubuntu}-{arch}.deb'
            for name in ('autobricks-pki', 'autobricks-pki-cli')
            for ubuntu in ('22.04', '24.04') for arch in ('amd64', 'arm64')}
files = list(Path(stage).glob('*.deb'))
if len(files) != 8 or {p.name for p in files} != expected:
    raise SystemExit('Incomplete package matrix; expected exactly eight packages')
for path in files:
    shutil.move(path, output / path.name)
checksums = ''.join(f'{hashlib.sha256((output / name).read_bytes()).hexdigest()}  {name}\n'
                    for name in sorted(expected))
(output / f'SHA256SUMS-{version}.txt').write_text(checksums)
print(f'Published eight local packages for {version}')
PY
chown "$host_uid:$host_gid" "build/SHA256SUMS-$version.txt"
