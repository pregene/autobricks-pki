#!/usr/bin/env bash
set -euo pipefail
# /usr/include is a compiler default path and -I does not prioritize it over
# /usr/local/include. Stage one coherent distro OpenSSL header tree instead.
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd -- "$project_root"
install -d build
openssl_headers=$(mktemp -d "$PWD/build/openssl-headers.XXXXXX")
trap 'rm -rf -- "$openssl_headers"' EXIT
multiarch=$(dpkg-architecture -qDEB_HOST_MULTIARCH)
cp -R /usr/include/openssl "$openssl_headers/openssl"
if [[ -d /usr/include/$multiarch/openssl ]]; then
    cp -R "/usr/include/$multiarch/openssl/." "$openssl_headers/openssl/"
fi
export OPENSSL_DIR=/usr
export OPENSSL_LIB_DIR="/usr/lib/$multiarch"
export OPENSSL_INCLUDE_DIR="$openssl_headers"
export OPENSSL_STATIC=0
export ABPKI_DISTRIBUTION_OPENSSL=1
"$@"
