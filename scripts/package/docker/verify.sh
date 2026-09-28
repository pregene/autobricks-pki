#!/usr/bin/env bash
set -euo pipefail
version=$(<VERSION)
arch=${ABPKI_DEB_ARCH:-$(dpkg --print-architecture)}
for name in autobricks-pki autobricks-pki-cli; do
    files=(build/"$name-$version-ubuntu-"*"-$arch.deb")
    [[ ${#files[@]} == 1 && -f ${files[0]} ]]
    package=${files[0]}
    [[ $(dpkg-deb -f "$package" Package) == "$name" ]]
    [[ $(dpkg-deb -f "$package" Version) == "$version" ]]
    [[ $(dpkg-deb -f "$package" Architecture) == "$arch" ]]
    stage=$(mktemp -d)
    trap 'rm -rf -- "$stage"' EXIT
    dpkg-deb -x "$package" "$stage"
    for binary in "$stage"/usr/bin/*; do
        cmp "$binary" "bin/$(basename "$binary")"
        if [[ $arch == arm64 ]]; then
            readelf -h "$binary" | grep -q 'Machine:.*AArch64'
            readelf -l "$binary" | grep -q '/lib/ld-linux-aarch64.so.1'
            while read -r library; do
                [[ -f /usr/lib/aarch64-linux-gnu/$library || -f /lib/aarch64-linux-gnu/$library ]]
            done < <(readelf -d "$binary" | sed -n 's/.*Shared library: \[\(.*\)\].*/\1/p')
        else
            readelf -h "$binary" | grep -q 'Machine:.*X86-64'
            [[ $("$binary" --version) == "$(basename "$binary") $version" ]]
            "$binary" --help >/dev/null
            if ldd "$binary" | grep -q 'not found'; then
                echo "Missing shared library: $binary" >&2
                exit 1
            fi
        fi
    done
    [[ -f "$stage/usr/bin/abpki-cli" ]]
    if [[ $name == autobricks-pki ]]; then
        [[ -f "$stage/usr/bin/abpkid" ]]
    else
        [[ ! -e "$stage/usr/bin/abpkid" ]]
    fi
    printf 'Verified %s\n' "$package"
    rm -rf -- "$stage"
    trap - EXIT
done
