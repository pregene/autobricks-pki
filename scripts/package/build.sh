#!/usr/bin/env bash
set -euo pipefail
[[ ${1:-} == --existing-binaries || -n ${AUTOBRICKS_PKI_VERSION:-} ]] || { echo 'Use scripts/build/run.sh scripts/package/build.sh' >&2; exit 2; }
if [[ ${1:-} == --existing-binaries && $# == 1 ]]; then
    AUTOBRICKS_PKI_VERSION=$(<VERSION)
    export AUTOBRICKS_PKI_VERSION
    for binary in abpkid abpki-cli; do
        [[ $("bin/$binary" --version) == "$binary $AUTOBRICKS_PKI_VERSION" ]] || {
            echo "Binary version does not match VERSION: $binary" >&2
            exit 2
        }
    done
elif (( $# == 0 )); then
    scripts/build/release.sh
else
    echo 'Usage: scripts/package/build.sh [--existing-binaries]' >&2
    exit 2
fi
read -r package_os package_os_version < <(python3 - <<'PLATFORM'
import shlex
from pathlib import Path
values = {}
for line in Path('/etc/os-release').read_text().splitlines():
    if '=' in line and not line.startswith('#'):
        key, value = line.split('=', 1)
        values[key] = shlex.split(value)[0] if value else ''
print(values['ID'], values['VERSION_ID'])
PLATFORM
)
[[ $package_os =~ ^[a-z0-9]+$ && $package_os_version =~ ^[A-Za-z0-9.-]+$ ]] || exit 2
package_arch=$(dpkg --print-architecture)
staging=$(mktemp -d "$PWD/build/package.XXXXXX")
trap 'rm -rf -- "$staging"' EXIT
for kind in server client; do
    package_name=autobricks-pki
    other_package=autobricks-pki-cli
    if [[ $kind == client ]]; then package_name=autobricks-pki-cli; other_package=autobricks-pki; fi
    stage="$staging/$kind"
    install -d "$stage/DEBIAN" "$stage/usr/bin" "$stage/usr/libexec" "$stage/lib/systemd/system" "$stage/usr/share/doc/autobricks-pki" "$stage/usr/lib/autobricks-pki/setup"
    install -m 0755 bin/abpki-cli "$stage/usr/bin/"
    install -m 0644 packaging/debian/abpki-cli.service "$stage/lib/systemd/system/"
    install -m 0755 packaging/setup/access.py "$stage/usr/libexec/abpki-client-access"
    install -m 0644 packaging/setup/main.py packaging/setup/client.py "$stage/usr/lib/autobricks-pki/setup/"
    install -m 0644 scripts/installer/preview.py "$stage/usr/lib/autobricks-pki/setup/screens.py"
    install -m 0644 VERSION "$stage/usr/lib/autobricks-pki/setup/VERSION"
    install -m 0644 LICENSE "$stage/usr/share/doc/autobricks-pki/copyright"
    install -m 0644 README.md PACKAGE.md FILES.md INSTALL.md LEAF-CREATE.md "$stage/usr/share/doc/autobricks-pki/"
    cp -R licenses "$stage/usr/share/doc/autobricks-pki/"
    extra_dependencies=''
    binary_args=(-eusr/bin/abpki-cli)
    if [[ $kind == server ]]; then
        install -m 0755 bin/abpkid "$stage/usr/bin/"
        install -m 0644 packaging/debian/install.py "$stage/usr/lib/autobricks-pki/setup/server.py"
        install -m 0644 packaging/debian/abpkid.service "$stage/lib/systemd/system/"
        install -m 0755 packaging/debian/postinst packaging/debian/prerm "$stage/DEBIAN/"
        extra_dependencies=', autobricks-dns, autobricks-truelog, autobricks-truelog-cli'
        binary_args+=(-eusr/bin/abpkid)
    else
        install -m 0755 packaging/debian/client-postinst "$stage/DEBIAN/postinst"
        install -m 0755 packaging/debian/client-prerm "$stage/DEBIAN/prerm"
    fi
    cat > "$stage/DEBIAN/postrm" <<'POSTRM'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then systemctl daemon-reload; fi
[ "${1:-}" = purge ] || exit 0
POSTRM
    printf "\npython3 - <<'PKI_PURGE'\n" >> "$stage/DEBIAN/postrm"
    # Perform server DNS conflict checks before deleting any client state.
    if [[ $kind == server ]]; then cat packaging/debian/purge.py >> "$stage/DEBIAN/postrm"; fi
    cat packaging/setup/purge_client.py >> "$stage/DEBIAN/postrm"
    printf '\nPKI_PURGE\n' >> "$stage/DEBIAN/postrm"
    chmod 0755 "$stage/DEBIAN/postrm"
    install -d "$stage/debian"
    printf 'Source: %s\nSection: admin\nPriority: optional\nMaintainer: Autobricks, Co. <development@autobricks.invalid>\n\nPackage: %s\nArchitecture: any\nDescription: Autobricks PKI\n' "$package_name" "$package_name" > "$stage/debian/control"
    libraries=$(cd "$stage" && dpkg-shlibdeps -O "${binary_args[@]}")
    libraries=${libraries#shlibs:Depends=}
    rm -rf "$stage/debian"
    cat > "$stage/DEBIAN/control" <<CONTROL
Package: $package_name
Version: $AUTOBRICKS_PKI_VERSION
Architecture: $package_arch
Section: admin
Priority: optional
Maintainer: Autobricks, Co. <development@autobricks.invalid>
Depends: $libraries, python3, ca-certificates, openssl, adduser, systemd, util-linux, coreutils, acl$extra_dependencies
Conflicts: $other_package
Description: Autobricks PKI Server 1.0 - $kind package
 Certificate management with interactive terminal configuration.
CONTROL
    dpkg-deb --root-owner-group --build "$stage" "$staging/$package_name.deb"
done
# Publish only after both package builds succeed.
for package_name in autobricks-pki autobricks-pki-cli; do
    mv "$staging/$package_name.deb" "build/${package_name}-${AUTOBRICKS_PKI_VERSION}-${package_os}-${package_os_version}-${package_arch}.deb"
done
