#!/bin/bash
set -euo pipefail
[[ $(uname -s) == Darwin ]] || { echo 'This package requires macOS.' >&2; exit 1; }
[[ $EUID == 0 ]] || { echo 'Run sudo ./install.sh' >&2; exit 1; }
package_dir=$(cd -- "$(dirname -- "$0")" && pwd)
expected_arch=$(cat "$package_dir/ARCH")
[[ $(uname -m) == "$expected_arch" ]] || { echo "This package requires $expected_arch." >&2; exit 1; }
[[ $# == 0 || $# == 3 ]] || { echo 'Usage: sudo ./install.sh [SERVER TLS_PORT HTTPS_PORT]' >&2; exit 2; }
if [[ $# == 3 ]]; then
    server=$1; tls_port=$2; https_port=$3
else
    read -r -p 'PKI server hostname: ' server </dev/tty
    read -r -p 'TLS port [5545]: ' tls_port </dev/tty
    read -r -p 'HTTPS port [5546]: ' https_port </dev/tty
    tls_port=${tls_port:-5545}; https_port=${https_port:-5546}
fi
[[ $server =~ ^[A-Za-z0-9][A-Za-z0-9.:-]*$ ]] || { echo 'Enter a DNS hostname or IP address.' >&2; exit 2; }
for port in "$tls_port" "$https_port"; do
    [[ $port =~ ^[0-9]{1,5}$ ]] && (( 10#$port > 0 && 10#$port <= 65535 )) || { echo 'Invalid port.' >&2; exit 2; }
done
[[ $tls_port != "$https_port" ]] || { echo 'TLS and HTTPS ports must differ.' >&2; exit 2; }
config_dir='/Library/Application Support/Autobricks PKI'
plist='/Library/LaunchDaemons/com.autobricks.pki.client.plist'
root_file="$config_dir/root.crt"
# Reject unowned files before any installation changes.
if [[ -e "$config_dir" || -L "$config_dir" ]]; then
    [[ ! -L "$config_dir" && -d "$config_dir" && $(stat -f %u "$config_dir") == 0 && -f "$config_dir/package-owned" ]] || { echo 'Configuration directory is not owned by this package.' >&2; exit 1; }
fi
for path in "$root_file" "$config_dir/client.json" "$plist" /usr/local/bin/abpki-cli /var/run/autobricks-pki-client; do
    [[ ! -L "$path" ]] || { echo "Refusing symlink: $path" >&2; exit 1; }
done
if [[ -e /usr/local/bin/abpki-cli && ! -f "$config_dir/package-owned" ]]; then
    echo 'Existing abpki-cli is not owned by this package.' >&2; exit 1
fi
authority=$server
[[ $server != *:* ]] || authority="[$server]"
work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT
# First-use bootstrap is separate from normal verified TLS.
/usr/bin/curl --fail --silent --show-error --insecure --connect-timeout 5 --max-time 30 \
    --max-filesize 1048576 "https://$authority:$https_port/root" -o "$work_dir/root.crt"
/usr/bin/openssl x509 -in "$work_dir/root.crt" -noout -text | /usr/bin/grep -q 'CA:TRUE'
/usr/bin/openssl verify -CAfile "$work_dir/root.crt" "$work_dir/root.crt"
if [[ -f "$root_file" ]]; then
    cmp "$root_file" "$work_dir/root.crt" || { echo 'Previously enrolled Root CA differs.' >&2; exit 1; }
else
    /usr/bin/openssl x509 -in "$work_dir/root.crt" -noout -subject -fingerprint -sha256
    echo 'Confirm this Root CA fingerprint through your trusted distribution channel.'
    read -r -p 'Trust this Root CA? [yes/no]: ' answer </dev/tty
    [[ $answer == yes ]] || exit 1
    /usr/bin/security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$work_dir/root.crt"
fi
# Use the package binary before publishing settings or replacing the installed binary.
"$package_dir/abpki-cli" configure "$server" "$tls_port" "$https_port" > "$work_dir/client.json"
/usr/bin/plutil -lint "$package_dir/com.autobricks.pki.client.plist"
/bin/launchctl bootout system/com.autobricks.pki.client 2>/dev/null || true
/usr/bin/install -d -o root -g wheel -m 0755 "$config_dir" /usr/local/bin
/usr/bin/install -o root -g wheel -m 0644 "$work_dir/root.crt" "$root_file"
/usr/bin/install -o root -g wheel -m 0600 "$work_dir/client.json" "$config_dir/client.json"
/usr/bin/install -o root -g wheel -m 0600 "$package_dir/VERSION" "$config_dir/package-owned"
/usr/bin/install -o root -g wheel -m 0755 "$package_dir/abpki-cli" /usr/local/bin/abpki-cli
/usr/bin/install -o root -g wheel -m 0644 "$package_dir/com.autobricks.pki.client.plist" "$plist"
/usr/bin/install -d -o root -g staff -m 0750 /var/run/autobricks-pki-client
/usr/bin/touch /var/log/autobricks-pki-client.log
/usr/sbin/chown root:wheel /var/log/autobricks-pki-client.log
/bin/chmod 0600 /var/log/autobricks-pki-client.log
/bin/launchctl bootstrap system "$plist"
for attempt in {1..30}; do
    if [[ -S /var/run/autobricks-pki-client/client.sock ]]; then break; fi
    /bin/sleep 1
done
/usr/local/bin/abpki-cli list-ca
echo "Autobricks PKI Server $(cat "$package_dir/VERSION") client installation completed."
echo 'CLI access uses the staff group. Run abpki-cli --help.'
