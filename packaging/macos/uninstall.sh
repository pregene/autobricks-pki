#!/bin/bash
set -euo pipefail
[[ $(uname -s) == Darwin && $EUID == 0 ]] || { echo 'Run sudo ./uninstall.sh on macOS.' >&2; exit 1; }
config_dir='/Library/Application Support/Autobricks PKI'
[[ -d "$config_dir" && ! -L "$config_dir" && -f "$config_dir/package-owned" && $(stat -f %u "$config_dir") == 0 ]] || { echo 'No package-owned installation found.' >&2; exit 1; }
/bin/launchctl bootout system/com.autobricks.pki.client 2>/dev/null || true
/usr/bin/security remove-trusted-cert -d "$config_dir/root.crt"
# Remove only package files; user certificate tokens and downloads remain.
/bin/rm -f /Library/LaunchDaemons/com.autobricks.pki.client.plist /usr/local/bin/abpki-cli \
    /var/run/autobricks-pki-client/client.sock "$config_dir/client.json" "$config_dir/root.crt" "$config_dir/package-owned"
/bin/rmdir /var/run/autobricks-pki-client "$config_dir"
echo 'Autobricks PKI client removed. User credentials and logs were retained.'
