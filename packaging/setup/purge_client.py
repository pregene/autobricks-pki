"""Remove package-owned client state and trust without changing WORM."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

config = Path('/etc/autobricks-pki-client')
trust = Path('/usr/local/share/ca-certificates/autobricks-pki-client.crt')
if config.is_symlink():
    raise SystemExit('Refusing client purge through a symlink configuration directory')
for line in Path('/proc/self/mountinfo').read_text().splitlines():
    mount = Path(line.split()[4].replace('\\040', ' '))
    if mount == config or config in mount.parents:
        raise SystemExit('Refusing client purge through a mounted configuration path')
owner_path = config / 'ownership.json'
if owner_path.exists() and trust.exists():
    ownership = json.loads(owner_path.read_text())
    if trust.is_symlink() or hashlib.sha256(trust.read_bytes()).hexdigest() != ownership['trust_sha256']:
        raise SystemExit('Client Root trust entry changed outside this package; resolve before purge')
    trust.unlink()
    subprocess.run(['update-ca-certificates'], check=True)
if (config / 'account-owned').is_file():
    subprocess.run(['deluser', '--system', 'autobricks-pki-cli'], check=False)
    subprocess.run(['delgroup', '--only-if-empty', 'autobricks-pki-cli'], check=False)
if config.exists():
    shutil.rmtree(config)
