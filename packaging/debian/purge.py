"""Remove mutable PKI state while preserving the shared WORM namespace."""
import json
from pathlib import Path
import pwd
import shutil
import sqlite3
import subprocess

config = Path('/etc/autobricks-pki')
state = Path('/var/lib/autobricks-pki')
roots = [config, state, Path('/etc/systemd/system/abpkid.service.d')]
for line in Path('/proc/self/mountinfo').read_text().splitlines():
    mounted = Path(line.split()[4].replace('\\040', ' '))
    if any(mounted == root or root in mounted.parents for root in roots):
        raise SystemExit(f'Refusing purge through a mounted PKI path: {mounted}')

# Delete only unchanged DNS records recorded by this PKI instance.
database = state / 'abpki.sqlite'
if database.exists() and not state.is_symlink() and not database.is_symlink():
    with sqlite3.connect(f'file:{database}?mode=ro', uri=True) as connection:
        exists = connection.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='outbox'").fetchone()[0]
        payloads = connection.execute("SELECT payload FROM outbox WHERE kind='dns'").fetchall() if exists else []
    owned = {}
    for (payload,) in payloads:
        record = json.loads(payload)
        owned.setdefault(record['name'], set()).add((record['type'], record['ip']))
    if owned:
        current = json.loads(subprocess.check_output(['/usr/bin/autobricks-dns', 'list'], timeout=30))
        targets = []
        for name, expected in owned.items():
            actual = {(record['type'], record['ip']) for record in current if record['name'] == name}
            if actual and not actual.issubset(expected):
                raise SystemExit(f'DNS record changed outside PKI; resolve before purge: {name}')
            if actual:
                targets.append(name)
        for name in targets:
            subprocess.run(['/usr/bin/autobricks-dns', 'delete', '--name', name], check=True, timeout=30)
        if targets:
            subprocess.run(['/usr/bin/autobricks-dns', 'restart'], check=True, timeout=30)

marker = config / 'account-owned'
if not config.is_symlink() and marker.is_file() and not marker.is_symlink() and marker.stat().st_uid == 0:
    try:
        pwd.getpwnam('autobricks-pki')
    except KeyError:
        pass
    else:
        subprocess.run(['deluser', '--system', 'autobricks-pki'], check=True)
    subprocess.run(['delgroup', '--only-if-empty', 'autobricks-pki'], check=False)
for path in roots:
    if path.is_symlink():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)
for path in [Path('/etc/systemd/system/abpkid.service'), Path('/etc/systemd/system/multi-user.target.wants/abpkid.service')]:
    if path.exists() or path.is_symlink():
        path.unlink()
if Path('/run/systemd/system').exists():
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'reset-failed', 'abpkid.service'], check=False)
print('PKI configuration, SQLite, keys, passwords and package-owned account removed. WORM and TrueLog archives remain protected.')
