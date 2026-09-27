#!/usr/bin/env python3
"""One-time local storage repair; never invoked by the service or installer."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import sqlite3
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def env_file(path):
    return dict(line.split('=', 1) for line in path.read_text().splitlines()
                if line.strip() and not line.startswith('#'))


def archive_paths(row, timestamp):
    cn = ''.join(chr(b) if chr(b).isascii() and (chr(b).isalnum() or b in b'.-_')
                 else f'%{b:02X}' for b in row['cn'].encode())
    if row['kind'] == 'root':
        base = f'root/{cn}'
    else:
        date = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).strftime('%Y-%m-%d')
        category = 'intermediate' if row['kind'] == 'intermediate' else 'certificate'
        base = f"{category}/{date}/{row['fingerprint']}/{cn}"
    return base + '.pem', base + '.key.pem'


# Runs under the existing service identity, respecting the mounted WORM policy.
WRITER = r'''
import json, os, pathlib, sys
request = json.load(sys.stdin)
root = pathlib.Path(request['root']).resolve(strict=True)
for name, text in request['files']:
    relative = pathlib.PurePosixPath(name)
    if relative.is_absolute() or any(p in ('', '.', '..') for p in name.split('/')):
        raise ValueError('unsafe archive path')
    path = root
    for part in relative.parts[:-1]:
        path /= part
        if path.is_symlink():
            raise ValueError('archive symlink')
        path.mkdir(mode=0o700, exist_ok=True)
    path /= relative.name
    if path.is_symlink():
        raise ValueError('archive symlink')
    data = text.encode()
    if path.exists():
        existing = path.read_bytes()
        if not data.startswith(existing):
            raise ValueError('existing WORM artifact differs: ' + name)
        if len(existing) == len(data):
            continue
        flags = os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW
        remaining = data[len(existing):]
    else:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        remaining = data
    with os.fdopen(os.open(path, flags, 0o600), 'ab') as output:
        output.write(remaining)
        output.flush()
        os.fsync(output.fileno())
    if path.read_bytes() != data:
        raise ValueError('WORM verification failed: ' + name)
'''


def export_database(source, target, worm, writer):
    source.row_factory = sqlite3.Row
    rows = list(source.execute('SELECT * FROM certificates ORDER BY idx'))
    archive_times = {}
    for event in source.execute("SELECT payload FROM outbox WHERE kind='certificate' ORDER BY id"):
        try:
            payload = json.loads(event[0])
            archive_times[payload['fingerprint']] = int(payload['created_at'])
        except (ValueError, TypeError, KeyError):
            pass
    password = source.execute("SELECT value FROM settings WHERE name='private_key_password'").fetchone()[0]
    if isinstance(password, bytes):
        password = password.decode()
    key_environment = dict(os.environ, ABPKI_REPAIR_KEY_PASSWORD=password)
    mapped = []
    for row in rows:
        if 'pem' not in row.keys():
            mapped.append((row, row['certificate_path'], row['private_key_path']))
            continue
        pem = row['pem']
        der = subprocess.check_output(['openssl', 'x509', '-outform', 'DER'], input=pem.encode())
        if hashlib.sha256(der).hexdigest() != row['fingerprint']:
            raise ValueError('certificate fingerprint mismatch')
        if not row['key_pem'].startswith('-----BEGIN ENCRYPTED PRIVATE KEY-----'):
            raise ValueError('expected encrypted private key')
        public = subprocess.check_output(['openssl', 'x509', '-pubkey', '-noout'], input=pem.encode())
        key_public = subprocess.check_output(['openssl', 'pkey', '-pubout', '-passin', 'env:ABPKI_REPAIR_KEY_PASSWORD'], input=row['key_pem'].encode(), env=key_environment)
        if public != key_public:
            raise ValueError('certificate and key mismatch')
        cert_path, key_path = archive_paths(row, archive_times.get(row['fingerprint'], row['not_before']))
        writer(worm, [(cert_path, pem), (key_path, row['key_pem'])])
        mapped.append((row, cert_path, key_path))
    target.executescript((ROOT / 'src/storage/schema.sql').read_text())
    for table in ('settings', 'outbox'):
        for row in source.execute(f'SELECT * FROM {table}'):
            names = ','.join(row.keys())
            placeholders = ','.join('?' for _ in row)
            target.execute(f'INSERT INTO {table} ({names}) VALUES ({placeholders})', tuple(row))
    for row, cert_path, key_path in mapped:
        item = {key: row[key] for key in row.keys() if key not in ('pem', 'key_pem')}
        item.update(certificate_path=cert_path, private_key_path=key_path,
                    valid=row['valid'] if 'valid' in row.keys() else ('REVOKED' if row['revoked_at'] is not None else 'VALID'))
        target.execute('INSERT INTO certificates (' + ','.join(item) + ') VALUES (' +
                       ','.join('?' for _ in item) + ')', tuple(item.values()))
    for row in source.execute('SELECT * FROM crls'):
        item = dict(row)
        if 'pem' in item:
            pem = item.pop('pem')
            pem = pem.encode() if isinstance(pem, str) else pem
            subprocess.run(['openssl', 'crl', '-noout'], input=pem, check=True, capture_output=True)
            fingerprint = source.execute('SELECT fingerprint FROM certificates WHERE idx=?', (item['issuer'],)).fetchone()[0]
            path = f"crl/{fingerprint}/{item['number']}-{hashlib.sha256(pem).hexdigest()}.pem"
            writer(worm, [(path, pem.decode())])
            item['crl_path'] = path
        target.execute('INSERT INTO crls (' + ','.join(item) + ') VALUES (' + ','.join('?' for _ in item) + ')', tuple(item.values()))
    target.execute("INSERT INTO intermediate_leaf(intermediate_idx,leaf_idx) SELECT ca.idx,leaf.idx FROM certificates ca JOIN certificates leaf ON leaf.issuer=ca.fingerprint WHERE ca.kind='intermediate' AND leaf.kind IN ('server','client','server-and-client')")
    target.execute("UPDATE outbox SET done=1 WHERE kind='certificate'")
    for name, sequence in source.execute('SELECT name,seq FROM sqlite_sequence'):
        target.execute('UPDATE sqlite_sequence SET seq=MAX(seq,?) WHERE name=?', (sequence, name))
    target.execute('PRAGMA user_version=1')
    target.commit()
    if target.execute('PRAGMA integrity_check').fetchone()[0] != 'ok' or target.execute('PRAGMA foreign_key_check').fetchall():
        raise ValueError('rebuilt database failed integrity checks')
    return len(rows)


def main():
    if os.geteuid() != 0:
        raise SystemExit('Run this one-time repair with sudo.')
    os.umask(0o077)
    settings = env_file(Path('/etc/autobricks-pki/abpkid.env'))
    database = Path(settings['ABPKI_DATABASE'])
    worm = Path(settings['ABPKI_WORM'])
    account = pwd.getpwnam('autobricks-pki')
    for binary in ('abpkid', 'abpki-cli'):
        run(str(ROOT / 'bin' / binary), '--version')
    backup = Path(tempfile.mkdtemp(prefix='abpki-storage-', dir='/var/backups'))
    for binary in ('abpkid', 'abpki-cli'):
        shutil.copy2('/usr/bin/' + binary, backup / binary)
    shutil.copy2('/etc/autobricks-pki/abpkid.env', backup / 'abpkid.env')
    run('systemctl', 'stop', 'abpki-cli.service', 'abpkid.service')
    replaced = False
    candidate = None
    try:
        with sqlite3.connect(database) as old, sqlite3.connect(backup / 'abpki.sqlite') as saved:
            old.backup(saved)
        columns = {row[1] for row in old.execute('PRAGMA table_info(certificates)')}
        crl_columns = {row[1] for row in old.execute('PRAGMA table_info(crls)')}
        if 'pem' in columns or 'pem' in crl_columns:
            fd, name = tempfile.mkstemp(prefix='.abpki-repair-', dir=database.parent)
            os.close(fd)
            candidate = Path(name)
            def writer(root, files):
                run('runuser', '-u', 'autobricks-pki', '--', '/usr/bin/python3', '-c', WRITER,
                    input=json.dumps({'root': str(root), 'files': files}), text=True)
            with sqlite3.connect(candidate) as new:
                count = export_database(old, new, worm, writer)
            print(f'Preserved {count} certificates; certificate, key, and CRL contents reside on WORM.')
            os.chown(candidate, account.pw_uid, account.pw_gid)
            old.close()
            os.replace(candidate, database)
            replaced = True
        elif not {'certificate_path', 'private_key_path', 'valid'} <= columns:
            raise ValueError('unrecognized database layout')
        for binary in ('abpkid', 'abpki-cli'):
            run('install', '-m', '0755', str(ROOT / 'bin' / binary), '/usr/bin/' + binary)
        run('systemctl', 'start', 'abpkid.service', 'abpki-cli.service')
        import time
        for attempt in range(30):
            result = subprocess.run([str(ROOT / 'bin/abpki-cli'), 'list-ca'], capture_output=True, text=True)
            if result.returncode == 0:
                print(result.stdout, end='')
                break
            time.sleep(1)
        else:
            raise RuntimeError('updated service did not become ready')
        run(str(ROOT / 'bin/abpki-cli'), 'list')
        print('Storage repair complete. Existing certificates, trust, passwords, and settings are preserved.')
        print('Protected rollback backup: ' + str(backup))
    except Exception:
        run('systemctl', 'stop', 'abpki-cli.service', 'abpkid.service')
        if replaced:
            shutil.copy2(backup / 'abpki.sqlite', database)
            os.chown(database, account.pw_uid, account.pw_gid)
        for binary in ('abpkid', 'abpki-cli'):
            run('install', '-m', '0755', str(backup / binary), '/usr/bin/' + binary)
        run('systemctl', 'start', 'abpkid.service', 'abpki-cli.service')
        raise
    finally:
        if candidate is not None:
            candidate.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
