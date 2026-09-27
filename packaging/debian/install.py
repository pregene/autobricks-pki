#!/usr/bin/python3
"""Configure the packaged PKI service from the installation screen values."""
import grp
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import socket
import sqlite3
import subprocess
import sys
import time
import secrets
import string

CONFIG = Path('/etc/autobricks-pki')
STATE = Path('/var/lib/autobricks-pki')
WORM_MOUNT = Path('/mnt/worm-storage')
ACCOUNT = 'autobricks-pki'


def run(*args, **kwargs):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)


def environment_file(path):
    values = {}
    for line in path.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        name, value = line.split('=', 1)
        if name.strip() in values:
            raise ValueError('duplicate TrueLog setting')
        values[name.strip()] = value.strip().strip('"\'')
    return values


def initialized():
    database = STATE / 'abpki.sqlite'
    if not database.exists():
        return False
    with sqlite3.connect(f'file:{database}?mode=ro', uri=True) as connection:
        try:
            return connection.execute("SELECT EXISTS(SELECT 1 FROM certificates WHERE kind='root')").fetchone()[0]
        except sqlite3.OperationalError:
            return False


def stored_worm_path(env_path, existing):
    if not env_path.exists():
        if existing:
            raise ValueError('existing CA requires its installation WORM configuration')
        return None
    settings = environment_file(env_path)
    timestamp = settings.get('ABPKI_INSTALLED_AT', '')
    if not re.fullmatch(r'[1-9][0-9]*', timestamp):
        raise ValueError('missing or invalid installation timestamp')
    path = WORM_MOUNT / timestamp / 'pki'
    if settings.get('ABPKI_WORM') != str(path):
        raise ValueError('WORM path does not match installation timestamp')
    if path.parent.is_symlink() or path.is_symlink():
        raise ValueError('symlink WORM installation path')
    return path


def allocate_worm_path():
    # Reserve a fresh timestamp namespace; retained installations are never reused.
    while True:
        namespace = WORM_MOUNT / str(int(time.time()))
        result = subprocess.run(
            ['runuser', '-u', ACCOUNT, '--', 'mkdir', str(namespace)],
            capture_output=True, text=True)
        if result.returncode == 0:
            return namespace / 'pki'
        if namespace.exists() or namespace.is_symlink():
            time.sleep(0.1)
            continue
        raise ValueError(f'cannot reserve WORM namespace: {result.stderr.strip()}')


def main(report=lambda step: None):
    report(0)
    domain = os.environ['ABPKI_INSTALL_DOMAIN'].strip().lower()
    if not 1 <= len(domain) <= 24 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', label) for label in domain.split('.')):
        raise ValueError('baseDomain must contain at most 24 ASCII DNS characters')
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise ValueError('baseDomain cannot be an IP address')
    ip = ipaddress.ip_address(os.environ['ABPKI_INSTALL_IP'])
    if ip.is_unspecified or ip.is_multicast:
        raise ValueError('registration IP must identify the server')
    bind = ipaddress.ip_address(os.environ['ABPKI_INSTALL_BIND'])
    ports = [int(os.environ[name]) for name in ('ABPKI_INSTALL_TLS', 'ABPKI_INSTALL_HTTPS')]
    if len(set(ports)) != 2 or any(not 1 <= port <= 65535 for port in ports):
        raise ValueError('TLS and HTTPS ports must be distinct and between 1 and 65535')
    truelog = environment_file(Path('/etc/default/autobricks-log'))
    if int(truelog['AB_WORM_RETAIN_DAYS']) < 365:
        raise ValueError('TrueLog retention must be at least 365 days')
    if truelog.get('AB_WORM_MOUNT_PATH') != '/mnt/worm-storage':
        raise ValueError('this package requires the TrueLog mount at /mnt/worm-storage')
    mount = subprocess.check_output(['findmnt', '-n', '-o', 'FSTYPE,SOURCE', '--mountpoint', '/mnt/worm-storage'], text=True).split()
    if len(mount) != 2 or not mount[0].startswith('fuse') or mount[1] != 'ab-worm':
        raise ValueError('TrueLog WORM mount is unavailable')
    writer_group = grp.getgrgid(int(truelog['AUTOBRICKS_LOG_GID'])).gr_name
    groups = ['autobricks-dns', 'autobricks-truelog-cli', writer_group]
    for group in groups:
        grp.getgrnam(group)
    for service in ['autobricks-dns', 'ab-truelog', 'ab-truelog-cli']:
        run('systemctl', 'is-active', '--quiet', service)
    for path in [CONFIG, STATE]:
        if path.is_symlink():
            raise ValueError(f'symlink installation path: {path}')
    existing = initialized()
    env_path = CONFIG / 'abpkid.env'
    worm = stored_worm_path(env_path, existing)
    metadata = STATE / 'install.json'
    saved_settings = environment_file(env_path) if env_path.exists() else {}
    password = saved_settings.get('ABPKI_ADMIN_PASSWORD')
    if password is None:
        if existing:
            raise ValueError('existing server administrator password configuration is missing')
        password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
    if existing:
        saved = json.loads(metadata.read_text())
        if saved['base_domain'] != domain or saved['registration_ip'] != str(ip):
            raise ValueError('existing CA domain and registration IP cannot be changed by reconfiguration')
    else:
        if worm is not None and worm.exists() and any(worm.iterdir()):
            raise ValueError('existing WORM artifacts require recovery; initialization cannot overwrite them')
    report(1)
    run('systemctl', 'stop', 'abpkid.service')
    family = socket.AF_INET6 if bind.version == 6 else socket.AF_INET
    for port in ports:
        with socket.socket(family, socket.SOCK_STREAM) as listener:
            listener.bind((str(bind), port))
    try:
        pwd.getpwnam(ACCOUNT)
        if not (CONFIG / 'account-owned').is_file():
            raise ValueError('existing service account is not managed by this package')
    except KeyError:
        run('adduser', '--system', '--group', '--no-create-home', '--home', '/nonexistent', '--shell', '/usr/sbin/nologin', ACCOUNT)
        CONFIG.mkdir(mode=0o750, parents=True, exist_ok=True)
        (CONFIG / 'account-owned').write_text('autobricks-pki\n')
    user = pwd.getpwnam(ACCOUNT)
    run('usermod', '-aG', ','.join(dict.fromkeys(groups)), ACCOUNT)
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(STATE, user.pw_uid, user.pw_gid)
    os.chmod(STATE, 0o700)
    # WORM controls ownership and permissions; do not chmod/chown its namespace.
    if worm is None:
        worm = allocate_worm_path()
    settings = {
        'ABPKI_DATABASE': str(STATE / 'abpki.sqlite'), 'ABPKI_WORM': str(worm),
        'ABPKI_INSTALLED_AT': worm.parent.name,
        'ABPKI_ADMIN_PASSWORD': password,
        'ABPKI_ORIGIN': f'https://pki.{domain}', 'ABPKI_BIND': str(bind),
        'ABPKI_TLS_PORT': str(ports[0]), 'ABPKI_HTTPS_PORT': str(ports[1]),
        'AUTOBRICKS_DNS_SOCKET': '/run/autobricks-dns/autobricks-dns.sock',
        'ABPKI_TRUELOG_CLI': '/usr/bin/ab-truelog-cli',
        'ABPKI_TRUELOG_CONFIG': '/etc/default/autobricks-log',
    }
    with env_path.open('w') as output:
        os.chmod(env_path, 0o600)
        output.write(''.join(f'{key}={value}\n' for key, value in settings.items()))
    run('runuser', '-u', ACCOUNT, '--', 'mkdir', '-p', str(worm))
    metadata.write_text(json.dumps({'base_domain': domain, 'registration_ip': str(ip)}))
    os.chown(metadata, user.pw_uid, user.pw_gid)
    os.chmod(metadata, 0o600)
    report(2)
    if not existing:
        environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', **settings,
                       'ABPKI_ADMIN_PASSWORD': password}
        run('runuser', '-u', ACCOUNT, '--', '/usr/bin/abpkid', 'init', str(ip), domain, env=environment)
    report(3)
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', '--now', 'abpkid.service')
    run('systemctl', 'is-active', '--quiet', 'abpkid.service')
    return settings


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'PKI installation failed: {error}', file=sys.stderr)
        sys.exit(1)
