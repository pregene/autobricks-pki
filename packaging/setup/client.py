"""Client provisioning and one-time Root CA enrollment."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import pwd
import socket
import ssl
import subprocess
import tempfile

CONFIG = Path('/etc/autobricks-pki-client')
TRUST = Path('/usr/local/share/ca-certificates/autobricks-pki-client.crt')
ACCOUNT = 'autobricks-pki-cli'


def run(*args, **kwargs):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)


def write_config(path, data, mode=0o600):
    if path.is_symlink():
        raise ValueError(f'symlink configuration path: {path}')
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as output:
            os.fchmod(output.fileno(), mode)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def handshake(host, port, context):
    with socket.create_connection((host, port), timeout=10) as connection:
        with context.wrap_socket(connection, server_hostname=host):
            pass


def retrieve(host, port):
    # Only first-use Root retrieval bypasses existing trust. All subsequent TLS verifies.
    connection = http.client.HTTPSConnection(host, port, timeout=10,
                                            context=ssl._create_unverified_context())
    try:
        connection.request('GET', '/root')
        response = connection.getresponse()
        data = response.read(1024 * 1024 + 1)
        if response.status != 200 or len(data) > 1024 * 1024:
            raise ValueError('Root CA download failed')
        return data
    finally:
        connection.close()


def provision(host, port, https_port, report, root=None):
    report(0)
    previous = json.loads((CONFIG / 'client.json').read_text()) if (CONFIG / 'client.json').exists() else None
    if previous and previous['server'] != host:
        raise ValueError('existing client server identity cannot be replaced by reinstallation')
    report(1)
    ownership = json.loads((CONFIG / 'ownership.json').read_text()) if previous else None
    if TRUST.exists():
        if previous is None or TRUST.is_symlink():
            raise ValueError('existing Root trust entry is not owned by this client installation')
        pem = TRUST.read_bytes()
        if hashlib.sha256(pem).hexdigest() != ownership['trust_sha256']:
            raise ValueError('enrolled Root trust entry was modified outside this installation')
        if root is not None and pem != root:
            raise ValueError('initialized Root does not match enrolled client trust')
    else:
        pem = root if root is not None else retrieve(host, https_port)
        if ownership and hashlib.sha256(pem).hexdigest() != ownership['trust_sha256']:
            raise ValueError('recovered Root does not match the previously enrolled Root')
    with tempfile.TemporaryDirectory() as temporary:
        certificate = Path(temporary) / 'root.crt'
        certificate.write_bytes(pem)
        text = run('openssl', 'x509', '-in', str(certificate), '-noout', '-text').stdout
        if b'CA:TRUE' not in text:
            raise ValueError('downloaded certificate is not a CA certificate')
        run('openssl', 'verify', '-CAfile', str(certificate), str(certificate))
        context = ssl.create_default_context(cafile=str(certificate))
        handshake(host, port, context)
        handshake(host, https_port, context)
    report(2)
    if CONFIG.is_symlink():
        raise ValueError('symlink client configuration directory')
    CONFIG.mkdir(mode=0o755, parents=True, exist_ok=True)
    marker = CONFIG / 'account-owned'
    try:
        pwd.getpwnam(ACCOUNT)
        if not marker.is_file():
            raise ValueError('client service account is not owned by this package')
    except KeyError:
        run('adduser', '--system', '--group', '--no-create-home', '--home', '/nonexistent', '--shell', '/usr/sbin/nologin', ACCOUNT)
        write_config(marker, ACCOUNT + '\n')
    user = pwd.getpwnam(ACCOUNT)
    installer_uid = None
    caller = os.environ.get('SUDO_USER')
    if caller and caller != 'root':
        installer_uid = pwd.getpwnam(caller).pw_uid
        run('usermod', '-aG', ACCOUNT, caller)
    elif previous:
        installer_uid = json.loads((CONFIG / 'ownership.json').read_text()).get('installer_uid')
    report(3)
    trust_hash = hashlib.sha256(pem).hexdigest()
    # Record ownership before writing trust so interrupted enrollment can be recovered.
    settings = {'server': host, 'port': port, 'https_port': https_port,
                'unix_socket': '/run/autobricks-pki-client/client.sock',
                'ca': '/etc/ssl/certs/ca-certificates.crt'}
    write_config(CONFIG / 'client.json', json.dumps(settings, indent=2) + '\n', 0o640)
    os.chown(CONFIG / 'client.json', 0, user.pw_gid)
    write_config(CONFIG / 'ownership.json', json.dumps({'trust_sha256': trust_hash, 'installer_uid': installer_uid}))
    TRUST.parent.mkdir(parents=True, exist_ok=True)
    write_config(TRUST, pem.decode('ascii'), 0o644)
    run('update-ca-certificates')
    handshake(host, port, ssl.create_default_context())
    report(4)
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', 'abpki-cli.service')
    run('systemctl', 'restart', 'abpki-cli.service')
    run('systemctl', 'is-active', '--quiet', 'abpki-cli.service')
    run('runuser', '-u', ACCOUNT, '--', '/usr/bin/abpki-cli', 'list-ca')
