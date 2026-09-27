#!/usr/bin/python3
"""Run the package-specific installation screens and provisioning backend."""
import curses
import importlib.util
import json
import os
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import client
from screens import Preview


def load_server():
    spec = importlib.util.spec_from_file_location('server_install', HERE / 'server.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def server_install(values, report):
    names = {'Base domain': 'ABPKI_INSTALL_DOMAIN', 'DNS registration IP': 'ABPKI_INSTALL_IP',
             'Bind address': 'ABPKI_INSTALL_BIND', 'Management TLS port': 'ABPKI_INSTALL_TLS',
             'Public HTTPS port': 'ABPKI_INSTALL_HTTPS'}
    for field, name in names.items():
        os.environ[name] = values[field]
    server = load_server()
    settings = server.main(report)
    environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', **settings}
    root = server.run('runuser', '-u', server.ACCOUNT, '--', '/usr/bin/abpkid', 'root', env=environment).stdout
    client.provision(values['DNS registration IP'], int(values['Management TLS port']),
                     int(values['Public HTTPS port']), lambda step: report(4 if step < 4 else 5), root)
    return settings['ABPKI_ADMIN_PASSWORD']


def client_install(values, report):
    client.provision(values['Server address'], int(values['Management TLS port']),
                     int(values['Public HTTPS port']), report)
    return None


def initial_values(mode):
    if mode == 'client':
        path = client.CONFIG / 'client.json'
        if not path.exists():
            return None
        values = json.loads(path.read_text())
        return {'Server address': values['server'], 'Management TLS port': str(values['port']),
                'Public HTTPS port': str(values['https_port'])}
    server = load_server()
    if not (server.CONFIG / 'abpkid.env').exists() or not (server.STATE / 'install.json').exists():
        return None
    settings = server.environment_file(server.CONFIG / 'abpkid.env')
    metadata = json.loads((server.STATE / 'install.json').read_text())
    return {'Base domain': metadata['base_domain'], 'DNS registration IP': metadata['registration_ip'],
            'Bind address': settings['ABPKI_BIND'], 'Management TLS port': settings['ABPKI_TLS_PORT'],
            'Public HTTPS port': settings['ABPKI_HTTPS_PORT']}


def main():
    if os.geteuid() != 0:
        raise SystemExit('Package configuration requires root privileges.')
    if len(sys.argv) != 2 or sys.argv[1] not in ('server', 'client'):
        raise SystemExit('Specify the package type: server or client.')
    mode = sys.argv[1]
    version = (HERE / 'VERSION').read_text().strip()
    initial = initial_values(mode)
    # apt/dpkg may redirect standard input; the installer UI uses the controlling terminal.
    try:
        tty = os.open('/dev/tty', os.O_RDWR)
    except OSError:
        raise SystemExit('An interactive terminal is required. Run dpkg --configure from a terminal.')
    saved = [os.dup(fd) for fd in (0, 1, 2)]
    try:
        for fd in (0, 1, 2):
            os.dup2(tty, fd)
        os.close(tty)
        def screen(stdscr):
            ui = Preview(stdscr, version, mode, server_install if mode == 'server' else client_install, initial)
            ui.run()
            return ui.completed, ui.failure
        success, failure = curses.wrapper(screen)
    finally:
        for fd, duplicate in enumerate(saved):
            os.dup2(duplicate, fd)
            os.close(duplicate)
    if not success:
        raise SystemExit(f'Package configuration failed: {failure}' if failure else 'Package configuration was cancelled.')


if __name__ == '__main__':
    main()
