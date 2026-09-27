#!/usr/bin/env bash
# Check installed CLI/service operations without issuing or revoking certificates.
set -euo pipefail
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
exec python3 - "$project_root" "$@" <<'PY'
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

project = Path(sys.argv.pop(1))
if len(sys.argv) > 2:
    sys.exit('Usage: tests/post-test.sh [EXPECTED_VERSION]')
expected_version = sys.argv[1] if len(sys.argv) == 2 else None
cli = '/usr/bin/abpki-cli'
counts = {'PASS': 0, 'FAIL': 0, 'SKIP': 0}
number = 0


def report(purpose, result, detail=''):
    global number
    number += 1
    counts[result] += 1
    print(f'[{number:03d}] {purpose} ... {result}', flush=True)
    if detail:
        print(f'      {detail}', flush=True)


def test(purpose, action):
    try:
        value = action()
        report(purpose, 'PASS')
        return value
    except Exception as error:
        report(purpose, 'FAIL', str(error))
        return None


def require(condition, message):
    if not condition:
        raise ValueError(message)


def run(args, cwd=None, success=True):
    env = os.environ.copy()
    env.pop('ABPKI_SOCKET', None)
    result = subprocess.run(args, cwd=cwd, env=env, text=True,
                            capture_output=True, timeout=30)
    if success:
        require(result.returncode == 0, result.stderr.strip() or
                f'Command failed with exit code {result.returncode}')
    return result


def version():
    server = Path('/usr/bin/abpkid')
    if server.is_file():
        print('Installed server: ' + run([str(server), '--version']).stdout.strip(), flush=True)
    else:
        print('Installed server: abpkid not installed on this machine', flush=True)
    text = run([cli, '--version']).stdout.strip()
    match = re.fullmatch(r'abpki-cli (1\.0\.\d{3,})', text)
    require(match is not None, f'Unexpected version: {text}')
    if expected_version:
        require(match[1] == expected_version,
                f'Expected {expected_version}, installed {match[1]}')
    print(f'Installed CLI: {text}', flush=True)


def help_output(command=None):
    args = [cli] + ([command] if command else []) + ['--help']
    text = run(args).stdout
    require('Usage:' in text and 'abpki-cli' in text, 'Missing usage help')


def listing(command):
    text = run([cli, command]).stdout
    lines = text.strip().splitlines()
    require(bool(lines) and lines[0].split() ==
            ['Index', 'Common', 'Name', 'Status', 'IssuedAt', 'remain', 'Fingerprint'],
            'Unexpected list columns')
    rows = []
    for line in lines[1:]:
        fields = line.split()
        require(len(fields) == 7, 'Unexpected certificate row')
        idx, cn, state, date, time, remain, fingerprint = fields
        require(idx.isdigit() and remain.isdigit() and
                state in ('VALID', 'REVOKED', 'SUPERSEDED') and
                re.fullmatch(r'[0-9a-f]{64}', fingerprint) is not None,
                'Invalid certificate metadata')
        rows.append((cn, state, fingerprint))
    return rows


def status(fingerprint, expected):
    value = json.loads(run([cli, 'check', fingerprint]).stdout)
    require(value.get('status') == expected, f'Unexpected status: {value}')


def info(fingerprint):
    text = run([cli, 'info', fingerprint]).stdout
    for marker in (f'SHA256 Fingerprint: {fingerprint}', 'Certificate:',
                   'Serial Number:', 'Issuer:', 'Validity', 'Subject:'):
        require(marker in text, f'Missing X.509 field: {marker}')
    require('-----BEGIN' not in text, 'Unexpected PEM body in certificate info')


def absent_info(fingerprint):
    result = run([cli, 'info', fingerprint], success=False)
    require(result.returncode != 0 and
            ('404' in result.stderr or 'not found' in result.stderr.lower()),
            'Missing certificate did not return a not-found error')


def root(directory):
    run([cli, 'root'], cwd=directory)
    path = Path(directory) / 'root.crt'
    text = path.read_text()
    require(text.count('-----BEGIN CERTIFICATE-----') == 1 and
            'PRIVATE KEY' not in text, 'Unexpected Root download contents')
    run(['openssl', 'verify', '-CAfile', str(path), str(path)])
    return path


def chain(directory, identifier, fingerprint, root_path):
    with tempfile.TemporaryDirectory(dir=directory) as child:
        run([cli, 'chain', identifier], cwd=child)
        text = (Path(child) / 'trust-chain').read_text()
        blocks = re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
                            text, re.S)
        require(len(blocks) == 2 and 'PRIVATE KEY' not in text,
                'Trust chain must contain two public certificates')
        issuer = Path(child) / 'issuer.pem'
        issuer.write_text(blocks[0] + '\n')
        actual = run(['openssl', 'x509', '-in', str(issuer), '-noout',
                      '-fingerprint', '-sha256']).stdout.split('=', 1)[1]
        require(actual.strip().replace(':', '').lower() == fingerprint,
                'Trust-chain issuer fingerprint mismatch')
        require(blocks[1] == root_path.read_text().strip(), 'Root mismatch')
        run(['openssl', 'verify', '-CAfile', str(root_path), str(issuer)])


test('Installed CLI version', version)
test('CLI command help', help_output)
test('Certificate info help', lambda: help_output('info'))
cas = test('Intermediate CA metadata list', lambda: listing('list-ca'))
leaves = test('Leaf certificate metadata list', lambda: listing('list'))
rows = (cas or []) + (leaves or [])
for cn, state, fingerprint in rows:
    test(f'Certificate status: {cn}',
         lambda fp=fingerprint, st=state: status(fp, 'REVOKED' if st == 'REVOKED' else 'GOOD'))
    test(f'X.509 information: {cn}', lambda fp=fingerprint: info(fp))
if not rows:
    report('Existing certificate checks', 'SKIP', 'No certificate rows available')
if cas is not None and leaves is not None:
    known = {row[2] for row in rows}
    missing = next(f'{n:064x}' for n in range(len(known) + 1) if f'{n:064x}' not in known)
    test('Unknown certificate status', lambda: status(missing, 'UNKNOWN'))
    test('Unknown certificate info rejection', lambda: absent_info(missing))
else:
    report('Unknown certificate checks', 'SKIP', 'Certificate list unavailable')
with tempfile.TemporaryDirectory(prefix='abpki-post-test-') as directory:
    root_path = test('Root PEM download and signature', lambda: root(directory))
    if root_path is not None and cas:
        for cn, _, fingerprint in cas:
            test(f'Trust chain by fingerprint: {cn}',
                 lambda fp=fingerprint: chain(directory, fp, fp, root_path))
        # CN selects the latest generation, so skip ambiguous renewed CA names.
        for cn, _, fingerprint in cas:
            if sum(row[0] == cn for row in cas) == 1:
                test(f'Trust chain by Common Name: {cn}',
                     lambda name=cn, fp=fingerprint: chain(directory, name, fp, root_path))
            else:
                report(f'Trust chain by Common Name: {cn}', 'SKIP', 'Multiple CA generations')
    else:
        report('Trust-chain downloads', 'SKIP', 'Root or Intermediate CA unavailable')
if rows:
    cn, state, fingerprint = rows[-1]
    def concurrent_status():
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(status, fingerprint, 'REVOKED' if state == 'REVOKED' else 'GOOD') for _ in range(8)]
            for future in futures:
                future.result()
    def concurrent_info():
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(info, fingerprint) for _ in range(8)]
            for future in futures:
                future.result()
    test('Installed concurrent status requests (8 callers)', concurrent_status)
    test('Installed concurrent X.509 requests (8 callers)', concurrent_info)
else:
    report('Installed concurrent requests', 'SKIP', 'No certificate available')

sys.path.insert(0, str(project / 'tests/post_test'))
sys.dont_write_bytecode = True
from regressions import execute
execute(project, test, run, require)
print(f"Summary: {counts['PASS']} PASS, {counts['FAIL']} FAIL, {counts['SKIP']} SKIP")
sys.exit(1 if counts['FAIL'] else 0)
PY
