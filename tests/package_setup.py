"""Exercise client enrollment with mocked external services and temporary files."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('client_setup', ROOT / 'packaging/setup/client.py')
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


class ClientSetupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.config = Path(self.temporary.name) / 'config'
        self.trust = Path(self.temporary.name) / 'trust' / 'root.crt'
        self.config.mkdir()
        (self.config / 'account-owned').write_text('autobricks-pki-cli\n')
        self.commands = []
        def run(*args, **kwargs):
            self.commands.append(args)
            return subprocess.CompletedProcess(args, 0, b'CA:TRUE', b'')
        mocks = [patch.object(client, 'CONFIG', self.config), patch.object(client, 'TRUST', self.trust),
                 patch.object(client, 'run', side_effect=run), patch.object(client, 'handshake'),
                 patch.object(client.ssl, 'create_default_context'), patch.object(client.os, 'chown'),
                 patch.object(client.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=1000, pw_gid=1000)),
                 patch.dict(os.environ, {'SUDO_USER': ''})]
        for mock in mocks:
            mock.start()
            self.addCleanup(mock.stop)

    def test_combined_configuration_and_idempotent_reinstallation(self):
        pem = b'test CA'
        client.provision('192.0.2.10', 5545, 5546, lambda step: None, pem)
        config = json.loads((self.config / 'client.json').read_text())
        self.assertEqual((config['server'], config['port'], config['https_port']), ('192.0.2.10', 5545, 5546))
        self.assertEqual(config['ca'], '/etc/ssl/certs/ca-certificates.crt')
        self.assertEqual(self.trust.read_bytes(), pem)
        self.assertEqual((self.config / 'client.json').stat().st_mode & 0o777, 0o640)
        self.assertEqual((self.config / 'ownership.json').stat().st_mode & 0o777, 0o600)
        client.provision('192.0.2.10', 5545, 5546, lambda step: None, pem)
        self.assertIn(('systemctl', 'restart', 'abpki-cli.service'), self.commands)
        self.assertFalse(any('ABPKI_ADMIN_PASSWORD' in arg for cmd in self.commands for arg in cmd))

    def test_untrusted_endpoint_does_not_register_root_or_enable_service(self):
        with patch.object(client, 'handshake', side_effect=ValueError('wrong identity')):
            with self.assertRaisesRegex(ValueError, 'wrong identity'):
                client.provision('192.0.2.10', 5545, 5546, lambda step: None, b'test CA')
        self.assertFalse(self.trust.exists())
        self.assertFalse((self.config / 'client.json').exists())
        self.assertFalse(any(cmd[0] == 'systemctl' for cmd in self.commands))

    def test_reinstallation_rejects_changed_server_or_root(self):
        client.provision('192.0.2.10', 5545, 5546, lambda step: None, b'first CA')
        with self.assertRaisesRegex(ValueError, 'identity'):
            client.provision('192.0.2.11', 5545, 5546, lambda step: None, b'first CA')
        with self.assertRaisesRegex(ValueError, 'does not match'):
            client.provision('192.0.2.10', 5545, 5546, lambda step: None, b'second CA')

    def test_client_only_enrolls_downloaded_root(self):
        with patch.object(client, 'retrieve', return_value=b'remote CA') as retrieve:
            client.provision('pki.example.internal', 5545, 5546, lambda step: None)
        retrieve.assert_called_once_with('pki.example.internal', 5546)
        self.assertEqual(self.trust.read_bytes(), b'remote CA')


if __name__ == '__main__':
    unittest.main()
