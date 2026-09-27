"""Exercise installation namespaces without touching system services or WORM."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'pki_install', Path(__file__).resolve().parents[1] / 'packaging/debian/install.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class NamespaceTests(unittest.TestCase):
    def test_reinstall_retains_archives_and_avoids_timestamp_collision(self):
        with tempfile.TemporaryDirectory() as temporary:
            mount = Path(temporary)
            old = mount / '1790467200' / 'pki'
            old.mkdir(parents=True)
            archive = old / 'retained.pem'
            archive.write_text('retained certificate')

            def mkdir(args, **kwargs):
                try:
                    Path(args[-1]).mkdir()
                    return subprocess.CompletedProcess(args, 0, '', '')
                except FileExistsError:
                    return subprocess.CompletedProcess(args, 1, '', 'File exists')

            with patch.object(installer, 'WORM_MOUNT', mount), \
                 patch.object(installer.time, 'time', side_effect=[1790467200, 1790467201]), \
                 patch.object(installer.time, 'sleep'), \
                 patch.object(installer.subprocess, 'run', side_effect=mkdir):
                fresh = installer.allocate_worm_path()
                self.assertEqual(fresh, mount / '1790467201' / 'pki')
                self.assertEqual(archive.read_text(), 'retained certificate')
                config = mount / 'abpkid.env'
                config.write_text(f'ABPKI_INSTALLED_AT=1790467201\nABPKI_WORM={fresh}\n')
                self.assertEqual(installer.stored_worm_path(config, True), fresh)
                self.assertEqual(installer.stored_worm_path(config, False), fresh)
                config.unlink()  # Purge removes configuration, not retained archives.
                self.assertIsNone(installer.stored_worm_path(config, False))
                with self.assertRaises(ValueError):
                    installer.stored_worm_path(config, True)
                self.assertTrue(archive.exists())

    def test_mismatched_namespace_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            mount = Path(temporary)
            config = mount / 'abpkid.env'
            config.write_text(f'ABPKI_INSTALLED_AT=1790467200\nABPKI_WORM={mount}/1790467201/pki\n')
            with patch.object(installer, 'WORM_MOUNT', mount):
                with self.assertRaises(ValueError):
                    installer.stored_worm_path(config, True)

    def test_reservation_permission_failure_is_reported(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(installer, 'WORM_MOUNT', Path(temporary)), \
                 patch.object(installer.subprocess, 'run', return_value=
                              subprocess.CompletedProcess([], 1, '', 'Permission denied')):
                with self.assertRaisesRegex(ValueError, 'Permission denied'):
                    installer.allocate_worm_path()


if __name__ == '__main__':
    unittest.main()
