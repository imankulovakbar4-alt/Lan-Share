"""Tests for LAN Share user-data paths and legacy migration."""

import tempfile
import unittest
from pathlib import Path

from storage.paths import get_storage_paths, prepare_storage


class StoragePathTests(unittest.TestCase):
    def test_windows_uses_roaming_appdata(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            roaming = Path(temp) / "roaming"
            paths = get_storage_paths(home=home, appdata=roaming, windows=True)

            self.assertEqual(paths.root, roaming / "LAN Share")
            self.assertEqual(paths.config, paths.root / "settings.json")
            self.assertEqual(paths.history, paths.root / "history.json")
            self.assertEqual(paths.certificates, paths.root / "tls")

    def test_non_windows_uses_hidden_user_folder(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            paths = get_storage_paths(home=home, windows=False)

            self.assertEqual(paths.root, home / ".lan_share")

    def test_migrates_legacy_settings_history_and_certificates(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            roaming = Path(temp) / "roaming"
            home.mkdir()

            old_config = home / ".lan_share.json"
            old_history = home / ".lan_share_history.json"
            old_tls = home / ".lan_share_tls"
            old_config.write_text('{"theme":"dark"}', encoding="utf-8")
            old_history.write_text("[]", encoding="utf-8")
            old_tls.mkdir()
            (old_tls / "cert.pem").write_text("certificate", encoding="utf-8")

            paths = get_storage_paths(home=home, appdata=roaming, windows=True)
            prepare_storage(paths)

            self.assertEqual(paths.config.read_text(encoding="utf-8"), '{"theme":"dark"}')
            self.assertEqual(paths.history.read_text(encoding="utf-8"), "[]")
            self.assertEqual(
                (paths.certificates / "cert.pem").read_text(encoding="utf-8"),
                "certificate",
            )
            self.assertFalse(old_config.exists())
            self.assertFalse(old_history.exists())
            self.assertFalse(old_tls.exists())

    def test_does_not_overwrite_existing_new_settings(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            roaming = Path(temp) / "roaming"
            home.mkdir()
            (home / ".lan_share.json").write_text("legacy", encoding="utf-8")

            paths = get_storage_paths(home=home, appdata=roaming, windows=True)
            paths.root.mkdir(parents=True)
            paths.config.write_text("current", encoding="utf-8")
            prepare_storage(paths)

            self.assertEqual(paths.config.read_text(encoding="utf-8"), "current")
            self.assertTrue((home / ".lan_share.json").exists())


if __name__ == "__main__":
    unittest.main()
