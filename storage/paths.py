"""Centralized paths for user-owned LAN Share data.

No directories are created at import time. Call prepare_storage() during
application startup so packaged and source runs use the same writable paths.
"""

from dataclasses import dataclass
import os
from pathlib import Path
import shutil


@dataclass(frozen=True)
class StoragePaths:
    root: Path
    config: Path
    history: Path
    certificates: Path
    legacy_home: Path


def get_storage_paths(*, home=None, appdata=None, windows=None):
    """Return platform-aware paths; arguments make the function easy to test."""
    home_path = Path(home) if home is not None else Path.home()
    is_windows = os.name == "nt" if windows is None else bool(windows)

    if is_windows:
        roaming = Path(appdata) if appdata else home_path / "AppData" / "Roaming"
        root = roaming / "LAN Share"
    else:
        root = home_path / ".lan_share"

    return StoragePaths(
        root=root,
        config=root / "settings.json",
        history=root / "history.json",
        certificates=root / "tls",
        legacy_home=home_path,
    )


def _move_legacy(source, destination):
    """Move legacy user data once, without overwriting newer destination data."""
    if not source.exists() or destination.exists():
        return False

    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.move(str(source), str(destination))
    except OSError:
        # Keep the old data in place if migration cannot be completed.
        return False
    return True


def prepare_storage(paths=None):
    """Create writable data folders and migrate files from the old locations."""
    paths = paths or get_storage_paths()
    paths.root.mkdir(parents=True, exist_ok=True)

    _move_legacy(paths.legacy_home / ".lan_share.json", paths.config)
    _move_legacy(paths.legacy_home / ".lan_share_history.json", paths.history)
    _move_legacy(paths.legacy_home / ".lan_share_tls", paths.certificates)

    paths.certificates.mkdir(parents=True, exist_ok=True)
    return paths


_DEFAULT_PATHS = get_storage_paths()
CONFIG_PATH = os.fspath(_DEFAULT_PATHS.config)
HISTORY_PATH = os.fspath(_DEFAULT_PATHS.history)
CERT_DIR = os.fspath(_DEFAULT_PATHS.certificates)
