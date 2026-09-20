"""Cross-platform user-data paths for Top Antywir.

Resolves OS-appropriate locations for quarantine storage, audit logs and
any other persistent app state. Centralises platform-detection so the
rest of the code never branches on ``sys.platform``.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

APP_NAME = "top-antywir"


def is_windows() -> bool:
    return sys.platform.startswith("win")


def is_macos() -> bool:
    return sys.platform == "darwin"


def is_linux() -> bool:
    return sys.platform.startswith("linux")


def user_data_dir() -> Path:
    """Root directory for persistent user data.

    - Windows: ``%LOCALAPPDATA%\\top-antywir``
    - macOS:   ``~/Library/Application Support/top-antywir``
    - Linux:   ``$XDG_DATA_HOME/top-antywir`` (or ``~/.local/share/top-antywir``)
    """
    if is_windows():
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / APP_NAME
    if is_macos():
        return Path.home() / "Library" / "Application Support" / APP_NAME
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / APP_NAME


def quarantine_dir() -> Path:
    return user_data_dir() / "quarantine"


def log_dir() -> Path:
    """Audit-log directory.

    Follows OS conventions (XDG_STATE_HOME on Linux, Logs on macOS,
    LocalAppData on Windows).
    """
    if is_windows():
        return user_data_dir() / "logs"
    if is_macos():
        return Path.home() / "Library" / "Logs" / APP_NAME
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / APP_NAME / "logs"
