"""Scan-target presets for quick and full-system scans.

Cross-platform helpers that return the set of roots a scan should walk.
Combined with ``Scanner``'s exclusion lists they let the GUI offer
"Szybkie skanowanie" (common malware locations) and "Pełne skanowanie"
(all fixed drives / root filesystem) without scanning useless pseudo-FS
or huge OS-managed directories.
"""
from __future__ import annotations

import os
from pathlib import Path

from .paths import is_macos, is_windows

# Directory names to skip when walking. Compared case-insensitively
# against each path segment.
EXCLUDED_DIR_NAMES: frozenset[str] = frozenset({
    # Source-control / build noise
    ".git", ".hg", ".svn", "node_modules", "__pycache__",
    ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache",
    # Linux / *nix pseudo-filesystems (only skipped at root-level walks
    # because top-level "/proc" etc. are not children of every directory)
    "proc", "sys", "dev", "run",
    # Windows system noise that's huge and not useful to scan
    "system volume information", "$recycle.bin",
    "winsxs", "servicing", "windowsapps",
    # macOS noise (Time Machine snapshots, Spotlight index, system caches)
    ".spotlight-v100", ".trashes", ".fseventsd", ".documentrevisions-v100",
    ".mobilebackups", ".temporaryitems", ".vol",
})

# Exact file names to skip (case-insensitive).
EXCLUDED_FILE_NAMES: frozenset[str] = frozenset({
    # Windows
    "pagefile.sys", "hiberfil.sys", "swapfile.sys",
    "dumpstack.log", "dumpstack.log.tmp",
    "ntuser.dat", "ntuser.dat.log1", "ntuser.dat.log2",
    # macOS / Linux noise
    ".ds_store", ".localized", "thumbs.db",
})


def quick_scan_targets() -> list[Path]:
    """Common locations where malware tends to land.

    Returns existing, de-duplicated absolute paths. Empty list means the
    environment is too unusual to suggest a default — caller should fall
    back to ``full_scan_targets``.
    """
    home = Path.home()
    candidates: list[Path] = []

    if is_windows():
        for env_var in ("TEMP", "TMP"):
            value = os.environ.get(env_var)
            if value:
                candidates.append(Path(value))
        candidates += [
            home / "Downloads",
            home / "Desktop",
            home / "Documents",
            home / "AppData" / "Local" / "Temp",
            home / "AppData" / "Roaming"
                 / "Microsoft" / "Windows"
                 / "Start Menu" / "Programs" / "Startup",
        ]
        public = os.environ.get("PUBLIC")
        if public:
            candidates.append(Path(public) / "Downloads")

    elif is_macos():
        candidates += [
            home / "Downloads",
            home / "Desktop",
            home / "Documents",
            home / "Library" / "Caches",
            home / "Library" / "LaunchAgents",
            home / ".Trash",
            Path("/tmp"),
            Path("/private/tmp"),
            Path("/var/tmp"),
            Path("/Library/LaunchAgents"),
            Path("/Library/LaunchDaemons"),
        ]

    else:  # Linux / *BSD
        candidates += [
            home / "Downloads",
            home / "Desktop",
            home / "Documents",
            home / ".cache",
            home / ".local" / "share" / "Trash",
            home / ".config" / "autostart",
            Path("/tmp"),
            Path("/var/tmp"),
            Path("/dev/shm"),
        ]

    return _dedupe_existing(candidates)


def full_scan_targets() -> list[Path]:
    """Top-level roots covering the entire computer.

    - Windows: every fixed drive (C:, D:, …) excluding USB/CD/network.
    - macOS:   ``/`` plus every mounted volume under ``/Volumes`` (skipping
               the symlink that points to the boot disk).
    - Linux:   ``/`` — pseudo-filesystems are pruned by the scanner.
    """
    if is_windows():
        return _windows_fixed_drives()
    if is_macos():
        return _macos_roots()
    return [Path("/")]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _dedupe_existing(paths: list[Path]) -> list[Path]:
    seen: set[Path] = set()
    out: list[Path] = []
    for p in paths:
        try:
            resolved = p.expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if resolved in seen or not resolved.exists():
            continue
        seen.add(resolved)
        out.append(resolved)
    return out


def _windows_fixed_drives() -> list[Path]:
    """Enumerate fixed (DRIVE_FIXED) drives on Windows.

    Falls back to ``[C:\\]`` if the Win32 API isn't available.
    """
    try:
        import ctypes
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        get_drive_type = ctypes.windll.kernel32.GetDriveTypeW
        DRIVE_FIXED = 3
        drives: list[Path] = []
        for i in range(26):
            if bitmask & (1 << i):
                root = f"{chr(ord('A') + i)}:\\"
                try:
                    if get_drive_type(root) == DRIVE_FIXED:
                        drives.append(Path(root))
                except OSError:
                    pass
        return drives or [Path("C:\\")]
    except (OSError, AttributeError):
        return [Path("C:\\")]


def _macos_roots() -> list[Path]:
    """Root filesystem + every external/mounted volume under ``/Volumes``."""
    roots: list[Path] = [Path("/")]
    volumes = Path("/Volumes")
    if volumes.exists():
        try:
            for entry in volumes.iterdir():
                # Skip symlinks (the boot volume appears here as a symlink
                # back to "/", which would double-scan it).
                if entry.is_symlink() or not entry.is_dir():
                    continue
                roots.append(entry)
        except OSError:
            pass
    return roots
