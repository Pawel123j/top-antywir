"""Small cross-platform helpers used by GUI and CLI."""
from __future__ import annotations

import subprocess
from pathlib import Path

from .paths import is_linux, is_macos, is_windows


def reveal_in_file_manager(path: Path) -> bool:
    """Open the OS file manager focused on ``path``.

    - Windows: ``explorer /select,"<path>"`` highlights the file.
    - macOS:   ``open -R "<path>"`` reveals it in Finder.
    - Linux:   falls back to ``xdg-open`` on the parent directory because
               no portable equivalent of "select this file" exists.

    Returns ``True`` if the launcher was invoked, ``False`` if no
    suitable command was found.
    """
    if not path:
        return False
    try:
        if is_windows():
            # Note: explorer doesn't honour absolute file paths reliably
            # via shell=False with spaces, so pass it as a single arg.
            subprocess.Popen(["explorer", f"/select,{path}"])
            return True
        if is_macos():
            subprocess.Popen(["open", "-R", str(path)])
            return True
        if is_linux():
            target = path if path.is_dir() else path.parent
            subprocess.Popen(["xdg-open", str(target)])
            return True
    except (OSError, FileNotFoundError):
        return False
    return False
