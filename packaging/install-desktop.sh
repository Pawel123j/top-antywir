#!/usr/bin/env bash
# Install Top Antywir desktop integration on Linux (user-local, no sudo).
#
# Copies:
#   packaging/top-antywir.desktop          -> ~/.local/share/applications/
#   top_antywir/assets/icon.png            -> ~/.local/share/icons/hicolor/256x256/apps/top-antywir.png
#
# After running this, "Top Antywir" should appear in your application menu.
# Requires that `top-antywir-gui` is already installed and on PATH (e.g.
# `pip install -e .` from the project root).

set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
desktop_src="$repo/packaging/top-antywir.desktop"
icon_src="$repo/top_antywir/assets/icon.png"

apps_dir="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
icons_dir="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/256x256/apps"

if [[ ! -f "$desktop_src" ]]; then
    echo "Error: $desktop_src not found." >&2
    exit 1
fi
if [[ ! -f "$icon_src" ]]; then
    echo "Error: $icon_src not found. Run 'python scripts/make_icon.py' first." >&2
    exit 1
fi

mkdir -p "$apps_dir" "$icons_dir"
cp "$desktop_src" "$apps_dir/top-antywir.desktop"
cp "$icon_src"    "$icons_dir/top-antywir.png"

if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$apps_dir" || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -q -t "${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor" || true
fi

echo "Installed:"
echo "  $apps_dir/top-antywir.desktop"
echo "  $icons_dir/top-antywir.png"
echo
echo "If 'top-antywir-gui' isn't on PATH yet, run from the project root:"
echo "  pip install -e ."
