"""Generate the Top Antywir application icon.

Produces:
  top_antywir/assets/icon.png   — 256x256 RGBA PNG (used on Linux + as tk iconphoto fallback)
  top_antywir/assets/icon.ico   — multi-size ICO (16/32/48/64/128/256) for Windows taskbar

Re-run this script whenever the design changes. The generated files are
committed to the repo so end users don't need Pillow at runtime.
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw


# Colours match top_antywir/gui.py palette
BG_TRANSPARENT = (0, 0, 0, 0)
SHIELD_FILL    = (88, 166, 255, 255)   # ACCENT  #58a6ff
SHIELD_EDGE    = (31, 111, 235, 255)   # darker rim
CHECK_COLOR    = (255, 255, 255, 255)


def _shield_polygon(size: int) -> list[tuple[float, float]]:
    """Return polygon points for a classic shield outline scaled to `size`."""
    s = size
    return [
        (s * 0.50, s * 0.06),   # top centre
        (s * 0.90, s * 0.20),   # top right shoulder
        (s * 0.90, s * 0.55),   # right side
        (s * 0.72, s * 0.86),   # bottom right curve start
        (s * 0.50, s * 0.96),   # bottom point
        (s * 0.28, s * 0.86),   # bottom left curve start
        (s * 0.10, s * 0.55),   # left side
        (s * 0.10, s * 0.20),   # top left shoulder
    ]


def _draw_icon(size: int) -> Image.Image:
    img = Image.new("RGBA", (size, size), BG_TRANSPARENT)
    draw = ImageDraw.Draw(img)

    # Shield body
    poly = _shield_polygon(size)
    draw.polygon(poly, fill=SHIELD_FILL, outline=SHIELD_EDGE,
                 width=max(1, size // 64))

    # Check mark — three-point polyline
    s = size
    check_width = max(2, size // 14)
    draw.line(
        [
            (s * 0.30, s * 0.52),
            (s * 0.45, s * 0.68),
            (s * 0.72, s * 0.36),
        ],
        fill=CHECK_COLOR,
        width=check_width,
        joint="curve",
    )

    return img


def main() -> None:
    repo = Path(__file__).resolve().parent.parent
    assets = repo / "top_antywir" / "assets"
    assets.mkdir(parents=True, exist_ok=True)

    # Master PNG (high-res for Linux hicolor 256x256)
    master = _draw_icon(256)
    master.save(assets / "icon.png", format="PNG", optimize=True)

    # Multi-size ICO for Windows
    sizes = [16, 32, 48, 64, 128, 256]
    layers = [_draw_icon(s) for s in sizes]
    layers[-1].save(
        assets / "icon.ico",
        format="ICO",
        sizes=[(s, s) for s in sizes],
        append_images=layers[:-1],
    )

    print(f"Wrote {assets / 'icon.png'}")
    print(f"Wrote {assets / 'icon.ico'}")


if __name__ == "__main__":
    main()
