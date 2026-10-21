"""Launch the GUI, wait for it to render, screenshot, then close.

Used for visual regression checks. Saves to %TEMP%\\top-antywir-shot.png
and exits. Safe to run multiple times.
"""
from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path,
        default=Path(tempfile.gettempdir()) / "top-antywir-shot.png",
    )
    args = parser.parse_args()
    # Run the GUI in this process — easier to screenshot the right window.
    from top_antywir.gui import TopAntywirApp

    app = TopAntywirApp()
    success = False

    def shoot_and_exit() -> None:
        nonlocal success
        out_path = args.output
        try:
            # Force the window to the top so it isn't occluded by whatever
            # else the user happens to have open. Then take the shot.
            app.deiconify()
            app.lift()
            app.attributes("-topmost", True)
            app.focus_force()
            app.update_idletasks()
            app.update()

            from PIL import ImageGrab
            x, y = app.winfo_rootx(), app.winfo_rooty()
            bbox = (x, y, x + app.winfo_width(), y + app.winfo_height())
            if sys.platform == "win32":
                import ctypes
                from ctypes import wintypes
                user32 = ctypes.windll.user32
                hwnd = user32.FindWindowW(None, "Top Antywir")
                if hwnd:
                    rect = wintypes.RECT()
                    user32.GetWindowRect(hwnd, ctypes.byref(rect))
                    bbox = (rect.left, rect.top, rect.right, rect.bottom)
            img = ImageGrab.grab(bbox=bbox)
            img.save(out_path)
            success = True
            app.attributes("-topmost", False)
            print(f"Saved: {out_path}")
        except Exception as exc:
            print(f"Screenshot failed: {exc}", file=sys.stderr)
        finally:
            app.after(50, app.destroy)

    # Wait for the window to be fully rendered and topmost before shooting.
    app.after(700, shoot_and_exit)
    app.mainloop()
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
