"""Launch the GUI, wait for it to render, screenshot, then close.

Used for visual regression checks. Saves to %TEMP%\\top-antywir-shot.png
and exits. Safe to run multiple times.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path


def main() -> int:
    # Run the GUI in this process — easier to screenshot the right window.
    from top_antywir.gui import TopAntywirApp

    app = TopAntywirApp()

    def shoot_and_exit() -> None:
        out_path = Path(tempfile.gettempdir()) / "top-antywir-shot.png"
        try:
            # Force the window to the top so it isn't occluded by whatever
            # else the user happens to have open. Then take the shot.
            app.deiconify()
            app.lift()
            app.attributes("-topmost", True)
            app.focus_force()
            app.update_idletasks()
            app.update()

            import ctypes
            from ctypes import wintypes
            user32 = ctypes.windll.user32

            hwnd = user32.FindWindowW(None, "Top Antywir")
            from PIL import ImageGrab
            if hwnd:
                rect = wintypes.RECT()
                user32.GetWindowRect(hwnd, ctypes.byref(rect))
                bbox = (rect.left, rect.top, rect.right, rect.bottom)
                img = ImageGrab.grab(bbox=bbox)
            else:
                img = ImageGrab.grab()
            img.save(out_path)
            app.attributes("-topmost", False)
            print(f"Saved: {out_path}")
        except Exception as exc:
            print(f"Screenshot failed: {exc}", file=sys.stderr)
        finally:
            app.after(50, app.destroy)

    # Wait for the window to be fully rendered and topmost before shooting.
    app.after(700, shoot_and_exit)
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
