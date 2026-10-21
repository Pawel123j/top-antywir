"""Real Tk widgets and scan worker on isolated harmless files (opt-in display)."""
import hashlib
import os
import time

import pytest


@pytest.mark.skipif(not os.environ.get("DISPLAY"), reason="GUI needs a display/Xvfb")
def test_gui_scan_report_quarantine_restore(tmp_path, monkeypatch):
    pytest.importorskip("customtkinter")
    from top_antywir import gui, paths
    from top_antywir.scanner import Scanner
    from top_antywir.signatures import HashSignature

    # Redirect all persistent app state, including custom signature discovery.
    monkeypatch.setattr(paths, "user_data_dir", lambda: tmp_path / "state")
    monkeypatch.setattr(paths, "log_dir", lambda: tmp_path / "logs")
    sample = tmp_path / "scan" / "fixture.bin"
    sample.parent.mkdir()
    content = b"harmless GUI regression fixture\n"
    sample.write_bytes(content)
    (sample.parent / "clean.txt").write_text("clean")
    signature = HashSignature(name="GUI-Test", sha256=hashlib.sha256(content).hexdigest(),
                              severity="high", description="Harmless test fixture")
    monkeypatch.setattr(gui, "Scanner", lambda: Scanner(hash_signatures=(signature,)))
    errors = []
    monkeypatch.setattr(gui.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))
    monkeypatch.setattr(gui.messagebox, "showinfo", lambda *args, **kwargs: None)
    monkeypatch.setattr(gui.messagebox, "askyesno", lambda *args, **kwargs: True)
    monkeypatch.setattr(gui.webbrowser, "open", lambda *args, **kwargs: False)
    report = tmp_path / "report.html"
    monkeypatch.setattr(gui.filedialog, "asksaveasfilename", lambda **kwargs: str(report))

    app = gui.TopAntywirApp()
    app.report_callback_exception = lambda *args: errors.append(args)
    try:
        app.update()
        app.path_entry.insert(0, str(sample.parent))
        app.scan_button.invoke()
        deadline = time.monotonic() + 10
        while not app._last_stats and time.monotonic() < deadline:
            app.update()
            time.sleep(0.02)
        assert app._last_stats.get("count") == 2
        assert app._last_stats.get("infected") == 1
        assert len(app.results) == 1
        app.export_btn.invoke()
        assert "GUI-Test" in report.read_text()
        app.quarantine_btn.invoke()
        assert not sample.exists()
        app.show_quarantine()
        app.update()
        app._q_tree.selection_set(app._q_tree.get_children()[0])
        app._on_quarantine_select()
        app._q_restore_btn.invoke()
        assert sample.read_bytes() == content
        assert not errors, errors
    finally:
        app._on_close()
