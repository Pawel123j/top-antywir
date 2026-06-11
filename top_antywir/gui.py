"""Modern dark-theme GUI for Top Antywir (customtkinter edition)."""

from __future__ import annotations

import queue
import sys
import time
import threading
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, ttk
from pathlib import Path

# Make Tk pixel-perfect on high-DPI Windows displays. Must run before
# any Tk window is created, otherwise widgets get bitmap-scaled by the OS.
if sys.platform.startswith("win"):
    try:
        import ctypes
        try:
            # PROCESS_PER_MONITOR_DPI_AWARE = 2 (Win 8.1+, preferred)
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except (OSError, AttributeError):
            ctypes.windll.user32.SetProcessDPIAware()
    except (OSError, AttributeError):
        pass

import customtkinter as ctk

from . import __version__
from .audit import AuditLog
from .monitor import FolderMonitor
from .quarantine import Quarantine, QuarantineItem
from .report import write_html_report
from .scanner import ScanResult, Scanner, Verdict
from .targets import full_scan_targets, quick_scan_targets
from .utils import reveal_in_file_manager


ASSETS_DIR = Path(__file__).resolve().parent / "assets"
ICON_PNG   = ASSETS_DIR / "icon.png"
ICON_ICO   = ASSETS_DIR / "icon.ico"


def _apply_icon(window: tk.Misc) -> None:
    """Set the window icon, cross-platform.

    Uses iconbitmap on Windows (.ico) and iconphoto everywhere
    (works on Linux/macOS via the PNG). Silently no-ops if files
    aren't present — the GUI still launches.
    """
    try:
        if sys.platform.startswith("win") and ICON_ICO.exists():
            window.iconbitmap(default=str(ICON_ICO))  # type: ignore[arg-type]
    except tk.TclError:
        pass
    try:
        if ICON_PNG.exists():
            photo = tk.PhotoImage(file=str(ICON_PNG))
            window.iconphoto(True, photo)  # type: ignore[attr-defined]
            # Hold a reference so Tk doesn't garbage-collect the image
            window._icon_photo = photo  # type: ignore[attr-defined]
    except tk.TclError:
        pass

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# ── Colour palette ────────────────────────────────────────────────────────────
BG     = "#0d1117"
BG2    = "#161b22"
BG3    = "#21262d"
BORDER = "#30363d"
ACCENT = "#58a6ff"
GREEN  = "#3fb950"
YELLOW = "#d29922"
RED    = "#f85149"
GRAY   = "#8b949e"
FG     = "#e6edf3"
FG2    = "#c9d1d9"

VERDICT_COLOR: dict[Verdict, str] = {
    Verdict.CLEAN:      GREEN,
    Verdict.SUSPICIOUS: YELLOW,
    Verdict.INFECTED:   RED,
    Verdict.ERROR:      GRAY,
}

VERDICT_DISPLAY: dict[Verdict, str] = {
    Verdict.CLEAN:      "✓  Czyste",
    Verdict.SUSPICIOUS: "⚠  Podejrzane",
    Verdict.INFECTED:   "✗  Zainfekowane",
    Verdict.ERROR:      "?  Błąd",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _style_dark_treeview() -> None:
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Dark.Treeview",
        background=BG2,
        foreground=FG,
        fieldbackground=BG2,
        borderwidth=0,
        rowheight=30,
        font=("Segoe UI", 10),
    )
    style.configure("Dark.Treeview.Heading",
        background=BG3,
        foreground=GRAY,
        borderwidth=0,
        relief="flat",
        font=("Segoe UI", 9, "bold"),
    )
    style.map("Dark.Treeview",
        background=[("selected", "#1f6feb")],
        foreground=[("selected", "#ffffff")],
    )
    style.map("Dark.Treeview.Heading",
        background=[("active", BG3)],
        relief=[("active", "flat")],
    )
    style.configure("Dark.Vertical.TScrollbar",
        background=BG3,
        troughcolor=BG2,
        borderwidth=0,
        arrowsize=12,
    )
    style.map("Dark.Vertical.TScrollbar",
        background=[("active", BORDER)],
    )


# ── Stat card widget ──────────────────────────────────────────────────────────

class _StatCard(ctk.CTkFrame):
    def __init__(self, parent: ctk.CTkFrame, label: str, color: str, **kwargs) -> None:
        super().__init__(parent, fg_color=BG2, corner_radius=10,
                         border_width=1, border_color=BORDER, **kwargs)
        self._count_var = tk.StringVar(value="0")

        ctk.CTkFrame(self, fg_color=color, corner_radius=4, height=4).pack(
            fill="x", padx=14, pady=(14, 0)
        )
        ctk.CTkLabel(
            self,
            textvariable=self._count_var,
            font=ctk.CTkFont(family="Segoe UI", size=34, weight="bold"),
            text_color=color,
        ).pack(pady=(4, 0))
        ctk.CTkLabel(
            self,
            text=label,
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=GRAY,
        ).pack(pady=(0, 14))

    def set_count(self, n: int) -> None:
        self._count_var.set(str(n))


# ── Main window ───────────────────────────────────────────────────────────────

class TopAntywirApp(ctk.CTk):
    # WM_CLASS used by Linux desktop environments to match the .desktop entry.
    WM_CLASS = "TopAntywir"

    def __init__(self) -> None:
        super().__init__(className=self.WM_CLASS)
        self.title("Top Antywir")
        # customtkinter auto-applies a DPI scaling factor (≈1.25 on a
        # 125%-scaled Windows display), so a literal 960×600 here ends up
        # rendered around 1200×750 physical pixels — a comfortable fit
        # on a 1280-logical-wide / 1600-physical screen.
        self.geometry("960x600")
        self.minsize(820, 540)
        self.configure(fg_color=BG)
        _apply_icon(self)

        self.scanner = Scanner()
        self.audit = AuditLog()
        self.quarantine = Quarantine(audit=self.audit)
        self.results: list[ScanResult] = []          # detections shown in the table
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self._stop_event: threading.Event | None = None
        self._scan_label: str = ""
        self._scan_started_at: float = 0.0
        self._scan_mode: str = ""
        # Last finished scan's summary, kept so the HTML report can show
        # accurate counts even though we only retain detections in memory.
        self._last_stats: dict[str, int] = {}
        self._last_duration: float = 0.0
        # Real-time monitor state.
        self._monitor_stop: threading.Event | None = None
        self._monitor_detections = 0

        self.target_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Gotowy.  ⚡ Skanuj / 🚀 Szybkie / 🌐 Pełne  ·  Ctrl+O / Ctrl+Shift+O / F5")
        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress_label_var = tk.StringVar(value="")

        _style_dark_treeview()
        self._build_ui()
        self._bind_shortcuts()
        # Centre once Tk has processed its event queue so the requested
        # geometry sticks instead of being overridden by layout reflow.
        self.after_idle(self._center_window)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._poll_events()

    def _on_close(self) -> None:
        """Stop the background monitor (if any) before tearing down Tk."""
        if self._monitor_stop is not None:
            self._monitor_stop.set()
        if self._stop_event is not None:
            self._stop_event.set()
        self.destroy()

    def _center_window(self, w: int = 960, h: int = 600) -> None:
        """Centre the window slightly above geometric centre of the screen.

        Takes the *requested* size as arguments — relying on
        ``winfo_width()`` is unreliable here because the window isn't
        mapped yet during ``__init__``.
        """
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        w = min(w, max(400, sw - 40))
        h = min(h, max(300, sh - 80))
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 3)
        self.geometry(f"{w}x{h}+{x}+{y}")

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)

        self._build_header()         # row 0
        self._build_scan_bar()       # row 1
        self._build_presets_bar()    # row 2
        self._build_progress_bar()   # row 3 (hidden when idle)
        self._build_body()           # row 4 (expandable)
        self._build_footer()         # row 5

    def _build_header(self) -> None:
        hdr = ctk.CTkFrame(self, fg_color=BG2, corner_radius=0, height=66)
        hdr.grid(row=0, column=0, sticky="ew")
        hdr.grid_columnconfigure(1, weight=1)
        hdr.grid_propagate(False)

        ctk.CTkLabel(hdr, text="🛡", font=ctk.CTkFont(size=30), text_color=ACCENT).grid(
            row=0, column=0, padx=(20, 6), pady=14, sticky="w"
        )

        title_row = ctk.CTkFrame(hdr, fg_color="transparent")
        title_row.grid(row=0, column=1, sticky="w")
        ctk.CTkLabel(
            title_row,
            text="Top Antywir",
            font=ctk.CTkFont(family="Segoe UI", size=20, weight="bold"),
            text_color=FG,
        ).pack(side="left", padx=(0, 8))
        ctk.CTkLabel(
            title_row,
            text=f"v{__version__}",
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color=GRAY,
        ).pack(side="left", pady=6)

        # Separator line at bottom of header
        ctk.CTkFrame(self, fg_color=BORDER, height=1, corner_radius=0).grid(
            row=0, column=0, sticky="sew"
        )

    def _build_scan_bar(self) -> None:
        bar = ctk.CTkFrame(self, fg_color=BG2, corner_radius=0, height=60)
        bar.grid(row=1, column=0, sticky="ew")
        bar.grid_propagate(False)

        inner = ctk.CTkFrame(bar, fg_color="transparent")
        inner.pack(fill="x", padx=20, pady=11)
        inner.columnconfigure(0, weight=1)

        self.path_entry = ctk.CTkEntry(
            inner,
            textvariable=self.target_var,
            placeholder_text="Ścieżka do pliku lub folderu...",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color=BG3,
            border_color=BORDER,
            text_color=FG,
            height=38,
        )
        self.path_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))

        btns = ctk.CTkFrame(inner, fg_color="transparent")
        btns.grid(row=0, column=1)

        def _ghost_btn(parent: ctk.CTkFrame, text: str, cmd, width: int) -> ctk.CTkButton:
            return ctk.CTkButton(
                parent, text=text, command=cmd, width=width, height=38,
                fg_color=BG3, hover_color=BORDER, text_color=FG2,
                border_width=1, border_color=BORDER,
                font=ctk.CTkFont(family="Segoe UI", size=11), corner_radius=8,
            )

        _ghost_btn(btns, "📄 Plik",   self.choose_file,   78).pack(side="left", padx=(0, 6))
        _ghost_btn(btns, "📁 Folder", self.choose_folder, 90).pack(side="left", padx=(0, 8))

        self.scan_button = ctk.CTkButton(
            btns, text="⚡  Skanuj", command=self.start_scan_custom,
            width=128, height=38,
            fg_color=ACCENT, hover_color="#4090e0", text_color="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            corner_radius=8,
        )
        self.scan_button.pack(side="left")

    def _build_presets_bar(self) -> None:
        bar = ctk.CTkFrame(self, fg_color=BG, corner_radius=0, height=46)
        bar.grid(row=2, column=0, sticky="ew")
        bar.grid_propagate(False)

        inner = ctk.CTkFrame(bar, fg_color="transparent")
        inner.pack(fill="x", padx=20, pady=6)

        ctk.CTkLabel(
            inner, text="Predefiniowane skany:",
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color=GRAY,
        ).pack(side="left", padx=(0, 10))

        def _preset_btn(text: str, cmd, color_fg: str = FG2) -> ctk.CTkButton:
            return ctk.CTkButton(
                inner, text=text, command=cmd, height=30, width=190,
                fg_color=BG3, hover_color=BORDER, text_color=color_fg,
                border_width=1, border_color=BORDER,
                font=ctk.CTkFont(family="Segoe UI", size=11),
                corner_radius=6,
            )

        self.quick_btn = _preset_btn("🚀  Szybkie skanowanie", self.start_scan_quick)
        self.quick_btn.pack(side="left", padx=(0, 8))

        self.full_btn = _preset_btn("🌐  Pełne skanowanie komputera", self.start_scan_full)
        self.full_btn.pack(side="left")

    def _build_progress_bar(self) -> None:
        self.progress_frame = ctk.CTkFrame(self, fg_color=BG, corner_radius=0, height=32)
        self.progress_frame.grid(row=3, column=0, sticky="ew")
        self.progress_frame.grid_propagate(False)

        inner = ctk.CTkFrame(self.progress_frame, fg_color="transparent")
        inner.pack(fill="x", padx=20, pady=6)
        inner.columnconfigure(0, weight=1)

        self.progress_bar = ctk.CTkProgressBar(
            inner,
            variable=self.progress_var,
            fg_color=BG3,
            progress_color=ACCENT,
            height=6,
            corner_radius=3,
        )
        self.progress_bar.grid(row=0, column=0, sticky="ew", padx=(0, 12))

        ctk.CTkLabel(
            inner,
            textvariable=self.progress_label_var,
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color=GRAY,
            width=210,
            anchor="e",
        ).grid(row=0, column=1, sticky="e")

        self.progress_frame.grid_remove()

    def _build_body(self) -> None:
        body = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        body.grid(row=4, column=0, sticky="nsew")
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(1, weight=1)

        # ── Stats cards ──────────────────────────────────────────────────────
        cards = ctk.CTkFrame(body, fg_color="transparent")
        cards.grid(row=0, column=0, sticky="ew", padx=20, pady=(14, 10))
        cards.columnconfigure((0, 1, 2, 3), weight=1)

        self.card_clean      = _StatCard(cards, "Czyste",       GREEN)
        self.card_suspicious = _StatCard(cards, "Podejrzane",   YELLOW)
        self.card_infected   = _StatCard(cards, "Zainfekowane", RED)
        self.card_errors     = _StatCard(cards, "Błędy",        GRAY)

        for col, card in enumerate(
            (self.card_clean, self.card_suspicious, self.card_infected, self.card_errors)
        ):
            card.grid(row=0, column=col, sticky="ew", padx=(0, 8) if col < 3 else (0, 0))

        # ── Results table ────────────────────────────────────────────────────
        tbl_wrap = ctk.CTkFrame(body, fg_color=BG2, corner_radius=10,
                                border_width=1, border_color=BORDER)
        tbl_wrap.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 8))
        tbl_wrap.columnconfigure(0, weight=1)
        tbl_wrap.rowconfigure(0, weight=1)

        cols = ("verdict", "path", "findings")
        self.tree = ttk.Treeview(
            tbl_wrap, columns=cols, show="headings",
            style="Dark.Treeview", selectmode="browse",
        )
        self.tree.heading("verdict",  text="  Status")
        self.tree.heading("path",     text="Plik")
        self.tree.heading("findings", text="Wykrycia")
        self.tree.column("verdict",  width=136, minwidth=100, stretch=False)
        self.tree.column("path",     width=480, minwidth=240)
        self.tree.column("findings", width=290, minwidth=160)

        self.tree.tag_configure("clean",       foreground=GREEN)
        self.tree.tag_configure("suspicious",  foreground=YELLOW)
        self.tree.tag_configure("infected",    foreground=RED)
        self.tree.tag_configure("error",       foreground=GRAY)
        self.tree.tag_configure("quarantined", foreground="#4d5560")  # dim — moved out

        self.tree.grid(row=0, column=0, sticky="nsew", padx=(1, 0), pady=1)
        vsb = ttk.Scrollbar(tbl_wrap, orient="vertical", command=self.tree.yview,
                            style="Dark.Vertical.TScrollbar")
        vsb.grid(row=0, column=1, sticky="ns", pady=1)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        # ── Details panel ────────────────────────────────────────────────────
        det = ctk.CTkFrame(body, fg_color=BG2, corner_radius=10,
                           border_width=1, border_color=BORDER)
        det.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 8))
        det.columnconfigure(0, weight=1)

        det_hdr = ctk.CTkFrame(det, fg_color="transparent")
        det_hdr.grid(row=0, column=0, sticky="ew", padx=14, pady=(10, 0))
        det_hdr.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            det_hdr, text="Szczegóły",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=GRAY,
        ).grid(row=0, column=0, sticky="w")

        det_btns = ctk.CTkFrame(det_hdr, fg_color="transparent")
        det_btns.grid(row=0, column=1, sticky="e")

        self.reveal_btn = ctk.CTkButton(
            det_btns, text="📂  Pokaż w eksploratorze",
            command=self.reveal_selected,
            height=28, width=200,
            fg_color=BG3, hover_color=BORDER, text_color=FG2,
            border_width=1, border_color=BORDER,
            font=ctk.CTkFont(family="Segoe UI", size=10),
            corner_radius=6, state="disabled",
        )
        self.reveal_btn.pack(side="left", padx=(0, 6))

        self.quarantine_btn = ctk.CTkButton(
            det_btns, text="⬇  Kwarantanna dla wykryć",
            command=self.quarantine_detections,
            height=28, width=210,
            fg_color=BG3, hover_color=BORDER, text_color=FG2,
            border_width=1, border_color=BORDER,
            font=ctk.CTkFont(family="Segoe UI", size=10),
            corner_radius=6, state="disabled",
        )
        self.quarantine_btn.pack(side="left", padx=(0, 6))

        self.export_btn = ctk.CTkButton(
            det_btns, text="💾  Raport HTML",
            command=self.export_html_report,
            height=28, width=140,
            fg_color=BG3, hover_color=BORDER, text_color=FG2,
            border_width=1, border_color=BORDER,
            font=ctk.CTkFont(family="Segoe UI", size=10),
            corner_radius=6, state="disabled",
        )
        self.export_btn.pack(side="left")

        self.details_text = ctk.CTkTextbox(
            det, height=112, fg_color="transparent",
            text_color=FG2,
            font=ctk.CTkFont(family="Consolas", size=11),
            wrap="word", state="disabled",
        )
        self.details_text.grid(row=1, column=0, sticky="ew", padx=14, pady=(6, 12))

    def _build_footer(self) -> None:
        ftr = ctk.CTkFrame(self, fg_color=BG2, corner_radius=0, height=40)
        ftr.grid(row=5, column=0, sticky="ew")
        ftr.grid_columnconfigure(0, weight=1)
        ftr.grid_propagate(False)

        ctk.CTkLabel(
            ftr, textvariable=self.status_var,
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color=GRAY,
        ).grid(row=0, column=0, sticky="w", padx=20, pady=10)

        right = ctk.CTkFrame(ftr, fg_color="transparent")
        right.grid(row=0, column=1, sticky="e", padx=20, pady=7)

        self.monitor_btn = ctk.CTkButton(
            right, text="🛡  Ochrona: WYŁ", command=self.toggle_monitor,
            height=26, width=158,
            fg_color=BG3, hover_color=BORDER, text_color=FG2,
            border_width=1, border_color=BORDER,
            font=ctk.CTkFont(family="Segoe UI", size=10),
            corner_radius=6,
        )
        self.monitor_btn.pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            right, text="🔒  Kwarantanna", command=self.show_quarantine,
            height=26, width=130,
            fg_color=BG3, hover_color=BORDER, text_color=FG2,
            border_width=1, border_color=BORDER,
            font=ctk.CTkFont(family="Segoe UI", size=10),
            corner_radius=6,
        ).pack(side="left")

    # ── Keyboard shortcuts ────────────────────────────────────────────────────

    def _bind_shortcuts(self) -> None:
        """Application-wide keyboard shortcuts."""
        # Enter in the path entry starts the custom scan
        self.path_entry.bind("<Return>", lambda _e: self.start_scan_custom())
        # Window-level bindings
        self.bind_all("<F5>",          lambda _e: self.start_scan_custom())
        self.bind_all("<Control-o>",   lambda _e: self.choose_file())
        self.bind_all("<Control-O>",   lambda _e: self.choose_folder())   # Shift+O
        self.bind_all("<Control-l>",   lambda _e: self._focus_path())
        self.bind_all("<Control-k>",   lambda _e: self.show_quarantine())
        self.bind_all("<Control-e>",   lambda _e: self.export_html_report())
        self.bind_all("<Control-m>",   lambda _e: self.toggle_monitor())
        self.bind_all("<Control-q>",   lambda _e: self._on_close())
        # Scan presets
        self.bind_all("<Control-Key-1>", lambda _e: self.start_scan_quick())
        self.bind_all("<Control-Key-2>", lambda _e: self.start_scan_full())
        # Stop current scan
        self.bind_all("<Escape>",      lambda _e: self._cancel_scan_if_active())

    def _cancel_scan_if_active(self) -> None:
        if self._stop_event is not None and not self._stop_event.is_set():
            self._cancel_scan()

    def _focus_path(self) -> None:
        self.path_entry.focus_set()
        self.path_entry.select_range(0, "end")

    # ── Event handlers ────────────────────────────────────────────────────────

    def choose_file(self) -> None:
        path = filedialog.askopenfilename(title="Wybierz plik do skanowania")
        if path:
            self.target_var.set(path)

    def choose_folder(self) -> None:
        path = filedialog.askdirectory(title="Wybierz folder do skanowania")
        if path:
            self.target_var.set(path)

    # ── Scan modes ────────────────────────────────────────────────────────────

    def start_scan_custom(self) -> None:
        """Scan the path currently in the input field."""
        target = self.target_var.get().strip()
        if not target:
            messagebox.showinfo("Top Antywir", "Wybierz plik albo folder do skanowania.")
            return
        self._start_scan([Path(target)], label=f"Skanowanie: {target}", mode="custom")

    def start_scan_quick(self) -> None:
        """Scan common malware locations (Downloads, Temp, Startup, …)."""
        targets = quick_scan_targets()
        if not targets:
            messagebox.showinfo(
                "Top Antywir",
                "Brak typowych lokalizacji do szybkiego skanu na tym systemie.",
            )
            return
        self._start_scan(targets, label="🚀 Szybkie skanowanie", mode="quick")

    def start_scan_full(self) -> None:
        """Scan all fixed drives (Windows) or / (Unix)."""
        targets = full_scan_targets()
        if not targets:
            messagebox.showerror("Top Antywir", "Nie wykryto żadnych dysków do skanowania.")
            return
        roots_str = "\n  ".join(str(t) for t in targets)
        if not messagebox.askyesno(
            "Top Antywir — Pełne skanowanie",
            "Pełne skanowanie komputera może potrwać DŁUGO\n"
            "(od kilkunastu minut do kilku godzin).\n\n"
            f"Skanowane lokalizacje:\n  {roots_str}\n\n"
            "W każdej chwili możesz nacisnąć ⏹ Zatrzymaj.\n\n"
            "Kontynuować?",
            icon="warning",
        ):
            return
        self._start_scan(targets, label="🌐 Pełne skanowanie", mode="full")

    def _start_scan(self, targets: list[Path], label: str, mode: str = "custom") -> None:
        self._scan_label = label
        self._scan_mode = mode
        self._stop_event = threading.Event()
        self._scan_started_at = time.monotonic()
        self.status_var.set(f"{label} — skanowanie w toku…")
        self.progress_var.set(0.0)
        self.progress_label_var.set("")
        self.progress_frame.grid(row=3, column=0, sticky="ew")
        self._clear_results()
        self._reset_stats()
        self._set_scan_active(True)

        self.audit.log("scan.start", mode=mode, source="gui", targets=targets)

        threading.Thread(
            target=self._scan_worker, args=(targets,), daemon=True
        ).start()

    def _cancel_scan(self) -> None:
        if self._stop_event is not None:
            self._stop_event.set()
        self.status_var.set("⏹ Zatrzymywanie skanowania…")

    def _set_scan_active(self, active: bool) -> None:
        if active:
            self.scan_button.configure(
                text="⏹  Zatrzymaj", command=self._cancel_scan,
                fg_color=RED, hover_color="#c33d35",
            )
            self.quick_btn.configure(state="disabled")
            self.full_btn.configure(state="disabled")
            self.quarantine_btn.configure(state="disabled")
        else:
            self.scan_button.configure(
                text="⚡  Skanuj", command=self.start_scan_custom,
                fg_color=ACCENT, hover_color="#4090e0",
            )
            self.quick_btn.configure(state="normal")
            self.full_btn.configure(state="normal")

    # ── Worker thread + event pump ────────────────────────────────────────────

    def _scan_worker(self, targets: list[Path]) -> None:
        """Run the scan in a background thread, streaming results."""
        stop = self._stop_event
        stats = {"count": 0, "clean": 0, "suspicious": 0, "infected": 0, "errors": 0}
        last_emit = 0.0

        for result in self.scanner.iter_scan(targets, stop_event=stop):
            stats["count"] += 1
            if result.verdict == Verdict.CLEAN:
                stats["clean"] += 1
            elif result.verdict == Verdict.SUSPICIOUS:
                stats["suspicious"] += 1
                self.events.put(("detection", result))
            elif result.verdict == Verdict.INFECTED:
                stats["infected"] += 1
                self.events.put(("detection", result))
            else:  # ERROR
                stats["errors"] += 1
                # Don't spam the table with permission-denied noise during
                # full-system scans; surface only "real" errors.
                err = (result.error or "").lower()
                if "permission" not in err and "denied" not in err:
                    self.events.put(("detection", result))

            now = time.monotonic()
            if stats["count"] % 25 == 0 or (now - last_emit) >= 0.15:
                self.events.put(("stats", (dict(stats), str(result.path))))
                last_emit = now

        cancelled = bool(stop is not None and stop.is_set())
        self.events.put(("done", (dict(stats), cancelled)))

    def _poll_events(self) -> None:
        try:
            for _ in range(200):  # drain up to 200 events per tick
                event, payload = self.events.get_nowait()
                if event == "detection":
                    self._add_detection(payload)  # type: ignore[arg-type]
                elif event == "stats":
                    stats, current_path = payload  # type: ignore[misc]
                    self._update_stats(stats, current_path)
                elif event == "done":
                    stats, cancelled = payload  # type: ignore[misc]
                    self._finalize_scan(stats, cancelled)
                elif event == "monitor_detection":
                    self._on_monitor_detection(payload)  # type: ignore[arg-type]
                elif event == "monitor_stopped":
                    self._on_monitor_stopped()
        except queue.Empty:
            pass
        self.after(80, self._poll_events)

    def _add_detection(self, result: ScanResult) -> None:
        self.results.append(result)
        idx = len(self.results) - 1
        findings_str = (
            ", ".join(f.name for f in result.findings)
            or (result.error and f"Błąd: {result.error}")
            or "—"
        )
        tag = result.verdict.name.lower()
        self.tree.insert(
            "", "end", iid=str(idx),
            values=(VERDICT_DISPLAY[result.verdict], str(result.path), findings_str),
            tags=(tag,),
        )

    def _update_stats(self, stats: dict, current_path: str) -> None:
        self.card_clean.set_count(stats["clean"])
        self.card_suspicious.set_count(stats["suspicious"])
        self.card_infected.set_count(stats["infected"])
        self.card_errors.set_count(stats["errors"])
        # Indeterminate "bouncing" progress since we don't pre-count files
        self.progress_var.set(((stats["count"] // 30) % 100) / 100.0)
        shown = current_path if len(current_path) <= 62 else "…" + current_path[-60:]
        self.progress_label_var.set(f"{stats['count']:>7}  ·  {shown}")

    def _finalize_scan(self, stats: dict, cancelled: bool) -> None:
        self._update_stats(stats, "")
        detections = stats["suspicious"] + stats["infected"]
        prefix = "⏹ Przerwano" if cancelled else "✓ Zakończono"
        duration = time.monotonic() - self._scan_started_at
        self.status_var.set(
            f"{prefix} ({self._scan_label}).  "
            f"Przeskanowano: {stats['count']}  ·  "
            f"Zagrożenia: {detections}  ·  Błędy: {stats['errors']}  ·  "
            f"{duration:.1f}s"
        )
        self.progress_var.set(1.0)
        self.after(700, self.progress_frame.grid_remove)
        self._set_scan_active(False)
        self.quarantine_btn.configure(state="normal" if detections else "disabled")
        self.export_btn.configure(state="normal" if stats["count"] else "disabled")
        self._last_stats = dict(stats)
        self._last_duration = duration
        self._stop_event = None

        self.audit.log(
            "scan.done", mode=self._scan_mode, source="gui",
            scanned=stats["count"], clean=stats["clean"],
            suspicious=stats["suspicious"], infected=stats["infected"],
            errors=stats["errors"],
            cancelled=cancelled,
            duration_seconds=round(duration, 2),
        )

    def _clear_results(self) -> None:
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        # Reset the backing list too so tree iids (which equal the index
        # into self.results) restart at 0 and stay aligned for this scan.
        self.results.clear()
        self._set_details("")

    def _reset_stats(self) -> None:
        for card in (self.card_clean, self.card_suspicious,
                     self.card_infected, self.card_errors):
            card.set_count(0)

    def _on_select(self, _event: object = None) -> None:
        sel = self.tree.selection()
        if not sel:
            self._set_details("")
            self.reveal_btn.configure(state="disabled")
            return
        result = self.results[int(sel[0])]
        lines = [
            f"Plik:    {result.path}",
            f"Status:  {result.verdict.value}",
        ]
        if result.sha256:
            lines.append(f"SHA-256: {result.sha256}")
        if result.error:
            lines.append(f"Błąd:    {result.error}")
        for f in result.findings:
            lines.append(f"  [{f.severity.upper():6}]  {f.name}: {f.description}")
        self._set_details("\n".join(lines))
        self.reveal_btn.configure(state="normal" if result.path.exists() else "disabled")

    def reveal_selected(self) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        result = self.results[int(sel[0])]
        if not result.path.exists():
            messagebox.showinfo(
                "Top Antywir",
                "Plik nie istnieje pod tą ścieżką (mógł zostać przeniesiony do kwarantanny).",
            )
            return
        if not reveal_in_file_manager(result.path):
            messagebox.showerror(
                "Top Antywir",
                "Nie udało się otworzyć menedżera plików na tej platformie.",
            )

    def quarantine_detections(self) -> None:
        detections = [
            (idx, r) for idx, r in enumerate(self.results)
            if r.is_detection and r.path.exists()
        ]
        if not detections:
            messagebox.showinfo("Top Antywir", "Brak plików do przeniesienia do kwarantanny.")
            return
        if not messagebox.askyesno(
            "Top Antywir",
            f"Przenieść {len(detections)} wykrytych plików do kwarantanny?",
        ):
            return

        moved, errs = 0, []
        for idx, r in detections:
            try:
                self.quarantine.add(r)
                moved += 1
                # Mark this row as moved so the user sees what changed.
                values = self.tree.item(str(idx), "values")
                if values:
                    self.tree.item(
                        str(idx),
                        values=(f"⇩ {values[0]}", values[1], "→ kwarantanna"),
                        tags=("quarantined",),
                    )
            except OSError as exc:
                errs.append(f"{r.path.name}: {exc}")

        self.status_var.set(f"Kwarantanna: przeniesiono {moved} plików.")
        self.quarantine_btn.configure(state="disabled")
        self.reveal_btn.configure(state="disabled")
        if errs:
            messagebox.showwarning("Top Antywir", "\n".join(errs[:5]))
        else:
            messagebox.showinfo("Top Antywir", f"Przeniesiono {moved} plików do kwarantanny.")

    # ── HTML report export ──────────────────────────────────────────────────────

    def export_html_report(self) -> None:
        if not self.results and not self._last_stats:
            messagebox.showinfo("Top Antywir", "Najpierw wykonaj skanowanie.")
            return
        path_str = filedialog.asksaveasfilename(
            title="Zapisz raport HTML",
            defaultextension=".html",
            initialfile="top-antywir-raport.html",
            filetypes=[("Plik HTML", "*.html"), ("Wszystkie pliki", "*.*")],
        )
        if not path_str:
            return

        stats = self._last_stats
        counts = scanned = None
        if stats:
            counts = {
                Verdict.CLEAN:      stats.get("clean", 0),
                Verdict.SUSPICIOUS: stats.get("suspicious", 0),
                Verdict.INFECTED:   stats.get("infected", 0),
                Verdict.ERROR:      stats.get("errors", 0),
            }
            scanned = stats.get("count")

        try:
            written = write_html_report(
                Path(path_str), self.results,
                mode=self._scan_mode or "custom",
                duration=self._last_duration,
                counts=counts, scanned=scanned,
            )
        except OSError as exc:
            messagebox.showerror("Top Antywir", f"Nie udało się zapisać raportu:\n{exc}")
            return

        self.status_var.set(f"Zapisano raport HTML: {written}")
        if messagebox.askyesno(
            "Top Antywir",
            f"Zapisano raport:\n{written}\n\nOtworzyć w przeglądarce?",
        ):
            try:
                webbrowser.open(written.as_uri())
            except (OSError, ValueError):
                pass

    # ── Real-time monitor ─────────────────────────────────────────────────────

    def toggle_monitor(self) -> None:
        # Already running → request a stop.
        if self._monitor_stop is not None and not self._monitor_stop.is_set():
            self._monitor_stop.set()
            self.monitor_btn.configure(text="🛡  Ochrona: …", state="disabled")
            self.status_var.set("🛡 Zatrzymywanie ochrony…")
            return

        roots = quick_scan_targets()
        if not roots:
            messagebox.showinfo(
                "Top Antywir",
                "Brak typowych lokalizacji do monitorowania na tym systemie.",
            )
            return

        self._monitor_detections = 0
        stop_event = threading.Event()
        self._monitor_stop = stop_event
        monitor = FolderMonitor(
            self.scanner, roots,
            interval=3.0, auto_quarantine=False, audit=self.audit,
        )
        self.monitor_btn.configure(
            text="🛡  Ochrona: WŁ",
            fg_color=GREEN, hover_color="#2ea043", text_color="#ffffff",
        )
        self.status_var.set(
            "🛡 Ochrona w czasie rzeczywistym włączona — obserwuję typowe lokalizacje…"
        )
        threading.Thread(
            target=self._monitor_worker, args=(monitor, stop_event), daemon=True,
        ).start()

    def _monitor_worker(self, monitor: FolderMonitor, stop_event: threading.Event) -> None:
        def on_det(result: ScanResult) -> None:
            self.events.put(("monitor_detection", result))
        try:
            monitor.run(stop_event, on_detection=on_det)
        finally:
            self.events.put(("monitor_stopped", None))

    def _on_monitor_detection(self, result: ScanResult) -> None:
        self._monitor_detections += 1
        self._add_detection(result)
        self.export_btn.configure(state="normal")
        self.status_var.set(f"🛡 Monitor wykrył zagrożenie: {result.path}")
        try:
            self.bell()
        except tk.TclError:
            pass

    def _on_monitor_stopped(self) -> None:
        self._monitor_stop = None
        self.monitor_btn.configure(
            text="🛡  Ochrona: WYŁ", state="normal",
            fg_color=BG3, hover_color=BORDER, text_color=FG2,
        )
        self.status_var.set(
            f"🛡 Ochrona zatrzymana.  Wykryć w sesji monitora: {self._monitor_detections}"
        )

    def show_quarantine(self) -> None:
        win = ctk.CTkToplevel(self)
        win.title("Kwarantanna — Top Antywir")
        win.geometry("900x460")
        win.minsize(700, 320)
        win.configure(fg_color=BG)
        _apply_icon(win)
        win.grab_set()
        win.grid_columnconfigure(0, weight=1)
        win.grid_rowconfigure(2, weight=1)

        # ── Header row: title + toolbar buttons ────────────────────────────────
        header = ctk.CTkFrame(win, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=(16, 6))
        header.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            header, text="🔒  Kwarantanna",
            font=ctk.CTkFont(family="Segoe UI", size=16, weight="bold"),
            text_color=FG,
        ).grid(row=0, column=0, sticky="w")

        self._q_status_var = tk.StringVar(value="")
        ctk.CTkLabel(
            win, textvariable=self._q_status_var,
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color=GRAY,
        ).grid(row=1, column=0, sticky="w", padx=20, pady=(0, 6))

        actions = ctk.CTkFrame(header, fg_color="transparent")
        actions.grid(row=0, column=1, sticky="e")

        def _action_btn(text: str, cmd, color: str = BG3, fg: str = FG2,
                        width: int = 120) -> ctk.CTkButton:
            return ctk.CTkButton(
                actions, text=text, command=cmd,
                height=30, width=width,
                fg_color=color, hover_color=BORDER, text_color=fg,
                border_width=1, border_color=BORDER,
                font=ctk.CTkFont(family="Segoe UI", size=11),
                corner_radius=6,
            )

        self._q_restore_btn = _action_btn(
            "↩  Przywróć", self._quarantine_restore_selected, width=124,
        )
        self._q_restore_btn.pack(side="left", padx=(0, 6))

        self._q_delete_btn = _action_btn(
            "🗑  Usuń trwale", self._quarantine_delete_selected,
            color=BG3, fg=RED, width=140,
        )
        self._q_delete_btn.pack(side="left", padx=(0, 6))

        _action_btn("⟳  Odśwież", self._quarantine_reload, width=110).pack(side="left")

        # ── Table ─────────────────────────────────────────────────────────────
        tbl = ctk.CTkFrame(win, fg_color=BG2, corner_radius=10,
                           border_width=1, border_color=BORDER)
        tbl.grid(row=2, column=0, sticky="nsew", padx=20, pady=(0, 16))
        tbl.columnconfigure(0, weight=1)
        tbl.rowconfigure(0, weight=1)

        self._q_tree = ttk.Treeview(
            tbl, columns=("id", "verdict", "path", "date"),
            show="headings", style="Dark.Treeview", selectmode="browse",
        )
        self._q_tree.heading("id",      text="ID")
        self._q_tree.heading("verdict", text="Status")
        self._q_tree.heading("path",    text="Oryginalna ścieżka")
        self._q_tree.heading("date",    text="Data")
        self._q_tree.column("id",      width=130, stretch=False)
        self._q_tree.column("verdict", width=110, stretch=False)
        self._q_tree.column("path",    width=460)
        self._q_tree.column("date",    width=160, stretch=False)
        self._q_tree.grid(row=0, column=0, sticky="nsew", padx=(1, 0), pady=1)
        self._q_tree.bind("<<TreeviewSelect>>", self._on_quarantine_select)

        vsb2 = ttk.Scrollbar(tbl, orient="vertical", command=self._q_tree.yview,
                             style="Dark.Vertical.TScrollbar")
        vsb2.grid(row=0, column=1, sticky="ns", pady=1)
        self._q_tree.configure(yscrollcommand=vsb2.set)

        # Per-window shortcuts
        win.bind("<Control-r>", lambda _e: self._quarantine_restore_selected())
        win.bind("<Delete>",    lambda _e: self._quarantine_delete_selected())
        win.bind("<F5>",        lambda _e: self._quarantine_reload())
        win.bind("<Escape>",    lambda _e: win.destroy())

        self._q_window = win
        self._q_items_by_iid: dict[str, QuarantineItem] = {}
        self._quarantine_reload()

    def _quarantine_reload(self) -> None:
        for iid in self._q_tree.get_children():
            self._q_tree.delete(iid)
        self._q_items_by_iid.clear()

        items = self.quarantine.list_items()
        for item in items:
            date_str = item.created_at[:19].replace("T", " ")
            iid = self._q_tree.insert("", "end", values=(
                item.item_id[:12] + "…",
                item.verdict,
                str(item.original_path),
                date_str,
            ))
            self._q_items_by_iid[iid] = item

        if not items:
            placeholder = self._q_tree.insert(
                "", "end",
                values=("—", "—", "Kwarantanna jest pusta.", ""),
            )
            self._q_items_by_iid[placeholder] = None  # type: ignore[assignment]

        self._q_status_var.set(f"Elementów: {len(items)}")
        self._update_quarantine_buttons()

    def _on_quarantine_select(self, _event: object = None) -> None:
        self._update_quarantine_buttons()

    def _update_quarantine_buttons(self) -> None:
        item = self._quarantine_selected_item()
        state = "normal" if item is not None else "disabled"
        self._q_restore_btn.configure(state=state)
        self._q_delete_btn.configure(state=state)

    def _quarantine_selected_item(self) -> QuarantineItem | None:
        sel = self._q_tree.selection()
        if not sel:
            return None
        return self._q_items_by_iid.get(sel[0])

    def _quarantine_restore_selected(self) -> None:
        item = self._quarantine_selected_item()
        if item is None:
            return
        if not messagebox.askyesno(
            "Top Antywir",
            f"Przywrócić plik do oryginalnej lokalizacji?\n\n{item.original_path}",
            parent=self._q_window,
        ):
            return
        try:
            target = self.quarantine.restore(item.item_id)
        except FileExistsError:
            new_target = filedialog.asksaveasfilename(
                parent=self._q_window,
                title="Plik docelowy istnieje — wybierz inną lokalizację",
                initialfile=item.original_path.name,
            )
            if not new_target:
                return
            try:
                target = self.quarantine.restore(item.item_id, Path(new_target))
            except OSError as exc:
                messagebox.showerror("Top Antywir", str(exc), parent=self._q_window)
                return
        except OSError as exc:
            messagebox.showerror("Top Antywir", str(exc), parent=self._q_window)
            return
        self._q_status_var.set(f"Przywrócono do: {target}")
        self._quarantine_reload()

    def _quarantine_delete_selected(self) -> None:
        item = self._quarantine_selected_item()
        if item is None:
            return
        if not messagebox.askyesno(
            "Top Antywir",
            f"Usunąć plik z kwarantanny TRWAŁE?\n\n{item.original_path.name}\n\n"
            "Tej operacji nie da się cofnąć.",
            icon="warning",
            parent=self._q_window,
        ):
            return
        try:
            self.quarantine.delete(item.item_id)
        except OSError as exc:
            messagebox.showerror("Top Antywir", str(exc), parent=self._q_window)
            return
        self._q_status_var.set(f"Usunięto: {item.original_path.name}")
        self._quarantine_reload()

    def _set_details(self, text: str) -> None:
        self.details_text.configure(state="normal")
        self.details_text.delete("1.0", "end")
        if text:
            self.details_text.insert("1.0", text)
        self.details_text.configure(state="disabled")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> int:
    app = TopAntywirApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
