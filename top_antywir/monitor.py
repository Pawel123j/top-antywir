"""Real-time folder monitor.

A dependency-free, cross-platform watcher: it takes a baseline snapshot of
the files under one or more roots, then on each poll re-walks them and
scans whatever is **new or has changed** (mtime/size) since the snapshot.
Detections are reported through a callback and can be auto-quarantined.

This is the portable backend — it polls rather than using kernel
notifications (inotify / FSEvents / ReadDirectoryChangesW). That keeps it
zero-dependency and identical on every OS, at the cost of CPU on very
large trees. It is meant for *bounded* roots (Downloads, a project
folder, the quick-scan locations), not for watching ``/`` or ``C:\\``.

The polling loop is fully cancellable via a ``threading.Event`` and never
calls ``time.sleep`` in a busy loop — it waits on the event with a
timeout, so cancellation is immediate.
"""
from __future__ import annotations

import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .audit import AuditLog
from .quarantine import Quarantine
from .scanner import Scanner, ScanResult

# (mtime, size) fingerprint used to decide whether a file changed.
_Fingerprint = tuple[float, int]

OnDetection = Callable[[ScanResult], None]
OnTick = Callable[[int, int], None]  # (scanned_this_tick, detections_this_tick)


@dataclass
class MonitorStats:
    ticks: int = 0
    files_scanned: int = 0
    detections: int = 0
    quarantined: int = 0


class FolderMonitor:
    """Watch ``roots`` and scan files as they appear or change."""

    def __init__(
        self,
        scanner: Scanner,
        roots: Iterable[Path],
        *,
        interval: float = 2.0,
        auto_quarantine: bool = False,
        quarantine: Quarantine | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        self.scanner = scanner
        self.roots = [Path(r).expanduser() for r in roots]
        self.interval = max(0.2, float(interval))
        self.auto_quarantine = auto_quarantine
        self.quarantine = quarantine
        self.audit = audit if audit is not None else AuditLog()
        self.stats = MonitorStats()
        self._snapshot: dict[str, _Fingerprint] = {}
        self._primed = False

    # ── Baseline ──────────────────────────────────────────────────────────────

    def prime(self) -> int:
        """Record the current state without scanning. Returns file count.

        Files already present when monitoring starts are treated as the
        baseline and are *not* reported — the monitor only reacts to
        changes from this point forward. Call :meth:`poll` afterwards.
        """
        self._snapshot.clear()
        for path in self._iter_all():
            fp = self._fingerprint(path)
            if fp is not None:
                self._snapshot[str(path)] = fp
        self._primed = True
        return len(self._snapshot)

    # ── One cycle ───────────────────────────────────────────────────────────────

    def poll(self) -> list[ScanResult]:
        """Scan everything new or changed since the last poll/prime.

        Returns the detections found this cycle (suspicious/infected).
        Auto-quarantines them when configured. Safe to call repeatedly.
        """
        if not self._primed:
            # Be forgiving: an un-primed poll scans everything once.
            self._primed = True
        detections: list[ScanResult] = []
        scanned = 0

        for path in self._iter_all():
            key = str(path)
            fp = self._fingerprint(path)
            if fp is None:
                continue
            if self._snapshot.get(key) == fp:
                continue  # unchanged — skip
            self._snapshot[key] = fp
            result = self.scanner.scan_file(path)
            scanned += 1
            if result.is_detection:
                detections.append(result)
                self._handle_detection(result)

        self.stats.ticks += 1
        self.stats.files_scanned += scanned
        self.stats.detections += len(detections)
        return detections

    # ── Loop ────────────────────────────────────────────────────────────────────

    def run(
        self,
        stop_event: threading.Event,
        on_detection: OnDetection | None = None,
        on_tick: OnTick | None = None,
    ) -> MonitorStats:
        """Block, polling every ``interval`` seconds until ``stop_event``.

        ``on_detection`` fires for each detection (in addition to any
        auto-quarantine). ``on_tick`` fires once per cycle with the counts
        for that cycle. Returns the accumulated stats when stopped.
        """
        self.audit.log(
            "monitor.start",
            roots=[str(r) for r in self.roots],
            interval=self.interval,
            auto_quarantine=self.auto_quarantine,
        )
        baseline = self.prime()
        if on_tick:
            on_tick(baseline, 0)

        try:
            while not stop_event.is_set():
                # Cancellable wait: returns immediately when the event is set.
                if stop_event.wait(self.interval):
                    break
                detections = self.poll()
                if on_detection:
                    for result in detections:
                        on_detection(result)
                if on_tick:
                    on_tick(self.stats.files_scanned, len(detections))
        finally:
            self.audit.log(
                "monitor.stop",
                ticks=self.stats.ticks,
                files_scanned=self.stats.files_scanned,
                detections=self.stats.detections,
                quarantined=self.stats.quarantined,
            )
        return self.stats

    # ── Internals ───────────────────────────────────────────────────────────────

    def _iter_all(self):
        for root in self.roots:
            try:
                if not root.exists():
                    continue
                if root.is_file():
                    yield root
                    continue
            except OSError:
                continue
            yield from self.scanner.iter_files(root)

    @staticmethod
    def _fingerprint(path: Path) -> _Fingerprint | None:
        try:
            st = path.stat()
        except OSError:
            return None
        return (st.st_mtime, st.st_size)

    def _handle_detection(self, result: ScanResult) -> None:
        self.audit.log(
            "monitor.detection",
            path=str(result.path),
            verdict=result.verdict.value,
            findings=[f.name for f in result.findings],
            detected_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )
        if self.auto_quarantine and self.quarantine is not None:
            try:
                if result.path.is_file():
                    self.quarantine.add(result)
                    self.stats.quarantined += 1
                    # The file is gone now; drop it from the snapshot so a
                    # later file at the same path is treated as new.
                    self._snapshot.pop(str(result.path), None)
            except (OSError, ValueError):
                pass
