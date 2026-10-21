"""Tests for the real-time folder monitor.

Uses a synthetic HashSignature (never the EICAR string) so the test does
not race the host's real antivirus.
"""
from __future__ import annotations

import hashlib
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from top_antywir.audit import AuditLog
from top_antywir.monitor import FolderMonitor
from top_antywir.quarantine import Quarantine
from top_antywir.scanner import Scanner, ScanResult, Verdict
from top_antywir.signatures import HashSignature

_MAL = b"\x07MONITOR-TEST-MALWARE-PAYLOAD\x09" * 3
_MAL_SHA = hashlib.sha256(_MAL).hexdigest()
_BENIGN = b"just some harmless text that matches nothing at all\n"


def _scanner() -> Scanner:
    sig = HashSignature(
        name="Monitor-Test", sha256=_MAL_SHA, severity="high",
        description="Synthetic monitor test signature.",
    )
    # Pin signatures so the test is deterministic regardless of any user packs.
    return Scanner(hash_signatures=(sig,), pattern_signatures=())


class MonitorTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.watch = self.root / "watched"
        self.watch.mkdir()
        self.audit = AuditLog(path=self.root / "audit.jsonl")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _monitor(self, **kw) -> FolderMonitor:
        return FolderMonitor(_scanner(), [self.watch], audit=self.audit, **kw)

    def test_new_malware_is_detected_after_prime(self) -> None:
        (self.watch / "benign.txt").write_bytes(_BENIGN)
        mon = self._monitor()
        mon.prime()
        # Nothing changed yet.
        self.assertEqual(mon.poll(), [])
        # Drop a malicious file.
        (self.watch / "evil.bin").write_bytes(_MAL)
        detections = mon.poll()
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].verdict, Verdict.INFECTED)
        self.assertEqual(detections[0].path.name, "evil.bin")

    def test_preexisting_files_are_baseline_not_detected(self) -> None:
        (self.watch / "evil.bin").write_bytes(_MAL)
        mon = self._monitor()
        mon.prime()
        # The malware was already there when monitoring started → baseline.
        self.assertEqual(mon.poll(), [])

    def test_unchanged_file_not_rescanned(self) -> None:
        mon = self._monitor()
        mon.prime()
        (self.watch / "evil.bin").write_bytes(_MAL)
        self.assertEqual(len(mon.poll()), 1)
        # Second poll: file unchanged, must not re-report.
        self.assertEqual(mon.poll(), [])

    def test_changed_file_is_redetected(self) -> None:
        target = self.watch / "file.dat"
        target.write_bytes(_BENIGN)
        mon = self._monitor()
        mon.prime()
        self.assertEqual(mon.poll(), [])
        # Overwrite with malware (different size → fingerprint changes).
        target.write_bytes(_MAL)
        detections = mon.poll()
        self.assertEqual(len(detections), 1)

    def test_auto_quarantine_moves_file(self) -> None:
        q = Quarantine(root=self.root / "q", audit=self.audit)
        mon = self._monitor(auto_quarantine=True, quarantine=q)
        mon.prime()
        evil = self.watch / "evil.bin"
        evil.write_bytes(_MAL)
        mon.poll()
        self.assertFalse(evil.exists())
        self.assertEqual(len(q.list_items()), 1)
        self.assertEqual(mon.stats.quarantined, 1)

    def test_run_loop_detects_then_stops(self) -> None:
        """Drive the real run() loop without arbitrary sleeps.

        ``on_tick`` fires right after the baseline is primed; we use that
        moment to drop the malware (guaranteed post-prime, so it is seen as
        *new*). The detection callback then sets the stop event, so the loop
        exits on its own and ``join`` returns promptly.
        """
        mon = self._monitor(interval=0.1)
        stop = threading.Event()
        detected: list = []
        primed = threading.Event()

        def on_tick(_scanned: int, _this_tick: int) -> None:
            if not primed.is_set():
                primed.set()
                (self.watch / "evil.bin").write_bytes(_MAL)

        def on_det(result) -> None:
            detected.append(result)
            stop.set()

        t = threading.Thread(
            target=lambda: mon.run(stop, on_detection=on_det, on_tick=on_tick)
        )
        t.start()
        t.join(timeout=5.0)
        self.assertFalse(t.is_alive(), "monitor loop did not stop")
        self.assertEqual(len(detected), 1)

    def test_transient_scan_failure_is_retried_without_file_changes(self) -> None:
        target = self.watch / "retry.bin"
        target.write_bytes(_MAL)
        mon = self._monitor()
        with patch.object(mon.scanner, "scan_file", return_value=ScanResult(target, Verdict.ERROR, error="access denied")):
            self.assertEqual(mon.poll(), [])
        self.assertEqual(len(mon.poll()), 1)

    def test_replacement_same_size_and_mtime_is_scanned(self) -> None:
        target = self.watch / "replace.bin"
        target.write_bytes(b"x" * len(_MAL))
        original = target.stat()
        mon = self._monitor()
        mon.prime()
        replacement = self.root / "new.bin"
        replacement.write_bytes(_MAL)
        os.utime(replacement, ns=(original.st_atime_ns, original.st_mtime_ns))
        replacement.replace(target)
        self.assertEqual(len(mon.poll()), 1)

    def test_deleted_paths_are_removed_from_snapshot(self) -> None:
        target = self.watch / "gone.txt"
        target.write_bytes(_BENIGN)
        mon = self._monitor()
        mon.prime()
        target.unlink()
        mon.poll()
        self.assertEqual(mon._snapshot, {})

    def test_real_permission_denial_is_error_and_recovers(self) -> None:
        target = self.watch / "private.bin"
        target.write_bytes(_MAL)
        target.chmod(0)
        try:
            if os.access(target, os.R_OK):
                self.skipTest("Current user can bypass file mode permissions")
            self.assertEqual(_scanner().scan_file(target).verdict, Verdict.ERROR)
        finally:
            target.chmod(0o600)
        self.assertEqual(_scanner().scan_file(target).verdict, Verdict.INFECTED)

    def test_audit_records_monitor_events(self) -> None:
        mon = self._monitor()
        mon.prime()
        (self.watch / "evil.bin").write_bytes(_MAL)
        mon.poll()
        events = [e.event for e in self.audit.read_recent()]
        self.assertIn("monitor.detection", events)


if __name__ == "__main__":
    unittest.main()
