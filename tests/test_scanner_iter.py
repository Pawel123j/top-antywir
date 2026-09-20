"""Tests for the streaming scanner (iter_scan, exclusions, stop event)."""
from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from top_antywir.scanner import Scanner, Verdict


class IterScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.scanner = Scanner()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _make_files(self, count: int) -> None:
        for i in range(count):
            (self.root / f"file_{i:03d}.txt").write_text(f"content {i}")

    def test_iter_scan_walks_all_files(self) -> None:
        self._make_files(15)
        results = list(self.scanner.iter_scan([self.root]))
        self.assertEqual(len(results), 15)
        for r in results:
            self.assertEqual(r.verdict, Verdict.CLEAN)

    def test_iter_scan_skips_excluded_directories(self) -> None:
        self._make_files(5)
        # These directory names should be pruned by EXCLUDED_DIR_NAMES.
        for forbidden in ("node_modules", ".git", "__pycache__"):
            sub = self.root / forbidden
            sub.mkdir()
            (sub / "leaked.txt").write_text("you-should-not-scan-me")

        results = list(self.scanner.iter_scan([self.root]))
        scanned_names = {r.path.name for r in results}
        self.assertEqual(scanned_names, {f"file_{i:03d}.txt" for i in range(5)})
        self.assertNotIn("leaked.txt", scanned_names)

    def test_stop_event_cancels_walk(self) -> None:
        self._make_files(30)
        stop = threading.Event()
        captured = []
        for i, r in enumerate(self.scanner.iter_scan([self.root], stop_event=stop)):
            captured.append(r)
            if i == 4:
                stop.set()
        # After the stop signal we may emit at most one more file
        # (the event is checked at the top of the loop), so 5-6 is fine.
        self.assertLessEqual(len(captured), 6)
        self.assertGreaterEqual(len(captured), 5)

    def test_iter_scan_handles_missing_target(self) -> None:
        results = list(self.scanner.iter_scan([self.root / "does-not-exist"]))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].verdict, Verdict.ERROR)

    def test_iter_scan_with_multiple_roots(self) -> None:
        root_a = self.root / "a"
        root_a.mkdir()
        root_b = self.root / "b"
        root_b.mkdir()
        (root_a / "x.txt").write_text("a")
        (root_b / "y.txt").write_text("b")
        results = list(self.scanner.iter_scan([root_a, root_b]))
        self.assertEqual(len(results), 2)


if __name__ == "__main__":
    unittest.main()
