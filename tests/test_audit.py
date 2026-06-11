"""Tests for the audit log."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from top_antywir.audit import AuditLog


class AuditLogTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.log_path = Path(self._tmp.name) / "audit.jsonl"
        self.log = AuditLog(path=self.log_path)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_log_appends_jsonl_line(self) -> None:
        target = Path("/tmp")
        self.log.log("scan.start", mode="quick", targets=[target])
        self.assertTrue(self.log_path.exists())
        lines = self.log_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        record = json.loads(lines[0])
        self.assertEqual(record["event"], "scan.start")
        self.assertEqual(record["data"]["mode"], "quick")
        # Paths are coerced via str(), which uses the OS native separator.
        # Just verify the coercion happened, don't pin to a specific format.
        self.assertEqual(record["data"]["targets"], [str(target)])
        self.assertIsInstance(record["data"]["targets"][0], str)

    def test_multiple_entries_append(self) -> None:
        self.log.log("a", x=1)
        self.log.log("b", x=2)
        self.log.log("c", x=3)
        lines = self.log_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 3)

    def test_read_recent_returns_newest_first(self) -> None:
        for i in range(5):
            self.log.log("event", n=i)
        entries = self.log.read_recent(limit=3)
        ns = [e.data["n"] for e in entries]
        self.assertEqual(ns, [4, 3, 2])

    def test_read_recent_returns_empty_when_no_log(self) -> None:
        log = AuditLog(path=Path(self._tmp.name) / "missing.jsonl")
        self.assertEqual(log.read_recent(), [])

    def test_log_swallows_io_failure(self) -> None:
        # Pointing at a directory rather than a file is guaranteed to fail
        # but should NOT raise — the audit log must never crash callers.
        bad = AuditLog(path=Path(self._tmp.name))
        bad.log("event", x=1)  # should not raise


if __name__ == "__main__":
    unittest.main()
