"""Tests for the audit log."""
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from top_antywir.audit import AuditLog
from top_antywir.quarantine import Quarantine
from top_antywir.scanner import Scanner
from top_antywir.signatures import HashSignature


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

    def test_quarantine_and_restore_history_is_recorded(self) -> None:
        # UTF-8 Polish name (any OS) and the same name as CP1250 bytes on a
        # UTF-8 filesystem, which Python exposes with lone surrogates.
        names = {"utf8": "zażółć.bin", "cp1250": "za\udcbf\udcf3\udcb3\udce6.bin"}
        payload = b"\x10TOP-ANTYWIR-AUDIT-HISTORY\x20" * 3
        scanner = Scanner(
            hash_signatures=(HashSignature(
                "Audit-Test", hashlib.sha256(payload).hexdigest(), "high", "test",
            ),),
            pattern_signatures=(),
        )
        for label, name in names.items():
            with self.subTest(name=label):
                root = Path(self._tmp.name) / label
                root.mkdir()
                source = root / name
                try:
                    source.write_bytes(payload)
                except (OSError, UnicodeEncodeError):
                    self.skipTest("filesystem cannot store this file name")
                log = AuditLog(path=root / "audit.jsonl")
                quarantine = Quarantine(root / "q", audit=log)

                item = quarantine.add(scanner.scan_file(source))
                restored = quarantine.restore(item.item_id)

                self.assertEqual(restored.read_bytes(), payload)
                restore, add = log.read_recent(limit=2)
                self.assertEqual((add.event, restore.event),
                                 ("quarantine.add", "quarantine.restore"))
                self.assertEqual(add.data["item_id"], restore.data["item_id"])
                self.assertEqual(add.data["item_id"], item.item_id)
                self.assertEqual(add.data["original_path"], str(item.original_path))
                self.assertEqual(restore.data["restored_to"], str(restored))
                self.assertEqual(add.data["findings"], ["Audit-Test"])
                # Every record is strict UTF-8 JSON.
                for raw in log.path.read_bytes().decode("utf-8").splitlines():
                    json.loads(raw)

    def test_unserialisable_data_does_not_raise(self) -> None:
        self.log.log("event", value=object())  # should not raise


if __name__ == "__main__":
    unittest.main()
