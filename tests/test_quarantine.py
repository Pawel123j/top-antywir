"""Tests for the Quarantine module (delete, restore, disarm, audit).

These tests avoid the EICAR test string because real antivirus software
on the test machine (Windows Defender, ClamAV) will race the test and
quarantine the file out from under us. Instead we create a custom
HashSignature matching an arbitrary controllable byte payload.
"""
from __future__ import annotations

import hashlib
import stat
import tempfile
import unittest
from pathlib import Path

from top_antywir.audit import AuditLog
from top_antywir.paths import is_windows
from top_antywir.quarantine import Quarantine
from top_antywir.scanner import Scanner, Verdict
from top_antywir.signatures import HashSignature

# A harmless byte string with no malware-like markers; reproducible hash.
_PAYLOAD = b"\x10\x20TOP-ANTYWIR-TEST-PAYLOAD\x30\x40" * 4
_PAYLOAD_SHA = hashlib.sha256(_PAYLOAD).hexdigest()
_TEST_SIGNATURE = (
    HashSignature(
        name="Test-Payload",
        sha256=_PAYLOAD_SHA,
        severity="high",
        description="Synthetic payload used by Top Antywir's test suite.",
    ),
)


class QuarantineTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.audit_path = self.root / "audit.jsonl"
        self.audit = AuditLog(path=self.audit_path)
        self.q = Quarantine(root=self.root / "q", audit=self.audit)
        self.scanner = Scanner(hash_signatures=_TEST_SIGNATURE)

        self.src = self.root / "payload.bin"
        self.src.write_bytes(_PAYLOAD)
        self.scan_result = self.scanner.scan_file(self.src)
        self.assertEqual(self.scan_result.verdict, Verdict.INFECTED,
                         f"Expected INFECTED, got {self.scan_result.verdict} "
                         f"(error: {self.scan_result.error})")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_add_moves_file_and_records_metadata(self) -> None:
        item = self.q.add(self.scan_result)
        self.assertFalse(self.src.exists())
        self.assertTrue(item.stored_path.exists())
        self.assertEqual(len(self.q.list_items()), 1)

    def test_add_disarms_file_permissions(self) -> None:
        item = self.q.add(self.scan_result)
        if not is_windows():
            mode = stat.S_IMODE(item.stored_path.stat().st_mode)
            # No execute bits, no group/other access.
            self.assertEqual(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH), 0)
            self.assertEqual(
                mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH),
                0,
            )

    def test_restore_returns_file_to_original_location(self) -> None:
        item = self.q.add(self.scan_result)
        restored = self.q.restore(item.item_id)
        self.assertEqual(restored, self.src)
        self.assertTrue(self.src.exists())
        self.assertEqual(len(self.q.list_items()), 0)

    def test_restore_to_alternate_path(self) -> None:
        item = self.q.add(self.scan_result)
        alt = self.root / "restored_here.bin"
        restored = self.q.restore(item.item_id, alt)
        self.assertEqual(restored.resolve(), alt.resolve())
        self.assertTrue(alt.exists())

    def test_restore_refuses_when_destination_exists(self) -> None:
        item = self.q.add(self.scan_result)
        self.src.write_text("placeholder")  # recreate at original path
        with self.assertRaises(FileExistsError):
            self.q.restore(item.item_id)

    def test_delete_purges_file_and_metadata(self) -> None:
        item = self.q.add(self.scan_result)
        self.q.delete(item.item_id)
        self.assertFalse(item.stored_path.exists())
        self.assertEqual(len(self.q.list_items()), 0)

    def test_delete_raises_for_unknown_id(self) -> None:
        with self.assertRaises(FileNotFoundError):
            self.q.delete("not-a-real-id")

    def test_audit_log_records_actions(self) -> None:
        item = self.q.add(self.scan_result)
        self.q.delete(item.item_id)

        events = [e.event for e in self.audit.read_recent()]
        self.assertIn("quarantine.add",    events)
        self.assertIn("quarantine.delete", events)


if __name__ == "__main__":
    unittest.main()
