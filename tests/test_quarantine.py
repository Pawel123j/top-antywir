"""Tests for the Quarantine module (delete, restore, disarm, audit).

These tests avoid the EICAR test string because real antivirus software
on the test machine (Windows Defender, ClamAV) will race the test and
quarantine the file out from under us. Instead we create a custom
HashSignature matching an arbitrary controllable byte payload.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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
        self.assertEqual(self.src.read_text(), "placeholder")
        self.assertEqual(item.stored_path.read_bytes(), _PAYLOAD)

    def test_metadata_failure_leaves_original_untouched(self) -> None:
        with (
            patch.object(self.q, "_write_metadata", side_effect=OSError("disk full")),
            self.assertRaises(OSError),
        ):
            self.q.add(self.scan_result)
        self.assertEqual(self.src.read_bytes(), _PAYLOAD)
        self.assertEqual(self.q.list_items(), [])
        self.assertEqual(list(self.q.files_dir.iterdir()), [])

    def test_metadata_flush_failure_never_moves_source(self) -> None:
        with (
            patch("top_antywir.quarantine.os.fsync", side_effect=OSError("flush failed")),
            self.assertRaises(OSError),
        ):
            self.q.add(self.scan_result)
        self.assertEqual(self.src.read_bytes(), _PAYLOAD)
        self.assertEqual(self.q.list_items(), [])

    def test_move_failure_before_move_leaves_original_and_no_visible_item(self) -> None:
        with (
            patch.object(self.q, "_copy_then_remove", side_effect=OSError("move failed")),
            self.assertRaises(OSError),
        ):
            self.q.add(self.scan_result)
        self.assertEqual(self.src.read_bytes(), _PAYLOAD)
        restarted = Quarantine(self.q.root, audit=self.audit)
        self.assertEqual(restarted.list_items(), [])

    def test_exception_after_move_is_recoverable_without_rollback(self) -> None:
        real_move = self.q._copy_then_remove

        def move_then_fail(source, destination):
            real_move(source, destination)
            raise OSError("failure after move; no further writes available")

        with (
            patch.object(self.q, "_copy_then_remove", side_effect=move_then_fail),
            self.assertRaises(OSError),
        ):
            self.q.add(self.scan_result)
        self.assertFalse(self.src.exists())
        restarted = Quarantine(self.q.root, audit=self.audit)
        item, = restarted.list_items()
        self.assertFalse(item.recovery_required)
        self.assertEqual(item.stored_path.read_bytes(), _PAYLOAD)
        self.assertEqual(restarted.restore(item.item_id), self.src)
        self.assertEqual(self.src.read_bytes(), _PAYLOAD)

    def test_process_interruption_after_move_keeps_recovery_journal(self) -> None:
        with (
            patch.object(self.q, "_disarm", side_effect=SystemExit("interrupted")),
            self.assertRaises(SystemExit),
        ):
            self.q.add(self.scan_result)
        restarted = Quarantine(self.q.root, audit=self.audit)
        item, = restarted.list_items()
        self.assertEqual(restarted.restore(item.item_id).read_bytes(), _PAYLOAD)

    def test_missing_or_damaged_metadata_does_not_hide_payload(self) -> None:
        item = self.q.add(self.scan_result)
        meta_path = self.q.meta_dir / f"{item.item_id}.json"
        for contents in (None, "{broken", "null", "{}", '"text"'):
            with self.subTest(contents=contents):
                if contents is None:
                    meta_path.unlink(missing_ok=True)
                else:
                    meta_path.write_text(contents)
                recovered, = Quarantine(self.q.root, audit=self.audit).list_items()
                self.assertTrue(recovered.recovery_required)
                self.assertEqual(recovered.stored_path.read_bytes(), _PAYLOAD)
                with self.assertRaises(FileExistsError):
                    self.q.restore(item.item_id)
        destination = self.root / "recovered.bin"
        self.assertEqual(self.q.restore(item.item_id, destination).read_bytes(), _PAYLOAD)

    def test_metadata_stored_path_cannot_redirect_delete(self) -> None:
        item = self.q.add(self.scan_result)
        unrelated = self.root / "unrelated.bin"
        unrelated.write_bytes(b"keep me")
        meta_path = self.q.meta_dir / f"{item.item_id}.json"
        metadata = json.loads(meta_path.read_text())
        metadata["stored_path"] = str(unrelated)
        meta_path.write_text(json.dumps(metadata))
        self.q.delete(item.item_id)
        self.assertEqual(unrelated.read_bytes(), b"keep me")

    def test_legacy_journal_without_size_remains_restorable(self) -> None:
        item = self.q.add(self.scan_result)
        meta_path = self.q.meta_dir / f"{item.item_id}.json"
        metadata = json.loads(meta_path.read_text())
        del metadata["size_bytes"]
        meta_path.write_text(json.dumps(metadata))
        self.assertFalse(self.q.list_items()[0].recovery_required)
        self.assertEqual(self.q.restore(item.item_id).read_bytes(), _PAYLOAD)

    def test_destination_directory_flush_failure_does_not_remove_source(self) -> None:
        real_sync = self.q._sync_directory

        def fail_payload_directory(path):
            if path == self.q.files_dir:
                raise OSError("directory flush failed")
            real_sync(path)

        with (
            patch.object(Quarantine, "_sync_directory", side_effect=fail_payload_directory),
            self.assertRaisesRegex(OSError, "directory flush failed"),
        ):
            self.q.add(self.scan_result)
        self.assertEqual(self.src.read_bytes(), _PAYLOAD)
        self.assertEqual(self.q.list_items(), [])

    def test_destination_replaced_during_transfer_preserves_source_and_new_data(self) -> None:
        real_sync = self.q._sync_directory

        def replace_destination(path):
            real_sync(path)
            if path == self.q.files_dir:
                destination, = self.q.files_dir.iterdir()
                replacement = self.root / "replacement.bin"
                replacement.write_bytes(b"new user data")
                replacement.replace(destination)

        with (
            patch.object(Quarantine, "_sync_directory", side_effect=replace_destination),
            self.assertRaisesRegex(OSError, "Destination changed"),
        ):
            self.q.add(self.scan_result)
        self.assertEqual(self.src.read_bytes(), _PAYLOAD)
        destination, = self.q.files_dir.iterdir()
        self.assertEqual(destination.read_bytes(), b"new user data")

    def test_id_traversal_is_rejected(self) -> None:
        for item_id in ("../payload", "../" + "a" * 32, "/tmp/file", "a" * 31):
            with self.subTest(item_id=item_id):
                with self.assertRaises(FileNotFoundError):
                    self.q.restore(item_id)
                with self.assertRaises(FileNotFoundError):
                    self.q.delete(item_id)
        self.assertEqual(self.src.read_bytes(), _PAYLOAD)

    def test_restore_partial_copy_failure_keeps_complete_quarantine_copy(self) -> None:
        item = self.q.add(self.scan_result)

        def partial_copy(source, target):
            target.write(source.read(5))
            raise OSError("disk full")

        with (
            patch("top_antywir.quarantine.shutil.copyfileobj", side_effect=partial_copy),
            self.assertRaises(OSError),
        ):
            self.q.restore(item.item_id)
        self.assertFalse(self.src.exists())
        self.assertEqual(item.stored_path.read_bytes(), _PAYLOAD)
        self.assertEqual(len(self.q.list_items()), 1)

    def test_add_partial_copy_failure_preserves_original(self) -> None:
        def partial_copy(source, target):
            target.write(source.read(5))
            raise OSError("disk full")

        with (
            patch("top_antywir.quarantine.shutil.copyfileobj", side_effect=partial_copy),
            self.assertRaises(OSError),
        ):
            self.q.add(self.scan_result)
        self.assertEqual(self.src.read_bytes(), _PAYLOAD)
        self.assertEqual(self.q.list_items(), [])

    def test_interrupted_partial_add_is_marked_for_recovery_after_restart(self) -> None:
        # A process termination cannot run copy cleanup. Reproduce the on-disk
        # state left by it: durable journal, short destination, intact original.
        with (
            patch.object(self.q, "_copy_then_remove", side_effect=OSError("stopped")),
            self.assertRaises(OSError),
        ):
            self.q.add(self.scan_result)
        metadata_path, = self.q.meta_dir.glob("*.json")
        (self.q.files_dir / metadata_path.stem).write_bytes(_PAYLOAD[:5])
        recovered, = Quarantine(self.q.root, audit=self.audit).list_items()
        self.assertTrue(recovered.recovery_required)
        self.assertEqual(recovered.original_path, self.src)
        self.assertEqual(self.src.read_bytes(), _PAYLOAD)
        with self.assertRaises(FileExistsError):
            self.q.restore(recovered.item_id)

    def test_source_modified_during_copy_is_not_removed(self) -> None:
        def changed_copy(source, target):
            target.write(source.read())
            self.src.write_bytes(b"new user content")

        with (
            patch("top_antywir.quarantine.shutil.copyfileobj", side_effect=changed_copy),
            self.assertRaisesRegex(OSError, "Source changed"),
        ):
            self.q.add(self.scan_result)
        self.assertEqual(self.src.read_bytes(), b"new user content")
        self.assertEqual(self.q.list_items(), [])

    def test_failed_partial_copy_cleanup_still_preserves_quarantined_file(self) -> None:
        item = self.q.add(self.scan_result)
        unlink = Path.unlink

        def partial_copy(source, target):
            target.write(source.read(5))
            raise OSError("disk full")

        def fail_cleanup(path, *args, **kwargs):
            if path == self.src:
                raise OSError("cleanup denied")
            return unlink(path, *args, **kwargs)

        with (
            patch("top_antywir.quarantine.shutil.copyfileobj", side_effect=partial_copy),
            patch.object(Path, "unlink", fail_cleanup),
            self.assertRaises(OSError),
        ):
            self.q.restore(item.item_id)
        self.assertEqual(self.src.read_bytes(), _PAYLOAD[:5])
        restarted = Quarantine(self.q.root, audit=self.audit)
        recovered, = restarted.list_items()
        destination = self.root / "recovered.bin"
        self.assertEqual(restarted.restore(recovered.item_id, destination).read_bytes(), _PAYLOAD)

    def test_restore_unlink_failure_preserves_both_complete_copies(self) -> None:
        item = self.q.add(self.scan_result)
        unlink = Path.unlink

        def fail_unlink(path, *args, **kwargs):
            if path == item.stored_path:
                raise OSError("unlink denied")
            return unlink(path, *args, **kwargs)

        with (
            patch.object(Path, "unlink", fail_unlink),
            self.assertRaises(OSError),
        ):
            self.q.restore(item.item_id)
        self.assertEqual(self.src.read_bytes(), _PAYLOAD)
        self.assertEqual(item.stored_path.read_bytes(), _PAYLOAD)
        self.assertEqual(len(self.q.list_items()), 1)

    def test_restore_rejects_destination_created_concurrently(self) -> None:
        item = self.q.add(self.scan_result)
        original_open = os.open

        def race_open(path, flags, *args, **kwargs):
            if path == self.src and flags & os.O_EXCL:
                self.src.write_bytes(b"new user data")
            return original_open(path, flags, *args, **kwargs)

        with (
            patch("top_antywir.quarantine.os.open", side_effect=race_open),
            self.assertRaises(FileExistsError),
        ):
            self.q.restore(item.item_id)
        self.assertEqual(self.src.read_bytes(), b"new user data")
        self.assertEqual(item.stored_path.read_bytes(), _PAYLOAD)

    @unittest.skipIf(is_windows(), "POSIX mode bits do not describe Windows ACLs")
    def test_payload_and_journal_are_private_during_transfer(self) -> None:
        def checked_copy(source, target):
            self.assertEqual(stat.S_IMODE(os.fstat(target.fileno()).st_mode), 0o600)
            journal, = self.q.meta_dir.glob("*.json")
            self.assertEqual(stat.S_IMODE(journal.stat().st_mode), 0o600)
            target.write(source.read())

        with patch("top_antywir.quarantine.shutil.copyfileobj", side_effect=checked_copy):
            self.q.add(self.scan_result)

    @unittest.skipIf(is_windows(), "symlinks require platform privileges on Windows")
    def test_symlink_payload_and_dangling_restore_target_are_rejected(self) -> None:
        link = self.root / "link.bin"
        link.symlink_to(self.src)
        self.scan_result.path = link
        with self.assertRaises(ValueError):
            self.q.add(self.scan_result)
        self.scan_result.path = self.src
        item = self.q.add(self.scan_result)
        referent = self.root / "must-not-be-created.bin"
        self.src.symlink_to(referent)
        with self.assertRaises(FileExistsError):
            self.q.restore(item.item_id)
        self.assertFalse(referent.exists())
        self.assertEqual(item.stored_path.read_bytes(), _PAYLOAD)

    @unittest.skipIf(is_windows(), "symlinks require platform privileges on Windows")
    def test_quarantine_directory_symlink_is_rejected(self) -> None:
        self.q.root.mkdir(parents=True)
        self.q.files_dir.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            self.q.add(self.scan_result)
        self.assertEqual(self.src.read_bytes(), _PAYLOAD)

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
