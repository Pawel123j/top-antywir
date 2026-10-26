"""Local quarantine storage for detected files."""

from __future__ import annotations

import json
import os
import shutil
import stat
import uuid
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .audit import AuditLog
from .paths import is_windows, quarantine_dir
from .scanner import ScanResult


@dataclass(frozen=True)
class QuarantineItem:
    item_id: str
    original_path: Path
    stored_path: Path
    created_at: str
    verdict: str
    findings: list[str]
    size_bytes: int | None = None
    recovery_required: bool = False


class Quarantine:
    def __init__(self, root: Path | None = None, audit: AuditLog | None = None) -> None:
        self.root = (root or quarantine_dir()).expanduser().resolve()
        self.files_dir = self.root / "files"
        self.meta_dir = self.root / "metadata"
        self.audit = audit if audit is not None else AuditLog()

    def ensure(self) -> None:
        if self.files_dir.is_symlink() or self.meta_dir.is_symlink():
            raise OSError("Quarantine directories must not be symbolic links.")
        self.files_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.meta_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    def add(self, result: ScanResult) -> QuarantineItem:
        if result.path.is_symlink() or not result.path.is_file():
            raise ValueError("Only regular files, not symbolic links, can be quarantined.")

        self.ensure()
        item_id = uuid.uuid4().hex
        stored_path = self.files_dir / item_id
        if stored_path.exists() or stored_path.is_symlink():
            raise FileExistsError(f"Quarantine destination already exists: {stored_path}")
        item = QuarantineItem(
            item_id=item_id,
            original_path=result.path.absolute(),
            stored_path=stored_path,
            created_at=datetime.now(timezone.utc).isoformat(),
            verdict=result.verdict.value,
            findings=[finding.name for finding in result.findings],
            size_bytes=result.path.stat().st_size,
        )
        # Write and flush the recovery journal BEFORE moving any user data.
        # If the move fails before moving, the original remains. If it fails
        # after moving, or the process exits here, list/restore can still find
        # the stored file. No fallible rollback is needed to discover it.
        self._write_metadata(item)
        self._copy_then_remove(result.path, stored_path)
        self._disarm(stored_path)
        self.audit.log(
            "quarantine.add",
            item_id=item.item_id,
            original_path=item.original_path,
            verdict=item.verdict,
            findings=item.findings,
        )
        return item

    @staticmethod
    def _disarm(path: Path) -> None:
        """Make a quarantined file non-executable / hidden.

        Best-effort: failures are swallowed because the file is already
        in a private directory and stored under a UUID without an
        extension, so the OS won't double-click-execute it anyway.
        """
        try:
            if path.is_symlink():
                return
            if is_windows():
                # Hide from Explorer; we intentionally avoid READONLY so
                # the file can still be deleted/restored programmatically.
                import ctypes
                FILE_ATTRIBUTE_HIDDEN = 0x02
                FILE_ATTRIBUTE_SYSTEM = 0x04
                ctypes.windll.kernel32.SetFileAttributesW(
                    str(path), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
                )
            else:
                # Drop execute bits everywhere; keep owner-read so we can
                # still inspect the file later if needed.
                os.chmod(path, stat.S_IRUSR)
        except (OSError, AttributeError):
            pass

    @staticmethod
    def _rearm(path: Path) -> None:
        """Restore reasonable permissions when a file leaves quarantine."""
        try:
            if path.is_symlink():
                return
            if is_windows():
                import ctypes
                FILE_ATTRIBUTE_NORMAL = 0x80
                ctypes.windll.kernel32.SetFileAttributesW(str(path), FILE_ATTRIBUTE_NORMAL)
            else:
                os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except (OSError, AttributeError):
            pass

    def list_items(self) -> list[QuarantineItem]:
        self.ensure()
        items: list[QuarantineItem] = []
        # Iterate payloads, not journals: an interrupted add before the move
        # leaves a harmless journal with its original still in place. Old
        # orphaned payloads and damaged metadata must remain discoverable.
        for stored_path in sorted(self.files_dir.iterdir()):
            if (
                self._valid_id(stored_path.name)
                and not stored_path.is_symlink()
                and stored_path.is_file()
            ):
                items.append(self._find_item(stored_path.name))
        return items

    def restore(self, item_id: str, destination: Path | None = None) -> Path:
        self.ensure()
        item = self._find_item(item_id)
        metadata_path = self.meta_dir / f"{item_id}.json"
        if item.recovery_required and destination is None:
            raise FileExistsError(
                "Recovery entry: check the original file, then choose an explicit new path."
            )
        # Do not resolve the final component: a dangling destination symlink
        # is occupied too, and must not cause a write to its referent.
        target = destination.expanduser().absolute() if destination else item.original_path
        target.parent.mkdir(parents=True, exist_ok=True)
        self._copy_then_remove(item.stored_path, target)
        self._rearm(target)
        metadata_path.unlink(missing_ok=True)
        self.audit.log("quarantine.restore", item_id=item_id, restored_to=target)
        return target

    def delete(self, item_id: str) -> None:
        """Permanently remove a quarantined file and its metadata."""
        self.ensure()
        item = self._find_item(item_id)
        metadata_path = self.meta_dir / f"{item_id}.json"
        if item.stored_path.exists():
            # Clear any protective attributes (HIDDEN/READONLY) so
            # unlink succeeds on Windows even after _disarm.
            self._rearm(item.stored_path)
            item.stored_path.unlink()
        metadata_path.unlink(missing_ok=True)
        self.audit.log(
            "quarantine.delete",
            item_id=item_id,
            original_path=item.original_path,
        )

    def _write_metadata(self, item: QuarantineItem) -> None:
        payload = {
            "item_id": item.item_id,
            "original_path": str(item.original_path),
            "stored_path": str(item.stored_path),
            "created_at": item.created_at,
            "verdict": item.verdict,
            "findings": item.findings,
            "size_bytes": item.size_bytes,
        }
        # IDs are new, so exclusive create also avoids replacing a preexisting
        # journal. An incomplete write never moves the original file.
        descriptor = os.open(
            self.meta_dir / f"{item.item_id}.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        self._sync_directory(self.meta_dir)

    @staticmethod
    def _sync_directory(path: Path) -> None:
        """Persist new directory entries before deleting a source on POSIX."""
        if os.name == "posix":
            descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    def _read_metadata(self, metadata_path: Path) -> QuarantineItem:
        if metadata_path.is_symlink():
            raise ValueError("Metadata must not be a symbolic link.")
        payload = json.loads(metadata_path.read_text(encoding="utf-8"))
        item_id = metadata_path.stem
        if (
            not isinstance(payload, dict)
            or payload.get("item_id") != item_id
            or not isinstance(payload.get("original_path"), str)
            or not Path(payload["original_path"]).is_absolute()
            or not isinstance(payload.get("created_at"), str)
            or not isinstance(payload.get("verdict"), str)
            or not isinstance(payload.get("findings"), list)
            or not all(isinstance(value, str) for value in payload["findings"])
            or (
                payload.get("size_bytes") is not None
                and (type(payload["size_bytes"]) is not int or payload["size_bytes"] < 0)
            )
        ):
            raise ValueError("Invalid quarantine metadata.")
        # Never trust a stored_path supplied by JSON to restore/delete another
        # file. Existing journals keep their format; the UUID determines data.
        expected_size = payload.get("size_bytes")
        stored_path = self.files_dir / item_id
        incomplete = expected_size is not None and stored_path.stat().st_size != expected_size
        findings = list(payload["findings"])
        if incomplete:
            findings.append(
                "Incomplete transfer; check the original path before recovering a copy."
            )
        return QuarantineItem(
            item_id=item_id,
            original_path=Path(payload["original_path"]),
            stored_path=stored_path,
            created_at=payload["created_at"],
            verdict="recovery" if incomplete else payload["verdict"],
            findings=findings,
            size_bytes=expected_size,
            recovery_required=incomplete,
        )

    @staticmethod
    def _valid_id(item_id: str) -> bool:
        return len(item_id) == 32 and all(char in "0123456789abcdef" for char in item_id)

    def _find_item(self, item_id: str) -> QuarantineItem:
        if not self._valid_id(item_id):
            raise FileNotFoundError(f"Unknown quarantine item: {item_id}")
        stored_path = self.files_dir / item_id
        if stored_path.is_symlink() or not stored_path.is_file():
            raise FileNotFoundError(f"Quarantine payload is unavailable: {item_id}")
        try:
            return self._read_metadata(self.meta_dir / f"{item_id}.json")
        except (OSError, ValueError, TypeError):
            return QuarantineItem(
                item_id=item_id,
                original_path=stored_path,
                stored_path=stored_path,
                created_at=datetime.fromtimestamp(
                    stored_path.stat().st_mtime, timezone.utc,
                ).isoformat(),
                verdict="recovery",
                findings=["Metadata unavailable; recover to an explicit new path."],
                recovery_required=True,
            )

    @staticmethod
    def _copy_then_remove(source: Path, target: Path) -> None:
        """Copy exclusively, flush, then remove source; never replace a target.

        A crash during copy leaves the complete source in place. A failed
        source unlink leaves both copies. Used in both directions, so it also
        works across filesystems without shutil.move's partial-copy ambiguity.
        Exclusive creation rejects a target that appears concurrently.
        """
        descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        created_stat = None
        try:
            with os.fdopen(descriptor, "rb") as incoming:
                source_stat = os.fstat(incoming.fileno())
                if not stat.S_ISREG(source_stat.st_mode):
                    raise OSError("Quarantine payload must be a regular file.")
                target_descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(target_descriptor, "wb") as outgoing:
                    created_stat = os.fstat(outgoing.fileno())
                    shutil.copyfileobj(incoming, outgoing)
                    outgoing.flush()
                    os.fsync(outgoing.fileno())
                    # Compare timestamps from the same API: on Windows 3.13,
                    # lstat's legacy ctime can mean creation time while fstat's
                    # ctime means metadata change time. Path identity is still
                    # checked separately to detect replacement or symlinks.
                    current_stat = os.fstat(incoming.fileno())
                    path_stat = source.lstat()
                    if (
                        not stat.S_ISREG(path_stat.st_mode)
                        or not os.path.samestat(path_stat, source_stat)
                        or current_stat.st_size != source_stat.st_size
                        or current_stat.st_mtime_ns != source_stat.st_mtime_ns
                        or current_stat.st_ctime_ns != source_stat.st_ctime_ns
                    ):
                        raise OSError("Source changed during transfer; it was not removed.")
                Quarantine._sync_directory(target.parent)
                if not os.path.samestat(target.lstat(), created_stat):
                    raise OSError("Destination changed during transfer; source was not removed.")
        except BaseException:
            # Only a partial file created by this operation may be cleaned up.
            # If cleanup fails, source is still intact and visible in quarantine.
            if created_stat is not None:
                with suppress(OSError):
                    if os.path.samestat(target.lstat(), created_stat):
                        target.unlink()
            raise
        source.unlink()

