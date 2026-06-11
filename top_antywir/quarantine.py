"""Local quarantine storage for detected files."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import stat
import uuid

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


class Quarantine:
    def __init__(self, root: Path | None = None, audit: AuditLog | None = None) -> None:
        self.root = (root or quarantine_dir()).expanduser()
        self.files_dir = self.root / "files"
        self.meta_dir = self.root / "metadata"
        self.audit = audit if audit is not None else AuditLog()

    def ensure(self) -> None:
        self.files_dir.mkdir(parents=True, exist_ok=True)
        self.meta_dir.mkdir(parents=True, exist_ok=True)

    def add(self, result: ScanResult) -> QuarantineItem:
        if not result.path.is_file():
            raise ValueError("Only files can be quarantined.")

        self.ensure()
        item_id = uuid.uuid4().hex
        stored_path = self.files_dir / item_id
        shutil.move(str(result.path), stored_path)
        self._disarm(stored_path)

        item = QuarantineItem(
            item_id=item_id,
            original_path=result.path,
            stored_path=stored_path,
            created_at=datetime.now(timezone.utc).isoformat(),
            verdict=result.verdict.value,
            findings=[finding.name for finding in result.findings],
        )
        self._write_metadata(item)
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
        for meta_file in sorted(self.meta_dir.glob("*.json")):
            items.append(self._read_metadata(meta_file))
        return items

    def restore(self, item_id: str, destination: Path | None = None) -> Path:
        self.ensure()
        metadata_path = self.meta_dir / f"{item_id}.json"
        if not metadata_path.exists():
            raise FileNotFoundError(f"Unknown quarantine item: {item_id}")

        item = self._read_metadata(metadata_path)
        target = destination.expanduser().resolve() if destination else item.original_path
        target.parent.mkdir(parents=True, exist_ok=True)

        if target.exists():
            raise FileExistsError(f"Destination already exists: {target}")

        shutil.move(str(item.stored_path), target)
        self._rearm(target)
        metadata_path.unlink()
        self.audit.log("quarantine.restore", item_id=item_id, restored_to=target)
        return target

    def delete(self, item_id: str) -> None:
        """Permanently remove a quarantined file and its metadata."""
        self.ensure()
        metadata_path = self.meta_dir / f"{item_id}.json"
        if not metadata_path.exists():
            raise FileNotFoundError(f"Unknown quarantine item: {item_id}")

        item = self._read_metadata(metadata_path)
        if item.stored_path.exists():
            # Clear any protective attributes (HIDDEN/READONLY) so
            # unlink succeeds on Windows even after _disarm.
            self._rearm(item.stored_path)
            item.stored_path.unlink()
        metadata_path.unlink()
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
        }
        (self.meta_dir / f"{item.item_id}.json").write_text(
            json.dumps(payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def _read_metadata(self, metadata_path: Path) -> QuarantineItem:
        payload = json.loads(metadata_path.read_text(encoding="utf-8"))
        return QuarantineItem(
            item_id=payload["item_id"],
            original_path=Path(payload["original_path"]),
            stored_path=Path(payload["stored_path"]),
            created_at=payload["created_at"],
            verdict=payload["verdict"],
            findings=list(payload["findings"]),
        )

