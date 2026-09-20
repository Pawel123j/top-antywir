"""Append-only audit log for Top Antywir.

Records every scan and quarantine action as one JSON object per line in
the user's local log directory. The log is never rotated or pruned by
the application — it is small (one record per scan) and the user owns
it. Errors writing the log are intentionally swallowed: an audit-log
failure must never block actual scanning.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .paths import log_dir


@dataclass
class AuditEntry:
    timestamp: str
    event: str
    data: dict[str, Any] = field(default_factory=dict)


class AuditLog:
    def __init__(self, path: Path | None = None) -> None:
        self.path = (path or log_dir() / "audit.jsonl").expanduser()

    def log(self, event: str, **data: Any) -> None:
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            event=event,
            data=_jsonable(data),
        )
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps(asdict(entry), ensure_ascii=False)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            # Never crash the scanner because of audit-log issues.
            pass

    def read_recent(self, limit: int = 50) -> list[AuditEntry]:
        """Return the last ``limit`` entries (newest first)."""
        if not self.path.exists():
            return []
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        entries: list[AuditEntry] = []
        for raw in lines[-limit:]:
            try:
                obj = json.loads(raw)
                entries.append(AuditEntry(
                    timestamp=obj.get("timestamp", ""),
                    event=obj.get("event", ""),
                    data=obj.get("data", {}),
                ))
            except json.JSONDecodeError:
                continue
        entries.reverse()
        return entries


def _jsonable(value: Any) -> Any:
    """Recursively coerce common non-JSON types (Path, set, …) to strings/lists."""
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(v) for v in value]
    return value
