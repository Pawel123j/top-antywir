"""User-extensible signature packs.

The built-in signatures in :mod:`signatures` are deliberately small. This
module lets a user (or a future auto-updater) drop additional *signature
packs* — plain JSON files — into the app data directory and have them
merged into every scan automatically.

There is no server and no code execution: a pack is **data**, never code.
Malformed entries are skipped with a recorded reason rather than crashing
a scan — a bad third-party pack must never take the scanner down.

Pack format (JSON)::

    {
      "name": "community-pack-2026-06",
      "hashes": [
        {"name": "Evil-Dropper", "sha256": "<64 hex>",
         "severity": "high", "description": "..."}
      ],
      "patterns": [
        {"name": "Suspicious-Thing", "regex": "foo.*bar",
         "flags": ["IGNORECASE", "DOTALL"],
         "severity": "medium", "description": "..."}
      ]
    }
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .paths import user_data_dir
from .signatures import (
    HASH_SIGNATURES,
    PATTERN_SIGNATURES,
    HashSignature,
    PatternSignature,
)

MAX_PACK_BYTES = 2 * 1024 * 1024
MAX_ENTRIES = 2000
MAX_FIELD_CHARS = 4096

VALID_SEVERITIES = frozenset({"low", "medium", "high"})

# Only a curated subset of re flags is honoured — enough for real
# signatures, nothing that could surprise (e.g. no VERBOSE whitespace
# foot-guns unless explicitly asked for).
_FLAG_MAP = {
    "IGNORECASE": re.IGNORECASE,
    "I": re.IGNORECASE,
    "DOTALL": re.DOTALL,
    "S": re.DOTALL,
    "MULTILINE": re.MULTILINE,
    "M": re.MULTILINE,
    "VERBOSE": re.VERBOSE,
    "X": re.VERBOSE,
}

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass
class LoadReport:
    """Outcome of loading one or more packs."""
    hashes: list[HashSignature] = field(default_factory=list)
    patterns: list[PatternSignature] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def extend(self, other: LoadReport) -> None:
        self.hashes.extend(other.hashes)
        self.patterns.extend(other.patterns)
        self.errors.extend(other.errors)


@dataclass
class ImportResult:
    name: str
    dest: Path
    hashes: int
    patterns: int
    errors: list[str] = field(default_factory=list)


def signatures_dir() -> Path:
    """Directory holding user signature packs (one ``*.json`` per pack)."""
    return user_data_dir() / "signatures"


# ── Loading ─────────────────────────────────────────────────────────────────

def load_pack(path: Path) -> LoadReport:
    """Parse a single pack file. Never raises — problems land in ``errors``."""
    report = LoadReport()
    try:
        with path.open("rb") as stream:
            raw_bytes = stream.read(MAX_PACK_BYTES + 1)
        if len(raw_bytes) > MAX_PACK_BYTES:
            report.errors.append(f"{path.name}: pack exceeds {MAX_PACK_BYTES} bytes")
            return report
        raw = raw_bytes.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        report.errors.append(f"{path.name}: cannot read ({exc})")
        return report

    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, RecursionError) as exc:
        report.errors.append(f"{path.name}: invalid JSON ({exc})")
        return report

    if not isinstance(data, dict):
        report.errors.append(f"{path.name}: top level must be a JSON object")
        return report

    pack_name = data.get("name", path.stem)
    if not isinstance(pack_name, str) or not pack_name or len(pack_name) > 256:
        report.errors.append(f"{path.name}: name must be a nonempty string up to 256 characters")
        return report
    for field_name in ("hashes", "patterns"):
        entries = data.get(field_name, [])
        if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
            report.errors.append(
                f"{pack_name}: {field_name} must be an array of up to {MAX_ENTRIES} entries"
            )
            return report

    for i, entry in enumerate(data.get("hashes", []) or []):
        sig, err = _parse_hash(entry, pack_name, i)
        if err:
            report.errors.append(err)
        elif sig is not None:
            report.hashes.append(sig)

    for i, entry in enumerate(data.get("patterns", []) or []):
        sig, err = _parse_pattern(entry, pack_name, i)
        if err:
            report.errors.append(err)
        elif sig is not None:
            report.patterns.append(sig)

    return report


def load_user_signatures(directory: Path | None = None) -> LoadReport:
    """Aggregate every ``*.json`` pack in ``directory`` (default: app dir)."""
    directory = directory or signatures_dir()
    report = LoadReport()
    try:
        if not directory.is_dir():
            return report
        pack_files = sorted(directory.glob("*.json"))
    except OSError as exc:
        report.errors.append(f"{directory}: cannot list ({exc})")
        return report

    for pack_file in pack_files:
        report.extend(load_pack(pack_file))
    return report


def all_signatures(
    directory: Path | None = None,
) -> tuple[tuple[HashSignature, ...], tuple[PatternSignature, ...]]:
    """Built-in signatures merged with valid user packs.

    De-duplicates hashes by sha256 and patterns by name, with the
    built-ins taking precedence (a user pack cannot silently override a
    shipped signature, only add to it).
    """
    user = load_user_signatures(directory)

    hashes: list[HashSignature] = list(HASH_SIGNATURES)
    seen_hashes = {sig.sha256.lower() for sig in hashes}
    for sig in user.hashes:
        if sig.sha256.lower() not in seen_hashes:
            hashes.append(sig)
            seen_hashes.add(sig.sha256.lower())

    patterns: list[PatternSignature] = list(PATTERN_SIGNATURES)
    seen_names = {sig.name for sig in patterns}
    for sig in user.patterns:
        if sig.name not in seen_names:
            patterns.append(sig)
            seen_names.add(sig.name)

    return tuple(hashes), tuple(patterns)


# ── Importing ─────────────────────────────────────────────────────────────────

def import_pack(src: Path, directory: Path | None = None) -> ImportResult:
    """Validate ``src`` and copy it into the signatures directory.

    Raises ``ValueError`` if the pack contains no usable signatures at all
    (so the CLI can report a hard failure); otherwise installs it and
    returns counts plus any per-entry warnings.
    """
    src = src.expanduser()
    report = load_pack(src)
    if not report.hashes and not report.patterns:
        detail = "; ".join(report.errors) or "no 'hashes' or 'patterns' found"
        raise ValueError(f"No usable signatures in {src.name}: {detail}")

    directory = directory or signatures_dir()
    directory.mkdir(parents=True, exist_ok=True)

    name = _sanitize_name(src.stem)
    dest = directory / f"{name}.json"
    # Re-serialise from the parsed content so we never copy arbitrary
    # extra keys, and so the stored file is normalised/pretty-printed.
    dest.write_text(_serialise(report, name), encoding="utf-8")

    return ImportResult(
        name=name,
        dest=dest,
        hashes=len(report.hashes),
        patterns=len(report.patterns),
        errors=report.errors,
    )


# ── Parsing helpers ─────────────────────────────────────────────────────────

def _parse_hash(entry: object, pack: str, i: int) -> tuple[HashSignature | None, str | None]:
    where = f"{pack}.hashes[{i}]"
    if not isinstance(entry, dict):
        return None, f"{where}: not an object"
    name = entry.get("name")
    sha = entry.get("sha256")
    severity = entry.get("severity", "medium")
    description = entry.get("description", "")
    if not isinstance(severity, str):
        return None, f"{where}: severity must be a string"
    severity = severity.lower()
    if not isinstance(description, str) or len(description) > MAX_FIELD_CHARS:
        return None, f"{where}: description must be a string up to {MAX_FIELD_CHARS} characters"
    if not isinstance(name, str) or not name or len(name) > 256:
        return None, f"{where}: missing 'name'"
    if not isinstance(sha, str) or not _HEX64.match(sha):
        return None, f"{where} ({name}): 'sha256' must be 64 hex chars"
    if severity not in VALID_SEVERITIES:
        return None, f"{where} ({name}): severity must be one of {sorted(VALID_SEVERITIES)}"
    return HashSignature(
        name=name, sha256=sha.lower(), severity=severity, description=str(description)
    ), None


def _parse_pattern(entry: object, pack: str, i: int) -> tuple[PatternSignature | None, str | None]:
    where = f"{pack}.patterns[{i}]"
    if not isinstance(entry, dict):
        return None, f"{where}: not an object"
    name = entry.get("name")
    regex = entry.get("regex")
    severity = entry.get("severity", "medium")
    description = entry.get("description", "")
    if not isinstance(severity, str):
        return None, f"{where}: severity must be a string"
    severity = severity.lower()
    if not isinstance(description, str) or len(description) > MAX_FIELD_CHARS:
        return None, f"{where}: description must be a string up to {MAX_FIELD_CHARS} characters"
    if not isinstance(name, str) or not name or len(name) > 256:
        return None, f"{where}: missing 'name'"
    if not isinstance(regex, str) or not regex or len(regex) > MAX_FIELD_CHARS:
        return None, f"{where} ({name}): missing 'regex'"
    if severity not in VALID_SEVERITIES:
        return None, f"{where} ({name}): severity must be one of {sorted(VALID_SEVERITIES)}"
    flags = 0
    raw_flags = entry.get("flags", [])
    if not isinstance(raw_flags, list) or any(
        not isinstance(flag, str) or flag.upper() not in _FLAG_MAP for flag in raw_flags
    ):
        return None, f"{where}: flags must be an array of supported flag names"
    for flag in raw_flags:
        flags |= _FLAG_MAP[flag.upper()]
    try:
        compiled = re.compile(regex, flags)
    except (re.error, OverflowError, RecursionError) as exc:
        return None, f"{where} ({name}): bad regex ({exc})"
    return PatternSignature(
        name=name, pattern=compiled, severity=severity, description=str(description)
    ), None


def _sanitize_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-._")
    return cleaned or "pack"


def _serialise(report: LoadReport, name: str) -> str:
    payload = {
        "name": name,
        "hashes": [
            {
                "name": s.name,
                "sha256": s.sha256,
                "severity": s.severity,
                "description": s.description,
            }
            for s in report.hashes
        ],
        "patterns": [
            {
                "name": s.name,
                "regex": s.pattern.pattern,
                "flags": _flags_to_names(s.pattern.flags),
                "severity": s.severity,
                "description": s.description,
            }
            for s in report.patterns
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True)


def _flags_to_names(flags: int) -> list[str]:
    names: list[str] = []
    for flag, value in (
        ("IGNORECASE", re.IGNORECASE),
        ("DOTALL", re.DOTALL),
        ("MULTILINE", re.MULTILINE),
        ("VERBOSE", re.VERBOSE),
    ):
        if flags & value:
            names.append(flag)
    return names
