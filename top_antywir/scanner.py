"""File scanning engine for Top Antywir."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import math
import os
from pathlib import Path
import stat
import threading
from typing import Iterable

from .signature_store import all_signatures
from .signatures import HashSignature, PatternSignature
from .targets import EXCLUDED_DIR_NAMES, EXCLUDED_FILE_NAMES


MAX_TEXT_SCAN_BYTES = 2 * 1024 * 1024
MAX_ENTROPY_BYTES = 1024 * 1024


class Verdict(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    INFECTED = "infected"
    ERROR = "error"


@dataclass(frozen=True)
class Finding:
    name: str
    severity: str
    description: str


@dataclass
class ScanResult:
    path: Path
    verdict: Verdict
    findings: list[Finding] = field(default_factory=list)
    sha256: str | None = None
    error: str | None = None

    @property
    def is_detection(self) -> bool:
        return self.verdict in {Verdict.SUSPICIOUS, Verdict.INFECTED}


class Scanner:
    def __init__(
        self,
        max_file_size: int = 100 * 1024 * 1024,
        hash_signatures: tuple[HashSignature, ...] | None = None,
        pattern_signatures: tuple[PatternSignature, ...] | None = None,
        excluded_dir_names: Iterable[str] = EXCLUDED_DIR_NAMES,
        excluded_file_names: Iterable[str] = EXCLUDED_FILE_NAMES,
    ) -> None:
        # When the caller doesn't pin signatures explicitly, fall back to the
        # built-ins merged with any user signature packs on disk. Tests and
        # advanced callers can still inject an exact tuple to stay
        # deterministic.
        if hash_signatures is None or pattern_signatures is None:
            builtin_hashes, builtin_patterns = all_signatures()
        self.max_file_size = max_file_size
        chosen_hashes = hash_signatures if hash_signatures is not None else builtin_hashes
        chosen_patterns = (
            pattern_signatures if pattern_signatures is not None else builtin_patterns
        )
        self.hash_signatures = {sig.sha256: sig for sig in chosen_hashes}
        self.pattern_signatures = tuple(chosen_patterns)
        self.excluded_dir_names = {name.lower() for name in excluded_dir_names}
        self.excluded_file_names = {name.lower() for name in excluded_file_names}

    def scan_path(
        self,
        target: Path,
        progress_callback: Callable[[int, int, Path], None] | None = None,
    ) -> list[ScanResult]:
        target = target.expanduser().resolve()
        if not target.exists():
            return [ScanResult(path=target, verdict=Verdict.ERROR, error="Path does not exist.")]

        if target.is_file():
            if progress_callback:
                progress_callback(0, 1, target)
            result = self.scan_file(target)
            if progress_callback:
                progress_callback(1, 1, target)
            return [result]

        files = list(self._iter_files(target))
        total = len(files)
        results: list[ScanResult] = []
        for i, file_path in enumerate(files):
            if progress_callback:
                progress_callback(i, total, file_path)
            results.append(self.scan_file(file_path))
        if progress_callback and files:
            progress_callback(total, total, files[-1])
        return results

    def iter_scan(
        self,
        targets: Iterable[Path],
        stop_event: threading.Event | None = None,
    ) -> Iterator[ScanResult]:
        """Stream ScanResult for each file across one or more roots.

        Use this for "Quick" or "Full" scans where pre-counting the file
        tree would itself take minutes. Yields results in walk order;
        honours ``stop_event`` between files for cooperative cancellation.
        """
        for raw_target in targets:
            if stop_event is not None and stop_event.is_set():
                return
            try:
                target = raw_target.expanduser().resolve()
            except (OSError, RuntimeError) as exc:
                yield ScanResult(path=raw_target, verdict=Verdict.ERROR, error=str(exc))
                continue

            if not target.exists():
                yield ScanResult(path=target, verdict=Verdict.ERROR, error="Path does not exist.")
                continue

            if target.is_file():
                if stop_event is not None and stop_event.is_set():
                    return
                yield self.scan_file(target)
                continue

            for file_path in self._iter_files(target):
                if stop_event is not None and stop_event.is_set():
                    return
                yield self.scan_file(file_path)

    def scan_file(self, path: Path) -> ScanResult:
        try:
            if not path.is_file():
                return ScanResult(path=path, verdict=Verdict.ERROR, error="Not a file.")

            size = path.stat().st_size
            if size > self.max_file_size:
                return ScanResult(
                    path=path,
                    verdict=Verdict.ERROR,
                    error=f"File is larger than limit: {self.max_file_size} bytes.",
                )

            # Stream the file once: compute SHA-256 over the whole content
            # while keeping the first SAMPLE_BYTES in memory for pattern
            # + entropy analysis. Old version opened the file three times.
            digest, sample = self._hash_and_sample(path)
            findings: list[Finding] = []

            hash_sig = self.hash_signatures.get(digest)
            if hash_sig:
                findings.append(
                    Finding(
                        name=hash_sig.name,
                        severity=hash_sig.severity,
                        description=hash_sig.description,
                    )
                )

            findings.extend(self._pattern_findings(sample))
            findings.extend(self._heuristic_findings(path, sample))

            if any(f.severity == "high" for f in findings):
                verdict = Verdict.INFECTED
            elif findings:
                verdict = Verdict.SUSPICIOUS
            else:
                verdict = Verdict.CLEAN

            return ScanResult(path=path, verdict=verdict, findings=findings, sha256=digest)
        except OSError as exc:
            return ScanResult(path=path, verdict=Verdict.ERROR, error=str(exc))

    def iter_files(self, root: Path) -> Iterator[Path]:
        """Public: yield scannable files under ``root``, honouring exclusions.

        Used by the real-time monitor so it walks exactly the same set of
        files a manual scan would, minus pseudo-filesystems and OS noise.
        """
        yield from self._iter_files(root)

    def _iter_files(self, root: Path) -> Iterator[Path]:
        excl_dirs = self.excluded_dir_names
        excl_files = self.excluded_file_names
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=None):
            # Prune excluded directories in place so os.walk skips them
            dirnames[:] = [d for d in dirnames if d.lower() not in excl_dirs]
            for filename in filenames:
                if filename.lower() in excl_files:
                    continue
                yield Path(dirpath) / filename

    # How many leading bytes to retain in memory for pattern + heuristic
    # analysis. The full file is still hashed.
    _SAMPLE_BYTES = max(MAX_TEXT_SCAN_BYTES, MAX_ENTROPY_BYTES)

    def _hash_and_sample(self, path: Path) -> tuple[str, bytes]:
        """Single pass over the file: SHA-256 over everything, first
        ``_SAMPLE_BYTES`` retained for pattern/entropy checks.
        """
        digest = hashlib.sha256()
        sample = bytearray()
        sample_target = self._SAMPLE_BYTES
        with path.open("rb") as file:
            for chunk in iter(lambda: file.read(1024 * 1024), b""):
                digest.update(chunk)
                if len(sample) < sample_target:
                    take = sample_target - len(sample)
                    sample.extend(chunk[:take])
        return digest.hexdigest(), bytes(sample)

    def _pattern_findings(self, sample: bytes) -> list[Finding]:
        findings: list[Finding] = []
        text_sample = sample[:MAX_TEXT_SCAN_BYTES]

        if b"\x00" in text_sample[:4096]:
            return findings

        text = text_sample.decode("utf-8", errors="ignore")
        for sig in self.pattern_signatures:
            if sig.pattern.search(text):
                findings.append(
                    Finding(
                        name=sig.name,
                        severity=sig.severity,
                        description=sig.description,
                    )
                )
        return findings

    def _heuristic_findings(self, path: Path, sample: bytes) -> list[Finding]:
        findings: list[Finding] = []
        try:
            mode = path.stat().st_mode
            is_executable = bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        except OSError:
            is_executable = False

        entropy_sample = sample[:MAX_ENTROPY_BYTES]
        entropy = shannon_entropy(entropy_sample)
        suffix = path.suffix.lower()

        is_shell_script = suffix in {".sh", ".bash", ".zsh"} and (
            is_executable or sample.startswith(
                (b"#!/bin/sh", b"#!/usr/bin/env sh",
                 b"#!/bin/bash", b"#!/usr/bin/env bash",
                 b"#!/bin/zsh", b"#!/usr/bin/env zsh")
            )
        )

        if is_shell_script:
            findings.append(
                Finding(
                    name="Executable-Shell-Script",
                    severity="low",
                    description="Shell scripts should be reviewed before running.",
                )
            )

        if len(entropy_sample) >= 128 * 1024 and entropy >= 7.5:
            findings.append(
                Finding(
                    name="High-Entropy-Content",
                    severity="low",
                    description="File content is highly compressed or encrypted.",
                )
            )

        return findings


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    frequencies = [0] * 256
    for byte in data:
        frequencies[byte] += 1

    entropy = 0.0
    length = len(data)
    for count in frequencies:
        if count:
            probability = count / length
            entropy -= probability * math.log2(probability)
    return entropy
