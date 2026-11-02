"""Failure boundaries use harmless data in isolated temporary directories."""
import errno
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from top_antywir.audit import AuditLog
from top_antywir.quarantine import Quarantine
from top_antywir.report import render_html_report
from top_antywir.scanner import Scanner, Verdict
from top_antywir.signature_store import load_pack


def setup_quarantine(tmp_path):
    source = tmp_path / "sample.txt"
    source.write_text("harmless recovery fixture")
    result = Scanner(hash_signatures=(), pattern_signatures=()).scan_file(source)
    return source, result, Quarantine(tmp_path / "quarantine", AuditLog(tmp_path / "audit"))


def test_metadata_failure_leaves_original(tmp_path):
    source, result, quarantine = setup_quarantine(tmp_path)
    with patch.object(quarantine, "_write_metadata", side_effect=OSError(errno.ENOSPC, "full")), \
            pytest.raises(OSError):
        quarantine.add(result)
    assert source.read_text() == "harmless recovery fixture"
    assert not quarantine.list_items()


def test_interrupted_copy_keeps_original(tmp_path):
    source, result, quarantine = setup_quarantine(tmp_path)
    with patch("top_antywir.quarantine.shutil.copyfileobj", side_effect=OSError("full")), \
            pytest.raises(OSError):
        quarantine.add(result)
    assert source.exists()
    assert not quarantine.list_items()


def test_restart_after_payload_commit_recovers_file(tmp_path):
    source, result, quarantine = setup_quarantine(tmp_path)
    original_unlink = Path.unlink

    def fail_source_removal(path, *args, **kwargs):
        if path == source:
            raise OSError("interrupted before source removal")
        return original_unlink(path, *args, **kwargs)

    with patch.object(Path, "unlink", fail_source_removal), pytest.raises(OSError):
        quarantine.add(result)
    restarted = Quarantine(quarantine.root, quarantine.audit)
    [item] = restarted.list_items()
    assert source.exists()
    restored = restarted.restore(item.item_id, tmp_path / "recovered.txt")
    assert restored.read_bytes() == source.read_bytes()


def test_old_orphan_is_listed_and_restorable(tmp_path):
    _, _, quarantine = setup_quarantine(tmp_path)
    quarantine.ensure()
    (quarantine.files_dir / "legacy-orphan").write_bytes(b"recover me")
    [item] = quarantine.list_items()
    assert item.verdict == "recovered"
    assert quarantine.restore(item.item_id).read_bytes() == b"recover me"


def test_restore_disk_full_keeps_quarantine(tmp_path):
    source, result, quarantine = setup_quarantine(tmp_path)
    item = quarantine.add(result)
    with patch("top_antywir.quarantine.shutil.copyfileobj", side_effect=OSError("full")), \
            pytest.raises(OSError):
        quarantine.restore(item.item_id)
    assert not source.exists()
    assert quarantine.list_items() == [item]


@pytest.mark.parametrize("payload", [
    {"patterns": 1}, {"hashes": {}}, {"name": []},
    {"patterns": [{"name": "bad", "regex": "x", "severity": []}]},
    {"patterns": [{"name": "bad", "regex": "x", "flags": 1}]},
    {"patterns": [{"name": "bad", "regex": "x", "flags": ["UNKNOWN"]}]},
    {"hashes": [{"name": "bad", "sha256": "a" * 64, "description": []}]},
    {"patterns": [None] * 2001},
])
def test_invalid_pack_is_reported(tmp_path, payload):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(payload))
    report = load_pack(path)
    assert report.errors
    assert not report.patterns and not report.hashes


def test_invalid_encoding_and_oversized_pack(tmp_path):
    path = tmp_path / "bad.json"
    for payload in (b"\xff", b" " * (2 * 1024 * 1024 + 1)):
        path.write_bytes(payload)
        assert load_pack(path).errors


def test_directory_access_failure_is_reported_by_both_scan_apis(tmp_path):
    def denied_walk(root, **kwargs):
        kwargs["onerror"](PermissionError(errno.EACCES, "Permission denied", str(root / "private")))
        return iter(())

    scanner = Scanner(hash_signatures=(), pattern_signatures=())
    with patch("top_antywir.scanner.os.walk", denied_walk):
        for results in (scanner.scan_path(tmp_path), list(scanner.iter_scan([tmp_path]))):
            assert len(results) == 1
            assert results[0].verdict == Verdict.ERROR
            html = render_html_report(results)
            assert "Incomplete scan" in html
            assert "private" in html


def test_cancelled_report_cannot_claim_completion():
    assert "Incomplete scan" in render_html_report([], cancelled=True)
