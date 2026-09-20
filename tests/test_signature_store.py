"""Tests for user-extensible signature packs."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from top_antywir import signature_store as store
from top_antywir.signatures import HASH_SIGNATURES, PATTERN_SIGNATURES

_GOOD_PACK = {
    "name": "unit-pack",
    "hashes": [
        {
            "name": "Unit-Hash",
            "sha256": "a" * 64,
            "severity": "high",
            "description": "Synthetic hash signature.",
        }
    ],
    "patterns": [
        {
            "name": "Unit-Pattern",
            "regex": r"evil_[a-z]+\(",
            "flags": ["IGNORECASE"],
            "severity": "medium",
            "description": "Synthetic pattern signature.",
        }
    ],
}


class SignatureStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write(self, name: str, data: object) -> Path:
        path = self.dir / name
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_load_pack_parses_hashes_and_patterns(self) -> None:
        path = self._write("good.json", _GOOD_PACK)
        report = store.load_pack(path)
        self.assertEqual(len(report.hashes), 1)
        self.assertEqual(len(report.patterns), 1)
        self.assertEqual(report.errors, [])
        self.assertEqual(report.hashes[0].name, "Unit-Hash")
        self.assertTrue(report.patterns[0].pattern.search("call EVIL_run("))

    def test_bad_regex_is_skipped_with_error(self) -> None:
        pack = {"patterns": [
            {"name": "Broken", "regex": "(", "severity": "low", "description": "x"},
        ]}
        report = store.load_pack(self._write("broken.json", pack))
        self.assertEqual(report.patterns, [])
        self.assertEqual(len(report.errors), 1)
        self.assertIn("bad regex", report.errors[0])

    def test_invalid_sha256_is_skipped(self) -> None:
        pack = {"hashes": [
            {"name": "ShortHash", "sha256": "abc", "severity": "high", "description": "x"},
        ]}
        report = store.load_pack(self._write("badhash.json", pack))
        self.assertEqual(report.hashes, [])
        self.assertEqual(len(report.errors), 1)
        self.assertIn("64 hex", report.errors[0])

    def test_invalid_severity_is_skipped(self) -> None:
        pack = {"hashes": [
            {"name": "X", "sha256": "b" * 64, "severity": "critical", "description": "x"},
        ]}
        report = store.load_pack(self._write("sev.json", pack))
        self.assertEqual(report.hashes, [])
        self.assertIn("severity", report.errors[0])

    def test_invalid_json_does_not_raise(self) -> None:
        path = self.dir / "junk.json"
        path.write_text("{ not json", encoding="utf-8")
        report = store.load_pack(path)
        self.assertEqual(report.hashes, [])
        self.assertEqual(report.patterns, [])
        self.assertEqual(len(report.errors), 1)

    def test_load_user_signatures_aggregates_directory(self) -> None:
        self._write("a.json", _GOOD_PACK)
        self._write("b.json", {"hashes": [
            {"name": "Second", "sha256": "c" * 64, "severity": "low", "description": "y"},
        ]})
        report = store.load_user_signatures(self.dir)
        self.assertEqual(len(report.hashes), 2)
        self.assertEqual(len(report.patterns), 1)

    def test_all_signatures_merges_builtins(self) -> None:
        self._write("a.json", _GOOD_PACK)
        hashes, patterns = store.all_signatures(self.dir)
        self.assertEqual(len(hashes), len(HASH_SIGNATURES) + 1)
        self.assertEqual(len(patterns), len(PATTERN_SIGNATURES) + 1)

    def test_all_signatures_empty_dir_returns_builtins(self) -> None:
        hashes, patterns = store.all_signatures(self.dir)
        self.assertEqual(len(hashes), len(HASH_SIGNATURES))
        self.assertEqual(len(patterns), len(PATTERN_SIGNATURES))

    def test_import_pack_installs_and_counts(self) -> None:
        src = self._write("incoming.json", _GOOD_PACK)
        dest_dir = self.dir / "installed"
        result = store.import_pack(src, dest_dir)
        self.assertEqual(result.hashes, 1)
        self.assertEqual(result.patterns, 1)
        self.assertTrue(result.dest.exists())
        # The installed copy must itself be a valid, reloadable pack.
        reloaded = store.load_pack(result.dest)
        self.assertEqual(len(reloaded.hashes), 1)
        self.assertEqual(len(reloaded.patterns), 1)

    def test_import_pack_rejects_empty(self) -> None:
        src = self._write("empty.json", {"name": "nothing"})
        with self.assertRaises(ValueError):
            store.import_pack(src, self.dir / "installed")


if __name__ == "__main__":
    unittest.main()
