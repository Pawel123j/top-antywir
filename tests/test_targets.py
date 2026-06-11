"""Tests for the scan-target presets."""
from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from top_antywir import targets


class QuickScanTargetsTests(unittest.TestCase):
    def test_returns_existing_paths_only(self) -> None:
        result = targets.quick_scan_targets()
        for path in result:
            self.assertTrue(path.exists(), f"{path} should exist")
            self.assertTrue(path.is_absolute(), f"{path} should be absolute")

    def test_no_duplicates(self) -> None:
        result = targets.quick_scan_targets()
        self.assertEqual(len(result), len(set(result)))

    def test_dedupe_handles_repeated_input(self) -> None:
        home = Path.home()
        duped = [home, home, home / "Downloads", home / "Downloads"]
        # Only existing paths should survive, and each at most once.
        out = targets._dedupe_existing(duped)
        self.assertEqual(len(out), len(set(out)))


class FullScanTargetsTests(unittest.TestCase):
    def test_returns_non_empty_list(self) -> None:
        result = targets.full_scan_targets()
        self.assertGreater(len(result), 0)
        for path in result:
            self.assertTrue(path.is_absolute())

    def test_macos_includes_root_when_simulated(self) -> None:
        with patch.object(targets, "is_windows", return_value=False), \
             patch.object(targets, "is_macos",  return_value=True):
            result = targets.full_scan_targets()
        self.assertIn(Path("/"), result)

    def test_linux_returns_root_when_simulated(self) -> None:
        with patch.object(targets, "is_windows", return_value=False), \
             patch.object(targets, "is_macos",  return_value=False):
            result = targets.full_scan_targets()
        self.assertEqual(result, [Path("/")])


class ExclusionListsTests(unittest.TestCase):
    def test_excluded_names_lowercase(self) -> None:
        for name in targets.EXCLUDED_DIR_NAMES:
            self.assertEqual(name, name.lower(),
                             f"{name!r} should be lowercase for case-insensitive match")
        for name in targets.EXCLUDED_FILE_NAMES:
            self.assertEqual(name, name.lower())

    def test_windows_specific_entries_present(self) -> None:
        self.assertIn("system volume information", targets.EXCLUDED_DIR_NAMES)
        self.assertIn("$recycle.bin",              targets.EXCLUDED_DIR_NAMES)
        self.assertIn("pagefile.sys",              targets.EXCLUDED_FILE_NAMES)

    def test_macos_specific_entries_present(self) -> None:
        self.assertIn(".spotlight-v100", targets.EXCLUDED_DIR_NAMES)
        self.assertIn(".fseventsd",      targets.EXCLUDED_DIR_NAMES)
        self.assertIn(".ds_store",       targets.EXCLUDED_FILE_NAMES)


if __name__ == "__main__":
    unittest.main()
