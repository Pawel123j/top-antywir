"""Tests for the scheduled-scan command/unit/plist generators.

Only the *pure* generators are exercised — these tests never register a
real OS scheduled task.
"""
from __future__ import annotations

import sys
import unittest

from top_antywir import schedule


class ScanCommandTests(unittest.TestCase):
    def test_scan_command_argv_quick(self) -> None:
        argv = schedule.scan_command_argv("quick")
        self.assertEqual(argv[0], sys.executable)
        self.assertIn("-m", argv)
        self.assertIn("top_antywir.cli", argv)
        self.assertIn("scan", argv)
        self.assertIn("--quick", argv)
        self.assertIn("--quarantine", argv)

    def test_scan_command_without_quarantine(self) -> None:
        argv = schedule.scan_command_argv("full", quarantine=False)
        self.assertIn("--full", argv)
        self.assertNotIn("--quarantine", argv)

    def test_scan_command_rejects_bad_mode(self) -> None:
        with self.assertRaises(ValueError):
            schedule.scan_command_argv("sideways")


class TimeParsingTests(unittest.TestCase):
    def test_parse_valid(self) -> None:
        self.assertEqual(schedule.parse_hhmm("03:30"), (3, 30))
        self.assertEqual(schedule.parse_hhmm("23:59"), (23, 59))
        self.assertEqual(schedule.parse_hhmm("00:00"), (0, 0))

    def test_parse_invalid(self) -> None:
        for bad in ("99:99", "nope", "12", "12:60", "24:00", ""):
            with self.assertRaises(ValueError):
                schedule.parse_hhmm(bad)


class WindowsGeneratorTests(unittest.TestCase):
    def test_schtasks_create_argv(self) -> None:
        argv = schedule.windows_create_argv("TopAntywir-Quick", "cmd here", "03:00")
        self.assertIn("/Create", argv)
        self.assertIn("/TN", argv)
        self.assertIn("TopAntywir-Quick", argv)
        self.assertIn("/SC", argv)
        self.assertIn("DAILY", argv)
        self.assertIn("/ST", argv)
        self.assertIn("03:00", argv)

    def test_command_string_quotes_argv(self) -> None:
        s = schedule.windows_command_string([r"C:\Program Files\Py\python.exe", "-m", "x"])
        self.assertIn("python.exe", s)
        self.assertIn("-m", s)


class SystemdGeneratorTests(unittest.TestCase):
    def test_service_unit_has_execstart(self) -> None:
        argv = ["/usr/bin/python3", "-m", "top_antywir.cli", "scan", "--quick"]
        unit = schedule.systemd_service_unit("quick", argv)
        self.assertIn("[Service]", unit)
        self.assertIn("Type=oneshot", unit)
        self.assertIn("ExecStart=", unit)
        self.assertIn("top_antywir.cli", unit)

    def test_timer_unit_has_oncalendar(self) -> None:
        unit = schedule.systemd_timer_unit("quick", "03:05")
        self.assertIn("OnCalendar=*-*-* 03:05:00", unit)
        self.assertIn("WantedBy=timers.target", unit)
        self.assertIn("Persistent=true", unit)


class LaunchdGeneratorTests(unittest.TestCase):
    def test_plist_structure(self) -> None:
        argv = ["/usr/bin/python3", "-m", "top_antywir.cli", "scan", "--quick"]
        plist = schedule.launchd_plist("com.topantywir.quickscan", argv, "03:07")
        self.assertIn("<key>Label</key>", plist)
        self.assertIn("com.topantywir.quickscan", plist)
        self.assertIn("<key>ProgramArguments</key>", plist)
        self.assertIn("top_antywir.cli", plist)
        self.assertIn("<key>Hour</key><integer>3</integer>", plist)
        self.assertIn("<key>Minute</key><integer>7</integer>", plist)

    def test_plist_escapes_xml(self) -> None:
        plist = schedule.launchd_plist("lbl", ["a&b", "<c>"], "01:00")
        self.assertIn("a&amp;b", plist)
        self.assertIn("&lt;c&gt;", plist)
        self.assertNotIn("<c>", plist)


class JobLabelTests(unittest.TestCase):
    def test_label_mentions_mode(self) -> None:
        self.assertIn("quick", schedule.job_label("quick").lower())
        self.assertIn("full", schedule.job_label("full").lower())


if __name__ == "__main__":
    unittest.main()
