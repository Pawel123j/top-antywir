"""Tests for the HTML report renderer."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from top_antywir.report import render_html_report, write_html_report
from top_antywir.scanner import Finding, ScanResult, Verdict


def _result(path: str, verdict: Verdict, findings=(), error=None, sha=None) -> ScanResult:
    return ScanResult(
        path=Path(path), verdict=verdict, findings=list(findings),
        sha256=sha, error=error,
    )


class ReportTests(unittest.TestCase):
    def test_renders_valid_html_document(self) -> None:
        html = render_html_report([_result("/tmp/a", Verdict.CLEAN)])
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("Top Antywir", html)
        self.assertIn("</html>", html)

    def test_counts_are_derived_from_results(self) -> None:
        # Use markers that survive str(Path()) identically on every OS
        # (no leading slash, which Windows would render as a backslash).
        results = [
            _result("clean_marker_aaa", Verdict.CLEAN),
            _result("clean_marker_bbb", Verdict.CLEAN),
            _result("infected_marker_ccc", Verdict.INFECTED, [Finding("Bad", "high", "nope")]),
        ]
        html = render_html_report(results)
        # 2 clean, 1 infected — the infected file should appear in the table.
        self.assertIn("infected_marker_ccc", html)
        self.assertIn("Bad", html)
        # Clean files are summarised but not listed individually.
        self.assertNotIn("clean_marker_aaa", html)

    def test_explicit_counts_override(self) -> None:
        # GUI only retains detections but knows the real totals.
        detection = _result("/x", Verdict.SUSPICIOUS, [Finding("S", "medium", "d")])
        html = render_html_report(
            [detection],
            counts={Verdict.CLEAN: 999, Verdict.SUSPICIOUS: 1,
                    Verdict.INFECTED: 0, Verdict.ERROR: 0},
            scanned=1000,
        )
        self.assertIn("999", html)
        self.assertIn("1000", html)

    def test_html_is_escaped(self) -> None:
        evil = _result(
            "/tmp/<script>alert(1)</script>",
            Verdict.INFECTED,
            [Finding("<b>x</b>", "high", "<i>desc</i>")],
        )
        html = render_html_report([evil])
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<b>x</b>", html)

    def test_write_html_report_creates_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "nested" / "report.html"
            written = write_html_report(out, [_result("/a", Verdict.CLEAN)])
            self.assertTrue(written.exists())
            self.assertIn("<!DOCTYPE html>", written.read_text(encoding="utf-8"))

    def test_polish_names_are_readable_from_written_report(self) -> None:
        finding = [Finding("Polish-Test", "medium", "Zażółć gęślą jaźń")]
        utf8_name = "zażółć gęślą jaźń.sh"
        # "zażółć.sh" encoded in CP1250 and decoded by a UTF-8 filesystem
        # (os.fsdecode with surrogateescape): b"za\xbf\xf3\xb3\xe6.sh".
        cp1250_name = "za\udcbf\udcf3\udcb3\udce6.sh"
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "raport-źćł.html"
            written = write_html_report(out, [
                _result(utf8_name, Verdict.SUSPICIOUS, finding),
                _result(cp1250_name, Verdict.SUSPICIOUS, finding),
            ])
            self.assertEqual(written.name, "raport-źćł.html")
            # Strict decode: the whole file must be valid UTF-8.
            html = written.read_bytes().decode("utf-8")
        self.assertIn(utf8_name, html)
        self.assertIn("Zażółć gęślą jaźń", html)
        self.assertIn(r"za\udcbf\udcf3\udcb3\udce6.sh", html)
        self.assertIn("</html>", html)


if __name__ == "__main__":
    unittest.main()
