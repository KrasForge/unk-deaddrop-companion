import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from unk_scanner import scan, ScannerError, _command


class WrapperTests(unittest.TestCase):
    def test_installed_api_and_cli_agree_without_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.js"
            data = b'navigator.clipboard.writeText("inert"); throw new Error("never run");'
            path.write_bytes(data)
            report = scan(path)
            self.assertEqual(report["sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(report["findings"][0]["kind"], "clipboard-write")
            cli = subprocess.run([sys.executable, "-m", "unk_scanner", str(path)],
                                 capture_output=True, text=True, check=True)
            self.assertEqual(json.loads(cli.stdout), report)
            compressed = Path(directory) / "compressed.js"
            compressed.write_bytes(gzip.compress(data))
            self.assertEqual(scan(compressed, gzip=True)["decoded"]["sha256"], report["sha256"])

    def test_invalid_input_and_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.js"
            path.write_text("const = ;")
            with self.assertRaises(ScannerError):
                scan(path)
            with self.assertRaises(ScannerError):
                scan(Path(directory) / "missing.js")
            with self.assertRaises(ValueError):
                scan(path, timeout=0)

    def test_missing_or_old_node_has_actionable_error(self):
        with patch("unk_scanner.shutil.which", return_value=None):
            with self.assertRaisesRegex(ScannerError, "Node.js 22"):
                _command()
        with patch("unk_scanner.shutil.which", return_value="/node"):
            with patch("unk_scanner.subprocess.run") as run:
                run.return_value.stdout = "v20.0.0"
                with self.assertRaisesRegex(ScannerError, "Node.js 22"):
                    _command()

    def test_process_timeout_is_reported(self):
        with patch("unk_scanner._command", return_value=["node", "scanner"]):
            with patch("unk_scanner.subprocess.run",
                       side_effect=subprocess.TimeoutExpired("scanner", 1)):
                with self.assertRaises(ScannerError):
                    scan("file.js")

if __name__ == "__main__":
    unittest.main()
