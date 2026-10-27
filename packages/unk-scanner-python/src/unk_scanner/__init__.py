"""Python interface to the bundled static JavaScript scanner.

Requires Node.js >=22. Submitted source is parsed, never executed.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

__version__ = "0.1.0"


class ScannerError(RuntimeError):
    """The scanner could not produce a complete analysis."""


def _command() -> list[str]:
    node = shutil.which("node")
    if node is None:
        raise ScannerError("Node.js 22 or later is required; install Node.js and put node on PATH")
    try:
        version = subprocess.run(
            [node, "--version"], capture_output=True, text=True, timeout=5, check=True
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as error:
        raise ScannerError("Could not check the installed Node.js version") from error
    match = re.fullmatch(r"v(\d+)\.\d+\.\d+(?:[-+].*)?", version)
    if not match or int(match[1]) < 22:
        raise ScannerError(f"Node.js 22 or later is required; found {version!r}")
    return [node, str(Path(__file__).parent / "_engine" / "bin" / "unk-scanner.mjs")]


def scan(path: str | Path, *, gzip: bool = False, timeout: float = 30) -> dict:
    """Return the scanner's JSON result for one file.

    gzip explicitly enables bounded gzip decoding. Findings are review leads;
    artifactMatches are separate identity records, not malware verdicts.
    """
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    args = _command() + (["--gzip"] if gzip else []) + ["--", str(path)]
    try:
        result = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", timeout=timeout)
    except (OSError, subprocess.SubprocessError) as error:
        raise ScannerError(f"Scanner process failed: {error}") from error
    if result.returncode:
        raise ScannerError(result.stderr.strip() or f"Scanner exited with code {result.returncode}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ScannerError("Scanner returned invalid JSON") from error


def main() -> int:
    try:
        return subprocess.run(_command() + sys.argv[1:], timeout=30).returncode
    except (ScannerError, OSError, subprocess.SubprocessError) as error:
        print(f"unk-scanner: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
