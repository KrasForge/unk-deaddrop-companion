# unk-scanner for Python

Python CLI and API for the static JavaScript scanner from the [UNK_DeadDrop investigation](https://krasforge.github.io/UNK_DeadDrop/).

Requires Python 3.10+ and **Node.js 22+ on PATH**. The wheel bundles the same JavaScript engine as the npm distribution, plus Acorn 8.17.0. It does not require npm, execute submitted JavaScript, or download code during analysis.

## Installation and usage

Once published:

```sh
pip install unk-scanner
python -m unk_scanner suspect.js > findings.json
python -m unk_scanner --gzip captured-response.js > findings.json
```

The distribution also installs an `unk-scanner` command. Prefer `python -m unk_scanner` if both npm and Python versions are installed, to make the selected installation explicit.

```python
from unk_scanner import scan, ScannerError

try:
    report = scan("suspect.js")
    print(report["findings"])
except ScannerError as error:
    print(error)
```

## Scope

Reports contain original SHA-256 hashes, byte counts, source locations, findings, limitations, and separate artifact identity records. With `--gzip`, `decoded` records the decompressed hash and size. `artifactMatches` can identify ordinary login code or a shared polyfill; these are context, not malware alerts.

The scanner recognizes literal and selected identifier markers, clipboard writes, and one linked AES-GCM loader pattern. It does not decrypt payloads, resolve general aliases or obfuscated string tables, prove execution, or determine whether a file is safe. Exact identity matches cover only the listed bytes.

Input and decompressed sizes are limited to 8 MiB. Parsing uses a worker with a 10-second deadline and V8 heap limits; reports are capped at 10,000 findings. The Python wrapper applies an additional process timeout. Limit failures return an error rather than a partial report. These controls are not an OS security sandbox. Output can contain input strings and should be handled accordingly.

The CLI returns 0 for completed analysis, including findings, and 2 for errors. The Python API raises `ScannerError` when analysis fails.

Original code is MIT licensed. Bundled Acorn includes its MIT license. No malware samples or active credentials are distributed. See the [companion repository](https://github.com/KrasForge/unk-deaddrop-companion) and [preprint](https://doi.org/10.5281/zenodo.23652298).
