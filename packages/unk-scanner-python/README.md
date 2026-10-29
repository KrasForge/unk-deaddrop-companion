# unk-scanner for Python

Python CLI and API for the static JavaScript scanner from the [UNK_DeadDrop investigation](https://krasforge.github.io/UNK_DeadDrop/).

Requires Python 3.10+ and **Node.js 22+ on PATH**. The wheel bundles the same JavaScript engine as the npm distribution, plus Acorn 8.17.0. It does not require npm, execute submitted JavaScript, or download code during analysis.

## Installation and usage

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

Reports contain original SHA-256 hashes, byte counts, findings with severities and source locations, a `deobfuscation` summary, limitations and separate artifact identity records. With `--gzip`, `decoded` records the decompressed hash and size. `artifactMatches` can identify ordinary login code or a shared polyfill; these are context, not malware alerts.

The scanner reports ClickFix clipboard command substitution, Electron `ELECTRON_RUN_AS_NODE` launches, obfuscator.io string arrays (recovering their strings without running the decoder), one linked AES-GCM loader pattern and campaign markers. See the [rule reference](https://github.com/KrasForge/unk-deaddrop-companion/blob/main/docs/rules.md). It does not prove execution or determine whether a file is safe.

Each file is parsed in a separate Node process under the permission model, with a capped heap, a per-file deadline and an empty environment. On Linux, where permitted, the process also gets a network namespace and rlimits. The Python wrapper applies an additional process timeout. Input and decompressed sizes are limited to 8 MiB and reports to 10,000 findings; limit failures return an error rather than a partial report. These controls are not a sandbox against an engine exploit. Output can contain input strings and should be handled accordingly.

The CLI returns 0 for completed analysis, 1 when a finding reaches `--fail-on`, and 2 for errors. All npm CLI options, including `--format sarif`, are available. The Python API raises `ScannerError` when analysis fails.

Original code is MIT licensed. Bundled Acorn includes its MIT license. No malware samples or active credentials are distributed. See the [companion repository](https://github.com/KrasForge/unk-deaddrop-companion) and [preprint](https://doi.org/10.5281/zenodo.23652297).
