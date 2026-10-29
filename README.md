# UNK_DeadDrop Companion

Static JavaScript analysis and 33 experimental YARA detections for defensive analysis of developer-targeting lures. The investigation discusses behaviors reported in the wider Contagious Interview cluster tracked by MITRE ATT&CK as [G1052](https://attack.mitre.org/groups/G1052/). Similarities do not establish that UNK_DeadDrop and G1052 share an operator or identity.

Start with the [twelve-part research series](https://krasforge.github.io/UNK_DeadDrop/) and its [preprint PDF](https://krasforge.github.io/UNK_DeadDrop/downloads/UNK_DeadDrop-Preprint.pdf). The preprint is published on Zenodo under CC BY 4.0: [record DOI](https://doi.org/10.5281/zenodo.23696198) · [concept DOI](https://doi.org/10.5281/zenodo.23652297).

This repository is the versioned source for the experimental YARA suite and the parse-only scanner. The scanner's package versions, evaluation scope, and known limits are documented below. Findings and infrastructure status remain bounded by the investigation evidence and dates described in the preprint.

The defensive purpose is to inspect JavaScript without executing it and to exercise detection logic against inert fixtures. A finding is a lead for review, not a verdict.

## Contents

| Path | Purpose |
| --- | --- |
| `rules/yara/` | 33 experimental file-content rules in 28 files, each matched against at least one retained investigation artifact |
| `tools/replay_yara.py` | Read-only replay over selected files and supported archive members, without extracting or executing content |
| `packages/unk-scanner/` and `packages/unk-scanner-python/` | npm and Python CLI/API packages; Python bundles the JavaScript engine and Acorn with their licenses |
| `test/` and `tests/` | Inert JavaScript buffers, a generated obfuscation fixture, isolation probes and YARA boundary fixtures |
| `benchmark/` | Corpus acquisition, benchmark harness and review data (source code of the corpus is not redistributed) |
| `docs/` | Scanner design, rule reference, CI integration, limitations, evidence coverage, and validation results |
| `CITATION.cff` and `.zenodo.json` | Citation and archive metadata for the software and its related preprint |

This public repository contains zero live malware payloads or active credentials. It also excludes victim data, private case records, and raw investigation databases. The tests use synthetic inert fixtures.

## Use the scanner

`unk-scanner` 0.2.0 is published on [npm](https://www.npmjs.com/package/unk-scanner) and [PyPI](https://pypi.org/project/unk-scanner/0.2.0/) (`npm install -g unk-scanner --ignore-scripts` or `python -m pip install unk-scanner`; both need Node.js 22+). It recovers obfuscator.io string arrays and reports ClickFix clipboard command substitution and Electron `ELECTRON_RUN_AS_NODE` launches with context-dependent severity. It also writes SARIF for code scanning and parses each file in an isolated process. See the [npm package README](packages/unk-scanner/README.md), the [rule reference](docs/rules.md), the [CI guide](docs/ci.md) and the [design notes](docs/tool-design.md).

From a checkout:

```sh
npm ci --ignore-scripts
npm test
node packages/unk-scanner/bin/unk-scanner.mjs /path/to/held/source.js > analysis-output.json
node packages/unk-scanner/bin/unk-scanner.mjs --format sarif --fail-on error src/ > results.sarif
```

The scanner is local and static: it does not execute, import, fetch or install project content, and its evaluator interprets only a side-effect-free expression subset. Output can include literal strings from the input; handle it with the same care as the source file. Process isolation reduces the impact of a parser defect but is not a sandbox against an engine exploit. Analyse hostile samples in a disposable environment.

The [corpus benchmark](BENCHMARK.md) covers 2,500 npm packages and 500 Open VSX extensions, 143,153 unique files. It reports parse coverage, finding prevalence by rule and severity, the review of every warning, throughput, and sensitivity on the retained UNK_DeadDrop artifacts. See the [scanner validation](docs/scanner-validation.md) for the earlier artifact checks.

## Review the detection content

Requires Python 3.11 or later.

```sh
python -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python tools/replay_yara.py --root /path/to/case /path/to/case/selected-artifacts
```

The replay command prints aggregate counts as JSON and includes skipped-object
labels when a limit is reached. `--details` adds labels for matched objects.
Keep output local when those paths are sensitive.

All 33 YARA rules compile, and every rule matched at least one retained investigation artifact in a read-only replay. The content rules also have inert positive and near-miss fixtures; exact-hash positives are verified against retained files, not synthetic samples. The replay covered 192 selected files and 395 raw or archive-member views; it read ZIP, VSIX, TAR, gzip and nested ZIP content in memory. Five RAR containers were not decoded: four ECHOES archives require passwords, and the sealed environment archive was excluded from member inspection. Four ECHOES archive hashes matched exactly. Of 192 inputs, 90 had at least one hit and 102 had none; many unmatched files are generic interface assets or research context with no reliable content signature. A separate archive-aware baseline scan of 1,914 standard-library and installed-package files produced no hits. The wallet-agent rule requires ELF magic at byte zero; its marker-rich prose boundary fixture stays negative. Exact-hash rules identify only listed bytes. These checks do not provide production precision or recall estimates. See the [validation report](docs/actual-artifact-validation.md) for corpus scope and limitations. Authentic endpoint event logs are not available, so this repository contains no Sigma rules. Review the [detection notes](docs/detection-notes.md) and [evidence coverage map](docs/coverage-map.md) for match conditions, boundaries, and exclusions before use.

## Scope and license

Infrastructure details describe evidence collected through 24 July 2026 and do not establish current status. Original code, tests and rules are licensed under MIT. Acorn retains its own license. See [LICENSE](LICENSE) and [SECURITY.md](SECURITY.md).
