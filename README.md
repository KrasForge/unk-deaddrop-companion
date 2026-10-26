# UNK_DeadDrop Companion

Parse-only JavaScript AST scanning and experimental YARA and Sigma detections for defensive analysis of developer-targeting lures. The investigation discusses behaviors reported in the wider Contagious Interview cluster tracked by MITRE ATT&CK as [G1052](https://attack.mitre.org/groups/G1052/). Similarities do not establish that UNK_DeadDrop and G1052 share an operator or identity.

Start with the [twelve-part research series](https://krasforge.github.io/UNK_DeadDrop/) and its [preprint PDF](https://krasforge.github.io/UNK_DeadDrop/downloads/UNK_DeadDrop-Preprint.pdf). The preprint is published on Zenodo under CC BY 4.0: [version 1.0 DOI](https://doi.org/10.5281/zenodo.23652298) · [latest-version DOI](https://doi.org/10.5281/zenodo.23652297).

The defensive purpose is to inspect JavaScript without executing it and to exercise detection logic against inert fixtures. A finding is a lead for review, not a verdict.

## Contents

| Path | Purpose |
| --- | --- |
| `rules/yara/` | Four experimental YARA rules for wallet-agent markers, capture symbols, extracted extension manifests and stage-three source |
| `rules/sigma/` | Six experimental rules for Linux persistence and Windows collection, task, elevation and extension artifacts |
| `src/inspect-js.mjs` | Acorn-based, parse-only AST scanner |
| `test/` and `tests/` | Inert JavaScript buffers and boundary/event fixtures |
| `docs/` | Scanner design, detection conditions, telemetry needs and limitations |
| `CITATION.cff` | Citation metadata for the software and its related preprint |

This public repository contains zero live malware payloads or active credentials. It also excludes victim data, private case records, and raw investigation databases. The tests use synthetic inert fixtures.

## Use the scanner

Requires Node.js 22 or later.

```sh
npm ci --ignore-scripts
npm test
node src/inspect-js.mjs /path/to/held/source.js > analysis-output.json
```

The output can include literal strings from the input. Handle it with the same care as the source file. The 8 MiB limit and parse-only behavior do not make an untrusted file safe to process; use isolation and operating-system resource limits.

## Review the detection content

Requires Python 3.11 or later.

```sh
python -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m unittest discover -s tests -v
```

Fixtures check rule parsing and selected matching behavior. The wallet YARA rule has one historical positive against a held Linux sample; the other YARA rules have synthetic fixtures only. No rule has production precision or recall estimates, a validated SIEM query, or confirmed alert-delivery results. Review the [detection notes](docs/detection-notes.md) for each rule's input, match conditions and blind spots before use.

## Scope and license

Infrastructure details describe evidence collected through 24 July 2026 and do not establish current status. Original code, tests and rules are licensed under MIT. Acorn retains its own license. See [LICENSE](LICENSE) and [SECURITY.md](SECURITY.md).
