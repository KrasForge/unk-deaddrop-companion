# UNK_DeadDrop Companion

A focused public release of the investigation's parse-only JavaScript scanner,
experimental YARA and Sigma rules, and inert fixtures for exercising them.

The scanner parses JavaScript syntax and reports selected clipboard-write calls
and campaign markers with source locations and a SHA-256 digest. It does not
import or execute the input. A finding is a lead for review, not a verdict.

## Contents

- `src/inspect-js.mjs`: bounded, parse-only AST scanner using Acorn.
- `rules/`: four experimental YARA rules and six experimental Sigma rules.
- `test/` and `tests/`: synthetic JavaScript, YARA and event fixtures.
- `docs/tool-design.md`: scanner behavior and limits.
- `docs/detection-notes.md`: required telemetry, false positives and tuning.

No malware samples, credentials, victim data, raw investigation records, or
unreviewed scan output are included.

## Use the scanner

Requires Node.js 22 or later.

```sh
npm ci --ignore-scripts
npm test
node src/inspect-js.mjs /path/to/held/source.js > analysis-output.json
```

The output can include literal strings from the input. Handle it with the same
care as the source file. The 8 MiB limit and parse-only behavior do not make an
untrusted file safe to process; use isolation and operating-system resource
limits.

## Review the detection content

Requires Python 3.11 or later.

```sh
python -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m unittest discover -s tests -v
```

Fixtures are synthetic and inert. They check rule parsing and a limited set of
Sigma matching behavior. They do not measure production precision or recall,
validate a particular SIEM backend, or show that an alert was delivered. Review
the [detection notes](docs/detection-notes.md) before using the rules.

## Scope and license

This repository contains code, rules, tests and their operating notes. It does
not include the research paper, private case records, payloads or evidence files.
The public [article series](https://krasforge.github.io/UNK_DeadDrop/) gives
investigation context. Infrastructure details describe evidence collected
through 24 July 2026 and do not establish current status.

Original code, tests and rules are licensed under MIT. Acorn retains its own
license. See [LICENSE](LICENSE) and [SECURITY.md](SECURITY.md).
