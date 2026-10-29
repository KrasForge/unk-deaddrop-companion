# Changelog

## Unreleased: scanner 0.2.0

Scanner 0.2.0 (JSON schema version 2). Not yet published to npm or PyPI.

- **String arrays:** recover obfuscator.io-style string arrays statically. The scanner identifies plain, base64 and RC4 decoders and their offsets, and reimplements the decoding. It solves the rotation from the obfuscator's own checksum loop, including several decoders sharing one array, and otherwise uses guarded printable consensus. Recovered strings feed every rule. Nothing from the input is executed.
- **Pure evaluator:** add a pure partial evaluator for constants, literal objects, string operations and single-return helpers, with step and depth caps.
- **ClickFix rules:**
  - `clickfix-clipboard-command` resolves the copied value or harvests fragments from command builders and caller arguments, then classifies shell, PowerShell, `mshta`, detaching and lure indicators.
  - `clipboard-copy-override` reports global copy handlers.
- **Electron rules:** `electron-run-as-node` reports launches, generated scripts and assignments, and escalates only alongside hidden execution. `child-process-hidden-script` reports scripts launched from temporary or `.vscode` paths.
- **Rule modules:** rules are now modules (`id`, `meta`, `create(context)`) dispatched in one pass. Custom rules load through `--rule` or `inspect(source, { rules })`. Each finding carries a `severity`.
- **Isolation:** the CLI parses in a pool of child processes under the Node permission model with a capped heap and an empty environment. On Linux it adds a network namespace and rlimits where available. A per-file deadline restarts the process. The default heap is 512 MiB, which the largest corpus bundles (up to 8 MiB of source) need. Acorn location objects are no longer created: peak memory on a 7.9 MB bundle fell from 462 MB to 399 MB.
- **CLI:** add `--format sarif` (SARIF 2.1.0), `--fail-on`, multiple files and directories, `--jobs`, `--timeout` and `--strict`.
- **Benchmark:** evaluate on 2,500 npm packages and 500 Open VSX extensions (143,153 unique files); see `BENCHMARK.md`.

## 2.1.0 - 2026-10-28

This release adds installable scanner packages and records the current tool and detection scope.

- Publish `unk-scanner` 0.1.0 on npm and 0.1.1 on PyPI. The Python package bundles the JavaScript engine and Acorn 8.17.0 with their licenses.
- Publish npm `unk-scanner` 0.1.1 with corrected installation instructions in the packaged README; a fresh registry install reports version 0.1.1.
- Add bounded worker parsing, heap and finding limits, explicit bounded gzip decoding, preserved BOM columns, and nonblocking rejection of named pipes.
- Recognize retained AES-GCM loader structure through linked top-level bindings without decrypting or executing the source.
- Add separate exact-source identity records for the retained login interface, shared module-preload polyfill, and obfuscated extension. Keep contextual identity out of behavioral findings.
- Add marker-identifier and parenthesized optional clipboard-owner recognition, packed-install checks, and a Node 22/24 Linux, Windows, and macOS CI matrix.
- Retain 33 experimental YARA rules in 28 files, replayed against retained investigation artifacts. Keep the scope and limitations documented; no Sigma event rules are included because authentic endpoint logs were unavailable for replay.

## 2.0.0 - 2026-10-27

This release replaces the initial mixed prototype with detections validated against retained case artifacts.

- Add 33 named YARA rules across 28 files. Every rule compiled and matched at least one retained investigation artifact in a read-only replay.
- Replay 192 selected files across 395 raw and archive-member views. A separate local software scan covered 1,914 files and 2,379 views with no hits. This small baseline does not establish fleet-wide false-positive rates.
- Keep the wallet-agent YARA condition tied to ELF magic at byte zero after a marker-rich prose false positive; the prose boundary fixture remains negative.
- Remove Sigma event rules because authentic endpoint event logs were unavailable for target replay.
- Omit workspace-file rules because the original `.vscode` task and settings targets were not retained.
- Retain the parse-only Acorn scanner and inert boundary tests.

The rule set is experimental. A match identifies content for investigation and does not establish execution, collection, attribution, or production precision and recall.

## 1.0.0 - 2026-10-26

Initial public release with the parse-only scanner and early detection prototypes. Its Sigma and workspace-file rules were removed in 2.0.0 after checking which detections could be evaluated against authentic retained targets.
