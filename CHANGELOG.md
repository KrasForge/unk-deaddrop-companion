# Changelog

## Unreleased

- Add separate exact-source identity records for the retained login interface, shared module-preload polyfill, and obfuscated extension. Keep contextual identity out of behavioral findings.

- Recognize the retained AES-GCM loader structure through linked top-level const bindings, with five source evidence locations and no decryption or execution.

- Bound CLI parsing with a worker deadline and heap limits; reject excessive findings without a partial report.
- Support explicit bounded gzip decoding with original and decoded hashes. Preserve BOM columns and reject named pipes without blocking.
- Recognize specific marker identifiers and parenthesized optional clipboard owners. Add packed-install tests and a Node 22/24 Linux, Windows, and macOS CI matrix.

- Package the existing static scanner as npm and Python CLI/API distributions named `unk-scanner` 0.1.0. The Python distribution bundles the JavaScript engine and Acorn 8.17.0 with their licenses.
- Preserve the original scanner entry point and findings schema. The Python distribution is published on PyPI; npm publication remains pending a write-time one-time password.

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
