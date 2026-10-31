# Changelog

## 2.2.0 - 2026-10-31

This companion archive adds the scanner's TypeScript and JSX parsing, bypass-hardening work, and controlled rotation benchmark. The npm and PyPI releases remain at 0.2.0; the newer scanner changes in this archive have not been published to either registry.

- Parse TypeScript and JSX: when Acorn rejects a file, `@babel/parser` 8.0.8 (pinned) parses it in AST-only mode with the TypeScript and/or JSX plugin chosen by file extension and emits ESTree, so all rules apply unchanged. Reports carry a `parser` field. TypeScript-only wrapper nodes (`as`, `satisfies`, non-null) are transparent to evaluation and member resolution.
- Directory scans include `.jsx`, `.ts`, `.mts`, `.cts` and `.tsx`, skipping `.d.ts` declarations.
- The isolated analysis process may read the pinned Babel packages; the Python wheel bundles them with their licenses.
- **Bypass hardening** (the one-change variants in `benchmark/bypass`, 22 of 23 now detected, up from 5; test `test/bypass.test.mjs`):
  - Evaluator: `let` and `var` bindings that no assignment resolves to are constants; `atob`, `Buffer.from(...).toString(...)`, spread arguments of known arrays and `eval` of a constant identifier name are evaluated. Other `eval` text is still not interpreted.
  - ClickFix: text stored into a mutable variable is harvested, copy handlers registered as object methods are recognised, and `document.execCommand('copy')` is a clipboard sink whose value is the field filled before it. Command text fetched at run time remains out of scope.
  - Electron: script text whose variable name is assembled or decoded is resolved; an encoded PowerShell command counts as hidden execution; a detached, windowless child of a binary other than `process.execPath` escalates (extensions relaunch their own runtime detached for helper servers, so that case stays a warning); script text bound to a variable escalates where the variable is used.
  - Encrypted loader: links an embedded base64 or hex payload, a recognised cipher (any mode; an authentication tag is evidence, not a requirement) and a code-compiling sink (`Module._compile`, `vm`, `eval`, `Function`) through bindings in any scope, instead of one top-level `const` pattern. Evidence roles are now `embedded-payload`, `cipher`, `authentication-tag`, `decrypted-text`, `code-sink`.
  - String arrays: the self-replacing decoder of javascript-obfuscator 4.x and earlier (the index is rebased inside the function the decoder assigns to itself) is recognised, and helpers that declare locals with pure initialisers before returning (function wrappers combined with the calls transform) are followed. Found by the controlled experiment in `benchmark/rotation`; recall there rose from 0% (4.1.1) and 87% (5.9.0) to 99.8%, and to 99.7% on a held-out set covering 3.2.7, 4.1.1, 4.2.2, 5.0.0 and 5.9.0, with no wrong or misplaced call site.
  - String arrays: rotation steps written with `splice`, `pop` or `unshift` are recognised; any other reordering of the array counts as rotation code; an array is taken as unrotated only when its decoded call sites read as text (previously a `splice` rotation decoded wrongly as unrotated); call sites reached through an alias or an object member are decoded.

## Scanner 0.2.0 - 2026-10-29

Scanner 0.2.0 (JSON schema version 2), published on [npm](https://www.npmjs.com/package/unk-scanner/v/0.2.0) and [PyPI](https://pypi.org/project/unk-scanner/0.2.0/). Fresh installs from both registries report 0.2.0, and the registry artifacts match the reviewed local builds (npm shasum `ad805cfd8f615cdceb20744c2599245a1733df02`; PyPI wheel and sdist SHA-256 identical to `dist/python-0.2.0`).

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
