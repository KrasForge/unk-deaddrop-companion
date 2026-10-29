# unk-scanner

Static JavaScript triage from the [UNK_DeadDrop investigation](https://krasforge.github.io/UNK_DeadDrop/). It finds ClickFix clipboard command substitution, Electron `ELECTRON_RUN_AS_NODE` launches, obfuscator.io string arrays (and recovers their strings), encrypted loaders and campaign markers. Input is parsed and partially evaluated in isolated processes and never executed.

## Install and run

Requires Node.js 22 or later.

```sh
npm install --global unk-scanner@0.2.0 --ignore-scripts
unk-scanner suspect.js > findings.json
unk-scanner --format sarif --fail-on error src/ > results.sarif
unk-scanner --help
```

Arguments are files or directories; directories are searched for `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.mts`, `.cts` and `.tsx` (not `.d.ts`), skipping `node_modules` unless `--include-node-modules` is given. Use `--` before option-like paths. One file with JSON output prints a single report. Several files print `{ schemaVersion, tool, isolation, files }`.

| Option | Effect |
| --- | --- |
| `--format json\|sarif` | Output format; SARIF 2.1.0 for code scanning ([CI guide](https://github.com/KrasForge/unk-deaddrop-companion/blob/main/docs/ci.md)) |
| `--fail-on error\|warning\|note\|none` | Exit 1 when a finding reaches the level (default `none`) |
| `--rule FILE` | Load an additional rule module (repeatable) |
| `--timeout MS` / `--jobs N` | Per-file deadline (default 10,000) and analysis processes (default up to 4) |
| `--strict` | Exit 2 if any file could not be analysed |
| `--gzip` | Decode one gzip-compressed input; compressed and decoded sizes are capped at 8 MiB |

Exit 0 means analysis completed, including when there are findings below `--fail-on`. Exit 1 means the `--fail-on` threshold was reached. Exit 2 means invalid arguments, no analysable input, or `--strict` with an analysis error; errors go to stderr.

## Findings

Each finding has `kind`, `severity`, `line`, `column` and `detail`. Rule-specific fields such as `indicators` and `evidence` may also appear. The rules, their severities and their escalation conditions are documented in [rules.md](https://github.com/KrasForge/unk-deaddrop-companion/blob/main/docs/rules.md). Severities were calibrated on 3,000 popular npm packages and Open VSX extensions, where no error-level finding occurred ([benchmark](https://github.com/KrasForge/unk-deaddrop-companion/blob/main/BENCHMARK.md)).

The report also contains:

- `schemaVersion` (2);
- the input's SHA-256 and byte count;
- `deobfuscation`, giving each string array's variant, offset, rotation, method and decoded call-site count;
- `artifactMatches`;
- `limitations`.

With `--gzip`, `decoded` records the decompressed hash and size.

A finding is a review lead, not a verdict, and an empty report does not establish safety. Output can contain strings from the input; handle it with the input's sensitivity.

## Isolation

The CLI parses each file in a child process under the Node permission model. The process has no file writes, child processes, workers or addons, and can read only the scanner's own code. It runs with a capped heap and an empty environment. On Linux, where permitted, it also runs in an empty network namespace with rlimits. A per-file deadline kills a stuck process. The JSON and SARIF output record which controls applied. These reduce the impact of a parser defect but are not a sandbox against a V8 exploit; analyse hostile samples in a disposable environment.

## JavaScript API

```js
import { inspect } from 'unk-scanner';
const report = inspect('navigator.clipboard.writeText("example");');
const custom = inspect(source, { rules: [myRule] });
```

`inspect()` runs synchronously in the caller's process without isolation or deadlines. It hashes the UTF-8 encoding of the text. The CLI hashes the original file bytes, including any byte-order mark.

## Encrypted loaders and artifact identity

An `encrypted-loader` finding links an embedded base64 or hex payload, its decryption with a recognised cipher, and a code-compiling sink (`Module._compile`, `vm`, `eval`, `Function`) through bindings in any scope. Nothing is decrypted. `artifactMatches` identifies three exact retained source hashes and is separate from findings: login code and a shared polyfill are context only.

## Development

From the companion repository root:

```sh
npm ci --ignore-scripts
npm test
npm run test:package
```

Code is MIT licensed. Acorn retains its own license. The package includes no malware samples or credentials.
