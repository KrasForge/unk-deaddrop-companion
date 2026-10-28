# unk-scanner

Local, static JavaScript triage based on the [UNK_DeadDrop investigation](https://krasforge.github.io/UNK_DeadDrop/). Acorn parses the input without executing it. The scanner reports literal and allowlisted identifier campaign markers, syntactic clipboard writes, and a specific encrypted-loader pattern with one-based source locations.

## Install and run

Requires Node.js 22 or later. Install version 0.1.0 from npm:

```sh
npm install --global unk-scanner@0.1.0 --ignore-scripts
unk-scanner suspect.js > findings.json
unk-scanner --help
unk-scanner --version
```

Use `unk-scanner -- ./-filename.js` for option-like paths. The command accepts one UTF-8 JavaScript file, up to 8 MiB, and emits JSON. For gzip-compressed HTTP bodies, use `unk-scanner --gzip input.js`. Both compressed and decoded sizes are capped at 8 MiB. Without the flag, gzip magic produces an actionable error. Exit status 0 means analysis completed, including when findings exist. Status 2 means invalid arguments, unreadable input, encoding failure, or parse failure. Errors go to stderr.

## Findings and limits

With `--gzip`, top-level hashes and sizes describe the original compressed input; `decoded` records the decoded SHA-256, byte count, and encoding. Locations refer to decoded JavaScript.

The JSON includes schemaVersion, the original file's SHA-256, byte count, findings, and limitations. Each finding contains kind, line, column, and detail. Clipboard literal details are truncated to 240 JavaScript string code units; dynamic arguments are marked unresolved.

The scanner folds string literals, templates without interpolation, and literal concatenation. It supports module syntax with a script-syntax fallback. It does not resolve aliases, track data flow or reachability, decrypt payloads, or decode obfuscated string tables. A marker or clipboard write alone does not establish maliciousness; an empty result does not establish safety.

Analysis does not execute or import the input, install its dependencies, or contact remote infrastructure. Output can contain source strings. Handle reports with the input's sensitivity. The CLI parses in a worker with a 10-second deadline and V8 heap limits (256 MiB old generation, 32 MiB young generation). A maximum of 10,000 findings prevents unbounded reports. Limit failures return exit 2 without a partial report. These are application limits, not a security sandbox or a total process-memory guarantee. Use operating-system isolation for untrusted inputs.

## Encrypted-loader findings

An `encrypted-loader` finding links a specific top-level sequence: a literal base64 buffer, its IV/tag/ciphertext slices, an AES-256-GCM decipher, authentication-tag assignment, conversion of update/final output to text, and an `_compile` call receiving that text. Evidence locations identify five steps without copying keys or encrypted payloads into the report.

Recognition follows direct top-level `const` bindings. It tolerates renamed variables and literal-computed method names. It does not evaluate expressions, decrypt anything, establish that receivers are genuine Node APIs, or prove execution or successful authentication. Other loader layouts, nested scopes, mutable bindings, and string-table obfuscation may remain unmatched. Encryption or compilation alone does not trigger this finding; it is not campaign attribution.

## Exact artifact identity

`artifactMatches` is separate from `findings`. It identifies three exact decoded-source hashes retained in the investigation: the login interface, a shared module-preload polyfill, and the obfuscated extension entry point. The login interface has classification `context-only`; the polyfill is a `shared-web-component`. Neither is a malware alert or an attribution indicator. The extension match identifies the retained bytes but does not resolve its behavior.

With gzip input, identity matches use the decoded source hash, while the top-level hash still describes the original input. Any source-byte change invalidates exact identity. Do not merge identity counts into behavioral detection or recall statistics. Review context at the [research series](https://krasforge.github.io/UNK_DeadDrop/).

## JavaScript API

```js
import { inspect } from 'unk-scanner';
const result = inspect('navigator.clipboard.writeText("example");');
```

The synchronous API runs in the caller process without the CLI worker deadline or heap limits. The API accepts source text and hashes its UTF-8 encoding. The CLI hashes original file bytes, including any UTF-8 byte-order mark.

## Development

From the companion repository root:

```sh
npm ci --ignore-scripts
npm test
npm pack --workspace unk-scanner
```

Code is MIT licensed. Acorn retains its own license. This package includes no malware samples, YARA rules, or credentials. Existing YARA validation statistics do not measure scanner accuracy.
