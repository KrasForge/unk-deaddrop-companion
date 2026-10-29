# Scanner design

```
input bytes → UTF-8 validation → isolated analysis process
  → Acorn AST (no location objects) → iterative index with parent links
  → string-array recovery (decoder variant, offset, rotation)
  → rule visitors over one pass, with pure evaluation on demand
  → findings, deobfuscation summary, artifact identity → JSON or SARIF
```

Nothing from the input is executed, imported, installed or fetched. "Evaluation" means interpreting a small, side-effect-free expression subset in the scanner's own code.

## Pure evaluation

`evaluate.mjs` interprets the following:

- literals, templates and arithmetic, bitwise, comparison and logical operators on primitives;
- `const` bindings and literal object properties;
- array and string indexing and `.length`;
- `parseInt`, `String.fromCharCode` and a fixed set of string methods;
- functions whose body is a single `return` of a supported expression, with parameters bound to the call's arguments.

Anything else is unresolved, never guessed. This covers:

- calls and member access on unknown values;
- `let`/`var` bindings, assignments and loops;
- getters, spreads and regular expressions.

Each evaluation is capped at 20,000 steps and depth 48. Strings are capped at 1 MiB and arrays at 10,000 elements. Scopes are function-level; conflicting declarations in one scope are treated as unknown.

## String-array recovery

`deobfuscate.mjs` finds obfuscator.io-style arrays and their decoders. It identifies each decoder's variant and offset from its syntax. Plain, base64 (with the shuffled alphabet read from the decoder) and RC4 decoding are reimplemented in the scanner. Rotation recovery is described in [rules.md](rules.md#string-array-obfuscation).

On the retained UNK_DeadDrop VSIX entry point, the checksum gives rotation 391, the same value the manually verified decoder used. It decodes 2,139 of 2,140 call sites in under a second, without running the sample. The preprint's manual workflow compared candidate rotations by printable output. The checksum method reproduces the program's own stopping condition instead, and the printable heuristic is kept only as a guarded fallback.

## Context

Rules receive constant propagation and recovered strings, so a ClickFix command held in a `const` or hidden in a string array is visible to the clipboard rules. When a clipboard value cannot be resolved, the rule harvests string fragments; it does not evaluate them. Fragments come from the argument, from locally defined helpers and objects of helpers, and from caller arguments for generic copy helpers. All of these traversals have node budgets.

## Isolation and limits

The CLI analyses each file in a pool of child processes (`isolate.mjs`). Each analysis process runs as follows:

- under the Node permission model, with no file writes, child processes, workers, WASI or native addons, and reads limited to the scanner's own directory, Acorn and named rule files;
- with `--disallow-code-generation-from-strings`, a 512 MiB old-generation heap, an empty environment and lowered priority;
- on Linux, when the system permits it, inside an unprivileged user and network namespace with no interfaces (`unshare --net`), and with `prlimit` caps on CPU time (600 s per process), file size (0), open files (128) and core dumps.

A per-file deadline (default 10 s) kills the process, and a fresh one takes the next file. A crash, out-of-memory termination or timeout affects only that file's result.

Acorn is recursive-descent. Deeply nested input ends in a stack error, which is reported. The scanner's own walkers are iterative, and its recursive helpers (literal folding and evaluation) are depth-capped. Input is limited to 8 MiB, decoded gzip to 8 MiB, and findings to 10,000 per file; a limit failure gives an error, never a partial report.

These controls reduce the impact of a parser or engine defect; they are not a substitute for running the scanner itself in a disposable account or container when handling hostile samples at scale. The Node permission model is not a security boundary against a V8 exploit. The namespace and rlimits are the stronger layer and are only applied where available, so the report's `isolation` object records exactly what was applied.

The `inspect()` API runs in the caller's process without these controls.

## Output

JSON schema version 2 adds `severity` to each finding and a `deobfuscation` array to each report. A single file with JSON output produces one report, as in version 1. Several files or a directory produce `{ schemaVersion, tool, isolation, files: [...] }`. `--format sarif` produces SARIF 2.1.0 (see [ci.md](ci.md)).

## Rules

Rules are modules with `id`, `meta` and `create(context)`, dispatched in one pass over the AST. Built-in rules live in `src/rules/`; see [rules.md](rules.md) for each rule and for writing new ones.

## Release checks

Before release, run the following:

- `npm ci --ignore-scripts` and `npm test`;
- `npm run test:package`, which checks the tarball allowlist, the installed CLI, SARIF output and the API in an empty directory;
- `node scripts/prepare-python.mjs` before building the Python wheel.

Publish only reviewed tarballs from an authorized account. Scanner versions are independent of the companion rule-suite version.
