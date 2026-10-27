# Parse-only AST engineering

The original case used Acorn to locate string tables and decoder wrappers before
separate decoding. This companion provides a smaller, newly implemented triage
tool; it is not the original full deobfuscator and does not claim equivalent
coverage.

Input bytes → UTF-8 validation → Acorn AST → iterative tree traversal → literal
folding / member-call recognition → JSON findings with locations and hash.

The scanner accepts JavaScript module syntax, falling back to script syntax. It
recognises clipboard writes through `navigator.clipboard.writeText(...)`-shaped
and `event.clipboardData.setData(...)`-shaped calls, including literal computed
names and optional member access. It also searches folded string literals for
specific markers from the clipboard lure, phase-three home sweep, browser
App-Bound decryption path, Windows collection branches, COM elevation builder,
and Overlord agent. Receiver names are syntactic: an object named `clipboard`
might be unrelated to a browser. A finding does not prove command execution,
clipboard deception or malicious intent.

Only string literals, interpolation-free template literals and string-literal
addition are folded. Variables, getters, calls and mixed-type coercion are not
evaluated. The tool does not reconstruct encrypted tables, follow aliases, prove
data flow or compare displayed text to copied text. Dynamic arguments remain
explicitly unresolved. Nested literal folding stops at depth 32.

The CLI limits input to 8 MiB, validates a regular file, hashes original bytes,
and rejects malformed UTF-8. Parsing is in-process and can still consume substantial
CPU/memory on adversarial syntax; use OS resource controls and isolation for
untrusted samples. No input is imported, installed, fetched or executed.

## npm package

The scanner implementation lives in `packages/unk-scanner/src/inspect.mjs`. The original `src/inspect-js.mjs` entry point delegates to it. The npm package exposes the `unk-scanner` executable and the `inspect` API. The companion root remains private.

Before release, run `npm ci --ignore-scripts`, `npm test`, and `npm pack --workspace unk-scanner`. Run `npm run test:package` to check the ten-file tarball allowlist and verify its installed executable and API in an empty directory. Publish only the reviewed package tarball with an authorized npm account. Update the package and root READMEs after publication. Scanner versions are independent of the companion rule-suite version. Future changes should preserve schemaVersion 1 or explicitly version incompatible output changes.

The CLI uses a worker with a 10-second deadline and V8 heap limits. The synchronous API retains caller-process behavior. Explicit `--gzip` decoding bounds compressed and decoded input to 8 MiB and records both hashes. A 10,000-finding limit fails the analysis explicitly. The matcher also recognizes an allowlist of marker identifiers and parenthesized optional clipboard owners; it still performs no variable or alias resolution.

Encrypted-loader analysis recognizes a narrow chain of top-level const bindings. It links embedded base64, fixed IV/tag/ciphertext subarrays, AES-256-GCM decipher/update/final calls, authentication-tag assignment, and text passed to _compile. It emits evidence locations rather than embedded material. These are syntactic relationships; receiver identity and runtime outcomes remain unproven. Tests disconnect individual links to verify that unrelated encryption and compilation do not form a finding.

The additive artifactMatches field identifies three exact decoded-source hashes independently of findings. Context-only login code and a shared polyfill are explicitly classified as non-alert context. The obfuscated extension has exact identity coverage only. Counts of identified artifacts must remain separate from findings; neither measures recall on unseen variants.
