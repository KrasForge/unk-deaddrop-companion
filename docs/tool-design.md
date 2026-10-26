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
