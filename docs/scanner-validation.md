# Scanner validation, 26 October 2026

Version 0.1.0 was reviewed on Linux with Node.js 22.22.2 using retained investigation files and a small local software baseline. Inputs were passed only to the static parser, never executed.

The review selected all 31 .js and .mjs files under the local incident directories, excluding node_modules and tools directories. Sixteen were plain JavaScript: all parsed, and eleven produced findings. The other fifteen were gzip-compressed HTTP bodies despite their .js filenames. The initial CLI rejected those raw bodies as invalid UTF-8. The hardened CLI now recognizes gzip magic and supports explicit `--gzip` decoding with an 8 MiB output bound. All fifteen compressed files parsed with that option, and twelve produced findings. Both input and decoded hashes are retained.

After adding encrypted-loader recognition, 27 of 31 plain or decoded artifact views produced findings (previously 23). These counts include related or duplicate content and panel assets; they are not recall estimates. Four install_guard loader views now produce an encrypted-loader finding based on linked base64, AES-GCM, authentication-tag, decoded-text, and _compile syntax. The retained obfuscated extension entry point remains unmatched. The scanner does not decode string tables or establish execution.

For the baseline, the first 500 lexicographically sorted .js paths under the local site's node_modules directory were scanned. All parsed. One Astro-generated dependency bundle produced a clipboard-write finding; it was a legitimate clipboard operation, with no campaign-marker finding. This is expected syntactic behavior but would be a false alarm if findings were treated as malware verdicts. This convenience sample is not representative of enterprise software or sufficient for a precision estimate.

Two implementation defects were corrected during review:

- Opening a named pipe could wait indefinitely before the regular-file check. Nonblocking open now allows the check to reject it.
- UTF-8 decoding stripped a leading byte-order mark and shifted first-line columns. The decoder now preserves it while hashes continue to cover original bytes.

Twenty-four Node tests pass, including regression checks for both defects, worker deadlines and failures, excessive findings, gzip expansion limits, malformed compressed streams, marker identifiers, parenthesized optional clipboard owners, and encrypted-loader link boundaries. Loader tests cover disconnected data, missing authentication, unrelated compilation, renamed variables, computed methods, comments, quoted code, nested scopes, and ordering. A separate package test verifies the ten-file allowlist, installation outside the checkout, the CLI, and the public API. The installed package replay successfully parsed all 31 retained files (15 with --gzip) and all 500 baseline files, with original-byte hash checks. Package installation and analysis required no execution of submitted JavaScript. Windows and macOS execution have not been verified locally. A Node 22/24 CI matrix for Linux, Windows, and macOS is prepared but has not run remotely.

The CLI parser now runs in a worker with a 10-second deadline and V8 heap limits; finding-count overflow fails explicitly. These bounds do not establish a complete OS security sandbox. The synchronous API still runs in the caller process.

The encrypted-loader pass produced four new matched artifact views and no new findings in the same 500-file baseline. The installed tarball independently reproduced 27 matched inputs out of 31 with original-byte hash verification. This is a narrow syntactic recognizer, not a general deobfuscator; receivers may be overridden, and the finding does not demonstrate that decryption or execution succeeded.

Per-file local records, including paths and hashes, are retained in ignored analysis-output/loader-review.json and analysis-output/loader-package-review.json; earlier review records remain alongside it. They are not included in the npm package.


## Exact-identity coverage

The rebuilt installed package now accounts for all 31 retained inputs: 27 have findings and four have separate artifactMatches entries. This is not 31 behavioral detections. The four views represent three distinct decoded-source hashes: two copies of login-interface code (context-only), one generic module-preload polyfill (shared-web-component), and the obfuscated extension entry point (known-investigation-artifact). These records preserve the distinction between observed file identity and malicious behavior.

Identity matches are deliberately outside findings. The polyfill may occur in unrelated benign sites, and a matching login interface alone does not prove a malicious panel. The extension hash only covers the exact retained source. No new deobfuscation or variant detection is claimed.

The installed-package replay verified all 31 original hashes and the expected division of findings and identity records. The 500 unchanged baseline file hashes produced no identity matches. Behavioral logic was unchanged in this identity addition; the earlier baseline's single benign clipboard finding remains the behavioral result. Records are in analysis-output/identity-package-review.json and analysis-output/identity-baseline-review.json.
