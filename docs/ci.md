# CI and code scanning

`unk-scanner --format sarif` writes SARIF 2.1.0. GitHub code scanning shows the results as alerts with rule descriptions, ATT&CK tags, `security-severity` scores, file paths and lines. Files that could not be analysed are listed as tool execution notifications rather than dropped.

## GitHub Actions

```yaml
name: unk-scanner
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '22'
      - run: npm install --global unk-scanner@0.2.0 --ignore-scripts
      - run: unk-scanner --format sarif --fail-on error . > unk-scanner.sarif
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: unk-scanner.sarif
          category: unk-scanner
```

`--fail-on error` fails the job on error-level findings; use `warning` for a stricter gate or `none` to report only. The upload step runs even when the gate fails, so the alerts are visible. Directories are searched for `.js`, `.mjs` and `.cjs` files, and `node_modules` is skipped unless `--include-node-modules` is given. To check vendored dependencies or an unpacked VSIX, pass that directory with the flag.

## Pre-commit

```sh
#!/bin/sh
# .git/hooks/pre-commit
files=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(c|m)?js$')
[ -z "$files" ] && exit 0
unk-scanner --fail-on error $files > /dev/null
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Analysis completed; no finding reached `--fail-on` |
| 1 | A finding reached the `--fail-on` level |
| 2 | Invalid arguments, no file could be analysed, or `--strict` with any analysis error |

## Isolation in CI

Each file is parsed in a separate Node process under the permission model, with no write, child-process, worker or addon access and reads limited to the scanner's code. On Linux the process is also given an empty network namespace and rlimits when the runner allows unprivileged user namespaces. The `isolation` object in JSON output, and the SARIF invocation properties, record what was applied. Some hosted runners restrict user namespaces; the scan still runs, without the network namespace.
