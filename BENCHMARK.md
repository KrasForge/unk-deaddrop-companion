# Corpus benchmark

Scanner 0.2.0 (engine source SHA-256 `a5d2e40fd7b8cf3428d8aefd3fca15901302f959c7e9376fbc1474af8ac6efff`), run on 29 October 2026 over 2,500 npm packages and 500 Open VSX extensions.

| Measure | Result |
| --- | --- |
| Unique source files analysed | 143,153 (from 197,978 occurrences; 113 members over 8 MiB excluded at acquisition) |
| Error-level findings on the corpus | **0** |
| Warning-level findings | 107, all reviewed: 90 confirm real obfuscation, 17 are accurate observations in legitimate code |
| JavaScript files Acorn rejected although valid | 28 of 108,096 valid `.js`/`.mjs`/`.cjs` files (0.026%) |
| Obfuscated call sites decoded | 486,208 of 486,601 (99.92%) in 90 string arrays |
| Throughput, 4 isolated processes (CLI path) | 412 files/s, 11.2 MB/s |
| Throughput, 4 in-process worker threads | 439 files/s, 11.9 MB/s |
| Retained UNK_DeadDrop artifacts | 12 of 14 at error or warning; the other two are context-only by design |

Popularity is a convenience sample, not ground truth, and files within a package are correlated; see [limitations](#limitations).

## Corpus

| Ecosystem | Selection | Packages | Unique files |
| --- | --- | --- | --- |
| npm | `npm-high-impact@1.13.0` `npmTopDownloads`, top 2,500 | 2,500 downloaded | 71,820 |
| Open VSX | API `sortBy=downloadCount`, top 500 | 500 downloaded | 85,055 |

The two sets share files (bundled dependencies), so the union is 143,153. The npm snapshot replaces the live ecosyste.ms ranking, which returned HTTP 403; it must not be described as a verified current global top 2,500. Open VSX is a separate registry from the VS Code Marketplace. `benchmark/manifest.json` pins the ranking source, versions and retrieval time. Acquisition receipts record archive and file hashes. Archives were read as data: no installs, no lifecycle scripts, and caps of 256 MiB per archive, 8 MiB per source and 512 MiB expanded per package. Corpus source is not redistributed.

## Parse coverage

Acorn parsed 111,189 files and rejected 31,964. Each rejected file was checked independently with `@babel/parser` 8.0.8, using TypeScript and JSX plugins by extension. 31,292 of the rejected files are valid source:

| Rejected extension | Files |
| --- | --- |
| `.ts` / `.mts` / `.cts` | 28,864 / 2,039 / 751 |
| `.tsx` / `.jsx` | 206 / 1 |
| `.js` / `.mjs` / `.cjs` | 99 / 2 / 2 |

The scanner does not parse TypeScript; there is no fallback parser, and rejected files receive no findings. Published packages normally also ship compiled JavaScript, which is analysed. Of 108,171 JavaScript files, 103 were rejected, and 28 of those are valid under Babel; all 28 contain JSX. The other 75 are invalid or partial sources. In this corpus that is a 0.026% valid-JavaScript rejection rate.

## Findings

| Rule:severity | Instances | Files | Packages | Review |
| --- | --- | --- | --- | --- |
| `string-array-obfuscation:warning` | 90 | 90 | 5 | All confirmed obfuscator.io structures |
| `electron-run-as-node:warning` | 16 | 9 | 7 | All legitimate launches |
| `clickfix-clipboard-command:warning` | 1 | 1 | 1 | Installer copy button |
| `clipboard-write:note` | 1,272 | 521 | 167 | Context |
| `campaign-marker:note` | 298 | 243 | 155 | Context |
| `obfuscated-string-indicator:note` | 273 | 15 | 4 | Context |
| `electron-run-as-node:note` | 183 | 172 | 127 | Context (assignments) |
| `clipboard-copy-override:note` | 55 | 28 | 18 | Context |

No error-level finding occurred in any of the 143,153 files. For the error severity that is an observed rate of 0. A naive per-file 95% upper bound would be 3/143,153 (0.002%), but files are not independent samples, so treat this as a calibration result rather than a deployment false-positive rate.

Every warning was reviewed against the cited source; the decisions are in `benchmark/review-ledger-v2.csv` and `benchmark/reviewed-v2.json`:

- **Electron launches:** the 16 warnings are four copies of TypeScript's own `tsserver` typings installer, SSH proxy shims, CLI shims, a local helper server and a Playwright browser install. All run Node through the editor binary for legitimate reasons. None hides execution, so none escalates.
- **Clipboard command:** the single warning is a setup wizard's "copy install command" button (`curl … | bash`, `irm … | iex`). A plain install command is a warning by design.
- **Obfuscation:** five commercial extensions ship obfuscator.io output. The finding is correct (strings are hidden) and says nothing about intent.

### Severity calibration

Earlier runs during development shaped the severities, and the changes are recorded here because they are design decisions, not tuning against hidden labels:

- **Electron:** assigning `ELECTRON_RUN_AS_NODE` (182 files) and launching with it are common in legitimate extensions. Assignments became notes, and launches became warnings that escalate only when the same file hides execution.
- **Copy override:** copy-override handlers (51 warnings in 26 files) are rich-text editors and notebooks, so the rule became a note. The ClickFix rule still escalates a substituted command.
- **Data arrays:** lookup arrays with index arithmetic (Roman numerals in PDF.js, HTML entity names, tag lists) briefly looked like string-array decoders. Array variables are now reported only with a proven rotation, and self-redefining array functions remain the primary signal.
- **Minified rotation loop:** a minified rotation loop (`for(;;)`, no parameters) was at first missed, which caused 22 Zencoder arrays to be decoded with rotation 0. They are now solved by checksum, and a regression test keeps an unsolved loop from being treated as unrotated.

## String-array recovery

90 arrays were found in 5 packages: 71 solved by the obfuscator's checksum loop (69 plain, 1 RC4, 1 sharing base64 and RC4 decoders) and 19 left unresolved. Across the corpus, 486,208 of 486,601 decoder call sites were decoded. The unresolved arrays are ES5-style output in which the decoder is reached through `var` aliases, which the evaluator deliberately does not follow, because `var` bindings can be reassigned. They are reported as unresolved, not guessed.

## Throughput

Hardware: Intel Xeon W-1370 (16 threads), 16 GB, Fedora, Node v22.22.2, 4 analysis workers. Timing covers read, UTF-8 decode, analysis, messaging and JSONL output. Acquisition is excluded, and so is the in-process run's Babel validation of rejected files.

| Mode | Wall time | Files/s | MB/s |
| --- | --- | --- | --- |
| 4 isolated child processes (the CLI's `ScannerPool`) | 347.3 s | 412.2 | 11.2 |
| 4 worker threads around `inspect()` | 326.0 s | 439.1 | 11.9 |

Both modes produced identical statuses and findings. Per-file analysis time for parsed files was 0.78 ms at the median, 16.1 ms at p95 and 188 ms at p99, with a maximum of 7.6 s for an 8 MB bundle. Run-to-run variation across the final development runs was roughly ±10%.

On a 3,000-file sample, 0.2.0 takes about 17% longer than 0.1.1 (18.3 s against 15.6 s), because it now does deobfuscation, scoping and more rules. Removing Acorn location objects lowered peak memory on a 7.9 MB bundle from 462 MB to 399 MB. With the previous 256 MiB heap, 13 bundles of 5–8 MB failed in isolation; the default is now 512 MiB, and all files completed.

## Retained artifacts

Static analysis of the investigation's retained JavaScript, in isolated processes; nothing was executed (`benchmark/artifact-sensitivity-v2.json`, hashes only).

| Artifact | Result |
| --- | --- |
| ClickFix lure bundles (three generations) | error: `clickfix-clipboard-command` (builder code and caller tracing) |
| Encrypted loaders (three) | error: `encrypted-loader` |
| Decrypted collectors (three) and Windows Node/Python pipeline | error: `electron-run-as-node` with hidden PowerShell |
| VSIX extension entry point and Node bootstrap | warning: `string-array-obfuscation`, solved by checksum (rotation 391, 2,139/2,140 sites; rotation 261, 15/17) |
| Windows Node agent | notes only |
| Domatisc login interface | no findings (context-only artifact identity) |

These files informed the rules, so they show that the rules fire on their targets, not how well the rules generalise to unseen variants.

## Three-tier evaluation and hardening (unreleased 0.3.0)

After 0.2.0, the scanner was evaluated on three further corpora on one server (8 vCPU, 15 GiB). The companion scanner paper gives the full analysis; the records are here.

| Tier | Corpus | Frozen engine (`caf3f552…`) |
| --- | --- | --- |
| 1 | top 5,000 npm and top 1,000 VS Code Marketplace extensions plus the Open VSX set; 332,054 unique files, 188,901 outside the calibration set | 0 errors and 12 reviewed benign warnings in the additional files (`tiers/review-t1-heldout.csv`) |
| 2 | 20,000 most recently changed npm packages (19,976 acquired); 2,403,437 unique files | 2 errors, both false positives; warnings reviewed (`tiers/review-t2.csv`) |
| 3 | Datadog malicious-packages dataset `438afad`: 122 IDE extensions and 2,000 seeded npm samples; 41,359 files | 62 of 2,122 samples at warning, none at error |

Manifests are in `tiers/`, run summaries in `summary-*.json`. A bypass test (`bypass/`, 23 inert fixtures) found that 18 of 19 single-change variants evaded a rule, lowered its severity or defeated recovery; one produced incorrect strings.

The hardened engine (`202f56f2…`, see `CHANGELOG.md`) was then rescanned against everything, diffed file by file against the frozen results (`mitigation/`, script `mitigation/mitdiff.py`):

| Check | Hardened engine |
| --- | --- |
| Bypass variants | 18 of 19 at baseline severity and full recovery (the exception fetches its command at run time); `test/bypass.test.mjs` |
| Retained artifacts | 14 of 14 expected outputs |
| Calibration (143,153 files) | 0 new errors; 2 files (1 package) newly warning on genuine obfuscation; all 96 arrays solved by checksum |
| Tier 1 (332,054) | 0 new errors; the same package; none in the additional files |
| Tier 2 (2,403,437) | 0 new errors; 3 files (2 packages) newly warning; unresolved arrays from 1,387 to 16 |
| Tier 3 (41,359) | 0 new errors; detected samples from 62 to 64 |
| Throughput, calibration, 4 in-process workers | 281 files/s (frozen: 264) |

**Decoder coverage (revised engine, `ba4d1468…`).** The controlled experiment in `rotation/` showed two decoder shapes the hardened engine did not recognise. Both were fixed, and every corpus was rescanned (`mitigation/revised/`, diffed against the frozen and hardened results):

| Check | Revised engine, compared with hardened |
| --- | --- |
| Bypass fixtures, artifacts | unchanged: 22 of 23, 14 of 14 |
| Calibration | 15 more files warn (2 commercial extensions), all checksum-solved and fully decoded; 0 new errors |
| Tier 1 | 19 more files warn (4 outside calibration, 3 extensions); 0 new errors |
| Tier 2 | 917 more files warn (5 packages), all fully decoded string arrays; 0 new errors; newly decoded strings screened, none malicious |
| Tier 3 | detected samples 64 → 128 (`t3samples.py`), none at error |
| Controlled experiment | recall 99.8% on 5.9.0 and 4.1.1; 99.7% on a held-out set of five releases; 0 of 3,265,560 decoded sites misplaced |

A first version of the hardening raised an error on a benign extension that relaunches its own runtime as a detached helper server; the rule was narrowed before these runs (see `docs/rules.md`). The fixtures were written together with the fixes, so these results record regression coverage, not robustness against an adaptive adversary.

## Limitations

- The corpus is popular, published code. It does not represent private repositories, malware-adjacent code or a team's own codebase, and popularity is not proof of benignness.
- Reviews were static readings of the cited code by the analyst's tooling session, not audits; spot-check the ledger before relying on it.
- TypeScript and JSX are not parsed.
- No general child-process detector exists, by design; only the Electron and temporary-script patterns are reported.
- Severity calibration used this corpus. A held-out corpus would be needed to estimate false-positive rates for other code populations.

## Reproduce

```sh
python benchmark/acquire.py                                 # corpus (about 3.8 GB of source)
npm ci --prefix benchmark --ignore-scripts                  # pinned Babel for validation
BENCH_TAG=-v2 BENCH_VALIDATE=1 node benchmark/run.mjs 4     # in-process run + validation
BENCH_TAG=-v2 BENCH_MODE=isolated node benchmark/run.mjs 4  # CLI isolation path
python benchmark/report_v2.py                               # analysis-v2.json and review ledger
```

Results from scanner 0.1.x (`results-1.jsonl`, `summary-4-npm-validated.json`, `reviewed-npm-findings.json`) are kept for comparison and superseded by the files above.

## Ranking provenance

The npm selection uses `npm-high-impact@1.13.0`, published 8 June 2026; its maintainer describes `npmTopDownloads` as download-sorted and warns that download counts can be gamed (<https://github.com/wooorm/npm-high-impact>). The Open VSX ranking endpoint is <https://open-vsx.org/api/-/search?size=100&offset=0&sortBy=downloadCount&sortOrder=desc>; pagination was captured as retrieved, and the service does not provide a transactional ranking snapshot.
