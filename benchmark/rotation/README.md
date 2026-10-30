# Controlled string-array recovery

A ground-truth test of string-array recovery, reported in Section 5.7 of the scanner paper. Benign source files are obfuscated with javascript-obfuscator under a grid of string-array options, so every hidden string has a known original. `unk-scanner` and three published deobfuscators are then scored the same way.

## Design

- **Inputs** (`select.mjs`, `inputs.json`): 50 files from the calibration corpus, chosen by seeded sample (seed 20261030) from 1,325 eligible packages, one file per package. Each file has no findings, parses with Acorn as a script, is 3–30 KB, and has at least 15 distinct string literals. The sources are not redistributed; `inputs.json` records their hashes.
- **Obfuscation** (`generate.mjs`, `samples-v5.json`, `samples-v4.json`): javascript-obfuscator 5.9.0 (current at the time of the test) and 4.1.1 (the release current when the newest baseline was last updated). The grid has 72 configurations: string encoding (none, base64, RC4) × rotation (on, off) × wrappers (none; two variable wrappers; two function wrappers) × calls transform (off, on) × index shift (off, on). Each sample gets its own seed. Only the string-array transforms are enabled, so control-flow flattening and dead code do not add strings. The 3,600 samples per version are kept on the evaluation server.
- **Tools** (`measure.mjs`, `package.json`, `package-lock.json`):
  - `unk-scanner` frozen engine (`caf3f552…`) and hardened engine (`202f56f2…`);
  - webcrack 2.16.0, which runs the decoder in `isolated-vm`;
  - synchrony (npm `deobfuscator`) 2.4.6;
  - obfuscator-io-deobfuscator 1.0.6.

  The scanner engines run on all 7,200 samples. The baselines run on a stratified subset (`ids-subset.txt`): every configuration and both versions with the first 10 inputs, 1,440 samples, one process per sample with a 60 s limit.
- **Scoring:** see the header of `measure.mjs`.
  - Hidden strings are the original's string literals, template text and identifier property names that do not appear outside the obfuscator's string array.
  - A tool recovers a hidden string when the string appears in its output, or among the scanner's decoded call-site values.
  - A string a tool produced counts as wrong only when the original and the obfuscated sample cannot account for it, neither directly nor as a concatenation of their strings.
  - Set scoring cannot see a wrong rotation of a plain or base64 array, so the scanner's decoded call sites are also aligned, in source order, with the original's sequence of string literals, template text, property names and method names. Sites outside the longest common subsequence count as misplaced. `validate-alignment.mjs` shows that the check works: 25 correctly decoded samples give 0 misplaced sites out of 5,402, while shifting each decoded value by one array position misplaces 4,240 of 4,903.

## Revised engine and held-out set

The experiment exposed two recognition gaps in the hardened engine: the self-replacing decoder of 4.x output, and function wrappers that declare an offset object before returning. Both were fixed (revised engine, `ba4d1468…`). Because the fixes were designed against these samples, a held-out set was generated afterwards: 20 further inputs from the same seeded order (`SKIP=50 COUNT=20`, `inputs-heldout.json`), obfuscated under the same 72 configurations by 5.9.0 and 4.1.1, and by three releases not used before, 5.0.0, 4.2.2 and 3.2.7 (`samples-h*.json`, 7,200 samples). All three scanner engines run on all 14,400 samples (`ids-scanner.txt`; results gzipped).

| Engine | 5.9.0 | 4.1.1 | Held-out 5.9.0 / 5.0.0 / 4.2.2 / 4.1.1 / 3.2.7 | Misplaced or wrong |
| --- | --- | --- | --- | --- |
| frozen | 68.3% | 0% | 64.8% / 64.9% / 64.9% / 0% / 0% | 0 |
| hardened | 87.2% | 0% | 85.0% / 85.0% / 85.0% / 0% / 0% | 0 |
| revised | 99.8% | 99.8% | 99.7% for every release | 0 of 3,265,560 decoded sites |

`show-misplaced.mjs` lists the sites outside the alignment. The held-out set also exposed a gap in the reference sequence, not the scanner: class field names were missing from it. After adding them, every engine has 0 misplaced sites.

## Results (`summary.json`)

| Tool | 5.9.0 recall | 4.1.1 recall | Samples with wrong strings |
| --- | --- | --- | --- |
| unk-scanner, frozen (7,200) | 68.3% | 0% | 0 |
| unk-scanner, hardened (7,200) | 87.2% | 0% | 0 |
| unk-scanner, hardened (subset, 1,440) | 90.3% | 0% | 0 |
| webcrack (1,440) | 98.1% | 98.1% | 144: one input; `JSON.parse` of a constant becomes an object literal |
| synchrony (1,440) | 0%: "no decoder" | 98.2% | 144: one input; an obfuscator identifier becomes a property name |
| obfuscator-io-deobfuscator (1,440; 144 timeouts) | 0%: array left in place | 98.0% | 144: one input; constant propagation folds a variable to `undefined` in a message |

The scanner never produced a wrong string, and none of its decoded call sites was misplaced: 638,574 sites for the hardened engine and 492,474 for the frozen engine. The hardened engine's misses on 5.9.0 output come from function wrappers combined with the calls transform: there each wrapper declares a local offset object before returning, which falls outside the single-return helper model. In 4.1.1 output, it does not recognise the self-redefining decoder that rebases its index inside the inner function. In both cases it reports nothing rather than guessing. The revised engine closes both gaps (see above). Webcrack's missing 2% are strings it folds into longer literals or rewrites. synchrony and obfuscator-io-deobfuscator were not inspected string by string.

`example/` holds the three-line program and its seed-19 obfuscation used as the worked example in Section 3.3.

## Reproduce

```sh
npm ci                              # javascript-obfuscator 5.9.0 and the baselines
(cd v4 && npm ci)                   # javascript-obfuscator 4.1.1
node select.mjs                     # needs the calibration corpus and its results
node generate.mjs v5 .
node generate.mjs v4 ./v4
./run.sh v5 v4                      # paths assume the evaluation server layout
python3 summarize.py
```
