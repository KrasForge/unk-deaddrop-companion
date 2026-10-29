# Scanner rules

Every finding carries `kind` (the rule id), `severity` (`error`, `warning` or `note`), a one-based `line` and `column`, and `detail`. Severities were set against the [corpus benchmark](../BENCHMARK.md): a pattern that popular, legitimate software uses routinely is a note or a warning, and becomes an error only with corroborating context. A finding is a lead for review, not a verdict, and an empty report does not establish that a file is safe.

| Rule | Default | ATT&CK | Escalation |
| --- | --- | --- | --- |
| [`clickfix-clipboard-command`](#clickfix-clipboard-command) | error | T1204.004 | warning when the only signal is a plain install command |
| [`clipboard-copy-override`](#clipboard-copy-override) | note | T1204.004 | none; the ClickFix rule escalates command substitutions |
| [`clipboard-write`](#clipboard-write) | note | | none |
| [`electron-run-as-node`](#electron-run-as-node) | warning | T1218.015 | error when the file also hides execution; assignments are notes |
| [`child-process-hidden-script`](#child-process-hidden-script) | warning | T1059 | none |
| [`string-array-obfuscation`](#string-array-obfuscation) | warning | T1027 | none |
| [`obfuscated-string-indicator`](#obfuscated-string-indicator) | note | T1027 | none |
| [`encrypted-loader`](#encrypted-loader) | error | T1027.013 | none |
| [`campaign-marker`](#campaign-marker) | note | | none |

## clickfix-clipboard-command

A clipboard write (`navigator.clipboard.writeText`, `clipboardData.setData`) whose value is a terminal command. The value is resolved by pure evaluation where possible, including `const` bindings and recovered obfuscated strings. When it cannot be resolved, the rule harvests string fragments from the argument expression. It also follows locally defined helper functions and objects of helpers, and, for a generic copy helper such as `copyText(text)`, the arguments its callers pass. The detail says which of these supplied the text.

Indicators include pipes into a shell, download cradles, hidden or encoded PowerShell, `iex`, `mshta`, `cmd /c`, base64 decoding, detaching (`nohup`, `setsid`, `perl -MPOSIX`), `osascript -e`, quiet `msiexec` and `rundll32`. The finding is an error when any of these also holds:

- the write happens inside a `copy` or `cut` handler;
- the text includes verification-lure wording;
- a strong indicator is present: a hidden or encoded window, `mshta`, base64 decoding or detaching.

A plain `curl … | sh` copied by an install button is a warning: documentation pages and setup wizards do this legitimately.

## clipboard-copy-override

A `copy` or `cut` handler, registered with `addEventListener`, jQuery-style `.on` or `oncopy`/`oncut`, that calls `setData` with data not derived from `getSelection()`. Rich-text editors, notebooks and terminals do this to serialize their own selection models, so it is a note. Selection-derived attribution handlers are not reported.

## clipboard-write

Any programmatic clipboard write, with the resolved value or `dynamic argument; unresolved`. Copy buttons produce this; it is context.

## electron-run-as-node

`spawn`, `fork`, `exec` or `execFile` called with `ELECTRON_RUN_AS_NODE` in an `env` object, `ELECTRON_RUN_AS_NODE=1` set inside generated shell, batch or PowerShell text, or an assignment to `env.ELECTRON_RUN_AS_NODE`. The TypeScript server, `vscode-languageclient`, CLI shims and local helper servers use this legitimately to run Node through the editor binary, so launches are warnings and assignments are notes.

Both escalate (to error and warning respectively) when the same file contains hidden-window PowerShell (`-WindowStyle Hidden`, `-w hidden`) or a script path in a temporary or `.vscode` directory. The recovered UNK_DeadDrop Windows branch writes a temporary `.ps1` that sets the variable and launches the editor binary with a hidden window. Reading the variable, as native-addon loaders do, produces only a `campaign-marker` note.

## child-process-hidden-script

A child-process call whose resolved command or arguments name a `.js`, `.py`, `.sh`, `.ps1`, `.vbs`, `.bat` or `.cmd` file under `/tmp`, `/var/tmp`, `%TEMP%`, `$env:TEMP`, `AppData\Local\Temp` or `.vscode`.

## string-array-obfuscation

An obfuscator.io-style string array: a self-redefining function holding a string-array literal, or an array variable that rotation code shifts, together with a decoder that rebases its index (`i = i - OFFSET`). The decoder's own code is never run. The scanner identifies the variant (plain, base64 with the custom alphabet, RC4) and the offset, then reimplements the decoding.

The rotation is recovered in one of three ways:

- **`checksum`:** the rotation loop's `parseInt` checksum is evaluated for each candidate rotation, and the first match is taken, as the obfuscated program's own loop would. Several decoders sharing one array (for example base64 and RC4) are solved together.
- **`unrotated`:** no code rotates the array.
- **`printable-consensus`:** a single rotation is the only one that decodes at least 80% of up to 64 call sites to printable text, and the runner-up decodes at most half as many. A keyless base64 or plain array decodes to printable text under every rotation, so it stays `unresolved` rather than guessed.

Recovered strings, including those reached through wrapper functions, aliases (`const a = decoder`), constant objects and single-return helpers, are substituted into every other rule. The `deobfuscation` array in the report records the variant, offset, rotation, method and decoded call-site count.

Obfuscation is common in commercial extensions; this finding says the strings were hidden and whether they were recovered, not that the code is malicious.

## obfuscated-string-indicator

A URL with a host, or the argument to `require`/`import` of `child_process`, `vscode`, `crypto`, `fs`, `net`, `http`, `https`, `os`, `vm`, `module` or `worker_threads`, recovered from a string array. Reported at the outermost folded concatenation.

## encrypted-loader

Embedded base64, AES-256-GCM decipher with authentication tag, and the decoded text passed to `_compile`, linked through top-level `const` bindings. Nothing is decrypted. Evidence locations name each link.

## campaign-marker

Strings and identifiers from the UNK_DeadDrop source (configuration names, wallet API paths, the ClickFix `VERIFY-` token, the COM elevation CLSID, PowerShell fragments). Recovered obfuscated strings are checked too and carry `via: "string-array"`. Markers are context; several occur in benign code.

## Writing a rule

A rule is a module exporting `rule` (or `rules`):

```js
export const rule = {
  id: 'eval-call',
  meta: { severity: 'warning', description: 'Direct eval call', mitre: 'T1059.007' },
  create(context) {
    return {
      CallExpression(node) {
        if (node.callee.type === 'Identifier' && node.callee.name === 'eval') {
          context.report({ node, detail: `eval(${context.resolve(node.arguments[0]) ?? 'dynamic'})` });
        }
      },
    };
  },
};
```

Visitors are keyed by ESTree node type, `'*'` for every node, or `'Program:exit'`. The context provides the following:

- **`report`:** `report({ node, detail, severity?, data? })` records a finding.
- **Values:** `literal`, `literalInfo` and `resolve` give literal folding, recovered strings and pure evaluation; `fragments` harvests string fragments.
- **Structure:** `memberName`, `parent`, `visit`, `objectOf`, `propertyValue` and `hasProperty`.
- **Clipboard helpers:** `clipboardWrite`, `copyListener` and `callerArguments`.
- **Analysis state:** `deobfuscation` and `position`.

Load rules with `unk-scanner --rule ./my-rule.mjs` (repeatable) or `inspect(source, { rules: [rule] })`. The CLI allows the analysis process to read only the scanner's code and each named rule file.
