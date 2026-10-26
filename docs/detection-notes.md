# Detection engineering notes

These rules are experimental file and event selectors for the artifacts described
in the linked analysis. They are investigation leads, not verdicts about a host,
user or operator. Rule references point to the relevant article in the
[twelve-part series](https://krasforge.github.io/UNK_DeadDrop/).

| Rule file | Required input and match | What a match establishes | Main gaps |
|---|---|---|---|
| `yara/deaddrop_wallet_agent.yar` | Unpacked file under 64 MiB; Overlord module path, server-environment marker and at least two wallet strings | A file contains a conjunction of framework and wallet-collection markers | Packing, encryption or changed strings can evade it; source and research documents can match |
| `yara/deaddrop_clickfix_lure.yar` | Plaintext/decoded source under 2 MiB; `cmdline_copied`, `text/plain`, `VERIFY-` and a clipboard-write method | Source contains the recovered verification and clipboard-write markers together | Does not establish displayed/copied-text mismatch or user execution; source documents can match |
| `yara/deaddrop_electron_com_elevation_source.yar` | Plaintext/decoded source under 4 MiB; CMSTPLUA CLSID and elevation moniker, Electron Node marker, `process.execPath`, one branch argument and one temp/sentinel name | Source contains the combined elevation and interpreter-launch markers | Does not show successful elevation; changed strings or obfuscation evade it; source documents can match |
| `yara/deaddrop_windows_node_collector.yar` | Plaintext/decoded source under 1 MiB; both phase arguments, one browser-store marker and one archive-output name | Source contains the recovered Windows Node collection stages | Does not show that any data was read or uploaded; source documents can match |
| `yara/deaddrop_app_bound_credential_source.yar` | Plaintext/decoded source under 1 MiB; Chromium credential stores, App-Bound key marker and two recovery terms | Source contains the recovered browser credential-recovery markers | Does not show successful decryption; other forensic/research source may match |
| `sigma/linux_google_agent_persistence.yml` | Linux file events with `TargetFilename`; exact system unit path or user-unit suffix | A file event names one of the recovered unit paths | Does not show that the event created or changed the file, or that systemd loaded or ran it; renamed units evade it |
| `sigma/windows_capture_task.yml` | Windows process events with full `Image` and `CommandLine`; `schtasks.exe`, `/create` and the task-name substring | A process command line contains the recovered scheduled-task creation markers | Substring may match a longer task name; other tools, APIs or renamed binaries evade it |
| `sigma/windows_editor_node_collection.yml` | Windows process events with `Image` and `CommandLine`; Code or Cursor plus either recovered collection argument | The editor process was started with a collection-specific argument | Does not observe `ELECTRON_RUN_AS_NODE`; renamed executables or changed arguments evade it |
| `sigma/windows_powershell_electron_node_mode.yml` | PowerShell script-block text; Electron Node-mode variable name plus either recovered collection argument | A logged script block contains both strings | Does not establish assignment to `1` or execution; missing or encoded script-block data evade it |
| `sigma/windows_elevation_temp_artifacts.yml` | Windows file events with `TargetFilename`; generated phase-two script or completion-sentinel name | A file event path contains a name emitted by the recovered elevation code | Does not show file creation, a UAC bypass or successful elevation; names can change |
| `sigma/windows_vscode_extension_artifact.yml` | Windows file events with `TargetFilename`; package or loader beneath the recovered VS Code/Cursor extension ID | A file event names a path beneath the recovered extension identifier | Does not show installation or activation; alternate roots and renamed packages evade it |
| `yara/deaddrop_capture_agent.yar` | Unpacked file under 64 MiB; Overlord environment marker plus at least four of six capture symbols | Capture-related symbols occur alongside an Overlord marker | Capability and lineage only; does not show display access or transmission; other Overlord builds may match |
| `yara/deaddrop_vsix_manifest.yar` | One extracted text member under 512 KiB; all three identity/activation strings and at least two of four settings | The member contains a conjunction from the recovered extension manifest | YARA does not unpack the VSIX archive; scan extracted members |
| `yara/deaddrop_stage3_collector.yar` | Plaintext source under 8 MiB; task name plus at least three of five collection/staging constants | The source contains several specific stage-three markers | Obfuscation, encryption or changed names evade it; source and research documents can match |

## Evidence and validation limits

The wallet-agent rule's earlier version was reported to match one held Linux Go
sample, SHA-256
`ef183bbb40f4c7c3f4b52994cdba3295f3eab2604fdad99eefa3b67b8d966e8d`. That is a
single historical positive, not a sensitivity estimate. The four original YARA
rules have synthetic fixture coverage; a boundary fixture also demonstrates
that prose containing wallet strings can match. The four additional YARA rules
are draft selectors and are not yet compiled or exercised by the repository's
fixture suite. No clean-software corpus was used to estimate false-positive rates.

The Sigma fixtures parse the YAML and exercise only the modifier and condition
patterns used in this suite. They do not validate conversion to a particular SIEM,
field mapping, event normalization, ingestion or alert delivery. The rules have
not been replayed against a representative production event set.

The YARA rules deliberately combine distinctive strings rather than treating
short `GUS_` tokens as operator evidence. Even a full conjunction does not
establish attribution. The historical absence of wallet strings in selected
upstream files does not prove that all versions of the framework lack them.

Linux collection must cover system and user systemd directories. Windows process
collection must preserve the full command line. The PowerShell rule needs script
block telemetry. The VSIX rule must run against extracted archive members. Field
mapping, case handling and backend conversion require validation in the target
environment before operational use.

Use the rules in hunt mode. Review parent processes, signers, task or service
contents, network activity and acquisition context before escalation. A match
alone does not justify a takedown or establish compromise. Add synthetic positive
and negative fixtures for the draft rules, then tune against representative clean
developer workloads before production use.
