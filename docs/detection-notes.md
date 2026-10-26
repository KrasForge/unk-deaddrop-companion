# Detection engineering notes

These experimental YARA rules match file content in artifacts described in the
linked analysis. They are investigation leads, not verdicts about a host, user
or operator. Rule references point to the relevant article in the
[twelve-part series](https://krasforge.github.io/UNK_DeadDrop/).

| Rule file | Required input and match | What a match establishes | Main gaps |
|---|---|---|---|
| `yara/deaddrop_wallet_agent.yar` | ELF file under 64 MiB with ELF magic at byte zero; Overlord module path, server-environment marker and at least two wallet strings | An ELF begins with the expected header and contains the framework and wallet-collection marker conjunction | A spoofed header or marker-rich ELF can still match; packing, encryption or changed strings can evade it |
| `yara/deaddrop_clickfix_lure.yar` | Plaintext/decoded source under 2 MiB; `cmdline_copied`, `text/plain`, `VERIFY-` and a clipboard-write method | Source contains the recovered verification and clipboard-write markers together | Does not establish displayed/copied-text mismatch or user execution; source documents can match |
| `yara/deaddrop_clickfix_fleet_bundle.yar` | Recovered web bundle under 4 MiB; `navigator.clipboard.writeText`, `text/plain`, telemetry, `curl -ks`, verification token, and a platform launcher | One file contains the fleet's clipboard-substitution and download-command markers | Does not establish that a visitor copied or ran the command; altered bundles and source documents can match |
| `yara/deaddrop_stage1_dropper.yar` | Small file with launcher telemetry, a detach/hide guard, and a deepfake-guard or platform marker | File contains the recovered first-stage dropper marker conjunction | Does not establish execution; embedded stage-two content can also match the stage-two rule |
| `yara/deaddrop_stage2_installer.yar` | File under 2 MiB with at least two installer strings or both embedded base64 anchors | File contains recovered second-stage installer content or its embedded representation | Does not establish installation; first-stage wrappers intentionally embed these anchors; a later Windows variant was not independently decoded |
| `yara/deaddrop_encrypted_stage3_loader.yar` | JavaScript under 512 KiB with the recovered obfuscated require, crypto, AES-GCM, and decipher markers | Source contains the static loader's structural crypto markers | Does not include the loader key; generic source discussing these exact markers can match |
| `yara/deaddrop_electron_com_elevation_source.yar` | Plaintext/decoded source under 4 MiB; CMSTPLUA CLSID and elevation moniker, Electron Node marker, `process.execPath`, one branch argument and one temp/sentinel name | Source contains the combined elevation and interpreter-launch markers | Does not show successful elevation; changed strings or obfuscation evade it; source documents can match |
| `yara/deaddrop_windows_node_collector.yar` | Plaintext/decoded source under 1 MiB; both phase arguments, one browser-store marker and one archive-output name | Source contains the recovered Windows Node collection stages | Does not show that any data was read or uploaded; source documents can match |
| `yara/deaddrop_app_bound_credential_source.yar` | Plaintext/decoded source under 1 MiB; Chromium credential stores, App-Bound key marker and two recovery terms | Source contains the recovered browser credential-recovery markers | Does not show successful decryption; other forensic/research source may match |
| `yara/deaddrop_abe_bypass_source.yar` | Plaintext/decoded source under 2 MiB with the App-Bound key, IElevator, DecryptData, a browser CLSID/moniker, and a legacy/decryptor marker | Source contains the recovered Chromium App-Bound recovery path | Does not establish successful decryption; forensic and research scripts may share the API names |
| `yara/deaddrop_home_credential_sweep.yar` | JavaScript under 8 MiB with the credential-name regex, phase-three marker, two budget constants, and two sweep/TCC/config markers | Source contains the recovered bounded home-directory search behavior | Does not establish that files were read or uploaded; decoded source or documentation can match |
| `yara/deaddrop_resolver_source.yar` | Source or unpacked binary under 64 MiB with the GitLab project path, raw config path, and Overlord resolver variable | Content names the observed mutable server-list resolver | Does not show a fetch or current infrastructure status; documentation can match |
| `yara/deaddrop_windows_agent_bundle.yar` | ZIP under 64 MiB with two recovered member names, or unpacked source with agent-directory and WebSocket markers | Content matches the recovered Windows Node agent bundle shape | Does not scan compressed VSIX members automatically or establish execution |
| `yara/echoes_stage2_task_staging.yar` | Decoded PowerShell under 2 MiB with the ECHOES task prefix, task registration, trigger, hidden launch, and a recovered script filename | Source contains the separate ECHOES stage-two scheduled-task staging sequence | Does not identify the final payload or establish relation to UNK_DeadDrop; source documents can match |
| `yara/deaddrop_capture_agent.yar` | Unpacked file under 64 MiB; Overlord environment marker plus at least four of six capture symbols | Capture-related symbols occur alongside an Overlord marker | Capability and lineage only; does not show display access or transmission; other Overlord builds may match |
| `yara/deaddrop_vsix_manifest.yar` | One extracted text member under 512 KiB; all three identity/activation strings and at least two of four settings | The member contains a conjunction from the recovered extension manifest | YARA does not unpack the VSIX archive; scan extracted members |
| `yara/deaddrop_stage3_collector.yar` | Plaintext source under 8 MiB; task name plus at least three of five collection/staging constants | The source contains several specific stage-three markers | Obfuscation, encryption or changed names evade it; source and research documents can match |

## Evidence and validation limits

All seventeen retained YARA rules compile and have inert positive and near-miss
fixtures. Each also matched at least one retained case artifact in the read-only
replay described in the [validation report](actual-artifact-validation.md). The
local software baseline had no hits. A constructed harmless prose fixture with
the full wallet marker set no longer matches after the rule was narrowed to ELF
files with the header at byte zero. A marker-rich ELF can still match regardless
of whether those strings are executable or reachable code.
No authentic endpoint event logs were available, so this repository does not
include the earlier Sigma rules or claim event-rule validation.

The YARA rules deliberately combine distinctive strings rather than treating
short `GUS_` tokens as operator evidence. Even a full conjunction does not
establish attribution. The historical absence of wallet strings in selected
upstream files does not prove that all versions of the framework lack them.

The VSIX rule must run against extracted archive members. The rule set has not
been evaluated against a broad, independently curated developer-workstation
corpus, and no false-positive rate or recall estimate is available.

Use the rules in hunt mode. Review file type, acquisition context and matched
content before escalation. A match alone does not establish execution,
compromise or attribution. Add broader, licensed clean-software corpora before
using these signatures for production alerting.
