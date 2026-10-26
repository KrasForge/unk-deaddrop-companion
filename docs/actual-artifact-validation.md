# Actual-artifact and benign-corpus validation

Read-only replay on 2026-10-26. No sample was executed. The replay helper in
[`tools/replay_yara.py`](../tools/replay_yara.py) scans explicitly selected files
and reads ZIP, VSIX, TAR, gzip and nested archive contents in memory. It writes
no extracted files. Raw RAR files are scanned, but their members are not
decoded. Object size, nesting, total-byte and timeout limits are enforced.

## Retained rules against case artifacts

The selected corpus included files from all 15 `*-DO-NOT-RUN` directories, the
15 gzip-compressed lure bundles, related site assets, extracted VSIX components
and agent archives, two collector source files, and six retained lure messages
(three originals, two duplicate copies, and a separate Surge Group message).
The two SQLite databases
containing target addresses were excluded. No victim records, credentials,
message bodies or raw samples are included in this repository.

The replay covered 192 input files and 395 raw or archive-member views totaling
234,050,891 bytes across those views. Duplicate artifacts and nested archive
members are counted more than once. At least one rule matched 90 input files;
102 input files produced no match. All 33 named YARA rules in 28 rule files
matched at least one actual case object. The replay reported no YARA timeouts or
read errors. Five RAR containers were not decoded: four ECHOES archives require
a password, and the separate sealed environment archive was excluded from
member inspection.

| Rule | Matching object views |
| --- | ---: |
| `ECHOES_GitHub_Commit_Metadata_Harvester_Source_Experimental` | 1 |
| `ECHOES_LNK_Launchers_Exact_Hash_Experimental` | 4 |
| `ECHOES_RAR_Lure_Archives_Exact_Hash_Experimental` | 4 |
| `ECHOES_RMS_Repository_Monitor_Frontend_Experimental` | 1 |
| `ECHOES_RMS_Wallet_Admin_Frontend_Experimental` | 2 |
| `ECHOES_Stage2_Scheduled_Task_Staging_Experimental` | 4 |
| `ECHOES_Target_Pool_Merge_Source_Experimental` | 1 |
| `Overlord_Capture_Capability_Experimental` | 10 |
| `Surge_Group_Received_Lure_Email_Exact_Hash_Experimental` | 1 |
| `UNK_DeadDrop_App_Bound_Credential_Source_Experimental` | 2 |
| `UNK_DeadDrop_Chromium_App_Bound_Bypass_Source_Experimental` | 4 |
| `UNK_DeadDrop_ClickFix_Copy_Hijack_Experimental` | 17 |
| `UNK_DeadDrop_ClickFix_D2S_Build_Experimental` | 2 |
| `UNK_DeadDrop_ClickFix_D2S_Stage1_Telemetry_Experimental` | 6 |
| `UNK_DeadDrop_ClickFix_Device_Check_Prop_Experimental` | 4 |
| `UNK_DeadDrop_ClickFix_Fleet_Bundle_Experimental` | 10 |
| `UNK_DeadDrop_ClickFix_Lure_Source_Experimental` | 11 |
| `UNK_DeadDrop_ClickFix_Stage1_Dropper_Experimental` | 16 |
| `UNK_DeadDrop_ClickFix_Stage2_Installer_Experimental` | 20 |
| `UNK_DeadDrop_Electron_COM_Elevation_Source_Experimental` | 4 |
| `UNK_DeadDrop_Electron_Node_Bootstrap_Source_Experimental` | 2 |
| `UNK_DeadDrop_Encrypted_Stage3_Loader_Experimental` | 5 |
| `UNK_DeadDrop_GitLab_Resolver_Source_Experimental` | 5 |
| `UNK_DeadDrop_Linux_Systemd_Persistence_Source_Experimental` | 2 |
| `UNK_DeadDrop_Overlord_Wallet_Agent_Experimental` | 4 |
| `UNK_DeadDrop_Phase3_Home_Credential_Sweep_Experimental` | 2 |
| `UNK_DeadDrop_Recruitment_Email_Exact_Hash_Experimental` | 5 |
| `UNK_DeadDrop_Stage3_Collector_Source_Experimental` | 2 |
| `UNK_DeadDrop_VSIX_And_Encrypted_Artifacts_Exact_Hash_Experimental` | 14 |
| `UNK_DeadDrop_VSIX_Manifest_Experimental` | 2 |
| `UNK_DeadDrop_Windows_Launchers_Exact_Hash_Experimental` | 3 |
| `UNK_DeadDrop_Windows_Node_Agent_Bundle_Experimental` | 2 |
| `UNK_DeadDrop_Windows_Node_Collector_Source_Experimental` | 1 |

These are object-view counts, not independent samples or incidents. Several
objects are copied variants or archive-member views of the same bytes. The
stage-two rule also matches first-stage wrappers that embed its content. The
exact-hash rules identify only the listed bytes; they do not generalize to
modified messages, rebuilt packages or changed archives. Four ECHOES RAR
archives matched exact hashes. All four require a password, which was not used
to inspect their members. The separate sealed environment RAR was scanned only
as raw bytes; its members were not read and it was not added to the exact-hash
rules.

The earlier folder-open task and workspace-settings signatures had no original
`.vscode/tasks.json` or `.vscode/settings.json` files for replay, so they remain
removed. The 14 event rules were removed because authentic endpoint logs are
unavailable. The current Linux persistence signature is a YARA source-file rule
against recovered installer code; it does not replace a log-based event rule.

An additional replay scanned the retained repository tarball and Git bundle as
two input containers and 34 raw or archive-member views, with no matches. The
Git bundle was also inspected as repository data without checkout or execution:
its three tracked file blobs had no matches, and its preserved history contains
no `.vscode` task or settings files. This confirms those workspace files are
unavailable in the retained repository copies.

The Acorn scanner also parsed four retained ClickFix JavaScript bundles without
executing them. Each produced clipboard-write and campaign-marker findings.
This checks parser behavior against those saved bundles, not runtime clipboard
behavior.

## False-positive checks

The 33 rules were scanned against 1,914 files from the CPython 3.13 standard
library, the local Python environment, globally installed npm packages and the
Acorn dependency. The archive-aware replay evaluated 2,379 raw or nested object
views totaling 59,243,687 bytes and reported zero matches, errors or timeouts.
The 19 Markdown research articles and companion notes also produced zero hits
after source-oriented rules were narrowed to avoid the prose examples.

This is a small local baseline, not an independently curated or representative
endpoint corpus. It cannot establish fleet-wide false-positive rates, precision
or recall. The wallet rule's earlier marker-rich prose collision is blocked by
its ELF-header requirement; a marker-rich ELF can still match without proving
that strings are executable or reachable code.

## Interpretation

The broader replay covers the retrievable, technically meaningful artifacts as
far as the available evidence supports. The unmatched inputs include generic
dashboard template modules, lure artwork, timeline and other research material,
and artifacts with no stable file-content signature. Adding weak rules for
those files would identify the evidence set, not reliably detect malicious
behavior. RAR contents, original workspace files and runtime events remain
unvalidated. Treat every hit as a lead; review file type, acquisition context
and matched content before escalation.
