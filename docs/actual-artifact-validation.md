# Actual artifact and benign-corpus validation

Read-only validation on 2026-10-26. No sample was executed. Files were scanned
from the investigation's 15 directories named `*-DO-NOT-RUN`; ZIP, VSIX and TAR
members were read into memory without extracting them. RAR files were skipped.
Research prose, timeline data and private case records were not used as the
artifact corpus.

## Retained YARA rules against case artifacts

After removing the unsupported workspace signatures and narrowing the wallet
rule, all 17 retained YARA rules compiled together and were replayed. The scan
covered 328 file objects, including archive members, totaling 71,249,970 bytes.
It reported no scan errors or timeouts. Every retained rule matched at least
one case object:

| Rule file | Matching objects |
| --- | ---: |
| `deaddrop_abe_bypass_source.yar` | 4 |
| `deaddrop_app_bound_credential_source.yar` | 2 |
| `deaddrop_capture_agent.yar` | 1 |
| `deaddrop_clickfix_fleet_bundle.yar` | 2 |
| `deaddrop_clickfix_lure.yar` | 2 |
| `deaddrop_electron_com_elevation_source.yar` | 4 |
| `deaddrop_encrypted_stage3_loader.yar` | 1 |
| `deaddrop_home_credential_sweep.yar` | 2 |
| `deaddrop_resolver_source.yar` | 5 |
| `deaddrop_stage1_dropper.yar` | 16 |
| `deaddrop_stage2_installer.yar` | 20 |
| `deaddrop_stage3_collector.yar` | 2 |
| `deaddrop_vsix_manifest.yar` | 1 |
| `deaddrop_wallet_agent.yar` | 1 |
| `deaddrop_windows_agent_bundle.yar` | 2 |
| `deaddrop_windows_node_collector.yar` | 1 |
| `echoes_stage2_task_staging.yar` | 4 |

Counts are matching file objects, not independent samples or incidents. They
include copied variants and archive-member views of some of the same content.
The stage-two installer rule also matches first-stage wrappers that embed its
content, as described in the detection notes.

In the earlier 19-rule inventory, two rules did not match any original target
file: the folder-open task rule and workspace-settings rule. The retained corpus
has no raw `.vscode/tasks.json` or `.vscode/settings.json` files; report excerpts
are not original target files. Those rules have been removed. The 14 Sigma rules
were also removed because no authentic endpoint process or file-event logs are
retained for replay. Synthetic event fixtures were not treated as target
validation.

The Acorn scanner parsed four retained ClickFix JavaScript bundles without
executing them. Each produced clipboard-write and campaign-marker findings.
This checks parser behavior against those saved bundles; it does not establish
runtime clipboard behavior.

## False-positive check on local software

The 17 retained YARA rules were scanned against 1,914 files totaling 53,634,415
bytes from the local CPython 3.13 standard library, Python virtual-environment
packages, globally installed npm packages and the Acorn dependency. The scan
reported zero rule matches and zero scan errors.

This is a small local software baseline, not an independently curated or
representative endpoint corpus. It cannot establish fleet-wide false-positive
rates. The first wallet-rule version matched harmless research prose containing
all required markers. It was narrowed to require ELF magic at byte zero; the
updated inert prose fixture no longer matches. A marker-rich ELF can still match
without showing that the strings are executable or reachable.

## Interpretation

The artifact replay establishes at least one positive case-artifact match for
each retained YARA rule. The baseline scan found no matches in the listed local
software files, and the wallet rule's prose boundary test now stays negative.
These checks do not estimate precision or recall, test packed/evasive variants,
or show alert behavior in a SIEM or EDR. Treat matches as leads and review file
type, acquisition context, and the matched content before escalating.
