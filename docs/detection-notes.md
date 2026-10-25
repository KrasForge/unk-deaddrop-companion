# Detection engineering notes

These rules are newly authored for this suite. Historical validation numbers
from the original rules do **not** apply to these revisions.

| Rule | Required input | Intent | Main limitation |
|---|---|---|---|
| YARA wallet agent | Unpacked file under 64 MiB | Framework module + environment marker + two wallet markers | Packed/encrypted builds and changed strings can evade; research documents can match |
| Linux service | File create/modify telemetry with `TargetFilename` | Exact system unit or per-user unit suffix | Does not prove the service ran; renamed units evade |
| Windows task | Process creation with full `Image` and `CommandLine` | `schtasks.exe`, `/create`, specific task name | API/COM registration and renamed tasks evade |

The YARA rule deliberately excludes short `GUS_` strings as sufficient operator
evidence. Even the stronger marker conjunction is not national attribution.
Security labs, source archives and research documents can contain these strings.
The historical absence of wallet strings in selected upstream files is not a
proof that all upstream versions lack them.

Linux file collection must cover system and user systemd directories. Windows
collection must preserve the command line; truncation can defeat the rule.
Backend field mappings and case sensitivity need validation in the target SIEM.
The Sigma tests parse rules with pySigma, then exercise only the modifier subset
used here. No SIEM conversion, ingestion or end-to-end alert delivery was tested.

Start in hunt mode. Review parent processes, signer, task/service contents,
network activity and acquisition context before escalation. A single marker
should not trigger an automatic takedown or imply a victim is an operator.
Tune against representative clean developer workloads before production use.
