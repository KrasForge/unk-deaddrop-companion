rule ECHOES_Stage2_Scheduled_Task_Staging_Experimental
{
    meta:
        description = "ECHOES archive-derived PowerShell stage that installs the WORD/DDD scheduled-task chain"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/09-echoes-lineage-image-provenance/"
        source_note = "docs/coverage-map.md"
        status = "experimental"
        scope = "decoded ECHOES stage-two script only; does not attribute it to UNK_DeadDrop or identify the unavailable final payload"
    strings:
        $task = "OneDrive Reporting Task-" ascii nocase
        $register = "Register-ScheduledTask" ascii nocase
        $trigger = "New-ScheduledTaskTrigger" ascii nocase
        $vbs = "whale.vbs" ascii nocase
        $script = "wale.ps1" ascii nocase
        $hidden = "-WindowStyle Hidden" ascii nocase
    condition:
        filesize < 2MB and $task and $register and $trigger and
        1 of ($vbs, $script) and $hidden
}
