rule UNK_DeadDrop_Electron_COM_Elevation_Source_Experimental
{
    meta:
        description = "Recovered COM elevation builder paired with Electron Node collection source"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/02-vsix-editor-execution/"
        source_note = "docs/detection-notes.md"
        status = "experimental"
        scope = "plaintext or decoded JavaScript source; not evidence of successful elevation"
    strings:
        $clsid = "3E5FC7F9-9A51-4367-9063-A120244FBEC7" ascii nocase
        $moniker = "Elevation:Administrator!new:" ascii
        $electron = "ELECTRON_RUN_AS_NODE" ascii
        $exec_path = "process.execPath" ascii
        $job_vsix = "--company-wallet-job" ascii
        $job_clickfix = "--win-build-ep-only" ascii
        $temp_vsix = "gus-phase2-" ascii
        $temp_clickfix = "sa-elev-done-" ascii
    condition:
        filesize < 4MB and $clsid and $moniker and $electron and $exec_path and
        1 of ($job_*) and 1 of ($temp_*)
}
