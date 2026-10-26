rule UNK_DeadDrop_Windows_Node_Collector_Source_Experimental
{
    meta:
        description = "Windows JavaScript collector with the recovered phase-one and elevated phase-two modes"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/02-vsix-editor-execution/"
        source_note = "docs/detection-notes.md"
        status = "experimental"
        scope = "plaintext or decoded JavaScript source; does not establish collection"
    strings:
        $phase1 = "--company-wallet-phase1-local" ascii
        $phase2 = "--company-wallet-job" ascii
        $login_data = "Login Data" ascii
        $local_extension_data = "Local Extension Settings" ascii
        $phase1_archive = "_phase1.zip" ascii
        $phase2_archive = "_pass.zip" ascii
    condition:
        filesize < 1MB and $phase1 and $phase2 and
        1 of ($login_data, $local_extension_data) and
        1 of ($phase1_archive, $phase2_archive)
}
