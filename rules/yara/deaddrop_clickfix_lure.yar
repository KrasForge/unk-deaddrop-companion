rule UNK_DeadDrop_ClickFix_Lure_Source_Experimental
{
    meta:
        description = "Recruitment verification page with clipboard substitution telemetry"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/01-clickfix-clipboard-manipulation/"
        source_note = "docs/detection-notes.md"
        status = "experimental"
        scope = "plaintext or decoded web source; does not establish user execution"
    strings:
        $telemetry = "cmdline_copied" ascii
        $mime = "text/plain" ascii
        $verify = "VERIFY-" ascii
        $clipboard_set = "setData" ascii
        $clipboard_write = "writeText" ascii
    condition:
        filesize < 2MB and all of ($telemetry, $mime, $verify) and
        1 of ($clipboard_*)
}
