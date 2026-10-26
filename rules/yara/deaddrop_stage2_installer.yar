rule UNK_DeadDrop_ClickFix_Stage2_Installer_Experimental
{
    meta:
        description = "ClickFix second-stage installer or a first-stage file carrying its encoded body"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/01-clickfix-clipboard-manipulation/"
        source_note = "docs/coverage-map.md"
        status = "experimental"
        scope = "plaintext installer or a small wrapper embedding the known base64 anchors"
    strings:
        $work = "deepfake_guard_work" ascii wide
        $fallback = "GUARD_STORE_FALLBACK" ascii wide
        $runner = "deepfake_guard_run.sh" ascii wide
        $log = "guard-install-log" ascii wide
        $encoded_guard = "ZGVlcGZha2VfZ3VhcmQ" ascii
        $encoded_fallback = "R1VBUkRfU1RPUkVfRkFMTEJBQ0s" ascii
    condition:
        filesize < 2MB and (2 of ($work, $fallback, $runner, $log) or
                            all of ($encoded_guard, $encoded_fallback))
}
