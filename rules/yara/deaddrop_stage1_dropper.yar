rule UNK_DeadDrop_ClickFix_Stage1_Dropper_Experimental
{
    meta:
        description = "ClickFix first-stage dropper with recovered installer telemetry and launcher guards"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/01-clickfix-clipboard-manipulation/"
        source_note = "docs/coverage-map.md"
        status = "experimental"
        scope = "small Windows or Unix first-stage files; names and lure brands are not required"
    strings:
        $telemetry = "guard-launcher-result" ascii wide
        $platform = "X-Guard-Platform" ascii wide
        $guard = "deepfake_guard" ascii wide
        $detached = "NVDG_DETACHED" ascii wide
        $hidden = "NVDG_HIDDEN" ascii wide
    condition:
        filesize < 1MB and $telemetry and 1 of ($detached, $hidden) and
        1 of ($platform, $guard)
}
