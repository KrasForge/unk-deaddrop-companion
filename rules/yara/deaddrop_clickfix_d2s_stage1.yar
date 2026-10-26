rule UNK_DeadDrop_ClickFix_D2S_Stage1_Telemetry_Experimental
{
    meta:
        description = "Historical D2S build marker in a ClickFix stage-one file"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/01-clickfix-clipboard-manipulation/"
        source_note = "incident-d2saitrade-2026-07-22/reports/d2saitrade-supplement.yar"
        status = "experimental"
        scope = "historical file-content identification only; hostname string is time-bound"
    strings:
        $host = "d2saitrade.ink" ascii nocase
        $event1 = "/guard-launcher-result" ascii
        $event2 = "/guard-install-log" ascii
        $api = "api.fallbaav.ink" ascii nocase
        $family = "deepfake_guard" ascii
    condition:
        filesize < 1MB and $host and 1 of ($event*) and ($api or $family)
}
