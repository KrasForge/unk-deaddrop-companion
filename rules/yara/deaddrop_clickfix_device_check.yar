rule UNK_DeadDrop_ClickFix_Device_Check_Prop_Experimental
{
    meta:
        description = "ClickFix lure bundle that pairs browser ML dependencies with shell-download markers"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/01-clickfix-clipboard-manipulation/"
        source_note = "incident-d2saitrade-2026-07-22/reports/d2saitrade-supplement.yar"
        status = "experimental"
        scope = "plaintext or gzip-decoded web bundle; subtype indicator, not a general ML detector"
    strings:
        $ml1 = "tensorflow" nocase ascii
        $ml2 = "@tensorflow" nocase ascii
        $three = "three" nocase ascii
        $device = "device-check" ascii
        $curl = "curl -ks" ascii
        $daemon = "perl -MPOSIX" ascii
    condition:
        filesize > 300KB and filesize < 2MB and
        ($ml1 or $ml2) and $three and $device and ($curl or $daemon)
}
