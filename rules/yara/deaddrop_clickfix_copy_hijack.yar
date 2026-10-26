rule UNK_DeadDrop_ClickFix_Copy_Hijack_Experimental
{
    meta:
        description = "Recruitment-lure JavaScript that writes a shell download command to the clipboard"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/01-clickfix-clipboard-manipulation/"
        source_note = "incident-d2saitrade-2026-07-22/reports/d2saitrade-supplement.yar"
        status = "experimental"
        scope = "plaintext or gzip-decoded JavaScript; detects content, not visitor execution"
    strings:
        $daemon = "perl -MPOSIX" ascii
        $setsid = "POSIX::setsid" ascii
        $winhide = "start -WindowStyle Hidden cmd" ascii
        $curl = "curl -ks" ascii
        $setdata = ".setData(" ascii
        $write = "clipboard.writeText" ascii
        $clipboard = "clipboard" ascii
    condition:
        filesize > 16KB and filesize < 4MB and
        ($setdata or $write) and $clipboard and
        (($daemon and $setsid) or $winhide or $curl)
}
