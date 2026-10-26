rule UNK_DeadDrop_ClickFix_D2S_Build_Experimental
{
    meta:
        description = "Identifies the observed D2S ClickFix bundle variant by its challenge and walkthrough features"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/01-clickfix-clipboard-manipulation/"
        source_note = "incident-d2saitrade-2026-07-22/reports/d2saitrade-supplement.yar"
        status = "experimental"
        scope = "variant identification for plaintext or gzip-decoded lure bundles"
    strings:
        $daemon = "perl -MPOSIX" ascii
        $setsid = "setsid" ascii
        $winhide = "start -WindowStyle Hidden cmd" ascii
        $new1 = "design-challenge" ascii
        $new2 = "/guide.mp4" ascii
        $new3 = "design_challenge_render" ascii
        $new4 = "design_challenge_antibot_required" ascii
        $new5 = "check_3d_m" ascii
        $new6 = "check_bot_m" ascii
        $kit1 = "track-activity" ascii
        $kit2 = "environment-setup" ascii
        $kit3 = "anti-bot-check" ascii
    condition:
        filesize < 2MB and ($winhide or ($daemon and $setsid)) and
        2 of ($new*) and 1 of ($kit*)
}
