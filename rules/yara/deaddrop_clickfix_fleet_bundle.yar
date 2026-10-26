rule UNK_DeadDrop_ClickFix_Fleet_Bundle_Experimental
{
    meta:
        description = "Recovered recruitment bundle that writes a shell download command to the browser clipboard"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/01-clickfix-clipboard-manipulation/"
        source_note = "docs/coverage-map.md"
        status = "experimental"
        scope = "recovered minified web bundles; detects source markers, not visitor execution"
    strings:
        $clipboard_api = "navigator.clipboard.writeText" ascii
        $mime = "text/plain" ascii
        $telemetry = "cmdline_copied" ascii
        $download = "curl -ks" ascii
        $verify = "VERIFY-" ascii
        $unix_detach = "perl -MPOSIX -e" ascii
        $windows_hidden = "start -WindowStyle Hidden cmd" ascii
    condition:
        filesize < 4MB and $clipboard_api and $mime and $telemetry and
        $download and $verify and ($unix_detach or $windows_hidden)
}
