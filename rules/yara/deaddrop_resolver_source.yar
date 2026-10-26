rule UNK_DeadDrop_GitLab_Resolver_Source_Experimental
{
    meta:
        description = "Overlord-based campaign component naming the mutable GitLab server-list resolver"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/06-gitlab-dead-drop-infrastructure/"
        source_note = "docs/coverage-map.md"
        status = "experimental"
        scope = "source or unpacked binary; historical resolver path, not a live domain blocklist"
    strings:
        $project = "gitlab.com/drop-indexing/tasks" ascii wide nocase
        $path = "/-/raw/main/config.json" ascii wide
        $setting = "OVERLORD_SERVER_RAW" ascii wide
    condition:
        filesize < 64MB and all of them
}
