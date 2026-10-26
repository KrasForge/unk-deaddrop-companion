rule ECHOES_RMS_Repository_Monitor_Frontend_Experimental
{
    meta:
        description = "Recovered rms-platform repository-availability monitoring component"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/08-administration-platform/"
        source_note = "incident-echoes-2026-07-22/dashboard-cklomino-source-DO-NOT-RUN/rms-client-src/src__pages__StatsPage__GithubCheckPage.tsx"
        status = "experimental"
        scope = "frontend source component identification; not proof of backend activity"
    strings:
        $endpoint = "github-jobs-check" ascii nocase
        $clone_url = "clone_url" ascii
        $status = "httpStatus" ascii
        $warming = "warming_up" ascii
        $not_found = "httpStatus === 404" ascii
        $refresh = "refresh" ascii nocase
    condition:
        filesize < 512KB and $endpoint and $clone_url and $status and
        $warming and $not_found and $refresh
}
