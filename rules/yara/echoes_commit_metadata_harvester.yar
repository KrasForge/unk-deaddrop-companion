rule ECHOES_GitHub_Commit_Metadata_Harvester_Source_Experimental
{
    meta:
        description = "Python source for harvesting GitHub repository commit-author and committer email metadata"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/07-developer-target-harvesting/"
        source_note = "incident-echoes-2026-07-22/github-fetch-tool-EVIDENCE-PII/code/1_main.py"
        status = "experimental"
        scope = "static collector-source identification; no addresses, credentials or database contents are included"
    strings:
        $api = "https://api.github.com" ascii
        $stars = "stars:" ascii
        $branches = "MAX_BRANCHES_PER_REPO = 20" ascii
        $search = "MAX_SEARCH_RESULTS = 1000" ascii
        $author = "author_email" ascii
        $committer = "committer_email" ascii
        $sqlite = "sqlite3" ascii
    condition:
        filesize < 256KB and all of ($api, $stars, $branches, $search, $author, $committer, $sqlite)
}
