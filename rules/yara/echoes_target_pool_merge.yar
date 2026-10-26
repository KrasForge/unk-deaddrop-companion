rule ECHOES_Target_Pool_Merge_Source_Experimental
{
    meta:
        description = "Python source that partitions harvested addresses into named mailing pools"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/07-developer-target-harvesting/"
        source_note = "incident-echoes-2026-07-22/github-fetch-tool-EVIDENCE-PII/code/merge.py"
        status = "experimental"
        scope = "static source identification; no database contents or addresses are included"
    strings:
        $splitter = "ANTISPAM_DOMAINS" ascii
        $predicate = "def is_antispam(email: str)" ascii
        $antispam_db = "results_antispam.db" ascii
        $safe_db = "results_safe.db" ascii
        $table = "CREATE TABLE IF NOT EXISTS emails" ascii
        $insert = "INSERT OR IGNORE INTO emails" ascii
    condition:
        filesize < 64KB and all of them
}
