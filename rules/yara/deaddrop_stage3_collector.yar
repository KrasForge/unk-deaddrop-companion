rule UNK_DeadDrop_Stage3_Collector_Source_Experimental
{
    meta:
        description = "Plaintext stage-three JavaScript collection and Windows agent staging markers"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/04-credential-wallet-collection/"
        source_note = "docs/detection-notes.md"
        status = "experimental"
        scope = "plaintext source; obfuscation or encryption can evade"
    strings:
        $task = "GoogleUpdateSupporterNode" ascii
        $stage1 = "GUS_UPLOAD_CHUNK_SIZE" ascii
        $stage2 = "DEFAULT_PHASE3_MAX_MS" ascii
        $stage3 = "OVERLORD_KEEP_AGENT_STATE" ascii
        $stage4 = "WIN_NODE_AGENT_BUNDLE_B64" ascii
        $stage5 = "DEFAULT_WALK_MAX_DIRS" ascii
    condition:
        filesize < 8MB and $task and 3 of ($stage*)
}
