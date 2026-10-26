rule UNK_DeadDrop_Windows_Node_Agent_Bundle_Experimental
{
    meta:
        description = "Embedded Windows Node agent archive or its unpacked runtime markers"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/05-screen-capture-analysis/"
        source_note = "docs/coverage-map.md"
        status = "experimental"
        scope = "ZIP member names or unpacked JavaScript; not a detector for the full VSIX archive"
    strings:
        $zip1 = "run-update-agent.vbs" ascii
        $zip2 = "update-agent.js" ascii
        $zip3 = "lib/agent-update.js" ascii
        $agent_dir = "OVERLORD_NODE_AGENT_DIR" ascii
        $websocket = "WebSocket" ascii
    condition:
        filesize < 64MB and
        ((uint32(0) == 0x04034b50 and 2 of ($zip*)) or
         ($agent_dir and $websocket))
}
