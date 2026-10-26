rule Overlord_Capture_Capability_Experimental
{
    meta:
        description = "Overlord framework agent with multiple capture and frame-difference symbols"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/05-screen-capture-analysis/"
        source_note = "docs/detection-notes.md"
        status = "experimental"
        scope = "capability and lineage; not campaign attribution"
    strings:
        $environment = "OVERLORD_SERVER_RAW" ascii wide
        $capture1 = "overlord-client/cmd/agent/capture.CaptureAndSend" ascii
        $capture2 = "overlord-client/cmd/agent/capture.encodeBlocks" ascii
        $capture3 = "overlord-client/cmd/agent/capture.blockChanged" ascii
        $capture4 = "overlord-client/cmd/agent/capture.copyPrev" ascii
        $capture5 = "overlord-client/cmd/agent/capture.frameFPS" ascii
        $capture6 = "overlord-client/cmd/agent/capture.CaptureDisplay" ascii
    condition:
        filesize < 64MB and $environment and 4 of ($capture*)
}
