rule UNK_DeadDrop_Electron_Node_Bootstrap_Source_Experimental
{
    meta:
        description = "Recovered source pairing Electron Node mode with the campaign wallet-client header"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/02-vsix-editor-execution/"
        source_note = "incident-predicttogether-2026-07-22/samples-DO-NOT-RUN/gus-node-bootstrap.js"
        status = "experimental"
        scope = "static JavaScript source identification; does not establish task execution"
    strings:
        $electron = "ELECTRON_RUN_AS_NODE" ascii
        $client = "X-Company-Wallet-Client-Id" ascii
    condition:
        filesize > 32KB and filesize < 512KB and all of them
}
