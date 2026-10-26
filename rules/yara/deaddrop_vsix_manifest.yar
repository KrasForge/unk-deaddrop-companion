rule UNK_DeadDrop_VSIX_Manifest_Experimental
{
    meta:
        description = "Extracted Google Update Support VSIX manifest and company-wallet configuration"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/02-vsix-editor-execution/"
        source_note = "docs/detection-notes.md"
        status = "experimental"
        scope = "small extracted VSIX manifest members; does not decompress archives"
    strings:
        $identity1 = "google-update-support" ascii
        $identity2 = "google-dev-tools" ascii
        $identity3 = "onStartupFinished" ascii
        $config1 = "googleUpdateSupport.companyWalletServerUrl" ascii
        $config2 = "googleUpdateSupport.companyWalletClientId" ascii
        $config3 = "googleUpdateSupport.companyWalletAgentToken" ascii
        $config4 = "googleUpdateSupport.windowsActivationMode" ascii
    condition:
        filesize < 4KB and all of ($identity*) and 2 of ($config*)
}
