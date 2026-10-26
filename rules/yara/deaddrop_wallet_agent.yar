rule UNK_DeadDrop_Overlord_Wallet_Agent_Experimental
{
    meta:
        description = "ELF Overlord wallet-agent marker conjunction; static hunting only"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/12-framework-and-collection-boundary/"
        source_note = "docs/detection-notes.md"
        status = "experimental"
        scope = "marker conjunction; not campaign attribution"
    strings:
        $elf = { 7F 45 4C 46 }
        $framework = "overlord-client/cmd/agent" ascii wide
        $env = "OVERLORD_SERVER_RAW" ascii wide
        $wallet1 = "OVERLORD_COMPANY_WALLET_EP" ascii wide
        $wallet2 = "X-Company-Wallet-Client-Id" ascii wide
        $wallet3 = "/api/company-wallet/upload" ascii wide
    condition:
        filesize < 64MB and $elf at 0 and $framework and $env and 2 of ($wallet*)
}
