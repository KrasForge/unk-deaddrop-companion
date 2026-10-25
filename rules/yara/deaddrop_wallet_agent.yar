rule UNK_DeadDrop_Overlord_Wallet_Agent_Experimental
{
    meta:
        description = "Overlord framework plus wallet-collection markers; static hunting only"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-21"
        evidence_cutoff = "2026-07-24"
        reference = "docs/detection-notes.md"
        status = "experimental"
    strings:
        $framework = "overlord-client/cmd/agent" ascii wide
        $env = "OVERLORD_SERVER_RAW" ascii wide
        $wallet1 = "OVERLORD_COMPANY_WALLET_EP" ascii wide
        $wallet2 = "X-Company-Wallet-Client-Id" ascii wide
        $wallet3 = "/api/company-wallet/upload" ascii wide
    condition:
        filesize < 64MB and $framework and $env and 2 of ($wallet*)
}
