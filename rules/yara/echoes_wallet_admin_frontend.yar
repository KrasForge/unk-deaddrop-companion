rule ECHOES_RMS_Wallet_Admin_Frontend_Experimental
{
    meta:
        description = "Recovered rms-platform wallet-administration component with multi-chain import and claim controls"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/08-administration-platform/"
        source_note = "incident-echoes-2026-07-22/dashboard-cklomino-source-DO-NOT-RUN/WalletBalancesPage.tsx"
        status = "experimental"
        scope = "frontend source component identification; does not prove backend use or wallet transactions"
    strings:
        $claim_call = "adminBase.post(\"admin/wallets/claim-all/\")" ascii
        $coldkey = "ColdKey" ascii
        $mnemonic = "mnemonic" ascii nocase
        $aptos = "Aptos" ascii
        $evm = "EVM" ascii
        $solana = "Solana wallet.json" ascii
    condition:
        filesize < 512KB and $claim_call and $coldkey and $mnemonic and
        2 of ($aptos, $evm, $solana)
}
