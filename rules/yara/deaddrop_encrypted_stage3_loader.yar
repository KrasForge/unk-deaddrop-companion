rule UNK_DeadDrop_Encrypted_Stage3_Loader_Experimental
{
    meta:
        description = "Obfuscated JavaScript loader using AES-GCM to recover later-stage source"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/04-credential-wallet-collection/"
        source_note = "docs/coverage-map.md"
        status = "experimental"
        scope = "plaintext JavaScript loader; exact case examples are up to 1.6 MiB; does not include the embedded decryption key"
    strings:
        $entry = "const _0x1=require" ascii
        $crypto = "(\"crypto\")" ascii
        $cipher = "aes-256-gcm" ascii
        $decrypt = "createDecipheriv" ascii
        $auth = "setAuthTag" ascii
        $compile = "_compile" ascii
    condition:
        filesize < 2MB and all of them
}
