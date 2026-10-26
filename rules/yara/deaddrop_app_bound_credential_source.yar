rule UNK_DeadDrop_App_Bound_Credential_Source_Experimental
{
    meta:
        description = "Python source referring to Chromium credential stores and App-Bound key recovery"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/04-credential-wallet-collection/"
        source_note = "docs/detection-notes.md"
        status = "experimental"
        scope = "plaintext or decoded source; does not establish successful credential recovery"
    strings:
        $login_data = "Login Data" ascii
        $local_state = "Local State" ascii
        $app_bound_key = "app_bound_encrypted_key" ascii
        $recovery_dpapi = "DPAPI" ascii nocase
        $recovery_app_bound = "App-Bound Encryption" ascii nocase
        $recovery_elevation = "Elevation Service" ascii nocase
        $recovery_aes_gcm = "AES-GCM" ascii nocase
    condition:
        filesize < 1MB and $login_data and $local_state and $app_bound_key and
        2 of ($recovery_*)
}
