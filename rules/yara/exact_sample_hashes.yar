import "hash"

rule UNK_DeadDrop_VSIX_And_Encrypted_Artifacts_Exact_Hash_Experimental
{
    meta:
        description = "Exact SHA-256 identifiers for the retained VSIX, obfuscated loader, nested agent archive and encrypted payload members"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/02-vsix-editor-execution/"
        status = "experimental"
        scope = "exact-byte identification only; does not generalize to rebuilt or modified files"
    condition:
        (filesize == 17647582 and hash.sha256(0, filesize) == "52886aab179f26421678ff23af1b0fabf0a17ffbb534369cdbbac8008cbed8e7") or
        (filesize == 606460 and hash.sha256(0, filesize) == "d5e9288693aa745dc89368deac677e7ea1ec81e663283af30838cdae189b7a7e") or
        (filesize == 17283435 and hash.sha256(0, filesize) == "e1bf1b29e6fa3525d7f32f429290a88d6ea2890e61c06574b8ff6372aa5d0667") or
        (filesize == 60082 and hash.sha256(0, filesize) == "fa5312c5d190c619fa48ea0ff63c6a794d4dd874527ca42e4336f0cf040cf3b0") or
        (filesize == 56121 and hash.sha256(0, filesize) == "82cf5955e5b8b575343ba73289468b476c39c92961dcdd90885772dcc37182d4") or
        (filesize == 32352 and hash.sha256(0, filesize) == "6aa0c5b29da370e93a9760322ac4378f3f06a72124550580c400c671ca6cf154") or
        (filesize == 60082 and hash.sha256(0, filesize) == "9bbe197504bed49d152b5053fd5eff09ba6dfb0a8facd90618a7ee471509ad09") or
        (filesize == 56121 and hash.sha256(0, filesize) == "ee1b016374ff6a076bbd2474a21e2c0e82e9abcc84e44992a23faf800c36cf21") or
        (filesize == 32352 and hash.sha256(0, filesize) == "e4898fe06377006411342940acd7f2602fc12c8ed9ab246623f7e4ccedb3ca4b")
}

rule UNK_DeadDrop_Windows_Launchers_Exact_Hash_Experimental
{
    meta:
        description = "Exact SHA-256 identifiers for the retained VBS, CMD and shell launch wrappers"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/02-vsix-editor-execution/"
        status = "experimental"
        scope = "exact-byte identification only; does not generalize to rebuilt or modified files"
    condition:
        (filesize == 1464 and hash.sha256(0, filesize) == "4c0d9b802c075be79e9edb52d88f8dd72e6904f5c58267213745818470945c78") or
        (filesize == 23356 and hash.sha256(0, filesize) == "62761f38ed194c59abe15c49f09f0ebc431ac852c965180c9327ed84d3a454fb") or
        (filesize == 25357 and hash.sha256(0, filesize) == "734699773e53d995f20d485eb61261033d9d00b4332b39ca26071bcd60cd352f")
}

rule UNK_DeadDrop_Recruitment_Email_Exact_Hash_Experimental
{
    meta:
        description = "Exact SHA-256 identifiers for three retained recruitment-lure messages"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/10-investigation-connections/"
        status = "experimental"
        scope = "exact RFC message bytes only; no addresses or message content are included and header changes will evade"
    condition:
        (filesize == 7185 and hash.sha256(0, filesize) == "6c1835159c8da69aaf0743fce634c3345e6b4f16eb4a492cfda5cf893b98eb5b") or
        (filesize == 9176 and hash.sha256(0, filesize) == "3efb15d6cc89e3690bd1e19fbc96034110f55066d69ef25dc2d30ca057d2ee21") or
        (filesize == 9462 and hash.sha256(0, filesize) == "924db78f6fe47e7696c42d77d42d8f030c80e4a04965f7529731bfab4353d6ec")
}

rule Surge_Group_Received_Lure_Email_Exact_Hash_Experimental
{
    meta:
        description = "Exact SHA-256 identifier for the retained 23 July Surge Group lure email"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/10-investigation-connections/"
        source_note = "incident-echoes-2026-07-22/received-lures/surge-group-2026-07-23.eml"
        status = "experimental"
        scope = "exact RFC message bytes only; does not establish shared control or relation to UNK_DeadDrop"
    condition:
        filesize == 9174 and hash.sha256(0, filesize) == "d062c3115237bfe03cb17ec992186db9e2aa5a6f34e791c7df58aa0d9550b3a3"
}

rule ECHOES_LNK_Launchers_Exact_Hash_Experimental
{
    meta:
        description = "Exact SHA-256 identifiers for four retained ECHOES shortcut launchers"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/09-echoes-lineage-image-provenance/"
        status = "experimental"
        scope = "exact-byte identification only; the unrecovered final payload is not inferred"
    condition:
        (filesize == 429728 and hash.sha256(0, filesize) == "a44068e9758262a65861b91f2b00d0a3eca019d3b35543dd60c1c7f2e0ba1952") or
        (filesize == 420736 and hash.sha256(0, filesize) == "9c7b507eba958ecee653ff42f13cf4e084f49cd38985d3abfd77ab2bfa40b4e2") or
        (filesize == 429662 and hash.sha256(0, filesize) == "b80028534a414f199992a49610f8d5ffa94f8098d5a820653f68b8a9eb51e3ca") or
        (filesize == 420512 and hash.sha256(0, filesize) == "bbbeadae38bf1406f331c9e42ab49cbdd22f503cd9caecb6b390964bafa1b56f")
}

rule ECHOES_RAR_Lure_Archives_Exact_Hash_Experimental
{
    meta:
        description = "Exact SHA-256 identifiers for four retained ECHOES lure archive revisions that could not be opened by the available archive reader"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/09-echoes-lineage-image-provenance/"
        status = "experimental"
        scope = "exact-byte identification only; no claim about unrecovered archive contents"
    condition:
        (filesize == 2294526 and hash.sha256(0, filesize) == "7db6789c09e29305c728bf3d7b94c5ef1c3e13eef1b321ee52d3ae3997731f56") or
        (filesize == 2292670 and hash.sha256(0, filesize) == "4ff03731d2061ad2f50da9f63dc1481374908d5bc837c86d0c7574d23b23a37b") or
        (filesize == 2294542 and hash.sha256(0, filesize) == "11bf34ccce585fe051abaa8d01ba1b29e2d44727c070b56ab0dd84a9dc9f91b2") or
        (filesize == 2292622 and hash.sha256(0, filesize) == "2bd4cfd495fdcad6d7b2adaedc31614ca2984ea1246aed7608c339eaa82eb978")
}
