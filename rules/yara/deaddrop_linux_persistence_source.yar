rule UNK_DeadDrop_Linux_Systemd_Persistence_Source_Experimental
{
    meta:
        description = "Recovered Linux agent source that writes and manages the google-agent systemd unit"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/04-credential-wallet-collection/"
        source_note = "incident-2026-07-22/samples-DO-NOT-RUN/stage3.js"
        status = "experimental"
        scope = "static installer-source identification; not evidence that a unit was written or started"
    strings:
        $system_unit = "/etc/systemd/system/google-agent.service" ascii
        $user_unit = ".config/systemd/user/google-agent.service" ascii
        $agent_dir = ".local/share/google/agent" ascii
        $unit_staging = "unitStaging" ascii
        $enable = "systemctl enable google-agent.service" ascii
        $restart = "systemctl restart google-agent.service" ascii
        $desktop = "google-agent.desktop" ascii
    condition:
        filesize < 8MB and 1 of ($system_unit, $user_unit) and
        1 of ($enable, $restart) and 1 of ($unit_staging, $agent_dir, $desktop)
}
