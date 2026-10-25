"""Compile real YARA; parse Sigma and exercise this suite's modifier subset."""
import unittest
from pathlib import Path
import yaml
import yara
from sigma.collection import SigmaCollection

ROOT = Path(__file__).resolve().parents[1]


def selection_matches(selection, event):
    """Fixture evaluator only; deliberately not a Sigma backend."""
    for key, expected in selection.items():
        field, *modifiers = key.split('|')
        if field not in event:
            return False
        actual = str(event[field]).casefold()
        values = expected if isinstance(expected, list) else [expected]
        checks = []
        for value in values:
            value = value.casefold()
            if 'endswith' in modifiers:
                checks.append(actual.endswith(value))
            elif 'contains' in modifiers:
                checks.append(value in actual)
            else:
                checks.append(actual == value)
        if not (all(checks) if 'all' in modifiers else any(checks)):
            return False
    return True


class DetectionTests(unittest.TestCase):
    def test_yara_positive_and_framework_only_negative(self):
        rules = yara.compile(filepath=str(ROOT / 'rules/yara/deaddrop_wallet_agent.yar'))
        framework = b'overlord-client/cmd/agent OVERLORD_SERVER_RAW'
        wallet = b' OVERLORD_COMPANY_WALLET_EP X-Company-Wallet-Client-Id'
        self.assertTrue(rules.match(data=framework + wallet))
        self.assertFalse(rules.match(data=framework))
        self.assertFalse(rules.match(data=wallet))
        self.assertFalse(rules.match(data=framework + b' OVERLORD_COMPANY_WALLET_EP'))
        self.assertTrue(rules.match(data=(framework + wallet).decode().encode('utf-16le')))

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

    def test_sigma_schema(self):
        for path in (ROOT / 'rules/sigma').glob('*.yml'):
            with self.subTest(path=path.name):
                collection = SigmaCollection.from_yaml(path.read_text())
                self.assertEqual(len(collection.rules), 1)
                self.assertFalse(collection.errors)

    def test_linux_fixture(self):
        rule = yaml.safe_load((ROOT / 'rules/sigma/linux_google_agent_persistence.yml').read_text())
        detection = rule['detection']
        self.assertEqual(detection['condition'], 'selection_system or selection_user')
        def hit(event):
            return any(selection_matches(detection[name], event) for name in ('selection_system', 'selection_user'))
        self.assertTrue(hit({'TargetFilename': '/etc/systemd/system/google-agent.service'}))
        self.assertTrue(hit({'TargetFilename': '/home/example/.config/systemd/user/google-agent.service'}))
        self.assertFalse(hit({'TargetFilename': '/etc/systemd/system/google-updater.service'}))
        self.assertFalse(hit({}))

    def test_windows_fixture(self):
        rule = yaml.safe_load((ROOT / 'rules/sigma/windows_capture_task.yml').read_text())
        self.assertEqual(rule['detection']['condition'], 'selection')
        selection = rule['detection']['selection']
        event = {'Image': r'C:\Windows\System32\schtasks.exe',
                 'CommandLine': 'schtasks /Create /TN GoogleUpdateSupporterNode /TR example'}
        self.assertTrue(selection_matches(selection, event))
        self.assertFalse(selection_matches(selection, {**event, 'CommandLine': 'schtasks /query /TN GoogleUpdateSupporterNode'}))
        self.assertFalse(selection_matches(selection, {**event, 'Image': r'C:\example.exe'}))

    def test_editor_as_node_fixture(self):
        detection = yaml.safe_load((ROOT / 'rules/sigma/windows_editor_node_collection.yml').read_text())['detection']
        def hit(event):
            return selection_matches(detection['selection_image'], event) and selection_matches(detection['selection_argument'], event)
        self.assertTrue(hit({'Image': r'C:\Program Files\Microsoft VS Code\Code.exe',
                             'CommandLine': r'Code.exe C:\Temp\agent.js --company-wallet-job'}))
        self.assertTrue(hit({'Image': r'C:\Users\example\Cursor.exe',
                             'CommandLine': r'Cursor.exe agent.js --win-build-ep-only'}))
        self.assertFalse(hit({'Image': r'C:\Program Files\Microsoft VS Code\Code.exe', 'CommandLine': 'Code.exe project'}))
        self.assertFalse(hit({'Image': r'C:\node.exe', 'CommandLine': 'node agent.js --company-wallet-job'}))

    def test_powershell_electron_mode_fixture(self):
        detection = yaml.safe_load((ROOT / 'rules/sigma/windows_powershell_electron_node_mode.yml').read_text())['detection']
        def hit(event):
            return selection_matches(detection['selection_mode'], event) and selection_matches(detection['selection_argument'], event)
        self.assertTrue(hit({'ScriptBlockText': "$env:ELECTRON_RUN_AS_NODE='1'; & $editor agent.js --company-wallet-job"}))
        self.assertFalse(hit({'ScriptBlockText': "$env:ELECTRON_RUN_AS_NODE='1'; & $editor --version"}))
        self.assertFalse(hit({'ScriptBlockText': '& $editor agent.js --company-wallet-job'}))

    def test_elevation_temp_artifact_fixture(self):
        detection = yaml.safe_load((ROOT / 'rules/sigma/windows_elevation_temp_artifacts.yml').read_text())['detection']
        def hit(event):
            return any(selection_matches(detection[name], event) for name in
                       ('selection_phase_script', 'selection_elevation_sentinel'))
        self.assertTrue(hit({'TargetFilename': r'C:\Users\example\AppData\Local\Temp\gus-phase2-1729.ps1'}))
        self.assertTrue(hit({'TargetFilename': r'C:\Temp\sa-elev-done-1729.txt'}))
        self.assertFalse(hit({'TargetFilename': r'C:\Temp\gus-phase2-1729.txt'}))
        self.assertFalse(hit({'TargetFilename': r'C:\Temp\ordinary.ps1'}))

    def test_extension_artifact_fixture(self):
        detection = yaml.safe_load((ROOT / 'rules/sigma/windows_vscode_extension_artifact.yml').read_text())['detection']
        selection = detection['selection_path']
        self.assertTrue(selection_matches(selection, {
            'TargetFilename': r'C:\Users\example\.vscode\extensions\google-dev-tools.google-update-support-1.0.0\package.json'}))
        self.assertTrue(selection_matches(selection, {
            'TargetFilename': r'C:\Users\example\.cursor\extensions\google-dev-tools.google-update-support-1.0.0\extension.js'}))
        self.assertFalse(selection_matches(selection, {
            'TargetFilename': r'C:\Users\example\.vscode\extensions\google-dev-tools.google-update-support-1.0.0\README.md'}))
        self.assertFalse(selection_matches(selection, {
            'TargetFilename': r'C:\Users\example\.vscode\extensions\legitimate.extension-1.0.0\package.json'}))


if __name__ == '__main__':
    unittest.main()
