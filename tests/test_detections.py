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


if __name__ == '__main__':
    unittest.main()
