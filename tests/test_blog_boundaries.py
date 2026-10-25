"""Inert boundary examples used in the detection-engineering blog article."""
import unittest
from pathlib import Path
import yaml
import yara
from test_detections import selection_matches

ROOT = Path(__file__).resolve().parents[1]

class BlogBoundaryTests(unittest.TestCase):
    def test_yara_documentation_can_match(self):
        rules = yara.compile(filepath=str(ROOT / 'rules/yara/deaddrop_wallet_agent.yar'))
        document = b'''Research notes only, no executable code:
        overlord-client/cmd/agent OVERLORD_SERVER_RAW
        OVERLORD_COMPANY_WALLET_EP X-Company-Wallet-Client-Id'''
        self.assertTrue(rules.match(data=document))
        self.assertFalse(rules.match(data=document.replace(b'OVERLORD_SERVER_RAW', b'SERVER_RENAMED')))

    def test_windows_name_is_substring_not_task_name_equality(self):
        rule = yaml.safe_load((ROOT / 'rules/sigma/windows_capture_task.yml').read_text())
        selection = rule['detection']['selection']
        event = {'Image': r'C:\Windows\System32\schtasks.exe',
                 'CommandLine': 'schtasks /create /tn GoogleUpdateSupporterNode-Lab /tr example'}
        self.assertTrue(selection_matches(selection, event))
        self.assertFalse(selection_matches(selection, {'Image': event['Image']}))

    def test_linux_fixture_evaluator_folds_case(self):
        rule = yaml.safe_load((ROOT / 'rules/sigma/linux_google_agent_persistence.yml').read_text())
        selection = rule['detection']['selection_system']
        self.assertTrue(selection_matches(selection, {'TargetFilename': '/etc/systemd/system/GOOGLE-AGENT.service'}))
        self.assertFalse(selection_matches(selection, {'TargetFilename': '/etc/systemd/system/google-agent.service.bak'}))

if __name__ == '__main__':
    unittest.main()
