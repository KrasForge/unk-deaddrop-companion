"""Inert boundary examples used in the detection-engineering article."""
import unittest
from pathlib import Path

import yara

ROOT = Path(__file__).resolve().parents[1]


class BlogBoundaryTests(unittest.TestCase):
    def test_wallet_rule_does_not_match_marker_rich_prose(self):
        rules = yara.compile(filepath=str(ROOT / 'rules/yara/deaddrop_wallet_agent.yar'))
        document = b'''Research notes only, no executable code:
        overlord-client/cmd/agent OVERLORD_SERVER_RAW
        OVERLORD_COMPANY_WALLET_EP X-Company-Wallet-Client-Id'''
        self.assertFalse(rules.match(data=document))
        self.assertFalse(rules.match(data=document.replace(b'OVERLORD_SERVER_RAW', b'SERVER_RENAMED')))


if __name__ == '__main__':
    unittest.main()
