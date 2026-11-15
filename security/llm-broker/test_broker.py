import os
import unittest
from unittest.mock import patch
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).parent))
import broker

class BrokerTests(unittest.TestCase):
    def test_allowed_methods_restricted(self):
        self.assertNotIn("/v1/files",broker.ALLOWED_POST)
        self.assertIn("/v1/chat/completions",broker.ALLOWED_POST)
    def test_external_protocol_rejected(self):
        for url in ["http://example.com","https://u:p@example.com","https://example.com/path","https://example.com?q=bad"]:
            with self.subTest(url=url), patch.object(broker,"UPSTREAM",url):
                with self.assertRaises(ValueError):
                    broker.validate_configuration()
    def test_requires_client_token(self):
        with patch.object(broker,"UPSTREAM","https://api.openai.com"),patch.object(broker,"CLIENT_TOKEN","short"):
            with self.assertRaises(ValueError):
                broker.validate_configuration()
if __name__=="__main__":
    unittest.main()
