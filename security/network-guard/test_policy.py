#!/usr/bin/env python3
"""Static validation: the egress guard requires independent network enforcement."""
import pathlib
import unittest
p = pathlib.Path(__file__).resolve().parents[2]
class GuardConfig(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c=(p/"docker-compose.contained.yml").read_text()
        cls.s=(p/"security/network-guard/entrypoint.sh").read_text()
    def test_separate_network_namespace(self):
        self.assertIn('network_mode: "service:network-guard"', self.c)
        self.assertIn('cap_drop: [ALL]', self.c)
        self.assertIn('cap_add: [NET_ADMIN]', self.c)
    def test_restricted_bind(self):
        self.assertIn('127.0.0.1:8787:8787', self.c)
    def test_default_deny(self):
        self.assertIn('iptables -P OUTPUT DROP', self.s)
        self.assertIn('ip6tables -P OUTPUT DROP', self.s)
        self.assertIn('ARTEX_TARGET_CIDRS:?', self.s)
        self.assertIn('exec tail -f /dev/null',self.s)
    def test_dns_opt_in(self):
        self.assertIn('ARTEX_ALLOW_DNS:-0',self.s)
if __name__=="__main__":
    unittest.main()
