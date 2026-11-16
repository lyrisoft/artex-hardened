import unittest
from unittest import mock

import guard
from guard import parse_endpoints


class EndpointParsingTests(unittest.TestCase):
    def test_only_exact_private_ipv4_tcp_pairs(self):
        self.assertEqual(parse_endpoints('[{"address":"172.30.139.20","port":80}]'), [("172.30.139.20", 80)])
        invalid = [
            "", "[]", "{}", "\ud800", '[{"address":"172.30.139.20","port":80,"extra":1}]',
            '[{"address":"172.30.139.20","port":80,"port":81}]',
            '[{"address":"example.test","port":80}]', '[{"address":"172.30.139.0/24","port":80}]',
            '[{"address":"8.8.8.8","port":53}]', '[{"address":"169.254.169.254","port":80}]',
            '[{"address":"127.0.0.1","port":80}]', '[{"address":"fd42::1","port":80}]',
            '[{"address":"172.030.139.20","port":80}]', '[{"address":"172.30.139.20","port":true}]',
            '[{"address":"172.30.139.20","port":0}]', '[{"address":"172.30.139.20","port":65536}]',
            '[{"address":"172.30.139.20","port":80},{"address":"172.30.139.20","port":80}]',
            "[" + ",".join('{"address":"10.0.0.%d","port":80}' % i for i in range(1, 34)) + "]",
        ]
        for document in invalid:
            with self.subTest(document=document), self.assertRaises(ValueError):
                parse_endpoints(document)

    def test_refuses_without_disposable_namespace_acknowledgement(self):
        with mock.patch.dict(guard.os.environ, {}, clear=True), mock.patch.object(guard, "_run") as run:
            with self.assertRaises(SystemExit):
                guard.main()
            run.assert_not_called()

    def test_invalid_policy_never_adds_an_allow_rule_or_readiness(self):
        env = {"ARTEX_FIXTURE_GUARD_ACK": "DISPOSABLE_NETWORK_NAMESPACE_ONLY", "ARTEX_FIXTURE_ENDPOINTS": "[]"}
        with mock.patch.dict(guard.os.environ, env, clear=True), mock.patch.object(guard, "_run") as run, mock.patch("builtins.open") as opened:
            with self.assertRaises(ValueError):
                guard.main()
            opened.assert_not_called()
            calls = [call.args for call in run.call_args_list]
            self.assertEqual(calls[:3], [("iptables", "-P", chain, "DROP") for chain in ("OUTPUT", "INPUT", "FORWARD")])
            self.assertEqual(calls[6:9], [("ip6tables", "-P", chain, "DROP") for chain in ("OUTPUT", "INPUT", "FORWARD")])
            self.assertTrue(all("-A" not in call for call in calls))

    def test_valid_policy_adds_only_the_exact_ipv4_tcp_pair(self):
        env = {"ARTEX_FIXTURE_GUARD_ACK": "DISPOSABLE_NETWORK_NAMESPACE_ONLY", "ARTEX_FIXTURE_ENDPOINTS": '[{"address":"172.30.139.20","port":80}]'}
        with mock.patch.dict(guard.os.environ, env, clear=True), mock.patch.object(guard, "_run") as run, \
                mock.patch("builtins.open", mock.mock_open()), mock.patch.object(guard.signal, "signal"), \
                mock.patch.object(guard.signal, "pause", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                guard.main()
            allows = [call.args for call in run.call_args_list if "-A" in call.args]
            self.assertEqual(allows, [
                ("iptables", "-A", "OUTPUT", "-d", "172.30.139.20/32", "-p", "tcp", "--dport", "80", "-j", "ACCEPT"),
                ("iptables", "-A", "INPUT", "-s", "172.30.139.20/32", "-p", "tcp", "--sport", "80", "-m", "conntrack", "--ctstate", "ESTABLISHED", "-j", "ACCEPT"),
            ])


if __name__ == "__main__":
    unittest.main()
