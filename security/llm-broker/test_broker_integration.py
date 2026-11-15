"""Loopback-only broker tests with a synthetic TLS provider and dummy secrets."""
import contextlib
import http.client
import json
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import broker

CLIENT_TOKEN = "fixture-client-token-not-a-secret"
PROVIDER_KEY = "fixture-provider-key-not-a-secret"


class FakeProvider(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self.server.records.append((self.path, dict(self.headers), body))
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Connection", "close")
        chunked = self.path.endswith("fixture=chunked")
        if chunked:
            self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

        def send_event(data):
            if chunked:
                self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
            else:
                self.wfile.write(data)
            self.wfile.flush()

        send_event(b"data: first\n\n")
        self.server.first_sent.set()
        self.server.release.wait(5)
        try:
            send_event(b"data: second\n\n")
            if chunked:
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        self.close_connection = True


class BrokerIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("openssl"):
            raise unittest.SkipTest("openssl is required for a synthetic TLS certificate")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.cert = Path(cls.tmp.name) / "cert.pem"
        key = Path(cls.tmp.name) / "key.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cls.cert), "-days", "1",
            "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.key = key

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.provider = ThreadingHTTPServer(("127.0.0.1", 0), FakeProvider)
        self.provider.records = []
        self.provider.first_sent = threading.Event()
        self.provider.release = threading.Event()
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(str(self.cert), str(self.key))
        self.provider.socket = tls.wrap_socket(self.provider.socket, server_side=True)
        self.provider_thread = threading.Thread(target=self.provider.serve_forever, daemon=True)
        self.provider_thread.start()

        # Trust only this generated certificate for the positive fixture. The
        # negative TLS test uses the normal trust store instead.
        self.trusted = ssl.create_default_context(cafile=str(self.cert))
        self.untrusted = ssl.create_default_context()
        self.patches = contextlib.ExitStack()
        self.patches.enter_context(patch.object(broker, "CLIENT_TOKEN", CLIENT_TOKEN))
        self.patches.enter_context(patch.object(broker, "UPSTREAM_HOST", "127.0.0.1", create=True))
        self.patches.enter_context(patch.object(broker, "UPSTREAM_PORT", self.provider.server_port, create=True))
        self.patches.enter_context(patch.object(broker, "UPSTREAM_KEY", PROVIDER_KEY, create=True))
        self.patches.enter_context(patch.object(broker.ssl, "create_default_context", return_value=self.trusted))
        self.proxy = ThreadingHTTPServer(("127.0.0.1", 0), broker.Handler)
        self.proxy_thread = threading.Thread(target=self.proxy.serve_forever, daemon=True)
        self.proxy_thread.start()

    def tearDown(self):
        self.provider.release.set()
        self.proxy.shutdown()
        self.proxy.server_close()
        self.proxy_thread.join(timeout=3)
        self.provider.shutdown()
        self.provider.server_close()
        self.provider_thread.join(timeout=3)
        self.patches.close()

    def request(self, path, token, body=b"{}", extra_headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.proxy.server_port, timeout=2)
        headers = {"Authorization": "Bearer " + token}
        headers.update(extra_headers or {})
        connection.request("POST", path, body=body, headers=headers)
        response = connection.getresponse()
        return connection, response

    def test_denied_requests_never_reach_provider(self):
        for path, token, expected in [
            ("/v1/chat/completions", "wrong", 401),
            ("/v1/files", CLIENT_TOKEN, 403),
            ("http://other.example/v1/chat/completions", CLIENT_TOKEN, 403),
        ]:
            with self.subTest(path=path, expected=expected):
                conn, response = self.request(path, token)
                self.assertEqual(response.status, expected)
                response.read()
                conn.close()
        with patch.object(broker, "MAX_BYTES", 3):
            conn, response = self.request("/v1/chat/completions", CLIENT_TOKEN, b"1234")
            self.assertEqual(response.status, 413)
            response.read()
            conn.close()
        conn, response = self.request("/v1/chat/completions", CLIENT_TOKEN, b"{}", {"Transfer-Encoding": "chunked"})
        self.assertEqual(response.status, 411)
        response.read()
        conn.close()
        self.assertEqual(self.provider.records, [])

    def test_provider_key_substitution_and_incremental_stream(self):
        self.assert_incremental_stream("1")

    def test_chunked_provider_response_streams_incrementally(self):
        self.assert_incremental_stream("chunked")

    def assert_incremental_stream(self, fixture):
        body = json.dumps({"model": "fixture", "stream": True}).encode()
        path = "/v1/chat/completions?fixture=" + fixture
        conn, response = self.request(path, CLIENT_TOKEN, body,
                                      {"X-Do-Not-Forward": "fixture-private-header"})
        try:
            self.assertEqual(response.status, 200)
            self.assertTrue(self.provider.first_sent.wait(2))
            try:
                first = response.fp.readline()
            except socket.timeout:
                self.fail("broker buffered the first event until the provider finished")
            self.assertEqual(first, b"data: first\n")
            self.assertEqual(response.fp.readline(), b"\n")
            self.provider.release.set()
            self.assertEqual(response.read(), b"data: second\n\n")
        finally:
            self.provider.release.set()
            conn.close()
        self.assertEqual(len(self.provider.records), 1)
        path, headers, sent = self.provider.records[0]
        self.assertEqual(path, "/v1/chat/completions?fixture=" + fixture)
        self.assertEqual(sent, body)
        self.assertEqual(headers.get("Authorization"), "Bearer " + PROVIDER_KEY)
        self.assertNotIn(CLIENT_TOKEN, str(headers))
        self.assertNotIn("X-Do-Not-Forward", headers)

    def test_untrusted_provider_certificate_is_rejected(self):
        with patch.object(broker.ssl, "create_default_context", return_value=self.untrusted):
            conn, response = self.request("/v1/chat/completions", CLIENT_TOKEN)
            self.assertEqual(response.status, 502)
            payload = response.read()
            conn.close()
        self.assertNotIn(PROVIDER_KEY.encode(), payload)
        self.assertNotIn(CLIENT_TOKEN.encode(), payload)
        self.assertEqual(self.provider.records, [])


if __name__ == "__main__":
    unittest.main()
