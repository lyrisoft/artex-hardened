"""Fixed-destination OpenAI-compatible proxy. Holds cloud key outside agent container.

This is a credential boundary, NOT a DLP solution: a permitted model request
can still contain confidential prompt content. Deploy only to trusted providers.
"""
import http.client
import ipaddress
import os
import socket
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

UPSTREAM = os.getenv("ARTEX_BROKER_UPSTREAM", "https://api.openai.com")
CLIENT_TOKEN = os.getenv("ARTEX_BROKER_CLIENT_TOKEN", "")
SECRET_FILE = os.getenv("ARTEX_BROKER_KEY_FILE", "/run/secrets/openai_api_key")
MAX_BYTES = 16 * 1024 * 1024
ALLOWED_POST = frozenset({
    "/v1/chat/completions", "/v1/responses", "/v1/embeddings", "/v1/completions",
})
ALLOWED_GET = frozenset({"/v1/models"})

def validate_configuration():
    u = urlsplit(UPSTREAM)
    if u.scheme != "https" or not u.hostname or u.username or u.password or u.query or u.fragment or u.path not in ("", "/"):
        raise ValueError("Upstream must be a bare HTTPS origin with no embedded credentials or path")
    if len(CLIENT_TOKEN) < 24 or CLIENT_TOKEN == "broker-placeholder":
        raise ValueError("Provide random ARTEX_BROKER_CLIENT_TOKEN of at least 24 characters")
    with open(SECRET_FILE, "r", encoding="utf-8") as f:
        api_key = f.read().strip()
    if len(api_key) < 16:
        raise ValueError("Broker secret file missing or too short")
    return u, api_key

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *_):
        pass  # Never log model prompts, Authorization, tokens or response bodies.
    def send_error_json(self, status, message):
        data = ('{"error":{"message":"'+message+'"}}').encode()
        self.send_response(status)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(data)))
        self.send_header("Connection","close")
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True
    def do_POST(self): self.proxy("POST")
    def do_GET(self): self.proxy("GET")
    def proxy(self, method):
        u = urlsplit(self.path)
        if u.scheme or u.netloc or u.fragment or u.path not in (ALLOWED_POST if method=="POST" else ALLOWED_GET):
            return self.send_error_json(403,"Endpoint not allowed")
        if self.headers.get("Authorization") != "Bearer "+CLIENT_TOKEN:
            return self.send_error_json(401,"Unauthorized")
        if self.headers.get("Transfer-Encoding"):
            return self.send_error_json(411,"Chunked input not supported")
        try:
            length = int(self.headers.get("Content-Length","0"))
        except ValueError:
            return self.send_error_json(400,"Invalid length")
        if length < 0 or length > MAX_BYTES or (method == "POST" and length == 0):
            return self.send_error_json(413,"Invalid request body size")
        data = self.rfile.read(length) if length else None
        conn = http.client.HTTPSConnection(UPSTREAM_HOST,UPSTREAM_PORT,timeout=180,context=ssl.create_default_context())
        try:
            path = u.path + (("?"+u.query) if u.query else "")
            headers = {
                "Authorization": "Bearer "+UPSTREAM_KEY,
                "Content-Type": "application/json",
                "Accept": self.headers.get("Accept","application/json"),
                "Connection": "close",
            }
            conn.request(method,path,body=data,headers=headers)
            res = conn.getresponse()
            self.send_response(res.status)
            self.send_header("Content-Type",res.getheader("Content-Type","application/json"))
            self.send_header("Cache-Control","no-store")
            self.send_header("Connection","close")
            self.end_headers()
            while True:
                # read() can wait for the full buffer or EOF, delaying small
                # streaming events. read1() forwards currently available bytes.
                chunk = res.read1(16384)
                if not chunk: break
                self.wfile.write(chunk)
                self.wfile.flush()
        except (OSError, http.client.HTTPException) as e:
            # Do not return exception details containing endpoint or credentials.
            if not self.wfile.closed:
                try: self.send_error_json(502,"Upstream request failed")
                except (OSError, BrokenPipeError): pass
        finally:
            self.close_connection = True
            conn.close()

if __name__ == "__main__":
    parsed, UPSTREAM_KEY = validate_configuration()
    UPSTREAM_HOST = parsed.hostname
    UPSTREAM_PORT = parsed.port or 443
    ThreadingHTTPServer(("0.0.0.0",8899),Handler).serve_forever()
