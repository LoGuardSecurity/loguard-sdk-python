"""Django -> bounded queue -> signed HTTP transport -> local ingest mock."""

from http.server import BaseHTTPRequestHandler, HTTPServer
import hashlib
import hmac
import json
import threading
from unittest.mock import patch

from django.http import HttpResponse
from django.test import RequestFactory

from loguard.integrations.django import LoGuardMiddleware
from loguard.monitor import _Monitor


def test_signed_django_delivery_to_loopback(monkeypatch):
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        monkeypatch.delenv(name, raising=False)
    key = "local-test-key"
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            raw = self.rfile.read(int(self.headers["Content-Length"]))
            timestamp = self.headers["X-LoGuard-Timestamp"]
            expected = (
                "sha256="
                + hmac.new(
                    key.encode(), timestamp.encode() + b"." + raw, hashlib.sha256
                ).hexdigest()
            )
            received.append(
                (self.path, self.headers["X-LoGuard-Signature"], expected, raw)
            )
            body = b'{"ok":true,"accepted":1}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(
        target=lambda: server.serve_forever(poll_interval=0.01), daemon=True
    )
    thread.start()
    monitor = _Monitor()
    monitor.init(
        api_key=key,
        base_url=f"http://127.0.0.1:{server.server_port}",
        allow_insecure_transport=True,
        retries=1,
        timeout=1,
        env="tests",
    )
    try:
        raw = b'{"q":"test","password":"never-forward"}'
        request = RequestFactory().post(
            "/search?q=test&token=never-forward", raw, content_type="application/json"
        )

        def view(req):
            assert req.read() == raw
            return HttpResponse("ok")

        with patch("loguard.integrations.django._monitor", monitor):
            assert (
                LoGuardMiddleware(view, security_capture=True)(request).content == b"ok"
            )
        assert monitor.shutdown(2)
        assert monitor.delivery_stats["failed_batches"] == 0
        assert len(received) == 1
        path, signature, expected, payload = received[0]
        assert path == "/v1/ingest"
        assert signature == expected
        assert b"never-forward" not in payload
        ev = json.loads(payload)["events"][0]
        assert ev["meta"]["body"] == {"q": "test"}
        assert ev["meta"]["query"] == {"q": "test"}
        assert ev["meta"]["env"] == "tests"
    finally:
        monitor.shutdown(2)
        server.shutdown()
        server.server_close()
        thread.join(1)
