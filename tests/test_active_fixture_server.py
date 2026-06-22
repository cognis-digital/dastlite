"""End-to-end active-mode test against a LOCALHOST fixture server only.

Binds a throwaway HTTP server to 127.0.0.1 on an ephemeral port and runs the
real ``fetch`` + active scanner against it. No external network is touched.
"""
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from dastlite.active import ActiveConfig, run_active_scan
from dastlite.core import fetch


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        if self.path == "/.env":
            body = b"SECRET=leaked"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
        else:
            body = b"<html><body>ok</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def server():
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()


def test_active_against_localhost_fixture(server):
    host_port = server.replace("http://", "")
    cfg = ActiveConfig(authorized=True, allowlist=[host_port], rate_limit=1000,
                       check_trace=False)
    result = run_active_scan([server + "/"], cfg, fetcher=fetch, sleeper=lambda s: None)
    rules = {f.rule_id for f in result.findings}
    # /.env is served 200 -> exposed-dotenv error
    assert "exposed-dotenv" in rules
    # baseline page is html without security headers -> passive findings present
    assert "missing-csp" in rules


def test_fetch_localhost_captures_response(server):
    t = fetch(server + "/", timeout=5)
    assert t.error is None
    assert t.status == 200
    assert "ok" in t.body


def test_out_of_scope_localhost_skipped(server):
    # server is up, but we deliberately leave it out of scope -> must be skipped
    cfg = ActiveConfig(authorized=True, allowlist=["someone-else.invalid"],
                       rate_limit=1000)
    result = run_active_scan([server + "/"], cfg, fetcher=fetch, sleeper=lambda s: None)
    assert all(f.rule_id == "skipped-out-of-scope" for f in result.findings)
    assert result.targets == []  # nothing was fetched
