"""Integration & Security Test Suite for Feature 3 (dashboard.py).
"""

import json
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import dashboard
from dashboard import (
    HOST,
    SentinelRequestHandler,
    _session_token,
    load_or_create_identity,
)


class TestSentinelDashboard(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Start a test server instance on a designated test port."""
        cls.test_port = 5555
        cls.server = ThreadingHTTPServer((HOST, cls.test_port), SentinelRequestHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        """Shutdown test server."""
        cls.server.shutdown()
        cls.server.server_close()

    def make_request(self, path: str, method: str = "GET", headers: dict = None, data: dict = None):
        url = f"http://{HOST}:{self.test_port}{path}"
        body_bytes = json.dumps(data).encode("utf-8") if data else None
        req_headers = {"User-Agent": "DashboardTest/1.0"}
        if headers:
            req_headers.update(headers)
        if body_bytes:
            req_headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=body_bytes, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp_body = resp.read().decode("utf-8")
                return resp.status, json.loads(resp_body) if resp.headers.get_content_type() == "application/json" else resp_body
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8")
            try:
                parsed_err = json.loads(err_body)
            except Exception:
                parsed_err = err_body
            return e.code, parsed_err

    def test_01_get_status_endpoint(self):
        """Test GET /api/status returns valid DID, fingerprint, and metrics."""
        status, data = self.make_request("/api/status")
        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "ONLINE")
        self.assertTrue(data["did"].startswith("did:key:z6Mk"))
        self.assertEqual(len(data["fingerprint"]), 16)
        self.assertIn("uptime_seconds", data)
        self.assertNotIn("session_token", data)

    def test_02_get_rooms_and_feed_endpoints(self):
        """Test GET /api/rooms and /api/feed endpoints."""
        # 1. Rooms
        status, data = self.make_request("/api/rooms")
        self.assertEqual(status, 200)
        self.assertIn("rooms", data)
        self.assertTrue(any(r["room"] == "lobby" for r in data["rooms"]))

        # 2. Feed
        status, feed_data = self.make_request("/api/feed?room=lobby")
        self.assertEqual(status, 200)
        self.assertEqual(feed_data["room"], "lobby")
        self.assertIn("messages", feed_data)
        self.assertIn("health", feed_data)

    def test_03_get_html_ui(self):
        """Test GET / serves valid HTML dashboard."""
        status, html = self.make_request("/")
        self.assertEqual(status, 200)
        self.assertIn("TECHNOCORE SENTINEL", html)
        self.assertIn("1-Click Ed25519 Signed Broadcaster", html)

    def test_04_unauthorized_mutations_blocked(self):
        """Verify mutating endpoints strictly reject requests lacking valid Bearer token."""
        # 1. No auth header
        status, data = self.make_request("/api/send", method="POST", data={"room": "lobby", "text": "test"})
        self.assertEqual(status, 401)
        self.assertIn("Unauthorized", data.get("error", ""))

        # 2. Invalid auth token
        status, data = self.make_request(
            "/api/send",
            method="POST",
            headers={"Authorization": "Bearer invalid_token_12345"},
            data={"room": "lobby", "text": "test"}
        )
        self.assertEqual(status, 401)

    def test_05_authenticated_post_validation(self):
        """Verify authenticated POST /api/send validates input properly."""
        # Empty text
        status, data = self.make_request(
            "/api/send",
            method="POST",
            headers={"Authorization": f"Bearer {dashboard._session_token}"},
            data={"room": "lobby", "text": "   "}
        )
        self.assertEqual(status, 400)
        self.assertIn("cannot be empty", data.get("error", ""))

    def test_06_authenticated_post_send_pipeline(self):
        """Verify full sign, sweep, and broadcast pipeline via POST /api/send."""
        from unittest.mock import patch
        with patch("dashboard.http_get", return_value=(200, "# room lobby messages 1")):
            status, data = self.make_request(
                "/api/send",
                method="POST",
                headers={"Authorization": f"Bearer {dashboard._session_token}"},
                data={"room": "lobby", "text": "  Automated test message \u200b  "}
            )
            self.assertEqual(status, 200)
            self.assertTrue(data.get("success"))
            self.assertEqual(data.get("swept_text"), "Automated test message")
            self.assertEqual(len(data.get("signature", "")), 86)


if __name__ == "__main__":
    unittest.main(verbosity=2)
