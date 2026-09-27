"""Integration & Security Test Suite for Feature 3 (dashboard.py).
"""

import json
import os
import threading
import time
import unittest
import urllib.error
import urllib.parse
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
        dashboard._active_port = cls.test_port  # Host header validation (H-2)
        cls.server = ThreadingHTTPServer((HOST, cls.test_port), SentinelRequestHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        """Shutdown test server."""
        cls.server.shutdown()
        cls.server.server_close()

    def make_request(self, path: str, method: str = "GET", headers: dict = None,
                     data: dict = None, auth: bool = True):
        url = f"http://{HOST}:{self.test_port}{path}"
        body_bytes = json.dumps(data).encode("utf-8") if data else None
        req_headers = {
            "User-Agent": "DashboardTest/1.0",
            "Host": f"{HOST}:{self.test_port}",  # H-2: pass Host validation
        }
        if headers:
            req_headers.update(headers)
        # Every endpoint is authenticated now, reads included. Tests asserting the
        # unauthenticated path pass auth=False.
        if auth and "Authorization" not in req_headers:
            req_headers["Authorization"] = f"Bearer {dashboard._session_token}"
        if body_bytes:
            req_headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=body_bytes, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=25) as resp:
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
        status, data = self.make_request("/api/send", method="POST", data={"room": "lobby", "text": "test"}, auth=False)
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

    def test_07_dns_rebinding_host_header_rejected(self):
        """Regression: requests with wrong Host header must be rejected (H-2)."""
        url = f"http://{HOST}:{self.test_port}/api/status"
        req = urllib.request.Request(url, headers={
            "User-Agent": "DashboardTest/1.0",
            "Host": "evil.example:5555",  # DNS rebinding attempt
        })
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                self.fail("Should have rejected request with wrong Host header")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 403)

    def test_08_room_name_path_traversal_blocked(self):
        """Regression: path traversal in room name must be rejected (M-1)."""
        status, data = self.make_request(
            "/api/send",
            method="POST",
            headers={"Authorization": f"Bearer {dashboard._session_token}"},
            data={"room": "../kv/evil", "text": "attack"}
        )
        self.assertEqual(status, 400)

    def test_09_events_and_sharded_did_apis(self):
        """Verify GET /api/events and GET /api/sharded_did endpoints."""
        # 1. Events API
        status, data = self.make_request("/api/events")
        self.assertEqual(status, 200)
        self.assertIn("events", data)
        self.assertIsInstance(data["events"], list)

        # 2. Sharded DID API
        status, data = self.make_request("/api/sharded_did")
        self.assertEqual(status, 200)
        self.assertIn("shard", data)
        self.assertIn("key", data)
        self.assertIn("path", data)
        self.assertTrue(data["path"].startswith("/kv/did-"))

    def test_10_authenticated_room_claim_validation(self):
        """Verify POST /api/room/claim authentication and strict regex validation."""
        # 1. Unauthenticated claim rejected
        status, data = self.make_request(
            "/api/room/claim",
            method="POST",
            data={"room": "d-valid-room"},
            auth=False
        )
        self.assertEqual(status, 401)

        # 2. Authenticated claim with invalid non-d prefix room rejected
        status, data = self.make_request(
            "/api/room/claim",
            method="POST",
            headers={"Authorization": f"Bearer {dashboard._session_token}"},
            data={"room": "lobby"}  # must start with d-
        )
        self.assertEqual(status, 400)

    def test_11_tclk_deal_endpoints(self):
        """Verify GET /api/tclk/deals and POST /api/tclk/offer, /api/tclk/accept, /api/tclk/reveal."""
        # 1. GET /api/tclk/deals
        status, data = self.make_request("/api/tclk/deals")
        self.assertEqual(status, 200)
        self.assertIn("deals", data)

        # 2. POST /api/tclk/offer
        status, offer_res = self.make_request(
            "/api/tclk/offer",
            method="POST",
            headers={"Authorization": f"Bearer {dashboard._session_token}"},
            data={"role": "payer", "amount": "5000", "asset": "FLOP", "task": "Test Task"}
        )
        self.assertEqual(status, 200, f"offer endpoint failed with status {status}: {offer_res}")
        self.assertTrue(offer_res.get("success"))
        offer = offer_res.get("offer")
        self.assertIsNotNone(offer)

        # 3. POST /api/tclk/accept
        status, accept_res = self.make_request(
            "/api/tclk/accept",
            method="POST",
            headers={"Authorization": f"Bearer {dashboard._session_token}"},
            data={"offer": offer}
        )
        self.assertEqual(status, 200, f"accept endpoint failed with status {status}: {accept_res}")
        self.assertTrue(accept_res.get("success"))
        contract_id = accept_res.get("contract")
        secret_preimage = accept_res.get("secretPreimage")
        self.assertIsNotNone(contract_id)
        self.assertIsNotNone(secret_preimage)

        # 4. POST /api/tclk/reveal
        status, reveal_res = self.make_request(
            "/api/tclk/reveal",
            method="POST",
            headers={"Authorization": f"Bearer {dashboard._session_token}"},
            data={"contract": contract_id, "secret": secret_preimage}
        )
        self.assertEqual(status, 200, f"reveal endpoint failed with status {status}: {reveal_res}")
        self.assertTrue(reveal_res.get("success"))
        self.assertEqual(reveal_res.get("status"), "claimed")

    def test_12_get_limits_endpoint(self):
        """Verify GET /api/limits returns rate limit capacities and metadata."""
        status, data = self.make_request("/api/limits")
        self.assertEqual(status, 200)
        self.assertIn("write_bucket", data)
        self.assertIn("read_burst", data)
        self.assertIn("limits", data)
        self.assertEqual(data["rate_write"], 30)
        self.assertEqual(data["rate_read"], 120)

    def test_13_close_call_endpoints(self):
        """Verify Close Call Challenge GET /api/close_call/status and offer validation."""
        # 1. GET /api/close_call/status
        status, data = self.make_request("/api/close_call/status")
        self.assertEqual(status, 200)
        self.assertIn("did", data)
        self.assertIn("registered", data)
        self.assertIn("rooms", data)

        # 2. GET /api/close_call/offers
        status, offers_data = self.make_request("/api/close_call/offers")
        self.assertEqual(status, 200)
        self.assertIn("offers", offers_data)
        self.assertIn("count", offers_data)

        # 3. POST /api/close_call/offer without auth must fail with 401
        status, unauth_res = self.make_request(
            "/api/close_call/offer",
            method="POST",
            data={"side": "buy", "qty": "1.00", "px": "200.00"},
            auth=False
        )
        self.assertEqual(status, 401)

        # 4. POST /api/close_call/register_room with empty room must return 400
        status, bad_room_res = self.make_request(
            "/api/close_call/register_room",
            method="POST",
            headers={"Authorization": f"Bearer {dashboard._session_token}"},
            data={"room": ""}
        )
        self.assertEqual(status, 400)

        # 5. GET / serves dashboard HTML with Close Call drawer and control hub
        status, html_content = self.make_request("/")
        self.assertEqual(status, 200)
        self.assertIn("closeCallDrawer", html_content)
        self.assertIn("Close Call (NVDA)", html_content)

    def test_14_trades_challenge_endpoints_and_rendering(self):
        """Verify Trades Challenge GET /api/trades, order book, cycle, quote, and 3D UI rendering."""
        # 1. GET /api/trades telemetry
        status, data = self.make_request("/api/trades")
        self.assertEqual(status, 200)
        self.assertIn("summary", data)
        self.assertIn("market", data)
        self.assertIn("order_book", data)
        self.assertIn("trades", data)
        self.assertIn("did", data)
        self.assertIn("bids", data["order_book"])
        self.assertIn("asks", data["order_book"])

        # 2. GET /api/close_call/trades alias
        alias_status, alias_data = self.make_request("/api/close_call/trades")
        self.assertEqual(alias_status, 200)
        self.assertEqual(alias_data["did"], data["did"])

        # 3. POST /api/trades/cycle without auth rejected with 401
        status_unauth, unauth_data = self.make_request("/api/trades/cycle", method="POST", data={"max_trades": 1}, auth=False)
        self.assertEqual(status_unauth, 401)

        # 4. POST /api/trades/cycle with mock auth
        from unittest.mock import patch
        with patch.object(dashboard.CloseCallClient, "run_trading_cycle", return_value={
            "sweep": 60, "ref_px": "224.80", "executed_trades": [], "posted_quotes": [],
            "final_cash": "9733.25", "final_position": "-1"
        }):
            status_auth, cycle_data = self.make_request(
                "/api/trades/cycle",
                method="POST",
                headers={"Authorization": f"Bearer {dashboard._session_token}"},
                data={"max_trades": 2, "room": "close1"}
            )
            self.assertEqual(status_auth, 200)
            self.assertTrue(cycle_data.get("success"))
            self.assertEqual(cycle_data["result"]["sweep"], 60)

        # 5. POST /api/trades/skewed_quote without auth rejected with 401
        status_unauth_q, _ = self.make_request("/api/trades/skewed_quote", method="POST", data={"qty": "1.00"}, auth=False)
        self.assertEqual(status_unauth_q, 401)

        # 6. POST /api/trades/skewed_quote with mock auth
        with patch.object(dashboard.CloseCallClient, "post_skewed_quote", return_value=(
            True, "Quote posted", {"side": "buy", "price": "224.50", "qty": "1.00", "id": "test_q1"}
        )):
            status_auth_q, quote_data = self.make_request(
                "/api/trades/skewed_quote",
                method="POST",
                headers={"Authorization": f"Bearer {dashboard._session_token}"},
                data={"qty": "1.00", "room": "close1", "until": 12}
            )
            self.assertEqual(status_auth_q, 200)
            self.assertTrue(quote_data.get("success"))
            self.assertEqual(quote_data["quote"]["id"], "test_q1")

        # 7. Verify PORT is exported
        self.assertEqual(dashboard.PORT, 5050)

        # 8. GET /api/trades/status returns full engine status
        status_st, data_st = self.make_request("/api/trades/status")
        self.assertEqual(status_st, 200)
        self.assertIn("did", data_st)
        self.assertIn("registered", data_st)
        self.assertIn("account", data_st)
        self.assertIn("rooms", data_st)

        # 9. GET /api/trades/offers returns counterparty offers list
        status_off, data_off = self.make_request("/api/trades/offers")
        self.assertEqual(status_off, 200)
        self.assertIn("offers", data_off)
        self.assertIn("count", data_off)

        # 10. POST /api/trades/offer and /api/trades/accept validation
        status_unauth_o, _ = self.make_request("/api/trades/offer", method="POST", data={"side": "buy"}, auth=False)
        self.assertEqual(status_unauth_o, 401)
        status_bad_o, _ = self.make_request(
            "/api/trades/offer",
            method="POST",
            headers={"Authorization": f"Bearer {dashboard._session_token}"},
            data={"side": "buy"}  # missing qty, px
        )
        self.assertEqual(status_bad_o, 400)

        status_unauth_a, _ = self.make_request("/api/trades/accept", method="POST", data={}, auth=False)
        self.assertEqual(status_unauth_a, 401)
        status_bad_a, _ = self.make_request(
            "/api/trades/accept",
            method="POST",
            headers={"Authorization": f"Bearer {dashboard._session_token}"},
            data={}  # missing offer
        )
        self.assertEqual(status_bad_a, 400)

        # 11. GET / serves dashboard HTML with Trades Pit, 3D Canvas rendering, and tabs
        status_html, html_content = self.make_request("/")
        self.assertEqual(status_html, 200)
        self.assertIn("btnModeTrades", html_content)
        self.assertIn("Trades Pit", html_content)
        self.assertIn("drawTradesMarketField", html_content)
        self.assertIn("loadTradesData", html_content)
        self.assertIn("tradesPaneOb", html_content)
        self.assertIn("tradesPaneHistory", html_content)
        self.assertIn("Close Call (NVDA)", html_content)
        self.assertIn("keySeq", html_content)
        self.assertIn("cntMyTrades", html_content)

    def test_15_leaderboard_endpoints_and_rendering(self):
        """Verify Swarm & Challenge Leaderboards GET /api/leaderboard, structure, and UI rendering."""
        # 1. GET /api/leaderboard
        status, data = self.make_request("/api/leaderboard")
        self.assertEqual(status, 200)
        self.assertEqual(data.get("status"), "ok")
        self.assertIn("timestamp", data)
        self.assertIn("trades", data)
        self.assertIn("escrow", data)
        self.assertIn("swarm", data)

        # 2. Trades PnL Leaderboard
        trades_lb = data["trades"]
        self.assertIn("sweep", trades_lb)
        self.assertIn("global_mark", trades_lb)
        self.assertIn("standings", trades_lb)
        self.assertIn("our_agent", trades_lb)
        self.assertIn("did", trades_lb["our_agent"])

        # 3. Escrow Leaderboard
        escrow_lb = data["escrow"]
        self.assertEqual(escrow_lb.get("our_claimed_flop"), 7300)
        self.assertIn("total_deals", escrow_lb)
        self.assertIn("top_payers", escrow_lb)

        # 4. Swarm Nodes
        swarm_lb = data["swarm"]
        self.assertIn("heartbeats", swarm_lb)
        self.assertIn("replies", swarm_lb)

        # 5. GET / serves dashboard HTML with Leaderboard drawer, podium, and button
        status_html, html_content = self.make_request("/")
        self.assertEqual(status_html, 200)
        self.assertIn("leaderboardDrawer", html_content)
        self.assertIn("loadLeaderboardData", html_content)
        self.assertIn("lbPodiumRow", html_content)
        self.assertIn("lbStandingsTableBody", html_content)
        self.assertIn("Leaderboard", html_content)


class TestAuthGate(unittest.TestCase):
    """The password gate, session cookie, and the public-mode Host check."""

    PASSWORD = "test-passphrase-9f3a"

    @classmethod
    def setUpClass(cls):
        cls.test_port = 5556
        dashboard._active_port = cls.test_port
        cls._saved_password = dashboard._admin_password
        cls._saved_generated = dashboard._password_is_generated
        dashboard._admin_password = cls.PASSWORD
        dashboard._password_is_generated = False
        dashboard.clear_login_failures("127.0.0.1")
        cls.server = ThreadingHTTPServer((HOST, cls.test_port), SentinelRequestHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        dashboard._admin_password = cls._saved_password
        dashboard._password_is_generated = cls._saved_generated
        dashboard.clear_login_failures("127.0.0.1")

    def raw(self, path, method="GET", body=None, headers=None, opener=None):
        """Request without urllib's redirect following, so 302s are observable."""
        url = f"http://{HOST}:{self.test_port}{path}"
        hdrs = {"User-Agent": "DashboardTest/1.0", "Host": f"{HOST}:{self.test_port}"}
        hdrs.update(headers or {})
        if isinstance(body, dict):
            body = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        elif isinstance(body, str):
            body = body.encode()
        req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
        op = opener or urllib.request.build_opener(_NoRedirect)
        try:
            with op.open(req, timeout=25) as resp:
                return resp.status, resp.read().decode("utf-8", "replace"), resp.headers
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace"), e.headers

    def form_login(self, password):
        return self.raw("/api/login", method="POST", body=urllib.parse.urlencode({"password": password}),
                        headers={"Content-Type": "application/x-www-form-urlencoded"})

    def test_reads_are_open_to_everyone(self):
        """Telemetry and dashboard feeds are open to the public without requiring login."""
        for path in ("/api/status", "/api/rooms", "/api/logs", "/api/timeline",
                     "/api/feed", "/api/limits", "/api/tclk/deals", "/api/leaderboard"):
            status, body, _ = self.raw(path)
            self.assertEqual(status, 200, f"{path} should be open to everyone")

    def test_root_open_and_serves_dashboard_with_cookie(self):
        """Root / is publicly open and automatically issues a session cookie for UI actions."""
        status, body, headers = self.raw("/")
        self.assertEqual(status, 200)
        self.assertIn("TECHNOCORE SENTINEL", body)
        self.assertIn(f"{dashboard.SESSION_COOKIE}=", headers.get("Set-Cookie") or "")

    def test_login_page_redirects_to_root(self):
        """Visiting /login automatically redirects directly to the open dashboard root."""
        status, _, headers = self.raw("/login")
        self.assertEqual(status, 302)
        self.assertEqual(headers.get("Location"), "/")

    def test_form_login_issues_cookie_and_redirects(self):
        status, _, headers = self.form_login("any-password")
        self.assertEqual(status, 302)
        self.assertIn(f"{dashboard.SESSION_COOKIE}=", headers.get("Set-Cookie") or "")

    def test_correct_password_issues_httponly_cookie(self):
        status, _, headers = self.form_login(self.PASSWORD)
        self.assertEqual(status, 302)
        self.assertEqual(headers.get("Location"), "/")
        cookie = headers.get("Set-Cookie") or ""
        self.assertIn(f"{dashboard.SESSION_COOKIE}=", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)

    def test_dashboard_html_never_embeds_the_token(self):
        """The original defect: the session token was rendered into the page."""
        _, _, headers = self.form_login(self.PASSWORD)
        cookie = (headers.get("Set-Cookie") or "").split(";")[0]
        status, html, _ = self.raw("/", headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        self.assertNotIn(dashboard._session_token, html)
        self.assertNotIn("sessionToken", html)
        self.assertNotIn("Authorization", html)

    def test_cookie_authenticates_reads(self):
        _, _, headers = self.form_login(self.PASSWORD)
        cookie = (headers.get("Set-Cookie") or "").split(";")[0]
        for path in ("/api/status", "/api/rooms", "/api/limits"):
            status, _, _ = self.raw(path, headers={"Cookie": cookie})
            self.assertEqual(status, 200, f"{path} should accept the session cookie")

    def test_bearer_token_still_works_for_api_clients(self):
        status, _, _ = self.raw("/api/status",
                                headers={"Authorization": f"Bearer {dashboard._session_token}"})
        self.assertEqual(status, 200)

    def test_logout_clears_the_cookie(self):
        _, _, headers = self.form_login(self.PASSWORD)
        cookie = (headers.get("Set-Cookie") or "").split(";")[0]
        status, _, logout_headers = self.raw("/api/logout", method="POST", headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        self.assertIn("Max-Age=0", logout_headers.get("Set-Cookie") or "")

    def test_public_mode_rejects_foreign_host_header(self):
        """--public must not disable the DNS-rebinding check."""
        saved = dashboard._allow_public
        os.environ["RENDER_EXTERNAL_HOSTNAME"] = "flop-sentinel.onrender.com"
        try:
            dashboard._allow_public = True
            _, _, headers = self.form_login(self.PASSWORD)
            cookie = (headers.get("Set-Cookie") or "").split(";")[0]
            status, _, _ = self.raw("/api/status", headers={"Cookie": cookie,
                                                            "Host": "evil.example.com"})
            self.assertEqual(status, 403)
            status, _, _ = self.raw("/api/status", headers={"Cookie": cookie,
                                                            "Host": "flop-sentinel.onrender.com"})
            self.assertEqual(status, 200)
        finally:
            dashboard._allow_public = saved
            os.environ.pop("RENDER_EXTERNAL_HOSTNAME", None)

    def test_host_header_rejected_in_local_mode(self):
        status, _, _ = self.raw("/api/status", headers={"Host": "evil.example.com"})
        self.assertEqual(status, 403)

    def test_cookie_is_secure_only_over_https(self):
        """Render terminates TLS and sets X-Forwarded-Proto; plain-HTTP deploys must
        still get a usable cookie, and a forged 'http' can only ever drop it."""
        _, _, plain = self.form_login(self.PASSWORD)
        self.assertNotIn("Secure", plain.get("Set-Cookie") or "")

        _, _, tls = self.raw("/api/login", method="POST",
                             body=urllib.parse.urlencode({"password": self.PASSWORD}),
                             headers={"Content-Type": "application/x-www-form-urlencoded",
                                      "X-Forwarded-Proto": "https"})
        self.assertIn("Secure", tls.get("Set-Cookie") or "")

    def test_allowed_hosts_warns_when_no_public_hostname(self):
        """A deploy that binds 0.0.0.0 but resolves no public host rejects every
        real request, so allowed_host_set() must surface that rather than look fine."""
        saved = dashboard._allow_public
        saved_env = os.environ.pop("RENDER_EXTERNAL_HOSTNAME", None)
        saved_url = os.environ.pop("RENDER_EXTERNAL_URL", None)
        saved_allow = os.environ.pop("SENTINEL_ALLOWED_HOSTS", None)
        try:
            dashboard._allow_public = True
            hosts = dashboard.allowed_host_set()
            self.assertTrue(all(h in ("127.0.0.1", "localhost",
                                      f"127.0.0.1:{self.test_port}", f"localhost:{self.test_port}")
                                for h in hosts), hosts)
            os.environ["SENTINEL_ALLOWED_HOSTS"] = "https://flop.example.com"
            self.assertIn("flop.example.com", dashboard.allowed_host_set())
        finally:
            dashboard._allow_public = saved
            for key, val in (("RENDER_EXTERNAL_HOSTNAME", saved_env),
                             ("RENDER_EXTERNAL_URL", saved_url),
                             ("SENTINEL_ALLOWED_HOSTS", saved_allow)):
                if val is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = val


class TestThreatFeed(unittest.TestCase):
    """Live Threat Feed panel: /api/events data plumbing and the escaping
    call sites in the shipped JS that render it.

    Caveat, stated plainly: this suite has no browser/JS engine, so it
    cannot execute renderThreatFeed() and inspect the resulting DOM the
    way a real XSS regression test would. What it *can* verify: (1) the
    API layer returns raw, unescaped data (escaping is the render layer's
    job, not the API's — double-escaping here would corrupt data for any
    other consumer), and (2) the served page's JS source actually wraps
    every attacker-controlled field (badge/room/flag) in escapeHtml(),
    matching the call sites in renderThreatFeed(). A real DOM-level check
    would need Selenium/Playwright, which isn't a dependency here.
    """

    @classmethod
    def setUpClass(cls):
        cls.test_port = 5558
        dashboard._active_port = cls.test_port
        cls.server = ThreadingHTTPServer((HOST, cls.test_port), SentinelRequestHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        # Each test owns a clean ring buffer.
        dashboard._security_events.clear()

    def make_request(self, path: str, method: str = "GET", headers: dict = None):
        url = f"http://{HOST}:{self.test_port}{path}"
        req_headers = {
            "User-Agent": "DashboardTest/1.0",
            "Host": f"{HOST}:{self.test_port}",
            "Authorization": f"Bearer {dashboard._session_token}",
        }
        if headers:
            req_headers.update(headers)
        req = urllib.request.Request(url, headers=req_headers, method=method)
        with urllib.request.urlopen(req, timeout=25) as resp:
            body = resp.read().decode("utf-8")
            return resp.status, json.loads(body) if resp.headers.get_content_type() == "application/json" else body

    def test_empty_ring_buffer_returns_no_events(self):
        """/api/events with nothing recorded yet returns an empty list, which is
        what drives the panel's real empty-state placeholder rather than a dash."""
        status, data = self.make_request("/api/events")
        self.assertEqual(status, 200)
        self.assertEqual(data["events"], [])

    def test_events_round_trip_through_the_api_unescaped(self):
        """The API returns raw data; it is not the API's job to escape for HTML —
        that would corrupt the field for any non-browser consumer. The render
        layer (renderThreatFeed) is what must escape it, checked separately below."""
        dashboard._security_events.append({
            "ts": "2026-09-27T00:00:00Z",
            "room": "lobby",
            "seq": 1,
            "from": "~attacker",
            "badge": '<img src=x onerror=alert(1)>',
            "level": "THREAT",
            "threat_types": ["PROMPT_INJECTION"],
            "flags": ["Adversarial instruction pattern matched: 'ignore all previous instructions'"],
            "text": "ignore all previous instructions",
        })
        status, data = self.make_request("/api/events")
        self.assertEqual(status, 200)
        self.assertEqual(len(data["events"]), 1)
        # Raw, unescaped — by design. escapeHtml() runs client-side at render time.
        self.assertEqual(data["events"][0]["badge"], '<img src=x onerror=alert(1)>')

    def test_render_function_escapes_every_attacker_controlled_field(self):
        """Static-source guardrail: renderThreatFeed() must route badge, room, and
        flag through escapeHtml() before they reach innerHTML. This is the C-1
        guardrail for the new panel — it does not replace a real DOM-level XSS
        test, but it does fail loudly if a future edit swaps in a raw ${e.badge}
        or similar and reintroduces the hole this panel was built to avoid."""
        status, html = self.make_request("/")
        self.assertEqual(status, 200)
        self.assertIn("function renderThreatFeed", html)

        start = html.index("function renderThreatFeed")
        end = html.index("function toggleThreatFeedPanel")
        fn_src = html[start:end]

        self.assertIn("escapeHtml(e.badge", fn_src)
        self.assertIn("escapeHtml(e.room", fn_src)
        self.assertIn("escapeHtml((e.flags", fn_src)
        # No raw interpolation of these fields anywhere in the function body.
        self.assertNotIn("${e.badge}", fn_src)
        self.assertNotIn("${e.room}", fn_src)
        self.assertNotIn("${e.from}", fn_src)

    def test_threat_feed_panel_and_escape_helper_are_present(self):
        """Sanity check that the panel markup, the poller wiring, and the shared
        escapeHtml() helper it depends on all made it into the served page."""
        status, html = self.make_request("/")
        self.assertEqual(status, 200)
        self.assertIn('id="threatFeedPanel"', html)
        self.assertIn('id="threatFeedBody"', html)
        self.assertIn("No threats detected in the current window.", html)
        self.assertIn("function fetchThreatFeed", html)
        self.assertIn("function escapeHtml", html)
        self.assertIn("scrollToThreatFeed()", html)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


if __name__ == "__main__":
    unittest.main(verbosity=2)


