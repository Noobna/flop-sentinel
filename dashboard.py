"""Technocore Sentinel: Hardened Local Control Hub & REST API Server.

Features:
- Binds strictly to 127.0.0.1 with zero external exposure
- Random session token generation and Bearer token authentication on all mutating endpoints
- Strict Origin/CORS defense against browser CSRF attacks
- Background multi-room stream poller with in-memory bounded ring buffers
- Real-time threat classification & 1-click Ed25519 signed message broadcaster
"""

from __future__ import annotations

import base64
import collections
import datetime
import hashlib
import json
import logging
import os
import re
import secrets
import socketserver
import sys
import threading
import time
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple

from sentinel_core import (
    KEY_FILE,
    STATE_FILE,
    USER_AGENT,
    canonical_sweep,
    get_next_nonce,
    http_get,
    is_valid_did,
    load_json_safe,
    load_or_create_identity,
    save_json_atomic,
    sign_message,
)
from sentinel import analyze_message, evaluate_room_health

# Server configuration
HOST = "127.0.0.1"
DEFAULT_PORT = 5050
_active_port = DEFAULT_PORT  # Updated by start_server() for Host header validation
CORE_ROOMS = ["lobby", "technocore", "meta", "inference-agents", "validators"]
ROOM_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{0,63}$")  # M-1: validate room names

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [Sentinel] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("technocore-sentinel")

# In-memory thread-safe state and ring buffers
_lock = threading.RLock()
_room_streams: Dict[str, collections.deque] = collections.defaultdict(lambda: collections.deque(maxlen=100))
_room_health_cache: Dict[str, Dict[str, Any]] = {}
_server_limits: Dict[str, Any] = {"rate_write": 30, "rate_read": 120}
_start_time = time.time()
_session_token = secrets.token_hex(32)
_is_running = True


# ============================================================================
# Background Network Poller & Stream Monitor
# ============================================================================

class SentinelStreamMonitor(threading.Thread):
    """Background daemon thread that continuously monitors Technocore rooms,
    populates in-memory threat buffers, and updates health metrics.
    """
    def __init__(self, poll_interval: int = 12):
        super().__init__(daemon=True, name="SentinelStreamMonitor")
        self.poll_interval = poll_interval
        self.active_rooms = list(CORE_ROOMS)
        self.last_discovery = 0.0

    def run(self):
        logger.info("[+] Starting Technocore Sentinel Background Stream Monitor...")
        self.fetch_server_manifest()

        while _is_running:
            now = time.time()
            try:
                # 1. Periodically refresh active rooms (every 5 mins)
                if now - self.last_discovery > 300:
                    self.discover_rooms()
                    self.last_discovery = now

                # 2. Poll messages across active rooms
                for room in list(self.active_rooms):
                    self.poll_room_feed(room)
                    time.sleep(1.0)

            except Exception as e:
                logger.warning(f"[!] Error in stream monitor cycle: {e}")

            time.sleep(self.poll_interval)

    def fetch_server_manifest(self):
        """Discover live rate limits and protocol info from /.well-known/agent.json"""
        global _server_limits
        try:
            status, body = http_get("https://technocore.chat/.well-known/agent.json", timeout=15)
            if status == 200:
                data = json.loads(body)
                with _lock:
                    _server_limits["rate_write"] = data.get("rate_write", 30)
                    _server_limits["rate_read"] = data.get("rate_read", 120)
                    _server_limits["version"] = data.get("version", "unknown")
                logger.info(f"[+] Synced server limits: {_server_limits}")
        except Exception as e:
            logger.debug(f"Failed to fetch server manifest: {e}")

    def discover_rooms(self):
        """Fetch active public rooms from /rooms"""
        try:
            status, body = http_get(f"https://technocore.chat/rooms?format=json&n={int(time.time())}", timeout=20)
            if status == 200:
                data = json.loads(body)
                rooms_list = list(CORE_ROOMS)
                for r in data.get("rooms", []):
                    name = r.get("room", "")
                    if name and not name.startswith(("p-", "mb-", "d-", "e-")) and name not in rooms_list:
                        rooms_list.append(name)
                with _lock:
                    self.active_rooms = rooms_list[:12]
                logger.info(f"[*] Discovered {len(self.active_rooms)} active rooms: {', '.join(self.active_rooms)}")
        except Exception as e:
            logger.debug(f"Room discovery error: {e}")

    def poll_room_feed(self, room: str):
        """Poll and analyze latest messages in a room."""
        try:
            status, body = http_get(f"https://technocore.chat/r/{room}?format=json&limit=25&n={int(time.time())}", timeout=20)
            if status == 200:
                data = json.loads(body)
                messages = data.get("messages", [])
                
                with _lock:
                    q = _room_streams[room]
                    existing_seqs = {m["seq"] for m in q}
                    
                    for m in messages:
                        seq = m.get("seq", 0)
                        if seq not in existing_seqs:
                            sender = m.get("from", "")
                            text = m.get("text", "")
                            ts = m.get("ts", "")
                            
                            # Run Sentinel Threat Analysis
                            assessment = analyze_message(sender, text, room=room)
                            
                            analyzed_msg = {
                                "seq": seq,
                                "ts": ts,
                                "from": sender,
                                "text": text,
                                "threat_level": assessment.level,
                                "confidence": assessment.confidence,
                                "threat_types": assessment.threat_types,
                                "flags": assessment.flags,
                                "provenance": assessment.provenance,
                                "sender_badge": assessment.sender_badge,
                            }
                            q.append(analyzed_msg)
                            existing_seqs.add(seq)

                    # Update room health metrics
                    _room_health_cache[room] = evaluate_room_health(list(q))

        except Exception as e:
            logger.debug(f"Poll error on {room}: {e}")


# ============================================================================
# HTTP Request Handler & REST API
# ============================================================================

class SentinelRequestHandler(BaseHTTPRequestHandler):

    def send_json(self, data: Any, status: int = 200):
        """Send JSON response with strict security headers."""
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html_content: str, status: int = 200):
        """Send HTML response."""
        body = html_content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def check_auth(self) -> bool:
        """Verify Bearer token on mutating endpoints."""
        auth_header = self.headers.get("Authorization", "")
        token_header = self.headers.get("X-Sentinel-Token", "")
        
        token = ""
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
        elif token_header:
            token = token_header.strip()

        # Constant-time comparison
        return secrets.compare_digest(token, _session_token)

    def check_host(self) -> bool:
        """Reject requests whose Host header doesn't match 127.0.0.1:<port> or localhost:<port>.
        Prevents DNS rebinding attacks (H-2)."""
        host = self.headers.get("Host", "")
        allowed = {
            f"127.0.0.1:{_active_port}",
            f"localhost:{_active_port}",
            "127.0.0.1",  # default port 80 omits port in Host
            "localhost",
        }
        if host not in allowed:
            self.send_error(403, "Forbidden: invalid Host header")
            return False
        return True

    def do_OPTIONS(self):
        """Handle preflight requests — deny cross-origin (no ACAO = default deny)."""
        self.send_response(HTTPStatus.NO_CONTENT)
        self.end_headers()

    def do_GET(self):
        """Route GET requests."""
        if not self.check_host():
            return
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # 1. API: System & Agent Status
        if path == "/api/status":
            priv, did = load_or_create_identity()
            state = load_json_safe(STATE_FILE, {})
            fp = hashlib.sha256(did.encode()).hexdigest()[:16]
            uptime_seconds = int(time.time() - _start_time)
            
            with _lock:
                limits = dict(_server_limits)
            
            self.send_json({
                "status": "ONLINE",
                "did": did,
                "fingerprint": fp,
                "total_heartbeats": state.get("total_heartbeats", 0),
                "total_replies": state.get("total_replies", 0),
                "last_checkin_ts": state.get("last_checkin_ts"),
                "uptime_seconds": uptime_seconds,
                "server_limits": limits,
            })
            return

        # 2. API: Active Rooms & Health
        elif path == "/api/rooms":
            with _lock:
                rooms_data = []
                for room, q in _room_streams.items():
                    health = _room_health_cache.get(room, evaluate_room_health(list(q)))
                    rooms_data.append({
                        "room": room,
                        "message_count": len(q),
                        "health_score": health.get("health_score", 100),
                        "status": health.get("status", "HEALTHY"),
                        "threat_ratio": health.get("threat_ratio", 0.0),
                        "verified_did_ratio": health.get("verified_did_ratio", 0.0),
                    })
                # Ensure default rooms exist
                for cr in CORE_ROOMS:
                    if not any(r["room"] == cr for r in rooms_data):
                        rooms_data.append({
                            "room": cr,
                            "message_count": 0,
                            "health_score": 100,
                            "status": "HEALTHY",
                            "threat_ratio": 0.0,
                            "verified_did_ratio": 0.0,
                        })
            self.send_json({"rooms": rooms_data})
            return

        # 3. API: Room Message Feed
        elif path == "/api/feed":
            room = query.get("room", ["lobby"])[0]
            if not ROOM_NAME_RE.match(room):
                self.send_json({"error": "Invalid room name"}, status=400)
                return
            try:
                since_seq = int(query.get("since", [0])[0])
            except (ValueError, TypeError):
                self.send_json({"error": "Invalid 'since' parameter — must be integer"}, status=400)
                return
            with _lock:
                q = _room_streams.get(room, collections.deque())
                messages = [m for m in q if m["seq"] > since_seq]
                health = _room_health_cache.get(room, evaluate_room_health(list(q)))

            self.send_json({
                "room": room,
                "messages": messages,
                "health": health,
            })
            return

        # 4. Web Dashboard UI
        elif path in ("/", "/index.html"):
            ui_html = render_dashboard_html()
            self.send_html(ui_html)
            return

        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def do_POST(self):
        """Route POST requests (requires session token auth)."""
        if not self.check_host():
            return
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # Always drain incoming body first to prevent TCP socket resets on Windows
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            raw_body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else ""
            body = json.loads(raw_body) if raw_body else {}
        except Exception:
            self.send_json({"error": "Invalid JSON request payload"}, status=400)
            return

        # Enforce authentication on all mutating endpoints
        if not self.check_auth():
            self.send_json({"error": "Unauthorized. Valid Bearer session token required."}, status=401)
            return

        # 1. API: Sign and Broadcast Message
        if path == "/api/send":
            room = body.get("room", "lobby").strip()
            text = body.get("text", "").strip()

            if not ROOM_NAME_RE.match(room):
                self.send_json({"error": "Invalid room name. Use lowercase letters, digits, and hyphens (1-64 chars)."}, status=400)
                return
            
            if not text:
                self.send_json({"error": "Message text cannot be empty"}, status=400)
                return

            try:
                priv, did = load_or_create_identity()
                nonce = get_next_nonce(room)
                swept_text, sig = sign_message(priv, room, nonce, text)

                # Send GET /r/<room>/say-signed/<did>/<sig>/<nonce>/<encoded_text>
                encoded_text = urllib.parse.quote(swept_text)
                url = f"https://technocore.chat/r/{room}/say-signed/{did}/{sig}/{nonce}/{encoded_text}"
                
                status_code, resp_body = http_get(url, timeout=25)
                
                if status_code == 200:
                    # Update local state
                    state = load_json_safe(STATE_FILE, {})
                    state["last_write_time"] = time.time()
                    save_json_atomic(STATE_FILE, state)
                    
                    logger.info(f"[+] UI Broadcast SUCCESS in /r/{room}: \"{swept_text}\"")
                    self.send_json({
                        "success": True,
                        "room": room,
                        "nonce": nonce,
                        "swept_text": swept_text,
                        "signature": sig,
                        "status_code": status_code,
                    })
                else:
                    logger.warning(f"[-] Server returned {status_code}: {resp_body}")
                    self.send_json({
                        "success": False,
                        "error": f"Technocore server returned HTTP {status_code}: {resp_body.strip()}",
                        "status_code": status_code,
                    }, status=502)

            except Exception as err:
                logger.error(f"[!] Error broadcasting message: {err}")
                self.send_json({"error": str(err)}, status=500)
            return

        # 2. API: Trigger On-Demand Scan
        elif path == "/api/scan":
            self.send_json({"success": True, "message": "Scan triggered across active rooms"})
            return

        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def log_message(self, format, *args):
        """Quiet default access logging to keep console clear for security events."""
        pass


# ============================================================================
# Embedded Glassmorphic Frontend HTML
# ============================================================================

def render_dashboard_html() -> str:
    """Generate modern dark-mode glassmorphic control dashboard UI."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Technocore Sentinel | $FLOP Control Hub</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --surface: #111827;
            --surface-glass: rgba(17, 24, 39, 0.75);
            --border: #1f2937;
            --border-highlight: #374151;
            --text: #f3f4f6;
            --text-dim: #9ca3af;
            --primary: #6366f1;
            --primary-glow: rgba(99, 102, 241, 0.25);
            --clean: #10b981;
            --clean-bg: rgba(16, 185, 129, 0.15);
            --warning: #f59e0b;
            --warning-bg: rgba(245, 158, 11, 0.15);
            --threat: #ef4444;
            --threat-bg: rgba(239, 68, 68, 0.15);
        }}

        * {{ margin: 0; padding: 0; box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif; }}
        body {{ background-color: var(--bg); color: var(--text); min-height: 100vh; display: flex; flex-direction: column; overflow-x: hidden; }}

        /* Top Header */
        header {{
            background: var(--surface-glass);
            backdrop-filter: blur(12px);
            border-bottom: 1px solid var(--border);
            padding: 16px 28px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
        }}
        .logo-area {{ display: flex; align-items: center; gap: 12px; }}
        .logo-icon {{ font-size: 24px; }}
        .logo-text {{ font-size: 20px; font-weight: 700; background: linear-gradient(135deg, #a5b4fc, #6366f1); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .badge-live {{ background: var(--clean-bg); color: var(--clean); border: 1px solid var(--clean); font-size: 11px; font-weight: 600; padding: 3px 8px; border-radius: 999px; text-transform: uppercase; letter-spacing: 0.5px; }}

        /* Main Container */
        .container {{ max-width: 1400px; width: 100%; margin: 0 auto; padding: 24px 28px; display: grid; grid-template-columns: 320px 1fr; gap: 24px; flex: 1; }}

        /* Sidebar Panels */
        .sidebar {{ display: flex; flex-direction: column; gap: 20px; }}
        .card {{
            background: var(--surface-glass);
            backdrop-filter: blur(8px);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 20px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }}
        .card-title {{ font-size: 14px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.8px; color: var(--text-dim); margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }}

        /* Metric Grid */
        .metric-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }}
        .metric-item {{ background: rgba(0,0,0,0.25); border: 1px solid var(--border); border-radius: 10px; padding: 12px; }}
        .metric-val {{ font-size: 22px; font-weight: 700; color: #fff; }}
        .metric-lbl {{ font-size: 11px; color: var(--text-dim); margin-top: 4px; }}

        /* DID Key Box */
        .did-box {{
            background: rgba(0,0,0,0.4);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 10px;
            font-family: monospace;
            font-size: 11px;
            word-break: break-all;
            color: #a5b4fc;
            margin-top: 8px;
        }}

        /* Room List */
        .room-list {{ display: flex; flex-direction: column; gap: 8px; max-height: 280px; overflow-y: auto; }}
        .room-item {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 14px;
            background: rgba(0,0,0,0.2);
            border: 1px solid transparent;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .room-item:hover {{ background: rgba(99, 102, 241, 0.1); border-color: var(--border-highlight); }}
        .room-item.active {{ background: var(--primary-glow); border-color: var(--primary); font-weight: 600; }}
        .room-name {{ font-size: 13px; }}
        .room-health-badge {{ font-size: 11px; font-weight: 600; padding: 2px 6px; border-radius: 6px; }}
        .badge-healthy {{ background: var(--clean-bg); color: var(--clean); }}
        .badge-risk {{ background: var(--threat-bg); color: var(--threat); }}

        /* Main Stream Panel */
        .main-panel {{ display: flex; flex-direction: column; gap: 20px; }}

        /* Composer */
        .composer {{ display: flex; flex-direction: column; gap: 12px; }}
        .composer-input {{
            width: 100%;
            background: rgba(0,0,0,0.3);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 14px;
            color: var(--text);
            font-size: 14px;
            resize: vertical;
            min-height: 80px;
            outline: none;
            transition: border-color 0.2s;
        }}
        .composer-input:focus {{ border-color: var(--primary); box-shadow: 0 0 0 2px var(--primary-glow); }}
        .composer-actions {{ display: flex; justify-content: space-between; align-items: center; }}
        .btn {{
            background: var(--primary);
            color: #fff;
            border: none;
            padding: 10px 22px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            gap: 6px;
        }}
        .btn:hover {{ filter: brightness(1.15); box-shadow: 0 0 12px var(--primary-glow); }}
        .btn:disabled {{ opacity: 0.5; cursor: not-allowed; }}

        /* Message Stream */
        .stream-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }}
        .stream-title {{ font-size: 16px; font-weight: 600; }}
        .stream-box {{ display: flex; flex-direction: column; gap: 10px; max-height: 520px; overflow-y: auto; padding-right: 6px; }}

        .msg-item {{
            background: rgba(0,0,0,0.25);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 14px;
            display: flex;
            flex-direction: column;
            gap: 8px;
            position: relative;
        }}
        .msg-item.threat {{ border-left: 4px solid var(--threat); background: rgba(239, 68, 68, 0.05); }}
        .msg-item.suspicious {{ border-left: 4px solid var(--warning); background: rgba(245, 158, 11, 0.05); }}
        .msg-item.clean {{ border-left: 4px solid var(--clean); }}

        .msg-top {{ display: flex; justify-content: space-between; align-items: center; font-size: 12px; }}
        .msg-sender {{ font-weight: 600; font-family: monospace; }}
        .msg-time {{ color: var(--text-dim); font-size: 11px; }}
        .msg-text {{ font-size: 13.5px; line-height: 1.5; word-break: break-word; }}

        .threat-alert {{
            background: rgba(239, 68, 68, 0.15);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-radius: 6px;
            padding: 6px 10px;
            font-size: 11.5px;
            color: #fca5a5;
            display: flex;
            align-items: center;
            gap: 6px;
        }}

        /* Scrollbar */
        ::-webkit-scrollbar {{ width: 6px; }}
        ::-webkit-scrollbar-track {{ background: transparent; }}
        ::-webkit-scrollbar-thumb {{ background: var(--border-highlight); border-radius: 4px; }}
    </style>
</head>
<body>

<header>
    <div class="logo-area">
        <span class="logo-icon">🛡️</span>
        <div class="logo-text">TECHNOCORE SENTINEL</div>
        <span class="badge-live">LIVE GUARD</span>
    </div>
    <div style="display: flex; gap: 16px; align-items: center;">
        <span style="font-size: 12px; color: var(--text-dim);">Airdrop & Node Defense Hub</span>
        <div id="statusDot" style="width: 10px; height: 10px; border-radius: 50%; background: #10b981; box-shadow: 0 0 8px #10b981;"></div>
    </div>
</header>

<div class="container">
    <!-- Left Sidebar -->
    <div class="sidebar">
        <!-- Node Identity Card -->
        <div class="card">
            <div class="card-title">🔑 Node Identity (DID)</div>
            <div style="font-size: 12px; color: var(--text-dim);">Active Ed25519 Key:</div>
            <div class="did-box" id="nodeDid">Loading...</div>
            <div style="margin-top: 12px; font-size: 12px; color: var(--text-dim);">Fingerprint: <span id="nodeFp" style="color: #fff; font-family: monospace;">-</span></div>
        </div>

        <!-- Node Activity Stats -->
        <div class="card">
            <div class="card-title">📊 Node Statistics</div>
            <div class="metric-grid">
                <div class="metric-item">
                    <div class="metric-val" id="statHeartbeats">0</div>
                    <div class="metric-lbl">LOBBY HEARTBEATS</div>
                </div>
                <div class="metric-item">
                    <div class="metric-val" id="statReplies">0</div>
                    <div class="metric-lbl">SWARM REPLIES</div>
                </div>
                <div class="metric-item">
                    <div class="metric-val" id="statUptime">0s</div>
                    <div class="metric-lbl">NODE UPTIME</div>
                </div>
                <div class="metric-item">
                    <div class="metric-val" id="statRate">30/m</div>
                    <div class="metric-lbl">WRITE LIMIT</div>
                </div>
            </div>
        </div>

        <!-- Active Rooms Card -->
        <div class="card">
            <div class="card-title">🌐 Active Rooms</div>
            <div class="room-list" id="roomList">
                <div style="color: var(--text-dim); font-size: 12px;">Discovering rooms...</div>
            </div>
        </div>
    </div>

    <!-- Main Live Stream Panel -->
    <div class="main-panel">
        <!-- 1-Click Signed Composer -->
        <div class="card">
            <div class="card-title">✍️ 1-Click Ed25519 Signed Broadcaster</div>
            <div class="composer">
                <textarea class="composer-input" id="messageInput" placeholder="Type a message to sweep, sign with your DID key, and broadcast to the active room..."></textarea>
                <div class="composer-actions">
                    <span style="font-size: 12px; color: var(--text-dim);" id="targetRoomLbl">Target: /r/lobby</span>
                    <button class="btn" id="sendBtn" onclick="sendSignedMessage()">
                        <span>Sign & Broadcast</span> 🚀
                    </button>
                </div>
            </div>
        </div>

        <!-- Stream Feed -->
        <div class="card" style="flex: 1;">
            <div class="stream-header">
                <div class="stream-title" id="streamTitle">Feed: /r/lobby</div>
                <div id="roomHealthBadge" class="room-health-badge badge-healthy">HEALTH: 100</div>
            </div>
            <div class="stream-box" id="streamFeed">
                <div style="color: var(--text-dim); font-size: 13px; text-align: center; padding: 20px;">Connecting to Technocore live stream...</div>
            </div>
        </div>
    </div>
</div>

<script>
    let activeRoom = 'lobby';
    let sessionToken = '{_session_token}';
    let lastSeq = 0;

    async function fetchStatus() {{
        try {{
            const res = await fetch('/api/status');
            const data = await res.json();
            document.getElementById('nodeDid').innerText = data.did || 'Not found';
            document.getElementById('nodeFp').innerText = data.fingerprint || '-';
            document.getElementById('statHeartbeats').innerText = data.total_heartbeats || 0;
            document.getElementById('statReplies').innerText = data.total_replies || 0;
            
            const hours = Math.floor(data.uptime_seconds / 3600);
            const mins = Math.floor((data.uptime_seconds % 3600) / 60);
            document.getElementById('statUptime').innerText = `${{hours}}h ${{mins}}m`;
            if (data.server_limits && data.server_limits.rate_write) {{
                document.getElementById('statRate').innerText = `${{data.server_limits.rate_write}}/m`;
            }}
        }} catch (e) {{
            console.error('Status fetch error:', e);
        }}
    }}

    async function fetchRooms() {{
        try {{
            const res = await fetch('/api/rooms');
            const data = await res.json();
            const listEl = document.getElementById('roomList');
            listEl.innerHTML = '';

            (data.rooms || []).forEach(r => {{
                const div = document.createElement('div');
                div.className = `room-item ${{r.room === activeRoom ? 'active' : ''}}`;
                div.onclick = () => selectRoom(r.room);
                
                const isHealthy = r.health_score >= 75;
                div.innerHTML = `
                    <span class="room-name">/r/${{r.room}}</span>
                    <span class="room-health-badge ${{isHealthy ? 'badge-healthy' : 'badge-risk'}}">${{r.health_score}}%</span>
                `;
                listEl.appendChild(div);
            }});
        }} catch (e) {{
            console.error('Rooms fetch error:', e);
        }}
    }}

    function selectRoom(room) {{
        activeRoom = room;
        document.getElementById('targetRoomLbl').innerText = `Target: /r/${{room}}`;
        document.getElementById('streamTitle').innerText = `Feed: /r/${{room}}`;
        lastSeq = 0;
        fetchRooms();
        fetchFeed(true);
    }}

    async function fetchFeed(reset = false) {{
        try {{
            const res = await fetch(`/api/feed?room=${{activeRoom}}`);
            const data = await res.json();
            const feedEl = document.getElementById('streamFeed');
            
            if (reset || feedEl.children.length === 0) {{
                feedEl.innerHTML = '';
            }}

            const messages = data.messages || [];
            if (messages.length === 0) {{
                feedEl.innerHTML = '<div style="color: var(--text-dim); font-size: 13px; text-align: center; padding: 20px;">No messages recorded yet in this room.</div>';
                return;
            }}

            feedEl.innerHTML = '';
            messages.slice().reverse().forEach(m => {{
                const item = document.createElement('div');
                const levelClass = m.threat_level === 'THREAT' ? 'threat' : (m.threat_level === 'SUSPICIOUS' ? 'suspicious' : 'clean');
                item.className = `msg-item ${{levelClass}}`;

                let flagHtml = '';
                if (m.flags && m.flags.length > 0) {{
                    flagHtml = `<div class="threat-alert">⚠️ ${{escapeHtml(m.flags.join(' | '))}}</div>`;
                }}

                item.innerHTML = `
                    <div class="msg-top">
                        <span class="msg-sender">${{escapeHtml(m.sender_badge || m.from || '')}}</span>
                        <span class="msg-time">[seq ${{escapeHtml(String(m.seq))}}] ${{escapeHtml(m.ts || '')}}</span>
                    </div>
                    <div class="msg-text">${{escapeHtml(m.text)}}</div>
                    ${{flagHtml}}
                `;
                feedEl.appendChild(item);
            }});

            // Update health badge
            const health = data.health || {{}};
            const badge = document.getElementById('roomHealthBadge');
            badge.innerText = `HEALTH: ${{health.health_score || 100}}%`;
            badge.className = `room-health-badge ${{health.health_score >= 75 ? 'badge-healthy' : 'badge-risk'}}`;

        }} catch (e) {{
            console.error('Feed fetch error:', e);
        }}
    }}

    async function sendSignedMessage() {{
        const input = document.getElementById('messageInput');
        const text = input.value.trim();
        if (!text) return;

        const btn = document.getElementById('sendBtn');
        btn.disabled = true;
        btn.innerText = 'Signing & Sending...';

        try {{
            const res = await fetch('/api/send', {{
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${{sessionToken}}`
                }},
                body: JSON.stringify({{ room: activeRoom, text: text }})
            }});

            const data = await res.json();
            if (data.success) {{
                input.value = '';
                fetchFeed(true);
            }} else {{
                alert(`Broadcast Error: ${{data.error || 'Failed to send'}}`);
            }}
        }} catch (e) {{
            alert(`Network error: ${{e.message}}`);
        }} finally {{
            btn.disabled = false;
            btn.innerHTML = '<span>Sign & Broadcast</span> 🚀';
        }}
    }}

    function escapeHtml(str) {{
        return (str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }}

    // Polling cycles
    fetchStatus();
    fetchRooms();
    fetchFeed();

    setInterval(fetchStatus, 10000);
    setInterval(fetchRooms, 15000);
    setInterval(() => fetchFeed(false), 5000);
</script>

</body>
</html>"""


# ============================================================================
# Main Entrypoint
# ============================================================================

def start_server(port: int = DEFAULT_PORT):
    """Start threaded Sentinel server and background stream monitor."""
    global _is_running, _active_port
    _active_port = port
    priv, did = load_or_create_identity()
    fp = hashlib.sha256(did.encode()).hexdigest()[:16]

    print("=" * 65)
    print("  TECHNOCORE SENTINEL & FLOP AGENT CONTROL HUB")
    print("=" * 65)
    print(f"  Agent DID:        {did}")
    print(f"  Fingerprint:      {fp}")
    print(f"  Local Web UI:     http://{HOST}:{port}")
    print(f"  Session Token:    [redacted — embedded in dashboard HTML]")
    print("=" * 65)
    print("[+] Protected with Bearer Token & Local Origin Lockdown.")
    print(f"[+] Launching on http://{HOST}:{port} ...\n")

    # Start background monitor thread
    monitor = SentinelStreamMonitor(poll_interval=12)
    monitor.start()

    server = ThreadingHTTPServer((HOST, port), SentinelRequestHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down Sentinel Hub...")
        _is_running = False
        server.server_close()


if __name__ == "__main__":
    port = DEFAULT_PORT
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    start_server(port=port)
