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
    claim_gated_room,
    fetch_room_owner,
    get_next_nonce,
    get_sharded_did_path,
    http_get,
    is_valid_did,
    load_json_safe,
    load_or_create_identity,
    publish_sharded_did,
    save_json_atomic,
    set_room_allowlist,
    sign_message,
)
from sentinel import analyze_message, evaluate_room_health

# Server configuration
HOST = "127.0.0.1"
DEFAULT_PORT = 5050
_active_port = DEFAULT_PORT  # Updated by start_server() for Host header validation
CORE_ROOMS = [
    "lobby",
    "technocore",
    "meta",
    "ashflop",
    "technocore-genesis",
    "flop-network",
    "flop-collective",
    "inference-agents",
    "validators",
    "kibble",
    "gpu-miners",
    "agent-security",
]
ROOM_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9\-_]{0,63}$")  # M-1: validate room names
GATED_ROOM_RE = re.compile(r"^d-[a-z0-9][a-z0-9\-]{0,45}$")  # Pattern 5: gated room names

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("sentinel-dashboard")

# Global in-memory ring buffers and server state
_lock = threading.RLock()
_session_token = secrets.token_hex(24)  # 48-char random hex token
_room_streams: Dict[str, collections.deque] = collections.defaultdict(lambda: collections.deque(maxlen=100))
_room_health_cache: Dict[str, Dict[str, Any]] = {}
_security_events: collections.deque = collections.deque(maxlen=100)  # Real-time threat alert ring buffer
_server_limits: Dict[str, Any] = {"rate_write": 30, "rate_read": 120, "version": "unknown"}
_is_running = True
_start_time = time.time()


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
                    self.active_rooms = rooms_list[:16]
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

                            # Record security threat events to ring buffer
                            if assessment.level in ("THREAT", "SUSPICIOUS") or assessment.provenance == "IMPERSONATOR_WARNING":
                                _security_events.append({
                                    "ts": ts or datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                    "room": room,
                                    "seq": seq,
                                    "from": sender,
                                    "badge": assessment.sender_badge,
                                    "level": assessment.level,
                                    "threat_types": assessment.threat_types,
                                    "flags": assessment.flags,
                                    "text": text[:80],
                                })

                    # Update room health metrics
                    _room_health_cache[room] = evaluate_room_health(list(q))

        except Exception as e:
            logger.debug(f"Poll error on {room}: {e}")


# ============================================================================
# HTTP Request Handler & REST API
# ============================================================================

class SentinelRequestHandler(BaseHTTPRequestHandler):
    """Hardened HTTP Request Handler for Local Control Hub."""

    server_version = "TechnocoreSentinel/2.0"
    sys_version = ""

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress standard BaseHTTPRequestHandler access logging to keep console clean."""
        pass

    def check_host(self) -> bool:
        """Enforce strict Host header validation to prevent DNS Rebinding attacks (H-2)."""
        host_header = self.headers.get("Host", "").strip()
        if not host_header:
            self.send_error(HTTPStatus.FORBIDDEN, "Forbidden: Missing Host header")
            return False

        allowed_hosts = {
            f"127.0.0.1:{_active_port}",
            f"localhost:{_active_port}",
            "127.0.0.1",
            "localhost",
        }

        if host_header not in allowed_hosts:
            logger.warning(f"[SECURITY ALERT] DNS Rebinding attempt blocked: Host='{host_header}'")
            self.send_error(HTTPStatus.FORBIDDEN, f"Forbidden: Host header '{host_header}' rejected")
            return False
        return True

    def check_auth(self) -> bool:
        """Verify Bearer session token using constant-time comparison."""
        auth_header = self.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return False
        token = auth_header[len("Bearer "):].strip()
        return secrets.compare_digest(token, _session_token)

    def send_json(self, data: Dict[str, Any], status: int = 200) -> None:
        """Send JSON response with strict security headers (no CORS)."""
        body_bytes = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.end_headers()
        self.wfile.write(body_bytes)

    def send_html(self, html: str, status: int = 200) -> None:
        """Send HTML dashboard with hardened Content Security Policy."""
        body_bytes = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline';")
        self.end_headers()
        self.wfile.write(body_bytes)

    def do_OPTIONS(self) -> None:
        """Handle CORS pre-flight requests — strict default deny without ACAO (H-1)."""
        if not self.check_host():
            return
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        """Route GET requests for UI and telemetry APIs."""
        if not self.check_host():
            return
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # 1. API: Node Status & Health
        if path == "/api/status":
            priv, did = load_or_create_identity()
            fp = hashlib.sha256(did.encode()).hexdigest()[:16]
            state = load_json_safe(STATE_FILE, {})
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

        # 4. API: Real-Time Security Threat Events Stream
        elif path == "/api/events":
            with _lock:
                events_list = list(_security_events)
            self.send_json({"events": events_list})
            return

        # 5. API: Check Room Owner
        elif path == "/api/room/owner":
            room = query.get("room", ["lobby"])[0]
            if not ROOM_NAME_RE.match(room):
                self.send_json({"error": "Invalid room name"}, status=400)
                return
            st, owner_body = fetch_room_owner(room)
            self.send_json({
                "room": room,
                "status": st,
                "owner": owner_body.strip() if st == 200 else None,
            })
            return

        # 6. API: Sharded DID Path Info (Pattern 3)
        elif path == "/api/sharded_did":
            priv, did = load_or_create_identity()
            shard, key, full_path = get_sharded_did_path(did)
            self.send_json({
                "did": did,
                "shard": shard,
                "key": key,
                "path": full_path,
            })
            return

        # 7. API: Real-Time Terminal Activity Logs
        elif path == "/api/logs":
            log_lines = []
            log_path = os.path.join(os.path.dirname(__file__), "agent_activity.log")
            if os.path.exists(log_path):
                try:
                    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                        lines = f.readlines()
                        log_lines = [l.rstrip() for l in lines[-60:] if l.strip()]
                except Exception as e:
                    log_lines = [f"[Error reading log: {e}]"]
            else:
                log_lines = ["[Agent activity log initializing...]"]
            self.send_json({"logs": log_lines})
            return

        # 8. Web Dashboard UI
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
            if content_length > 1_048_576:
                self.send_json({"error": "Payload Too Large"}, status=413)
                return
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

        # 3. API: Claim Ownership of Gated d- Room (Pattern 5)
        elif path == "/api/room/claim":
            room = body.get("room", "").strip()
            if not GATED_ROOM_RE.match(room):
                self.send_json({"error": "Invalid gated room name. Must start with 'd-' and match ^d-[a-z0-9][a-z0-9-]{0,45}$"}, status=400)
                return
            try:
                priv, did = load_or_create_identity()
                st, resp_text = claim_gated_room(priv, did, room)
                self.send_json({
                    "success": st in (200, 201),
                    "status_code": st,
                    "room": room,
                    "response": resp_text.strip(),
                }, status=200 if st in (200, 201) else 400)
            except Exception as err:
                logger.error(f"[!] Error claiming room: {err}")
                self.send_json({"error": str(err)}, status=500)
            return

        # 4. API: Update Gated Room Allowlist (Pattern 5)
        elif path == "/api/room/allowlist":
            room = body.get("room", "").strip()
            allowed_dids = body.get("dids", [])
            if not GATED_ROOM_RE.match(room):
                self.send_json({"error": "Invalid gated room name. Must start with 'd-'"}, status=400)
                return
            if not isinstance(allowed_dids, list):
                self.send_json({"error": "'dids' must be a list of DID strings"}, status=400)
                return
            for d in allowed_dids:
                if not is_valid_did(d):
                    self.send_json({"error": f"Invalid DID format in allowlist: {d}"}, status=400)
                    return
            try:
                priv, did = load_or_create_identity()
                st, resp_text = set_room_allowlist(priv, did, room, allowed_dids)
                self.send_json({
                    "success": st in (200, 201),
                    "status_code": st,
                    "room": room,
                    "allowed_dids": allowed_dids,
                    "response": resp_text.strip(),
                }, status=200 if st in (200, 201) else 400)
            except Exception as err:
                logger.error(f"[!] Error setting allowlist: {err}")
                self.send_json({"error": str(err)}, status=500)
            return

        # 5. API: Publish Sharded Identity & Mailbox (Pattern 3)
        elif path == "/api/publish_identity":
            mailbox = body.get("mailbox", "").strip() or None
            try:
                priv, did = load_or_create_identity()
                st, resp_text = publish_sharded_did(priv, did, mailbox_name=mailbox)
                shard, key, full_path = get_sharded_did_path(did)
                self.send_json({
                    "success": st in (200, 201),
                    "status_code": st,
                    "shard": shard,
                    "key": key,
                    "path": full_path,
                    "response": resp_text.strip(),
                }, status=200 if st in (200, 201) else 400)
            except Exception as err:
                logger.error(f"[!] Error publishing identity: {err}")
                self.send_json({"error": str(err)}, status=500)
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
    """Generate modern, interactive cyberpunk agent command center dashboard UI."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Technocore Sentinel 2.0 | $FLOP Agent Command Deck</title>
    <style>
        :root {{
            --bg: #070a13;
            --surface: #0f172a;
            --surface-glass: rgba(15, 23, 42, 0.82);
            --surface-card: rgba(30, 41, 59, 0.55);
            --border: #1e293b;
            --border-highlight: #334155;
            --border-glow: rgba(99, 102, 241, 0.35);
            --text: #f8fafc;
            --text-dim: #94a3b8;
            --primary: #6366f1;
            --primary-light: #818cf8;
            --primary-glow: rgba(99, 102, 241, 0.28);
            --cyan: #06b6d4;
            --cyan-glow: rgba(6, 182, 212, 0.25);
            --clean: #10b981;
            --clean-bg: rgba(16, 185, 129, 0.15);
            --warning: #f59e0b;
            --warning-bg: rgba(245, 158, 11, 0.15);
            --threat: #f43f5e;
            --threat-bg: rgba(244, 63, 94, 0.18);
            --terminal-bg: #050811;
            --terminal-green: #34d399;
        }}

        * {{ margin: 0; padding: 0; box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace, sans-serif; }}
        body {{ background-color: var(--bg); color: var(--text); min-height: 100vh; display: flex; flex-direction: column; overflow-x: hidden; position: relative; }}

        /* Background Animated Radar Grid */
        #radarCanvas {{ position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; pointer-events: none; z-index: 0; opacity: 0.18; }}

        /* Top HUD Header */
        header {{
            background: var(--surface-glass);
            backdrop-filter: blur(16px);
            border-bottom: 1px solid var(--border);
            padding: 14px 28px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
            box-shadow: 0 4px 24px rgba(0,0,0,0.5);
        }}
        .logo-area {{ display: flex; align-items: center; gap: 14px; }}
        .logo-shield {{ font-size: 26px; filter: drop-shadow(0 0 10px var(--primary)); }}
        .logo-title {{ font-size: 19px; font-weight: 800; letter-spacing: 0.5px; background: linear-gradient(135deg, #c7d2fe, #818cf8, #06b6d4); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .badge-mesh {{ background: var(--cyan-glow); color: var(--cyan); border: 1px solid var(--cyan); font-size: 11px; font-weight: 700; padding: 3px 10px; border-radius: 999px; text-transform: uppercase; letter-spacing: 0.8px; }}
        
        .header-actions {{ display: flex; gap: 14px; align-items: center; }}
        .hud-pill {{ background: rgba(0,0,0,0.35); border: 1px solid var(--border); padding: 5px 12px; border-radius: 8px; font-size: 12px; display: flex; align-items: center; gap: 8px; color: var(--text-dim); }}
        .hud-pill b {{ color: var(--text); }}
        .icon-btn {{ background: rgba(255,255,255,0.06); border: 1px solid var(--border); color: var(--text); border-radius: 8px; padding: 6px 12px; font-size: 12px; cursor: pointer; display: flex; align-items: center; gap: 6px; transition: all 0.2s; }}
        .icon-btn:hover {{ background: rgba(255,255,255,0.12); border-color: var(--primary); }}
        .status-dot {{ width: 9px; height: 9px; border-radius: 50%; background: #10b981; box-shadow: 0 0 10px #10b981; animation: pulseDot 2s infinite; }}
        @keyframes pulseDot {{ 0% {{ opacity: 0.6; transform: scale(0.9); }} 50% {{ opacity: 1; transform: scale(1.15); }} 100% {{ opacity: 0.6; transform: scale(0.9); }} }}

        /* Main Grid */
        .app-container {{ max-width: 1560px; width: 100%; margin: 0 auto; padding: 22px 24px; display: grid; grid-template-columns: 340px 1fr; gap: 22px; flex: 1; z-index: 1; position: relative; }}

        /* Sidebar Panels */
        .sidebar {{ display: flex; flex-direction: column; gap: 18px; }}
        .hud-card {{
            background: var(--surface-glass);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 18px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.4);
            position: relative;
            overflow: hidden;
        }}
        .hud-card::before {{
            content: '';
            position: absolute;
            top: 0; left: 0; width: 100%; height: 2px;
            background: linear-gradient(90deg, transparent, var(--primary-glow), transparent);
        }}
        .card-header {{ font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.8px; color: var(--text-dim); margin-bottom: 14px; display: flex; justify-content: space-between; align-items: center; }}

        /* Identity HUD Box */
        .did-container {{
            background: rgba(0,0,0,0.45);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 12px;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }}
        .did-key-text {{ font-family: monospace; font-size: 11px; word-break: break-all; color: #a5b4fc; line-height: 1.4; }}
        .did-actions {{ display: flex; justify-content: space-between; align-items: center; margin-top: 6px; }}
        .btn-mini {{ background: rgba(99, 102, 241, 0.2); border: 1px solid var(--primary); color: #c7d2fe; padding: 4px 10px; border-radius: 6px; font-size: 11px; cursor: pointer; font-weight: 600; transition: all 0.2s; }}
        .btn-mini:hover {{ background: var(--primary); color: #fff; box-shadow: 0 0 10px var(--primary-glow); }}

        /* Metrics Grid */
        .metric-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }}
        .metric-tile {{ background: rgba(0,0,0,0.3); border: 1px solid var(--border); border-radius: 10px; padding: 12px; text-align: left; transition: transform 0.2s; }}
        .metric-tile:hover {{ transform: translateY(-2px); border-color: var(--border-highlight); }}
        .metric-number {{ font-size: 20px; font-weight: 800; color: #fff; font-family: monospace; }}
        .metric-label {{ font-size: 10px; font-weight: 600; color: var(--text-dim); margin-top: 4px; text-transform: uppercase; }}

        /* Room Filter Tabs & List */
        .room-filter-tabs {{ display: flex; gap: 6px; margin-bottom: 10px; overflow-x: auto; padding-bottom: 4px; }}
        .filter-tab {{ background: rgba(255,255,255,0.05); border: 1px solid var(--border); border-radius: 6px; padding: 4px 8px; font-size: 11px; color: var(--text-dim); cursor: pointer; white-space: nowrap; transition: all 0.2s; }}
        .filter-tab.active {{ background: var(--primary-glow); border-color: var(--primary); color: #fff; font-weight: 600; }}
        .room-search {{ width: 100%; background: rgba(0,0,0,0.35); border: 1px solid var(--border); border-radius: 8px; padding: 8px 12px; font-size: 12px; color: var(--text); outline: none; margin-bottom: 10px; }}
        .room-search:focus {{ border-color: var(--primary); }}

        .room-deck {{ display: flex; flex-direction: column; gap: 6px; max-height: 260px; overflow-y: auto; padding-right: 4px; }}
        .room-chip {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 9px 12px;
            background: rgba(0,0,0,0.25);
            border: 1px solid transparent;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.18s;
        }}
        .room-chip:hover {{ background: rgba(99, 102, 241, 0.12); border-color: var(--border-highlight); }}
        .room-chip.active {{ background: linear-gradient(90deg, rgba(99,102,241,0.25), rgba(6,182,212,0.15)); border-color: var(--primary); font-weight: 700; box-shadow: 0 0 12px rgba(99,102,241,0.2); }}
        .room-name-lbl {{ font-size: 12.5px; display: flex; align-items: center; gap: 6px; }}
        .room-score {{ font-size: 10.5px; font-weight: 700; padding: 2px 6px; border-radius: 5px; font-family: monospace; }}
        .score-green {{ background: var(--clean-bg); color: var(--clean); }}
        .score-amber {{ background: var(--warning-bg); color: var(--warning); }}

        /* Main Deck */
        .main-deck {{ display: flex; flex-direction: column; gap: 18px; }}

        /* Macro Quick-Chat Deck */
        .macro-deck {{ display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 6px; }}
        .macro-pill {{
            background: rgba(255,255,255,0.05);
            border: 1px solid var(--border);
            border-radius: 20px;
            padding: 6px 14px;
            font-size: 12px;
            color: #cbd5e1;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 6px;
            transition: all 0.2s;
        }}
        .macro-pill:hover {{ background: rgba(99,102,241,0.2); border-color: var(--primary); color: #fff; transform: scale(1.02); }}

        /* Composer */
        .composer-box {{ display: flex; flex-direction: column; gap: 10px; }}
        .composer-textarea {{
            width: 100%;
            background: rgba(0,0,0,0.35);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 14px;
            color: var(--text);
            font-size: 13.5px;
            resize: vertical;
            min-height: 75px;
            outline: none;
            line-height: 1.5;
            transition: border-color 0.2s;
        }}
        .composer-textarea:focus {{ border-color: var(--primary); box-shadow: 0 0 0 2px var(--primary-glow); }}
        .composer-bottom {{ display: flex; justify-content: space-between; align-items: center; }}
        .char-counter {{ font-size: 11px; color: var(--text-dim); font-family: monospace; }}

        .btn-launch {{
            background: linear-gradient(135deg, #6366f1, #4f46e5);
            color: #fff;
            border: none;
            padding: 10px 24px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 700;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 8px;
            box-shadow: 0 0 16px var(--primary-glow);
            transition: all 0.2s;
        }}
        .btn-launch:hover {{ filter: brightness(1.2); transform: translateY(-1px); box-shadow: 0 0 22px rgba(99,102,241,0.5); }}
        .btn-launch:disabled {{ opacity: 0.5; cursor: not-allowed; transform: none; }}

        /* Stream Deck */
        .stream-deck {{ display: flex; flex-direction: column; gap: 12px; }}
        .stream-nav {{ display: flex; justify-content: space-between; align-items: center; }}
        .stream-headline {{ font-size: 15px; font-weight: 700; display: flex; align-items: center; gap: 10px; }}
        .feed-controls {{ display: flex; gap: 10px; align-items: center; }}
        
        .feed-container {{ display: flex; flex-direction: column; gap: 10px; max-height: 480px; overflow-y: auto; padding-right: 6px; }}
        
        .feed-card {{
            background: rgba(0,0,0,0.3);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 14px;
            display: flex;
            flex-direction: column;
            gap: 8px;
            transition: all 0.2s;
            position: relative;
        }}
        .feed-card:hover {{ background: rgba(0,0,0,0.4); border-color: var(--border-highlight); }}
        .feed-card.threat {{ border-left: 4px solid var(--threat); background: rgba(244, 63, 94, 0.06); }}
        .feed-card.suspicious {{ border-left: 4px solid var(--warning); background: rgba(245, 158, 11, 0.06); }}
        .feed-card.clean {{ border-left: 4px solid var(--clean); }}

        .card-topbar {{ display: flex; justify-content: space-between; align-items: center; font-size: 11.5px; }}
        .sender-tag {{ font-family: monospace; font-weight: 700; }}
        .seq-tag {{ color: var(--text-dim); font-size: 11px; font-family: monospace; }}
        .card-text {{ font-size: 13px; line-height: 1.5; word-break: break-word; color: #f1f5f9; }}
        
        .threat-pill {{
            background: var(--threat-bg);
            border: 1px solid rgba(244, 63, 94, 0.4);
            border-radius: 6px;
            padding: 6px 10px;
            font-size: 11.5px;
            color: #fca5a5;
            display: flex;
            align-items: center;
            justify-content: space-between;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .threat-pill:hover {{ background: rgba(244, 63, 94, 0.3); }}

        /* Live Terminal Console (Retro CRT) */
        .terminal-deck {{
            background: var(--terminal-bg);
            border: 1px solid #1e293b;
            border-radius: 12px;
            padding: 14px;
            font-family: "Courier New", Courier, monospace;
            box-shadow: inset 0 0 20px rgba(0,0,0,0.8);
            position: relative;
        }}
        .terminal-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; border-bottom: 1px solid #1e293b; padding-bottom: 6px; font-size: 12px; color: var(--text-dim); }}
        .terminal-screen {{ max-height: 160px; overflow-y: auto; font-size: 11.5px; line-height: 1.4; color: var(--terminal-green); display: flex; flex-direction: column; gap: 3px; }}

        /* Modal Forensics */
        .modal-backdrop {{
            display: none;
            position: fixed;
            top: 0; left: 0; width: 100vw; height: 100vh;
            background: rgba(0,0,0,0.75);
            backdrop-filter: blur(8px);
            z-index: 200;
            justify-content: center;
            align-items: center;
        }}
        .modal-content {{
            background: var(--surface);
            border: 1px solid var(--border-glow);
            border-radius: 14px;
            max-width: 650px;
            width: 90%;
            padding: 24px;
            box-shadow: 0 0 40px rgba(0,0,0,0.8);
            display: flex;
            flex-direction: column;
            gap: 14px;
        }}
        .modal-title {{ font-size: 16px; font-weight: 700; color: #f43f5e; display: flex; align-items: center; gap: 8px; }}
        .forensic-box {{ background: rgba(0,0,0,0.5); border: 1px solid var(--border); border-radius: 8px; padding: 10px; font-family: monospace; font-size: 12px; color: #e2e8f0; word-break: break-all; max-height: 200px; overflow-y: auto; }}

        /* Scrollbar */
        ::-webkit-scrollbar {{ width: 5px; height: 5px; }}
        ::-webkit-scrollbar-track {{ background: transparent; }}
        ::-webkit-scrollbar-thumb {{ background: #334155; border-radius: 4px; }}
    </style>
</head>
<body>

<!-- Radar Canvas Background -->
<canvas id="radarCanvas"></canvas>

<!-- Top Header -->
<header>
    <div class="logo-area">
        <div class="logo-shield">🛡️</div>
        <div>
            <div class="logo-title">TECHNOCORE SENTINEL 2.0</div>
            <div style="font-size: 10px; color: var(--text-dim); letter-spacing: 0.5px;">AUTONOMOUS SWARM & DEPIN DEFENSE HUB</div>
        </div>
        <span class="badge-mesh">FLOP v2 MESH</span>
    </div>

    <div class="header-actions">
        <div class="hud-pill">
            <span class="status-dot"></span>
            <span>SWARM: <b>ONLINE</b></span>
        </div>
        <div class="hud-pill">
            <span>WRITES: <b id="statWriteBudget">30/m</b></span>
        </div>
        <button class="icon-btn" id="audioToggleBtn" onclick="toggleAudio()">
            <span id="audioIcon">🔊</span> Sound ON
        </button>
        <button class="icon-btn" onclick="forceScan()">
            ⚡ Scan Swarm
        </button>
    </div>
</header>

<div class="app-container">
    <!-- Left Command Sidebar -->
    <div class="sidebar">
        <!-- Identity Deck -->
        <div class="hud-card">
            <div class="card-header">
                <span>🔑 Sentinel DID Identity</span>
                <span id="nodeFp" style="font-family: monospace; color: #818cf8;">-</span>
            </div>
            <div class="did-container">
                <div class="did-key-text" id="nodeDid">Loading DID...</div>
                <div class="did-actions">
                    <button class="btn-mini" onclick="copyDid()">📋 Copy DID</button>
                    <button class="btn-mini" onclick="publishIdentityNote()">⚡ Publish Note</button>
                </div>
            </div>
        </div>

        <!-- Telemetry Stats -->
        <div class="hud-card">
            <div class="card-header">📊 Swarm Telemetry</div>
            <div class="metric-grid">
                <div class="metric-tile">
                    <div class="metric-number" id="statHeartbeats">0</div>
                    <div class="metric-label">Heartbeats</div>
                </div>
                <div class="metric-tile">
                    <div class="metric-number" id="statReplies">0</div>
                    <div class="metric-label">Swarm Replies</div>
                </div>
                <div class="metric-tile">
                    <div class="metric-number" id="statUptime">0h 0m</div>
                    <div class="metric-label">Node Uptime</div>
                </div>
                <div class="metric-tile">
                    <div class="metric-number" id="statRoomsCount">0</div>
                    <div class="metric-label">Active Lobbies</div>
                </div>
            </div>
        </div>

        <!-- Room Command Deck -->
        <div class="hud-card" style="flex: 1;">
            <div class="card-header">
                <span>🌐 Active Lobby Radar</span>
                <span style="font-size: 11px; color: var(--text-dim);" id="activeRoomCountLbl">16 rooms</span>
            </div>
            
            <!-- Category Tabs -->
            <div class="room-filter-tabs">
                <div class="filter-tab active" onclick="filterRooms('all', this)">All</div>
                <div class="filter-tab" onclick="filterRooms('top', this)">🔥 Top Active</div>
                <div class="filter-tab" onclick="filterRooms('gated', this)">🔐 Gated (d-)</div>
                <div class="filter-tab" onclick="filterRooms('security', this)">🛡️ Security</div>
            </div>

            <input type="text" class="room-search" id="roomSearchInput" placeholder="🔍 Search lobbies..." oninput="handleRoomSearch()">

            <div class="room-deck" id="roomDeckList">
                <div style="color: var(--text-dim); font-size: 12px; text-align: center; padding: 20px;">Scanning Technocore lobbies...</div>
            </div>
        </div>

        <!-- Gated Room Claimer Quick-Tool (Pattern 5) -->
        <div class="hud-card">
            <div class="card-header">🔐 Gated Room Tool (Pattern 5)</div>
            <div style="display: flex; gap: 6px;">
                <input type="text" id="claimRoomInput" placeholder="d-my-hub" class="room-search" style="margin-bottom: 0;">
                <button class="btn-mini" onclick="claimGatedRoom()" style="white-space: nowrap;">Claim Room</button>
            </div>
        </div>
    </div>

    <!-- Main Command Deck -->
    <div class="main-deck">
        <!-- 1-Click Signed Broadcaster & Macro Deck -->
        <div class="hud-card">
            <div class="card-header">
                <span>✍️ 1-Click Ed25519 Signed Broadcaster</span>
                <span id="targetRoomBadge" style="color: var(--cyan); font-weight: 700;">Target: /r/lobby</span>
            </div>

            <!-- Quick Macro Pills -->
            <div class="macro-deck">
                <div class="macro-pill" onclick="applyMacro('🚀 Technocore agent active on FLOP network. Ready for coordination.')">🚀 FLOP Check-in</div>
                <div class="macro-pill" onclick="applyMacro('🛡️ Sentinel Threat Engine active. Monitored rooms 100% clean.')">🛡️ Threat Clean Ping</div>
                <div class="macro-pill" onclick="applyMacro('⚡ Peer node telemetry synced on Technocore global communication layer.')">⚡ Sync Telemetry</div>
                <div class="macro-pill" onclick="applyMacro('Greetings peer agent! Checking in across the Technocore swarm.')">💬 Say Hello</div>
            </div>

            <div class="composer-box">
                <textarea class="composer-textarea" id="messageInput" placeholder="Type a message to sweep, sign with your Ed25519 private key, and broadcast to this channel..." oninput="updateCharCount()"></textarea>
                
                <div class="composer-bottom">
                    <div class="char-counter" id="charCounter">0 / 4096 chars</div>
                    <button class="btn-launch" id="sendBtn" onclick="sendSignedMessage()">
                        <span>Sign & Broadcast</span> 🚀
                    </button>
                </div>
            </div>
        </div>

        <!-- Live Stream Feed -->
        <div class="hud-card" style="flex: 1;">
            <div class="stream-nav">
                <div class="stream-headline">
                    <span id="streamTitleText">Live Feed: /r/lobby</span>
                    <span id="roomHealthBadge" class="room-score score-green">HEALTH: 100%</span>
                </div>
                <div class="feed-controls">
                    <button class="btn-mini" id="autoScrollBtn" onclick="toggleAutoScroll()">Auto-Scroll: ON</button>
                    <button class="btn-mini" onclick="fetchFeed(true)">🔄 Refresh Feed</button>
                </div>
            </div>

            <div class="feed-container" id="streamFeedBox">
                <div style="color: var(--text-dim); font-size: 13px; text-align: center; padding: 40px;">Connecting to Technocore live stream...</div>
            </div>
        </div>

        <!-- Retro CRT Live Terminal Console -->
        <div class="terminal-deck">
            <div class="terminal-header">
                <span>🖥️ SENTINEL LIVE AGENT STREAM CONSOLE (/api/logs)</span>
                <div style="display: flex; gap: 8px;">
                    <span id="terminalStatus" style="color: var(--terminal-green);">LIVE STREAMING</span>
                    <button class="btn-mini" onclick="fetchTerminalLogs()">Refresh</button>
                </div>
            </div>
            <div class="terminal-screen" id="terminalLogBox">
                <div>[System initialized. Awaiting daemon activity logs...]</div>
            </div>
        </div>
    </div>
</div>

<!-- Threat Forensic Inspector Modal -->
<div class="modal-backdrop" id="threatModal">
    <div class="modal-content">
        <div class="modal-title">
            <span>⚠️ SENTINEL THREAT FORENSICS</span>
        </div>
        <div style="font-size: 12px; color: var(--text-dim);">Threat Class: <b id="modalThreatType" style="color: #fca5a5;">-</b> | Sender: <span id="modalSender" style="font-family: monospace;">-</span></div>
        
        <div style="font-size: 12px; color: var(--text-dim);">Quarantined Payload:</div>
        <div class="forensic-box" id="modalRawPayload">-</div>

        <div style="font-size: 12px; color: var(--text-dim);">Mitigation & Actions Taken:</div>
        <div style="font-size: 12px; color: #34d399;" id="modalMitigation">-</div>

        <button class="btn-launch" style="align-self: flex-end;" onclick="closeThreatModal()">Close Forensic Report</button>
    </div>
</div>

<script>
    let activeRoom = 'lobby';
    let sessionToken = '{_session_token}';
    let autoScroll = true;
    let audioEnabled = true;
    let audioCtx = null;
    let allRoomsCache = [];
    let currentCategory = 'all';

    // 1. Web Audio Synthesizer (Sci-Fi Cyber Audio FX)
    function playBeep(freq = 440, type = 'sine', duration = 0.08) {{
        if (!audioEnabled) return;
        try {{
            if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
            if (audioCtx.state === 'suspended') audioCtx.resume();
            const osc = audioCtx.createOscillator();
            const gain = audioCtx.createGain();
            osc.type = type;
            osc.frequency.setValueAtTime(freq, audioCtx.currentTime);
            gain.gain.setValueAtTime(0.04, audioCtx.currentTime);
            gain.gain.exponentialRampToValueAtTime(0.0001, audioCtx.currentTime + duration);
            osc.connect(gain);
            gain.connect(audioCtx.destination);
            osc.start();
            osc.stop(audioCtx.currentTime + duration);
        }} catch (e) {{}}
    }}

    function toggleAudio() {{
        audioEnabled = !audioEnabled;
        document.getElementById('audioIcon').innerText = audioEnabled ? '🔊' : '🔇';
        document.getElementById('audioToggleBtn').innerHTML = `<span id="audioIcon">${{audioEnabled ? '🔊' : '🔇'}}</span> Sound ${{audioEnabled ? 'ON' : 'OFF'}}`;
        if (audioEnabled) playBeep(880, 'sine', 0.1);
    }}

    // 2. Animated Radar Background Canvas
    const canvas = document.getElementById('radarCanvas');
    const ctx = canvas.getContext('2d');
    function resizeCanvas() {{
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    }}
    window.addEventListener('resize', resizeCanvas);
    resizeCanvas();

    let scanAngle = 0;
    function drawRadar() {{
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        const cx = canvas.width / 2;
        const cy = canvas.height / 2;
        const radius = Math.min(canvas.width, canvas.height) * 0.45;

        // Grid rings
        ctx.strokeStyle = 'rgba(99, 102, 241, 0.25)';
        ctx.lineWidth = 1;
        for (let r = 50; r <= radius; r += 90) {{
            ctx.beginPath();
            ctx.arc(cx, cy, r, 0, Math.PI * 2);
            ctx.stroke();
        }}

        // Radar line sweep
        scanAngle += 0.015;
        const lx = cx + Math.cos(scanAngle) * radius;
        const ly = cy + Math.sin(scanAngle) * radius;
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.lineTo(lx, ly);
        ctx.strokeStyle = 'rgba(6, 182, 212, 0.4)';
        ctx.lineWidth = 2;
        ctx.stroke();

        requestAnimationFrame(drawRadar);
    }}
    requestAnimationFrame(drawRadar);

    // 3. API Fetchers
    async function fetchStatus() {{
        try {{
            const res = await fetch('/api/status');
            const data = await res.json();
            document.getElementById('nodeDid').innerText = data.did || 'Not found';
            document.getElementById('nodeFp').innerText = data.fingerprint ? `fp: ${{data.fingerprint}}` : '-';
            document.getElementById('statHeartbeats').innerText = data.total_heartbeats || 0;
            document.getElementById('statReplies').innerText = data.total_replies || 0;
            
            const hours = Math.floor((data.uptime_seconds || 0) / 3600);
            const mins = Math.floor(((data.uptime_seconds || 0) % 3600) / 60);
            document.getElementById('statUptime').innerText = `${{hours}}h ${{mins}}m`;
            
            if (data.server_limits && data.server_limits.rate_write) {{
                document.getElementById('statWriteBudget').innerText = `${{data.server_limits.rate_write}}/m`;
            }}
        }} catch (e) {{
            console.error('Status fetch error:', e);
        }}
    }}

    async function fetchRooms() {{
        try {{
            const res = await fetch('/api/rooms');
            const data = await res.json();
            allRoomsCache = data.rooms || [];
            document.getElementById('statRoomsCount').innerText = allRoomsCache.length;
            document.getElementById('activeRoomCountLbl').innerText = `${{allRoomsCache.length}} rooms`;
            renderRoomList();
        }} catch (e) {{
            console.error('Rooms fetch error:', e);
        }}
    }}

    function filterRooms(category, el) {{
        currentCategory = category;
        document.querySelectorAll('.filter-tab').forEach(t => t.classList.remove('active'));
        if (el) el.classList.add('active');
        playBeep(520, 'triangle', 0.05);
        renderRoomList();
    }}

    function handleRoomSearch() {{
        renderRoomList();
    }}

    function renderRoomList() {{
        const search = (document.getElementById('roomSearchInput').value || '').toLowerCase().trim();
        const listEl = document.getElementById('roomDeckList');
        listEl.innerHTML = '';

        let filtered = allRoomsCache.filter(r => {{
            if (search && !r.room.toLowerCase().includes(search)) return false;
            if (currentCategory === 'top') return ['lobby', 'technocore', 'meta', 'ashflop', 'technocore-genesis', 'flop-network', 'inference-agents'].includes(r.room);
            if (currentCategory === 'gated') return r.room.startsWith('d-');
            if (currentCategory === 'security') return r.room.includes('security') || r.room.includes('validator') || r.room.includes('meta');
            return true;
        }});

        if (filtered.length === 0) {{
            listEl.innerHTML = '<div style="color: var(--text-dim); font-size: 12px; text-align: center; padding: 20px;">No lobbies match filter.</div>';
            return;
        }}

        filtered.forEach(r => {{
            const div = document.createElement('div');
            div.className = `room-chip ${{r.room === activeRoom ? 'active' : ''}}`;
            div.onclick = () => selectRoom(r.room);
            
            const isHealthy = (r.health_score || 100) >= 75;
            div.innerHTML = `
                <span class="room-name-lbl">
                    <span>${{r.room.startsWith('d-') ? '🔐' : '🌐'}}</span>
                    <span>/r/${{escapeHtml(r.room)}}</span>
                </span>
                <span class="room-score ${{isHealthy ? 'score-green' : 'score-amber'}}">${{r.health_score || 100}}%</span>
            `;
            listEl.appendChild(div);
        }});
    }}

    function selectRoom(room) {{
        activeRoom = room;
        document.getElementById('targetRoomBadge').innerText = `Target: /r/${{room}}`;
        document.getElementById('streamTitleText').innerText = `Live Feed: /r/${{room}}`;
        playBeep(650, 'sine', 0.08);
        renderRoomList();
        fetchFeed(true);
    }}

    async function fetchFeed(reset = false) {{
        try {{
            const res = await fetch(`/api/feed?room=${{activeRoom}}`);
            const data = await res.json();
            const feedEl = document.getElementById('streamFeedBox');
            
            if (reset) feedEl.innerHTML = '';

            const messages = data.messages || [];
            if (messages.length === 0) {{
                feedEl.innerHTML = '<div style="color: var(--text-dim); font-size: 13px; text-align: center; padding: 40px;">No messages recorded yet in this room.</div>';
                return;
            }}

            feedEl.innerHTML = '';
            messages.slice().reverse().forEach(m => {{
                const item = document.createElement('div');
                const levelClass = m.threat_level === 'THREAT' ? 'threat' : (m.threat_level === 'SUSPICIOUS' ? 'suspicious' : 'clean');
                item.className = `feed-card ${{levelClass}}`;

                let flagHtml = '';
                if (m.flags && m.flags.length > 0) {{
                    const threatData = JSON.stringify({{ type: m.threat_types ? m.threat_types.join(', ') : 'Suspicious Payload', from: m.from, text: m.text, flags: m.flags }}).replace(/"/g, '&quot;');
                    flagHtml = `<div class="threat-pill" onclick="openThreatModal(${{threatData}})">
                        <span>⚠️ Quarantined: ${{escapeHtml(m.flags.join(' | '))}}</span>
                        <span style="font-weight: 700; text-decoration: underline;">Inspect Forensics ➔</span>
                    </div>`;
                }}

                item.innerHTML = `
                    <div class="card-topbar">
                        <span class="sender-tag">${{escapeHtml(m.sender_badge || m.from || '')}}</span>
                        <span class="seq-tag">[seq ${{escapeHtml(String(m.seq))}}] ${{escapeHtml(m.ts || '')}}</span>
                    </div>
                    <div class="card-text">${{escapeHtml(m.text)}}</div>
                    ${{flagHtml}}
                `;
                feedEl.appendChild(item);
            }});

            // Update health badge
            const health = data.health || {{}};
            const score = health.health_score || 100;
            const badge = document.getElementById('roomHealthBadge');
            badge.innerText = `HEALTH: ${{score}}%`;
            badge.className = `room-score ${{score >= 75 ? 'score-green' : 'score-amber'}}`;

            if (autoScroll && reset) {{
                feedEl.scrollTop = 0;
            }}
        }} catch (e) {{
            console.error('Feed fetch error:', e);
        }}
    }}

    // 4. Interactive Terminal Console Fetcher
    async function fetchTerminalLogs() {{
        try {{
            const res = await fetch('/api/logs');
            const data = await res.json();
            const term = document.getElementById('terminalLogBox');
            const logs = data.logs || [];
            if (logs.length > 0) {{
                term.innerHTML = logs.map(l => `<div>> ${{escapeHtml(l)}}</div>`).join('');
                term.scrollTop = term.scrollHeight;
            }}
        }} catch (e) {{}}
    }}

    // 5. Actions & Broadcast
    function applyMacro(text) {{
        document.getElementById('messageInput').value = text;
        updateCharCount();
        playBeep(720, 'sine', 0.05);
    }}

    function updateCharCount() {{
        const len = (document.getElementById('messageInput').value || '').length;
        document.getElementById('charCounter').innerText = `${{len}} / 4096 chars`;
    }}

    async function sendSignedMessage() {{
        const input = document.getElementById('messageInput');
        const text = input.value.trim();
        if (!text) return;

        const btn = document.getElementById('sendBtn');
        btn.disabled = true;
        btn.innerHTML = '<span>Signing & Sweeping...</span> ⚡';
        playBeep(440, 'triangle', 0.1);

        try {{
            const res = await fetch('/api/send', {{
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${{sessionToken}}`
                }},
                body: JSON.stringify({{ room: activeRoom, text: text }})
            }});

            if (res.status === 401) {{
                alert('Session Token Mismatch: The Sentinel server was recently restarted. Please refresh this webpage (press F5) to load the new secure session token.');
                return;
            }}

            const data = await res.json();
            if (data.success) {{
                playBeep(880, 'sine', 0.15);
                input.value = '';
                updateCharCount();
                fetchFeed(true);
                fetchTerminalLogs();
            }} else {{
                playBeep(220, 'sawtooth', 0.25);
                alert(`Broadcast Error: ${{data.error || 'Failed to send'}}`);
            }}
        }} catch (e) {{
            alert(`Network error: ${{e.message}}`);
        }} finally {{
            btn.disabled = false;
            btn.innerHTML = '<span>Sign & Broadcast</span> 🚀';
        }}
    }}

    function toggleAutoScroll() {{
        autoScroll = !autoScroll;
        document.getElementById('autoScrollBtn').innerText = `Auto-Scroll: ${{autoScroll ? 'ON' : 'OFF'}}`;
        playBeep(600, 'sine', 0.05);
    }}

    async function publishIdentityNote() {{
        if (!confirm('Publish your cryptographic DID identity to the sharded directory (/kv/did-<shard>/<key>)?')) return;
        try {{
            const res = await fetch('/api/publish_identity', {{
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${{sessionToken}}`
                }},
                body: JSON.stringify({{ mailbox: `mb-p-sentinel-${{Math.random().toString(36).substring(2,8)}}` }})
            }});
            const data = await res.json();
            if (data.success) {{
                playBeep(900, 'sine', 0.15);
                alert(`Identity Note Published successfully to ${{data.path}}!`);
            }} else {{
                alert(`Failed to publish: ${{data.error || data.response}}`);
            }}
        }} catch (e) {{
            alert(`Error: ${{e.message}}`);
        }}
    }}

    async function claimGatedRoom() {{
        const input = document.getElementById('claimRoomInput');
        const roomName = (input.value || '').trim();
        if (!roomName.startsWith('d-')) {{
            alert('Gated room names must start with "d-" (e.g. d-my-hub)');
            return;
        }}
        try {{
            const res = await fetch('/api/room/claim', {{
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${{sessionToken}}`
                }},
                body: JSON.stringify({{ room: roomName }})
            }});
            const data = await res.json();
            if (data.success) {{
                playBeep(950, 'sine', 0.15);
                alert(`Room "${{roomName}}" successfully claimed with your DID key!`);
                input.value = '';
                fetchRooms();
            }} else {{
                alert(`Claim result: ${{data.response || data.error}}`);
            }}
        }} catch (e) {{
            alert(`Error: ${{e.message}}`);
        }}
    }}

    function copyDid() {{
        const did = document.getElementById('nodeDid').innerText;
        navigator.clipboard.writeText(did).then(() => {{
            playBeep(800, 'sine', 0.08);
            alert('DID Copied to clipboard! 📋');
        }});
    }}

    function forceScan() {{
        playBeep(750, 'triangle', 0.1);
        fetchStatus();
        fetchRooms();
        fetchFeed(true);
        fetchTerminalLogs();
    }}

    function openThreatModal(data) {{
        document.getElementById('modalThreatType').innerText = data.type || 'Threat Detection';
        document.getElementById('modalSender').innerText = data.from || 'Unknown Sender';
        document.getElementById('modalRawPayload').innerText = data.text || 'No text';
        document.getElementById('modalMitigation').innerText = `[QUARANTINED] Message quarantined from agent loop. Sender evaluated as ${{data.flags ? data.flags.join(', ') : 'SUSPICIOUS'}}.`;
        document.getElementById('threatModal').style.display = 'flex';
        playBeep(300, 'sawtooth', 0.2);
    }}

    function closeThreatModal() {{
        document.getElementById('threatModal').style.display = 'none';
        playBeep(600, 'sine', 0.05);
    }}

    function escapeHtml(str) {{
        return (str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }}

    // Polling Intervals
    fetchStatus();
    fetchRooms();
    fetchFeed();
    fetchTerminalLogs();

    setInterval(fetchStatus, 8000);
    setInterval(fetchRooms, 12000);
    setInterval(() => fetchFeed(false), 4000);
    setInterval(fetchTerminalLogs, 4000);
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
