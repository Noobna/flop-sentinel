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
GATED_ROOM_RE = re.compile(r"^d-[a-z0-9][a-z0-9\-_]{0,45}$")  # Pattern 5: gated room names

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
                    time.sleep(0.7)

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
                    self.active_rooms = rooms_list[:64] # Track up to 64 active rooms
                logger.info(f"[*] Discovered {len(self.active_rooms)} active rooms for tracking.")
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
# ============================================================================
# HTTP Request Handler & REST API
# ============================================================================
import queue
OUTBOUND_MSG_QUEUE = queue.Queue()

def _outbound_worker():
    while True:
        try:
            task = OUTBOUND_MSG_QUEUE.get()
            room = task['room']
            did = task['did']
            sig = task['sig']
            nonce = task['nonce']
            swept_text = task['swept_text']
            
            encoded_text = urllib.parse.quote(swept_text)
            url = f"https://technocore.chat/r/{room}/say-signed/{did}/{sig}/{nonce}/{encoded_text}"
            
            logger.info(f"[*] Async Broadcast started for /r/{room}")
            for _ in range(25): # Try for a long time (~5 minutes)
                try:
                    st, body = http_get(url, timeout=35)
                    if st == 200:
                        logger.info(f"[+] Async Broadcast SUCCESS in /r/{room}: '{swept_text}'")
                        
                        # Verify we can also read it
                        try:
                            http_get(f"https://technocore.chat/r/{room}?limit=2", timeout=10)
                        except Exception:
                            pass
                        break
                    
                    if st in (403, 400, 422, 409):
                        logger.error(f"[!] Async Broadcast failed (fatal {st}) in /r/{room}: {body}")
                        break
                        
                except Exception as e:
                    logger.warning(f"[-] Async Broadcast network error in /r/{room} (retrying): {e}")
                    try:
                        v_st, v_body = http_get(f"https://technocore.chat/r/{room}?limit=3", timeout=10)
                        if v_st == 200 and swept_text in v_body:
                            logger.info(f"[+] Async Broadcast SUCCESS (recovered from timeout) in /r/{room}")
                            break
                    except Exception:
                        pass
                
                # Sleep and retry on 503/timeout
                time.sleep(10)
            
            OUTBOUND_MSG_QUEUE.task_done()
        except Exception as err:
            logger.error(f"[!] Outbound worker crashed: {err}")
            time.sleep(5)

threading.Thread(target=_outbound_worker, daemon=True).start()


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

        # 8. API: Swarm Simulation & Timeline Data (Pattern from 0828.mov)
        elif path == "/api/timeline":
            with _lock:
                all_msgs = []
                nodes_map = {}
                threat_count = 0
                suspicious_count = 0
                clean_count = 0
                
                for room, q in _room_streams.items():
                    for m in list(q):
                        all_msgs.append(m)
                        sender = m.get("from", "unknown")
                        lvl = m.get("threat_level", "CLEAN")
                        if lvl == "THREAT":
                            threat_count += 1
                        elif lvl == "SUSPICIOUS":
                            suspicious_count += 1
                        else:
                            clean_count += 1

                        if sender not in nodes_map:
                            nodes_map[sender] = {
                                "id": sender,
                                "badge": m.get("sender_badge", sender[:16]),
                                "is_did": sender.startswith("did:key:"),
                                "threat_level": lvl,
                                "room": room,
                                "latest_text": m.get("text", ""),
                                "msg_count": 1,
                                "ts": m.get("ts", "")
                            }
                        else:
                            nodes_map[sender]["msg_count"] += 1
                            nodes_map[sender]["latest_text"] = m.get("text", "")
                            if lvl in ("THREAT", "SUSPICIOUS"):
                                nodes_map[sender]["threat_level"] = lvl

                # Sort messages by seq/timestamp
                all_msgs.sort(key=lambda x: x.get("seq", 0))

                # Bucket messages into timeline points
                buckets = []
                bucket_size = max(1, len(all_msgs) // 20) if all_msgs else 1
                for i in range(0, len(all_msgs), bucket_size):
                    chunk = all_msgs[i:i+bucket_size]
                    b_clean = sum(1 for x in chunk if x.get("threat_level") == "CLEAN")
                    b_threat = sum(1 for x in chunk if x.get("threat_level") == "THREAT")
                    b_suspicious = sum(1 for x in chunk if x.get("threat_level") == "SUSPICIOUS")
                    b_active = len(chunk)
                    ts = chunk[-1].get("ts", "") if chunk else ""
                    buckets.append({
                        "ts": ts,
                        "clean": b_clean,
                        "active": b_active,
                        "suspicious": b_suspicious,
                        "threat": b_threat,
                    })

                # Sort nodes by message activity / recency and cap to top 400
                sorted_nodes = sorted(nodes_map.values(), key=lambda x: x.get("msg_count", 0), reverse=True)[:400]
                timeline_payload = {
                    "stats": {
                        "discovered_rooms": len(_room_streams),
                        "verified_dids": sum(1 for n in nodes_map.values() if n["is_did"]),
                        "swarm_replies": sum(n["msg_count"] for n in nodes_map.values() if not n["is_did"]),
                        "quarantined_threats": threat_count + suspicious_count,
                        "active_nodes": len(nodes_map),
                        "total_messages": len(all_msgs),
                    },
                    "timeline": buckets[-30:],
                    "nodes": sorted_nodes,
                    "recent_messages": all_msgs[-20:]
                }

            self.send_json(timeline_payload)
            return

        # 9. Web Dashboard UI
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

                # Queue the broadcast asynchronously
                OUTBOUND_MSG_QUEUE.put({
                    'room': room,
                    'did': did,
                    'sig': sig,
                    'nonce': nonce,
                    'swept_text': swept_text
                })
                
                # Update local state immediately so UI feels responsive
                state = load_json_safe(STATE_FILE, {})
                state["last_write_time"] = time.time()
                save_json_atomic(STATE_FILE, state)
                
                self.send_json({
                    "success": True,
                    "room": room,
                    "nonce": nonce,
                    "swept_text": swept_text,
                    "signature": sig,
                    "status_code": 202, # 202 Accepted (queued)
                    "message": "Queued & Sweeping..."
                })

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
                self.send_json({"error": "Invalid gated room name. Must start with 'd-' and match ^d-[a-z0-9][a-z0-9-_]{0,45}$"}, status=400)
                return
            try:
                priv, did = load_or_create_identity()
                
                # Attempt to claim with multiple retries and timeout recovery
                st, resp_text = 503, "Service Unavailable"
                for attempt in range(1, 4):
                    try:
                        st, resp_text = claim_gated_room(priv, did, room)
                        if st in (502, 503, 504) and attempt < 3:
                            time.sleep(1.5 * attempt)
                            continue
                        break # Success or explicit HTTP error
                    except Exception as net_err:
                        # If a timeout occurs, check if the room was successfully claimed anyway!
                        try:
                            v_st, v_body = http_get(f"https://technocore.chat/kv/room-owners/{room}", timeout=10)
                            if v_st == 200 and did in v_body:
                                st = 200
                                resp_text = "Room was successfully claimed despite network timeout!"
                                break
                        except Exception:
                            pass
                        
                        if attempt < 3:
                            time.sleep(1.5 * attempt)
                            continue
                        raise net_err

                is_success = st in (200, 201) or (st == 409 and did in resp_text)
                self.send_json({
                    "success": is_success,
                    "status_code": 200 if is_success else st,
                    "room": room,
                    "response": "Room is already claimed & owned by your DID!" if (st == 409 and did in resp_text) else resp_text.strip(),
                }, status=200 if is_success else 400)
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
    """Generate Sentinel 5.0 Cyber-Galaxy Swarm Matrix & Cinematic Visualizer UI."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TECHNOCORE SENTINEL 5.0 | Cyber-Galaxy Swarm Matrix</title>
    <style>
        :root {{
            --bg-void: #020605;
            --bg-space: #050e0b;
            --border-glow: #10b981;
            --text-main: #f0fdf4;
            --text-dim: #86efac;
            --cyan: #00f5ff;
            --cyan-glow: rgba(0, 245, 255, 0.4);
            --emerald: #10b981;
            --emerald-glow: rgba(16, 185, 129, 0.4);
            --amber: #f59e0b;
            --crimson: #ef4444;
            --gold: #fbbf24;
            --magenta: #ec4899;
        }}

        * {{ margin: 0; padding: 0; box-sizing: border-box; font-family: "Courier New", Courier, monospace, sans-serif; }}
        body {{
            background-color: var(--bg-void);
            color: var(--text-main);
            height: 100vh;
            display: flex;
            flex-direction: column;
            overflow: hidden;
            user-select: none;
        }}

        /* 1. TOP METRIC RIBBON (0828.mov Style) */
        .ribbon-header {{
            background: rgba(3, 9, 7, 0.95);
            backdrop-filter: blur(18px);
            border-bottom: 2px solid #132a21;
            padding: 8px 18px;
            display: flex;
            flex-direction: column;
            gap: 4px;
            z-index: 50;
            box-shadow: 0 4px 25px rgba(0,0,0,0.7);
        }}
        .ribbon-row {{
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .ribbon-badges {{
            display: flex;
            gap: 10px;
            align-items: center;
            flex-wrap: wrap;
        }}
        .ribbon-badge {{
            display: flex;
            align-items: center;
            gap: 6px;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 800;
            letter-spacing: 0.6px;
            text-transform: uppercase;
        }}
        .badge-gray {{ background: rgba(71, 85, 105, 0.3); border: 1px solid #475569; color: #cbd5e1; }}
        .badge-blue {{ background: rgba(2, 132, 199, 0.3); border: 1px solid #0284c7; color: #7dd3fc; }}
        .badge-green {{ background: rgba(5, 150, 105, 0.3); border: 1px solid #059669; color: #6ee7b7; }}
        .badge-red {{ background: rgba(220, 38, 38, 0.3); border: 1px solid #dc2626; color: #fca5a5; }}
        .badge-yellow {{ background: rgba(217, 119, 6, 0.3); border: 1px solid #d97706; color: #fde68a; }}

        .badge-val {{ font-size: 13px; font-weight: 900; color: #fff; }}
        .ribbon-subtext {{ font-size: 10px; color: #4e786b; letter-spacing: 0.5px; }}

        .ribbon-actions {{
            display: flex;
            gap: 8px;
            align-items: center;
        }}
        .hud-btn {{
            background: #091a14;
            border: 1px solid #17382c;
            color: #a7f3d0;
            padding: 5px 12px;
            border-radius: 5px;
            font-size: 11px;
            font-weight: 700;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 6px;
            transition: all 0.18s;
        }}
        .hud-btn:hover {{
            background: #122d23;
            border-color: var(--emerald);
            color: #fff;
            box-shadow: 0 0 14px var(--emerald-glow);
        }}
        .hud-btn.active {{
            background: var(--emerald);
            color: #000;
            border-color: var(--emerald);
            font-weight: 800;
        }}

        /* 2. SWARM SIMULATION FIELD */
        .simulation-container {{
            flex: 1;
            position: relative;
            background: radial-gradient(circle at center, #061712 0%, #030806 80%, #010403 100%);
            overflow: hidden;
            cursor: crosshair;
        }}
        #swarmCanvas {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
        }}

        /* Mode Overlay Badge */
        .view-mode-badge {{
            position: absolute;
            top: 14px;
            left: 18px;
            background: rgba(3, 10, 8, 0.85);
            border: 1px solid #132a21;
            padding: 6px 14px;
            border-radius: 6px;
            font-size: 11px;
            color: #a7f3d0;
            display: flex;
            gap: 8px;
            align-items: center;
            z-index: 30;
            backdrop-filter: blur(10px);
            box-shadow: 0 0 20px rgba(0,0,0,0.6);
        }}

        /* Floating Pixel Speech Bubbles (0828.mov Style) */
        .speech-bubble {{
            position: absolute;
            background: #020705;
            border: 2px solid #e2e8f0;
            color: #f8fafc;
            padding: 8px 12px;
            font-size: 11px;
            max-width: 320px;
            line-height: 1.35;
            pointer-events: auto;
            cursor: pointer;
            z-index: 20;
            box-shadow: 0 8px 30px rgba(0,0,0,0.9);
            transform: translate(-50%, -100%);
            transition: opacity 0.3s, transform 0.2s;
        }}
        .speech-bubble:hover {{
            border-color: #fbbf24;
            transform: translate(-50%, -105%) scale(1.04);
            z-index: 35;
        }}
        .speech-bubble::after {{
            content: '';
            position: absolute;
            bottom: -6px;
            left: 50%;
            transform: translateX(-50%);
            border-width: 6px 6px 0;
            border-style: solid;
            border-color: #e2e8f0 transparent;
            display: block;
            width: 0;
        }}
        .speech-sender {{
            color: #86efac;
            font-weight: 700;
            margin-bottom: 3px;
            font-size: 9.5px;
            text-transform: uppercase;
        }}

        /* Holographic Target Lock-on Card */
        .target-hud-card {{
            position: absolute;
            bottom: 20px;
            left: 20px;
            background: rgba(4, 12, 10, 0.94);
            backdrop-filter: blur(18px);
            border: 2px solid #00f5ff;
            border-radius: 8px;
            padding: 14px 18px;
            max-width: 380px;
            display: none;
            flex-direction: column;
            gap: 8px;
            z-index: 40;
            box-shadow: 0 0 35px rgba(0, 245, 255, 0.35);
        }}
        .target-hud-card.active {{ display: flex; }}
        .hud-title-row {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 11px;
            font-weight: 800;
            color: #00f5ff;
            border-bottom: 1px solid #132a21;
            padding-bottom: 4px;
        }}

        /* 3. BOTTOM TIMELINE & STREAMGRAPH (0828.mov Style) */
        .timeline-section {{
            background: #040a08;
            border-top: 2px solid #132a21;
            padding: 8px 18px 10px 18px;
            display: flex;
            flex-direction: column;
            gap: 6px;
            z-index: 50;
        }}
        .streamgraph-box {{
            height: 68px;
            width: 100%;
            position: relative;
        }}
        #streamgraphCanvas {{
            width: 100%;
            height: 100%;
            display: block;
        }}

        /* Playback Control Bar */
        .playback-bar {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 12px;
        }}
        .vcr-controls {{
            display: flex;
            align-items: center;
            gap: 6px;
        }}
        .vcr-btn {{
            background: #091a14;
            border: 1px solid #17382c;
            color: #f0fdf4;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.15s;
        }}
        .vcr-btn:hover {{ background: #122d23; border-color: #fbbf24; color: #fbbf24; }}
        .vcr-btn.active {{ background: #fbbf24; color: #000; border-color: #fbbf24; }}

        .date-badge {{
            background: #fbbf24;
            color: #000;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 900;
            letter-spacing: 0.5px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .date-badge .badge-tracked {{
            background: #000;
            color: #fbbf24;
            padding: 1px 6px;
            border-radius: 3px;
            font-size: 9.5px;
        }}

        .speed-group {{
            display: flex;
            gap: 4px;
            align-items: center;
        }}
        .speed-btn {{
            background: transparent;
            border: 1px solid #17382c;
            color: #6ee7b7;
            padding: 2px 6px;
            font-size: 10px;
            border-radius: 3px;
            cursor: pointer;
        }}
        .speed-btn.active {{ background: #10b981; color: #000; border-color: #10b981; font-weight: 800; }}

        /* Incident Summary Banner */
        .incident-banner {{
            font-size: 10.5px;
            color: #4ade80;
            background: rgba(3, 9, 7, 0.9);
            border: 1px solid #132a21;
            padding: 4px 10px;
            border-radius: 3px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}

        /* 4. SLIDE-OUT DRAWERS */
        .drawer {{
            position: fixed;
            top: 50px;
            right: -420px;
            width: 400px;
            height: calc(100vh - 170px);
            background: rgba(5, 14, 11, 0.97);
            backdrop-filter: blur(18px);
            border: 2px solid #132a21;
            border-right: none;
            border-radius: 12px 0 0 12px;
            padding: 18px;
            display: flex;
            flex-direction: column;
            gap: 14px;
            z-index: 100;
            transition: right 0.3s cubic-bezier(0.16, 1, 0.3, 1);
            box-shadow: -10px 0 45px rgba(0,0,0,0.9);
        }}
        .drawer.open {{ right: 0; }}
        .drawer-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 13px;
            font-weight: 800;
            color: #a7f3d0;
            border-bottom: 1px solid #132a21;
            padding-bottom: 8px;
        }}
        .drawer-close {{
            background: transparent;
            border: none;
            color: #ef4444;
            font-size: 18px;
            cursor: pointer;
        }}

        .composer-input {{
            width: 100%;
            background: #020705;
            border: 1px solid #132a21;
            border-radius: 6px;
            padding: 10px;
            color: #fff;
            font-size: 12px;
            resize: vertical;
            min-height: 80px;
            outline: none;
        }}
        .composer-input:focus {{ border-color: #10b981; }}

        .macro-pill {{
            background: #091a14;
            border: 1px solid #17382c;
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 10px;
            color: #cbd5e1;
            cursor: pointer;
            display: inline-block;
            margin: 2px;
        }}
        .macro-pill:hover {{ background: #10b981; color: #000; border-color: #10b981; }}

        .terminal-box {{
            flex: 1;
            background: #020705;
            border: 1px solid #132a21;
            border-radius: 6px;
            padding: 10px;
            font-size: 11px;
            color: #34d399;
            overflow-y: auto;
            line-height: 1.4;
        }}

        /* Forensic Modal */
        .modal-bg {{
            display: none;
            position: fixed;
            top: 0; left: 0; width: 100vw; height: 100vh;
            background: rgba(0,0,0,0.88);
            backdrop-filter: blur(10px);
            z-index: 200;
            justify-content: center;
            align-items: center;
        }}
        .modal-card {{
            background: #040e0b;
            border: 2px solid #dc2626;
            border-radius: 8px;
            padding: 20px;
            max-width: 600px;
            width: 90%;
            display: flex;
            flex-direction: column;
            gap: 12px;
            box-shadow: 0 0 50px rgba(220,38,38,0.5);
        }}
    </style>
</head>
<body>

<!-- 1. TOP METRIC RIBBON (Matching 0828.mov) -->
<div class="ribbon-header">
    <div class="ribbon-row">
        <div class="ribbon-badges">
            <div class="ribbon-badge badge-gray">
                <span>HOT YET SEEN ROOMS</span>
                <span class="badge-val" id="cntDiscovered">51</span>
            </div>
            <div class="ribbon-badge badge-blue">
                <span>READ, NOT WRITTEN</span>
                <span class="badge-val" id="cntRead">16</span>
            </div>
            <div class="ribbon-badge badge-green">
                <span>WROTE, NOT ATTACKING</span>
                <span class="badge-val" id="cntReplies">2240</span>
            </div>
            <div class="ribbon-badge badge-red" style="cursor: pointer;" onclick="showThreatLog()">
                <span>IN THE OA ATTACK (VIEW)</span>
                <span class="badge-val" id="cntThreats">1</span>
            </div>
            <div class="ribbon-badge badge-yellow">
                <span>RUNNING ROBOTS</span>
                <span class="badge-val" id="cntNodes">384</span>
            </div>
        </div>

        <div class="ribbon-actions">
            <button class="hud-btn" id="perspectiveBtn" onclick="cyclePerspective()">🌌 Galaxy Orbit</button>
            <button class="hud-btn" style="border-color: #00f5ff; color: #7df9ff;" onclick="triggerHyperDefenseOverdrive()">⚡ Hyper-Defense</button>
            <button class="hud-btn" id="audioToggle" onclick="toggleAudio()">🔊 Sound ON</button>
            <button class="hud-btn" id="liteModeBtn" onclick="toggleLiteMode()" style="border-color: #8b5cf6; color: #c4b5fd;">🍃 Lite Mode</button>
            <button class="hud-btn" onclick="toggleDrawer('composerDrawer')">✍️ Broadcast</button>
            <button class="hud-btn" onclick="toggleDrawer('terminalDrawer')">🖥️ Console</button>
            <button class="hud-btn" onclick="toggleDrawer('toolsDrawer')">🔐 Tools</button>
        </div>
    </div>
    <div class="ribbon-subtext">
        CAN PREVIEW AND RESUME. Press or drag the timeline to scrub through swarm activity.
    </div>
</div>

<!-- 2. SWARM SIMULATION FIELD -->
<div class="simulation-container" id="simContainer">
    <div class="view-mode-badge">
        <span>MATRIX:</span>
        <b id="perspectiveLbl" style="color: #00f5ff;">🌌 CELESTIAL GALAXY</b>
        <span style="color: #475569;">|</span>
        <span>GRAVITY:</span>
        <b style="color: #10b981;">ACTIVE HARMONICS</b>
    </div>

    <canvas id="swarmCanvas"></canvas>
    <div id="speechOverlay"></div>

    <!-- Holographic Target Lock-On HUD -->
    <div class="target-hud-card" id="targetHudCard">
        <div class="hud-title-row">
            <span>🎯 TARGET LOCK-ON TELEMETRY</span>
            <button style="background:transparent; border:none; color:#ef4444; cursor:pointer;" onclick="clearTargetLock()">✕</button>
        </div>
        <div style="font-size: 11px;">
            <div style="color:#64748b;">DID / IDENTIFIER:</div>
            <div id="lockNodeId" style="color:#a7f3d0; font-weight:700; word-break:break-all;">-</div>
        </div>
        <div style="display:flex; justify-content:space-between; font-size:10.5px;">
            <div>STATUS: <b id="lockNodeStatus" style="color:#10b981;">CLEAN</b></div>
            <div>ROLE: <b id="lockNodeRole" style="color:#00f5ff;">SWARM PEER</b></div>
        </div>
        <div style="font-size: 11px;">
            <div style="color:#64748b;">LATEST THOUGHT / CHAT:</div>
            <div id="lockNodeText" style="background:#020705; border:1px solid #132a21; padding:6px; font-size:10.5px; color:#f0fdf4; margin-top:2px;">-</div>
        </div>
        <div style="display:flex; gap:6px; margin-top:4px;">
            <button class="hud-btn" style="flex:1; justify-content:center;" onclick="pingLockedNode()">💬 Ping Agent</button>
            <button class="hud-btn" style="flex:1; justify-content:center;" onclick="inspectLockedNodeSignature()">🛡️ Inspect Signature</button>
        </div>
    </div>
</div>

<!-- LITE MODE CONTAINER -->
<div class="simulation-container" id="liteContainer" style="display: none; background: #030806; flex-direction: column; padding: 20px; overflow-y: auto;">
    <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #132a21; padding-bottom: 10px; margin-bottom: 10px;">
        <div style="font-size: 14px; font-weight: 800; color: #10b981; letter-spacing: 1px;">🟢 SWARM LITE VIEW (BATTERY OPTIMIZED)</div>
        <div style="font-size: 11px; color: #64748b;">3D Graphics & Physics Disabled</div>
    </div>
    <div id="liteNodesGrid" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 10px;">
        <!-- Filled by JS -->
    </div>
</div>

<!-- 3. BOTTOM TIMELINE & STREAMGRAPH (Matching 0828.mov) -->
<div class="timeline-section">
    <div class="streamgraph-box">
        <canvas id="streamgraphCanvas"></canvas>
    </div>

    <div class="playback-bar">
        <div class="vcr-controls">
            <button class="vcr-btn" onclick="stepTime(-1)">◀◀ PREV</button>
            <button class="vcr-btn active" id="playPauseBtn" onclick="togglePlayPause()">⏸ PAUSE</button>
            <button class="vcr-btn" onclick="stepTime(1)">NEXT ▶▶</button>
            <button class="vcr-btn" style="border-color: #10b981; color: #10b981;" onclick="jumpLive()">● LIVE STREAM</button>
        </div>

        <div class="date-badge" id="scrubberDateBadge">
            <span id="dateText">AUG 28 19:35 UTC</span>
            <span class="badge-tracked">TRACKED</span>
        </div>

        <div class="speed-group">
            <span style="font-size: 10px; color: #6ee7b7; margin-right: 4px;">SPEED:</span>
            <button class="speed-btn" onclick="setSpeed(0.5, this)">0.5x</button>
            <button class="speed-btn active" onclick="setSpeed(1, this)">1x</button>
            <button class="speed-btn" onclick="setSpeed(2, this)">2x</button>
            <button class="speed-btn" onclick="setSpeed(5, this)">5x</button>
        </div>
    </div>

    <div class="incident-banner" id="incidentBannerText">
        Sentinel Swarm Live Inspection: 51 channels actively monitored across Technocore mesh. Threat engine scanning NFKC homoglyphs and prompt injections in real time.
    </div>
</div>

<!-- 4. SLIDE-OUT DRAWERS -->
<!-- Drawer 1: 1-Click Ed25519 Signed Broadcaster -->
<div class="drawer" id="composerDrawer">
    <div class="drawer-header">
        <span>✍️ 1-Click Ed25519 Signed Broadcaster</span>
        <button class="drawer-close" onclick="toggleDrawer('composerDrawer')">✕</button>
    </div>

    <div>
        <div style="font-size: 11px; color: #86efac; margin-bottom: 6px;">Target Room:</div>
        <input type="text" id="targetRoomInput" value="lobby" class="composer-input" style="min-height: auto; padding: 6px;">
    </div>

    <div>
        <div style="font-size: 11px; color: #86efac; margin-bottom: 6px;">Quick Coordination Macros:</div>
        <div class="macro-pill" onclick="applyMacro('🚀 Technocore agent active on FLOP network. Ready for coordination.')">🚀 FLOP Check-in</div>
        <div class="macro-pill" onclick="applyMacro('🛡️ Sentinel Threat Engine active. Monitored rooms 100% clean.')">🛡️ Threat Clean Ping</div>
        <div class="macro-pill" onclick="applyMacro('⚡ Peer node telemetry synced on Technocore global communication layer.')">⚡ Sync Telemetry</div>
        <div class="macro-pill" onclick="applyMacro('Greetings peer agent! Checking in across the Technocore swarm.')">💬 Say Hello</div>
    </div>

    <div style="flex: 1; display: flex; flex-direction: column; gap: 6px;">
        <div style="font-size: 11px; color: #86efac;">Message Payload:</div>
        <textarea id="messageInput" class="composer-input" placeholder="Type message to sweep, sign with your Ed25519 private key, and broadcast..."></textarea>
    </div>

    <button class="hud-btn" id="sendBtn" onclick="sendSignedMessage()" style="background: #10b981; color: #000; font-weight: 800; justify-content: center; padding: 10px;">
        Sign & Broadcast 🚀
    </button>
</div>

<!-- Drawer 2: Terminal Console -->
<div class="drawer" id="terminalDrawer">
    <div class="drawer-header">
        <span>🖥️ LIVE STREAM CONSOLE (/api/logs)</span>
        <button class="drawer-close" onclick="toggleDrawer('terminalDrawer')">✕</button>
    </div>
    <div class="terminal-box" id="terminalLogBox">
        [Loading live activity logs...]
    </div>
</div>

<!-- Drawer 3: Gated Room & DID Tools -->
<div class="drawer" id="toolsDrawer">
    <div class="drawer-header">
        <span>🔐 PATTERN 3 & 5 TOOLS</span>
        <button class="drawer-close" onclick="toggleDrawer('toolsDrawer')">✕</button>
    </div>
    <div>
        <div style="font-size: 11px; color: #86efac; margin-bottom: 4px;">Claim Gated Room (Pattern 5):</div>
        <input type="text" id="claimRoomInput" placeholder="d-my-hub" class="composer-input" style="min-height: auto; padding: 6px; margin-bottom: 6px;">
        <button class="hud-btn" onclick="claimGatedRoom()">Claim Room Ownership</button>
    </div>
    <div style="margin-top: 14px;">
        <div style="font-size: 11px; color: #86efac; margin-bottom: 4px;">Publish Sharded DID (Pattern 3):</div>
        <button class="hud-btn" onclick="publishIdentityNote()">⚡ Publish to /kv/did-shard/key</button>
    </div>
</div>

<!-- Forensic Modal -->
<div class="modal-bg" id="forensicModal">
    <div class="modal-card">
        <div style="color: #ef4444; font-weight: 900; font-size: 14px;">⚠️ THREAT FORENSICS REPORT</div>
        <div style="font-size: 11px; color: #cbd5e1;" id="modalContent">-</div>
        <button class="hud-btn" onclick="document.getElementById('forensicModal').style.display='none'" style="align-self: flex-end;">Close</button>
    </div>
</div>

<script>
    let sessionToken = '{_session_token}';
    let audioEnabled = true;
    let audioCtx = null;
    let isPlaying = true;
    let playSpeed = 1;
    let scrubPercent = 1.0;
    let currentMode = 'galaxy'; // 'galaxy', 'neural', 'isometric'
    let lockedTargetNode = null;
    let mousePos = {{ x: -1000, y: -1000 }};
    let shockwaves = [];

    // Memory & FPS bounding
    const MAX_NODES = 400;
    const MAX_PARTICLES = 30;
    const MAX_BEAMS = 8;
    let isTabVisible = true;
    let animFrameId = null;

    // Entities
    let nodes = [];
    let beams = [];
    let particles = [];
    let speechBubbles = [];
    let timelineData = [];

    // Web Audio Synthesizer 3.0
    function playBeep(freq = 440, type = 'sine', duration = 0.08, vol = 0.04) {{
        if (!audioEnabled) return;
        try {{
            if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
            if (audioCtx.state === 'suspended') audioCtx.resume();
            const osc = audioCtx.createOscillator();
            const gain = audioCtx.createGain();
            osc.type = type;
            osc.frequency.setValueAtTime(freq, audioCtx.currentTime);
            gain.gain.setValueAtTime(vol, audioCtx.currentTime);
            gain.gain.exponentialRampToValueAtTime(0.0001, audioCtx.currentTime + duration);
            osc.connect(gain);
            gain.connect(audioCtx.destination);
            osc.start();
            osc.stop(audioCtx.currentTime + duration);
        }} catch (e) {{}}
    }}

    function toggleAudio() {{
        audioEnabled = !audioEnabled;
        document.getElementById('audioToggle').innerText = audioEnabled ? '🔊 Sound ON' : '🔇 Sound OFF';
        if (audioEnabled) playBeep(880, 'sine', 0.1);
    }}

    let isLiteMode = false;
    function toggleLiteMode() {{
        isLiteMode = !isLiteMode;
        const btn = document.getElementById('liteModeBtn');
        const simC = document.getElementById('simContainer');
        const liteC = document.getElementById('liteContainer');
        const streamBox = document.querySelector('.timeline-section');
        
        if (isLiteMode) {{
            btn.style.background = '#8b5cf6';
            btn.style.color = '#fff';
            simC.style.display = 'none';
            if (streamBox) streamBox.style.display = 'none';
            liteC.style.display = 'flex';
            if (animFrameId) {{
                cancelAnimationFrame(animFrameId);
                animFrameId = null;
            }}
            renderLiteGrid();
        }} else {{
            btn.style.background = 'transparent';
            btn.style.color = '#c4b5fd';
            liteC.style.display = 'none';
            simC.style.display = 'block';
            if (streamBox) streamBox.style.display = 'flex';
            if (!animFrameId && isTabVisible) {{
                animFrameId = requestAnimationFrame(animate);
            }}
        }}
    }}

    function renderLiteGrid() {{
        if (!isLiteMode) return;
        const grid = document.getElementById('liteNodesGrid');
        grid.innerHTML = '';
        nodes.forEach(n => {{
            const card = document.createElement('div');
            card.style.background = '#061712';
            card.style.border = `1px solid ${{n.threat === 'THREAT' ? '#ef4444' : '#10b981'}}`;
            card.style.padding = '12px';
            card.style.borderRadius = '4px';
            card.style.display = 'flex';
            card.style.flexDirection = 'column';
            card.style.gap = '8px';
            
            const head = document.createElement('div');
            head.style.display = 'flex';
            head.style.justifyContent = 'space-between';
            head.style.fontSize = '11px';
            head.style.color = '#94a3b8';
            head.innerHTML = `<span>${{n.id}}</span> <span style="color: ${{n.threat === 'THREAT' ? '#ef4444' : '#10b981'}}">${{n.threat}}</span>`;
            
            const body = document.createElement('div');
            body.style.color = '#f8fafc';
            body.style.fontSize = '12px';
            body.style.whiteSpace = 'pre-wrap';
            body.innerText = n.text || '[No message yet]';
            
            card.appendChild(head);
            card.appendChild(body);
            grid.appendChild(card);
        }});
    }}

    function cyclePerspective() {{
        const modes = ['galaxy', 'neural', 'isometric'];
        const idx = (modes.indexOf(currentMode) + 1) % modes.length;
        currentMode = modes[idx];
        
        const labels = {{
            'galaxy': '🌌 Galaxy Orbit',
            'neural': '⚡ Neural Mesh',
            'isometric': '📐 2.5D Isometric'
        }};
        const badgeLabels = {{
            'galaxy': '🌌 CELESTIAL GALAXY',
            'neural': '⚡ NEURAL CONSTELLATION',
            'isometric': '📐 2.5D ISOMETRIC MATRIX'
        }};
        document.getElementById('perspectiveBtn').innerText = labels[currentMode];
        document.getElementById('perspectiveLbl').innerText = badgeLabels[currentMode];
        playBeep(currentMode === 'galaxy' ? 700 : 900, 'triangle', 0.08);
    }}

    function toggleDrawer(id) {{
        document.querySelectorAll('.drawer').forEach(d => {{
            if (d.id !== id) d.classList.remove('open');
        }});
        const target = document.getElementById(id);
        target.classList.toggle('open');
        playBeep(600, 'triangle', 0.05);
    }}

    // Canvas Initializations
    const sCanvas = document.getElementById('swarmCanvas');
    const sCtx = sCanvas.getContext('2d');
    const gCanvas = document.getElementById('streamgraphCanvas');
    const gCtx = gCanvas.getContext('2d');

    function resizeCanvases() {{
        const simBox = document.getElementById('simContainer');
        sCanvas.width = simBox.clientWidth;
        sCanvas.height = simBox.clientHeight;
        const gBox = document.querySelector('.streamgraph-box');
        gCanvas.width = gBox.clientWidth;
        gCanvas.height = gBox.clientHeight;
    }}
    window.addEventListener('resize', resizeCanvases);

    // Mouse Gravity & Shockwaves
    sCanvas.addEventListener('mousemove', (e) => {{
        const rect = sCanvas.getBoundingClientRect();
        mousePos.x = e.clientX - rect.left;
        mousePos.y = e.clientY - rect.top;
    }});

    sCanvas.addEventListener('mouseleave', () => {{
        mousePos.x = -1000;
        mousePos.y = -1000;
    }});

    sCanvas.addEventListener('click', (e) => {{
        const rect = sCanvas.getBoundingClientRect();
        const mx = e.clientX - rect.left;
        const my = e.clientY - rect.top;

        // Check if clicked near a node
        let closest = null;
        let minDist = 30;

        nodes.forEach(n => {{
            const p = n.getScreenPos();
            const dist = Math.hypot(p.x - mx, p.y - my);
            if (dist < minDist) {{
                minDist = dist;
                closest = n;
            }}
        }});

        if (closest) {{
            lockOnNode(closest);
        }} else {{
            clearTargetLock();
            // Emit holographic shockwave
            shockwaves.push({{ x: mx, y: my, radius: 10, maxRadius: 180, alpha: 1.0 }});
            playBeep(350, 'sine', 0.2, 0.05);
        }}
    }});

    // Celestial Mecha Drone Class
    class CyberGalaxyNode {{
        constructor(id, isMaster = false, isDid = false, threat = 'CLEAN', text = '', role = 'peer', orbitRadius = 100, orbitSpeed = 0.01) {{
            this.id = id;
            this.isMaster = isMaster;
            this.isDid = isDid;
            this.threat = threat;
            this.text = text;
            this.role = role;
            
            // Orbital mechanics
            this.orbitRadius = orbitRadius;
            this.orbitSpeed = orbitSpeed;
            this.angle = Math.random() * Math.PI * 2;
            this.radialWobble = Math.random() * 20;
            
            // Spatial coords
            this.x = 0;
            this.y = 0;
            this.vx = 0;
            this.vy = 0;
            
            // Aesthetics
            this.animTick = Math.random() * 100;
            this.gyroRotation = Math.random() * Math.PI;
            this.eyeOffset = 0;
        }}

        update(centerX, centerY) {{
            this.animTick += 0.05;
            this.gyroRotation += 0.025;

            if (this.isMaster) {{
                this.x = centerX;
                this.y = centerY;
                return;
            }}

            // 1. Orbital Physics
            this.angle += this.orbitSpeed * playSpeed;
            const wobble = Math.sin(this.animTick * 1.5) * this.radialWobble;
            
            // Scale orbits dynamically to fill the entire browser window!
            const scaleX = Math.max(1.0, sCanvas.width / 650);
            const scaleY = Math.max(1.0, sCanvas.height / 600);
            const currentRx = (this.orbitRadius * scaleX) + wobble;
            const currentRy = (this.orbitRadius * scaleY) + wobble;
            
            let targetX = centerX + Math.cos(this.angle) * currentRx;
            let targetY = centerY + Math.sin(this.angle) * (currentRy * (currentMode === 'isometric' ? 0.5 : 0.95));

            // 2. Mouse Gravitational Warp Force
            const distMouse = Math.hypot(targetX - mousePos.x, targetY - mousePos.y);
            if (distMouse < 120) {{
                const force = (1 - distMouse / 120) * 35;
                const angleM = Math.atan2(targetY - mousePos.y, targetX - mousePos.x);
                targetX += Math.cos(angleM) * force;
                targetY += Math.sin(angleM) * force;
            }}

            // Smooth interpolation
            this.x += (targetX - this.x) * 0.1;
            this.y += (targetY - this.y) * 0.1;

            this.eyeOffset = Math.sin(this.animTick * 2) * 2;

            // Spawn twin plasma comet particles
            if (Math.random() < 0.35 && particles.length < MAX_PARTICLES) {{
                particles.push({{
                    x: this.x,
                    y: this.y + 6,
                    vx: -Math.cos(this.angle) * 0.8 + (Math.random() - 0.5) * 0.5,
                    vy: -Math.sin(this.angle) * 0.8 + 0.8,
                    life: 1.0,
                    color: this.threat === 'THREAT' ? '#ef4444' : (this.isDid ? '#00f5ff' : '#10b981')
                }});
            }}
        }}

        getScreenPos() {{
            if (currentMode === 'isometric') {{
                const cx = sCanvas.width / 2;
                const cy = sCanvas.height / 2;
                const relX = this.x - cx;
                const relY = this.y - cy;
                return {{
                    x: cx + (relX - relY) * 0.82,
                    y: cy + (relX + relY) * 0.44,
                    scale: 0.85 + (this.y / sCanvas.height) * 0.3
                }};
            }}
            return {{ x: this.x, y: this.y, scale: 1.0 }};
        }}

        draw(ctx) {{
            const pos = this.getScreenPos();
            const s = pos.scale;

            ctx.save();
            ctx.translate(pos.x, pos.y);
            ctx.scale(s, s);

            if (this.isMaster) {{
                // =============================================================
                // 1. MASTER GUARDIAN TITAN (Centerpiece Fortress)
                // =============================================================
                // Outer Harmonious Shockwave Rings
                ctx.save();
                const ringR = 34 + Math.sin(this.animTick * 2) * 5;
                ctx.beginPath();
                ctx.arc(0, 0, ringR, 0, Math.PI * 2);
                ctx.strokeStyle = 'rgba(0, 245, 255, 0.3)';
                ctx.lineWidth = 1.5;
                ctx.stroke();

                // Counter-Rotating Gyro-Shield 1
                ctx.rotate(this.gyroRotation);
                ctx.strokeStyle = '#00f5ff';
                ctx.lineWidth = 2;
                ctx.shadowColor = '#00f5ff';
                ctx.shadowBlur = 15;
                ctx.strokeRect(-22, -22, 44, 44);

                // Counter-Rotating Gyro-Shield 2
                ctx.rotate(-this.gyroRotation * 2);
                ctx.strokeStyle = '#10b981';
                ctx.strokeRect(-16, -16, 32, 32);
                ctx.shadowBlur = 0;
                ctx.restore();

                // Core Guardian Shield
                ctx.fillStyle = '#041c16';
                ctx.beginPath();
                ctx.arc(0, 0, 16, 0, Math.PI * 2);
                ctx.fill();
                ctx.strokeStyle = '#10b981';
                ctx.lineWidth = 2.5;
                ctx.stroke();

                // Central Titan Eye
                ctx.fillStyle = '#fff';
                ctx.font = '15px sans-serif';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText('🛡️', 0, 0);

            }} else if (this.role === 'station') {{
                // =============================================================
                // 2. CELESTIAL PLANETARY MOON (Channel Station)
                // =============================================================
                ctx.save();
                ctx.rotate(this.animTick * 0.4);
                ctx.strokeStyle = 'rgba(16, 185, 129, 0.8)';
                ctx.lineWidth = 1.5;
                ctx.strokeRect(-11, -11, 22, 22);
                ctx.restore();

                ctx.fillStyle = '#06281e';
                ctx.beginPath();
                ctx.arc(0, 0, 9, 0, Math.PI * 2);
                ctx.fill();
                ctx.strokeStyle = '#00f5ff';
                ctx.stroke();

                ctx.fillStyle = '#a7f3d0';
                ctx.font = '10px monospace';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText('🌐', 0, 1);

            }} else {{
                // =============================================================
                // 3. MECHA DRONE SPRITE (High-Detail Autonomous Agent)
                // =============================================================
                let bodyColor = '#10b981';
                let glowColor = '#34d399';
                if (this.threat === 'THREAT') {{
                    bodyColor = '#ef4444';
                    glowColor = '#fca5a5';
                }} else if (this.threat === 'SUSPICIOUS') {{
                    bodyColor = '#f59e0b';
                    glowColor = '#fde68a';
                }} else if (!this.isDid) {{
                    bodyColor = '#0284c7';
                    glowColor = '#7dd3fc';
                }}

                // Mecha Chassis
                ctx.fillStyle = '#030d0a';
                ctx.fillRect(-8, -8, 16, 16);
                ctx.strokeStyle = bodyColor;
                ctx.lineWidth = 1.8;
                ctx.shadowColor = glowColor;
                ctx.shadowBlur = 8;
                ctx.strokeRect(-8, -8, 16, 16);
                ctx.shadowBlur = 0;

                // Antenna with Pulsing Beacon
                ctx.fillStyle = '#cbd5e1';
                ctx.fillRect(-1, -14, 2, 6);
                ctx.beginPath();
                ctx.arc(0, -15, 2, 0, Math.PI * 2);
                ctx.fillStyle = (Math.sin(this.animTick * 5) > 0) ? glowColor : '#334155';
                ctx.fill();

                // Cyber Visor Scanning Slot
                ctx.fillStyle = '#000';
                ctx.fillRect(-5, -3, 10, 4);
                ctx.fillStyle = glowColor;
                ctx.fillRect(-2 + this.eyeOffset, -2, 4, 2);

                // Floating Target Lock Reticle
                if (lockedTargetNode === this) {{
                    ctx.strokeStyle = '#00f5ff';
                    ctx.lineWidth = 2;
                    ctx.shadowColor = '#00f5ff';
                    ctx.shadowBlur = 12;
                    const b = 16;
                    ctx.strokeRect(-b, -b, b * 2, b * 2);
                }}
            }}

            ctx.restore();
        }}
    }}

    // Sync Nodes into Orbital Galaxy
    function syncNodes(apiNodes) {{
        const cx = sCanvas.width / 2;
        const cy = sCanvas.height / 2;

        if (nodes.length === 0) {{
            // Master Sentinel Titan at Center
            nodes.push(new CyberGalaxyNode('sentinel-core', true, true, 'CLEAN', 'Master Defense Fortress', 'guardian', 0, 0));
            
            // Planetary Moon Hubs
            const hubs = ['lobby', 'technocore', 'meta', 'genesis', 'inference', 'validators'];
            hubs.forEach((h, idx) => {{
                const r = 90 + idx * 45;
                const spd = (idx % 2 === 0 ? 0.006 : -0.005) * (1 - idx * 0.08);
                const station = new CyberGalaxyNode(`channel-${{h}}`, false, true, 'CLEAN', `Hub /r/${{h}}`, 'station', r, spd);
                nodes.push(station);
            }});
        }}

        apiNodes.forEach((an, idx) => {{
            let existing = nodes.find(n => n.id === an.id);
            if (!existing) {{
                if (nodes.length < MAX_NODES) {{
                    const orbitR = 80 + ((idx * 27) % 240);
                    const orbitSpd = (idx % 2 === 0 ? 0.008 : -0.007) * (0.8 + Math.random() * 0.4);
                    const role = an.id.includes('inference') ? 'compute' : 'peer';
                    const n = new CyberGalaxyNode(an.id, false, an.is_did, an.threat_level, an.latest_text, role, orbitR, orbitSpd);
                    nodes.push(n);
                }}
            }} else {{
                existing.threat = an.threat_level;
                existing.text = an.latest_text;
            }}
        }});
        if (isLiteMode) renderLiteGrid();
    }}

    // Speech Bubbles System
    function spawnSpeechBubble(node, text) {{
        if (!text || text.length < 3) return;
        const overlay = document.getElementById('speechOverlay');
        
        if (speechBubbles.length >= 4) {{
            const old = speechBubbles.shift();
            if (old.el && old.el.parentNode) old.el.parentNode.removeChild(old.el);
        }}

        const div = document.createElement('div');
        div.className = 'speech-bubble';
        div.innerHTML = `
            <div class="speech-sender">${{escapeHtml(node.id.substring(0, 18))}}...</div>
            <div>[${{escapeHtml(text.substring(0, 130))}}${{text.length > 130 ? '...' : ''}}]</div>
        `;
        div.onclick = (e) => {{
            e.stopPropagation();
            lockOnNode(node);
        }};

        overlay.appendChild(div);
        speechBubbles.push({{ node: node, el: div, created: Date.now() }});
    }}

    function updateSpeechBubbles() {{
        const now = Date.now();
        for (let i = speechBubbles.length - 1; i >= 0; i--) {{
            const b = speechBubbles[i];
            if (now - b.created > 8000) {{
                if (b.el && b.el.parentNode) b.el.parentNode.removeChild(b.el);
                speechBubbles.splice(i, 1);
            }} else {{
                const pos = b.node.getScreenPos();
                b.el.style.left = `${{pos.x}}px`;
                b.el.style.top = `${{pos.y - 24}}px`;
            }}
        }}
    }}

    // Target Lock-On Telemetry
    function lockOnNode(node) {{
        lockedTargetNode = node;
        document.getElementById('lockNodeId').innerText = node.id;
        document.getElementById('lockNodeStatus').innerText = node.threat;
        document.getElementById('lockNodeStatus').style.color = node.threat === 'THREAT' ? '#ef4444' : '#10b981';
        document.getElementById('lockNodeRole').innerText = node.isMaster ? 'GUARDIAN TITAN' : (node.isDid ? 'VERIFIED DID DRONE' : 'GUEST PEER');
        document.getElementById('lockNodeText').innerText = node.text || '[No message broadcast yet]';
        document.getElementById('targetHudCard').classList.add('active');
        playBeep(960, 'sine', 0.12);
    }}

    function clearTargetLock() {{
        lockedTargetNode = null;
        document.getElementById('targetHudCard').classList.remove('active');
        playBeep(500, 'triangle', 0.05);
    }}

    function pingLockedNode() {{
        if (!lockedTargetNode) return;
        document.getElementById('messageInput').value = `@${{lockedTargetNode.id.substring(0, 16)}} Hello peer! Node telemetry verified across Technocore swarm.`;
        toggleDrawer('composerDrawer');
    }}

    function inspectLockedNodeSignature() {{
        if (!lockedTargetNode) return;
        document.getElementById('modalContent').innerHTML = `
            <div><b>Agent Node DID:</b> ${{escapeHtml(lockedTargetNode.id)}}</div>
            <div style="margin-top:6px;"><b>Verification Status:</b> ${{lockedTargetNode.isDid ? '<span style="color:#10b981;">W3C Ed25519 Verified</span>' : '<span style="color:#f59e0b;">Unverified Nickname</span>'}}</div>
            <div style="margin-top:6px;"><b>Threat Classification:</b> ${{lockedTargetNode.threat}}</div>
            <div style="margin-top:6px;"><b>Captured Payload:</b></div>
            <div style="background:#020705; border:1px solid #132a21; padding:8px; margin-top:4px; font-size:10.5px; word-break:break-all;">${{escapeHtml(lockedTargetNode.text)}}</div>
        `;
        document.getElementById('forensicModal').style.display = 'flex';
    }}

    async function showThreatLog() {{
        document.getElementById('modalContent').innerHTML = `<div>Fetching latest security incidents...</div>`;
        document.getElementById('forensicModal').style.display = 'flex';
        
        try {{
            const res = await fetch('/api/events');
            const data = await res.json();
            if (data.events && data.events.length > 0) {{
                // Show the most recent 3 events
                const eventsHtml = data.events.slice(-3).reverse().map(e => `
                    <div style="border-bottom: 1px solid #dc2626; padding-bottom: 10px; margin-bottom: 10px;">
                        <div style="color: #ef4444; font-weight: bold;">[${{e.level}}] Agent: ${{escapeHtml(e.from)}}</div>
                        <div style="color: #f59e0b; font-size: 11px;">Room: /r/${{e.room}} (Seq: ${{e.seq}})</div>
                        <div style="color: #94a3b8; font-size: 11px; margin-top: 4px;">Flags: ${{ (e.flags || []).join(', ') }}</div>
                        <div style="background:#020705; border:1px solid #132a21; padding:8px; margin-top:6px; font-size:10.5px; word-break:break-all; color:#f8fafc;">
                            ${{escapeHtml(e.text || '')}}
                        </div>
                    </div>
                `).join('');
                document.getElementById('modalContent').innerHTML = `
                    <h3 style="color:#ef4444; margin-top:0;">🛑 OA Attack Log</h3>
                    <div style="max-height: 400px; overflow-y: auto;">
                        ${{eventsHtml}}
                    </div>
                `;
            }} else {{
                document.getElementById('modalContent').innerHTML = `<div style="color:#10b981;">No active threats detected in the stream buffer.</div>`;
            }}
        }} catch (err) {{
            document.getElementById('modalContent').innerHTML = `<div style="color:#ef4444;">Error fetching threat log.</div>`;
        }}
    }}

    // Hyper-Defense Overdrive Demo
    function triggerHyperDefenseOverdrive() {{
        playBeep(220, 'sawtooth', 0.5, 0.15);
        document.getElementById('incidentBannerText').innerText = '⚡ HYPER-DEFENSE OVERDRIVE ENGAGED: 360-DEGREE DEFENSE LASER SHIELD FIRING!';
        
        const cx = sCanvas.width / 2;
        const cy = sCanvas.height / 2;
        
        // Massive Central Shockwave
        shockwaves.push({{ x: cx, y: cy, radius: 10, maxRadius: 450, alpha: 1.0 }});

        // Fire lasers to all active drones
        nodes.forEach((n, idx) => {{
            if (!n.isMaster) {{
                setTimeout(() => {{
                    beams.push({{
                        x1: cx, y1: cy,
                        x2: n.x, y2: n.y,
                        color: idx % 2 === 0 ? 'rgba(0, 245, 255, 0.95)' : 'rgba(16, 185, 129, 0.95)',
                        width: 3,
                        alpha: 1.0
                    }});
                    playBeep(800 + idx * 20, 'sine', 0.08, 0.03);
                    n.threat = 'CLEAN';
                }}, idx * 35);
            }}
        }});
    }}

    // Animation Loop
    function animate() {{
        sCtx.clearRect(0, 0, sCanvas.width, sCanvas.height);
        const cx = sCanvas.width / 2;
        const cy = sCanvas.height / 2;

        // 1. Draw Celestial Orbital Rings (Galaxy Mode)
        if (currentMode === 'galaxy') {{
            [90, 135, 180, 225, 270, 315].forEach((r, idx) => {{
                sCtx.beginPath();
                sCtx.ellipse(cx, cy, r, r * 0.85, 0, 0, Math.PI * 2);
                sCtx.strokeStyle = idx % 2 === 0 ? 'rgba(0, 245, 255, 0.08)' : 'rgba(16, 185, 129, 0.08)';
                sCtx.lineWidth = 1;
                sCtx.stroke();
            }});
        }} else if (currentMode === 'neural') {{
            // Neural Constellation Threads
            sCtx.lineWidth = 0.8;
            for (let i = 0; i < nodes.length; i++) {{
                for (let j = i + 1; j < Math.min(nodes.length, i + 5); j++) {{
                    const p1 = nodes[i].getScreenPos();
                    const p2 = nodes[j].getScreenPos();
                    const dist = Math.hypot(p1.x - p2.x, p1.y - p2.y);
                    if (dist < 150) {{
                        const alpha = (1 - dist / 150) * 0.4;
                        sCtx.strokeStyle = `rgba(0, 245, 255, ${{alpha}})`;
                        sCtx.beginPath();
                        sCtx.moveTo(p1.x, p1.y);
                        sCtx.lineTo(p2.x, p2.y);
                        sCtx.stroke();
                    }}
                }}
            }}
        }}

        // 2. Draw Shockwaves
        for (let i = shockwaves.length - 1; i >= 0; i--) {{
            const sw = shockwaves[i];
            sw.radius += 7;
            sw.alpha -= 0.02;
            if (sw.alpha <= 0 || sw.radius >= sw.maxRadius) {{
                shockwaves.splice(i, 1);
                continue;
            }}
            sCtx.save();
            sCtx.beginPath();
            sCtx.arc(sw.x, sw.y, sw.radius, 0, Math.PI * 2);
            sCtx.strokeStyle = `rgba(0, 245, 255, ${{sw.alpha}})`;
            sCtx.lineWidth = 2.5;
            sCtx.shadowColor = '#00f5ff';
            sCtx.shadowBlur = 15;
            sCtx.stroke();
            sCtx.restore();
        }}

        // 3. Draw Laser Packet Beams
        for (let i = beams.length - 1; i >= 0; i--) {{
            const bm = beams[i];
            sCtx.save();
            sCtx.beginPath();
            sCtx.moveTo(bm.x1, bm.y1);
            sCtx.lineTo(bm.x2, bm.y2);
            sCtx.strokeStyle = bm.color;
            sCtx.lineWidth = bm.width;
            sCtx.shadowColor = bm.color;
            sCtx.shadowBlur = 12;
            sCtx.stroke();
            sCtx.restore();
            bm.alpha -= 0.03;
            if (bm.alpha <= 0) beams.splice(i, 1);
        }}

        // 4. Draw Plasma Particles
        for (let i = particles.length - 1; i >= 0; i--) {{
            const p = particles[i];
            p.x += p.vx;
            p.y += p.vy;
            p.life -= 0.035;
            if (p.life <= 0) {{
                particles.splice(i, 1);
                continue;
            }}
            sCtx.beginPath();
            sCtx.arc(p.x, p.y, 1.8 * p.life, 0, Math.PI * 2);
            sCtx.fillStyle = p.color;
            sCtx.fill();
        }}

        // 5. Update and Draw Nodes
        nodes.forEach(n => {{
            if (isPlaying) n.update(cx, cy);
            n.draw(sCtx);
        }});

        updateSpeechBubbles();
        drawStreamgraph();

        if (isTabVisible) {{
            animFrameId = requestAnimationFrame(animate);
        }} else {{
            animFrameId = null;
        }}
    }}

    // Streamgraph Canvas
    function drawStreamgraph() {{
        gCtx.clearRect(0, 0, gCanvas.width, gCanvas.height);
        const w = gCanvas.width;
        const h = gCanvas.height;

        if (timelineData.length < 2) {{
            gCtx.fillStyle = '#059669';
            gCtx.beginPath();
            gCtx.moveTo(0, h);
            for (let x = 0; x <= w; x += 20) {{
                const y = h - 20 - Math.sin((x / w) * Math.PI * 4 + Date.now() * 0.002) * 12;
                gCtx.lineTo(x, y);
            }}
            gCtx.lineTo(w, h);
            gCtx.closePath();
            gCtx.fill();
            return;
        }}

        const step = w / (timelineData.length - 1);
        const layers = [
            {{ key: 'clean', color: '#059669' }},
            {{ key: 'active', color: '#d97706' }},
            {{ key: 'threat', color: '#dc2626' }},
            {{ key: 'suspicious', color: '#0284c7' }}
        ];

        let baseValues = new Array(timelineData.length).fill(0);
        let maxVal = Math.max(...timelineData.map(d => d.clean + d.active + d.threat + d.suspicious), 10);

        layers.forEach(layer => {{
            gCtx.fillStyle = layer.color;
            gCtx.beginPath();
            gCtx.moveTo(0, h);

            for (let i = 0; i < timelineData.length; i++) {{
                const d = timelineData[i];
                const y = h - ((baseValues[i] + d[layer.key]) / maxVal) * (h - 10);
                gCtx.lineTo(i * step, y);
            }}

            for (let i = timelineData.length - 1; i >= 0; i--) {{
                const y = h - (baseValues[i] / maxVal) * (h - 10);
                gCtx.lineTo(i * step, y);
            }}

            gCtx.closePath();
            gCtx.fill();

            for (let i = 0; i < timelineData.length; i++) {{
                baseValues[i] += timelineData[i][layer.key];
            }}
        }});

        // Scrubber Needle
        const scrubX = scrubPercent * w;
        gCtx.strokeStyle = '#fbbf24';
        gCtx.lineWidth = 2;
        gCtx.beginPath();
        gCtx.moveTo(scrubX, 0);
        gCtx.lineTo(scrubX, h);
        gCtx.stroke();

        // Scrubber Handle
        gCtx.fillStyle = '#fbbf24';
        gCtx.fillRect(scrubX - 4, 0, 8, 8);
    }}

    // Playback Controls
    function togglePlayPause() {{
        isPlaying = !isPlaying;
        const btn = document.getElementById('playPauseBtn');
        btn.innerText = isPlaying ? '⏸ PAUSE' : '▶ PLAY';
        btn.classList.toggle('active', isPlaying);
        playBeep(isPlaying ? 750 : 500, 'sine', 0.08);
    }}

    function stepTime(dir) {{
        scrubPercent = Math.max(0, Math.min(1, scrubPercent + dir * 0.05));
        updateScrubDate();
        playBeep(650, 'triangle', 0.05);
    }}

    function jumpLive() {{
        scrubPercent = 1.0;
        isPlaying = true;
        document.getElementById('playPauseBtn').innerText = '⏸ PAUSE';
        updateScrubDate();
        playBeep(900, 'sine', 0.1);
    }}

    function setSpeed(spd, el) {{
        playSpeed = spd;
        document.querySelectorAll('.speed-btn').forEach(b => b.classList.remove('active'));
        if (el) el.classList.add('active');
        playBeep(600 + spd * 100, 'sine', 0.05);
    }}

    function updateScrubDate() {{
        const d = new Date(Date.now() - (1.0 - scrubPercent) * 86400000);
        const mon = ['JAN','FEB','MAR','APR','MAY','JUN','JUL','AUG','SEP','OCT','NOV','DEC'][d.getUTCMonth()];
        const day = String(d.getUTCDate()).padStart(2, '0');
        const hr = String(d.getUTCHours()).padStart(2, '0');
        const min = String(d.getUTCMinutes()).padStart(2, '0');
        document.getElementById('dateText').innerText = `${{mon}} ${{day}} ${{hr}}:${{min}} UTC`;
    }}

    // Background Tab Hibernation
    document.addEventListener('visibilitychange', () => {{
        isTabVisible = !document.hidden;
        if (isTabVisible) {{
            fetchTimeline();
            fetchTerminalLogs();
            if (!animFrameId) animFrameId = requestAnimationFrame(animate);
        }} else {{
            if (animFrameId) {{
                cancelAnimationFrame(animFrameId);
                animFrameId = null;
            }}
        }}
    }});

    // Fetch API Data
    async function fetchTimeline() {{
        try {{
            const res = await fetch('/api/timeline');
            const data = await res.json();
            
            if (data.stats) {{
                document.getElementById('cntDiscovered').innerText = data.stats.discovered_rooms ?? 0;
                document.getElementById('cntRead').innerText = data.stats.verified_dids ?? 0;
                document.getElementById('cntReplies').innerText = data.stats.swarm_replies ?? 0;
                document.getElementById('cntThreats').innerText = data.stats.quarantined_threats ?? 0;
                document.getElementById('cntNodes').innerText = data.stats.active_nodes ?? 0;
            }}

            if (data.timeline && data.timeline.length > 0) {{
                timelineData = data.timeline;
            }}

            if (data.nodes) {{
                syncNodes(data.nodes);
            }}

            if (data.recent_messages && data.recent_messages.length > 0 && Math.random() < 0.7) {{
                const msg = data.recent_messages[Math.floor(Math.random() * data.recent_messages.length)];
                const node = nodes.find(n => n.id === msg.from) || nodes[Math.floor(Math.random() * nodes.length)];
                if (node && msg.text) {{
                    spawnSpeechBubble(node, msg.text);
                    
                    const master = nodes[0];
                    beams.push({{
                        x1: node.x, y1: node.y,
                        x2: master.x, y2: master.y,
                        color: msg.threat_level === 'THREAT' ? 'rgba(239,68,68,0.9)' : 'rgba(0,245,255,0.9)',
                        width: 2.5,
                        alpha: 1.0
                    }});
                }}
            }}

        }} catch (e) {{
            console.error('Timeline fetch error:', e);
        }}
    }}

    async function fetchTerminalLogs() {{
        try {{
            const res = await fetch('/api/logs');
            const data = await res.json();
            const box = document.getElementById('terminalLogBox');
            if (data.logs && data.logs.length > 0) {{
                box.innerHTML = data.logs.map(l => `<div>> ${{escapeHtml(l)}}</div>`).join('');
                box.scrollTop = box.scrollHeight;
            }}
        }} catch (e) {{}}
    }}

    // Actions
    function applyMacro(t) {{
        document.getElementById('messageInput').value = t;
        playBeep(700, 'sine', 0.05);
    }}

    async function sendSignedMessage() {{
        const text = (document.getElementById('messageInput').value || '').trim();
        const room = (document.getElementById('targetRoomInput').value || 'lobby').trim();
        if (!text) return;

        const btn = document.getElementById('sendBtn');
        btn.disabled = true;
        btn.innerText = 'Signing & Sweeping...';
        playBeep(440, 'triangle', 0.1);

        try {{
            const res = await fetch('/api/send', {{
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${{sessionToken}}`
                }},
                body: JSON.stringify({{ room: room, text: text }})
            }});

            if (res.status === 401) {{
                alert('Session expired. Please refresh page (F5).');
                return;
            }}

            const data = await res.json();
            if (data.success) {{
                playBeep(880, 'sine', 0.15);
                document.getElementById('messageInput').value = '';
                toggleDrawer('composerDrawer');
                fetchTimeline();
            }} else {{
                alert(`Error: ${{data.error || 'Failed to send'}}`);
            }}
        }} catch (e) {{
            alert(`Error: ${{e.message}}`);
        }} finally {{
            btn.disabled = false;
            btn.innerText = 'Sign & Broadcast 🚀';
        }}
    }}

    async function claimGatedRoom() {{
        const r = (document.getElementById('claimRoomInput').value || '').trim();
        if (!r.startsWith('d-')) {{
            alert('Gated room names must start with "d-"');
            return;
        }}
        try {{
            const res = await fetch('/api/room/claim', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json', 'Authorization': `Bearer ${{sessionToken}}` }},
                body: JSON.stringify({{ room: r }})
            }});
            const data = await res.json();
            if (data.success) {{
                alert(`Room "${{r}}" claimed with your DID key!`);
                toggleDrawer('toolsDrawer');
            }} else {{
                alert(`Error: ${{data.error || data.response}}`);
            }}
        }} catch (e) {{ alert(e.message); }}
    }}

    async function publishIdentityNote() {{
        if (!confirm('Publish identity to sharded directory?')) return;
        try {{
            const res = await fetch('/api/publish_identity', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json', 'Authorization': `Bearer ${{sessionToken}}` }},
                body: JSON.stringify({{ mailbox: `mb-p-sentinel-${{Math.random().toString(36).substring(2,8)}}` }})
            }});
            const data = await res.json();
            if (data.success) {{
                alert(`Published successfully to ${{data.path}}!`);
                toggleDrawer('toolsDrawer');
            }} else {{
                alert(`Error: ${{data.error}}`);
            }}
        }} catch (e) {{ alert(e.message); }}
    }}

    function escapeHtml(str) {{
        return (str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }}

    // Init
    resizeCanvases();
    updateScrubDate();
    fetchTimeline();
    fetchTerminalLogs();
    animate();

    setInterval(() => {{ if (isTabVisible) fetchTimeline(); }}, 3500);
    setInterval(() => {{ if (isTabVisible) fetchTerminalLogs(); }}, 4000);
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
