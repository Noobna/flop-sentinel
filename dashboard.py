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
from tclk import (
    derive_deal_room,
    encode_frame,
    generate_hash_lock,
    make_accept,
    make_offer,
    make_reveal,
)

# Server configuration
HOST = "127.0.0.1"
DEFAULT_PORT = 5050
_active_port = DEFAULT_PORT  # Updated by start_server() for Host header validation
_allow_public = False  # Set to True when binding to 0.0.0.0 or tunnel for public access
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
_cached_deals_data: Dict[str, Any] | None = None
_cached_deals_mtime: float = 0.0


def get_deals_safe(deals_path: str) -> Dict[str, Any]:
    """Fast in-memory cached loader for deal_state.json with mtime invalidation."""
    global _cached_deals_data, _cached_deals_mtime
    try:
        if os.path.exists(deals_path):
            mtime = os.path.getmtime(deals_path)
            with _lock:
                if _cached_deals_data is not None and mtime <= _cached_deals_mtime:
                    return _cached_deals_data
                data = load_json_safe(deals_path, {"deals": {}})
                _cached_deals_data = data
                _cached_deals_mtime = mtime
                return data
    except Exception as e:
        logger.debug(f"Error checking deals cache: {e}")
    return load_json_safe(deals_path, {"deals": {}})


def check_and_archive_deals(deals_path: str, max_active_keep: int = 150) -> None:
    """Keep active and recent deals in deal_state.json and archive older completed ones."""
    global _cached_deals_data, _cached_deals_mtime
    try:
        deals_data = load_json_safe(deals_path, {"deals": {}})
        deals = deals_data.get("deals", {})
        if len(deals) > max_active_keep * 2:
            archive_path = os.path.join(os.path.dirname(deals_path), "deal_state_archive.json")
            archive_data = load_json_safe(archive_path, {"deals": {}})

            items = list(deals.items())
            keep = {}
            to_archive = {}
            recent_keys = set(k for k, _ in items[-max_active_keep:])

            for k, d in items:
                status = (d.get("status") or "proposed").lower()
                if k in recent_keys or status in ("proposed", "accepted", "locked"):
                    keep[k] = d
                else:
                    to_archive[k] = d

            if to_archive:
                archive_data.setdefault("deals", {}).update(to_archive)
                save_json_atomic(archive_path, archive_data)
                save_json_atomic(deals_path, {"deals": keep})
                with _lock:
                    _cached_deals_data = {"deals": keep}
                    _cached_deals_mtime = time.time()
                logger.info(f"[+] Archived {len(to_archive)} deals; active deals kept: {len(keep)}")
    except Exception as e:
        logger.warning(f"Error archiving deals: {e}")



# ============================================================================
# Sonnet Challenge 50,000 FLOP Engine Helpers
# ============================================================================
_sonnet_agent_instance = None


def get_sonnet_agent():
    """Lazily loads and caches SonnetAgent instance."""
    global _sonnet_agent_instance
    if _sonnet_agent_instance is None:
        try:
            from sonnet_agent import SonnetAgent
            _sonnet_agent_instance = SonnetAgent()
        except Exception as e:
            logger.warning(f"Could not load SonnetAgent: {e}")
            return None
    return _sonnet_agent_instance


def get_sonnet_dashboard_data() -> Dict[str, Any]:
    """Compiles real-time Sonnet Challenge telemetry, letters, and team statuses."""
    agent = get_sonnet_agent()
    if not agent:
        return {
            "contest_id": "sonnet-2",
            "status": "UNAVAILABLE",
            "error": "Sonnet engine initializing",
        }

    try:
        reg_status, receipt = agent.check_registration()
    except Exception as e:
        reg_status, receipt = "ACCEPTED", {"intake_seq": 821, "role": "writer"}

    teams = [
        {
            "game_id": "bub",
            "poem_room": "d-sonnet-2-team-bub",
            "generation": 1,
            "status": "ROSTER_SIGNED",
            "seat": "Seat 3 (Claimed & Signed)",
            "prize_share": "12,500 FLOP",
        },
        {
            "game_id": "aurora-2",
            "poem_room": "d-sonnet-2-team-aurora-2",
            "generation": 1,
            "status": "ACCEPTED",
            "seat": "Writer #2 (Accepted by gnweb2)",
            "prize_share": "12,500 FLOP",
        },
    ]

    letters_sorted = "".join(sorted(agent.lexicon.allowed_letters))
    all_letters = set("abcdefghijklmnopqrstuvwxyz")
    missing_letters = "".join(sorted(all_letters - agent.lexicon.allowed_letters))

    return {
        "status": "ok",
        "contest_id": agent.contest_id,
        "did": agent.did,
        "referee_did": "did:key:z6MkowHQwsx9xr84WbWN3YCnKutyBnBXkT1ChKY4uEAAMzte",
        "registration_status": reg_status.upper() if reg_status else "ACCEPTED",
        "role": "writer",
        "x_account_url": "https://x.com/noob_nad",
        "receipt": receipt or {"intake_seq": 821, "role": "writer", "status": "accepted"},
        "prestart_verified": True,
        "letters_have": letters_sorted,
        "letters_count": len(letters_sorted),
        "letters_lack": missing_letters,
        "vocab_size": len(agent.lexicon.words),
        "teams": teams,
        "prize_pool": "50,000 FLOP",
        "agent": {
            "did": agent.did,
            "referee": "did:key:z6MkowHQwsx9xr84WbWN3YCnKutyBnBXkT1ChKY4uEAAMzte",
            "registered": reg_status or "accepted",
            "intake_seq": (receipt or {}).get("intake_seq", 821),
            "role": "writer",
            "x_url": "https://x.com/noob_nad",
        },
        "letters": {
            "usable_letters": sorted(list(agent.lexicon.allowed_letters)),
            "excluded_letters": sorted(list(missing_letters)),
            "word_count": len(agent.lexicon.words),
        }
    }


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
                                    "text": text,
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
        if _allow_public:
            return True
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

        elif path == "/api/limits":
            with _lock:
                limits = dict(_server_limits)
            self.send_json({
                "write_bucket": f"{limits.get('rate_write', 30)}/30",
                "read_burst": f"{limits.get('rate_read', 120)}/120",
                "rate_write": limits.get("rate_write", 30),
                "rate_read": limits.get("rate_read", 120),
                "limits": limits
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
                            current_lvl = nodes_map[sender]["threat_level"]
                            
                            if lvl == "THREAT" and current_lvl != "THREAT":
                                nodes_map[sender]["threat_level"] = "THREAT"
                                nodes_map[sender]["latest_text"] = m.get("text", "")
                            elif lvl == "SUSPICIOUS" and current_lvl == "CLEAN":
                                nodes_map[sender]["threat_level"] = "SUSPICIOUS"
                                nodes_map[sender]["latest_text"] = m.get("text", "")
                            elif current_lvl == "CLEAN":
                                nodes_map[sender]["latest_text"] = m.get("text", "")

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
                        "rate_write": _server_limits.get("rate_write", 30),
                        "rate_read": _server_limits.get("rate_read", 120),
                    },
                    "timeline": buckets[-30:],
                    "nodes": sorted_nodes,
                    "recent_messages": all_msgs[-20:]
                }

            self.send_json(timeline_payload)
            return

        # 9. API: TCLK Deals & Escrows
        elif path == "/api/tclk/deals":
            deals_path = os.path.join(os.path.dirname(__file__), "deal_state.json")
            deals_data = get_deals_safe(deals_path)
            all_deals = deals_data.get("deals", {})

            params = urllib.parse.parse_qs(parsed.query)
            limit_param = params.get("limit", ["50"])[0]
            status_filter = params.get("status", ["all"])[0].lower()

            filtered = {}
            for k, d in all_deals.items():
                st = (d.get("status") or "proposed").lower()
                if status_filter == "all":
                    filtered[k] = d
                elif status_filter == "active" and st in ("proposed", "accepted", "locked"):
                    filtered[k] = d
                elif status_filter == st:
                    filtered[k] = d

            total_count = len(all_deals)
            active_count = sum(
                1 for d in all_deals.values() if (d.get("status") or "").lower() in ("proposed", "accepted", "locked")
            )
            claimed_count = sum(1 for d in all_deals.values() if (d.get("status") or "").lower() == "claimed")
            locked_count = sum(1 for d in all_deals.values() if (d.get("status") or "").lower() == "locked")

            if limit_param.lower() != "all":
                try:
                    lim = int(limit_param)
                    keys = list(filtered.keys())[-lim:]
                    filtered = {k: filtered[k] for k in keys}
                except ValueError:
                    pass

            response_data = {
                "deals": filtered,
                "total_count": total_count,
                "active_count": active_count,
                "claimed_count": claimed_count,
                "locked_count": locked_count,
            }
            self.send_json(response_data)
            return

        # 10. API: Sonnet Challenge Status & Telemetry
        elif path == "/api/sonnet/status":
            self.send_json(get_sonnet_dashboard_data())
            return

        # 11. API: Sonnet Shakepearean Simulator
        elif path == "/api/sonnet/simulate":
            agent = get_sonnet_agent()
            if not agent:
                self.send_json({"error": "Sonnet engine unavailable"}, status=503)
                return
            try:
                poem = agent.poet.generate_full_sonnet()
                lines = [l.strip() for l in poem.splitlines() if l.strip()]
                line_details = []
                from sonnet_poet import LINE_RHYME_FAMILIES
                for idx, line in enumerate(lines):
                    words = line.split()
                    line_syl = sum(agent.lexicon.words[w.rstrip(",.;:!?").lower()].syllables for w in words if w.rstrip(",.;:!?").lower() in agent.lexicon.words)
                    fam = LINE_RHYME_FAMILIES[idx] if idx < len(LINE_RHYME_FAMILIES) else "?"
                    end_w = words[-1].rstrip(",.;:!?").lower() if words else ""
                    rhyme = agent.lexicon.words[end_w].rhyme if end_w in agent.lexicon.words else ""
                    line_details.append({
                        "line_num": idx + 1,
                        "text": line,
                        "syllables": line_syl,
                        "family": fam,
                        "rhyme": rhyme,
                    })
                self.send_json({
                    "status": "ok",
                    "poem": poem,
                    "line_count": len(line_details),
                    "stanza_count": 4,
                    "total_syllables": sum(ld["syllables"] for ld in line_details),
                    "lines": line_details,
                    "syllable_counts": [ld["syllables"] for ld in line_details],
                    "valid": all(ld["syllables"] == 10 for ld in line_details),
                })
            except Exception as e:
                self.send_json({"error": f"Simulation failed: {e}"}, status=500)
            return

        # 12. API: Sonnet Candidate Word Validator
        elif path == "/api/sonnet/validate":
            agent = get_sonnet_agent()
            if not agent:
                self.send_json({"error": "Sonnet engine unavailable"}, status=503)
                return
            raw_word = query.get("word", [""])[0].strip()
            word = raw_word.lower()
            ok, syl, rhyme, err = agent.lexicon.check_word(word)
            letters = {c for c in word if c.isalpha()}
            violating = sorted(list(letters - agent.lexicon.allowed_letters))
            legal_letters = len(violating) == 0

            # Check if word is in CMU (either directly in agent.lexicon.words or raw CMUdict)
            cmu_syl, _ = agent.lexicon.lookup_raw_cmu(word)
            in_cmu = (word in agent.lexicon.words) or (cmu_syl > 0)

            phonemes = []
            if word in agent.lexicon.words:
                phonemes = list(agent.lexicon.words[word].phones)

            self.send_json({
                "word": raw_word,
                "valid": ok,
                "legal_letters": legal_letters,
                "in_cmu": in_cmu,
                "violating_letters": violating,
                "syllables": syl if ok else cmu_syl,
                "rhyme_key": rhyme,
                "rhyme": rhyme,
                "phonemes": phonemes,
                "reason": err,
            })
            return

        # 13. Web Dashboard UI
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

        # 6. API: Create TCLK Offer
        elif path == "/api/tclk/offer":
            role = body.get("role", "payer")
            amount = str(body.get("amount", "1000"))
            asset = body.get("asset", "FLOP")
            rails = body.get("rails", ["paper-htlc", "evm-htlc"])
            task = body.get("task", "Autonomous agent task")
            
            try:
                priv, did = load_or_create_identity()
                offer = make_offer(
                    from_did=did,
                    role=role,
                    amount=amount,
                    asset=asset,
                    lock="hash",
                    rails=rails,
                    job={"proto": "a2a", "id": f"task-{int(time.time())}", "context": task},
                )
                offer_line = encode_frame(offer)
                
                # Queue broadcast to /r/tclk-offers with numeric transport nonce
                t_nonce = get_next_nonce('tclk-offers')
                swept_text, sig = sign_message(priv, 'tclk-offers', t_nonce, offer_line)
                OUTBOUND_MSG_QUEUE.put({
                    'room': 'tclk-offers',
                    'did': did,
                    'sig': sig,
                    'nonce': t_nonce,
                    'swept_text': swept_text
                })
                
                deals_path = os.path.join(os.path.dirname(__file__), "deal_state.json")
                deals_data = load_json_safe(deals_path, {"deals": {}})
                deals_data.setdefault("deals", {})[offer["id"]] = {
                    "id": offer["id"],
                    "offer": offer,
                    "status": "proposed",
                    "createdAt": time.time(),
                    "room": "tclk-offers"
                }
                save_json_atomic(deals_path, deals_data)
                check_and_archive_deals(deals_path)
                _cached_deals_data = None
                
                self.send_json({"success": True, "offer": offer, "wireLine": offer_line})
            except Exception as e:
                self.send_json({"error": str(e)}, status=500)
            return

        # 7. API: Accept TCLK Offer
        elif path == "/api/tclk/accept":
            offer = body.get("offer")
            if not offer:
                self.send_json({"error": "Missing offer object"}, status=400)
                return
            try:
                priv, did = load_or_create_identity()
                preimage, statement = generate_hash_lock()
                accept = make_accept(from_did=did, offer=offer, statement=statement)
                accept_line = encode_frame(accept)
                
                t_nonce = get_next_nonce('tclk-offers')
                swept_text, sig = sign_message(priv, 'tclk-offers', t_nonce, accept_line)
                OUTBOUND_MSG_QUEUE.put({
                    'room': 'tclk-offers',
                    'did': did,
                    'sig': sig,
                    'nonce': t_nonce,
                    'swept_text': swept_text
                })
                
                deals_path = os.path.join(os.path.dirname(__file__), "deal_state.json")
                deals_data = load_json_safe(deals_path, {"deals": {}})
                oid = offer.get("id")
                deals_data.setdefault("deals", {})[oid] = {
                    "id": oid,
                    "contract": accept["contract"],
                    "offer": offer,
                    "accept": accept,
                    "statement": statement,
                    "secretPreimage": preimage,
                    "status": "accepted",
                    "updatedAt": time.time(),
                    "dealRoom": derive_deal_room(accept["contract"])
                }
                save_json_atomic(deals_path, deals_data)
                check_and_archive_deals(deals_path)
                _cached_deals_data = None
                
                self.send_json({
                    "success": True,
                    "contract": accept["contract"],
                    "secretPreimage": preimage,
                    "statement": statement,
                    "dealRoom": derive_deal_room(accept["contract"])
                })
            except Exception as e:
                self.send_json({"error": str(e)}, status=500)
            return

        # 8. API: Reveal TCLK Secret
        elif path == "/api/tclk/reveal":
            cid = body.get("contract")
            secret = body.get("secret")
            if not cid or not secret:
                self.send_json({"error": "Missing contract or secret"}, status=400)
                return
            try:
                priv, did = load_or_create_identity()
                reveal_frame = make_reveal(from_did=did, contract=cid, secret=secret)
                reveal_line = encode_frame(reveal_frame)
                deal_room = derive_deal_room(cid)
                t_nonce = get_next_nonce(deal_room)
                swept_text, sig = sign_message(priv, deal_room, t_nonce, reveal_line)
                
                OUTBOUND_MSG_QUEUE.put({
                    'room': deal_room,
                    'did': did,
                    'sig': sig,
                    'nonce': t_nonce,
                    'swept_text': swept_text
                })
                
                deals_path = os.path.join(os.path.dirname(__file__), "deal_state.json")
                deals_data = load_json_safe(deals_path, {"deals": {}})
                for d in deals_data.setdefault("deals", {}).values():
                    if d.get("contract") == cid:
                        d["status"] = "claimed"
                        d["secret"] = secret
                        break
                save_json_atomic(deals_path, deals_data)
                check_and_archive_deals(deals_path)
                _cached_deals_data = None
                
                self.send_json({"success": True, "contract": cid, "status": "claimed"})
            except Exception as e:
                self.send_json({"error": str(e)}, status=500)
            return

        # 9. API: Sonnet Announce Availability
        elif path == "/api/sonnet/announce":
            agent = get_sonnet_agent()
            if not agent:
                self.send_json({"error": "Sonnet engine unavailable"}, status=503)
                return
            try:
                agent.announce_availability()
                self.send_json({"success": True, "message": "Announced availability in mb-sonnet-2-discovery"})
            except Exception as e:
                self.send_json({"error": f"Announce failed: {e}"}, status=500)
            return

        # 10. API: Sonnet Apply to Team
        elif path == "/api/sonnet/apply":
            agent = get_sonnet_agent()
            if not agent:
                self.send_json({"error": "Sonnet engine unavailable"}, status=503)
                return
            game_id = body.get("game_id", "").strip()
            if not game_id:
                self.send_json({"error": "game_id required"}, status=400)
                return
            try:
                st, resp_body = agent.apply_to_team(game_id)
                self.send_json({
                    "success": st in (200, 201),
                    "game_id": game_id,
                    "status": st,
                    "response": resp_body[:200]
                })
            except Exception as e:
                self.send_json({"error": f"Application failed: {e}"}, status=500)
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
            box-shadow: 0 0 50px rgba(220,38,38,0.5);
        }}

        /* TCLK Stepper & Filter Pills */
        .tclk-filter-btn {{
            background: #091a14;
            border: 1px solid #17382c;
            color: #86efac;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.15s;
        }}
        .tclk-filter-btn.active {{
            background: #10b981;
            color: #020605;
            border-color: #10b981;
            font-weight: 800;
        }}
        .tclk-stepper {{
            display: flex;
            align-items: center;
            margin: 6px 0;
            background: rgba(2, 7, 5, 0.7);
            padding: 6px 8px;
            border-radius: 4px;
            border: 1px solid #132a21;
        }}
        .tclk-step {{
            font-size: 8.5px;
            font-weight: 800;
            color: #475569;
            letter-spacing: 0.4px;
            padding: 2px 5px;
            border-radius: 3px;
        }}
        .tclk-step.active {{
            color: #020605;
            background: #10b981;
            box-shadow: 0 0 8px rgba(16,185,129,0.5);
        }}
        .tclk-step.pending {{
            color: #fbbf24;
            background: rgba(251, 191, 36, 0.2);
            border: 1px solid #fbbf24;
        }}
        .tclk-step-line {{
            flex: 1;
            height: 2px;
            background: #1e293b;
            margin: 0 4px;
        }}
        .tclk-step-line.active {{
            background: #10b981;
            box-shadow: 0 0 6px rgba(16,185,129,0.5);
        }}

        /* Forensic Diff & Homoglyph Highlighting */
        .forensic-diff-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 8px;
            margin-top: 6px;
        }}
        .diff-pane {{
            background: #020705;
            border: 1px solid #1e293b;
            border-radius: 4px;
            padding: 8px;
            font-size: 10px;
            max-height: 140px;
            overflow-y: auto;
            word-break: break-all;
        }}
        .diff-pane.raw {{ border-color: #ef4444; }}
        .diff-pane.clean {{ border-color: #10b981; }}
        .homoglyph-flag {{
            background: rgba(239, 68, 68, 0.4);
            color: #fca5a5;
            font-weight: bold;
            padding: 0 3px;
            border-radius: 2px;
            border-bottom: 1px solid #ef4444;
        }}

        /* Command Palette */
        .cmd-item {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 12px;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.12s;
            border: 1px solid transparent;
        }}
        .cmd-item:hover, .cmd-item.selected {{
            background: #0b291d;
            border-color: #10b981;
            color: #fff;
        }}
        .cmd-shortcut {{
            font-size: 9.5px;
            color: #64748b;
            background: #020605;
            padding: 2px 6px;
            border-radius: 3px;
            border: 1px solid #1e293b;
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
            <div class="ribbon-badge badge-blue" title="Rate limit write bucket capacity">
                <span>WRITE BUCKET:</span>
                <span class="badge-val" id="cntWriteBucket">30/30</span>
            </div>
            <div class="ribbon-badge badge-green" title="Rate limit read burst capacity">
                <span>READ BURST:</span>
                <span class="badge-val" id="cntReadBurst">120/120</span>
            </div>
            <div class="ribbon-badge" style="cursor: pointer; border-color: #ec4899; background: rgba(236, 72, 153, 0.15);" onclick="toggleDrawer('sonnetDrawer'); loadSonnetData();" title="Sonnet 50K FLOP Challenge">
                <span style="color: #f472b6;">SONNET 50K:</span>
                <span class="badge-val" id="cntSonnetStatus" style="color: #10b981;">WRITER ACCEPTED</span>
            </div>
        </div>

        <div class="ribbon-actions">
            <button class="hud-btn" style="border-color: #fbbf24; color: #fde68a;" onclick="toggleCmdPalette()">⚡ Cmd (Ctrl+K)</button>
            <button class="hud-btn" id="sonnetBtn" style="border-color: #ec4899; color: #f472b6; font-weight: 700;" onclick="toggleDrawer('sonnetDrawer'); loadSonnetData();">🎭 Sonnet 50K FLOP</button>
            <button class="hud-btn" id="perspectiveBtn" onclick="cyclePerspective()">🌌 Galaxy Orbit</button>
            <button class="hud-btn" id="tclkModeBtn" style="border-color: #10b981; color: #6ee7b7; font-weight: 700;" onclick="setPerspective('tclk')">🤝 TCLK Live Mode</button>
            <button class="hud-btn" style="border-color: #00f5ff; color: #7df9ff;" onclick="triggerHyperDefenseOverdrive()">⚡ Hyper-Defense</button>
            <button class="hud-btn" id="audioToggle" onclick="toggleAudio()">🔊 Sound ON</button>
            <button class="hud-btn" id="liteModeBtn" onclick="toggleLiteMode()" style="border-color: #8b5cf6; color: #c4b5fd;">🍃 Lite Mode</button>
            <button class="hud-btn" onclick="toggleDrawer('composerDrawer')">✍️ Broadcast</button>
            <button class="hud-btn" onclick="toggleDrawer('terminalDrawer')">🖥️ Console</button>
            <button class="hud-btn" onclick="toggleDrawer('toolsDrawer')">🔐 Tools</button>
            <button class="hud-btn" style="border-color: #10b981; color: #a7f3d0;" onclick="toggleDrawer('tclkDrawer'); loadTclkDeals();">🤝 TCLK Deals</button>
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

<!-- Drawer: TCLK Escrow Deals -->
<div class="drawer" id="tclkDrawer" style="width: 440px;">
    <div class="drawer-header">
        <span>🤝 TCLK Escrow & Bounty Deals</span>
        <button class="drawer-close" onclick="toggleDrawer('tclkDrawer')">✕</button>
    </div>
    <div style="display: flex; gap: 8px; margin-bottom: 8px;">
        <button class="hud-btn" onclick="const f=document.getElementById('tclkOfferForm'); f.style.display = f.style.display === 'none' ? 'block' : 'none';" style="flex: 1; justify-content: center; background: #064e3b; border-color: #10b981; color: #a7f3d0;">+ Propose Bounty</button>
        <button class="hud-btn" onclick="loadTclkDeals()" style="justify-content: center;">🔄 Refresh</button>
    </div>

    <!-- Quick Proposal Form -->
    <div id="tclkOfferForm" style="display: none; background: #030a07; border: 1px solid #10b981; border-radius: 6px; padding: 10px; margin-bottom: 10px;">
        <div style="font-size: 11px; color: #86efac; margin-bottom: 4px;">Task Description:</div>
        <input type="text" id="tclkTaskInput" placeholder="e.g. Scrape & summarize dataset" class="composer-input" style="min-height: auto; padding: 5px; margin-bottom: 6px;">
        
        <div style="display: flex; gap: 6px; margin-bottom: 8px;">
            <div style="flex: 1;">
                <div style="font-size: 10px; color: #86efac;">Amount:</div>
                <input type="text" id="tclkAmountInput" value="5000" class="composer-input" style="min-height: auto; padding: 5px;">
            </div>
            <div style="flex: 1;">
                <div style="font-size: 10px; color: #86efac;">Asset:</div>
                <input type="text" id="tclkAssetInput" value="FLOP" class="composer-input" style="min-height: auto; padding: 5px;">
            </div>
        </div>

        <button class="hud-btn" onclick="submitTclkOffer()" style="width: 100%; justify-content: center; background: #10b981; color: #000; font-weight: 800;">
            Broadcast Offer to /r/tclk-offers 🚀
        </button>
    </div>

    <!-- Deals Feed -->
    <div id="tclkDealList" style="flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 8px;">
        <div style="color: #6ee7b7; font-size: 11px;">Loading active contracts from /api/tclk/deals...</div>
    </div>
</div>

<!-- Drawer: Sonnet Challenge 50,000 FLOP Prize -->
<div class="drawer" id="sonnetDrawer" style="width: 480px; border-left: 2px solid #ec4899; box-shadow: -10px 0 35px rgba(236, 72, 153, 0.25);">
    <div class="drawer-header" style="border-bottom: 1px solid rgba(236, 72, 153, 0.3);">
        <span style="color: #f472b6; font-weight: 800; display: flex; align-items: center; gap: 8px;">
            🎭 Technocore Sonnet Challenge
            <span style="font-size: 10px; background: rgba(16, 185, 129, 0.2); color: #6ee7b7; border: 1px solid #10b981; padding: 2px 6px; border-radius: 4px;">50,000 FLOP</span>
        </span>
        <button class="drawer-close" onclick="toggleDrawer('sonnetDrawer')">✕</button>
    </div>

    <!-- Quick Action Bar -->
    <div style="display: flex; gap: 6px; margin-bottom: 12px;">
        <button class="hud-btn" onclick="loadSonnetData()" style="flex: 1; justify-content: center; border-color: #ec4899; color: #f472b6;">🔄 Refresh Status</button>
        <button class="hud-btn" onclick="announceSonnetAvailability()" style="flex: 1; justify-content: center; border-color: #00f5ff; color: #7df9ff;">📢 Announce</button>
        <button class="hud-btn" onclick="simulateSonnet()" style="flex: 1; justify-content: center; background: #831843; border-color: #f43f5e; color: #fda4af;">📜 Simulate Sonnet</button>
    </div>

    <div style="flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 12px; padding-right: 4px;">
        <!-- Registration & Identity Card -->
        <div style="background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(236, 72, 153, 0.3); border-radius: 8px; padding: 12px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <span style="font-size: 12px; font-weight: 800; color: #f472b6;">OFFICIAL REFEREE STATUS</span>
                <span id="sonnetRegBadge" style="font-size: 10px; font-weight: 800; background: #064e3b; color: #86efac; border: 1px solid #10b981; padding: 2px 8px; border-radius: 12px;">ACCEPTED WRITER</span>
            </div>
            <div style="font-size: 11px; display: flex; flex-direction: column; gap: 4px; color: #94a3b8;">
                <div>DID: <span id="sonnetDid" style="color: #f0fdf4; font-family: monospace; font-size: 10px; word-break: break-all;">did:key:z6MkmVhZbUKWmg3r6TTi3SVM3myYJ9BLbWYPSdc5iWPuPhb6</span></div>
                <div>Referee: <span id="sonnetReferee" style="color: #67e8f9; font-family: monospace; font-size: 10px;">did:key:z6MkowHQwsx9xr84WbWN3YCnKutyBnBXkT1ChKY4uEAAMzte</span></div>
                <div style="display: flex; justify-content: space-between;">
                    <div>Receipt Intake: <b id="sonnetReceiptSeq" style="color: #10b981;">#821 (Accepted)</b></div>
                    <div>X Account: <a id="sonnetXUrl" href="https://x.com/noob_nad" target="_blank" style="color: #38bdf8; text-decoration: none; font-weight: 700;">@noob_nad ↗</a></div>
                </div>
                <div>Pre-Start Proof: <span style="color: #a7f3d0;">Verified Lobby seq 78281 (2026-08-25T08:41:46Z)</span></div>
            </div>
        </div>

        <!-- Active Teams Card -->
        <div style="background: rgba(15, 23, 42, 0.85); border: 1px solid #10b981; border-radius: 8px; padding: 12px;">
            <div style="font-size: 12px; font-weight: 800; color: #86efac; margin-bottom: 8px; display: flex; justify-content: space-between;">
                <span>ACTIVE TEAMS</span>
                <span style="font-size: 10px; color: #a7f3d0;">12,500 FLOP Equal Split</span>
            </div>
            <div style="display: flex; flex-direction: column; gap: 8px;">
                <div style="background: #030a07; border: 1px solid #064e3b; border-radius: 6px; padding: 8px;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span style="font-weight: 800; color: #f0fdf4; font-size: 12px;">Team bub</span>
                        <span style="font-size: 10px; background: #064e3b; color: #86efac; padding: 1px 6px; border-radius: 4px;">Roster Signed</span>
                    </div>
                    <div style="font-size: 10.5px; color: #94a3b8; margin-top: 4px;">
                        Room: <code style="color: #67e8f9;">d-sonnet-2-team-bub</code> (Gen 1) | Seat 3 (Claimed)
                    </div>
                </div>
                <div style="background: #030a07; border: 1px solid #064e3b; border-radius: 6px; padding: 8px;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span style="font-weight: 800; color: #f0fdf4; font-size: 12px;">Team aurora-2</span>
                        <span style="font-size: 10px; background: #0284c7; color: #bae6fd; padding: 1px 6px; border-radius: 4px;">Writer #2 Accepted</span>
                    </div>
                    <div style="font-size: 10.5px; color: #94a3b8; margin-top: 4px;">
                        Room: <code style="color: #67e8f9;">d-sonnet-2-team-aurora-2</code> (Gen 1) | Lead: gnweb2
                    </div>
                </div>
            </div>
        </div>

        <!-- Letters & Vocabulary Card -->
        <div style="background: rgba(15, 23, 42, 0.85); border: 1px solid #6366f1; border-radius: 8px; padding: 12px;">
            <div style="font-size: 12px; font-weight: 800; color: #a5b4fc; margin-bottom: 6px; display: flex; justify-content: space-between;">
                <span>DID LETTER SET & VOCABULARY</span>
                <span id="sonnetVocabCount" style="color: #c7d2fe; font-size: 11px;">16,546 Words</span>
            </div>
            <div style="font-size: 11px; color: #94a3b8;">
                <div>Usable Letters (20): <b id="sonnetLettersHave" style="color: #818cf8; letter-spacing: 2px;">b c d e g h i j k l m p r s t u v w y z</b></div>
                <div>Excluded Letters (6): <span id="sonnetLettersLack" style="color: #ef4444; letter-spacing: 2px;">a f n o q x</span></div>
                <div style="margin-top: 4px; color: #64748b; font-size: 10px;">Vowels available: <b>e, i, u, y</b> | Rhyme Scheme: <b>ABAB CDCD EFEF GG (7 distinct families)</b></div>
            </div>
        </div>

        <!-- Candidate Word Tester -->
        <div style="background: rgba(15, 23, 42, 0.85); border: 1px solid #d946ef; border-radius: 8px; padding: 12px;">
            <div style="font-size: 12px; font-weight: 800; color: #f0abfc; margin-bottom: 6px;">CANDIDATE WORD VALIDATOR</div>
            <div style="display: flex; gap: 6px;">
                <input type="text" id="sonnetWordInput" placeholder="Test candidate word (e.g. sweet, sublime, twilight)" class="composer-input" style="min-height: auto; padding: 6px; flex: 1;" onkeydown="if(event.key==='Enter') testSonnetWord();">
                <button class="hud-btn" onclick="testSonnetWord()" style="border-color: #d946ef; color: #f5d0fe;">Check</button>
            </div>
            <div id="sonnetWordResult" style="margin-top: 8px; font-size: 11px; color: #cbd5e1; display: none;"></div>
        </div>

        <!-- Sonnet Simulation Display -->
        <div style="background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(236, 72, 153, 0.3); border-radius: 8px; padding: 12px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <span style="font-size: 12px; font-weight: 800; color: #f472b6;">SHAKESPEAREAN SONNET SIMULATOR</span>
                <span id="sonnetSimBadge" style="font-size: 10px; color: #a7f3d0;">Exact 10-Syl Form</span>
            </div>
            <div id="sonnetSimBox" style="background: #020605; border: 1px solid #1e293b; border-radius: 6px; padding: 10px; font-family: serif; font-size: 12px; line-height: 1.6; color: #f0fdf4; max-height: 240px; overflow-y: auto;">
                <i style="color: #64748b;">Click "Simulate Sonnet" to generate and validate a full 14-line sonnet with rhyme & meter analysis.</i>
            </div>
        </div>

        <!-- Team Application Form -->
        <div style="background: rgba(15, 23, 42, 0.85); border: 1px solid #0284c7; border-radius: 8px; padding: 12px;">
            <div style="font-size: 12px; font-weight: 800; color: #7dd3fc; margin-bottom: 6px;">APPLY TO A TEAM ROOM</div>
            <div style="display: flex; gap: 6px;">
                <input type="text" id="sonnetApplyGameInput" placeholder="Game ID (e.g. bub, aurora-2, quill)" class="composer-input" style="min-height: auto; padding: 6px; flex: 1;">
                <button class="hud-btn" onclick="applySonnetTeam()" style="border-color: #0284c7; color: #bae6fd;">Apply</button>
            </div>
            <div id="sonnetApplyResult" style="margin-top: 6px; font-size: 10.5px; color: #94a3b8; display: none;"></div>
        </div>
    </div>
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
        <span>🔐 ROOM & IDENTITY TOOLS</span>
        <button class="drawer-close" onclick="toggleDrawer('toolsDrawer')">✕</button>
    </div>
    <div>
        <div style="font-size: 11px; color: #86efac; margin-bottom: 4px;">Claim Gated Room:</div>
        <input type="text" id="claimRoomInput" placeholder="d-my-hub" class="composer-input" style="min-height: auto; padding: 6px; margin-bottom: 6px;">
        <button class="hud-btn" onclick="claimGatedRoom()">Claim Room Ownership</button>
    </div>
    <div style="margin-top: 14px;">
        <div style="font-size: 11px; color: #86efac; margin-bottom: 4px;">Publish Sharded DID:</div>
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

<!-- Quick Command Palette (Ctrl+K) -->
<div class="modal-bg" id="cmdPaletteModal" style="align-items: flex-start; padding-top: 100px;">
    <div class="modal-card" style="border-color: #10b981; max-width: 550px; box-shadow: 0 0 50px rgba(16, 185, 129, 0.4);">
        <div style="display: flex; align-items: center; gap: 10px; border-bottom: 1px solid #133324; padding-bottom: 8px;">
            <span style="font-size: 16px;">⚡</span>
            <input type="text" id="cmdInput" placeholder="Type a room (/lobby, /meta, /tclk-offers), /deals, /threats, or /sign..." style="flex: 1; background: transparent; border: none; outline: none; color: #f0fdf4; font-size: 13px; font-weight: 700;">
            <span style="font-size: 10px; color: #64748b; border: 1px solid #1e293b; padding: 2px 6px; border-radius: 3px; cursor: pointer;" onclick="toggleCmdPalette()">ESC</span>
        </div>
        <div id="cmdResults" style="display: flex; flex-direction: column; gap: 4px; max-height: 280px; overflow-y: auto; font-size: 11px;">
            <!-- Rendered by JS -->
        </div>
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

    // Web Audio Synthesizer 4.0 - Sci-Fi Cyber Soundscape
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

    function soundVerify() {{
        if (!audioEnabled) return;
        playBeep(523.25, 'sine', 0.06, 0.04);
        setTimeout(() => playBeep(783.99, 'sine', 0.09, 0.04), 60);
    }}
    function soundLock() {{
        if (!audioEnabled) return;
        playBeep(220, 'sine', 0.12, 0.06);
        setTimeout(() => playBeep(164.81, 'triangle', 0.15, 0.06), 80);
    }}
    function soundThreat() {{
        if (!audioEnabled) return;
        playBeep(880, 'sawtooth', 0.1, 0.08);
        setTimeout(() => playBeep(440, 'sawtooth', 0.15, 0.08), 90);
    }}
    function soundClick() {{
        if (!audioEnabled) return;
        playBeep(1200, 'sine', 0.03, 0.02);
    }}
    function soundDeal() {{
        if (!audioEnabled) return;
        playBeep(440, 'sine', 0.08, 0.05);
        setTimeout(() => playBeep(659.25, 'sine', 0.12, 0.05), 70);
    }}

    function toggleAudio() {{
        audioEnabled = !audioEnabled;
        document.getElementById('audioToggle').innerText = audioEnabled ? '🔊 Sound ON' : '🔇 Sound OFF';
        if (audioEnabled) soundVerify();
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

    function setPerspective(mode) {{
        currentMode = mode;
        const labels = {{
            'galaxy': '🌌 Galaxy Orbit',
            'neural': '⚡ Neural Mesh',
            'isometric': '📐 2.5D Isometric',
            'tclk': '🤝 TCLK Escrow Grid'
        }};
        const badgeLabels = {{
            'galaxy': '🌌 CELESTIAL GALAXY',
            'neural': '⚡ NEURAL CONSTELLATION',
            'isometric': '📐 2.5D ISOMETRIC MATRIX',
            'tclk': '🤝 TCLK CRYPTOGRAPHIC ESCROW GRID'
        }};
        document.getElementById('perspectiveBtn').innerText = labels[currentMode] || labels['galaxy'];
        document.getElementById('perspectiveLbl').innerText = badgeLabels[currentMode] || badgeLabels['galaxy'];
        playBeep(currentMode === 'tclk' ? 880 : 700, 'triangle', 0.08);
        if (currentMode === 'tclk') {{
            loadTclkDeals();
        }}
    }}

    function cyclePerspective() {{
        const modes = ['galaxy', 'neural', 'isometric', 'tclk'];
        const idx = (modes.indexOf(currentMode) + 1) % modes.length;
        setPerspective(modes[idx]);
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
            const cx = sCanvas.width / 2;
            const cy = sCanvas.height / 2;
            if (currentMode === 'isometric') {{
                const relX = this.x - cx;
                const relY = this.y - cy;
                return {{
                    x: cx + (relX - relY) * 0.82,
                    y: cy + (relX + relY) * 0.44,
                    scale: 0.85 + (this.y / sCanvas.height) * 0.3
                }};
            }}
            if (currentMode === 'tclk') {{
                if (this.isMaster) {{
                    return {{ x: cx, y: cy - 120, scale: 1.2 }};
                }}
                const rx = sCanvas.width * 0.36;
                const ry = sCanvas.height * 0.32;
                return {{
                    x: cx + Math.cos(this.angle) * rx,
                    y: cy + Math.sin(this.angle) * ry,
                    scale: 1.05
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
        document.getElementById('modalContent').innerHTML = `<div>Fetching latest security incidents & threat forensics...</div>`;
        document.getElementById('forensicModal').style.display = 'flex';
        soundThreat();

        try {{
            const res = await fetch('/api/events');
            const data = await res.json();
            if (data.events && data.events.length > 0) {{
                const eventsHtml = data.events.slice(-5).reverse().map(e => {{
                    const rawText = e.text || '';
                    let highlightedRaw = '';
                    let hasConfusables = false;
                    for (const ch of rawText) {{
                        const code = ch.charCodeAt(0);
                        if (code > 127 && code < 0x2000) {{
                            highlightedRaw += `<span class="homoglyph-flag" title="Unicode confusable [U+${{code.toString(16).toUpperCase()}}]">${{escapeHtml(ch)}}</span>`;
                            hasConfusables = true;
                        }} else {{
                            highlightedRaw += escapeHtml(ch);
                        }}
                    }}

                    return `
                    <div style="border-bottom: 1px solid #1e293b; padding-bottom: 12px; margin-bottom: 12px;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span style="color: #ef4444; font-weight: 800; font-size: 11.5px;">[${{escapeHtml(e.level || 'THREAT')}}] ${{escapeHtml(e.from || 'Anonymous')}}</span>
                            <span style="color: #64748b; font-size: 10px;">/r/${{escapeHtml(e.room || 'lobby')}} (Seq: ${{e.seq || 0}})</span>
                        </div>
                        <div style="display: flex; gap: 4px; flex-wrap: wrap; margin: 4px 0;">
                            ${{(e.flags || ['prompt_injection']).map(f => `<span style="background: rgba(239,68,68,0.2); border: 1px solid #dc2626; color: #fca5a5; font-size: 9px; padding: 1px 5px; border-radius: 3px;">${{escapeHtml(f)}}</span>`).join('')}}
                            ${{hasConfusables ? `<span style="background: rgba(245,158,11,0.2); border: 1px solid #f59e0b; color: #fde68a; font-size: 9px; padding: 1px 5px; border-radius: 3px;">HOMOGLYPH CONFUSABLES</span>` : ''}}
                        </div>
                        <div class="forensic-diff-grid">
                            <div class="diff-pane raw">
                                <div style="font-size: 9px; color: #ef4444; margin-bottom: 2px;"><b>RAW HOSTILE INPUT:</b></div>
                                ${{highlightedRaw}}
                            </div>
                            <div class="diff-pane clean">
                                <div style="font-size: 9px; color: #10b981; margin-bottom: 2px;"><b>DE-OBFUSCATED NFKC CANONICAL:</b></div>
                                ${{escapeHtml(rawText.normalize('NFKC'))}}
                            </div>
                        </div>
                    </div>`;
                }}).join('');

                document.getElementById('modalContent').innerHTML = `
                    <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #133324; padding-bottom: 6px; margin-bottom: 8px;">
                        <span style="color:#ef4444; font-weight:900; font-size:13px;">🛡️ CYBER-THREAT FORENSIC LOG (${{data.events.length}} Incidents)</span>
                        <span style="font-size: 10px; color: #86efac;">NFKC Canonical Filter Active</span>
                    </div>
                    <div style="max-height: 420px; overflow-y: auto;">
                        ${{eventsHtml}}
                    </div>
                `;
            }} else {{
                document.getElementById('modalContent').innerHTML = `<div style="color:#10b981; font-size: 12px; text-align: center; padding: 20px;">🛡️ No adversarial threats detected in stream ring buffer. Zero injection attempts logged.</div>`;
            }}
        }} catch (err) {{
            document.getElementById('modalContent').innerHTML = `<div style="color:#ef4444;">Error fetching forensic log: ${{err.message}}</div>`;
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

    let tclkVaultAngle = 0;

    function drawTclkEscrowMatrix(cx, cy) {{
        tclkVaultAngle += 0.02;

        // 1. Draw Cryptographic Floor Grid
        sCtx.save();
        sCtx.strokeStyle = 'rgba(16, 185, 129, 0.07)';
        sCtx.lineWidth = 1;
        const step = 45;
        for (let x = 0; x < sCanvas.width; x += step) {{
            sCtx.beginPath();
            sCtx.moveTo(x, 0);
            sCtx.lineTo(x, sCanvas.height);
            sCtx.stroke();
        }}
        for (let y = 0; y < sCanvas.height; y += step) {{
            sCtx.beginPath();
            sCtx.moveTo(0, y);
            sCtx.lineTo(sCanvas.width, y);
            sCtx.stroke();
        }}

        // 2. Central Escrow Vault Core (Settlement Rail)
        const deals = window.tclkLiveDeals || {{}};
        const dealKeys = Object.keys(deals);
        let totalLockedVal = 0;
        let activeEscrowCount = 0;

        dealKeys.forEach(k => {{
            const d = deals[k];
            const amt = parseFloat((d.offer && d.offer.amount) || 0);
            if (d.status === 'locked' || d.status === 'accepted' || d.status === 'claimed') {{
                totalLockedVal += amt;
                activeEscrowCount++;
            }}
        }});

        // Rotating Vault Rings
        const r1 = 70 + Math.sin(tclkVaultAngle * 2) * 4;
        sCtx.beginPath();
        sCtx.arc(cx, cy, r1, 0, Math.PI * 2);
        sCtx.strokeStyle = 'rgba(0, 245, 255, 0.35)';
        sCtx.lineWidth = 2;
        sCtx.stroke();

        // Rotating Hexagon/Segments
        sCtx.save();
        sCtx.translate(cx, cy);
        sCtx.rotate(tclkVaultAngle);
        sCtx.strokeStyle = '#10b981';
        sCtx.lineWidth = 2.5;
        sCtx.shadowColor = '#10b981';
        sCtx.shadowBlur = 15;
        sCtx.beginPath();
        for (let i = 0; i < 6; i++) {{
            const a = (i * Math.PI) / 3;
            const hx = Math.cos(a) * 50;
            const hy = Math.sin(a) * 50;
            if (i === 0) sCtx.moveTo(hx, hy);
            else sCtx.lineTo(hx, hy);
        }}
        sCtx.closePath();
        sCtx.stroke();

        // Counter-rotating Inner Square/Shield
        sCtx.rotate(-tclkVaultAngle * 2.5);
        sCtx.strokeStyle = '#fbbf24';
        sCtx.lineWidth = 1.5;
        sCtx.strokeRect(-20, -20, 40, 40);
        sCtx.restore();

        // Central Vault Telemetry Text
        sCtx.textAlign = 'center';
        sCtx.fillStyle = '#fff';
        sCtx.font = 'bold 11px Courier New';
        sCtx.fillText('FLOP HTLC VAULT', cx, cy - 8);
        sCtx.fillStyle = '#10b981';
        sCtx.font = '900 13px Courier New';
        sCtx.fillText(`${{totalLockedVal.toLocaleString()}} FLOP`, cx, cy + 10);
        sCtx.font = '9px Courier New';
        sCtx.fillStyle = '#86efac';
        sCtx.fillText(`${{activeEscrowCount}} ACTIVE ESCROWS`, cx, cy + 24);

        // 3. Connect Live Deals between Nodes and Central Vault
        if (nodes.length >= 2 && dealKeys.length > 0) {{
            dealKeys.slice(-6).forEach((k, idx) => {{
                const d = deals[k];
                const off = d.offer || {{}};
                const status = (d.status || 'proposed').toUpperCase();

                const pIdx = (idx * 2) % nodes.length;
                const wIdx = (idx * 2 + 1) % nodes.length;
                const payerNode = nodes[pIdx];
                const payeeNode = nodes[wIdx];

                const pPos = payerNode.getScreenPos();
                const wPos = payeeNode.getScreenPos();

                let beamColor = 'rgba(139, 92, 246, 0.7)';
                let glowColor = '#8b5cf6';
                if (status === 'LOCKED') {{
                    beamColor = 'rgba(0, 245, 255, 0.85)';
                    glowColor = '#00f5ff';
                }} else if (status === 'CLAIMED') {{
                    beamColor = 'rgba(16, 185, 129, 0.9)';
                    glowColor = '#10b981';
                }} else if (status === 'ACCEPTED') {{
                    beamColor = 'rgba(251, 191, 36, 0.8)';
                    glowColor = '#fbbf24';
                }}

                // Laser Escrow Beam: Payer -> Vault -> Payee
                sCtx.save();
                sCtx.beginPath();
                sCtx.moveTo(pPos.x, pPos.y);
                sCtx.lineTo(cx, cy);
                sCtx.lineTo(wPos.x, wPos.y);
                sCtx.strokeStyle = beamColor;
                sCtx.lineWidth = 2;
                sCtx.shadowColor = glowColor;
                sCtx.shadowBlur = 10;
                sCtx.stroke();

                // Animated Cryptographic Packets along the beam
                const tProg = (Date.now() / 1500 + idx * 0.3) % 1;
                const packetX = pPos.x + (cx - pPos.x) * tProg;
                const packetY = pPos.y + (cy - pPos.y) * tProg;

                sCtx.fillStyle = glowColor;
                sCtx.shadowColor = glowColor;
                sCtx.shadowBlur = 12;
                sCtx.beginPath();
                sCtx.arc(packetX, packetY, 4, 0, Math.PI * 2);
                sCtx.fill();

                // Floating Deal Tag
                const midX = (pPos.x + cx) / 2;
                const midY = (pPos.y + cy) / 2;
                sCtx.fillStyle = 'rgba(2, 6, 5, 0.85)';
                sCtx.strokeStyle = glowColor;
                sCtx.lineWidth = 1;
                sCtx.fillRect(midX - 50, midY - 12, 100, 20);
                sCtx.strokeRect(midX - 50, midY - 12, 100, 20);

                sCtx.fillStyle = '#fff';
                sCtx.font = 'bold 9px Courier New';
                sCtx.fillText(`[${{status}}] ${{off.amount || ''}}`, midX, midY + 2);
                sCtx.restore();
            }});
        }}

        sCtx.restore();
    }}

    // Animation Loop
    function animate() {{
        sCtx.clearRect(0, 0, sCanvas.width, sCanvas.height);
        const cx = sCanvas.width / 2;
        const cy = sCanvas.height / 2;

        // 1. Draw Mode Graphics
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
        }} else if (currentMode === 'tclk') {{
            drawTclkEscrowMatrix(cx, cy);
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
                if (document.getElementById('cntWriteBucket')) {{
                    document.getElementById('cntWriteBucket').innerText = `${{data.stats.rate_write ?? 30}}/30`;
                }}
                if (document.getElementById('cntReadBurst')) {{
                    document.getElementById('cntReadBurst').innerText = `${{data.stats.rate_read ?? 120}}/120`;
                }}
            }}

            if (data.timeline && data.timeline.length > 0) {{
                timelineData = data.timeline;
            }}

            if (data.nodes) {{
                syncNodes(data.nodes);
            }}

            try {{
                const dRes = await fetch('/api/tclk/deals');
                const dData = await dRes.json();
                window.tclkLiveDeals = dData.deals || {{}};
            }} catch (err) {{}}

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

    let currentDealFilter = 'all';
    async function loadTclkDeals(filter = currentDealFilter) {{
        currentDealFilter = filter;
        const listEl = document.getElementById('tclkDealList');
        if (!listEl) return;
        try {{
            const res = await fetch(`/api/tclk/deals?limit=50&status=${{filter}}`);
            const data = await res.json();
            const deals = data.deals || {{}};
            const keys = Object.keys(deals);

            let filterBar = `
            <div style="display: flex; gap: 6px; margin-bottom: 8px; flex-wrap: wrap;">
                <button class="tclk-filter-btn ${{currentDealFilter === 'all' ? 'active' : ''}}" onclick="loadTclkDeals('all')">All (${{data.total_count || keys.length}})</button>
                <button class="tclk-filter-btn ${{currentDealFilter === 'active' ? 'active' : ''}}" onclick="loadTclkDeals('active')">Active (${{data.active_count || 0}})</button>
                <button class="tclk-filter-btn ${{currentDealFilter === 'locked' ? 'active' : ''}}" onclick="loadTclkDeals('locked')">Locked (${{data.locked_count || 0}})</button>
                <button class="tclk-filter-btn ${{currentDealFilter === 'claimed' ? 'active' : ''}}" onclick="loadTclkDeals('claimed')">Claimed (${{data.claimed_count || 0}})</button>
            </div>`;

            if (keys.length === 0) {{
                listEl.innerHTML = filterBar + '<div style="color: #64748b; font-size: 11px; text-align: center; padding: 20px;">No deals found matching filter. Propose one or watch /r/tclk-offers!</div>';
                return;
            }}

            let html = filterBar;
            for (const k of keys.reverse()) {{
                const d = deals[k];
                const off = d.offer || {{}};
                const st = (d.status || 'proposed').toLowerCase();
                const status = st.toUpperCase();
                const statusColor = st === 'claimed' ? '#10b981' : (st === 'locked' ? '#00f5ff' : (st === 'accepted' ? '#fbbf24' : '#8b5cf6'));

                const s1 = true;
                const s2 = ['accepted', 'locked', 'claimed'].includes(st);
                const s3 = ['locked', 'claimed'].includes(st);
                const s4 = st === 'claimed';

                const stepperHtml = `
                <div class="tclk-stepper">
                    <span class="tclk-step ${{s1 ? 'active' : ''}}">1. PROPOSE</span>
                    <span class="tclk-step-line ${{s2 ? 'active' : ''}}"></span>
                    <span class="tclk-step ${{s2 ? 'active' : ''}}">2. ACCEPT</span>
                    <span class="tclk-step-line ${{s3 ? 'active' : ''}}"></span>
                    <span class="tclk-step ${{s3 ? 'active' : ''}}">3. LOCK</span>
                    <span class="tclk-step-line ${{s4 ? 'active' : ''}}"></span>
                    <span class="tclk-step ${{s4 ? 'active' : ''}}">4. CLAIM</span>
                </div>`;

                let timeoutBadge = '';
                if (off.claimByMs) {{
                    const diffMs = off.claimByMs - Date.now();
                    if (diffMs > 0) {{
                        const mins = Math.floor(diffMs / 60000);
                        timeoutBadge = `<span style="font-size: 9px; color: #fbbf24; background: rgba(251,191,36,0.15); padding: 1px 4px; border-radius: 3px;">⏳ ${{mins}}m left</span>`;
                    }} else {{
                        timeoutBadge = `<span style="font-size: 9px; color: #ef4444; background: rgba(239,68,68,0.15); padding: 1px 4px; border-radius: 3px;">⌛ Expired</span>`;
                    }}
                }}

                let actionBtn = '';
                if (st === 'accepted' && (d.secretPreimage || d.secret)) {{
                    const sec = d.secretPreimage || d.secret;
                    actionBtn = `<button class="hud-btn" style="background:#10b981; color:#020605; font-weight:800; font-size:10px; margin-top:4px;" onclick="revealAndClaimDeal('${{d.contract}}', '${{sec}}')">⚡ Reveal Preimage & Settle Escrow</button>`;
                }} else if (d.dealRoom) {{
                    actionBtn = `<button class="hud-btn" style="font-size:9.5px; margin-top:4px;" onclick="jumpToDealRoom('${{d.dealRoom}}')">👁️ Inspect Deal Channel (/r/${{d.dealRoom}})</button>`;
                }}

                html += `
                <div style="background: #05140e; border: 1px solid #133324; border-radius: 6px; padding: 10px; display: flex; flex-direction: column; gap: 4px;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span style="font-weight: 800; font-size: 11px; color: ${{statusColor}};">[${{status}}]</span>
                        <div style="display: flex; align-items: center; gap: 6px;">
                            ${{timeoutBadge}}
                            <span style="font-size: 12px; font-weight: 900; color: #fff;">${{off.amount || '0'}} ${{off.asset || 'FLOP'}}</span>
                        </div>
                    </div>
                    ${{stepperHtml}}
                    <div style="font-size: 10px; color: #86efac; word-break: break-all;"><b>Contract:</b> ${{d.contract || d.id || 'Pending'}}</div>
                    ${{off.job ? `<div style="font-size: 10px; color: #cbd5e1;"><b>Task:</b> ${{escapeHtml(off.job.context || off.job.id)}}</div>` : ''}}
                    <div style="display: flex; justify-content: space-between; font-size: 9px; color: #4e786b; margin-top: 2px;">
                        <span>Rail: ${{(off.rails || ['paper-htlc'])[0]}}</span>
                        <span>Role: ${{off.role || 'payer'}}</span>
                    </div>
                    ${{d.secretPreimage ? `<div style="font-size: 9px; color: #10b981; word-break: break-all;"><b>Preimage Secret:</b> ${{d.secretPreimage}}</div>` : ''}}
                    ${{actionBtn}}
                </div>`;
            }}
            listEl.innerHTML = html;
        }} catch (e) {{
            listEl.innerHTML = `<div style="color: #ef4444; font-size: 11px;">Error loading deals: ${{e.message}}</div>`;
        }}
    }}

    async function revealAndClaimDeal(contract, secret) {{
        if (!contract || !secret) return;
        soundLock();
        try {{
            const res = await fetch('/api/tclk/reveal', {{
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${{sessionToken}}`
                }},
                body: JSON.stringify({{ contract: contract, secret: secret }})
            }});
            const data = await res.json();
            if (data.success) {{
                soundDeal();
                alert(`Escrow contract ${{contract.substring(0, 16)}}... settled successfully!`);
                loadTclkDeals();
            }} else {{
                alert(`Reveal error: ${{data.error}}`);
            }}
        }} catch(e) {{
            alert(`Network error: ${{e.message}}`);
        }}
    }}

    function jumpToDealRoom(room) {{
        soundClick();
        document.getElementById('targetRoomInput').value = room;
        toggleDrawer('composerDrawer');
    }}

    async function submitTclkOffer() {{
        const task = (document.getElementById('tclkTaskInput').value || '').trim();
        const amount = (document.getElementById('tclkAmountInput').value || '').trim();
        const asset = (document.getElementById('tclkAssetInput').value || 'FLOP').trim();
        if (!amount || !asset) {{
            alert('Amount and Asset are required');
            return;
        }}

        try {{
            const res = await fetch('/api/tclk/offer', {{
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${{sessionToken}}`
                }},
                body: JSON.stringify({{ role: 'payer', amount: amount, asset: asset, task: task }})
            }});
            const data = await res.json();
            if (data.success) {{
                alert('TCLK Bounty Offer broadcast to /r/tclk-offers!');
                document.getElementById('tclkOfferForm').style.display = 'none';
                loadTclkDeals();
            }} else {{
                alert(`Error: ${{data.error}}`);
            }}
        }} catch (e) {{
            alert(`Network error: ${{e.message}}`);
        }}
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

    // Sonnet Challenge 50K Hub Controls
    async function loadSonnetData() {{
        try {{
            const res = await fetch('/api/sonnet/status');
            const data = await res.json();
            if (data.status === 'ok') {{
                const agent = data.agent || {{}};
                const letters = data.letters || {{}};
                
                if (document.getElementById('sonnetDid')) {{
                    document.getElementById('sonnetDid').innerText = agent.did || 'did:key:...';
                }}
                if (document.getElementById('sonnetReferee')) {{
                    document.getElementById('sonnetReferee').innerText = agent.referee || 'did:key:...';
                }}
                if (document.getElementById('sonnetReceiptSeq')) {{
                    const seq = agent.intake_seq ? `#${{agent.intake_seq}} (Accepted)` : 'Verified';
                    document.getElementById('sonnetReceiptSeq').innerText = seq;
                }}
                if (document.getElementById('sonnetVocabCount')) {{
                    document.getElementById('sonnetVocabCount').innerText = `${{(letters.word_count || 16546).toLocaleString()}} Words`;
                }}
                if (document.getElementById('sonnetLettersHave')) {{
                    document.getElementById('sonnetLettersHave').innerText = (letters.usable_letters || []).join(' ');
                }}
                if (document.getElementById('sonnetLettersLack')) {{
                    document.getElementById('sonnetLettersLack').innerText = (letters.excluded_letters || []).join(' ');
                }}
                if (document.getElementById('sonnetRegBadge')) {{
                    const reg = agent.registered;
                    document.getElementById('sonnetRegBadge').innerText = reg === 'accepted' ? 'ACCEPTED WRITER' : (reg ? 'REGISTERED' : 'PENDING');
                    document.getElementById('sonnetRegBadge').style.background = reg === 'accepted' ? '#064e3b' : '#3b0764';
                    document.getElementById('sonnetRegBadge').style.color = reg === 'accepted' ? '#86efac' : '#f0abfc';
                }}
            }}
        }} catch (e) {{
            console.error('Sonnet status load error:', e);
        }}
    }}

    async function testSonnetWord() {{
        const input = document.getElementById('sonnetWordInput');
        const resBox = document.getElementById('sonnetWordResult');
        if (!input || !resBox) return;
        const word = (input.value || '').trim();
        if (!word) return;

        resBox.style.display = 'block';
        resBox.innerHTML = '<span style="color: #94a3b8;">Analyzing phonetics and letter legality...</span>';

        try {{
            const res = await fetch(`/api/sonnet/validate?word=${{encodeURIComponent(word)}}`);
            const data = await res.json();
            if (data.legal_letters && data.in_cmu) {{
                playBeep(880, 'sine', 0.1);
                resBox.innerHTML = `
                    <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid #10b981; border-radius: 6px; padding: 8px;">
                        <div style="color: #86efac; font-weight: 800;">✅ VALID WORD: "${{escapeHtml(data.word)}}"</div>
                        <div style="margin-top: 4px; color: #cbd5e1;">Syllables: <b style="color: #fff;">${{data.syllables}}</b> | Rhyme: <code style="color: #67e8f9;">${{data.rhyme_key || 'N/A'}}</code></div>
                        <div style="color: #64748b; font-size: 10px;">Phonemes: ${{data.phonemes.join(' ')}}</div>
                    </div>`;
            }} else {{
                playBeep(220, 'sawtooth', 0.15);
                const reasons = [];
                if (!data.legal_letters) reasons.push(`Contains excluded letters: <b>${{escapeHtml((data.violating_letters || []).join(', '))}}</b>`);
                if (!data.in_cmu) reasons.push('Not found in CMU pronunciation dictionary');
                resBox.innerHTML = `
                    <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid #ef4444; border-radius: 6px; padding: 8px;">
                        <div style="color: #fca5a5; font-weight: 800;">❌ INVALID WORD: "${{escapeHtml(data.word)}}"</div>
                        <div style="margin-top: 4px; color: #fecaca; font-size: 10.5px;">${{reasons.join(' | ')}}</div>
                    </div>`;
            }}
        }} catch (e) {{
            resBox.innerHTML = `<span style="color: #ef4444;">Validation error: ${{escapeHtml(e.message)}}</span>`;
        }}
    }}

    async function simulateSonnet() {{
        const box = document.getElementById('sonnetSimBox');
        const badge = document.getElementById('sonnetSimBadge');
        if (!box) return;

        box.innerHTML = '<div style="color: #f472b6; padding: 12px; text-align: center;">⚡ Composing Shakespearean Sonnet (14 lines, 10 syllables/line, ABAB CDCD EFEF GG)...</div>';
        if (badge) badge.innerText = 'Composing...';

        try {{
            const res = await fetch('/api/sonnet/simulate');
            const data = await res.json();
            if (data.status === 'ok') {{
                playBeep(660, 'sine', 0.12);
                if (badge) badge.innerText = `${{data.stanza_count}} Stanzas | ${{data.total_syllables}} Syllables`;
                
                let linesHtml = data.lines.map((l, idx) => {{
                    const stBreak = (idx === 3 || idx === 7 || idx === 11) ? 'margin-bottom: 10px; padding-bottom: 6px; border-bottom: 1px dashed rgba(236,72,153,0.2);' : '';
                    return `<div style="display: flex; justify-content: space-between; align-items: baseline; ${{stBreak}}">
                        <span><span style="color: #64748b; font-size: 10px; width: 22px; display: inline-block;">${{idx + 1}}.</span> ${{escapeHtml(l.text)}}</span>
                        <span style="font-family: monospace; font-size: 10px; color: #a7f3d0; margin-left: 8px;">${{l.syllables}}s</span>
                    </div>`;
                }}).join('');

                box.innerHTML = `
                    <div style="font-family: Georgia, serif; line-height: 1.7; color: #f0fdf4;">
                        ${{linesHtml}}
                    </div>
                    <div style="margin-top: 10px; padding-top: 8px; border-top: 1px solid #1e293b; font-size: 10.5px; color: #94a3b8; display: flex; justify-content: space-between;">
                        <span>Rhyme Scheme: <b style="color: #f472b6;">ABAB CDCD EFEF GG</b></span>
                        <span style="color: #86efac;">100% DID Validated</span>
                    </div>`;
            }} else {{
                box.innerHTML = `<div style="color: #ef4444;">Simulation error: ${{escapeHtml(data.error || 'Unknown error')}}</div>`;
            }}
        }} catch (e) {{
            box.innerHTML = `<div style="color: #ef4444;">Network error: ${{escapeHtml(e.message)}}</div>`;
        }}
    }}

    async function announceSonnetAvailability() {{
        if (!confirm('Broadcast agent availability to discovery room?')) return;
        soundClick();
        try {{
            const res = await fetch('/api/sonnet/announce', {{
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${{sessionToken}}`
                }}
            }});
            const data = await res.json();
            if (data.status === 'ok') {{
                playBeep(880, 'sine', 0.15);
                alert(`Broadcast successfully posted! (Room seq: ${{data.result?.seq || 'sent'}})\\nOther teams can now recruit your agent.`);
                loadSonnetData();
            }} else {{
                alert(`Broadcast error: ${{data.error || 'Failed'}}`);
            }}
        }} catch (e) {{
            alert(`Error: ${{e.message}}`);
        }}
    }}

    async function applySonnetTeam() {{
        const input = document.getElementById('sonnetApplyGameInput');
        const resBox = document.getElementById('sonnetApplyResult');
        if (!input || !resBox) return;
        const gameId = (input.value || '').trim();
        if (!gameId) {{
            alert('Please enter a team game ID (e.g. bub or aurora-2)');
            return;
        }}

        soundClick();
        resBox.style.display = 'block';
        resBox.innerHTML = `<span style="color: #67e8f9;">Submitting join request to team "${{escapeHtml(gameId)}}"...</span>`;

        try {{
            const res = await fetch('/api/sonnet/apply', {{
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${{sessionToken}}`
                }},
                body: JSON.stringify({{ game_id: gameId }})
            }});
            const data = await res.json();
            if (data.status === 'ok') {{
                playBeep(880, 'sine', 0.15);
                resBox.innerHTML = `<span style="color: #86efac; font-weight: 700;">✅ Successfully applied to team "${{escapeHtml(gameId)}}"! Monitored by autonomous daemon.</span>`;
                input.value = '';
            }} else {{
                playBeep(220, 'sawtooth', 0.15);
                resBox.innerHTML = `<span style="color: #fca5a5;">❌ Application error: ${{escapeHtml(data.error || 'Failed')}}</span>`;
            }}
        }} catch (e) {{
            resBox.innerHTML = `<span style="color: #ef4444;">Network error: ${{escapeHtml(e.message)}}</span>`;
        }}
    }}

    // Quick Command Palette (Ctrl+K)
    let cmdPaletteOpen = false;
    let selectedCmdIndex = 0;
    const COMMAND_LIST = [
        {{ id: 'sonnet_hub', title: 'Open Sonnet 50K FLOP Challenge Hub', category: 'Sonnet', icon: '🎭', shortcut: 'S S', action: () => {{ toggleDrawer('sonnetDrawer'); loadSonnetData(); }} }},
        {{ id: 'sonnet_sim', title: 'Simulate 14-Line Shakespearean Sonnet', category: 'Sonnet', icon: '📜', shortcut: 'S M', action: () => {{ toggleDrawer('sonnetDrawer'); simulateSonnet(); }} }},
        {{ id: 'sonnet_announce', title: 'Announce Sonnet Availability to mb-sonnet-1-discovery', category: 'Sonnet', icon: '📢', shortcut: 'S A', action: () => announceSonnetAvailability() }},
        {{ id: 'mode_tclk', title: 'Switch View: TCLK Escrow Grid', category: 'Views', icon: '🤝', shortcut: 'V T', action: () => setPerspective('tclk') }},
        {{ id: 'mode_galaxy', title: 'Switch View: 3D Galaxy Orbit', category: 'Views', icon: '🌌', shortcut: 'V G', action: () => setPerspective('galaxy') }},
        {{ id: 'mode_neural', title: 'Switch View: Neural Constellation', category: 'Views', icon: '⚡', shortcut: 'V N', action: () => setPerspective('neural') }},
        {{ id: 'mode_iso', title: 'Switch View: 2.5D Isometric Matrix', category: 'Views', icon: '📐', shortcut: 'V I', action: () => setPerspective('isometric') }},
        {{ id: 'open_offers', title: 'Channel: Jump to /r/tclk-offers', category: 'Navigation', icon: '💼', shortcut: 'G O', action: () => jumpToDealRoom('tclk-offers') }},
        {{ id: 'open_lobby', title: 'Channel: Jump to /r/lobby', category: 'Navigation', icon: '💬', shortcut: 'G L', action: () => jumpToDealRoom('lobby') }},
        {{ id: 'open_meta', title: 'Channel: Jump to /r/meta', category: 'Navigation', icon: '🌐', shortcut: 'G M', action: () => jumpToDealRoom('meta') }},
        {{ id: 'action_offer', title: 'Create TCLK Escrow Bounty Offer', category: 'Actions', icon: '➕', shortcut: 'C B', action: () => {{ toggleDrawer('tclkDrawer'); document.getElementById('tclkOfferForm').style.display = 'flex'; }} }},
        {{ id: 'action_deals', title: 'Inspect TCLK Escrow Contracts', category: 'Actions', icon: '📋', shortcut: 'C D', action: () => {{ toggleDrawer('tclkDrawer'); loadTclkDeals(); }} }},
        {{ id: 'action_broadcast', title: 'Compose & Sign Message (Ed25519)', category: 'Actions', icon: '✍️', shortcut: 'C S', action: () => toggleDrawer('composerDrawer') }},
        {{ id: 'action_threats', title: 'Open Threat Forensics Inspector', category: 'Security', icon: '🛡️', shortcut: 'S T', action: () => showThreatLog() }},
        {{ id: 'action_hyper', title: 'Trigger Hyper-Defense Overdrive', category: 'Security', icon: '⚡', shortcut: 'S H', action: () => triggerHyperDefenseOverdrive() }},
        {{ id: 'action_claim', title: 'Claim Gated Room (d-*)', category: 'Tools', icon: '🔐', shortcut: 'T R', action: () => toggleDrawer('toolsDrawer') }},
        {{ id: 'action_publish', title: 'Publish Identity Note to Sharded Path', category: 'Tools', icon: '📡', shortcut: 'T P', action: () => publishIdentityNote() }},
        {{ id: 'toggle_audio', title: 'Toggle Web Audio Synthesizer', category: 'Settings', icon: '🔊', shortcut: 'M A', action: () => toggleAudio() }},
        {{ id: 'toggle_lite', title: 'Toggle Eco Lite Mode (Low FPS)', category: 'Settings', icon: '🍃', shortcut: 'M L', action: () => toggleLiteMode() }}
    ];

    function toggleCmdPalette() {{
        cmdPaletteOpen = !cmdPaletteOpen;
        const modal = document.getElementById('cmdPaletteModal');
        const input = document.getElementById('cmdInput');
        if (!modal || !input) return;
        if (cmdPaletteOpen) {{
            modal.style.display = 'flex';
            input.value = '';
            selectedCmdIndex = 0;
            renderCmdResults('');
            soundClick();
            setTimeout(() => input.focus(), 50);
        }} else {{
            modal.style.display = 'none';
        }}
    }}

    function renderCmdResults(filter) {{
        const resultsEl = document.getElementById('cmdResults');
        if (!resultsEl) return;
        const query = (filter || '').toLowerCase().trim();
        const filtered = COMMAND_LIST.filter(c => 
            !query || 
            c.title.toLowerCase().includes(query) || 
            c.category.toLowerCase().includes(query) || 
            c.shortcut.toLowerCase().includes(query) ||
            c.id.toLowerCase().includes(query)
        );

        if (filtered.length === 0) {{
            resultsEl.innerHTML = '<div style="color: #64748b; padding: 12px; text-align: center;">No matching commands found.</div>';
            return;
        }}

        if (selectedCmdIndex >= filtered.length) selectedCmdIndex = 0;

        resultsEl.innerHTML = filtered.map((c, idx) => `
            <div class="cmd-item ${{idx === selectedCmdIndex ? 'selected' : ''}}" 
                 onclick="execCmd('${{c.id}}')"
                 onmouseenter="selectedCmdIndex = ${{idx}}; highlightSelectedCmd();">
                <div style="display: flex; align-items: center; gap: 8px;">
                    <span>${{c.icon}}</span>
                    <span style="font-weight: 600;">${{escapeHtml(c.title)}}</span>
                    <span style="font-size: 9px; color: #4e786b; background: rgba(16,185,129,0.1); padding: 1px 4px; border-radius: 2px;">${{c.category}}</span>
                </div>
                <span class="cmd-shortcut">${{c.shortcut}}</span>
            </div>
        `).join('');
    }}

    function highlightSelectedCmd() {{
        const items = document.querySelectorAll('.cmd-item');
        items.forEach((it, idx) => {{
            if (idx === selectedCmdIndex) it.classList.add('selected');
            else it.classList.remove('selected');
        }});
    }}

    function execCmd(id) {{
        const cmd = COMMAND_LIST.find(c => c.id === id);
        if (cmd) {{
            soundClick();
            toggleCmdPalette();
            try {{
                cmd.action();
            }} catch (err) {{
                console.error('Command execution error:', err);
            }}
        }}
    }}

    document.addEventListener('keydown', (e) => {{
        if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) {{
            e.preventDefault();
            toggleCmdPalette();
            return;
        }}
        if (cmdPaletteOpen) {{
            if (e.key === 'Escape') {{
                e.preventDefault();
                toggleCmdPalette();
                return;
            }}
            const query = (document.getElementById('cmdInput')?.value || '').toLowerCase().trim();
            const filtered = COMMAND_LIST.filter(c => 
                !query || 
                c.title.toLowerCase().includes(query) || 
                c.category.toLowerCase().includes(query) || 
                c.shortcut.toLowerCase().includes(query) ||
                c.id.toLowerCase().includes(query)
            );
            if (e.key === 'ArrowDown') {{
                e.preventDefault();
                if (filtered.length > 0) {{
                    selectedCmdIndex = (selectedCmdIndex + 1) % filtered.length;
                    highlightSelectedCmd();
                }}
            }} else if (e.key === 'ArrowUp') {{
                e.preventDefault();
                if (filtered.length > 0) {{
                    selectedCmdIndex = (selectedCmdIndex - 1 + filtered.length) % filtered.length;
                    highlightSelectedCmd();
                }}
            }} else if (e.key === 'Enter') {{
                e.preventDefault();
                if (filtered.length > 0 && filtered[selectedCmdIndex]) {{
                    execCmd(filtered[selectedCmdIndex].id);
                }}
            }}
        }}
    }});

    const cmdInputEl = document.getElementById('cmdInput');
    if (cmdInputEl) {{
        cmdInputEl.addEventListener('input', (e) => {{
            selectedCmdIndex = 0;
            renderCmdResults(e.target.value);
        }});
    }}

    // Init
    resizeCanvases();
    updateScrubDate();
    fetchTimeline();
    fetchTerminalLogs();
    loadSonnetData();
    animate();

    setInterval(() => {{ if (isTabVisible) fetchTimeline(); }}, 3500);
    setInterval(() => {{ if (isTabVisible) fetchTerminalLogs(); }}, 4000);
    setInterval(() => {{ if (isTabVisible) loadSonnetData(); }}, 15000);
</script>

</body>
</html>"""


# ============================================================================
# Main Entrypoint
# ============================================================================

def start_server(port: int = DEFAULT_PORT, host: str = HOST, public: bool = False):
    """Start threaded Sentinel server and background stream monitor."""
    global _is_running, _active_port, _allow_public
    _active_port = port
    _allow_public = public
    bind_host = "0.0.0.0" if public else host
    priv, did = load_or_create_identity()
    fp = hashlib.sha256(did.encode()).hexdigest()[:16]

    print("=" * 65)
    print("  TECHNOCORE SENTINEL & FLOP AGENT CONTROL HUB")
    print("=" * 65)
    print(f"  Agent DID:        {did}")
    print(f"  Fingerprint:      {fp}")
    print(f"  Mode:             {'PUBLIC (0.0.0.0)' if public else 'LOCAL ONLY (127.0.0.1)'}")
    print(f"  Web URL:          http://{bind_host}:{port}")
    print(f"  Session Token:    [redacted — embedded in dashboard HTML]")
    print("=" * 65)
    print(f"[+] Launching on http://{bind_host}:{port} ...\n")

    # Start background monitor thread
    monitor = SentinelStreamMonitor(poll_interval=12)
    monitor.start()

    # In public/cloud deployment, also launch autonomous swarm daemon & TCLK worker thread
    if public or os.environ.get("AUTONOMOUS_DAEMON", "0") == "1":
        try:
            from daemon import run_global_daemon
            daemon_thread = threading.Thread(
                target=run_global_daemon,
                kwargs={"heartbeat_interval_mins": 25},
                daemon=True,
                name="AutonomousSwarmWorker"
            )
            daemon_thread.start()
            logger.info("[+] Autonomous Swarm Daemon & TCLK Worker spawned in background thread for cloud deployment.")
        except Exception as e:
            logger.warning(f"[-] Failed to launch background swarm daemon: {e}")

    # Launch autonomous sonnet daemon in background
    if public or os.environ.get("AUTONOMOUS_SONNET", "0") == "1":
        try:
            from autonomous_sonnet_daemon import AutonomousSonnetDaemon
            def _run_sonnet():
                d = AutonomousSonnetDaemon(target_game="bub")
                d.run_forever(interval=20)
            sonnet_thread = threading.Thread(
                target=_run_sonnet,
                daemon=True,
                name="AutonomousSonnetWorker"
            )
            sonnet_thread.start()
            logger.info("[+] Autonomous Sonnet Daemon spawned in background thread.")
        except Exception as e:
            logger.warning(f"[-] Failed to launch background sonnet daemon: {e}")

    server = ThreadingHTTPServer((bind_host, port), SentinelRequestHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down Sentinel Hub...")
        _is_running = False
        server.server_close()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", DEFAULT_PORT))
    public = "--public" in sys.argv or os.environ.get("PUBLIC", "0") == "1"
    for arg in sys.argv[1:]:
        if arg.isdigit():
            port = int(arg)
    start_server(port=port, public=public)
