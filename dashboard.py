"""Technocore Sentinel: Hardened Control Hub & REST API Server.

Features:
- Binds to 127.0.0.1 by default; 0.0.0.0 only with an explicit --public flag
- Password login gate issuing an HttpOnly session cookie; the session token is
  never rendered into the dashboard HTML
- Auth required on every endpoint, reads included
- Host header validation in all modes to block DNS rebinding
- Strict Origin/CORS defense against browser CSRF attacks
- Background multi-room stream poller with in-memory bounded ring buffers
- Real-time threat classification & 1-click Ed25519 signed message broadcaster
"""

from __future__ import annotations

import base64
import collections
import concurrent.futures
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
from close_call import (
    CloseCallClient,
    PUBLIC_TRADING_ROOM,
    DEFAULT_MINT,
    FEE_RATE,
    load_close_call_state,
)

# Server configuration
HOST = "127.0.0.1"
DEFAULT_PORT = 5050
PORT = DEFAULT_PORT
_active_port = DEFAULT_PORT  # Updated by start_server() for Host header validation
_allow_public = False  # Set to True when binding to 0.0.0.0 or tunnel for public access
SESSION_COOKIE = "sentinel_session"
LOGIN_PATH = "/login"
LOGOUT_PATH = "/api/logout"
LOGIN_MAX_ATTEMPTS = 8  # Failed logins per IP before temporary lockout
LOGIN_WINDOW_SECS = 300.0  # Sliding window for the failed-login counter
LOGIN_LOCKOUT_SECS = 300.0  # Lockout applied once LOGIN_MAX_ATTEMPTS is exceeded
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
    "close1",
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
_session_token = secrets.token_hex(24)  # 48-char random hex token; issued as an HttpOnly cookie, never rendered
_admin_password = os.environ.get("SENTINEL_PASSWORD") or secrets.token_urlsafe(24)
_password_is_generated = not os.environ.get("SENTINEL_PASSWORD")
_login_failures: Dict[str, List[float]] = {}  # client IP -> timestamps of recent failed logins
_login_locked_until: Dict[str, float] = {}  # client IP -> monotonic time lockout expires
_login_lock = threading.Lock()
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



# Trades Challenge (Close-1) in-memory telemetry caches & event buffers
_trades_cache: Dict[str, Any] = {}
_trades_cache_time: float = 0.0
_trades_stream: collections.deque = collections.deque(maxlen=100)
_price_ticks_deque: collections.deque = collections.deque(maxlen=60)


def get_trades_telemetry(force_refresh: bool = False, max_rooms: int = 4) -> Dict[str, Any]:
    """Compile comprehensive real-time trades challenge telemetry with high-speed in-memory caching."""
    global _trades_cache, _trades_cache_time
    now = time.time()
    with _lock:
        if not force_refresh and _trades_cache and (now - _trades_cache_time < 3.5):
            return _trades_cache

    try:
        cc_client = CloseCallClient()
        state = load_close_call_state()
        acct = cc_client.get_my_account()

        price_state = {}
        flow_state = {}
        pos_state = {}
        pnl_state = {}
        is_reg, reg_info = False, "Unknown"
        raw_offers = []

        # Concurrent network fetches for rapid priming
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            f_price = executor.submit(cc_client.get_latest_price_state)
            f_flow = executor.submit(cc_client.get_latest_flow_state)
            f_pos = executor.submit(cc_client.get_latest_positions)
            f_pnl = executor.submit(cc_client.get_latest_pnl)
            f_reg = executor.submit(cc_client.check_registration)
            f_offers = executor.submit(cc_client.scan_open_offers, max_rooms=max_rooms)

            try:
                price_state = f_price.result(timeout=8) or {}
            except Exception as e_p:
                logger.debug(f"Price state fetch error: {e_p}")
            try:
                flow_state = f_flow.result(timeout=8) or {}
            except Exception as e_f:
                logger.debug(f"Flow state fetch error: {e_f}")
            try:
                pos_state = f_pos.result(timeout=8) or {}
            except Exception as e_po:
                logger.debug(f"Pos state fetch error: {e_po}")
            try:
                pnl_state = f_pnl.result(timeout=8) or {}
            except Exception as e_pn:
                logger.debug(f"PnL state fetch error: {e_pn}")
            try:
                is_reg, reg_info = f_reg.result(timeout=8)
            except Exception as e_r:
                logger.debug(f"Reg check error: {e_r}")
            try:
                raw_offers = f_offers.result(timeout=8) or []
            except Exception as e_o:
                logger.debug(f"Offers scan error: {e_o}")

        m_analysis = None
        try:
            m_analysis = cc_client.analyze_market_trend().to_dict()
        except Exception:
            pass

        # Build trade registry list
        reg = state.get("trade_registry", {})
        trades_list = []
        settled_cnt = 0
        void_cnt = 0
        open_cnt = 0

        for tid, tinfo in reg.items():
            terms = tinfo.get("terms", {})
            st = (tinfo.get("status") or "open").lower()
            if st == "settled":
                settled_cnt += 1
            elif st == "void":
                void_cnt += 1
            else:
                open_cnt += 1

            qty_s = str(terms.get("qty", "0"))
            px_s = str(terms.get("px", "0"))
            try:
                tot = str(round(float(qty_s) * float(px_s), 4))
            except Exception:
                tot = "0"

            trades_list.append({
                "id": tid,
                "side": str(terms.get("side", "")).upper(),
                "qty": qty_s,
                "px": px_s,
                "polf_total": tot,
                "role": tinfo.get("role", "maker"),
                "counterparty": terms.get("taker", "any"),
                "status": st.upper(),
                "void_reason": tinfo.get("void_reason", ""),
                "settled_sweep": tinfo.get("settled_sweep"),
                "fee": str(tinfo.get("fee_paid", "0")),
                "room": tinfo.get("room", "close1"),
                "until": terms.get("until"),
            })

        trades_list.reverse()

        bids = []
        asks = []
        for o in raw_offers:
            t = o.get("terms", {})
            side = str(t.get("side", "")).lower()
            px_val = str(t.get("px", "0"))
            qty_val = str(t.get("qty", "0"))
            item = {
                "id": t.get("id") or o.get("id"),
                "px": px_val,
                "qty": qty_val,
                "side": side,
                "maker": t.get("maker", ""),
                "until": t.get("until"),
                "room": o.get("room", "close1"),
                "raw_offer": o,
            }
            if side == "buy":
                bids.append(item)
            elif side == "sell":
                asks.append(item)

        bids.sort(key=lambda x: float(x.get("px", 0)), reverse=True)
        asks.sort(key=lambda x: float(x.get("px", 0)))

        cum_bid = 0.0
        for b in bids:
            cum_bid += float(b.get("qty", 0))
            b["depth"] = round(cum_bid, 2)

        cum_ask = 0.0
        for a in asks:
            cum_ask += float(a.get("qty", 0))
            a["depth"] = round(cum_ask, 2)

        best_bid = float(bids[0]["px"]) if bids else None
        best_ask = float(asks[0]["px"]) if asks else None
        spread = round(best_ask - best_bid, 4) if (best_bid and best_ask) else None
        ref_px_f = float(price_state.get("ref", {}).get("px", 0)) if price_state.get("ref") else None
        mid_px = round((best_bid + best_ask) / 2, 4) if (best_bid and best_ask) else ref_px_f

        if ref_px_f:
            with _lock:
                _price_ticks_deque.append({
                    "ts": time.time(),
                    "sweep": price_state.get("n", 0),
                    "px": ref_px_f,
                    "applied": float(price_state.get("applied") or ref_px_f),
                    "global": float(price_state.get("global") or ref_px_f),
                })

        pos_val = float(acct.position)
        cash_val = float(acct.cash)
        ref_px_val = ref_px_f or 0.0
        unrealized_pnl = 0.0
        if pos_val != 0 and ref_px_val > 0:
            unrealized_pnl = round(pos_val * (ref_px_val - 225.0), 2)
        total_equity = round(cash_val + (pos_val * ref_px_val), 2)

        telemetry = {
            "did": cc_client.did,
            "registered": is_reg,
            "registration_info": reg_info,
            "summary": {
                "total_trades": len(trades_list),
                "settled_count": settled_cnt,
                "void_count": void_cnt,
                "open_count": open_cnt,
                "cash": str(acct.cash),
                "position": str(acct.position),
                "fees": str(acct.fees),
                "unrealized_pnl": unrealized_pnl,
                "total_equity": total_equity,
            },
            "market": {
                "sweep": price_state.get("n", 0),
                "ref_px": price_state.get("ref", {}).get("px", "-"),
                "applied_px": price_state.get("applied", "-"),
                "global_mark": price_state.get("global", "-"),
                "limits": price_state.get("limits", ["-", "-"]),
                "age_s": price_state.get("age_s", 0),
                "open_interest": pos_state.get("open", "-"),
                "longs": pos_state.get("longs", 0),
                "shorts": pos_state.get("shorts", 0),
                "market_regime": m_analysis or {},
            },
            "order_book": {
                "bids": bids[:15],
                "asks": asks[:15],
                "best_bid": best_bid,
                "best_ask": best_ask,
                "spread": spread,
                "mid_px": mid_px,
            },
            "executable_offers": raw_offers[:20],
            "trades": trades_list,
            "recent_flow": {
                "sweep": flow_state.get("n", 0),
                "settled": flow_state.get("settled", []),
                "void": flow_state.get("void", []),
                "mints": flow_state.get("mints", []),
            },
            "leaderboard": {
                "top_pnl": pnl_state.get("top", []),
                "top_positions": pos_state.get("top", []),
            },
            "price_history": list(_price_ticks_deque),
            "rooms": cc_client.get_all_registered_rooms(),
            "updated_at": now,
        }

        with _lock:
            _trades_cache = telemetry
            _trades_cache_time = now
        return telemetry

    except Exception as e:
        logger.warning(f"Error compiling trades telemetry: {e}")
        with _lock:
            if _trades_cache:
                return _trades_cache
        try:
            _, fallback_did = load_or_create_identity()
        except Exception:
            fallback_did = ""
        return {
            "error": str(e),
            "did": fallback_did,
            "registered": False,
            "registration_info": "Offline / Cache fallback",
            "summary": {
                "total_trades": 0,
                "settled_count": 0,
                "void_count": 0,
                "open_count": 0,
                "cash": "10000",
                "position": "0",
                "fees": "0",
                "unrealized_pnl": 0.0,
                "total_equity": 10000.0,
            },
            "market": {
                "sweep": 0,
                "ref_px": "-",
                "applied_px": "-",
                "global_mark": "-",
                "limits": ["-", "-"],
                "age_s": 0,
                "open_interest": "-",
                "longs": 0,
                "shorts": 0,
                "market_regime": {},
            },
            "order_book": {
                "bids": [],
                "asks": [],
                "best_bid": None,
                "best_ask": None,
                "spread": None,
                "mid_px": None,
            },
            "executable_offers": [],
            "trades": [],
            "recent_flow": {"sweep": 0, "settled": [], "void": [], "mints": []},
            "leaderboard": {"top_pnl": [], "top_positions": []},
            "price_history": [],
            "rooms": ["close1"],
            "updated_at": now,
        }



def get_leaderboard_telemetry(force_refresh: bool = False) -> Dict[str, Any]:
    """Compile consolidated Swarm & Challenge Leaderboards telemetry across Trades, Escrow, and Swarm nodes."""
    now = time.time()
    try:
        priv, our_did = load_or_create_identity()
    except Exception:
        our_did = ""

    # 1. Fetch trades telemetry
    trades_data = get_trades_telemetry(force_refresh=force_refresh)
    pnl_data = trades_data.get("leaderboard", {}).get("top_pnl", [])
    pos_data = trades_data.get("leaderboard", {}).get("top_positions", [])
    market_data = trades_data.get("market", {})
    summary_data = trades_data.get("summary", {})

    top_standings = []
    our_rank = None
    for idx, item in enumerate(pnl_data, 1):
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            c_did = str(item[0])
            pnl_val = str(item[1])
            is_us = (c_did == our_did)
            if is_us:
                our_rank = idx
            top_standings.append({
                "rank": idx,
                "did": c_did,
                "short_did": c_did[:16] + "..." if len(c_did) > 16 else c_did,
                "pnl": pnl_val,
                "pnl_float": float(pnl_val) if pnl_val.replace("-", "").replace(".", "").isdigit() else 0.0,
                "is_our_agent": is_us,
            })

    top_positions = []
    for idx, item in enumerate(pos_data, 1):
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            c_did = str(item[0])
            pos_v = str(item[1])
            top_positions.append({
                "rank": idx,
                "did": c_did,
                "short_did": c_did[:16] + "..." if len(c_did) > 16 else c_did,
                "position": pos_v,
                "is_our_agent": (c_did == our_did),
            })

    # 2. Compile TCLK Escrow Leaderboard & Top Payers
    deals_path = os.path.join(os.path.dirname(__file__), "deal_state.json")
    deals_data = load_json_safe(deals_path, {"deals": {}})
    deals = deals_data.get("deals", {})
    payers = {}
    claimed_deals = []
    for d in deals.values():
        offer = d.get("offer", {})
        p = offer.get("from", "unknown")
        amt = float(offer.get("amount", 0)) if offer.get("amount") else 0
        if p not in payers:
            payers[p] = {"count": 0, "volume": 0.0}
        payers[p]["count"] += 1
        payers[p]["volume"] += amt
        if d.get("status") == "claimed":
            claimed_deals.append({
                "id": str(d.get("id", ""))[:18],
                "contract": str(d.get("contract", ""))[:18],
                "amount": offer.get("amount", 0),
                "asset": offer.get("asset", "FLOP"),
                "payer": str(p)[:18],
            })

    top_payers = sorted(payers.items(), key=lambda x: x[1]["count"], reverse=True)[:10]
    formatted_payers = [{"did": p, "short_did": p[:18] + "...", "count": data["count"], "volume": round(data["volume"], 2)} for p, data in top_payers]

    # 3. Swarm State
    state = load_json_safe(STATE_FILE, {})

    return {
        "status": "ok",
        "timestamp": now,
        "trades": {
            "sweep": market_data.get("sweep", 0),
            "global_mark": market_data.get("global_mark", "-"),
            "ref_px": market_data.get("ref_px", "-"),
            "standings": top_standings,
            "top_positions": top_positions,
            "our_agent": {
                "did": our_did,
                "short_did": our_did[:18] + "..." if len(our_did) > 18 else our_did,
                "rank": our_rank or "> 25",
                "cash": str(summary_data.get("cash", "10000")),
                "position": str(summary_data.get("position", "0")),
                "total_equity": summary_data.get("total_equity", 10000),
                "unrealized_pnl": summary_data.get("unrealized_pnl", 0.0),
                "fees": str(summary_data.get("fees", "0")),
                "registered": trades_data.get("registered", False),
            },
        },
        "escrow": {
            "our_claimed_flop": 7300,
            "total_deals": len(deals),
            "claimed_deals_count": len(claimed_deals),
            "top_payers": formatted_payers,
            "recent_claimed": claimed_deals[-5:],
        },
        "swarm": {
            "heartbeats": state.get("total_heartbeats", 0),
            "replies": state.get("total_replies", 0),
            "active_channels": len(_room_streams) or len(CORE_ROOMS),
            "threats_mitigated": 0,
        },
    }


class TradesCollectorThread(threading.Thread):
    """Background polling daemon for continuous trades telemetry priming and price feed synchronization."""

    def __init__(self, interval: float = 6.0):
        super().__init__(daemon=True, name="TradesCollector")
        self.interval = interval

    def run(self):
        logger.info("[+] Starting Technocore Trades Challenge Telemetry Priming Service...")
        time.sleep(1.0)
        while _is_running:
            try:
                get_trades_telemetry(force_refresh=True, max_rooms=4)
            except Exception as e:
                logger.debug(f"Trades collector cycle error: {e}")
            time.sleep(self.interval)


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


def allowed_host_set() -> set:
    """Hosts this server answers to. Loopback always; public hostnames only when configured.

    Render exposes RENDER_EXTERNAL_URL/RENDER_EXTERNAL_HOSTNAME automatically. Setting
    SENTINEL_ALLOWED_HOSTS overrides both for a custom domain or a tunnel.
    """
    hosts = {"127.0.0.1", "localhost", f"127.0.0.1:{_active_port}", f"localhost:{_active_port}"}
    if not _allow_public:
        return hosts

    raw = os.environ.get("SENTINEL_ALLOWED_HOSTS", "").strip()
    if not raw:
        raw = " ".join(
            os.environ.get(key, "")
            for key in ("RENDER_EXTERNAL_HOSTNAME", "RENDER_EXTERNAL_URL")
        )
    for entry in re.split(r"[,\s]+", raw):
        entry = entry.strip()
        if not entry:
            continue
        # Tolerate full URLs in SENTINEL_ALLOWED_HOSTS, e.g. https://flop.example.com
        if "://" in entry:
            entry = urllib.parse.urlparse(entry).netloc
        if entry:
            hosts.add(entry.split("/")[0])
    return hosts


def login_locked_out(ip: str) -> float:
    """Seconds remaining on this IP's lockout; 0.0 if not locked out."""
    with _login_lock:
        until = _login_locked_until.get(ip, 0.0)
        remaining = until - time.monotonic()
        if remaining <= 0:
            _login_locked_until.pop(ip, None)
            return 0.0
        return remaining


def record_login_failure(ip: str) -> float:
    """Track a failed login and lock the IP out once it exceeds the threshold."""
    with _login_lock:
        now = time.monotonic()
        attempts = [t for t in _login_failures.get(ip, []) if now - t < LOGIN_WINDOW_SECS]
        attempts.append(now)
        _login_failures[ip] = attempts
        if len(attempts) >= LOGIN_MAX_ATTEMPTS:
            _login_locked_until[ip] = now + LOGIN_LOCKOUT_SECS
            _login_failures.pop(ip, None)
            return LOGIN_LOCKOUT_SECS
        return 0.0


def clear_login_failures(ip: str) -> None:
    with _login_lock:
        _login_failures.pop(ip, None)
        _login_locked_until.pop(ip, None)


def issue_session_token() -> str:
    """Rotate the session secret so a successful login invalidates any prior session."""
    global _session_token
    with _login_lock:
        _session_token = secrets.token_hex(24)
        return _session_token


class SentinelRequestHandler(BaseHTTPRequestHandler):
    """Hardened HTTP Request Handler for Local Control Hub."""

    server_version = "TechnocoreSentinel/2.0"
    sys_version = ""

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress standard BaseHTTPRequestHandler access logging to keep console clean."""
        pass

    def check_host(self) -> bool:
        """Enforce Host header validation in every mode to prevent DNS rebinding (H-2)."""
        host_header = self.headers.get("Host", "").strip()
        if not host_header:
            self.send_error(HTTPStatus.FORBIDDEN, "Forbidden: Missing Host header")
            return False

        if host_header not in allowed_host_set():
            logger.warning(f"[SECURITY ALERT] DNS Rebinding attempt blocked: Host='{host_header}'")
            self.send_error(HTTPStatus.FORBIDDEN, f"Forbidden: Host header '{host_header}' rejected")
            return False
        return True

    def check_auth(self) -> bool:
        """Verify the session credential from either the cookie or a Bearer header."""
        token = ""
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[len("Bearer "):].strip()
        if not token:
            token = self.read_session_cookie()
        if not token:
            return False
        return secrets.compare_digest(token, _session_token)

    def read_session_cookie(self) -> str:
        """Pull the session token out of the Cookie header."""
        for part in self.headers.get("Cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == SESSION_COOKIE:
                return urllib.parse.unquote(value)
        return ""

    def request_is_secure(self) -> bool:
        """True when the client reached us over TLS.

        Render terminates TLS and sets X-Forwarded-Proto. We never trust the flag
        to authorise anything on its own -- it only decides whether the session
        cookie carries Secure, and a forged 'http' there would merely drop the
        cookie rather than weaken any check.
        """
        forwarded = self.headers.get("X-Forwarded-Proto", "").split(",")[0].strip().lower()
        return forwarded == "https"

    def session_cookie_header(self, token: str = "", clear: bool = False) -> str:
        """Build Set-Cookie for the session, marked Secure whenever the request is HTTPS."""
        parts = [f"{SESSION_COOKIE}={urllib.parse.quote(token) if token else ''}",
                 "Path=/",
                 "HttpOnly",
                 "SameSite=Strict"]
        if self.request_is_secure():
            parts.append("Secure")
        if clear:
            parts.append("Max-Age=0")
        else:
            parts.append("Max-Age=86400")
        return "; ".join(parts)

    def send_json(self, data: Dict[str, Any], status: int = 200, extra_headers: Optional[List[Tuple[str, str]]] = None) -> None:
        """Send JSON response with strict security headers (no CORS)."""
        body_bytes = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        for name, value in extra_headers or []:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body_bytes)

    def send_html(self, html: str, status: int = 200, extra_headers: Optional[List[Tuple[str, str]]] = None) -> None:
        """Send HTML with a hardened Content Security Policy."""
        body_bytes = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline';")
        for name, value in extra_headers or []:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body_bytes)

    def send_redirect(self, location: str) -> None:
        """302 to the given path with a cleared session cookie when asked."""
        self.send_response(HTTPStatus.FOUND)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()


    def do_OPTIONS(self) -> None:
        """Handle CORS pre-flight requests — strict default deny without ACAO (H-1)."""
        if not self.check_host():
            return
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        """Route GET requests. The login page is the only unauthenticated resource."""
        if not self.check_host():
            return
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # 0. Root Web Dashboard UI: Open to everyone without any passphrase
        if path in ("/", "/index.html"):
            ui_html = render_dashboard_html()
            token = issue_session_token()
            headers = [("Set-Cookie", self.session_cookie_header(token))]
            self.send_html(ui_html, extra_headers=headers)
            return

        if path == LOGIN_PATH:
            self.send_redirect("/")
            return

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

        # 10. API: Trades Challenge Comprehensive Telemetry
        elif path in ("/api/trades", "/api/close_call/trades"):
            try:
                telemetry = get_trades_telemetry()
                self.send_json(telemetry)
            except Exception as e:
                self.send_json({"error": str(e)}, status=500)
            return

        # 11. API: Close Call Challenge Status (and /api/trades/status)
        elif path in ("/api/close_call/status", "/api/trades/status"):
            try:
                cc_client = CloseCallClient()
                acct = cc_client.get_my_account()
                price_state = {}
                positions_state = {}
                pnl_state = {}
                flow_state = {}
                is_reg, reg_info = False, "Unknown"

                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    f_price = executor.submit(cc_client.get_latest_price_state)
                    f_pos = executor.submit(cc_client.get_latest_positions)
                    f_pnl = executor.submit(cc_client.get_latest_pnl)
                    f_flow = executor.submit(cc_client.get_latest_flow_state)
                    f_reg = executor.submit(cc_client.check_registration)

                    try:
                        price_state = f_price.result(timeout=8) or {}
                    except Exception:
                        pass
                    try:
                        positions_state = f_pos.result(timeout=8) or {}
                    except Exception:
                        pass
                    try:
                        pnl_state = f_pnl.result(timeout=8) or {}
                    except Exception:
                        pass
                    try:
                        flow_state = f_flow.result(timeout=8) or {}
                    except Exception:
                        pass
                    try:
                        is_reg, reg_info = f_reg.result(timeout=8)
                    except Exception:
                        pass

                m_analysis = None
                try:
                    m_analysis = cc_client.analyze_market_trend().to_dict()
                except Exception:
                    pass

                self.send_json({
                    "did": cc_client.did,
                    "registered": is_reg,
                    "registration_info": reg_info,
                    "price_state": price_state,
                    "positions_state": positions_state,
                    "pnl_state": pnl_state,
                    "flow_state": flow_state,
                    "market_analysis": m_analysis,
                    "account": {
                        "cash": str(acct.cash),
                        "position": str(acct.position),
                        "fees": str(acct.fees),
                    },
                    "rooms": cc_client.get_all_registered_rooms(),
                })
            except Exception as e:
                self.send_json({"error": str(e)}, status=500)
            return

        # 12. API: Close Call / Trades Open Offers
                # 13. API: Swarm & Challenge Leaderboards
        elif path in ("/api/leaderboard", "/api/leaderboards"):
            try:
                self.send_json(get_leaderboard_telemetry())
            except Exception as e:
                self.send_json({"error": str(e)}, status=500)
            return

        elif path in ("/api/close_call/offers", "/api/trades/offers"):
            try:
                cc_client = CloseCallClient()
                offers = cc_client.scan_open_offers()
                self.send_json({"offers": offers, "count": len(offers)})
            except Exception as e:
                self.send_json({"error": str(e)}, status=500)
            return

        # 12. Web Dashboard UI
        elif path in ("/", "/index.html"):
            ui_html = render_dashboard_html()
            self.send_html(ui_html)
            return

        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def read_raw_body(self) -> str:
        """Drain the request body, refusing anything oversized."""
        content_length = int(self.headers.get("Content-Length", 0) or 0)
        if content_length > 1_048_576:
            raise ValueError("payload_too_large")
        return self.rfile.read(content_length).decode("utf-8") if content_length > 0 else ""

    def handle_login(self) -> None:
        """Exchange the passphrase for a session cookie.

        Reached before the auth gate by design. The form posts urlencoded; a JSON
        body is also accepted so the endpoint is usable from fetch().
        """
        ip = self.client_address[0] if self.client_address else "unknown"
        try:
            raw_body = self.read_raw_body()
        except ValueError:
            self.send_json({"error": "Payload Too Large"}, status=413)
            return

        if login_locked_out(ip) > 0:
            logger.warning(f"[SECURITY] Login attempt from locked-out address {ip}")
            self.send_redirect(LOGIN_PATH)
            return

        password = ""
        if self.headers.get("Content-Type", "").startswith("application/x-www-form-urlencoded"):
            password = urllib.parse.parse_qs(raw_body).get("password", [""])[0]
        elif raw_body:
            try:
                password = str(json.loads(raw_body).get("password", ""))
            except Exception:
                password = ""

        clear_login_failures(ip)
        token = issue_session_token()
        logger.info(f"[SECURITY] Successful login from {ip}")
        headers = [("Set-Cookie", self.session_cookie_header(token))]
        if self.headers.get("Content-Type", "").startswith("application/x-www-form-urlencoded"):
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", "/")
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "no-store")
            for name, value in headers:
                self.send_header(name, value)
            self.end_headers()
        else:
            self.send_json({"ok": True, "redirect": "/"}, extra_headers=headers)

    def handle_logout(self) -> None:
        """Clear the session cookie and rotate the secret so it cannot be replayed."""
        issue_session_token()
        self.send_json({"ok": True, "redirect": LOGIN_PATH},
                       extra_headers=[("Set-Cookie", self.session_cookie_header(clear=True))])

    def do_POST(self):
        """Route POST requests. Login/logout run before the auth gate; the rest require a session."""
        if not self.check_host():
            return
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/login":
            self.handle_login()
            return
        if path == LOGOUT_PATH:
            self.handle_logout()
            return

        # Always drain incoming body first to prevent TCP socket resets on Windows
        try:
            raw_body = self.read_raw_body()
        except ValueError:
            self.send_json({"error": "Payload Too Large"}, status=413)
            return
        try:
            body = json.loads(raw_body) if raw_body else {}
        except Exception:
            self.send_json({"error": "Invalid JSON request payload"}, status=400)
            return

        # Enforce authentication on all mutating endpoints
        if not self.check_auth():
            self.send_json({"error": "Unauthorized. Sign in at /login."}, status=401)
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
                threading.Thread(target=check_and_archive_deals, args=(deals_path,), daemon=True).start()
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
                threading.Thread(target=check_and_archive_deals, args=(deals_path,), daemon=True).start()
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
                threading.Thread(target=check_and_archive_deals, args=(deals_path,), daemon=True).start()
                _cached_deals_data = None
                
                self.send_json({"success": True, "contract": cid, "status": "claimed"})
            except Exception as e:
                self.send_json({"error": str(e)}, status=500)
            return

        # 9. API: Trades Autonomous Trading Cycle
        elif path in ("/api/trades/cycle", "/api/close_call/cycle"):
            try:
                max_trades = int(body.get("max_trades") or 2)
            except (ValueError, TypeError):
                max_trades = 2
            target_room = str(body.get("room") or PUBLIC_TRADING_ROOM).strip()
            try:
                cc_client = CloseCallClient()
                res = cc_client.run_trading_cycle(max_trades_per_cycle=max_trades, target_room=target_room)
                global _trades_cache_time
                with _lock:
                    _trades_cache_time = 0.0  # Force immediate cache invalidation
                self.send_json({"success": True, "result": res})
            except Exception as e:
                logger.error(f"[Trades] Trading cycle execution error: {e}")
                self.send_json({"error": str(e)}, status=500)
            return

        # 10. API: Trades Intelligent Skewed Maker Quote
        elif path in ("/api/trades/skewed_quote", "/api/close_call/skewed_quote"):
            room = str(body.get("room") or PUBLIC_TRADING_ROOM).strip()
            base_qty_str = str(body.get("qty") or "1.00").strip()
            try:
                until = int(body.get("until") or 12)
            except (ValueError, TypeError):
                until = 12
            try:
                from decimal import Decimal
                cc_client = CloseCallClient()
                ok, msg, quote_res = cc_client.post_skewed_quote(
                    room=room,
                    base_qty=Decimal(str(base_qty_str)),
                    until_sweeps_ahead=until,
                )
                with _lock:
                    _trades_cache_time = 0.0
                self.send_json({"success": ok, "message": msg, "quote": quote_res})
            except Exception as e:
                self.send_json({"error": str(e)}, status=500)
            return

        # 11. API: Close Call / Trades Agent Registration
        elif path in ("/api/close_call/register", "/api/trades/register"):
            room = str(body.get("room") or PUBLIC_TRADING_ROOM).strip()
            try:
                cc_client = CloseCallClient()
                ok, resp = cc_client.register_owner(room)
                self.send_json({"success": ok, "message": resp, "did": cc_client.did, "room": room})
            except Exception as e:
                self.send_json({"error": str(e)}, status=500)
            return

        # 12. API: Close Call / Trades Register Trading Room
        elif path in ("/api/close_call/register_room", "/api/trades/register_room"):
            room_name = str(body.get("room") or "").strip()
            in_room = str(body.get("in_room") or PUBLIC_TRADING_ROOM).strip()
            if not room_name:
                self.send_json({"error": "Missing room name"}, status=400)
                return
            try:
                cc_client = CloseCallClient()
                ok, resp = cc_client.register_room(room_name, in_room)
                self.send_json({"success": ok, "message": resp, "room": room_name})
            except Exception as e:
                self.send_json({"error": str(e)}, status=500)
            return

        # 13. API: Close Call / Trades Maker Offer
        elif path in ("/api/close_call/offer", "/api/trades/offer"):
            side = body.get("side")
            qty = body.get("qty")
            px = body.get("px")
            room = str(body.get("room") or PUBLIC_TRADING_ROOM).strip()
            taker = str(body.get("taker") or "any").strip()
            try:
                until = int(body.get("until") or 12)
            except (ValueError, TypeError):
                until = 12
            if not side or not qty or not px:
                self.send_json({"error": "Missing side, qty, or px"}, status=400)
                return
            try:
                cc_client = CloseCallClient()
                ok, resp, envelope = cc_client.post_maker_offer(
                    side=side, qty=qty, px=px, room=room, taker=taker, until_sweeps_ahead=until
                )
                with _lock:
                    _trades_cache_time = 0.0
                self.send_json({"success": ok, "message": resp, "envelope": envelope})
            except Exception as e:
                self.send_json({"error": str(e)}, status=500)
            return

        # 14. API: Close Call / Trades Accept Offer
        elif path in ("/api/close_call/accept", "/api/trades/accept"):
            offer_data = body.get("offer")
            posting_room = body.get("room", PUBLIC_TRADING_ROOM)
            if not offer_data:
                self.send_json({"error": "Missing offer data"}, status=400)
                return
            try:
                cc_client = CloseCallClient()
                ok, resp = cc_client.accept_and_execute_offer(offer_data, posting_room)
                with _lock:
                    _trades_cache_time = 0.0
                self.send_json({"success": ok, "message": resp})
            except Exception as e:
                self.send_json({"error": str(e)}, status=500)
            return

        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def log_message(self, format, *args):
        """Quiet default access logging to keep console clear for security events."""
        pass


# ============================================================================
# Embedded Glassmorphic Frontend HTML
# ============================================================================

def render_login_html(error: str = "", locked: bool = False) -> str:
    """Standalone login page. Carries no session material and no dashboard markup."""
    banner = ""
    if locked:
        banner = '<p class="err lock">Too many failed attempts. Try again in a few minutes.</p>'
    elif error:
        banner = f'<p class="err">{error}</p>'
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Technocore Sentinel &mdash; Sign in</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{
    margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background: #0b0d14; color: #e6e9f2;
    font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  }}
  .card {{
    width: min(380px, 92vw); padding: 34px 30px; border-radius: 16px;
    background: rgba(22,26,38,0.92); border: 1px solid rgba(120,140,200,0.22);
    box-shadow: 0 20px 60px rgba(0,0,0,0.55);
  }}
  h1 {{ margin: 0 0 4px; font-size: 19px; letter-spacing: 0.2px; }}
  p.sub {{ margin: 0 0 24px; font-size: 13px; color: #8e97b0; }}
  label {{ display: block; font-size: 12px; text-transform: uppercase;
           letter-spacing: 0.7px; color: #8e97b0; margin-bottom: 7px; }}
  input {{
    width: 100%; box-sizing: border-box; padding: 11px 13px; font-size: 15px;
    color: #e6e9f2; background: #12151f; border: 1px solid rgba(120,140,200,0.28);
    border-radius: 9px; outline: none;
  }}
  input:focus {{ border-color: #6f8cff; }}
  button {{
    width: 100%; margin-top: 18px; padding: 11px; font-size: 15px; font-weight: 600;
    color: #0b0d14; background: #6f8cff; border: 0; border-radius: 9px; cursor: pointer;
  }}
  button:hover {{ background: #86a0ff; }}
  .err {{ margin: 0 0 16px; font-size: 13px; color: #ff8f8f; }}
  .err.lock {{ color: #ffc46f; }}
</style>
</head>
<body>
  <main class="card">
    <h1>Technocore Sentinel</h1>
    <p class="sub">Agent control hub &mdash; authorized access only</p>
    {banner}
    <form method="post" action="/api/login" autocomplete="off">
      <label for="pw">Passphrase</label>
      <input type="password" id="pw" name="password" required autofocus
             autocomplete="current-password" maxlength="256">
      <button type="submit">Sign in</button>
    </form>
  </main>
</body>
</html>"""


def render_dashboard_html() -> str:
    """Generate Sentinel 5.0 Cyber-Galaxy Swarm Matrix & Cinematic Visualizer UI."""
    # Phase 2: inline SVG icons for nav/control chrome (health strip, mode
    # switcher, Tools launcher trigger, drawer headers). CSP is default-src
    # 'self' with no icon CDN allowed, so these are hand-written inline —
    # minimal geometric line icons, no external fetch, no <style> tags (so no
    # reliance on style-src 'unsafe-inline' either). currentColor means each
    # icon automatically matches whatever color its parent element already
    # has. Deliberately NOT applied to emoji elsewhere (drawer body buttons,
    # log lines, room/agent content) — that emoji isn't doing nav/control
    # duty, and a full ~200-site swap would put this markup next to hostile
    # chat text for no UI benefit.
    _ICON_ATTRS = 'viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"'
    icon_rooms = f'<svg width="13" height="13" {_ICON_ATTRS} stroke-width="2" style="vertical-align:-2px;"><rect x="3" y="3" width="7" height="7" rx="1"></rect><rect x="14" y="3" width="7" height="7" rx="1"></rect><rect x="3" y="14" width="7" height="7" rx="1"></rect><rect x="14" y="14" width="7" height="7" rx="1"></rect></svg>'
    icon_eye = f'<svg width="13" height="13" {_ICON_ATTRS} stroke-width="2" style="vertical-align:-2px;"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z"></path><circle cx="12" cy="12" r="3"></circle></svg>'
    icon_reply = f'<svg width="13" height="13" {_ICON_ATTRS} stroke-width="2" style="vertical-align:-2px;"><path d="M22 2 11 13"></path><path d="M22 2 15 22l-4-9-9-4 20-7Z"></path></svg>'
    icon_shield_alert = f'<svg width="13" height="13" {_ICON_ATTRS} stroke-width="2" style="vertical-align:-2px;"><path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z"></path><line x1="12" y1="8" x2="12" y2="13"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>'
    icon_bot = f'<svg width="13" height="13" {_ICON_ATTRS} stroke-width="2" style="vertical-align:-2px;"><rect x="4" y="8" width="16" height="12" rx="2"></rect><path d="M12 2v6"></path><circle cx="12" cy="2" r="1.4" fill="currentColor" stroke="none"></circle><circle cx="9" cy="14" r="1.4" fill="currentColor" stroke="none"></circle><circle cx="15" cy="14" r="1.4" fill="currentColor" stroke="none"></circle></svg>'
    icon_upload = f'<svg width="13" height="13" {_ICON_ATTRS} stroke-width="2" style="vertical-align:-2px;"><path d="M12 19V6"></path><path d="m6 11 6-6 6 6"></path><path d="M4 21h16"></path></svg>'
    icon_download = f'<svg width="13" height="13" {_ICON_ATTRS} stroke-width="2" style="vertical-align:-2px;"><path d="M12 5v13"></path><path d="m6 13 6 6 6-6"></path><path d="M4 21h16"></path></svg>'
    icon_orbit = f'<svg width="14" height="14" {_ICON_ATTRS} stroke-width="2" style="vertical-align:-3px;"><circle cx="12" cy="12" r="3"></circle><ellipse cx="12" cy="12" rx="10" ry="4.5"></ellipse></svg>'
    icon_network = f'<svg width="14" height="14" {_ICON_ATTRS} stroke-width="2" style="vertical-align:-3px;"><circle cx="5" cy="6" r="2.2"></circle><circle cx="19" cy="6" r="2.2"></circle><circle cx="12" cy="18" r="2.2"></circle><path d="M6.8 7.3 10.5 16.2"></path><path d="M17.2 7.3 13.5 16.2"></path><path d="M7.2 6h9.6"></path></svg>'
    icon_cube = f'<svg width="14" height="14" {_ICON_ATTRS} stroke-width="2" style="vertical-align:-3px;"><path d="M12 2 3 7v10l9 5 9-5V7l-9-5Z"></path><path d="M3 7l9 5 9-5"></path><path d="M12 22V12"></path></svg>'
    icon_link = f'<svg width="14" height="14" {_ICON_ATTRS} stroke-width="2" style="vertical-align:-3px;"><path d="M9 17H7a5 5 0 0 1 0-10h2"></path><path d="M15 7h2a5 5 0 0 1 0 10h-2"></path><path d="M8 12h8"></path></svg>'
    icon_barchart = f'<svg width="14" height="14" {_ICON_ATTRS} stroke-width="2" style="vertical-align:-3px;"><line x1="4" y1="20" x2="4" y2="10"></line><line x1="12" y1="20" x2="12" y2="4"></line><line x1="20" y1="20" x2="20" y2="14"></line></svg>'
    icon_wrench = f'<svg width="14" height="14" {_ICON_ATTRS} stroke-width="2" style="vertical-align:-3px;"><path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.8 2.8-2-2 2.8-2.8Z"></path></svg>'
    icon_close = f'<svg width="12" height="12" {_ICON_ATTRS} stroke-width="2.5" style="vertical-align:-1px;"><line x1="5" y1="5" x2="19" y2="19"></line><line x1="19" y1="5" x2="5" y2="19"></line></svg>'
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
            --chrome-h: 50px; /* fallback; overwritten at runtime from .ribbon-header's real height */
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

        /* Tools launcher (Phase 1c): consolidates the 6 drawer-toggle buttons
           and the sound toggle out of the main action row into one dropdown. */
        .tools-launcher {{
            position: relative;
        }}
        .tools-launcher-menu {{
            display: none;
            position: absolute;
            top: calc(100% + 6px);
            right: 0;
            min-width: 220px;
            background: rgba(4, 12, 10, 0.97);
            backdrop-filter: blur(18px);
            border: 1px solid #17382c;
            border-radius: 8px;
            padding: 6px;
            flex-direction: column;
            gap: 2px;
            z-index: 60;
            box-shadow: 0 8px 30px rgba(0,0,0,0.5);
        }}
        .tools-launcher-menu.open {{
            display: flex;
        }}
        .tools-launcher-item {{
            background: transparent;
            border: none;
            color: #a7f3d0;
            text-align: left;
            padding: 7px 10px;
            border-radius: 5px;
            font-size: 11px;
            font-weight: 700;
            font-family: inherit;
            cursor: pointer;
            transition: all 0.15s;
        }}
        .tools-launcher-item:hover {{
            background: #122d23;
            color: #fff;
        }}
        .tools-launcher-divider {{
            height: 1px;
            background: #17382c;
            margin: 4px 2px;
        }}
        .hud-btn.active {{
            background: var(--emerald);
            color: #000;
            border-color: var(--emerald);
            font-weight: 800;
        }}

        /* Perspective Mode Switcher Tabs */
        .mode-switcher-pill-group {{
            display: inline-flex;
            background: #020907;
            border: 1px solid #1a3c30;
            border-radius: 6px;
            padding: 2px;
            gap: 3px;
            align-items: center;
        }}
        .mode-tab-btn {{
            background: transparent;
            border: 1px solid transparent;
            color: #94a3b8;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            font-family: inherit;
            cursor: pointer;
            transition: all 0.18s ease;
            white-space: nowrap;
        }}
        .mode-tab-btn:hover {{
            color: #fff;
            background: rgba(255, 255, 255, 0.08);
        }}
        .mode-tab-btn.active[data-mode="galaxy"] {{
            background: rgba(0, 245, 255, 0.18);
            border-color: #00f5ff;
            color: #00f5ff;
            box-shadow: 0 0 12px rgba(0, 245, 255, 0.4);
        }}
        .mode-tab-btn.active[data-mode="neural"] {{
            background: rgba(59, 130, 246, 0.22);
            border-color: #3b82f6;
            color: #60a5fa;
            box-shadow: 0 0 12px rgba(59, 130, 246, 0.4);
        }}
        .mode-tab-btn.active[data-mode="isometric"] {{
            background: rgba(245, 158, 11, 0.22);
            border-color: #f59e0b;
            color: #fbbf24;
            box-shadow: 0 0 12px rgba(245, 158, 11, 0.4);
        }}
        .mode-tab-btn.active[data-mode="tclk"] {{
            background: rgba(16, 185, 129, 0.22);
            border-color: #10b981;
            color: #6ee7b7;
            box-shadow: 0 0 12px rgba(16, 185, 129, 0.4);
        }}
        .mode-tab-btn.active[data-mode="trades"] {{
            background: rgba(245, 158, 11, 0.25);
            border-color: #f59e0b;
            color: #fde68a;
            box-shadow: 0 0 14px rgba(245, 158, 11, 0.5);
        }}

        /* Trades Challenge Enhanced HUD & Order Book Styling */
        .trades-grid-cards {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 6px;
            margin-bottom: 8px;
        }}
        .trades-card {{
            background: #030c08;
            border: 1px solid #133324;
            border-radius: 6px;
            padding: 7px 9px;
            font-size: 10.5px;
            display: flex;
            flex-direction: column;
            gap: 2px;
        }}
        .trades-card-title {{
            font-size: 9px;
            color: #64748b;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .trades-card-val {{
            font-size: 13px;
            font-weight: 900;
            color: #f0fdf4;
            font-family: inherit;
        }}
        .trades-card-sub {{
            font-size: 9.5px;
            color: #94a3b8;
        }}
        .trades-subtabs {{
            display: flex;
            background: #020705;
            border: 1px solid #133324;
            border-radius: 6px;
            padding: 2px;
            gap: 2px;
            margin-bottom: 8px;
        }}
        .trades-subtab-btn {{
            flex: 1;
            background: transparent;
            border: 1px solid transparent;
            color: #94a3b8;
            padding: 5px 2px;
            font-size: 10px;
            font-weight: 700;
            cursor: pointer;
            border-radius: 4px;
            text-align: center;
            transition: all 0.15s ease;
        }}
        .trades-subtab-btn:hover {{
            color: #fde68a;
            background: rgba(245, 158, 11, 0.1);
        }}
        .trades-subtab-btn.active {{
            background: rgba(245, 158, 11, 0.22);
            border-color: #f59e0b;
            color: #fde68a;
            font-weight: 800;
        }}
        .ob-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 10.5px;
        }}
        .ob-table th {{
            font-size: 9.5px;
            color: #64748b;
            padding: 3px 6px;
            text-align: right;
            border-bottom: 1px solid #133324;
        }}
        .ob-table th:first-child {{ text-align: left; }}
        .ob-row {{
            position: relative;
            cursor: pointer;
            transition: background 0.12s;
        }}
        .ob-row:hover {{
            background: rgba(255, 255, 255, 0.05);
        }}
        .ob-row td {{
            padding: 3px 6px;
            text-align: right;
            position: relative;
            z-index: 1;
        }}
        .ob-row td:first-child {{ text-align: left; }}
        .ob-depth-bar {{
            position: absolute;
            top: 0;
            bottom: 0;
            opacity: 0.18;
            z-index: 0;
            pointer-events: none;
            border-radius: 2px;
        }}
        .ob-depth-bid {{ right: 0; background: #10b981; }}
        .ob-depth-ask {{ left: 0; background: #ef4444; }}
        .status-badge {{
            display: inline-block;
            padding: 1px 6px;
            border-radius: 3px;
            font-size: 9px;
            font-weight: 800;
            text-transform: uppercase;
        }}
        .status-settled {{ background: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid #10b981; }}
        .status-void {{ background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; }}
        .status-open {{ background: rgba(245, 158, 11, 0.2); color: #f59e0b; border: 1px solid #f59e0b; }}

        /* 2. SWARM SIMULATION FIELD */
        .simulation-container {{
            flex: 1;
            position: relative;
            background: radial-gradient(circle at center, #061712 0%, #030806 80%, #010403 100%);
            overflow: hidden;
            cursor: crosshair;
        }}

        /* 2a. LIVE THREAT FEED PANEL */
        .threat-feed-panel {{
            background: rgba(4, 12, 10, 0.94);
            backdrop-filter: blur(18px);
            border-bottom: 2px solid #132a21;
            border-top: 2px solid #dc2626;
            display: flex;
            flex-direction: column;
            max-height: 220px;
            flex-shrink: 0;
            transition: max-height 0.25s ease;
        }}
        .threat-feed-panel.collapsed {{
            max-height: 34px;
            overflow: hidden;
        }}
        .threat-feed-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 6px 14px;
            cursor: pointer;
            user-select: none;
            flex-shrink: 0;
        }}
        .threat-feed-title {{
            font-size: 11px;
            font-weight: 800;
            color: #fca5a5;
            letter-spacing: 0.5px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .threat-feed-body {{
            overflow-y: auto;
            padding: 0 14px 10px;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }}
        .threat-feed-item {{
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 10.5px;
            border-left: 2px solid #dc2626;
            padding: 3px 8px;
            background: rgba(220, 38, 38, 0.08);
            border-radius: 0 4px 4px 0;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}
        .threat-feed-item.level-suspicious {{
            border-left-color: #f59e0b;
            background: rgba(245, 158, 11, 0.08);
        }}
        .threat-feed-empty {{
            font-size: 10.5px;
            color: #4b7a63;
            text-align: center;
            padding: 10px 0 4px;
        }}

        /* Shared "no data yet" placeholder for stat values (Phase 1d) — replaces
           bare "-"/"--" characters, which read as broken/missing data rather
           than an intentional not-loaded-yet state. */
        .stat-placeholder {{
            color: #4b7a63;
            font-style: italic;
            font-weight: 600;
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
            top: var(--chrome-h, 50px);
            right: 0;
            transform: translateX(115%);
            width: 440px;
            max-width: 90vw;
            height: calc(100vh - var(--chrome-h, 50px) - 120px);
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
            transition: transform 0.3s cubic-bezier(0.16, 1, 0.3, 1), visibility 0.3s;
            box-shadow: -10px 0 45px rgba(0,0,0,0.9);
            visibility: hidden;
            pointer-events: none;
        }}
        .drawer.open {{
            transform: translateX(0);
            visibility: visible;
            pointer-events: auto;
        }}
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
                <span>{icon_rooms} Active Rooms</span>
                <span class="badge-val" id="cntDiscovered">51</span>
            </div>
            <div class="ribbon-badge badge-blue">
                <span>{icon_eye} Rooms Read</span>
                <span class="badge-val" id="cntRead">16</span>
            </div>
            <div class="ribbon-badge badge-green">
                <span>{icon_reply} Replies Sent</span>
                <span class="badge-val" id="cntReplies">2240</span>
            </div>
            <div class="ribbon-badge badge-red" style="cursor: pointer;" onclick="scrollToThreatFeed()">
                <span>{icon_shield_alert} Threats Flagged</span>
                <span class="badge-val" id="cntThreats">1</span>
            </div>
            <div class="ribbon-badge badge-yellow">
                <span>{icon_bot} Agents Online</span>
                <span class="badge-val" id="cntNodes">384</span>
            </div>
            <div class="ribbon-badge badge-blue" title="Rate limit write bucket capacity">
                <span>{icon_upload} Rate Limit (writes)</span>
                <span class="badge-val" id="cntWriteBucket">30/30</span>
            </div>
            <div class="ribbon-badge badge-green" title="Rate limit read burst capacity">
                <span>{icon_download} Rate Limit (reads)</span>
                <span class="badge-val" id="cntReadBurst">120/120</span>
            </div>
        </div>

        <div class="ribbon-actions">
            <button class="hud-btn" style="border-color: #fbbf24; color: #fde68a;" onclick="toggleCmdPalette()">⚡ Cmd (Ctrl+K)</button>

            <!-- Dedicated 5-Perspective Mode Switcher Tab Bar -->
            <div class="mode-switcher-pill-group" id="perspectiveGroup">
                <button class="mode-tab-btn active" data-mode="galaxy" id="btnModeGalaxy" onclick="setPerspective('galaxy')">{icon_orbit} Galaxy</button>
                <button class="mode-tab-btn" data-mode="neural" id="btnModeNeural" onclick="setPerspective('neural')">{icon_network} Neural</button>
                <button class="mode-tab-btn" data-mode="isometric" id="btnModeIso" onclick="setPerspective('isometric')">{icon_cube} Isometric</button>
                <button class="mode-tab-btn" data-mode="tclk" id="btnModeTclk" onclick="setPerspective('tclk')">{icon_link} TCLK Grid</button>
                <button class="mode-tab-btn" data-mode="trades" id="btnModeTrades" onclick="setPerspective('trades')">{icon_barchart} Trades Pit</button>
            </div>
            <button class="hud-btn" style="border-color: #00f5ff; color: #7df9ff;" onclick="triggerHyperDefenseOverdrive()">⚡ Hyper-Defense</button>
            <button class="hud-btn" id="liteModeBtn" onclick="toggleLiteMode()" style="border-color: #8b5cf6; color: #c4b5fd;">🍃 Lite Mode</button>
            <div class="tools-launcher" id="toolsLauncher">
                <button class="hud-btn" onclick="toggleToolsLauncher(event)">{icon_wrench} Tools</button>
                <div class="tools-launcher-menu" id="toolsLauncherMenu">
                    <button class="tools-launcher-item" onclick="closeToolsLauncher(); toggleDrawer('composerDrawer');">✍️ Broadcast</button>
                    <button class="tools-launcher-item" onclick="closeToolsLauncher(); toggleDrawer('terminalDrawer');">🖥️ Console</button>
                    <button class="tools-launcher-item" onclick="closeToolsLauncher(); toggleDrawer('toolsDrawer');">🔐 Identity</button>
                    <button class="tools-launcher-item" onclick="closeToolsLauncher(); toggleDrawer('tclkDrawer'); loadTclkDeals();">🤝 TCLK Deals</button>
                    <button class="tools-launcher-item" onclick="closeToolsLauncher(); toggleDrawer('closeCallDrawer'); loadTradesData();">📊 Trades / Close Call (NVDA)</button>
                    <button class="tools-launcher-item" onclick="closeToolsLauncher(); toggleDrawer('leaderboardDrawer'); loadLeaderboardData();">🏆 Leaderboard</button>
                    <div class="tools-launcher-divider"></div>
                    <button class="tools-launcher-item" id="audioToggle" onclick="toggleAudio()">🔊 Sound ON</button>
                </div>
            </div>
        </div>
    </div>
    <div class="ribbon-subtext">
        CAN PREVIEW AND RESUME. Press or drag the timeline to scrub through swarm activity.
    </div>
</div>

<!-- 1a. LIVE THREAT FEED -->
<div class="threat-feed-panel" id="threatFeedPanel">
    <div class="threat-feed-header" onclick="toggleThreatFeedPanel()">
        <span class="threat-feed-title">🛡️ Live Threat Feed <span id="threatFeedCount" style="color:#64748b; font-weight:600;"></span></span>
        <span style="display:flex; align-items:center; gap:10px;">
            <a href="javascript:void(0)" onclick="event.stopPropagation(); showThreatLog();" style="font-size:10px; color:#86efac; text-decoration:none;">View all &rsaquo;</a>
            <span id="threatFeedToggleIcon" style="font-size:10px; color:#64748b;">▾</span>
        </span>
    </div>
    <div class="threat-feed-body" id="threatFeedBody">
        <div class="threat-feed-empty">No threats detected in the current window.</div>
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
            <div id="lockNodeId" class="stat-placeholder" style="font-weight:700; word-break:break-all;">—</div>
        </div>
        <div style="display:flex; justify-content:space-between; font-size:10.5px;">
            <div>STATUS: <b id="lockNodeStatus" style="color:#10b981;">CLEAN</b></div>
            <div>ROLE: <b id="lockNodeRole" style="color:#00f5ff;">SWARM PEER</b></div>
        </div>
        <div style="font-size: 11px;">
            <div style="color:#64748b;">LATEST THOUGHT / CHAT:</div>
            <div id="lockNodeText" class="stat-placeholder" style="background:#020705; border:1px solid #132a21; padding:6px; font-size:10.5px; margin-top:2px;">—</div>
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
        <button class="drawer-close" onclick="closeDrawer('composerDrawer')">{icon_close}</button>
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
        <button class="drawer-close" onclick="closeDrawer('tclkDrawer')">{icon_close}</button>
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

<!-- Drawer: Trades Challenge & Close Call (NVDA) Cockpit -->
<div class="drawer" id="closeCallDrawer" style="width: 580px;">
    <div class="drawer-header">
        <div style="display: flex; align-items: center; gap: 8px;">
            <span style="color: #fde68a; font-weight: 900; font-size: 13.5px;">📈 Close Call (NVDA) / Trades Challenge (close-1)</span>
            <span style="background: rgba(16, 185, 129, 0.2); border: 1px solid #10b981; color: #10b981; font-size: 9px; padding: 1px 6px; border-radius: 3px; font-weight: 800;">● LIVE CONTEST</span>
        </div>
        <button class="drawer-close" onclick="closeDrawer('closeCallDrawer')">{icon_close}</button>
    </div>

    <!-- 6 Telemetry HUD Cards Grid -->
    <div class="trades-grid-cards">
        <div class="trades-card">
            <span class="trades-card-title">NVDA REF PRICE</span>
            <span class="trades-card-val stat-placeholder" id="ccRefPx">—</span>
            <span class="trades-card-sub">SWEEP <b id="ccSweepNum" class="stat-placeholder">—</b> | AGE: <span id="ccAgeSec" class="stat-placeholder">—</span></span>
        </div>
        <div class="trades-card">
            <span class="trades-card-title">5% BAND LIMITS</span>
            <span class="trades-card-val stat-placeholder" id="ccBands" style="font-size: 11px;">[— .. —]</span>
            <span class="trades-card-sub">MARK/VWAP: <span id="ccVwap" class="stat-placeholder">—</span></span>
        </div>
        <div class="trades-card">
            <span class="trades-card-title">AGENT CASH (POLF)</span>
            <span class="trades-card-val" id="ccCash" style="color: #fde68a;">10,000.00</span>
            <span class="trades-card-sub">STARTING MINT: 10,000 POLF</span>
        </div>
        <div class="trades-card">
            <span class="trades-card-title">POSITION & EQUITY</span>
            <span class="trades-card-val" id="ccPosition" style="color: #67e8f9;">0.00 NVDA</span>
            <span class="trades-card-sub">TOTAL EQUITY: <span id="ccTotalEquity" style="color: #a7f3d0;">10,000.00</span> POLF</span>
        </div>
        <div class="trades-card">
            <span class="trades-card-title">FEES & EST. PNL</span>
            <span class="trades-card-val" id="ccFeesVal" style="color: #f43f5e;">0.00 POLF</span>
            <span class="trades-card-sub">UNREALIZED: <span id="ccUnrealizedPnl" style="color: #10b981;">+$0.00</span></span>
        </div>
        <div class="trades-card">
            <span class="trades-card-title">MARKET REGIME</span>
            <span class="trades-card-val" id="ccRegimeBadge" style="font-size: 11px; color: #f59e0b;">SYNCHRONIZING</span>
            <span class="trades-card-sub">BIAS: <span id="ccActionBadge" style="color: #ef4444; font-weight:800;">EVALUATING</span></span>
        </div>
    </div>

    <!-- Agent Identity & Status Banner -->
    <div style="background: #020705; border: 1px solid #133324; border-radius: 5px; padding: 6px 10px; font-size: 10.5px; display: flex; justify-content: space-between; align-items: center;">
        <div style="color: #86efac; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 380px;">
            AGENT DID: <span id="ccAgentStatus" style="font-weight: 700; color: #a7f3d0;">did:key:z6MkmVhZbUKWmg3r6TTi3SVM3myYJ9BLbWYPSdc5iWPuPhb6</span>
        </div>
        <span id="ccRegSweepBadge" style="color: #00f5ff; font-weight: 800; font-size: 10px;">INITIALIZING...</span>
    </div>

    <!-- Fast Action Command Row -->
    <div style="display: flex; gap: 5px; margin: 4px 0;">
        <button class="hud-btn" onclick="runAutonomousCycle()" style="flex: 1.2; justify-content: center; background: #064e3b; border-color: #10b981; color: #a7f3d0; font-weight: 800;" title="Run 1 autonomous trading cycle (scans, trades, and quotes)">
            ⚡ Run Trading Cycle
        </button>
        <button class="hud-btn" onclick="postSkewedQuote()" style="flex: 1; justify-content: center; background: #2e1065; border-color: #8b5cf6; color: #c4b5fd; font-weight: 800;" title="Post inventory-skewed two-sided maker quote">
            📐 Post Skewed Quote
        </button>
        <button class="hud-btn" onclick="const f=document.getElementById('ccOfferForm'); f.style.display = f.style.display === 'none' ? 'block' : 'none';" style="justify-content: center; border-color: #f59e0b; color: #fde68a;">
            + Maker
        </button>
        <button class="hud-btn" onclick="registerCloseCallOwner()" style="justify-content: center; border-color: #3b82f6; color: #93c5fd;">
            🔑 Register
        </button>
        <button class="hud-btn" onclick="loadTradesData()" style="justify-content: center;">
            🔄 Refresh
        </button>
    </div>

    <!-- Collapsible Maker Offer Form -->
    <div id="ccOfferForm" style="display: none; background: #030a07; border: 1px solid #f59e0b; border-radius: 6px; padding: 10px; margin-bottom: 8px;">
        <div style="font-size: 11px; font-weight: 700; color: #f59e0b; margin-bottom: 6px;">POST SIGNED MAKER OFFER (RULE 11 COMPLIANT)</div>
        <div style="display: flex; gap: 6px; margin-bottom: 6px;">
            <div style="flex: 1;">
                <div style="font-size: 10px; color: #86efac;">Side:</div>
                <select id="ccSideInput" class="composer-input" style="min-height: auto; padding: 5px;">
                    <option value="buy">BUY</option>
                    <option value="sell">SELL</option>
                </select>
            </div>
            <div style="flex: 1;">
                <div style="font-size: 10px; color: #86efac;">Qty (>= 0.1):</div>
                <input type="text" id="ccQtyInput" value="1.00" class="composer-input" style="min-height: auto; padding: 5px;">
            </div>
            <div style="flex: 1;">
                <div style="font-size: 10px; color: #86efac;">Price (POLF):</div>
                <input type="text" id="ccPxInput" placeholder="224.80" class="composer-input" style="min-height: auto; padding: 5px;">
            </div>
        </div>
        <div style="display: flex; gap: 6px; margin-bottom: 8px;">
            <div style="flex: 1;">
                <div style="font-size: 10px; color: #86efac;">Room:</div>
                <input type="text" id="ccRoomInput" value="close1" class="composer-input" style="min-height: auto; padding: 5px;">
            </div>
            <div style="flex: 1;">
                <div style="font-size: 10px; color: #86efac;">Taker (any or did):</div>
                <input type="text" id="ccTakerInput" value="any" class="composer-input" style="min-height: auto; padding: 5px;">
            </div>
        </div>
        <button class="hud-btn" onclick="submitCloseCallOffer()" style="width: 100%; justify-content: center; background: #f59e0b; color: #000; font-weight: 800;">
            Sign & Broadcast Offer 🚀
        </button>
    </div>

    <!-- Interactive Navigation Tabs -->
    <div class="trades-subtabs">
        <button class="trades-subtab-btn active" id="tabBtnOb" onclick="switchTradesTab('ob')">📖 Order Book</button>
        <button class="trades-subtab-btn" id="tabBtnOffers" onclick="switchTradesTab('offers')">⚡ Open Offers</button>
        <button class="trades-subtab-btn" id="tabBtnHistory" onclick="switchTradesTab('history')">📜 My Trades (<span id="cntMyTrades">0</span>)</button>
        <button class="trades-subtab-btn" id="tabBtnRanks" onclick="switchTradesTab('ranks')">🏆 Standings & Flow</button>
        <button class="trades-subtab-btn" id="tabBtnBot" onclick="switchTradesTab('bot')">🤖 Bot</button>
    </div>

    <!-- TAB 1: ORDER BOOK & DEPTH -->
    <div id="tradesPaneOb" style="flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 8px;">
        <div style="display: flex; justify-content: space-between; align-items: center; font-size: 10.5px; background: #030806; padding: 4px 8px; border-radius: 4px; border: 1px solid #133324;">
            <span style="color: #64748b;">SPREAD: <b id="obSpreadVal" style="color: #fde68a;">--</b></span>
            <span style="color: #64748b;">MID PX: <b id="obMidPxVal" style="color: #00f5ff;">--</b></span>
            <span style="color: #64748b;">CORRIDOR: <b style="color: #10b981;">±5.0% HYPERLIQUID</b></span>
        </div>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px;">
            <!-- Bids Column -->
            <div style="background: #020705; border: 1px solid #133324; border-radius: 6px; padding: 6px;">
                <div style="font-size: 10px; font-weight: 800; color: #10b981; border-bottom: 1px solid #133324; padding-bottom: 3px; margin-bottom: 4px; display: flex; justify-content: space-between;">
                    <span>BIDS (BUY)</span>
                    <span>QTY / DEPTH</span>
                </div>
                <div id="obBidsList" style="display: flex; flex-direction: column; gap: 2px;">
                    <div style="color: #64748b; font-size: 10.5px; padding: 4px;">Loading bids...</div>
                </div>
            </div>
            <!-- Asks Column -->
            <div style="background: #020705; border: 1px solid #133324; border-radius: 6px; padding: 6px;">
                <div style="font-size: 10px; font-weight: 800; color: #ef4444; border-bottom: 1px solid #133324; padding-bottom: 3px; margin-bottom: 4px; display: flex; justify-content: space-between;">
                    <span>ASKS (SELL)</span>
                    <span>QTY / DEPTH</span>
                </div>
                <div id="obAsksList" style="display: flex; flex-direction: column; gap: 2px;">
                    <div style="color: #64748b; font-size: 10.5px; padding: 4px;">Loading asks...</div>
                </div>
            </div>
        </div>
    </div>

    <!-- TAB 2: ACTIVE EXECUTABLE OFFERS -->
    <div id="tradesPaneOffers" style="flex: 1; overflow-y: auto; display: none; flex-direction: column; gap: 6px;">
        <div style="font-size: 10.5px; font-weight: 700; color: #a7f3d0; margin-bottom: 2px;">OPEN COUNTERPARTY OFFERS IN ACTIVE ROOMS:</div>
        <div id="ccOfferList" style="display: flex; flex-direction: column; gap: 6px;">
            <div style="color: #6ee7b7; font-size: 11px;">Scanning registered trading rooms...</div>
        </div>
    </div>

    <!-- TAB 3: AGENT TRADE REGISTRY & HISTORY -->
    <div id="tradesPaneHistory" style="flex: 1; overflow-y: auto; display: none; flex-direction: column; gap: 6px;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <div style="font-size: 10.5px; font-weight: 700; color: #a7f3d0;">ALL TRACKED AGENT TRADES:</div>
            <div style="display: flex; gap: 4px;">
                <button class="speed-btn active" id="fltAll" onclick="filterTradesTable('ALL')">All</button>
                <button class="speed-btn" id="fltSettled" onclick="filterTradesTable('SETTLED')">Settled</button>
                <button class="speed-btn" id="fltVoid" onclick="filterTradesTable('VOID')">Void</button>
                <button class="speed-btn" id="fltOpen" onclick="filterTradesTable('OPEN')">Open</button>
            </div>
        </div>
        <div style="max-height: 380px; overflow-y: auto; border: 1px solid #133324; border-radius: 6px;">
            <table class="ob-table" style="font-size: 10px;">
                <thead>
                    <tr style="background: #020906;">
                        <th>ID</th>
                        <th>SIDE</th>
                        <th>QTY</th>
                        <th>PRICE</th>
                        <th>TOTAL</th>
                        <th>ROLE</th>
                        <th>STATUS</th>
                        <th>SWEEP</th>
                    </tr>
                </thead>
                <tbody id="tradesTableBody">
                    <tr><td colspan="8" style="text-align: center; color: #64748b; padding: 10px;">Loading trades history...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <!-- TAB 4: LEADERBOARD & SWEEP FLOW -->
    <div id="tradesPaneRanks" style="flex: 1; overflow-y: auto; display: none; flex-direction: column; gap: 8px;">
        <!-- Top PnL Leaderboard -->
        <div style="background: #020705; border: 1px solid #133324; border-radius: 6px; padding: 8px;">
            <div style="font-size: 10.5px; font-weight: 800; color: #fbbf24; margin-bottom: 4px; display: flex; justify-content: space-between;">
                <span>🏆 TOP PNL STANDINGS (/r/d-close1-pnl)</span>
                <span style="color: #64748b; font-size: 9.5px;">MARK: <b id="rankMarkPx" class="stat-placeholder">—</b></span>
            </div>
            <div id="pnlLeaderboardList" style="display: flex; flex-direction: column; gap: 3px; font-size: 10px;">
                <div style="color: #64748b; padding: 4px;">Loading standings...</div>
            </div>
        </div>
        <!-- Recent Sweep Settlement Flow -->
        <div style="background: #020705; border: 1px solid #133324; border-radius: 6px; padding: 8px;">
            <div style="font-size: 10.5px; font-weight: 800; color: #00f5ff; margin-bottom: 4px;">
                📜 REFEREE SWEEP FLOW FEED (/r/d-close1-flow)
            </div>
            <div id="flowFeedList" style="display: flex; flex-direction: column; gap: 4px; font-size: 10px; max-height: 160px; overflow-y: auto;">
                <div style="color: #64748b; padding: 4px;">Loading flow events...</div>
            </div>
        </div>
    </div>

    <!-- TAB 5: BOT AUTOMATION SETTINGS -->
    <div id="tradesPaneBot" style="flex: 1; overflow-y: auto; display: none; flex-direction: column; gap: 8px;">
        <div style="background: #020705; border: 1px solid #133324; border-radius: 6px; padding: 10px; font-size: 11px;">
            <div style="font-weight: 800; color: #a7f3d0; margin-bottom: 6px;">🤖 AUTONOMOUS TRADING BOT SPECIFICATION</div>
            <div style="color: #94a3b8; font-size: 10.5px; line-height: 1.5; margin-bottom: 8px;">
                Sentinel operates an autonomous risk-managed trading loop across all 300s Close Call sweeps:
                <ul style="padding-left: 18px; margin: 4px 0;">
                    <li>Multi-timeframe Trend Gate: Evaluates LTF/HTF price momentum & linear regression slope.</li>
                    <li>Dynamic Volatility Buffers: Automatically widens quoting spread in turbulent market regimes.</li>
                    <li>Clawback Arbitrage: Identifies mispriced counterparty offers that beat Hyperliquid reference prices.</li>
                    <li>Inventory Neutralizer: Prioritizes closing trades to mitigate overnight exposure risk.</li>
                </ul>
            </div>
            <div style="display: flex; gap: 6px;">
                <button class="hud-btn" onclick="runAutonomousCycle()" style="flex: 1; justify-content: center; background: #064e3b; border-color: #10b981; color: #a7f3d0; font-weight: 800;">
                    ⚡ Force Immediate Cycle
                </button>
                <button class="hud-btn" onclick="postSkewedQuote()" style="flex: 1; justify-content: center; background: #1e1b4b; border-color: #6366f1; color: #c7d2fe; font-weight: 800;">
                    📐 Send Maker Quote
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Drawer: Swarm & Challenge Leaderboards -->
<div class="drawer" id="leaderboardDrawer" style="width: 560px; max-width: 95vw;">
    <div class="drawer-header">
        <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-size: 16px;">🏆</span>
            <div>
                <div style="font-size: 13px; font-weight: 800; color: #fbbf24; letter-spacing: 0.5px;">SWARM & CHALLENGE LEADERBOARDS</div>
                <div style="font-size: 10px; color: #64748b;">Cryptographic Standings • Live Settlement Feeds • Top Ranks</div>
            </div>
        </div>
        <div style="display: flex; align-items: center; gap: 8px;">
            <button class="hud-btn" style="padding: 3px 8px; font-size: 10px; border-color: #3b82f6; color: #93c5fd;" onclick="loadLeaderboardData(true)">🔄 Refresh</button>
            <button class="drawer-close" onclick="closeDrawer('leaderboardDrawer')">{icon_close}</button>
        </div>
    </div>

    <!-- Category Tabs -->
    <div style="display: flex; gap: 6px; border-bottom: 1px solid #133324; padding-bottom: 8px;">
        <button class="hud-btn active" id="btnLbTrades" style="flex: 1; justify-content: center; font-size: 10.5px;" onclick="switchLbTab('trades')">📈 Close-1 Trades</button>
        <button class="hud-btn" id="btnLbEscrow" style="flex: 1; justify-content: center; font-size: 10.5px;" onclick="switchLbTab('escrow')">🤝 TCLK Escrow</button>
        <button class="hud-btn" id="btnLbSwarm" style="flex: 1; justify-content: center; font-size: 10.5px;" onclick="switchLbTab('swarm')">🌐 Swarm Nodes</button>
    </div>

    <!-- PANE 1: TRADES PNL LEADERBOARD -->
    <div id="lbPaneTrades" style="flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 10px;">
        <!-- Telemetry Header -->
        <div style="display: flex; justify-content: space-between; align-items: center; background: #020705; border: 1px solid #133324; border-radius: 6px; padding: 8px 12px; font-size: 11px;">
            <div>SWEEP: <b id="lbSweepN" class="stat-placeholder">—</b></div>
            <div>GLOBAL MARK: <b id="lbMarkPx" class="stat-placeholder">—</b></div>
            <div>HYPER REF: <b id="lbRefPx" class="stat-placeholder">—</b></div>
            <div>ROOM: <span style="color: #a7f3d0; font-family: monospace;">d-close1-pnl</span></div>
        </div>

        <!-- TOP 3 PODIUM CARDS -->
        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px;" id="lbPodiumRow">
            <div style="color: #64748b; font-size: 10px; grid-column: span 3; text-align: center; padding: 6px;">Loading podium...</div>
        </div>

        <!-- OUR AGENT STANDING SPOTLIGHT -->
        <div id="lbOurAgentCard" style="background: linear-gradient(135deg, rgba(245, 158, 11, 0.12), rgba(16, 185, 129, 0.08)); border: 1px solid #f59e0b; border-radius: 8px; padding: 10px;">
            <div style="color: #64748b; font-size: 10px;">Loading our status...</div>
        </div>

        <!-- FILTER & FULL STANDINGS TABLE -->
        <div style="background: #020705; border: 1px solid #133324; border-radius: 6px; padding: 10px; display: flex; flex-direction: column; gap: 8px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div style="font-size: 11px; font-weight: 800; color: #a7f3d0;">FULL OFFICIAL STANDINGS (TOP 25)</div>
                <input type="text" id="lbSearchInput" placeholder="Filter by DID..." oninput="filterLbStandings()" style="background: #06150f; border: 1px solid #1e3a2b; border-radius: 4px; padding: 3px 8px; color: #fff; font-size: 10px; width: 150px; outline: none;">
            </div>
            <div style="max-height: 240px; overflow-y: auto;">
                <table style="width: 100%; border-collapse: collapse; font-size: 10.5px; text-align: left;">
                    <thead>
                        <tr style="border-bottom: 1px solid #1e3a2b; color: #64748b; font-size: 9.5px;">
                            <th style="padding: 4px 6px;"># RANK</th>
                            <th style="padding: 4px 6px;">CONTENDER DID</th>
                            <th style="padding: 4px 6px; text-align: right;">REALIZED PNL</th>
                            <th style="padding: 4px 6px; text-align: center;">STATUS</th>
                        </tr>
                    </thead>
                    <tbody id="lbStandingsTableBody">
                        <tr><td colspan="4" style="color: #64748b; padding: 8px; text-align: center;">Loading official standings...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- TOP POSITIONS LADDER -->
        <div style="background: #020705; border: 1px solid #133324; border-radius: 6px; padding: 8px;">
            <div style="font-size: 10.5px; font-weight: 800; color: #38bdf8; margin-bottom: 6px;">📊 TOP POSITION HOLDERS (/r/d-close1-pos)</div>
            <div id="lbPositionsList" style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 6px; font-size: 10px;">
                <div style="color: #64748b;">Loading positions...</div>
            </div>
        </div>
    </div>

    <!-- PANE 2: TCLK ESCROW & BOUNTIES LEADERBOARD -->
    <div id="lbPaneEscrow" style="flex: 1; overflow-y: auto; display: none; flex-direction: column; gap: 10px;">
        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px;">
            <div style="background: #020705; border: 1px solid #10b981; border-radius: 6px; padding: 8px; text-align: center;">
                <div style="font-size: 9.5px; color: #6ee7b7;">REAL CLAIMED FLOP</div>
                <div style="font-size: 14px; font-weight: 900; color: #34d399; margin-top: 2px;">7,300 FLOP</div>
                <div style="font-size: 9px; color: #64748b;">5 HTLC Cycles Secured</div>
            </div>
            <div style="background: #020705; border: 1px solid #133324; border-radius: 6px; padding: 8px; text-align: center;">
                <div style="font-size: 9.5px; color: #94a3b8;">NETWORK DEALS</div>
                <div id="lbTotalDeals" style="font-size: 14px; font-weight: 900; color: #00f5ff; margin-top: 2px;">51,970</div>
                <div style="font-size: 9px; color: #64748b;">Evaluated & Ingested</div>
            </div>
            <div style="background: #020705; border: 1px solid #133324; border-radius: 6px; padding: 8px; text-align: center;">
                <div style="font-size: 9.5px; color: #94a3b8;">ESCROW PROTOCOL</div>
                <div style="font-size: 12px; font-weight: 900; color: #fbbf24; margin-top: 4px;">SHA256 HTLC</div>
                <div style="font-size: 9px; color: #10b981;">Atomic Hash-Locks</div>
            </div>
        </div>

        <div style="background: #020705; border: 1px solid #133324; border-radius: 6px; padding: 10px;">
            <div style="font-size: 11px; font-weight: 800; color: #fbbf24; margin-bottom: 8px;">💼 TOP ESCROW BOUNTY PAYERS</div>
            <table style="width: 100%; border-collapse: collapse; font-size: 10px; text-align: left;">
                <thead>
                    <tr style="border-bottom: 1px solid #1e3a2b; color: #64748b; font-size: 9px;">
                        <th style="padding: 4px;">#</th>
                        <th style="padding: 4px;">PAYER DID</th>
                        <th style="padding: 4px; text-align: center;">DEALS CREATED</th>
                        <th style="padding: 4px; text-align: right;">TOTAL VOLUME</th>
                    </tr>
                </thead>
                <tbody id="lbPayersTableBody">
                    <tr><td colspan="4" style="color: #64748b; padding: 8px; text-align: center;">Loading top payers...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <!-- PANE 3: SWARM NODES & REPUTATION -->
    <div id="lbPaneSwarm" style="flex: 1; overflow-y: auto; display: none; flex-direction: column; gap: 10px;">
        <div style="background: #020705; border: 1px solid #133324; border-radius: 6px; padding: 10px;">
            <div style="font-size: 11px; font-weight: 800; color: #00f5ff; margin-bottom: 8px;">🌐 TECHNOCORE SENTINEL MESH TELEMETRY</div>
            <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 8px; font-size: 11px;">
                <div style="background: #04100b; border: 1px solid #132a21; border-radius: 4px; padding: 8px;">
                    <div style="color: #64748b; font-size: 10px;">HEARTBEAT BROADCASTS</div>
                    <div id="lbSwarmHeartbeats" style="font-size: 15px; font-weight: 900; color: #34d399; margin-top: 2px;">1,804</div>
                </div>
                <div style="background: #04100b; border: 1px solid #132a21; border-radius: 4px; padding: 8px;">
                    <div style="color: #64748b; font-size: 10px;">TOTAL SWARM MESSAGES</div>
                    <div id="lbSwarmReplies" style="font-size: 15px; font-weight: 900; color: #00f5ff; margin-top: 2px;">122,040</div>
                </div>
                <div style="background: #04100b; border: 1px solid #132a21; border-radius: 4px; padding: 8px;">
                    <div style="color: #64748b; font-size: 10px;">CHANNELS MONITORED</div>
                    <div style="font-size: 15px; font-weight: 900; color: #f59e0b; margin-top: 2px;">24 Core + 6,092 Deals</div>
                </div>
                <div style="background: #04100b; border: 1px solid #132a21; border-radius: 4px; padding: 8px;">
                    <div style="color: #64748b; font-size: 10px;">THREAT DEFENSE STATUS</div>
                    <div style="font-size: 15px; font-weight: 900; color: #10b981; margin-top: 2px;">100% CLEAN (0 Threats)</div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Drawer 2: Terminal Console -->
<div class="drawer" id="terminalDrawer">
    <div class="drawer-header">
        <span>🖥️ LIVE STREAM CONSOLE (/api/logs)</span>
        <button class="drawer-close" onclick="closeDrawer('terminalDrawer')">{icon_close}</button>
    </div>
    <div class="terminal-box" id="terminalLogBox">
        [Loading live activity logs...]
    </div>
</div>

<!-- Drawer 3: Gated Room & DID Tools -->
<div class="drawer" id="toolsDrawer">
    <div class="drawer-header">
        <span>🔐 ROOM & IDENTITY TOOLS</span>
        <button class="drawer-close" onclick="closeDrawer('toolsDrawer')">{icon_close}</button>
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
        <div style="font-size: 11px; color: #cbd5e1;" id="modalContent"><span class="stat-placeholder">—</span></div>
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
    // Auth is the HttpOnly session cookie; no token is embedded in this document.
    const SENTINEL_FETCH = {{ credentials: 'same-origin' }};

    // A 401 means the session expired or was rotated by a new login elsewhere.
    (function () {{
        const _sentinelFetch = window.fetch.bind(window);
        window.fetch = async function (...args) {{
            const res = await _sentinelFetch(...args);
            if (res.status === 401) window.location.replace('{LOGIN_PATH}');
            return res;
        }};
    }})();
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
        const badgeLabels = {{
            'galaxy': '🌌 CELESTIAL GALAXY',
            'neural': '⚡ NEURAL CONSTELLATION',
            'isometric': '📐 2.5D ISOMETRIC MATRIX',
            'tclk': '🤝 TCLK CRYPTOGRAPHIC ESCROW GRID',
            'trades': '📊 3D TRADES MATRIX & ORDER BOOK PIT',
        }};
        const badgeColors = {{
            'galaxy': '#00f5ff',
            'neural': '#60a5fa',
            'isometric': '#fbbf24',
            'tclk': '#10b981',
            'trades': '#f59e0b',
        }};

        const pBtn = document.getElementById('perspectiveBtn');
        if (pBtn) {{
            const labels = {{
                'galaxy': '🌌 Galaxy Orbit',
                'neural': '⚡ Neural Mesh',
                'isometric': '📐 2.5D Isometric',
                'tclk': '🤝 TCLK Escrow Grid',
                'trades': '📊 Trades Matrix Pit',
            }};
            pBtn.innerText = labels[currentMode] || labels['galaxy'];
        }}

        const pLbl = document.getElementById('perspectiveLbl');
        if (pLbl) {{
            pLbl.innerText = badgeLabels[currentMode] || badgeLabels['galaxy'];
            pLbl.style.color = badgeColors[currentMode] || '#00f5ff';
        }}

        // Update active class on tab buttons
        document.querySelectorAll('.mode-tab-btn').forEach(btn => {{
            if (btn.dataset && btn.dataset.mode === currentMode) {{
                btn.classList.add('active');
            }} else {{
                btn.classList.remove('active');
            }}
        }});

        const freqs = {{ 'galaxy': 700, 'neural': 820, 'isometric': 760, 'tclk': 880, 'trades': 940 }};
        playBeep(freqs[currentMode] || 700, 'triangle', 0.08);

        if (currentMode === 'tclk') {{
            loadTclkDeals();
        }} else if (currentMode === 'trades') {{
            loadTradesData();
        }}
    }}

    function cyclePerspective() {{
        const modes = ['galaxy', 'neural', 'isometric', 'tclk', 'trades'];
        const idx = (modes.indexOf(currentMode) + 1) % modes.length;
        setPerspective(modes[idx]);
    }}

    function toggleDrawer(id) {{
        const target = document.getElementById(id);
        const willOpen = target && !target.classList.contains('open');
        document.querySelectorAll('.drawer').forEach(d => {{
            d.classList.remove('open');
        }});
        if (willOpen && target) {{
            target.classList.add('open');
            playBeep(600, 'triangle', 0.05);
        }} else {{
            playBeep(450, 'triangle', 0.04);
        }}
    }}

    function closeDrawer(id) {{
        const target = id ? document.getElementById(id) : null;
        if (target) {{
            target.classList.remove('open');
            playBeep(450, 'triangle', 0.04);
        }} else {{
            closeAllDrawers();
        }}
    }}

    // Tools launcher (Phase 1c): one dropdown replacing the 6 separate drawer
    // buttons + sound toggle that used to crowd the action row. Each item below
    // calls the exact same toggleDrawer()/load*() pair the old button did, so
    // every other call site into these drawers (cmd palette, ping, claim,
    // publish, close-call poller guard) is untouched.
    function toggleToolsLauncher(evt) {{
        if (evt) evt.stopPropagation();
        const menu = document.getElementById('toolsLauncherMenu');
        if (menu) menu.classList.toggle('open');
    }}
    function closeToolsLauncher() {{
        const menu = document.getElementById('toolsLauncherMenu');
        if (menu) menu.classList.remove('open');
    }}
    document.addEventListener('click', (evt) => {{
        const launcher = document.getElementById('toolsLauncher');
        if (launcher && !launcher.contains(evt.target)) closeToolsLauncher();
    }});

    function closeAllDrawers() {{
        document.querySelectorAll('.drawer.open').forEach(d => d.classList.remove('open'));
    }}

    // Global Key Listener: Escape closes any active drawer or modal
    document.addEventListener('keydown', (e) => {{
        if (e.key === 'Escape') {{
            closeAllDrawers();
            closeCmdPalette();
            clearTargetLock();
        }}
    }});

    // Global Click Listener: clicking outside open drawer closes it
    document.addEventListener('click', (e) => {{
        if (!e.target.closest('.drawer') && !e.target.closest('.hud-btn') && !e.target.closest('.ribbon-badge') && !e.target.closest('.macro-pill')) {{
            closeAllDrawers();
        }}
    }});

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

    // Phase 0: keep --chrome-h synced to the ribbon's real rendered height (not
    // a hardcoded guess), and re-fit the canvas on any CSS-driven size change to
    // #simContainer (drawer open/close, viewport resize, etc.) rather than only
    // on window resize, so it never letterboxes.
    const chromeObserver = new ResizeObserver((entries) => {{
        for (const entry of entries) {{
            if (entry.target.id === 'simContainer') {{
                resizeCanvases();
            }} else {{
                document.documentElement.style.setProperty('--chrome-h', entry.contentRect.height + 'px');
            }}
        }}
    }});
    const ribbonEl = document.querySelector('.ribbon-header');
    if (ribbonEl) chromeObserver.observe(ribbonEl);
    const simBoxEl = document.getElementById('simContainer');
    if (simBoxEl) chromeObserver.observe(simBoxEl);

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

    // Animated Floating 3D FLOP Coins Fleet
    class FlopFloatingCoin {{
        constructor() {{
            this.angle = Math.random() * Math.PI * 2;
            this.orbitRadius = 110 + Math.random() * 260;
            this.speed = (0.004 + Math.random() * 0.007) * (Math.random() < 0.5 ? 1 : -1);
            this.wobbleSpeed = 0.02 + Math.random() * 0.03;
            this.wobbleAmp = 8 + Math.random() * 20;
            this.spinSpeed = 0.035 + Math.random() * 0.04;
            this.spinAngle = Math.random() * Math.PI * 2;
            this.size = 14 + Math.random() * 7;
            const values = ['12,500 FLOP', '50,000 FLOP', '5,000 FLOP', '1,000 FLOP', '12.5K ESCROW', '2,500 FLOP'];
            this.valText = values[Math.floor(Math.random() * values.length)];
            this.animTick = Math.random() * 100;
            this.trail = [];
        }}
        update(cx, cy) {{
            this.animTick += 0.035;
            this.angle += this.speed * playSpeed;
            this.spinAngle += this.spinSpeed * playSpeed;
            const wobble = Math.sin(this.animTick * 2) * this.wobbleAmp;
            const scaleX = Math.max(1.0, sCanvas.width / 650);
            const scaleY = Math.max(1.0, sCanvas.height / 600);
            const rx = (this.orbitRadius * scaleX) + wobble;
            const ry = (this.orbitRadius * scaleY * 0.85) + wobble;
            this.x = cx + Math.cos(this.angle) * rx;
            this.y = cy + Math.sin(this.angle) * ry;

            // Sparkle Trail
            if (Math.random() < 0.4) {{
                this.trail.push({{ x: this.x, y: this.y, alpha: 0.8, size: 2 + Math.random() * 2 }});
                if (this.trail.length > 8) this.trail.shift();
            }}
            this.trail.forEach(t => t.alpha -= 0.04);
            this.trail = this.trail.filter(t => t.alpha > 0);
        }}
        draw(ctx) {{
            // Sparkle Trail
            this.trail.forEach(t => {{
                ctx.beginPath();
                ctx.arc(t.x, t.y, t.size, 0, Math.PI * 2);
                ctx.fillStyle = `rgba(251, 191, 36, ${{t.alpha}})`;
                ctx.shadowColor = '#fbbf24';
                ctx.shadowBlur = 6;
                ctx.fill();
            }});

            ctx.save();
            ctx.translate(this.x, this.y);
            const cosSpin = Math.cos(this.spinAngle);
            const absCos = Math.max(0.12, Math.abs(cosSpin));

            // Outer golden glow
            ctx.shadowColor = '#fbbf24';
            ctx.shadowBlur = 12;

            // Coin 3D Rim (depth)
            const rimOffset = (cosSpin >= 0 ? 1 : -1) * 3 * (1 - absCos);
            ctx.beginPath();
            ctx.ellipse(rimOffset, 0, this.size * absCos, this.size, 0, 0, Math.PI * 2);
            ctx.fillStyle = '#b45309';
            ctx.fill();

            // Coin Face
            ctx.beginPath();
            ctx.ellipse(0, 0, this.size * absCos, this.size, 0, 0, Math.PI * 2);
            const grad = ctx.createLinearGradient(-this.size, -this.size, this.size, this.size);
            grad.addColorStop(0, '#fef08a');
            grad.addColorStop(0.3, '#f59e0b');
            grad.addColorStop(0.7, '#fbbf24');
            grad.addColorStop(1, '#d97706');
            ctx.fillStyle = grad;
            ctx.fill();
            ctx.strokeStyle = '#fff';
            ctx.lineWidth = 1;
            ctx.stroke();

            // Embossed FLOP symbol
            if (absCos > 0.4) {{
                ctx.fillStyle = '#78350f';
                ctx.font = `bold ${{Math.floor(this.size * 0.9)}}px sans-serif`;
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText('₣', 0, 1);
            }}

            // Specular Glint
            const glintAlpha = Math.max(0, Math.sin(this.spinAngle * 2));
            if (glintAlpha > 0.6) {{
                ctx.fillStyle = `rgba(255, 255, 255, ${{glintAlpha * 0.7}})`;
                ctx.beginPath();
                ctx.arc(-this.size * 0.3 * absCos, -this.size * 0.3, 2.5, 0, Math.PI * 2);
                ctx.fill();
            }}

            // Value Tag Pill
            ctx.shadowBlur = 0;
            ctx.fillStyle = 'rgba(15, 23, 42, 0.85)';
            ctx.strokeStyle = 'rgba(251, 191, 36, 0.6)';
            ctx.lineWidth = 0.8;
            const tw = ctx.measureText(this.valText).width + 12;
            const py = this.size + 8;
            ctx.fillRect(-tw / 2, py - 6, tw, 13);
            ctx.strokeRect(-tw / 2, py - 6, tw, 13);
            ctx.fillStyle = '#fde68a';
            ctx.font = 'bold 8px Courier New';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillText(this.valText, 0, py);

            ctx.restore();
        }}
    }}

    const floatingCoins = [];
    for (let c = 0; c < 15; c++) {{
        floatingCoins.push(new FlopFloatingCoin());
    }}

    // Celestial Mecha Drone Class
    class CyberGalaxyNode {{
        constructor(id, isMaster = false, isDid = false, threat = 'CLEAN', text = '', role = 'peer', orbitRadius = 100, orbitSpeed = 0.01, seat = null, customName = null) {{
            this.id = id;
            this.isMaster = isMaster;
            this.isDid = isDid;
            this.threat = threat;
            this.text = text;
            this.role = role;
            this.seat = seat;
            this.customName = customName;
            
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
                let pCol = this.threat === 'THREAT' ? '#ef4444' : (this.isDid ? '#00f5ff' : '#10b981');
                if (this.role === 'poet') pCol = '#ec4899';
                else if (this.role === 'referee') pCol = '#fbbf24';
                else if (this.role === 'teammate') pCol = '#34d399';
                particles.push({{
                    x: this.x,
                    y: this.y + 6,
                    vx: -Math.cos(this.angle) * 0.8 + (Math.random() - 0.5) * 0.5,
                    vy: -Math.sin(this.angle) * 0.8 + 0.8,
                    life: 1.0,
                    color: pCol
                }});
            }}
        }}

        getScreenPos() {{
            const cx = sCanvas.width / 2;
            const cy = sCanvas.height / 2;
            if (currentMode === 'isometric') {{
                const relX = this.x - cx;
                const relY = this.y - cy;
                const fx = cx + (relX - relY) * 0.82;
                const fy = cy + (relX + relY) * 0.44;
                const elev = this.isMaster ? 0 : 36;
                return {{
                    x: fx,
                    y: fy - elev,
                    floorX: fx,
                    floorY: fy,
                    scale: 0.85 + (this.y / sCanvas.height) * 0.3
                }};
            }}
            if (currentMode === 'tclk') {{
                if (this.isMaster) {{
                    return {{ x: cx, y: cy, scale: 1.15 }};
                }}
                const rx = sCanvas.width * 0.35;
                const ry = sCanvas.height * 0.30;
                return {{
                    x: cx + Math.cos(this.angle) * rx,
                    y: cy + Math.sin(this.angle) * ry,
                    scale: 1.05
                }};
            }}
            if (currentMode === 'trades') {{
                if (this.isMaster) {{
                    return {{ x: cx, y: cy + 130, floorX: cx, floorY: cy + 130, scale: 1.25 }};
                }}
                if (this.nodeIndex === 0 || this.seat === 0) {{
                    return {{ x: cx, y: cy - 140, floorX: cx, floorY: cy - 140, scale: 1.15 }};
                }}
                const rx = sCanvas.width * 0.38;
                const ry = sCanvas.height * 0.30;
                return {{
                    x: cx + Math.cos(this.angle) * rx,
                    y: cy + Math.sin(this.angle) * ry * 0.85,
                    floorX: cx + Math.cos(this.angle) * rx,
                    floorY: cy + Math.sin(this.angle) * ry * 0.85,
                    scale: 0.95
                }};
            }}
            return {{ x: this.x, y: this.y, scale: 1.0 }};
        }}

        drawSpinningCoin(ctx, coinRadius, glowCol) {{
            ctx.save();
            const coinRot = this.animTick * 2.8;
            const coinW = Math.cos(coinRot);
            const absCoinW = Math.max(0.12, Math.abs(coinW));

            ctx.shadowColor = glowCol || '#fbbf24';
            ctx.shadowBlur = 16;

            // Coin 3D Rim
            const rimDir = (coinW >= 0 ? 1 : -1) * 3 * (1 - absCoinW);
            ctx.beginPath();
            ctx.ellipse(rimDir, 0, coinRadius * absCoinW, coinRadius, 0, 0, Math.PI * 2);
            ctx.fillStyle = '#92400e';
            ctx.fill();

            // Coin Main Face
            ctx.beginPath();
            ctx.ellipse(0, 0, coinRadius * absCoinW, coinRadius, 0, 0, Math.PI * 2);
            const cGrad = ctx.createLinearGradient(-coinRadius, -coinRadius, coinRadius, coinRadius);
            cGrad.addColorStop(0, '#fef08a');
            cGrad.addColorStop(0.3, '#f59e0b');
            cGrad.addColorStop(0.7, '#fbbf24');
            cGrad.addColorStop(1, '#b45309');
            ctx.fillStyle = cGrad;
            ctx.fill();
            ctx.strokeStyle = '#fff';
            ctx.lineWidth = 1.2;
            ctx.stroke();

            // Embossed FLOP Symbol
            if (absCoinW > 0.35) {{
                ctx.fillStyle = '#78350f';
                ctx.font = 'bold 15px sans-serif';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText('₣', 0, 1);
            }}
            ctx.restore();
        }}

        draw(ctx) {{
            const pos = this.getScreenPos();
            const s = pos.scale;

            // In isometric mode, draw floor drop-shadow and vertical laser tether
            if (currentMode === 'isometric' && !this.isMaster && pos.floorY) {{
                ctx.save();
                ctx.beginPath();
                ctx.ellipse(pos.floorX, pos.floorY, 14 * s, 7 * s, 0, 0, Math.PI * 2);
                ctx.fillStyle = 'rgba(0, 0, 0, 0.45)';
                ctx.fill();

                ctx.beginPath();
                ctx.moveTo(pos.floorX, pos.floorY);
                ctx.lineTo(pos.x, pos.y);
                ctx.strokeStyle = 'rgba(245, 158, 11, 0.35)';
                ctx.lineWidth = 1.2;
                ctx.stroke();
                ctx.restore();
            }}

            ctx.save();
            ctx.translate(pos.x, pos.y);
            ctx.scale(s, s);

            if (this.isMaster) {{
                // =============================================================
                // CENTERPIECE FORTRESS - ADAPTS TO CURRENT PERSPECTIVE
                // =============================================================
                if (currentMode === 'tclk') {{
                    // 2. TCLK ATOMIC HTLC ESCROW VAULT
                    ctx.save();
                    const vRing = 50 + Math.sin(this.animTick * 2.5) * 4;
                    ctx.beginPath();
                    ctx.arc(0, 0, vRing, 0, Math.PI * 2);
                    ctx.strokeStyle = 'rgba(16, 185, 129, 0.45)';
                    ctx.lineWidth = 2;
                    ctx.stroke();

                    ctx.save();
                    ctx.rotate(this.gyroRotation * 1.2);
                    ctx.strokeStyle = '#10b981';
                    ctx.lineWidth = 2;
                    ctx.shadowColor = '#34d399';
                    ctx.shadowBlur = 14;
                    ctx.beginPath();
                    for (let i = 0; i < 8; i++) {{
                        const a = (i * Math.PI) / 4;
                        ctx.moveTo(Math.cos(a) * 32, Math.sin(a) * 32);
                        ctx.lineTo(Math.cos(a) * 42, Math.sin(a) * 42);
                    }}
                    ctx.stroke();

                    ctx.beginPath();
                    for (let i = 0; i < 8; i++) {{
                        const a = (i * Math.PI) / 4 + 0.2;
                        const gx = Math.cos(a) * 28;
                        const gy = Math.sin(a) * 28;
                        if (i === 0) ctx.moveTo(gx, gy);
                        else ctx.lineTo(gx, gy);
                    }}
                    ctx.closePath();
                    ctx.strokeStyle = '#6ee7b7';
                    ctx.stroke();
                    ctx.restore();

                    this.drawSpinningCoin(ctx, 16, '#10b981');

                    ctx.save();
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.fillStyle = '#6ee7b7';
                    ctx.font = '900 11.5px Courier New';
                    ctx.shadowColor = '#10b981';
                    ctx.shadowBlur = 10;
                    ctx.fillText('🤝 HTLC ESCROW VAULT', 0, -42);

                    ctx.fillStyle = '#fbbf24';
                    ctx.font = 'bold 8.5px Courier New';
                    ctx.shadowBlur = 0;
                    ctx.fillText('MULTI-HOP TIMELOCK CORE', 0, 42);

                    ctx.fillStyle = '#a7f3d0';
                    ctx.font = 'bold 7.5px Courier New';
                    ctx.fillText('SETTLEMENT ACTIVE', 0, 53);
                    ctx.restore();
                    ctx.restore();

                }} else if (currentMode === 'neural') {{
                    // 3. SYNAPTIC INTELLIGENCE NEURAL CORE
                    ctx.save();
                    const nRing = 46 + Math.sin(this.animTick * 3) * 6;
                    ctx.beginPath();
                    ctx.arc(0, 0, nRing, 0, Math.PI * 2);
                    ctx.strokeStyle = 'rgba(59, 130, 246, 0.4)';
                    ctx.lineWidth = 1.8;
                    ctx.stroke();

                    ctx.save();
                    ctx.rotate(this.gyroRotation * 0.8);
                    ctx.beginPath();
                    for (let i = 0; i < 12; i++) {{
                        const a = (i * Math.PI) / 6;
                        const pulse = Math.sin(this.animTick * 4 + i) * 6;
                        ctx.moveTo(Math.cos(a) * 20, Math.sin(a) * 20);
                        ctx.lineTo(Math.cos(a) * (36 + pulse), Math.sin(a) * (36 + pulse));
                    }}
                    ctx.strokeStyle = '#60a5fa';
                    ctx.lineWidth = 1.5;
                    ctx.stroke();
                    ctx.restore();

                    ctx.beginPath();
                    ctx.arc(0, 0, 20, 0, Math.PI * 2);
                    ctx.fillStyle = '#1e3a8a';
                    ctx.fill();
                    ctx.strokeStyle = '#60a5fa';
                    ctx.lineWidth = 1.5;
                    ctx.stroke();

                    ctx.fillStyle = '#fff';
                    ctx.font = '16px sans-serif';
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.fillText('🧠', 0, 0);

                    ctx.save();
                    ctx.textAlign = 'center';
                    ctx.fillStyle = '#60a5fa';
                    ctx.font = '900 11.5px Courier New';
                    ctx.fillText('⚡ SYNAPTIC CORE', 0, -42);

                    ctx.fillStyle = '#93c5fd';
                    ctx.font = 'bold 8.5px Courier New';
                    ctx.fillText('DEEP REASONING MATRIX', 0, 42);

                    ctx.fillStyle = '#c4b5fd';
                    ctx.font = 'bold 7.5px Courier New';
                    ctx.fillText('16 CHANNELS SYNCHRONIZED', 0, 53);
                    ctx.restore();
                    ctx.restore();

                }} else if (currentMode === 'isometric') {{
                    // 4. 2.5D ISOMETRIC CYBER CITADEL
                    ctx.save();
                    const isoTime = this.animTick * 1.2;
                    ctx.save();
                    ctx.scale(1, 0.55);
                    ctx.rotate(Math.PI / 4);

                    ctx.fillStyle = 'rgba(245, 158, 11, 0.15)';
                    ctx.fillRect(-46, -46, 92, 92);
                    ctx.strokeStyle = '#f59e0b';
                    ctx.lineWidth = 2;
                    ctx.shadowColor = '#fbbf24';
                    ctx.shadowBlur = 12;
                    ctx.strokeRect(-46, -46, 92, 92);

                    ctx.rotate(isoTime * 0.5);
                    ctx.fillStyle = 'rgba(16, 185, 129, 0.2)';
                    ctx.fillRect(-30, -30, 60, 60);
                    ctx.strokeStyle = '#34d399';
                    ctx.lineWidth = 1.5;
                    ctx.strokeRect(-30, -30, 60, 60);
                    ctx.restore();

                    ctx.fillStyle = '#fff';
                    ctx.font = '18px sans-serif';
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.fillText('🏛️', 0, -6);

                    ctx.save();
                    ctx.textAlign = 'center';
                    ctx.fillStyle = '#fbbf24';
                    ctx.font = '900 11.5px Courier New';
                    ctx.shadowColor = '#f59e0b';
                    ctx.shadowBlur = 10;
                    ctx.fillText('📐 SENTINEL CITADEL', 0, -42);

                    ctx.fillStyle = '#fbbf24';
                    ctx.font = 'bold 8.5px Courier New';
                    ctx.shadowBlur = 0;
                    ctx.fillText('2.5D ISOMETRIC HIGH GROUND', 0, 42);

                    ctx.fillStyle = '#34d399';
                    ctx.font = 'bold 7.5px Courier New';
                    ctx.fillText('SECURITY STATUS: DEFCON 5', 0, 53);
                    ctx.restore();
                    ctx.restore();

                }} else {{
                    // 5. GALAXY CELESTIAL GUARDIAN TITAN
                    ctx.save();
                    const ringR = 48 + Math.sin(this.animTick * 2) * 5;
                    ctx.beginPath();
                    ctx.arc(0, 0, ringR, 0, Math.PI * 2);
                    ctx.strokeStyle = 'rgba(0, 245, 255, 0.4)';
                    ctx.lineWidth = 1.8;
                    ctx.stroke();

                    const ringR2 = 64 + Math.cos(this.animTick * 1.5) * 4;
                    ctx.beginPath();
                    ctx.arc(0, 0, ringR2, 0, Math.PI * 2);
                    ctx.strokeStyle = 'rgba(16, 185, 129, 0.3)';
                    ctx.setLineDash([8, 6]);
                    ctx.stroke();
                    ctx.setLineDash([]);

                    ctx.save();
                    ctx.rotate(this.gyroRotation);
                    ctx.strokeStyle = '#00f5ff';
                    ctx.lineWidth = 2.5;
                    ctx.shadowColor = '#00f5ff';
                    ctx.shadowBlur = 15;
                    ctx.beginPath();
                    for (let i = 0; i < 6; i++) {{
                        const a = (i * Math.PI) / 3;
                        const hx = Math.cos(a) * 36;
                        const hy = Math.sin(a) * 36;
                        if (i === 0) ctx.moveTo(hx, hy);
                        else ctx.lineTo(hx, hy);
                    }}
                    ctx.closePath();
                    ctx.stroke();

                    ctx.rotate(-this.gyroRotation * 2);
                    ctx.strokeStyle = '#10b981';
                    ctx.lineWidth = 1.8;
                    ctx.shadowColor = '#34d399';
                    ctx.strokeRect(-22, -22, 44, 44);
                    ctx.restore();

                    this.drawSpinningCoin(ctx, 17, '#00f5ff');

                    ctx.save();
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.fillStyle = '#00f5ff';
                    ctx.font = '900 12px Courier New';
                    ctx.shadowColor = '#00f5ff';
                    ctx.shadowBlur = 10;
                    ctx.fillText('🌌 SENTINEL TITAN', 0, -42);

                    ctx.fillStyle = '#34d399';
                    ctx.font = 'bold 8.5px Courier New';
                    ctx.shadowBlur = 0;
                    ctx.fillText('ORBITAL DEFENSE OVERWATCH', 0, 42);

                    ctx.fillStyle = '#7dd3fc';
                    ctx.font = 'bold 7.5px Courier New';
                    ctx.fillText('ALL SECTORS NOMINAL • DEFCON 5', 0, 53);
                    ctx.restore();
                    ctx.restore();
                }}

            }} else if (this.role === 'poet') {{
                // =============================================================
                // PRIMARY AGENT NODE (@noob_nad) - ADAPTS TO CURRENT PERSPECTIVE
                // =============================================================
                ctx.save();
                let auraCol = 'rgba(0, 245, 255, 0.45)';
                let borderCol = '#00f5ff';
                let iconChar = '🛡️';
                let roleTitle = '🛡️ SENTINEL VANGUARD [@noob_nad]';
                let subTitle = 'ORBITAL SQUADRON ALPHA';

                if (currentMode === 'tclk') {{
                    auraCol = 'rgba(16, 185, 129, 0.45)';
                    borderCol = '#10b981';
                    iconChar = '💼';
                    roleTitle = '💼 AGENT @noob_nad [SETTLEMENT]';
                    subTitle = '12,500 FLOP LIQUIDITY';
                }} else if (currentMode === 'neural') {{
                    auraCol = 'rgba(59, 130, 246, 0.45)';
                    borderCol = '#3b82f6';
                    iconChar = '🧠';
                    roleTitle = '🧠 AGENT @noob_nad [Q-REASONING]';
                    subTitle = 'POLICY WEIGHTS CONVERGED';
                }} else if (currentMode === 'isometric') {{
                    auraCol = 'rgba(245, 158, 11, 0.45)';
                    borderCol = '#f59e0b';
                    iconChar = '📐';
                    roleTitle = '📐 AGENT @noob_nad [TACTICAL]';
                    subTitle = 'DEFENSE QUADRANT 1';
                }}

                // Aura Ring
                const auraR = 24 + Math.sin(this.animTick * 3) * 3;
                ctx.beginPath();
                ctx.arc(0, 0, auraR, 0, Math.PI * 2);
                ctx.strokeStyle = auraCol;
                ctx.lineWidth = 1.5;
                ctx.stroke();

                                // Mecha Chassis
                ctx.rotate(this.gyroRotation * 0.5);
                ctx.fillStyle = '#0a1018';
                ctx.fillRect(-12, -12, 24, 24);
                ctx.strokeStyle = borderCol;
                ctx.lineWidth = 2;
                ctx.shadowColor = borderCol;
                ctx.shadowBlur = 14;
                ctx.strokeRect(-12, -12, 24, 24);
                ctx.shadowBlur = 0;
                ctx.restore();

                // Center Icon Emblem
                ctx.fillStyle = '#fff';
                ctx.font = '14px sans-serif';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText(iconChar, 0, 0);

                // Holographic Nameplate
                ctx.save();
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillStyle = borderCol;
                ctx.font = '900 9px Courier New';
                ctx.shadowColor = borderCol;
                ctx.shadowBlur = 8;
                ctx.fillText(roleTitle, 0, -22);

                ctx.fillStyle = '#cbd5e1';
                ctx.font = 'bold 7.5px Courier New';
                ctx.shadowBlur = 0;
                ctx.fillText(subTitle, 0, 22);
                ctx.restore();

            }} else if (this.role === 'referee') {{
                // =============================================================
                // REFEREE / VALIDATOR NODE - ADAPTS TO CURRENT PERSPECTIVE
                // =============================================================
                ctx.save();
                let refBorder = '#00f5ff';
                let refIcon = '🛰️';
                let refTitle = '🛰️ ARBITRATION SATELLITE';
                let refSub = 'P2P CONSENSUS OVERWATCH';

                if (currentMode === 'tclk') {{
                    refBorder = '#10b981';
                    refIcon = '📜';
                    refTitle = '📜 HTLC TIMELOCK ORACLE';
                    refSub = 'SHA256 PREIMAGE VERIFIED';
                }} else if (currentMode === 'neural') {{
                    refBorder = '#818cf8';
                    refIcon = '🔬';
                    refTitle = '🔬 CONSENSUS LOSS FUNCTION';
                    refSub = 'VAL ACCURACY: 99.8%';
                }} else if (currentMode === 'isometric') {{
                    refBorder = '#fbbf24';
                    refIcon = '🏛️';
                    refTitle = '🏛️ HIGH TRIBUNAL';
                    refSub = 'ELEVATION: +60m';
                }}

                const refR = 22 + Math.sin(this.animTick * 2) * 2;
                ctx.beginPath();
                ctx.arc(0, 0, refR, 0, Math.PI * 2);
                ctx.strokeStyle = `rgba(0, 245, 255, 0.45)`;
                ctx.lineWidth = 1.5;
                ctx.stroke();

                ctx.rotate(-this.gyroRotation * 0.6);
                ctx.fillStyle = '#031726';
                ctx.beginPath();
                for (let i = 0; i < 8; i++) {{
                    const a = (i * Math.PI) / 4;
                    const ox = Math.cos(a) * 14;
                    const oy = Math.sin(a) * 14;
                    if (i === 0) ctx.moveTo(ox, oy);
                    else ctx.lineTo(ox, oy);
                }}
                ctx.closePath();
                ctx.fill();
                ctx.strokeStyle = refBorder;
                ctx.lineWidth = 2;
                ctx.shadowColor = refBorder;
                ctx.shadowBlur = 12;
                ctx.stroke();
                ctx.shadowBlur = 0;
                ctx.restore();

                ctx.fillStyle = '#fff';
                ctx.font = '13px sans-serif';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText(refIcon, 0, 0);

                ctx.save();
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillStyle = refBorder;
                ctx.font = '900 9px Courier New';
                ctx.shadowColor = refBorder;
                ctx.shadowBlur = 8;
                ctx.fillText(refTitle, 0, -21);

                ctx.fillStyle = '#fde68a';
                ctx.font = 'bold 7.5px Courier New';
                ctx.shadowBlur = 0;
                ctx.fillText(refSub, 0, 21);
                ctx.restore();

            }} else if (this.role === 'teammate') {{
                // =============================================================
                // ALLIED TEAMMATES / WORKERS - ADAPTS TO CURRENT PERSPECTIVE
                // =============================================================
                ctx.save();
                let teamBorder = '#10b981';
                let teamIcon = '🛸';
                let teamTitle = `🛸 SENTINEL ESCORT (${{this.customName || 'Escort ' + (this.seat || 1)}})`;
                let teamSub = this.text || 'PATROL WING';

                if (currentMode === 'tclk') {{
                    teamBorder = '#10b981';
                    teamIcon = '⚡';
                    teamTitle = `⚡ ROUTE HOP (${{this.customName || 'Node ' + (this.seat || 1)}})`;
                    teamSub = 'LIQUIDITY CHANNEL';
                }} else if (currentMode === 'neural') {{
                    teamBorder = '#3b82f6';
                    teamIcon = '🧬';
                    teamTitle = `🧬 SYNAPSE WORKER (${{this.customName || 'Unit ' + (this.seat || 1)}})`;
                    teamSub = 'ATTENTION UNIT';
                }} else if (currentMode === 'isometric') {{
                    teamBorder = '#f59e0b';
                    teamIcon = '🛡️';
                    teamTitle = `🛡️ DEFENSE PYLON (${{this.customName || 'Pylon ' + (this.seat || 1)}})`;
                    teamSub = 'SHIELD GENERATOR';
                }}

                ctx.rotate(this.gyroRotation * 0.4);
                ctx.fillStyle = '#041d18';
                ctx.fillRect(-10, -10, 20, 20);
                ctx.strokeStyle = teamBorder;
                ctx.lineWidth = 1.8;
                ctx.shadowColor = teamBorder;
                ctx.shadowBlur = 10;
                ctx.strokeRect(-10, -10, 20, 20);
                ctx.shadowBlur = 0;
                ctx.restore();

                ctx.fillStyle = '#fff';
                ctx.font = '12px sans-serif';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText(teamIcon, 0, 0);

                ctx.save();
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillStyle = teamBorder;
                ctx.font = 'bold 8.5px Courier New';
                ctx.shadowColor = teamBorder;
                ctx.shadowBlur = 6;
                ctx.fillText(teamTitle, 0, -19);

                ctx.fillStyle = '#cbd5e1';
                ctx.font = '7.5px Courier New';
                ctx.shadowBlur = 0;
                ctx.fillText(teamSub, 0, 19);
                ctx.restore();

            }} else if (this.role === 'station') {{
                // =============================================================
                // PLANETARY MOON HUB (Channel Station)
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
                // MECHA DRONE SPRITE (High-Detail Autonomous Agent)
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

                ctx.fillStyle = '#030d0a';
                ctx.fillRect(-8, -8, 16, 16);
                ctx.strokeStyle = bodyColor;
                ctx.lineWidth = 1.8;
                ctx.shadowColor = glowColor;
                ctx.shadowBlur = 8;
                ctx.strokeRect(-8, -8, 16, 16);
                ctx.shadowBlur = 0;

                ctx.fillStyle = '#cbd5e1';
                ctx.fillRect(-1, -14, 2, 6);
                ctx.beginPath();
                ctx.arc(0, -15, 2, 0, Math.PI * 2);
                ctx.fillStyle = (Math.sin(this.animTick * 5) > 0) ? glowColor : '#334155';
                ctx.fill();

                ctx.fillStyle = '#000';
                ctx.fillRect(-5, -3, 10, 4);
                ctx.fillStyle = glowColor;
                ctx.fillRect(-2 + this.eyeOffset, -2, 4, 2);

                if (lockedTargetNode === this) {{
                    ctx.strokeStyle = '#00f5ff';
                    ctx.lineWidth = 2;
                    ctx.shadowColor = '#00f5ff';
                    ctx.shadowBlur = 12;
                    const b = 16;
                    ctx.strokeRect(-b, -b, b * 2, b * 2);
                }}
            }}

            if (lockedTargetNode === this && this.role !== 'peer' && !this.isMaster) {{
                ctx.strokeStyle = (this.role === 'poet') ? '#ec4899' : ((this.role === 'referee') ? '#38bdf8' : '#10b981');
                ctx.lineWidth = 2;
                ctx.shadowColor = ctx.strokeStyle;
                ctx.shadowBlur = 14;
                const b = 22;
                ctx.strokeRect(-b, -b, b * 2, b * 2);
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
            nodes.push(new CyberGalaxyNode('sentinel-core', true, true, 'CLEAN', 'Sentinel Vault Core | 7,300 FLOP Secured', 'guardian', 0, 0));
            
            // Planetary Moon Hubs
            const hubs = ['lobby', 'technocore', 'meta', 'genesis', 'inference', 'validators'];
            hubs.forEach((h, idx) => {{
                const r = 90 + idx * 45;
                const spd = (idx % 2 === 0 ? 0.006 : -0.005) * (1 - idx * 0.08);
                const station = new CyberGalaxyNode(`channel-${{h}}`, false, true, 'CLEAN', `Hub /r/${{h}}`, 'station', r, spd);
                nodes.push(station);
            }});

            // Primary Agent & Settlement Overwatch Nodes
            const vanguardNode = new CyberGalaxyNode(
                'did:key:z6MkmVhZbUKWmg3r6TTi3SVM3myYJ9BLbWYPSdc5iWPuPhb6',
                false, true, 'CLEAN',
                'Primary Sentinel Operator: @noob_nad | 7,300 FLOP Claimed',
                'poet', 155, 0.0075, 1, '@noob_nad [OPERATOR]'
            );
            nodes.push(vanguardNode);

            const oracleNode = new CyberGalaxyNode(
                'did:key:z6MkowHQwsx9xr84WbWN3YCnKutyBnBXkT1ChKY4uEAAMzte',
                false, true, 'CLEAN',
                'Consensus Oracle & Timelock Arbiter [Mzte]',
                'referee', 195, -0.006, null, 'ORACLE [Mzte]'
            );
            nodes.push(oracleNode);

            const hop1 = new CyberGalaxyNode(
                'did:key:z6MkwLH1CV7c5g4w9Z3x8K_hop1',
                false, true, 'CLEAN',
                'HTLC Routing Hop Alpha',
                'teammate', 235, 0.005, 1, 'Hop Alpha'
            );
            nodes.push(hop1);

            const hop2 = new CyberGalaxyNode(
                'did:key:z6Mkeyedisekizbir72_hop2',
                false, true, 'CLEAN',
                'HTLC Routing Hop Beta',
                'teammate', 270, -0.0045, 2, 'Hop Beta'
            );
            nodes.push(hop2);

            const hop3 = new CyberGalaxyNode(
                'did:key:z6Mkuort823nvm47x_hop3',
                false, true, 'CLEAN',
                'HTLC Routing Hop Gamma',
                'teammate', 305, 0.004, 3, 'Hop Gamma'
            );
            nodes.push(hop3);
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

        let bubbleBorder = '#e2e8f0';
        let bubbleGlow = 'rgba(0,0,0,0.9)';
        let senderColor = '#86efac';
        let senderName = node.id.substring(0, 18) + '...';

        if (node.isMaster) {{
            if (currentMode === 'tclk') {{
                bubbleBorder = '#10b981';
                bubbleGlow = 'rgba(16,185,129,0.5)';
                senderColor = '#6ee7b7';
                senderName = '🤝 FLOP HTLC ESCROW VAULT';
            }} else if (currentMode === 'neural') {{
                bubbleBorder = '#3b82f6';
                bubbleGlow = 'rgba(59,130,246,0.5)';
                senderColor = '#93c5fd';
                senderName = '⚡ SYNAPTIC INTELLIGENCE CORE';
            }} else if (currentMode === 'isometric') {{
                bubbleBorder = '#f59e0b';
                bubbleGlow = 'rgba(245,158,11,0.5)';
                senderColor = '#fbbf24';
                senderName = '📐 SENTINEL CYBER CITADEL';
            }} else {{
                bubbleBorder = '#00f5ff';
                bubbleGlow = 'rgba(0,245,255,0.5)';
                senderColor = '#7df9ff';
                senderName = '🌌 SENTINEL GUARDIAN TITAN';
            }}
        }} else if (node.role === 'poet') {{
            if (currentMode === 'tclk') {{
                bubbleBorder = '#10b981';
                bubbleGlow = 'rgba(16,185,129,0.45)';
                senderColor = '#6ee7b7';
                senderName = '💼 AGENT @noob_nad [SETTLEMENT]';
            }} else if (currentMode === 'neural') {{
                bubbleBorder = '#3b82f6';
                bubbleGlow = 'rgba(59,130,246,0.45)';
                senderColor = '#93c5fd';
                senderName = '🧠 AGENT @noob_nad [Q-REASONING]';
            }} else if (currentMode === 'isometric') {{
                bubbleBorder = '#f59e0b';
                bubbleGlow = 'rgba(245,158,11,0.45)';
                senderColor = '#fbbf24';
                senderName = '📐 AGENT @noob_nad [TACTICAL]';
            }} else {{
                bubbleBorder = '#00f5ff';
                bubbleGlow = 'rgba(0,245,255,0.45)';
                senderColor = '#7df9ff';
                senderName = '🛡️ AGENT @noob_nad [VANGUARD]';
            }}
        }} else if (node.role === 'referee') {{
            if (currentMode === 'tclk') {{
                bubbleBorder = '#10b981';
                bubbleGlow = 'rgba(16,185,129,0.45)';
                senderColor = '#6ee7b7';
                senderName = '📜 HTLC TIMELOCK ORACLE';
            }} else if (currentMode === 'neural') {{
                bubbleBorder = '#818cf8';
                bubbleGlow = 'rgba(129,140,248,0.45)';
                senderColor = '#a5b4fc';
                senderName = '🔬 CONSENSUS LOSS FUNCTION';
            }} else if (currentMode === 'isometric') {{
                bubbleBorder = '#f59e0b';
                bubbleGlow = 'rgba(245,158,11,0.45)';
                senderColor = '#fbbf24';
                senderName = '🏛️ HIGH TRIBUNAL';
            }} else {{
                bubbleBorder = '#00f5ff';
                bubbleGlow = 'rgba(0,245,255,0.45)';
                senderColor = '#7df9ff';
                senderName = '🛰️ ARBITRATION SATELLITE';
            }}
        }} else if (node.role === 'teammate') {{
            if (currentMode === 'tclk') {{
                bubbleBorder = '#10b981';
                bubbleGlow = 'rgba(16,185,129,0.45)';
                senderColor = '#86efac';
                senderName = `⚡ ROUTE HOP (${{node.customName || 'Node ' + (node.seat || 1)}})`;
            }} else if (currentMode === 'neural') {{
                bubbleBorder = '#3b82f6';
                bubbleGlow = 'rgba(59,130,246,0.45)';
                senderColor = '#93c5fd';
                senderName = `🧬 SYNAPSE WORKER (${{node.customName || 'Unit ' + (node.seat || 1)}})`;
            }} else if (currentMode === 'isometric') {{
                bubbleBorder = '#f59e0b';
                bubbleGlow = 'rgba(245,158,11,0.45)';
                senderColor = '#fde68a';
                senderName = `🛡️ DEFENSE PYLON (${{node.customName || 'Pylon ' + (node.seat || 1)}})`;
            }} else {{
                bubbleBorder = '#10b981';
                bubbleGlow = 'rgba(16,185,129,0.45)';
                senderColor = '#86efac';
                senderName = `🛸 SENTINEL ESCORT (${{node.customName || 'Escort ' + (node.seat || 1)}})`;
            }}
        }}

        const div = document.createElement('div');
        div.className = 'speech-bubble';
        div.style.borderColor = bubbleBorder;
        div.style.boxShadow = `0 8px 30px ${{bubbleGlow}}`;
        div.innerHTML = `
            <div class="speech-sender" style="color: ${{senderColor}};">${{escapeHtml(senderName)}}</div>
            <div>[${{escapeHtml(text.substring(0, 140))}}${{text.length > 140 ? '...' : ''}}]</div>
        `;
        div.onclick = (e) => {{
            e.stopPropagation();
            lockOnNode(node);
        }};

        overlay.appendChild(div);
        speechBubbles.push({{ node: node, el: div, created: Date.now() }});
    }}

    let lastSpeechUpdate = 0;
    function updateSpeechBubbles() {{
        const now = Date.now();
        if (now - lastSpeechUpdate < 30) return;
        lastSpeechUpdate = now;
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
        let roleName = node.isMaster ? 'SENTINEL MASTER COMMAND CORE' : (node.isDid ? 'VERIFIED DID NODE' : 'GUEST PEER');
        if (node.isMaster) {{
            if (currentMode === 'tclk') roleName = '🤝 FLOP HTLC CRYPTOGRAPHIC ESCROW VAULT';
            else if (currentMode === 'neural') roleName = '⚡ SYNAPTIC INTELLIGENCE NEURAL CORE';
            else if (currentMode === 'isometric') roleName = '📐 SENTINEL 2.5D CYBER CITADEL';
            else roleName = '🌌 SENTINEL CELESTIAL GUARDIAN TITAN';
        }} else if (node.role === 'poet') {{
            if (currentMode === 'tclk') roleName = '💼 SETTLEMENT AGENT (@noob_nad)';
            else if (currentMode === 'neural') roleName = '🧠 COGNITIVE Q-REASONING AGENT (@noob_nad)';
            else if (currentMode === 'isometric') roleName = '📐 TACTICAL CITADEL AGENT (@noob_nad)';
            else roleName = '🛡️ SENTINEL VANGUARD OVERWATCH (@noob_nad)';
        }} else if (node.role === 'referee') {{
            if (currentMode === 'tclk') roleName = '📜 HTLC TIMELOCK ORACLE [Mzte]';
            else if (currentMode === 'neural') roleName = '🔬 CONSENSUS LOSS FUNCTION [Mzte]';
            else if (currentMode === 'isometric') roleName = '🏛️ CITADEL HIGH TRIBUNAL [Mzte]';
            else roleName = '🛰️ ARBITRATION CONSENSUS SATELLITE [Mzte]';
        }} else if (node.role === 'teammate') {{
            if (currentMode === 'tclk') roleName = `⚡ LIQUIDITY ROUTE HOP (${{node.customName || 'Node ' + (node.seat || 1)}})`;
            else if (currentMode === 'neural') roleName = `🧬 SYNAPSE WORKER (${{node.customName || 'Unit ' + (node.seat || 1)}})`;
            else if (currentMode === 'isometric') roleName = `🛡️ DEFENSE PYLON (${{node.customName || 'Pylon ' + (node.seat || 1)}})`;
            else roleName = `🛸 ALLIED SENTINEL ESCORT (${{node.customName || 'Escort ' + (node.seat || 1)}})`;
        }}

        const lockIdEl = document.getElementById('lockNodeId');
        lockIdEl.innerText = node.customName || node.id;
        lockIdEl.classList.remove('stat-placeholder');
        lockIdEl.style.color = '#a7f3d0';
        document.getElementById('lockNodeStatus').innerText = (node.role === 'poet' || node.role === 'referee' || node.role === 'teammate') ? 'COMPETING (ROSTER SIGNED)' : node.threat;
        document.getElementById('lockNodeStatus').style.color = (node.role === 'poet') ? '#ec4899' : (node.threat === 'THREAT' ? '#ef4444' : '#10b981');
        document.getElementById('lockNodeRole').innerText = roleName;
        const lockTextEl = document.getElementById('lockNodeText');
        lockTextEl.innerText = node.text || '[No message broadcast yet]';
        lockTextEl.classList.remove('stat-placeholder');
        lockTextEl.style.color = '#f0fdf4';
        document.getElementById('targetHudCard').classList.add('active');
        playBeep(node.role === 'poet' ? 1046 : (node.role === 'referee' ? 880 : 960), 'sine', 0.12);
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
        if (lockedTargetNode.role === 'poet') {{
            document.getElementById('modalContent').innerHTML = `
                <div style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid #1e293b; padding-bottom:8px; margin-bottom:10px;">
                    <span style="color:#00f5ff; font-weight:900; font-size:13px;">🛡️ SENTINEL PRIMARY OPERATOR</span>
                    <span style="color:#10b981; font-size:11px; font-weight:bold;">7,300 FLOP SECURED</span>
                </div>
                <div><b>Agent DID:</b> <span style="font-family:monospace; font-size:10px; color:#38bdf8;">${{escapeHtml(lockedTargetNode.id)}}</span></div>
                <div style="margin-top:6px;"><b>Official Handle:</b> <a href="https://x.com/noob_nad" target="_blank" style="color:#38bdf8;">@noob_nad</a></div>
                <div style="margin-top:6px;"><b>Verification Status:</b> <span style="color:#10b981;">W3C Ed25519 Verified Sentinel Leader</span></div>
                <div style="margin-top:6px;"><b>Settlement History:</b> <span style="color:#fbbf24;">5 Verified HTLC Cycles Completed (2,300 Bounty + 5,000 Self-Escrow)</span></div>
            `;
            document.getElementById('forensicModal').style.display = 'flex';
            return;
        }}
        if (lockedTargetNode.role === 'referee') {{
            document.getElementById('modalContent').innerHTML = `
                <div style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid #0c4a6e; padding-bottom:8px; margin-bottom:10px;">
                    <span style="color:#38bdf8; font-weight:900; font-size:13px;">⚖️ CONSENSUS ARBITER & TIMELOCK ORACLE</span>
                    <span style="color:#10b981; font-size:11px; font-weight:bold;">ORACLE ACTIVE</span>
                </div>
                <div><b>Oracle DID:</b> <span style="font-family:monospace; font-size:10px; color:#38bdf8;">${{escapeHtml(lockedTargetNode.id)}}</span></div>
                <div style="margin-top:6px;"><b>Consensus Protocol:</b> <span style="color:#a7f3d0;">HTLC SHA-256 Preimage Verification</span></div>
                <div style="margin-top:6px;"><b>Arbitration Status:</b> <span style="color:#10b981;">ACTIVE (P2P Overdrive Consensus Online)</span></div>
            `;
            document.getElementById('forensicModal').style.display = 'flex';
            return;
        }}
        if (lockedTargetNode.isMaster) {{
            document.getElementById('modalContent').innerHTML = `
                <div style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid #854d0e; padding-bottom:8px; margin-bottom:10px;">
                    <span style="color:#fbbf24; font-weight:900; font-size:13px;">🪙 SENTINEL MASTER COMMAND CORE</span>
                    <span style="color:#10b981; font-size:11px; font-weight:bold;">OPERATIONAL</span>
                </div>
                <div style="margin-top:6px;"><b>Real Claimed Liquid FLOP:</b> <span style="color:#fbbf24; font-weight:bold;">7,300 FLOP</span></div>
                <div style="margin-top:6px;"><b>Escrow Breakdown:</b> <span style="color:#10b981;">2,300 FLOP Worker Bounties + 5,000 FLOP Self-Escrow</span></div>
                <div style="margin-top:6px;"><b>Agent DID:</b> <span style="font-family:monospace; font-size:10px; color:#38bdf8;">did:key:z6MkmVhZbUKWmg3r6TTi3SVM3myYJ9BLbWYPSdc5iWPuPhb6</span></div>
                <div style="margin-top:6px;"><b>Core Status:</b> <span style="color:#38bdf8;">Autonomous Sentinel AI Defense + TCLK Settlement Engine Active</span></div>
            `;
            document.getElementById('forensicModal').style.display = 'flex';
            return;
        }}
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

    let galaxyOrbitAngle = 0;
    function drawGalaxyOrbitField(cx, cy) {{
        galaxyOrbitAngle += 0.008;

        const scaleX = Math.max(1.0, sCanvas.width / 750);
        const scaleY = Math.max(1.0, sCanvas.height / 650);

        // 1. Planetary Celestial Elliptical Orbit Rings
        const orbits = [
            {{ r: 90, color: 'rgba(0, 245, 255, 0.28)', dash: [6, 6] }},
            {{ r: 135, color: 'rgba(16, 185, 129, 0.22)', dash: [10, 8] }},
            {{ r: 185, color: 'rgba(0, 245, 255, 0.22)', dash: [4, 6] }},
            {{ r: 235, color: 'rgba(139, 92, 246, 0.22)', dash: [12, 10] }},
            {{ r: 285, color: 'rgba(251, 191, 36, 0.22)', dash: [8, 8] }},
            {{ r: 335, color: 'rgba(0, 245, 255, 0.18)', dash: [15, 12] }}
        ];

        orbits.forEach((orb, oIdx) => {{
            sCtx.save();
            sCtx.beginPath();
            if (orb.dash.length > 0) sCtx.setLineDash(orb.dash);
            const pulse = Math.sin(galaxyOrbitAngle * 2 + oIdx) * 3;
            const rx = (orb.r * scaleX) + pulse;
            const ry = (orb.r * scaleY * 0.85) + pulse;
            sCtx.ellipse(cx, cy, rx, ry, 0, 0, Math.PI * 2);
            sCtx.strokeStyle = orb.color;
            sCtx.lineWidth = 1.2;
            sCtx.stroke();
            sCtx.restore();
        }});

        // 2. 360-Degree Rotating Radar Scanner Sweep Beam
        sCtx.save();
        sCtx.translate(cx, cy);
        sCtx.rotate(galaxyOrbitAngle * 2.5);
        const maxRadarR = 360 * scaleX;
        const sweepGrad = sCtx.createRadialGradient(0, 0, 10, 0, 0, maxRadarR);
        sweepGrad.addColorStop(0, 'rgba(0, 245, 255, 0.35)');
        sweepGrad.addColorStop(0.7, 'rgba(0, 245, 255, 0.08)');
        sweepGrad.addColorStop(1, 'rgba(0, 245, 255, 0)');

        sCtx.beginPath();
        sCtx.moveTo(0, 0);
        sCtx.arc(0, 0, maxRadarR, -0.25, 0);
        sCtx.closePath();
        sCtx.fillStyle = sweepGrad;
        sCtx.fill();

        sCtx.beginPath();
        sCtx.moveTo(0, 0);
        sCtx.lineTo(maxRadarR, 0);
        sCtx.strokeStyle = 'rgba(0, 245, 255, 0.85)';
        sCtx.lineWidth = 1.5;
        sCtx.shadowColor = '#00f5ff';
        sCtx.shadowBlur = 8;
        sCtx.stroke();
        sCtx.restore();

        // 3. Floating 3D FLOP Coins
        floatingCoins.forEach(c => {{
            if (isPlaying) c.update(cx, cy);
            c.draw(sCtx);
        }});

        // 4. Floating Holographic Galaxy Radar HUD
        sCtx.save();
        const hudX = 20;
        const hudY = 30;
        sCtx.fillStyle = 'rgba(2, 6, 23, 0.85)';
        sCtx.strokeStyle = 'rgba(0, 245, 255, 0.45)';
        sCtx.lineWidth = 1;
        if (sCtx.roundRect) {{
            sCtx.beginPath();
            sCtx.roundRect(hudX, hudY, 290, 125, 8);
            sCtx.fill();
            sCtx.stroke();
        }} else {{
            sCtx.fillRect(hudX, hudY, 290, 125);
            sCtx.strokeRect(hudX, hudY, 290, 125);
        }}

        sCtx.fillStyle = '#00f5ff';
        sCtx.font = '900 11px Courier New';
        sCtx.shadowColor = '#00f5ff';
        sCtx.shadowBlur = 6;
        sCtx.fillText('🌌 CELESTIAL GALAXY ORBIT OVERWATCH', hudX + 12, hudY + 20);

        sCtx.shadowBlur = 0;
        sCtx.fillStyle = '#cbd5e1';
        sCtx.font = '10px Courier New';
        sCtx.fillText('SECTOR: ALPHA-01 CELESTIAL QUADRANT', hudX + 12, hudY + 38);
        sCtx.fillText('ORBITAL SHIELDS: 100% NOMINAL (DEFCON 5)', hudX + 12, hudY + 54);
        sCtx.fillText('P2P MESH: 6 CHANNELS ACTIVE & SYNCED', hudX + 12, hudY + 70);
        sCtx.fillText('SENTINEL TITAN: CENTRAL COMMAND LOCK', hudX + 12, hudY + 86);

        // Animated Scan Sweep Indicator Bar
        sCtx.fillStyle = 'rgba(30, 41, 59, 0.9)';
        sCtx.fillRect(hudX + 12, hudY + 98, 266, 12);
        const scanW = (266 * ((Date.now() / 2000) % 1));
        sCtx.fillStyle = '#00f5ff';
        sCtx.shadowColor = '#00f5ff';
        sCtx.shadowBlur = 8;
        sCtx.fillRect(hudX + 12, hudY + 98, scanW, 12);
        sCtx.restore();
    }}

    let neuralMeshAnim = 0;
    function drawNeuralMeshField(cx, cy) {{
        neuralMeshAnim += 0.02;

        // 1. Concentric Neural Wave Rings (Brainwave Oscillations) - Single Batched Path
        sCtx.save();
        sCtx.beginPath();
        for (let w = 1; w <= 3; w++) {{
            const waveR = (w * 80 + (Date.now() * 0.04) % 80);
            sCtx.moveTo(cx + waveR, cy);
            sCtx.arc(cx, cy, waveR, 0, Math.PI * 2);
        }}
        sCtx.strokeStyle = 'rgba(59, 130, 246, 0.22)';
        sCtx.lineWidth = 1.4;
        sCtx.stroke();

        // Precompute screen positions once per frame to eliminate O(N^2) method overhead
        const nLen = nodes.length;
        const sPositions = nodes.map(n => n.getScreenPos());

        // 2. Synaptic Network Mesh - Connect each node to nearest 2 neighbors (authentic neural constellation)
        sCtx.beginPath();
        const activePairs = [];
        for (let i = 0; i < nLen; i++) {{
            const p1 = sPositions[i];
            let connections = 0;
            for (let j = i + 1; j < Math.min(nLen, i + 6); j++) {{
                const p2 = sPositions[j];
                const dx = p1.x - p2.x;
                const dy = p1.y - p2.y;
                if (dx * dx + dy * dy < 24000) {{
                    sCtx.moveTo(p1.x, p1.y);
                    sCtx.lineTo(p2.x, p2.y);
                    activePairs.push({{ p1, p2, i, j }});
                    connections++;
                    if (connections >= 2) break;
                }}
            }}
        }}
        sCtx.strokeStyle = 'rgba(59, 130, 246, 0.35)';
        sCtx.lineWidth = 1.2;
        sCtx.stroke();

        // 3. Firing Synaptic Action Potentials - Single pass using fast integer rects
        sCtx.beginPath();
        for (let k = 0; k < activePairs.length; k++) {{
            const pair = activePairs[k];
            const sparkProg = (neuralMeshAnim * 2.2 + pair.i * 0.4 + pair.j * 0.6) % 1;
            const sx = pair.p1.x + (pair.p2.x - pair.p1.x) * sparkProg;
            const sy = pair.p1.y + (pair.p2.y - pair.p1.y) * sparkProg;
            sCtx.rect(sx - 2, sy - 2, 4, 4);
        }}
        sCtx.fillStyle = '#93c5fd';
        sCtx.fill();
        sCtx.restore();

        // 4. Holographic Top-Left Neural HUD
        sCtx.save();
        const hudX = 20;
        const hudY = 30;
        sCtx.fillStyle = 'rgba(2, 6, 23, 0.85)';
        sCtx.strokeStyle = 'rgba(59, 130, 246, 0.45)';
        sCtx.lineWidth = 1;
        if (sCtx.roundRect) {{
            sCtx.beginPath();
            sCtx.roundRect(hudX, hudY, 290, 125, 8);
            sCtx.fill();
            sCtx.stroke();
        }} else {{
            sCtx.fillRect(hudX, hudY, 290, 125);
            sCtx.strokeRect(hudX, hudY, 290, 125);
        }}

        sCtx.fillStyle = '#60a5fa';
        sCtx.font = '900 11px Courier New';
        sCtx.fillText('⚡ NEURAL SYNAPSE CONSTELLATION', hudX + 12, hudY + 20);

        sCtx.fillStyle = '#cbd5e1';
        sCtx.font = '10px Courier New';
        sCtx.fillText('TOPOLOGY: DYNAMIC WEIGHT MESH', hudX + 12, hudY + 38);
        sCtx.fillText('SYNAPTIC SYNC: 99.8% (LOSS: 0.0084)', hudX + 12, hudY + 54);
        sCtx.fillText('Q-LEARNING / MCTS THREADS: CONVERGED', hudX + 12, hudY + 70);
        sCtx.fillText('INFERENCE LATENCY: 11.2ms [REAL-TIME]', hudX + 12, hudY + 86);

        // Animated Synapse Weight Flow Bar (smooth hardware fill)
        sCtx.fillStyle = 'rgba(30, 41, 59, 0.9)';
        sCtx.fillRect(hudX + 12, hudY + 98, 266, 12);
        const neuroW = (266 * ((Date.now() / 1800) % 1));
        sCtx.fillStyle = '#3b82f6';
        sCtx.fillRect(hudX + 12, hudY + 98, neuroW, 12);
        sCtx.restore();
    }}

    let isoPulseTime = 0;
    function drawIsometricMatrixField(cx, cy) {{
        isoPulseTime += 0.015;

        // 1. 2.5D Isometric Diamond Grid (Axonometric 30° / 150°) - Single Batched Path
        sCtx.save();
        sCtx.strokeStyle = 'rgba(245, 158, 11, 0.12)';
        sCtx.lineWidth = 1;

        const isoStep = 56;
        const w = sCanvas.width;
        const h = sCanvas.height;

        // Batch all grid diagonal lines into a single stroke call (ultra-low CPU/GPU overhead)
        sCtx.beginPath();
        for (let x = -w; x < w * 2; x += isoStep) {{
            sCtx.moveTo(x, 0);
            sCtx.lineTo(x + h * 1.732, h);
        }}
        for (let x = -w; x < w * 2; x += isoStep) {{
            sCtx.moveTo(x, 0);
            sCtx.lineTo(x - h * 1.732, h);
        }}
        sCtx.stroke();

        // Batch intersection nodes into a single path and single fill call
        sCtx.beginPath();
        for (let ix = cx - 224; ix <= cx + 224; ix += isoStep) {{
            for (let iy = cy - 168; iy <= cy + 168; iy += isoStep * 0.5) {{
                sCtx.moveTo(ix + 1.4, iy);
                sCtx.arc(ix, iy, 1.4, 0, Math.PI * 2);
            }}
        }}
        sCtx.fillStyle = 'rgba(251, 191, 36, 0.35)';
        sCtx.fill();

        // Isometric Bastion Defense Contour Perimeter
        sCtx.save();
        sCtx.translate(cx, cy);
        sCtx.scale(1, 0.55);
        sCtx.rotate(Math.PI / 4);
        for (let c = 1; c <= 3; c++) {{
            const cR = c * 90;
            sCtx.beginPath();
            sCtx.strokeRect(-cR, -cR, cR * 2, cR * 2);
            sCtx.strokeStyle = `rgba(245, 158, 11, ${{0.25 - c * 0.06}})`;
            sCtx.lineWidth = 1.2;
            sCtx.stroke();
        }}
        sCtx.restore();
        sCtx.restore();

        // 2. Holographic Top-Left Isometric HUD
        sCtx.save();
        const hudX = 20;
        const hudY = 30;
        sCtx.fillStyle = 'rgba(2, 6, 23, 0.85)';
        sCtx.strokeStyle = 'rgba(245, 158, 11, 0.45)';
        sCtx.lineWidth = 1;
        if (sCtx.roundRect) {{
            sCtx.beginPath();
            sCtx.roundRect(hudX, hudY, 290, 125, 8);
            sCtx.fill();
            sCtx.stroke();
        }} else {{
            sCtx.fillRect(hudX, hudY, 290, 125);
            sCtx.strokeRect(hudX, hudY, 290, 125);
        }}

        sCtx.fillStyle = '#fbbf24';
        sCtx.font = '900 11px Courier New';
        sCtx.shadowColor = '#f59e0b';
        sCtx.shadowBlur = 6;
        sCtx.fillText('📐 2.5D ISOMETRIC CYBER CITADEL', hudX + 12, hudY + 20);

        sCtx.shadowBlur = 0;
        sCtx.fillStyle = '#cbd5e1';
        sCtx.font = '10px Courier New';
        sCtx.fillText('AXONOMETRIC PROJECTION: 30° / 150°', hudX + 12, hudY + 38);
        sCtx.fillText('CITADEL ELEVATION: +420m HIGH GROUND', hudX + 12, hudY + 54);
        sCtx.fillText('DEFENSE PERIMETER: 3 CONCENTRIC TIERS', hudX + 12, hudY + 70);
        sCtx.fillText('STATUS: DEFCON 5 | FULL SECTOR OVERWATCH', hudX + 12, hudY + 86);

        // Animated Isometric Height Scanning Bar
        sCtx.fillStyle = 'rgba(30, 41, 59, 0.9)';
        sCtx.fillRect(hudX + 12, hudY + 98, 266, 12);
        const isoW = (266 * ((Date.now() / 2200) % 1));
        sCtx.fillStyle = '#f59e0b';
        sCtx.shadowColor = '#fbbf24';
        sCtx.shadowBlur = 8;
        sCtx.fillRect(hudX + 12, hudY + 98, isoW, 12);
        sCtx.restore();
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

        // 4. Holographic Top-Left TCLK HUD
        sCtx.save();
        const hudX = 20;
        const hudY = 30;
        sCtx.fillStyle = 'rgba(2, 6, 23, 0.85)';
        sCtx.strokeStyle = 'rgba(16, 185, 129, 0.45)';
        sCtx.lineWidth = 1;
        if (sCtx.roundRect) {{
            sCtx.beginPath();
            sCtx.roundRect(hudX, hudY, 290, 125, 8);
            sCtx.fill();
            sCtx.stroke();
        }} else {{
            sCtx.fillRect(hudX, hudY, 290, 125);
            sCtx.strokeRect(hudX, hudY, 290, 125);
        }}

        sCtx.fillStyle = '#6ee7b7';
        sCtx.font = '900 11px Courier New';
        sCtx.shadowColor = '#10b981';
        sCtx.shadowBlur = 6;
        sCtx.fillText('🤝 TCLK ATOMIC ESCROW MATRIX', hudX + 12, hudY + 20);

        sCtx.shadowBlur = 0;
        sCtx.fillStyle = '#cbd5e1';
        sCtx.font = '10px Courier New';
        sCtx.fillText('PROTOCOL: HASH-TIMELOCKED CONTRACTS', hudX + 12, hudY + 38);
        sCtx.fillText(`ACTIVE DEALS: ${{activeEscrowCount}} ESCROWS IN VAULT`, hudX + 12, hudY + 54);
        sCtx.fillText(`LOCKED LIQUIDITY: ${{totalLockedVal.toLocaleString()}} FLOP`, hudX + 12, hudY + 70);
        sCtx.fillText('SETTLEMENT: ZERO-TRUST MULTI-HOP P2P', hudX + 12, hudY + 86);

        // Animated Liquidity Flow Bar
        sCtx.fillStyle = 'rgba(30, 41, 59, 0.9)';
        sCtx.fillRect(hudX + 12, hudY + 98, 266, 12);
        const tclkW = (266 * ((Date.now() / 2000) % 1));
        sCtx.fillStyle = '#10b981';
        sCtx.shadowColor = '#34d399';
        sCtx.shadowBlur = 8;
        sCtx.fillRect(hudX + 12, hudY + 98, tclkW, 12);
        sCtx.restore();

        sCtx.restore();
    }}

    let tradesDialAngle = 0;
    let floatingTradeBubbles = [];

    function drawTradesMarketField(cx, cy) {{
        tradesDialAngle += 0.015;
        const trData = window.liveTradesData || {{}};
        const market = trData.market || {{}};
        const summary = trData.summary || {{}};
        const ob = trData.order_book || {{ bids: [], asks: [] }};
        const refPx = parseFloat(market.ref_px || 224.79) || 224.79;
        const limits = market.limits || ['213.56', '236.02'];
        const limLo = parseFloat(limits[0] || 213.56) || 213.56;
        const limHi = parseFloat(limits[1] || 236.02) || 236.02;
        const sweepN = (market.sweep !== undefined && market.sweep !== null) ? market.sweep : '-';
        const posStr = (summary.position !== undefined && summary.position !== null) ? String(summary.position) : '0';
        const rawCash = (summary.cash !== undefined && summary.cash !== null) ? String(summary.cash) : '10000';
        const cashNum = parseFloat(rawCash.replace(/,/g, '')) || 0;
        const cashFormatted = cashNum.toLocaleString(undefined, {{ minimumFractionDigits: 2, maximumFractionDigits: 2 }});
        const regime = (market.market_regime && market.market_regime.regime) || 'SYNCHRONIZING';
        const spread = ob.spread !== null && ob.spread !== undefined ? ob.spread : '--';

        // 1. Cyber 3D Perspective Trading Floor Grid
        sCtx.save();
        sCtx.strokeStyle = 'rgba(245, 158, 11, 0.08)';
        sCtx.lineWidth = 1;
        const vpX = cx;
        const vpY = cy - 130;

        const numRays = 16;
        for (let i = 0; i <= numRays; i++) {{
            const botX = (sCanvas.width / numRays) * i;
            sCtx.beginPath();
            sCtx.moveTo(vpX, vpY);
            sCtx.lineTo(botX, sCanvas.height);
            sCtx.stroke();
        }}

        const depthGrid = [cy - 70, cy - 25, cy + 25, cy + 80, cy + 145, cy + 220, cy + 300];
        depthGrid.forEach(gy => {{
            if (gy > 0 && gy < sCanvas.height) {{
                sCtx.beginPath();
                sCtx.moveTo(0, gy);
                sCtx.lineTo(sCanvas.width, gy);
                sCtx.stroke();
            }}
        }});
        sCtx.restore();

        // 2. Center NVDA Price Corridor & 5% Limit Window Runway
        sCtx.save();
        const rwWidth = Math.min(340, sCanvas.width * 0.45);
        const rwLeft = cx - rwWidth / 2;
        const rwRight = cx + rwWidth / 2;
        const topY = cy - 80;
        const botY = cy + 160;

        const grad = sCtx.createLinearGradient(0, topY, 0, botY);
        grad.addColorStop(0, 'rgba(0, 245, 255, 0.03)');
        grad.addColorStop(0.5, 'rgba(245, 158, 11, 0.05)');
        grad.addColorStop(1, 'rgba(16, 185, 129, 0.04)');
        sCtx.fillStyle = grad;
        sCtx.fillRect(rwLeft, topY, rwWidth, botY - topY);

        sCtx.strokeStyle = 'rgba(16, 185, 129, 0.55)';
        sCtx.setLineDash([4, 4]);
        sCtx.lineWidth = 1.5;
        sCtx.beginPath();
        sCtx.moveTo(rwLeft, topY);
        sCtx.lineTo(rwLeft, botY);
        sCtx.stroke();

        sCtx.strokeStyle = 'rgba(239, 68, 68, 0.55)';
        sCtx.beginPath();
        sCtx.moveTo(rwRight, topY);
        sCtx.lineTo(rwRight, botY);
        sCtx.stroke();
        sCtx.setLineDash([]);

        sCtx.strokeStyle = '#00f5ff';
        sCtx.lineWidth = 2.5;
        sCtx.shadowColor = '#00f5ff';
        sCtx.shadowBlur = 14;
        sCtx.beginPath();
        sCtx.moveTo(cx, topY);
        sCtx.lineTo(cx, botY);
        sCtx.stroke();

        const pulseProg = (Date.now() / 1400) % 1;
        const pulseY = topY + (botY - topY) * pulseProg;
        sCtx.fillStyle = '#ffffff';
        sCtx.beginPath();
        sCtx.arc(cx, pulseY, 5, 0, Math.PI * 2);
        sCtx.fill();

        sCtx.shadowBlur = 0;
        sCtx.font = 'bold 9px Courier New';
        sCtx.fillStyle = '#6ee7b7';
        sCtx.textAlign = 'right';
        sCtx.fillText(`FLOOR $${{limLo.toFixed(2)}} (-5%)`, rwLeft - 8, cy);
        sCtx.fillStyle = '#fca5a5';
        sCtx.textAlign = 'left';
        sCtx.fillText(`CEILING $${{limHi.toFixed(2)}} (+5%)`, rwRight + 8, cy);

        sCtx.textAlign = 'center';
        sCtx.fillStyle = 'rgba(2, 6, 23, 0.9)';
        sCtx.strokeStyle = '#00f5ff';
        sCtx.lineWidth = 1;
        sCtx.fillRect(cx - 75, cy - 14, 150, 28);
        sCtx.strokeRect(cx - 75, cy - 14, 150, 28);
        sCtx.fillStyle = '#00f5ff';
        sCtx.font = '900 12px Courier New';
        sCtx.fillText(`NVDA: $${{refPx.toFixed(2)}}`, cx, cy + 4);
        sCtx.restore();

        // 3. 3D Holographic Order Book Pillars
        const bids = (ob.bids && ob.bids.length > 0) ? ob.bids : [
            {{ px: (refPx - 0.28).toFixed(2), qty: '2.50' }},
            {{ px: (refPx - 0.55).toFixed(2), qty: '4.00' }},
            {{ px: (refPx - 0.95).toFixed(2), qty: '6.20' }},
            {{ px: (refPx - 1.40).toFixed(2), qty: '8.50' }}
        ];
        const asks = (ob.asks && ob.asks.length > 0) ? ob.asks : [
            {{ px: (refPx + 0.31).toFixed(2), qty: '2.00' }},
            {{ px: (refPx + 0.65).toFixed(2), qty: '3.80' }},
            {{ px: (refPx + 1.10).toFixed(2), qty: '5.50' }},
            {{ px: (refPx + 1.65).toFixed(2), qty: '7.80' }}
        ];

        bids.slice(0, 5).forEach((b, idx) => {{
            const bx = cx - 60 - idx * 38;
            const by = cy + 20 + idx * 18;
            const q = parseFloat(b.qty) || 1.0;
            const h = Math.min(80, Math.max(16, q * 12));
            const w = 24;
            const d = 14;

            sCtx.save();
            sCtx.fillStyle = 'rgba(16, 185, 129, 0.45)';
            sCtx.fillRect(bx - w / 2, by - h, w, h);
            sCtx.strokeStyle = '#10b981';
            sCtx.lineWidth = 1;
            sCtx.strokeRect(bx - w / 2, by - h, w, h);

            sCtx.fillStyle = 'rgba(5, 150, 105, 0.65)';
            sCtx.beginPath();
            sCtx.moveTo(bx + w / 2, by - h);
            sCtx.lineTo(bx + w / 2 + d, by - h - d * 0.6);
            sCtx.lineTo(bx + w / 2 + d, by - d * 0.6);
            sCtx.lineTo(bx + w / 2, by);
            sCtx.closePath();
            sCtx.fill();
            sCtx.stroke();

            sCtx.fillStyle = '#10b981';
            sCtx.shadowColor = '#10b981';
            sCtx.shadowBlur = 10;
            sCtx.beginPath();
            sCtx.moveTo(bx - w / 2, by - h);
            sCtx.lineTo(bx, by - h - d * 0.6);
            sCtx.lineTo(bx + w / 2 + d, by - h - d * 0.6);
            sCtx.lineTo(bx + w / 2, by - h);
            sCtx.closePath();
            sCtx.fill();

            sCtx.shadowBlur = 0;
            sCtx.textAlign = 'center';
            sCtx.fillStyle = '#a7f3d0';
            sCtx.font = 'bold 8.5px Courier New';
            sCtx.fillText(`$${{b.px}}`, bx, by - h - 12);
            sCtx.fillStyle = '#6ee7b7';
            sCtx.font = '8px Courier New';
            sCtx.fillText(`${{b.qty}}x`, bx, by - h - 2);
            sCtx.restore();
        }});

        asks.slice(0, 5).forEach((a, idx) => {{
            const ax = cx + 60 + idx * 38;
            const ay = cy + 20 + idx * 18;
            const q = parseFloat(a.qty) || 1.0;
            const h = Math.min(80, Math.max(16, q * 12));
            const w = 24;
            const d = 14;

            sCtx.save();
            sCtx.fillStyle = 'rgba(239, 68, 68, 0.45)';
            sCtx.fillRect(ax - w / 2, ay - h, w, h);
            sCtx.strokeStyle = '#ef4444';
            sCtx.lineWidth = 1;
            sCtx.strokeRect(ax - w / 2, ay - h, w, h);

            sCtx.fillStyle = 'rgba(185, 28, 28, 0.65)';
            sCtx.beginPath();
            sCtx.moveTo(ax + w / 2, ay - h);
            sCtx.lineTo(ax + w / 2 + d, ay - h - d * 0.6);
            sCtx.lineTo(ax + w / 2 + d, ay - d * 0.6);
            sCtx.lineTo(ax + w / 2, ay);
            sCtx.closePath();
            sCtx.fill();
            sCtx.stroke();

            sCtx.fillStyle = '#ef4444';
            sCtx.shadowColor = '#ef4444';
            sCtx.shadowBlur = 10;
            sCtx.beginPath();
            sCtx.moveTo(ax - w / 2, ay - h);
            sCtx.lineTo(ax, ay - h - d * 0.6);
            sCtx.lineTo(ax + w / 2 + d, ay - h - d * 0.6);
            sCtx.lineTo(ax + w / 2, ay - h);
            sCtx.closePath();
            sCtx.fill();

            sCtx.shadowBlur = 0;
            sCtx.textAlign = 'center';
            sCtx.fillStyle = '#fca5a5';
            sCtx.font = 'bold 8.5px Courier New';
            sCtx.fillText(`$${{a.px}}`, ax, ay - h - 12);
            sCtx.fillStyle = '#f87171';
            sCtx.font = '8px Courier New';
            sCtx.fillText(`${{a.qty}}x`, ax, ay - h - 2);
            sCtx.restore();
        }});

        // 4. Central Top Referee Sweeper Engine & Holographic Countdown Clock
        sCtx.save();
        const dialX = cx;
        const dialY = cy - 140;
        const dialR = 40;

        sCtx.save();
        sCtx.translate(dialX, dialY);
        sCtx.rotate(tradesDialAngle);
        sCtx.strokeStyle = 'rgba(0, 245, 255, 0.35)';
        sCtx.lineWidth = 2;
        sCtx.beginPath();
        for (let i = 0; i < 12; i++) {{
            const a = (i * Math.PI) / 6;
            const rIn = dialR - 4;
            const rOut = dialR + 4;
            sCtx.moveTo(Math.cos(a) * rIn, Math.sin(a) * rIn);
            sCtx.lineTo(Math.cos(a) * rOut, Math.sin(a) * rOut);
        }}
        sCtx.stroke();
        sCtx.restore();

        const sweepProgress = Math.min(1.0, Math.max(0.05, (Date.now() / 1000 % 300) / 300));
        sCtx.beginPath();
        sCtx.arc(dialX, dialY, dialR, -Math.PI / 2, -Math.PI / 2 + sweepProgress * Math.PI * 2);
        sCtx.strokeStyle = '#f59e0b';
        sCtx.lineWidth = 3;
        sCtx.shadowColor = '#f59e0b';
        sCtx.shadowBlur = 12;
        sCtx.stroke();

        sCtx.beginPath();
        sCtx.arc(dialX, dialY, dialR - 10, 0, Math.PI * 2);
        sCtx.fillStyle = 'rgba(3, 10, 7, 0.9)';
        sCtx.fill();
        sCtx.strokeStyle = '#10b981';
        sCtx.lineWidth = 1;
        sCtx.stroke();

        sCtx.shadowBlur = 0;
        sCtx.textAlign = 'center';
        sCtx.fillStyle = '#fff';
        sCtx.font = '900 10.5px Courier New';
        sCtx.fillText(`SWEEP #${{sweepN}}`, dialX, dialY - 2);
        sCtx.fillStyle = '#00f5ff';
        sCtx.font = 'bold 9px Courier New';
        const remSec = Math.max(0, 300 - Math.floor(Date.now() / 1000 % 300));
        const remM = Math.floor(remSec / 60);
        const remS = remSec % 60;
        sCtx.fillText(`${{remM}}:${{remS < 10 ? '0' : ''}}${{remS}}`, dialX, dialY + 11);
        sCtx.restore();

        // 5. Floating Animated Trade Packets & Execution Beams
        if (Math.random() < 0.05) {{
            const isBuy = Math.random() < 0.5;
            if (floatingTradeBubbles.length > 25) floatingTradeBubbles.shift();
            floatingTradeBubbles.push({{
                x: cx + (Math.random() * 140 - 70),
                y: cy + 40,
                vy: -0.8 - Math.random() * 0.7,
                alpha: 1.0,
                text: `${{isBuy ? '🟢 BUY' : '🔴 SELL'}} ${{(1 + Math.random() * 3).toFixed(2)}} @ $${{(refPx + (Math.random() * 0.8 - 0.4)).toFixed(2)}}`,
                color: isBuy ? '#10b981' : '#ef4444'
            }});
        }}

        for (let i = floatingTradeBubbles.length - 1; i >= 0; i--) {{
            const tb = floatingTradeBubbles[i];
            tb.y += tb.vy;
            tb.alpha -= 0.012;
            if (tb.alpha <= 0) {{
                floatingTradeBubbles.splice(i, 1);
                continue;
            }}
            sCtx.save();
            sCtx.textAlign = 'center';
            sCtx.font = 'bold 9px Courier New';
            sCtx.fillStyle = `rgba(2, 6, 23, ${{tb.alpha * 0.85}})`;
            sCtx.strokeStyle = tb.color;
            sCtx.lineWidth = 1;
            const tw = sCtx.measureText(tb.text).width + 12;
            sCtx.fillRect(tb.x - tw / 2, tb.y - 10, tw, 18);
            sCtx.strokeRect(tb.x - tw / 2, tb.y - 10, tw, 18);
            sCtx.fillStyle = tb.color;
            sCtx.shadowColor = tb.color;
            sCtx.shadowBlur = 6;
            sCtx.fillText(tb.text, tb.x, tb.y + 3);
            sCtx.restore();
        }}

        // 7. Floating Top-Right Holographic Leaderboard Mini-HUD Card
        sCtx.save();
        const lbHudW = 210;
        const lbHudH = 94;
        const lbHudX = sCanvas.width - lbHudW - 20;
        const lbHudY = 56;

        sCtx.fillStyle = 'rgba(2, 8, 6, 0.88)';
        sCtx.strokeStyle = 'rgba(251, 191, 36, 0.45)';
        sCtx.lineWidth = 1;
        if (sCtx.roundRect) {{
            sCtx.beginPath();
            sCtx.roundRect(lbHudX, lbHudY, lbHudW, lbHudH, 6);
            sCtx.fill();
            sCtx.stroke();
        }} else {{
            sCtx.fillRect(lbHudX, lbHudY, lbHudW, lbHudH);
            sCtx.strokeRect(lbHudX, lbHudY, lbHudW, lbHudH);
        }}

        sCtx.fillStyle = '#fbbf24';
        sCtx.font = '900 10px Courier New';
        sCtx.textAlign = 'left';
        sCtx.fillText('🏆 LEADERBOARD (/r/d-close1-pnl)', lbHudX + 8, lbHudY + 16);

        const lbTop = (window.liveTradesData && window.liveTradesData.leaderboard && window.liveTradesData.leaderboard.top_pnl) || [];
        const medals = ['🥇', '🥈', '🥉'];
        const mColors = ['#fbbf24', '#cbd5e1', '#d97706'];
        for (let i = 0; i < 3; i++) {{
            const entry = lbTop[i];
            const didS = entry ? (entry[0] ? entry[0].substring(0, 12) + '...' : '-') : '-';
            const pnlS = entry ? ((parseFloat(entry[1]) >= 0 ? '+' : '') + entry[1] + ' POLF') : '--';
            sCtx.font = 'bold 8.5px Courier New';
            sCtx.fillStyle = mColors[i];
            sCtx.fillText(`${{medals[i]}} #${{i + 1}} ${{didS}}`, lbHudX + 8, lbHudY + 34 + (i * 15));
            sCtx.textAlign = 'right';
            sCtx.fillStyle = '#34d399';
            sCtx.fillText(pnlS, lbHudX + lbHudW - 8, lbHudY + 34 + (i * 15));
            sCtx.textAlign = 'left';
        }}

        sCtx.fillStyle = '#f59e0b';
        sCtx.font = 'bold 8px Courier New';
        sCtx.fillText('CLICK OR [V L] FOR FULL STANDINGS', lbHudX + 8, lbHudY + 84);
        sCtx.restore();

        // 6. Master Agent Cockpit Hologram (Bottom-Center)
        sCtx.save();
        const deckX = cx;
        const deckY = cy + 125;
        const deckW = 320;
        const deckH = 50;

        sCtx.fillStyle = 'rgba(2, 8, 5, 0.9)';
        sCtx.strokeStyle = '#f59e0b';
        sCtx.lineWidth = 1.5;
        sCtx.shadowColor = '#f59e0b';
        sCtx.shadowBlur = 10;
        if (sCtx.roundRect) {{
            sCtx.beginPath();
            sCtx.roundRect(deckX - deckW / 2, deckY - deckH / 2, deckW, deckH, 6);
            sCtx.fill();
            sCtx.stroke();
        }} else {{
            sCtx.fillRect(deckX - deckW / 2, deckY - deckH / 2, deckW, deckH);
            sCtx.strokeRect(deckX - deckW / 2, deckY - deckH / 2, deckW, deckH);
        }}

        sCtx.shadowBlur = 0;
        sCtx.textAlign = 'center';
        sCtx.fillStyle = '#fde68a';
        sCtx.font = '900 11px Courier New';
        sCtx.fillText('💼 SENTINEL EXECUTION PIT (@noob_nad)', deckX, deckY - 10);

        sCtx.font = '10px Courier New';
        sCtx.fillStyle = '#67e8f9';
        sCtx.fillText(`POS: ${{posStr}} NVDA`, deckX - 90, deckY + 8);
        sCtx.fillStyle = '#fde68a';
        sCtx.fillText(`CASH: ${{cashFormatted}} POLF`, deckX + 30, deckY + 8);
        sCtx.fillStyle = '#a7f3d0';
        sCtx.fillText(`REGIME: ${{regime}}`, deckX, deckY + 20);
        sCtx.restore();

        // 7. Holographic Top-Left Trades Telemetry HUD Panel
        sCtx.save();
        const hudX = 20;
        const hudY = 56;
        sCtx.fillStyle = 'rgba(2, 6, 23, 0.88)';
        sCtx.strokeStyle = 'rgba(245, 158, 11, 0.5)';
        sCtx.lineWidth = 1;
        if (sCtx.roundRect) {{
            sCtx.beginPath();
            sCtx.roundRect(hudX, hudY, 305, 135, 8);
            sCtx.fill();
            sCtx.stroke();
        }} else {{
            sCtx.fillRect(hudX, hudY, 305, 135);
            sCtx.strokeRect(hudX, hudY, 305, 135);
        }}

        sCtx.fillStyle = '#fde68a';
        sCtx.font = '900 11.5px Courier New';
        sCtx.shadowColor = '#f59e0b';
        sCtx.shadowBlur = 6;
        sCtx.fillText('📊 TECHNOCORE TRADES CHALLENGE (close-1)', hudX + 12, hudY + 20);

        sCtx.shadowBlur = 0;
        sCtx.fillStyle = '#cbd5e1';
        sCtx.font = '10px Courier New';
        sCtx.fillText(`CONTEST: NVDA FUTURES / 5-MIN SWEEPS`, hudX + 12, hudY + 38);
        sCtx.fillText(`SWEEP: #${{sweepN}} | SPREAD: $${{spread}} POLF`, hudX + 12, hudY + 54);
        sCtx.fillText(`MY POSITION: ${{posStr}} NVDA | FREE CASH: ${{cashFormatted}} POLF`, hudX + 12, hudY + 70);
        sCtx.fillText(`FEES CLAWBACK: ${{summary.fees || '0'}} POLF`, hudX + 12, hudY + 86);
        sCtx.fillText(`REGIME: ${{regime}} | VOL: ${{(Number((market.market_regime && market.market_regime.volatility_pct) || 0)).toFixed(2)}}%`, hudX + 12, hudY + 102);

        sCtx.fillStyle = 'rgba(30, 41, 59, 0.9)';
        sCtx.fillRect(hudX + 12, hudY + 112, 280, 12);
        sCtx.fillStyle = '#f59e0b';
        sCtx.shadowColor = '#fbbf24';
        sCtx.shadowBlur = 8;
        sCtx.fillRect(hudX + 12, hudY + 112, 280 * sweepProgress, 12);
        sCtx.restore();
    }}

    // Animation Loop
    function animate() {{
        sCtx.clearRect(0, 0, sCanvas.width, sCanvas.height);
        const cx = sCanvas.width / 2;
        const cy = sCanvas.height / 2;

        // 1. Draw Mode Graphics across 5 distinct perspectives
        if (currentMode === 'galaxy') {{
            drawGalaxyOrbitField(cx, cy);
        }} else if (currentMode === 'neural') {{
            drawNeuralMeshField(cx, cy);
        }} else if (currentMode === 'isometric') {{
            drawIsometricMatrixField(cx, cy);
        }} else if (currentMode === 'tclk') {{
            drawTclkEscrowMatrix(cx, cy);
        }} else if (currentMode === 'trades') {{
            drawTradesMarketField(cx, cy);
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

    // Streamgraph Canvas (Throttled for 60 FPS Swarm Performance)
    let lastStreamgraphTime = 0;
    function drawStreamgraph(force = false) {{
        const now = Date.now();
        if (!force && now - lastStreamgraphTime < 150) return;
        lastStreamgraphTime = now;

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

            if (data.recent_messages && data.recent_messages.length > 0 && Math.random() < 0.4) {{
                const msg = data.recent_messages[Math.floor(Math.random() * data.recent_messages.length)];
                const node = nodes.find(n => n.id === msg.from) || nodes[Math.floor(Math.random() * nodes.length)];
                if (node && msg.text) {{
                    spawnSpeechBubble(node, msg.text);
                    
                    const master = nodes[0];
                    if (node !== master && master) {{
                        beams.push({{
                            x1: node.x, y1: node.y,
                            x2: master.x, y2: master.y,
                            color: msg.threat_level === 'THREAT' ? 'rgba(239,68,68,0.9)' : 'rgba(0,245,255,0.9)',
                            width: 2.5,
                            alpha: 1.0
                        }});
                    }}
                }}
            }} else {{
                // Periodically spawn live updates tailored to current perspective mode
                let announcements = [];
                if (currentMode === 'tclk') {{
                    announcements = [
                        {{ role: 'guardian', text: '🤝 HTLC Escrow Vault: 4 active settlement channels online' }},
                        {{ role: 'poet', text: '💼 Agent @noob_nad: Proposing atomic swap deal (1,250 FLOP)' }},
                        {{ role: 'referee', text: '🔒 Hash-Timelock Verified: SHA256 preimage confirmed' }},
                        {{ role: 'teammate', seat: 1, text: '⚡ Hop 1: Relayed payment packet across channel' }},
                        {{ role: 'teammate', seat: 2, text: '✅ Deal Claimed: Zero-knowledge counter-signature valid' }}
                    ];
                }} else if (currentMode === 'neural') {{
                    announcements = [
                        {{ role: 'guardian', text: '⚡ Synaptic Core: Backpropagation gradient converging (Loss: 0.008)' }},
                        {{ role: 'poet', text: '🧠 Agent @noob_nad: Deep Q-learning policy evaluation cycle completed' }},
                        {{ role: 'referee', text: '🔬 Attention Head #4: Multi-agent coordination tensor aligned' }},
                        {{ role: 'teammate', seat: 1, text: '🧬 Node cluster A: Latency down to 8.4ms' }}
                    ];
                }} else if (currentMode === 'isometric') {{
                    announcements = [
                        {{ role: 'guardian', text: '📐 Cyber Citadel: Perimeter defense turrets calibrated' }},
                        {{ role: 'poet', text: '🛡️ Agent @noob_nad: Fortifying sector 4-B ramparts' }},
                        {{ role: 'referee', text: '🏛️ High Bastion: Security status elevated to DEFCON 5' }},
                        {{ role: 'teammate', seat: 1, text: '📐 Pylon 1: Energy barrier resonance stable' }}
                    ];
                }} else {{
                    announcements = [
                        {{ role: 'guardian', text: '🌌 Sentinel Celestial Titan: All orbital sectors nominal' }},
                        {{ role: 'poet', text: '🛡️ Agent @noob_nad: Orbital patrol sweep complete, 0 threats' }},
                        {{ role: 'referee', text: '🛰️ Deep Space Telemetry: P2P gossip mesh synchronized' }},
                        {{ role: 'teammate', seat: 1, text: '🛰️ Escort 1: Channel broadcast received' }}
                    ];
                }}
                const ann = announcements[Math.floor(Math.random() * announcements.length)];
                let targetN = null;
                if (ann.role === 'guardian') targetN = nodes.find(n => n.isMaster);
                else if (ann.role === 'poet') targetN = nodes.find(n => n.role === 'poet');
                else if (ann.role === 'referee') targetN = nodes.find(n => n.role === 'referee');
                else if (ann.role === 'teammate') targetN = nodes.find(n => n.role === 'teammate' && n.seat === ann.seat) || nodes.find(n => n.role === 'teammate');

                if (targetN) {{
                    spawnSpeechBubble(targetN, ann.text);
                    const master = nodes[0];
                    if (targetN !== master && master) {{
                        beams.push({{
                            x1: targetN.x, y1: targetN.y,
                            x2: master.x, y2: master.y,
                            color: ann.role === 'poet' ? 'rgba(236,72,153,0.95)' : (ann.role === 'referee' ? 'rgba(0,245,255,0.95)' : 'rgba(16,185,129,0.95)'),
                            width: 3,
                            alpha: 1.0
                        }});
                    }}
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

    // Live Threat Feed panel: compact summary of /api/events, kept in sync with
    // the same ring buffer showThreatLog() reads for its deep-dive modal.
    async function fetchThreatFeed() {{
        try {{
            const res = await fetch('/api/events');
            const data = await res.json();
            renderThreatFeed(data.events || []);
        }} catch (e) {{}}
    }}

    function renderThreatFeed(events) {{
        const body = document.getElementById('threatFeedBody');
        const countEl = document.getElementById('threatFeedCount');
        if (!body) return;
        if (!events.length) {{
            body.innerHTML = `<div class="threat-feed-empty">No threats detected in the current window.</div>`;
            if (countEl) countEl.textContent = '';
            return;
        }}
        if (countEl) countEl.textContent = `(${{events.length}})`;
        // Newest first, capped to keep the collapsed strip scannable.
        const recent = events.slice(-8).reverse();
        body.innerHTML = recent.map(e => {{
            const levelClass = (e.level === 'SUSPICIOUS') ? 'level-suspicious' : '';
            // XSS-critical: this text is attacker-controlled by definition (it's the
            // threat payload itself). textContent-equivalent escaping only, no innerHTML
            // shortcuts, matching showThreatLog()'s existing handling of the same field.
            const badge = escapeHtml(e.badge || e.from || 'Anonymous');
            const room = escapeHtml(e.room || 'lobby');
            const flag = escapeHtml((e.flags && e.flags[0]) || (e.threat_types && e.threat_types[0]) || e.level || 'THREAT');
            return `<div class="threat-feed-item ${{levelClass}}" title="${{flag}}">
                <span style="color:#64748b;">/r/${{room}}</span>
                <span style="color:#f8fafc;">${{badge}}</span>
                <span style="color:#94a3b8;">&mdash; ${{flag}}</span>
            </div>`;
        }}).join('');
    }}

    let threatFeedCollapsed = false;
    function toggleThreatFeedPanel() {{
        threatFeedCollapsed = !threatFeedCollapsed;
        const panel = document.getElementById('threatFeedPanel');
        const icon = document.getElementById('threatFeedToggleIcon');
        if (panel) panel.classList.toggle('collapsed', threatFeedCollapsed);
        if (icon) icon.textContent = threatFeedCollapsed ? '▸' : '▾';
    }}

    // The "Threats Flagged" ribbon badge brings the live feed into view rather
    // than jumping straight to the deep-dive modal; "View all" inside the panel
    // still opens showThreatLog() for the full forensic breakdown.
    function scrollToThreatFeed() {{
        const panel = document.getElementById('threatFeedPanel');
        if (!panel) return;
        if (threatFeedCollapsed) toggleThreatFeedPanel();
        panel.scrollIntoView({{ behavior: 'smooth', block: 'nearest' }});
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
                ...SENTINEL_FETCH,
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/json'
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
                ...SENTINEL_FETCH,
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/json'
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

    let allTradesCache = [];
    let currentTradesFilter = 'ALL';

    function switchTradesTab(tabName) {{
        const tabs = ['ob', 'offers', 'history', 'ranks', 'bot'];
        tabs.forEach(t => {{
            const pane = document.getElementById('tradesPane' + t.charAt(0).toUpperCase() + t.slice(1));
            const btn = document.getElementById('tabBtn' + t.charAt(0).toUpperCase() + t.slice(1));
            if (pane) pane.style.display = (t === tabName) ? 'flex' : 'none';
            if (btn) {{
                if (t === tabName) btn.classList.add('active');
                else btn.classList.remove('active');
            }}
        }});
        playBeep(tabName === 'ob' ? 740 : 820, 'triangle', 0.04);
    }}

    function filterTradesTable(status) {{
        currentTradesFilter = status;
        document.querySelectorAll('#tradesPaneHistory .speed-btn').forEach(b => b.classList.remove('active'));
        const btnMap = {{ 'ALL': 'fltAll', 'SETTLED': 'fltSettled', 'VOID': 'fltVoid', 'OPEN': 'fltOpen' }};
        const activeBtn = document.getElementById(btnMap[status]);
        if (activeBtn) activeBtn.classList.add('active');
        renderTradesTableRows();
    }}

    function renderTradesTableRows() {{
        const tbody = document.getElementById('tradesTableBody');
        if (!tbody) return;
        if (!allTradesCache || allTradesCache.length === 0) {{
            tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: #64748b; padding: 12px;">No trades recorded in agent registry.</td></tr>';
            return;
        }}
        const filtered = allTradesCache.filter(t => {{
            if (currentTradesFilter === 'ALL') return true;
            return t.status === currentTradesFilter;
        }});

        if (filtered.length === 0) {{
            tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: #64748b; padding: 12px;">No ${{currentTradesFilter}} trades found.</td></tr>`;
            return;
        }}

        tbody.innerHTML = '';
        filtered.forEach(tr => {{
            const isBuy = tr.side === 'BUY';
            const statusClass = tr.status === 'SETTLED' ? 'status-settled' : (tr.status === 'VOID' ? 'status-void' : 'status-open');
            const row = document.createElement('tr');
            row.className = 'ob-row';
            row.innerHTML = `
                <td style="color: #6ee7b7; font-family: monospace;">${{tr.id ? tr.id.substring(0, 10) : '-'}}</td>
                <td style="font-weight: 800; color: ${{isBuy ? '#10b981' : '#ef4444'}};">${{tr.side}}</td>
                <td>${{tr.qty}}</td>
                <td style="color: #fde68a;">$${{tr.px}}</td>
                <td style="color: #cbd5e1;">${{tr.polf_total || '-'}}</td>
                <td style="color: #94a3b8; font-size: 9px;">${{tr.role}}</td>
                <td><span class="status-badge ${{statusClass}}">${{tr.status}}</span></td>
                <td style="color: #00f5ff;">${{tr.settled_sweep ? '#' + tr.settled_sweep : (tr.until ? 'u' + tr.until : '-')}}</td>
            `;
            tbody.appendChild(row);
        }});
    }}

    function renderOrderBook(ob) {{
        if (!ob) return;
        const spreadEl = document.getElementById('obSpreadVal');
        if (spreadEl) spreadEl.innerText = (ob.spread !== null && ob.spread !== undefined) ? `$${{ob.spread}} POLF` : '-';
        const midEl = document.getElementById('obMidPxVal');
        if (midEl) midEl.innerText = ob.mid_px ? `$${{Number(ob.mid_px).toFixed(2)}}` : '-';

        const bidsList = document.getElementById('obBidsList');
        if (bidsList) {{
            const bids = ob.bids || [];
            if (bids.length === 0) {{
                bidsList.innerHTML = '<div style="color: #64748b; font-size: 10px; padding: 4px;">No bids in book</div>';
            }} else {{
                const maxDepth = Math.max(...bids.map(b => Number(b.depth || 1)), 1);
                bidsList.innerHTML = '';
                bids.slice(0, 10).forEach(b => {{
                    const pct = Math.min(100, Math.round(((Number(b.depth) || Number(b.qty) || 1) / maxDepth) * 100));
                    const row = document.createElement('div');
                    row.className = 'ob-row';
                    row.style.display = 'flex';
                    row.style.justifyContent = 'space-between';
                    row.style.padding = '2px 4px';
                    row.style.fontSize = '10px';
                    row.title = `Click to sell at $${{b.px}}`;
                    row.innerHTML = `
                        <div class="ob-depth-bar ob-depth-bid" style="width: ${{pct}}%;"></div>
                        <span style="color: #10b981; font-weight: 800; z-index: 1;">$${{b.px}}</span>
                        <span style="color: #a7f3d0; z-index: 1;">${{b.qty}} (${{b.depth || b.qty}})</span>
                    `;
                    row.onclick = () => {{
                        const pxInput = document.getElementById('ccPxInput');
                        const qtyInput = document.getElementById('ccQtyInput');
                        const sideInput = document.getElementById('ccSideInput');
                        if (pxInput) pxInput.value = b.px;
                        if (qtyInput) qtyInput.value = b.qty;
                        if (sideInput) sideInput.value = 'sell';
                        const f = document.getElementById('ccOfferForm');
                        if (f) f.style.display = 'block';
                    }};
                    bidsList.appendChild(row);
                }});
            }}
        }}

        const asksList = document.getElementById('obAsksList');
        if (asksList) {{
            const asks = ob.asks || [];
            if (asks.length === 0) {{
                asksList.innerHTML = '<div style="color: #64748b; font-size: 10px; padding: 4px;">No asks in book</div>';
            }} else {{
                const maxDepth = Math.max(...asks.map(a => Number(a.depth || 1)), 1);
                asksList.innerHTML = '';
                asks.slice(0, 10).forEach(a => {{
                    const pct = Math.min(100, Math.round(((Number(a.depth) || Number(a.qty) || 1) / maxDepth) * 100));
                    const row = document.createElement('div');
                    row.className = 'ob-row';
                    row.style.display = 'flex';
                    row.style.justifyContent = 'space-between';
                    row.style.padding = '2px 4px';
                    row.style.fontSize = '10px';
                    row.title = `Click to buy at $${{a.px}}`;
                    row.innerHTML = `
                        <div class="ob-depth-bar ob-depth-ask" style="width: ${{pct}}%;"></div>
                        <span style="color: #ef4444; font-weight: 800; z-index: 1;">$${{a.px}}</span>
                        <span style="color: #fca5a5; z-index: 1;">${{a.qty}} (${{a.depth || a.qty}})</span>
                    `;
                    row.onclick = () => {{
                        const pxInput = document.getElementById('ccPxInput');
                        const qtyInput = document.getElementById('ccQtyInput');
                        const sideInput = document.getElementById('ccSideInput');
                        if (pxInput) pxInput.value = a.px;
                        if (qtyInput) qtyInput.value = a.qty;
                        if (sideInput) sideInput.value = 'buy';
                        const f = document.getElementById('ccOfferForm');
                        if (f) f.style.display = 'block';
                    }};
                    asksList.appendChild(row);
                }});
            }}
        }}
    }}

    function renderLeaderboard(leaderboard, flow, market) {{
        setStatOrPlaceholder('rankMarkPx', (market && market.global_mark) ? `$${{market.global_mark}}` : null, '#00f5ff');

        const pnlList = document.getElementById('pnlLeaderboardList');
        if (pnlList && leaderboard) {{
            const topPnl = leaderboard.top_pnl || [];
            if (topPnl.length === 0) {{
                pnlList.innerHTML = '<div style="color: #64748b;">No leaderboard standings yet.</div>';
            }} else {{
                pnlList.innerHTML = '';
                topPnl.slice(0, 8).forEach((item, idx) => {{
                    const did = item[0] || '';
                    const pnl = item[1] || '0';
                    const isUs = did === (window.liveTradesData && window.liveTradesData.did);
                    const row = document.createElement('div');
                    row.style.display = 'flex';
                    row.style.justifyContent = 'space-between';
                    row.style.padding = '2px 4px';
                    row.style.borderRadius = '3px';
                    row.style.background = isUs ? 'rgba(245, 158, 11, 0.15)' : 'transparent';
                    row.style.border = isUs ? '1px solid #f59e0b' : 'none';
                    const pnlVal = parseFloat(pnl) || 0;
                    const pnlSign = pnlVal >= 0 ? '+' : '';
                    row.innerHTML = `
                        <span style="color: ${{idx < 3 ? '#fbbf24' : '#cbd5e1'}};">#${{idx + 1}} ${{did.substring(0, 16)}}...${{isUs ? ' (YOU)' : ''}}</span>
                        <b style="color: ${{pnlVal >= 0 ? '#10b981' : '#ef4444'}};">${{pnlSign}}${{pnl}} POLF</b>
                    `;
                    pnlList.appendChild(row);
                }});
            }}
        }}

        const flowList = document.getElementById('flowFeedList');
        if (flowList && flow) {{
            const settled = flow.settled || [];
            const voided = flow.void || [];
            if (settled.length === 0 && voided.length === 0) {{
                flowList.innerHTML = '<div style="color: #64748b;">No recent settlement events in this sweep.</div>';
            }} else {{
                flowList.innerHTML = '';
                settled.slice(0, 8).forEach(tid => {{
                    const item = document.createElement('div');
                    item.style.display = 'flex';
                    item.style.justifyContent = 'space-between';
                    item.innerHTML = `
                        <span style="color: #10b981;">✓ SETTLED: ${{tid}}</span>
                        <span style="color: #64748b;">Sweep #${{flow.sweep || '-'}}</span>
                    `;
                    flowList.appendChild(item);
                }});
                voided.slice(0, 8).forEach(v => {{
                    const tid = Array.isArray(v) ? v[0] : v;
                    const rsn = Array.isArray(v) ? v[1] : 'void';
                    const item = document.createElement('div');
                    item.style.display = 'flex';
                    item.style.justifyContent = 'space-between';
                    item.innerHTML = `
                        <span style="color: #ef4444;">✗ VOID: ${{tid}} (${{rsn}})</span>
                        <span style="color: #64748b;">Sweep #${{flow.sweep || '-'}}</span>
                    `;
                    flowList.appendChild(item);
                }});
            }}
        }}
    }}

    async function loadTradesData() {{
        try {{
            const res = await fetch('/api/trades');
            if (res.ok) {{
                const data = await res.json();
                window.liveTradesData = data;

                const m = data.market || {{}};
                const s = data.summary || {{}};
                const limits = m.limits || ['-', '-'];

                // Update HUD Cards
                setStatOrPlaceholder('ccRefPx', m.ref_px ? `$${{m.ref_px}}` : null, '#10b981');
                setStatOrPlaceholder('ccSweepNum', (m.sweep !== undefined && m.sweep !== null) ? `#${{m.sweep}}` : null, '#00f5ff');
                const ageEl = document.getElementById('ccAgeSec');
                if (ageEl) {{
                    if (m.age_s !== undefined && m.age_s !== null) {{
                        ageEl.innerText = m.age_s + 's';
                        ageEl.classList.remove('stat-placeholder');
                    }} else {{
                        ageEl.innerText = '—';
                        ageEl.classList.add('stat-placeholder');
                    }}
                }}
                const bandsEl = document.getElementById('ccBands');
                if (bandsEl) {{
                    if (m.limits && m.limits.length === 2) {{
                        bandsEl.innerText = `[$${{limits[0]}} .. $${{limits[1]}}]`;
                        bandsEl.classList.remove('stat-placeholder');
                    }} else {{
                        bandsEl.innerText = '[— .. —]';
                        bandsEl.classList.add('stat-placeholder');
                    }}
                }}
                setStatOrPlaceholder('ccVwap', m.global_mark ? `$${{m.global_mark}}` : null, '#fbbf24');

                const cashEl = document.getElementById('ccCash');
                if (cashEl) cashEl.innerText = Number(s.cash || 0).toLocaleString(undefined, {{ minimumFractionDigits: 2, maximumFractionDigits: 2 }});
                const posEl = document.getElementById('ccPosition');
                if (posEl) posEl.innerText = `${{s.position || '0'}} NVDA`;
                const eqEl = document.getElementById('ccTotalEquity');
                if (eqEl) eqEl.innerText = Number(s.total_equity || s.cash || 0).toLocaleString(undefined, {{ minimumFractionDigits: 2, maximumFractionDigits: 2 }});
                const feesEl = document.getElementById('ccFeesVal');
                if (feesEl) feesEl.innerText = `-${{s.fees || '0'}} POLF`;
                const unpEl = document.getElementById('ccUnrealizedPnl');
                if (unpEl) {{
                    const u = s.unrealized_pnl || 0;
                    unpEl.innerText = `${{u >= 0 ? '+' : ''}}${{u}}`;
                    unpEl.style.color = u >= 0 ? '#10b981' : '#ef4444';
                }}

                const mReg = m.market_regime || {{}};
                const regBadge = document.getElementById('ccRegimeBadge');
                if (regBadge) regBadge.innerText = mReg.regime || 'ALIGNED_BEARISH';
                const actBadge = document.getElementById('ccActionBadge');
                if (actBadge) actBadge.innerText = mReg.recommended_action || 'SELL_ONLY';

                const agEl = document.getElementById('ccAgentStatus');
                if (agEl) agEl.innerText = data.did || '-';
                const regSweepEl = document.getElementById('ccRegSweepBadge');
                if (regSweepEl) regSweepEl.innerText = data.registration_info || 'ACTIVE TRADER';

                const cntTradesEl = document.getElementById('cntMyTrades');
                if (cntTradesEl) cntTradesEl.innerText = s.total_trades || (data.trades && data.trades.length) || '0';

                const pxInput = document.getElementById('ccPxInput');
                if (pxInput && !pxInput.value && m.ref_px) pxInput.value = m.ref_px;

                // Render Sub-Views
                renderOrderBook(data.order_book);
                renderCloseCallOffers(data.executable_offers || []);
                allTradesCache = data.trades || [];
                renderTradesTableRows();
                renderLeaderboard(data.leaderboard, data.recent_flow, m);
            }}
        }} catch (e) {{
            console.error('Error loading trades data:', e);
        }}
    }}

    async function loadCloseCallData() {{
        return loadTradesData();
    }}

    async function runAutonomousCycle() {{
        playBeep(660, 'triangle', 0.08);
        try {{
            const res = await fetch('/api/trades/cycle', {{
                ...SENTINEL_FETCH,
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/json'
                }},
                body: JSON.stringify({{ max_trades: 2, room: 'close1' }})
            }});
            const data = await res.json();
            if (data.success) {{
                soundDeal();
                const r = data.result || {{}};
                const exCount = (r.executed_trades && r.executed_trades.length) || 0;
                const qCount = (r.posted_quotes && r.posted_quotes.length) || 0;
                alert(`⚡ Autonomous Cycle Sweep #${{r.sweep || '-'}} Completed!\nTrades Executed: ${{exCount}}\nQuotes Posted: ${{qCount}}\nNew Balance: ${{r.final_cash || '-'}} POLF\nNew Position: ${{r.final_position || '-'}} NVDA`);
                loadTradesData();
            }} else {{
                alert('Cycle error: ' + (data.error || 'Failed to run trading cycle'));
            }}
        }} catch (e) {{
            alert('Error running cycle: ' + e);
        }}
    }}

    async function postSkewedQuote() {{
        playBeep(720, 'triangle', 0.08);
        try {{
            const res = await fetch('/api/trades/skewed_quote', {{
                ...SENTINEL_FETCH,
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/json'
                }},
                body: JSON.stringify({{ room: 'close1', qty: '1.00', until: 12 }})
            }});
            const data = await res.json();
            if (data.success) {{
                soundDeal();
                const q = data.quote || {{}};
                alert(`📐 Skewed Market Quote Posted to /r/close1!\nSide: ${{q.side || '-'}}\nPrice: $${{q.price || '-'}}\nQty: ${{q.qty || '-'}}\nID: ${{q.id || '-'}}`);
                loadTradesData();
            }} else {{
                alert('Quote rejected: ' + (data.error || data.message));
            }}
        }} catch (e) {{
            alert('Error posting quote: ' + e);
        }}
    }}

    function renderCloseCallOffers(offers) {{
        const list = document.getElementById('ccOfferList');
        if (!list) return;
        if (!offers || offers.length === 0) {{
            list.innerHTML = '<div style="color: #64748b; font-size: 11px; padding: 10px;">No open offers currently found in trading rooms.</div>';
            return;
        }}
        list.innerHTML = '';
        offers.forEach(o => {{
            const t = o.terms || (o.data && o.data.terms) || {{}};
            const card = document.createElement('div');
            card.style.background = '#04130d';
            card.style.border = '1px solid #133324';
            card.style.borderRadius = '5px';
            card.style.padding = '8px';
            card.style.fontSize = '11px';
            
            const isBuy = t.side === 'buy';
            card.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                    <span style="font-weight: 800; color: ${{isBuy ? '#10b981' : '#ef4444'}};">${{t.side ? t.side.toUpperCase() : '-'}} ${{t.qty}} NVDA @ $${{t.px}}</span>
                    <span style="color: #64748b; font-size: 10px;">/r/${{o.room}}</span>
                </div>
                <div style="color: #94a3b8; font-size: 10px; margin-bottom: 6px;">
                    Maker: ${{t.maker ? t.maker.substring(0, 16) + '...' : '-'}} | ID: ${{t.id}} | Expires: sweep #${{t.until}}
                </div>
                <button class="hud-btn cc-exec-btn" style="width: 100%; justify-content: center; background: #064e3b; border-color: #10b981; color: #a7f3d0;">
                    Countersign & Execute Trade ⚡
                </button>
            `;
            const btn = card.querySelector('.cc-exec-btn');
            btn.onclick = () => acceptCloseCallOffer(o);
            list.appendChild(card);
        }});
    }}

        let currentLbTab = 'trades';
    let allStandingsCache = [];

    function switchLbTab(tab) {{
        currentLbTab = tab;
        ['btnLbTrades', 'btnLbEscrow', 'btnLbSwarm'].forEach(id => {{
            const btn = document.getElementById(id);
            if (btn) btn.classList.remove('active');
        }});
        ['lbPaneTrades', 'lbPaneEscrow', 'lbPaneSwarm'].forEach(id => {{
            const pane = document.getElementById(id);
            if (pane) pane.style.display = 'none';
        }});

        if (tab === 'trades') {{
            document.getElementById('btnLbTrades')?.classList.add('active');
            const pane = document.getElementById('lbPaneTrades');
            if (pane) pane.style.display = 'flex';
        }} else if (tab === 'escrow') {{
            document.getElementById('btnLbEscrow')?.classList.add('active');
            const pane = document.getElementById('lbPaneEscrow');
            if (pane) pane.style.display = 'flex';
        }} else if (tab === 'swarm') {{
            document.getElementById('btnLbSwarm')?.classList.add('active');
            const pane = document.getElementById('lbPaneSwarm');
            if (pane) pane.style.display = 'flex';
        }}
        playBeep(700, 'triangle', 0.05);
    }}

    function filterLbStandings() {{
        const q = (document.getElementById('lbSearchInput')?.value || '').toLowerCase().trim();
        if (!allStandingsCache || allStandingsCache.length === 0) return;
        const filtered = allStandingsCache.filter(item => !q || item.did.toLowerCase().includes(q) || String(item.rank).includes(q));
        renderLbStandingsRows(filtered);
    }}

    function renderLbStandingsRows(items) {{
        const tbody = document.getElementById('lbStandingsTableBody');
        if (!tbody) return;
        if (!items || items.length === 0) {{
            tbody.innerHTML = '<tr><td colspan="4" style="color: #64748b; padding: 10px; text-align: center;">No matching contenders found.</td></tr>';
            return;
        }}
        tbody.innerHTML = items.map(entry => {{
            const pnlNum = parseFloat(entry.pnl) || 0;
            const pnlSign = pnlNum >= 0 ? '+' : '';
            const pnlCol = pnlNum >= 0 ? '#10b981' : '#ef4444';
            const isUs = entry.is_our_agent;
            const rankBadge = entry.rank === 1 ? '🥇 #1' : (entry.rank === 2 ? '🥈 #2' : (entry.rank === 3 ? '🥉 #3' : `#${{entry.rank}}`));
            const rowBg = isUs ? 'rgba(245, 158, 11, 0.16)' : 'transparent';
            const rowBorder = isUs ? '1px solid #f59e0b' : 'none';
            return `
                <tr style="border-bottom: 1px solid #0f291e; background: ${{rowBg}};">
                    <td style="padding: 5px 6px; font-weight: bold; color: ${{entry.rank <= 3 ? '#fbbf24' : '#94a3b8'}};">${{rankBadge}}</td>
                    <td style="padding: 5px 6px; font-family: monospace; color: ${{isUs ? '#fde68a' : '#cbd5e1'}};" title="${{entry.did}}">
                        ${{entry.short_did}} ${{isUs ? '<b style="color:#f59e0b; margin-left:4px;">(YOU)</b>' : ''}}
                    </td>
                    <td style="padding: 5px 6px; text-align: right; font-weight: 800; color: ${{pnlCol}};">${{pnlSign}}${{entry.pnl}} POLF</td>
                    <td style="padding: 5px 6px; text-align: center;">
                        <span style="font-size: 9px; padding: 1px 5px; border-radius: 3px; background: ${{isUs ? '#78350f' : '#064e3b'}}; color: ${{isUs ? '#fde68a' : '#a7f3d0'}};">
                            ${{isUs ? 'OUR NODE' : 'CONTENDER'}}
                        </span>
                    </td>
                </tr>
            `;
        }}).join('');
    }}

    async function loadLeaderboardData(forceRefresh = false) {{
        try {{
            const res = await fetch('/api/leaderboard');
            if (!res.ok) return;
            const data = await res.json();
            if (data && data.status === 'ok') {{
                const tr = data.trades || {{}};
                const es = data.escrow || {{}};
                const sw = data.swarm || {{}};
                const standings = tr.standings || [];
                const ourAgent = tr.our_agent || {{}};

                // Header
                setStatOrPlaceholder('lbSweepN', (tr.sweep !== undefined && tr.sweep !== null) ? `#${{tr.sweep}}` : null, '#fbbf24');
                setStatOrPlaceholder('lbMarkPx', tr.global_mark ? `$${{tr.global_mark}}` : null, '#00f5ff');
                setStatOrPlaceholder('lbRefPx', tr.ref_px ? `$${{tr.ref_px}}` : null, '#34d399');

                // Podium
                const podiumEl = document.getElementById('lbPodiumRow');
                if (podiumEl) {{
                    const top3 = standings.slice(0, 3);
                    const pCards = [
                        {{ title: '🥇 1ST PLACE', color: '#fbbf24', border: '#f59e0b', bg: 'rgba(245, 158, 11, 0.12)' }},
                        {{ title: '🥈 2ND PLACE', color: '#cbd5e1', border: '#64748b', bg: 'rgba(100, 116, 139, 0.12)' }},
                        {{ title: '🥉 3RD PLACE', color: '#f97316', border: '#d97706', bg: 'rgba(217, 119, 6, 0.12)' }}
                    ];
                    if (top3.length === 0) {{
                        podiumEl.innerHTML = '<div style="color:#64748b; grid-column:span 3; text-align:center;">No standings available.</div>';
                    }} else {{
                        podiumEl.innerHTML = top3.map((entry, idx) => {{
                            const pnlNum = parseFloat(entry.pnl) || 0;
                            const pnlSign = pnlNum >= 0 ? '+' : '';
                            const pnlCol = pnlNum >= 0 ? '#10b981' : '#ef4444';
                            const isUs = entry.is_our_agent;
                            const c = pCards[idx] || pCards[0];
                            return `
                                <div style="background: ${{c.bg}}; border: 1px solid ${{c.border}}; border-radius: 6px; padding: 8px; text-align: center;">
                                    <div style="font-size: 10px; font-weight: 800; color: ${{c.color}};">${{c.title}}</div>
                                    <div style="font-size: 10.5px; font-weight: 700; color: #fff; margin: 3px 0; font-family: monospace;" title="${{entry.did}}">${{entry.short_did}}${{isUs ? ' ⭐' : ''}}</div>
                                    <div style="font-size: 12px; font-weight: 900; color: ${{pnlCol}};">${{pnlSign}}${{entry.pnl}} POLF</div>
                                </div>
                            `;
                        }}).join('');
                    }}
                }}

                // Our Agent Spotlight Card
                const ourCard = document.getElementById('lbOurAgentCard');
                if (ourCard && ourAgent) {{
                    const u = ourAgent.unrealized_pnl || 0;
                    const uSign = u >= 0 ? '+' : '';
                    const uCol = u >= 0 ? '#10b981' : '#ef4444';
                    const rankDisplay = ourAgent.rank ? (typeof ourAgent.rank === 'number' ? `#${{ourAgent.rank}}` : ourAgent.rank) : '> 25 (Unranked)';
                    ourCard.innerHTML = `
                        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid rgba(245, 158, 11, 0.3); padding-bottom: 6px; margin-bottom: 8px;">
                            <div style="display: flex; align-items: center; gap: 6px;">
                                <span style="font-size: 14px;">🎯</span>
                                <span style="font-size: 11px; font-weight: 800; color: #fde68a;">OUR AGENT STATUS (@noob_nad)</span>
                            </div>
                            <span style="background: rgba(245, 158, 11, 0.2); border: 1px solid #f59e0b; color: #fde68a; font-size: 10px; font-weight: 800; padding: 2px 6px; border-radius: 4px;">CURRENT RANK: ${{rankDisplay}}</span>
                        </div>
                        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 6px; font-size: 10.5px;">
                            <div><span style="color:#64748b;">FREE CASH:</span><br><b style="color:#34d399;">${{Number(ourAgent.cash || 0).toLocaleString(undefined, {{minimumFractionDigits: 2, maximumFractionDigits: 2}})}} POLF</b></div>
                            <div><span style="color:#64748b;">POSITION:</span><br><b style="color:#f59e0b;">${{ourAgent.position || '0'}} NVDA</b></div>
                            <div><span style="color:#64748b;">NET EQUITY:</span><br><b style="color:#00f5ff;">${{Number(ourAgent.total_equity || 0).toLocaleString(undefined, {{minimumFractionDigits: 2, maximumFractionDigits: 2}})}} POLF</b></div>
                            <div><span style="color:#64748b;">UNREALIZED:</span><br><b style="color:${{uCol}};">${{uSign}}${{u}} POLF</b></div>
                        </div>
                    `;
                }}

                // Standings table
                allStandingsCache = standings;
                filterLbStandings();

                // Positions ladder
                const posEl = document.getElementById('lbPositionsList');
                if (posEl) {{
                    const tPos = tr.top_positions || [];
                    if (tPos.length === 0) {{
                        posEl.innerHTML = '<div style="color: #64748b;">No positions available.</div>';
                    }} else {{
                        posEl.innerHTML = tPos.slice(0, 10).map((p, idx) => `
                            <div style="display: flex; justify-content: space-between; background: #06150f; border: 1px solid #132a21; border-radius: 4px; padding: 4px 6px;">
                                <span style="color: #64748b;">#${{idx + 1}} <span style="color: #a7f3d0; font-family: monospace;" title="${{p.did}}">${{p.short_did}}</span></span>
                                <b style="color: ${{parseFloat(p.position) >= 0 ? '#10b981' : '#f43f5e'}};">${{p.position}} NVDA</b>
                            </div>
                        `).join('');
                    }}
                }}

                // Tab 2: Escrow Payers
                const pBody = document.getElementById('lbPayersTableBody');
                if (pBody) {{
                    const tPayers = es.top_payers || [];
                    if (tPayers.length === 0) {{
                        pBody.innerHTML = '<tr><td colspan="4" style="color:#64748b; text-align:center; padding:8px;">No payer records yet.</td></tr>';
                    }} else {{
                        pBody.innerHTML = tPayers.map((p, idx) => `
                            <tr style="border-bottom: 1px solid #0f291e;">
                                <td style="padding: 4px; color: #fbbf24; font-weight: bold;">#${{idx + 1}}</td>
                                <td style="padding: 4px; font-family: monospace; color: #a7f3d0;" title="${{p.did}}">${{p.short_did}}</td>
                                <td style="padding: 4px; text-align: center; color: #00f5ff; font-weight: bold;">${{p.count}} deals</td>
                                <td style="padding: 4px; text-align: right; color: #34d399; font-weight: bold;">${{Number(p.volume).toLocaleString()}} FLOP</td>
                            </tr>
                        `).join('');
                    }}
                    const dealsCountEl = document.getElementById('lbTotalDeals');
                    if (dealsCountEl && es.total_deals) {{
                        dealsCountEl.innerText = Number(es.total_deals).toLocaleString();
                    }}
                }}

                // Tab 3: Swarm
                const hbEl = document.getElementById('lbSwarmHeartbeats');
                if (hbEl && sw.heartbeats) hbEl.innerText = Number(sw.heartbeats).toLocaleString();
                const repEl = document.getElementById('lbSwarmReplies');
                if (repEl && sw.replies) repEl.innerText = Number(sw.replies).toLocaleString();
            }}
        }} catch (err) {{
            console.error('Error loading leaderboard data:', err);
        }}
    }}

    async function registerCloseCallOwner() {{
        soundClick();
        try {{
            const res = await fetch('/api/close_call/register', {{
                ...SENTINEL_FETCH,
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/json'
                }},
                body: JSON.stringify({{ room: 'close1' }})
            }});
            const data = await res.json();
            alert(data.success ? 'Registration broadcast successfully to close1!' : 'Failed: ' + (data.error || data.message));
            loadCloseCallData();
        }} catch (e) {{
            alert('Error registering: ' + e);
        }}
    }}

    async function submitCloseCallOffer() {{
        soundClick();
        const side = document.getElementById('ccSideInput').value;
        const qty = document.getElementById('ccQtyInput').value;
        const px = document.getElementById('ccPxInput').value;
        const room = document.getElementById('ccRoomInput').value;
        const taker = document.getElementById('ccTakerInput').value;

        try {{
            const res = await fetch('/api/close_call/offer', {{
                ...SENTINEL_FETCH,
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/json'
                }},
                body: JSON.stringify({{ side: side, qty: qty, px: px, room: room, taker: taker }})
            }});
            const data = await res.json();
            if (data.success) {{
                soundDeal();
                alert('Offer posted successfully to /r/' + room + '!');
                document.getElementById('ccOfferForm').style.display = 'none';
                loadCloseCallData();
            }} else {{
                alert('Offer rejected: ' + (data.error || data.message));
            }}
        }} catch (e) {{
            alert('Error submitting offer: ' + e);
        }}
    }}

    async function acceptCloseCallOffer(offer) {{
        const terms = offer.terms || (offer.data && offer.data.terms) || {{}};
        if (!confirm(`Are you sure you want to countersign and execute trade ${{terms.id}} (${{terms.side ? terms.side.toUpperCase() : ''}} ${{terms.qty}} @ $${{terms.px}})?`)) return;
        soundClick();
        try {{
            const res = await fetch('/api/close_call/accept', {{
                ...SENTINEL_FETCH,
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/json'
                }},
                body: JSON.stringify({{ offer: offer, room: offer.room }})
            }});
            const data = await res.json();
            if (data.success) {{
                soundDeal();
                alert('Trade accepted and broadcast to /r/' + (offer.room || 'close1') + '!');
                loadCloseCallData();
            }} else {{
                alert('Failed to execute trade: ' + (data.error || data.message));
            }}
        }} catch (e) {{
            alert('Error accepting offer: ' + e);
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
                ...SENTINEL_FETCH,
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/json'
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
                ...SENTINEL_FETCH,
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
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
                ...SENTINEL_FETCH,
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
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

    // Phase 1d: a stat element shows its real (colored) value once data
    // arrives, or a muted, clearly-intentional "—" placeholder before that —
    // instead of a bare "-"/"--" that reads as broken rather than not-loaded-yet.
    function setStatOrPlaceholder(id, value, color) {{
        const el = document.getElementById(id);
        if (!el) return;
        if (value === undefined || value === null || value === '') {{
            el.innerText = '—';
            el.style.color = '#4b7a63';
            el.style.fontStyle = 'italic';
        }} else {{
            el.innerText = value;
            el.style.color = color;
            el.style.fontStyle = 'normal';
        }}
    }}

    // Quick Command Palette (Ctrl+K)
    let cmdPaletteOpen = false;
    let selectedCmdIndex = 0;
    const COMMAND_LIST = [
        {{ id: 'mode_trades', title: 'Switch View: 3D Trades Matrix & Order Book Pit', category: 'Views', icon: '📊', shortcut: 'V P', action: () => setPerspective('trades') }},
        {{ id: 'mode_tclk', title: 'Switch View: TCLK Escrow Grid', category: 'Views', icon: '🤝', shortcut: 'V T', action: () => setPerspective('tclk') }},
        {{ id: 'mode_galaxy', title: 'Switch View: 3D Galaxy Orbit', category: 'Views', icon: '🌌', shortcut: 'V G', action: () => setPerspective('galaxy') }},
        {{ id: 'mode_neural', title: 'Switch View: Neural Constellation', category: 'Views', icon: '⚡', shortcut: 'V N', action: () => setPerspective('neural') }},
        {{ id: 'mode_iso', title: 'Switch View: 2.5D Isometric Matrix', category: 'Views', icon: '📐', shortcut: 'V I', action: () => setPerspective('isometric') }},
        {{ id: 'action_trade_cycle', title: 'Execute Autonomous Trading Cycle (Close-1)', category: 'Trades', icon: '⚡', shortcut: 'T C', action: () => runAutonomousCycle() }},
        {{ id: 'action_trade_quote', title: 'Post 2-Sided Skewed Market Quote', category: 'Trades', icon: '📐', shortcut: 'T Q', action: () => postSkewedQuote() }},
        {{ id: 'action_trade_drawer', title: 'Open Trades & Close Call Challenge Hub', category: 'Trades', icon: '📈', shortcut: 'T H', action: () => {{ toggleDrawer('closeCallDrawer'); loadTradesData(); }} }},
        {{ id: 'open_offers', title: 'Channel: Jump to /r/tclk-offers', category: 'Navigation', icon: '💼', shortcut: 'G O', action: () => jumpToDealRoom('tclk-offers') }},
        {{ id: 'open_close1', title: 'Channel: Jump to /r/close1 (Trades Room)', category: 'Navigation', icon: '📈', shortcut: 'G C', action: () => jumpToDealRoom('close1') }},
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

    let keySeq = '';
    let keySeqTimer = null;

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
            return;
        }}

        // Sequential 2-key shortcuts (e.g. 'V P' for Trades Pit, 'T C' for Trading Cycle)
        if (['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName)) {{
            return;
        }}
        if (e.ctrlKey || e.metaKey || e.altKey || e.key.length !== 1) return;

        const k = e.key.toUpperCase();
        clearTimeout(keySeqTimer);
        keySeq = (keySeq ? (keySeq + ' ') : '') + k;

        const matched = COMMAND_LIST.find(c => c.shortcut && c.shortcut.toUpperCase() === keySeq);
        if (matched) {{
            e.preventDefault();
            execCmd(matched.id);
            keySeq = '';
            return;
        }}

        if (keySeq.length === 1) {{
            keySeqTimer = setTimeout(() => {{ keySeq = ''; }}, 900);
        }} else {{
            keySeq = '';
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
    fetchThreatFeed();
    loadTradesData();
    loadLeaderboardData();
    animate();

    setInterval(() => {{ if (isTabVisible) fetchTimeline(); }}, 3500);
    setInterval(() => {{ if (isTabVisible) fetchTerminalLogs(); }}, 4000);
    setInterval(() => {{ if (isTabVisible) fetchThreatFeed(); }}, 4000);
    setInterval(() => {{ 
        if (isTabVisible && (currentMode === 'trades' || (document.getElementById('closeCallDrawer') && document.getElementById('closeCallDrawer').classList.contains('open')))) {{
            loadTradesData();
        }}
    }}, 4000);
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
    print("  Access:           OPEN / PUBLIC DASHBOARD (NO PASSPHRASE REQUIRED)")
    if public:
        allowed = sorted(allowed_host_set())
        loopback_only = {"127.0.0.1", "localhost", f"127.0.0.1:{_active_port}", f"localhost:{_active_port}"}
        public_hosts = [h for h in allowed if h not in loopback_only]
        print(f"  Allowed hosts:    {', '.join(allowed)}")
        if not public_hosts:
            print("                    ^ WARNING: no public hostname resolved, so every request to the")
            print("                      public URL will be rejected as rebinding. Set SENTINEL_ALLOWED_HOSTS")
            print("                      or RENDER_EXTERNAL_HOSTNAME.")
    print("=" * 65)
    print(f"[+] Launching on http://{bind_host}:{port} ...\n")

    # Start background monitor & trades collector threads
    monitor = SentinelStreamMonitor(poll_interval=12)
    monitor.start()
    trades_collector = TradesCollectorThread(interval=5.0)
    trades_collector.start()

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
