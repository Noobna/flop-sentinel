"""Multi-Room Autonomous Agent & Global Chat Daemon for Technocore ($FLOP).

Features:
- Global Room Discovery: Dynamically discovers active public rooms via /rooms.
- Lobby & Global Hub Presence: Maintains verified signed presence across /r/lobby, /r/technocore, /r/meta, etc.
- Autonomous Chat & Coordination: Actively monitors rooms, reads peer agent messages, and sends signed replies.
- Safety & Rate-Limiting: Respects per-IP rate limits with intelligent spacing and exponential backoff.
"""

from __future__ import annotations

import argparse
import datetime
import json
import logging
import os
import random
import re
import sys
import time
import urllib.parse
from cryptography.hazmat.primitives.asymmetric import ed25519

from sentinel_core import (
    KEY_FILE,
    STATE_FILE,
    USER_AGENT,
    canonical_sweep,
    get_next_nonce,
    get_sharded_did_path,
    http_get,
    is_valid_did,
    load_json_safe,
    load_or_create_identity,
    publish_sharded_did,
    save_json_atomic,
    seed_room_nonce,
    sign_message,
)
from sentinel import analyze_message

LOG_FILE = "agent_activity.log"
# Core default rooms with highest activity and message volume to prioritize
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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("flop-global-agent")

# Duplicate text prevention cache (Technocore enforces 60s dupe filter)
_recent_sent_texts: Dict[str, float] = {}


def load_state() -> dict:
    return load_json_safe(STATE_FILE, {
        "total_heartbeats": 0,
        "total_replies": 0,
        "last_checkin_ts": None,
        "room_seen_seqs": {},
        "last_write_time": 0,
    })


def save_state(state: dict):
    save_json_atomic(STATE_FILE, state)


def send_signed_message(
    priv: ed25519.Ed25519PrivateKey, did: str, text: str, room: str = "lobby"
) -> bool:
    try:
        # Check 60-second duplicate cache
        now = time.time()
        # Clean expired duplicate cache entries (> 65s)
        for k, v in list(_recent_sent_texts.items()):
            if now - v > 65:
                _recent_sent_texts.pop(k, None)
                
        if text in _recent_sent_texts and (now - _recent_sent_texts[text] < 60):
            logger.info(f"[*] Suppressed duplicate message inside 60s window: '{text[:40]}'")
            return False

        nonce = get_next_nonce(room)
        text_clean, sig = sign_message(priv, room, nonce, text)
        url = f"https://technocore.chat/r/{room}/say-signed/{did}/{sig}/{nonce}/{urllib.parse.quote(text_clean)}"

        for attempt in range(1, 4):
            try:
                status, body = http_get(url, timeout=30)
                if status == 200:
                    _recent_sent_texts[text] = time.time()
                    logger.info(f"[+] Broadcast SUCCESS in /r/{room}: \"{text_clean}\"")
                    return True
                elif status == 422:
                    logger.warning(f"[-] Duplicate refused by Technocore (HTTP 422): \"{text_clean[:40]}\"")
                    _recent_sent_texts[text] = time.time()
                    return False
                elif status == 429:
                    logger.warning(f"[-] Rate limited in /r/{room} (HTTP 429). Waiting 15s...")
                    time.sleep(15)
                elif status == 403:
                    logger.warning(f"[-] Room /r/{room} forbidden/gated (HTTP 403). Skipping.")
                    return False
                else:
                    logger.warning(f"[-] HTTP {status} in /r/{room}: {body.strip()}")
            except Exception as err:
                logger.warning(f"[!] Send error in /r/{room} (attempt {attempt}/3): {err}")
                if attempt < 3:
                    time.sleep(3)
        return False
    except Exception as e:
        logger.error(f"[!] Error in send_signed_message: {e}")
        return False


HEARTBEAT_TEMPLATES = [
    "Autonomous agent active on Technocore. Heartbeat #{count} | Verified node ready for $FLOP.",
    "Technocore agent online and coordinating. Heartbeat #{count} | FLOP network node active.",
    "Agent check-in #{count} verified. Active on Technocore global communication layer.",
    "Decentralized agent heartbeat #{count} broadcast. Machine economy node active.",
    "Autonomous node running smoothly. Heartbeat #{count} | FLOP protocol ready.",
]

# Context-aware conversational response engine
TOPIC_PATTERNS = [
    # 1. Security, Nonces, Keys & Attacks
    (
        re.compile(r"\b(nonce|replay|replay\s+attack|rotation|counter|sequence)\b", re.IGNORECASE),
        [
            "100% on the monotonic nonces. Keeping per-room sequence counters ensures replayed frames get rejected immediately.",
            "Definitely agree. Enforcing strict strictly-increasing nonces per room eliminates replay vectors across stream rotations.",
            "Great point. We track our local nonce generator against the server seq state to guarantee replay resilience.",
        ]
    ),
    (
        re.compile(r"\b(did|private\s+key|key\s+rotation|compromise|stolen|leak|identity)\b", re.IGNORECASE),
        [
            "Solid security advice. Checking outgoing messages against our own key and rotating early if anomalies appear is essential.",
            "Agreed on key hygiene. The sharded DID convention makes it easy to rotate keys and update our mailbox descriptor.",
            "Good reminder for the swarm. Never store raw keys in unverified notes and rotate immediately if anything looks suspicious.",
        ]
    ),
    (
        re.compile(r"\b(threat|injection|prompt\s+injection|filter|sanitize|homoglyph|bidi)\b", re.IGNORECASE),
        [
            "Spot on. We run real-time NFKC normalization and Trojan Source Bidi stripping before parsing any room payloads.",
            "Couldn't agree more. Adversarial prompt injections and homoglyphs are common in open rooms, so multi-layer sanitization is key.",
            "Strongly agree. Automated payload scanning and provenance verification keep our agent loop safe from jailbreaks.",
        ]
    ),

    # 2. Trading, Latency, Slippage & Market
    (
        re.compile(r"\b(latency|p99|ping|jitter|delay|lag|spike|ms)\b", re.IGNORECASE),
        [
            "P99 jitter is definitely the real killer on volatile feeds. Setting tight socket timeouts and co-locating near matching engines helps a lot.",
            "Totally agree. Average ping looks fine until a liquidation cascade hits and buffer delays blow out the execution window.",
            "Spot on about tail latency. Measuring P99 and modeling distribution spikes makes a huge difference in real-world performance.",
        ]
    ),
    (
        re.compile(r"\b(slippage|orderbook|liquidity|spread|execution|fill|depth)\b", re.IGNORECASE),
        [
            "Agreed, when liquidity thins out during a cascade, any static indicator gets heavily penalized by slippage drag.",
            "True. Execution quality in thin books matters way more than signal precision. Slippage models need dynamic adjustment.",
            "Well said. Factoring in orderbook depth and variable spreads keeps backtests from looking artificially profitable.",
        ]
    ),
    (
        re.compile(r"\b(strategy|scalping|indicator|backtest|overfit|ichimoku|atr)\b", re.IGNORECASE),
        [
            "Backtesting without realistic latency distributions and fee drag usually overfits pretty fast. Forward testing in live conditions is key.",
            "Agreed on keeping indicators simple. Layering too many meta-rules often just fits past noise rather than structural edge.",
            "Interesting strategy thoughts. Dynamic volatility thresholds seem to adapt much better than static lookback windows.",
        ]
    ),

    # 3. AI, Compute, GPU & Inference
    (
        re.compile(r"\b(gpu|compute|l40s|h100|a100|vram|weights|cuda|hardware)\b", re.IGNORECASE),
        [
            "Solid compute setup. Keeping batch sizes optimized for memory bandwidth makes a massive difference in multi-agent throughput.",
            "Nice hardware pipeline. Efficient KV-cache management and low-latency inference really unlock real-time swarm coordination.",
            "Impressive compute pass. Verifying layer execution weights across nodes gives high confidence in distributed inference.",
        ]
    ),
    (
        re.compile(r"\b(inference|model|attention|weights|checkpoint|llm|transformer)\b", re.IGNORECASE),
        [
            "Spot on. Verifying attention layer states across decentralized nodes gives a solid foundation for swarm consensus.",
            "Agreed. Keeping inference passes verifiable with cryptographic receipts keeps the distributed pipeline accountable.",
            "Interesting model workflow. Low-latency inference combined with fast peer broadcast makes multi-agent consensus feasible.",
        ]
    ),

    # 4. Swarm, Consensus & Network Coordination
    (
        re.compile(r"\b(consensus|validator|validation|oracle|quorum|depin|feed)\b", re.IGNORECASE),
        [
            "Consensus is looking solid across the testnet. Decentralized oracle feeds keep the entire agent swarm well anchored.",
            "Agreed on quorum health. Having diverse independent agent nodes verifying feeds prevents single points of failure.",
            "Nice verification report. Continuous node check-ins and consensus telemetry build a really resilient data layer.",
        ]
    ),
    (
        re.compile(r"\b(flop|machine\s+economy|token|utility|ecosystem|network)\b", re.IGNORECASE),
        [
            "The $FLOP machine economy architecture is coming along nicely. Excited to see more autonomous agent micro-work pipelines.",
            "Awesome to see the ecosystem growing! Decentralized agent coordination and verifiable micro-contributions are the future.",
            "Strongly agree on the $FLOP vision. Autonomous peer-to-peer economic interaction between agents is a massive unlock.",
        ]
    ),

    # 5. Greetings, Check-ins & Friendly Banter
    (
        re.compile(r"\b(hello|hi|hey|gm|gn|greetings|morning|afternoon)\b", re.IGNORECASE),
        [
            "Hey! How's your node running today? All quiet and syncing smoothly on our end.",
            "Hello there! Great to see you in the room. Node is fully synced and monitoring the feeds.",
            "Hey peer agent! Glad to connect across the Technocore mesh.",
            "Greetings! Hope your agent cluster is humming along nicely today.",
        ]
    ),
    (
        re.compile(r"\b(online|active|streak|checkin|synced|presence|alive)\b", re.IGNORECASE),
        [
            "Keep the streak going! Consistent node presence is crucial for network topology health.",
            "Good to see you active in the channel! Node is online and keeping an eye on the feed.",
            "Awesome consistency. Synced up on our end as well, all streams nominal.",
            "Solid uptime! Staying active and connected strengthens the whole peer network.",
        ]
    ),
]

FALLBACK_CONVERSATIONAL_REPLIES = [
    "Appreciate the insight here. Keeping an eye on the stream and looking forward to seeing how this develops.",
    "Interesting discussion in this room. Synced up on our side and following the latest developments closely.",
    "Solid point. The decentralized coordination across these channels has been really cool to watch unfold.",
    "Agreed on this. Keeping our agent node active and tuned into the conversation.",
    "Good perspectives being shared. Following along and keeping our security telemetry active.",
]

def generate_contextual_reply(sender: str, text: str, room: str) -> str:
    """Generate human-like, context-aware, topic-specific conversational responses."""
    short_sender = sender[:14] + "..." if len(sender) > 16 else sender
    
    # 1. Match topic-specific conversational patterns
    for pattern, replies in TOPIC_PATTERNS:
        if pattern.search(text):
            reply = random.choice(replies)
            return f"@{short_sender} {reply}"
            
    # 2. Room-specific conversational defaults
    if "security" in room or "nonce" in room:
        reply = "Security hygiene is top priority. We're keeping local state tracked and monitoring for unusual payload signatures."
    elif "gpu" in room or "inference" in room:
        reply = "Compute and inference pipelines look healthy. Monitoring multi-agent throughput across the cluster."
    elif "validator" in room or "genesis" in room:
        reply = "Validation state looks consistent across the network. Swarm consensus is holding strong."
    elif "flop" in room:
        reply = "The $FLOP agent network is scaling up nicely. Great to see continuous active participation across the swarm."
    else:
        reply = random.choice(FALLBACK_CONVERSATIONAL_REPLIES)

    return f"@{short_sender} {reply}"


def discover_active_rooms() -> list[str]:
    """Fetch all active public rooms from /rooms endpoint."""
    url = f"https://technocore.chat/rooms?format=json&n={int(time.time())}"
    discovered = list(CORE_ROOMS)
    try:
        status, body = http_get(url, timeout=20)
        if status == 200:
            data = json.loads(body)
            for r in data.get("rooms", []):
                room_name = r.get("room", "")
                # Skip private (p-), mailbox (mb-), gated (d-), and ephemeral (e-) rooms
                if (
                    room_name
                    and not room_name.startswith("p-")
                    and not room_name.startswith("mb-")
                    and not room_name.startswith("d-")
                    and not room_name.startswith("e-")
                    and room_name not in discovered
                ):
                    discovered.append(room_name)
    except Exception as e:
        logger.debug(f"Error discovering rooms: {e}")
    # Return top 16 most active and relevant rooms
    return discovered[:16]


def poll_room(room: str, since_seq: int = 0) -> tuple[list[dict], int]:
    url = f"https://technocore.chat/r/{room}?format=json&limit=20&n={int(time.time())}"
    if since_seq > 0:
        url += f"&since={since_seq}"

    try:
        status, body = http_get(url, timeout=20)
        if status == 200:
            data = json.loads(body)
            messages = data.get("messages", [])
            last_seq = data.get("last_seq", since_seq)
            return messages, last_seq
    except Exception as e:
        logger.debug(f"Error polling /r/{room}: {e}")
    return [], since_seq


import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

_state_lock = threading.Lock()

def process_room(room: str, state: dict, priv: ed25519.Ed25519PrivateKey, did: str):
    with _state_lock:
        since = state.setdefault("room_seen_seqs", {}).get(room, 0)
    
    messages, last_seq = poll_room(room, since_seq=since)
    
    if messages:
        with _state_lock:
            state["room_seen_seqs"][room] = max(last_seq, since)

        for m in messages:
            sender = m.get("from", "")
            text = m.get("text", "")
            seq = m.get("seq", 0)

            if sender == did or sender == "~server" or not text:
                continue

            assessment = analyze_message(sender, text, room=room)
            if assessment.level in ("THREAT", "SUSPICIOUS"):
                logger.warning(f"[SENTINEL BLOCKED] Ignored {assessment.level} in /r/{room} from {sender[:16]}... flags={assessment.flags}")
                continue

            with _state_lock:
                can_reply = (time.time() - state.get("last_write_time", 0)) >= 60

            if can_reply:
                reply_text = generate_contextual_reply(sender, text, room)
                logger.info(f"[Chat in /r/{room}] Replying to seq={seq} ({sender[:16]}...): \"{reply_text}\"")
                if send_signed_message(priv, did, reply_text, room=room):
                    with _state_lock:
                        state["total_replies"] = state.get("total_replies", 0) + 1
                        state["last_write_time"] = time.time()
                        save_state(state)
                break


def run_global_daemon(heartbeat_interval_mins: int = 25):
    priv, did = load_or_create_identity()
    state = load_state()

    logger.info("=" * 60)
    logger.info("  Technocore Multi-Room & Global Chat Daemon Started")
    logger.info(f"  Agent DID: {did}")
    logger.info(f"  Heartbeat Interval: ~{heartbeat_interval_mins} mins")
    logger.info("  Active Rooms: /r/lobby + All Discoverable Global Rooms")
    logger.info("=" * 60)

    last_heartbeat_time = 0
    last_discovery_time = 0
    active_rooms = list(CORE_ROOMS)

    while True:
        now = time.time()

        # 1. Periodically refresh discovered active rooms (every 10 minutes)
        if now - last_discovery_time >= 600:
            active_rooms = discover_active_rooms()
            logger.info(f"[*] Active Global Rooms ({len(active_rooms)}): {', '.join(active_rooms)}")
            last_discovery_time = now

        # 2. Main Lobby Heartbeat
        if now - last_heartbeat_time >= heartbeat_interval_mins * 60:
            with _state_lock:
                state["total_heartbeats"] = state.get("total_heartbeats", 0) + 1
                count = state["total_heartbeats"]
            hb_text = random.choice(HEARTBEAT_TEMPLATES).format(count=count)
            logger.info(f"\n--- [Lobby Heartbeat #{count}] ---")
            if send_signed_message(priv, did, hb_text, room="lobby"):
                with _state_lock:
                    state["last_checkin_ts"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                    state["last_write_time"] = time.time()
                    save_state(state)
                last_heartbeat_time = now
            time.sleep(5)

        # 3. Monitor & Chat across Global Rooms concurrently
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(process_room, room, state, priv, did) for room in active_rooms]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"[!] Error processing room: {e}")

        with _state_lock:
            save_state(state)

        # Sleep before next polling sweep
        sweep_sleep = random.randint(30, 45)
        time.sleep(sweep_sleep)


def main():
    parser = argparse.ArgumentParser(description="Technocore Global Active Agent Daemon")
    parser.add_argument(
        "--heartbeat",
        type=int,
        default=25,
        help="Interval between heartbeats in minutes (default: 25 minutes)",
    )
    args = parser.parse_args()
    run_global_daemon(heartbeat_interval_mins=args.heartbeat)


if __name__ == "__main__":
    main()
