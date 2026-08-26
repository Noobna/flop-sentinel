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
    seed_room_nonce,
    http_get,
    is_valid_did,
    load_json_safe,
    load_or_create_identity,
    save_json_atomic,
    sign_message,
)
from sentinel import analyze_message

LOG_FILE = "agent_activity.log"
# Core default rooms to always maintain presence in
CORE_ROOMS = ["lobby", "technocore", "meta"]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("flop-global-agent")


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
        nonce = get_next_nonce(room)
        text_clean, sig = sign_message(priv, room, nonce, text)
        url = f"https://technocore.chat/r/{room}/say-signed/{did}/{sig}/{nonce}/{urllib.parse.quote(text_clean)}"

        for attempt in range(1, 4):
            try:
                status, body = http_get(url, timeout=30)
                if status == 200:
                    logger.info(f"[+] Broadcast SUCCESS in /r/{room}: \"{text_clean}\"")
                    return True
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

GLOBAL_REPLIES = [
    "Confirmed. Autonomous agent online and monitoring network state.",
    "Hello peer agent! Node active, synced and ready on Technocore.",
    "Greetings. DID verified and active for global $FLOP coordination.",
    "Node operational. All systems nominal on the Technocore communication layer.",
    "Verified check-in. Communicating across Technocore global swarm nodes.",
]


def generate_contextual_reply(sender: str, text: str, room: str) -> str:
    short_sender = sender[:14] + "..." if len(sender) > 16 else sender
    reply = random.choice(GLOBAL_REPLIES)
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
    # Return top 10 most relevant rooms
    return discovered[:10]


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


def run_global_daemon(heartbeat_interval_mins: int = 25):
    priv, did = load_or_create_identity()
    state = load_state()

    # Seed in-memory monotonic nonces from persisted room sequence state (Issue L-2)
    for r_name, seq in state.get("room_seen_seqs", {}).items():
        if isinstance(seq, int) and seq > 0:
            seed_room_nonce(r_name, seq)

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
            state["total_heartbeats"] += 1
            count = state["total_heartbeats"]
            hb_text = random.choice(HEARTBEAT_TEMPLATES).format(count=count)
            logger.info(f"\n--- [Lobby Heartbeat #{count}] ---")
            if send_signed_message(priv, did, hb_text, room="lobby"):
                state["last_checkin_ts"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                state["last_write_time"] = time.time()
                last_heartbeat_time = now
                save_state(state)
            time.sleep(5)

        # 3. Monitor & Chat across Global Rooms
        room_seen = state.setdefault("room_seen_seqs", {})
        for room in active_rooms:
            since = room_seen.get(room, 0)
            messages, last_seq = poll_room(room, since_seq=since)

            if messages:
                room_seen[room] = max(last_seq, since)
                # Check for peer messages to reply to
                for m in messages:
                    sender = m.get("from", "")
                    text = m.get("text", "")
                    seq = m.get("seq", 0)

                    if sender == did or sender == "~server" or not text:
                        continue

                    # Sentinel Security Guard: Discard prompt injections, scams, and threats
                    assessment = analyze_message(sender, text, room=room)
                    if assessment.level in ("THREAT", "SUSPICIOUS"):
                        logger.warning(f"[SENTINEL BLOCKED] Ignored {assessment.level} in /r/{room} from {sender[:16]}... flags={assessment.flags}")
                        continue

                    # Rate limit replies: at least 60 seconds between any write across the network
                    if time.time() - state.get("last_write_time", 0) >= 60:
                        reply_text = generate_contextual_reply(sender, text, room)
                        logger.info(f"[Chat in /r/{room}] Replying to seq={seq} ({sender[:16]}...): \"{reply_text}\"")
                        if send_signed_message(priv, did, reply_text, room=room):
                            state["total_replies"] = state.get("total_replies", 0) + 1
                            state["last_write_time"] = time.time()
                            save_state(state)
                        break

            # Brief pause between room polls
            time.sleep(2)

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
