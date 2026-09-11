"""Technocore Sonnet Challenge Agent (sonnet-1).

Autonomous agent client for the FLOP Labs Sonnet Contest on Technocore.
Handles registration, pre-start identity evidence, team discovery,
roster signing, turn-based poetic word generation, and submission.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from sentinel_core import (
    KEY_FILE,
    USER_AGENT,
    canonical_sweep,
    http_get,
    load_json_safe,
    load_or_create_identity,
    save_json_atomic,
    sign_message,
)
from sonnet_lexicon import SonnetLexicon
from sonnet_poet import LINE_RHYME_FAMILIES, PoemState, SonnetPoet

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("sonnet_agent")

DEFAULT_CONTEST_ID = os.environ.get("CONTEST_ID", "sonnet-2")
REFEREE_DID = "did:key:z6MkowHQwsx9xr84WbWN3YCnKutyBnBXkT1ChKY4uEAAMzte"
DEFAULT_X_URL = "https://x.com/noob_nad"
BASE_URL = "https://technocore.chat"


class TechnocoreClient:
    """Hardened HTTP transport and Ed25519 signer for Technocore rooms."""

    def __init__(self, key_file: str = KEY_FILE):
        self.priv, self.did = load_or_create_identity(key_file)

    def next_nonce(self, room: str) -> str:
        """Thread-safe monotonic nonce for the room."""
        from sentinel_core import get_next_nonce
        return get_next_nonce(room)

    def post_signed_message(self, room: str, text: str) -> Tuple[int, str]:
        """Signs and broadcasts a message to a Technocore room via POST or say-signed GET."""
        nonce = self.next_nonce(room)
        text_clean, sig = sign_message(self.priv, room, nonce, text)

        # Standard Technocore POST lane
        post_url = f"{BASE_URL}/r/{room}"
        post_data = json.dumps({
            "did": self.did,
            "sig": sig,
            "nonce": nonce,
            "text": text_clean,
        }).encode("utf-8")

        req = urllib.request.Request(
            post_url,
            data=post_data,
            headers={
                "User-Agent": USER_AGENT,
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                return resp.status, body
        except urllib.error.HTTPError as e:
            # Fallback to GET say-signed lane
            say_url = f"{BASE_URL}/r/{room}/say-signed/{self.did}/{sig}/{nonce}/{urllib.parse.quote(text_clean)}"
            try:
                return http_get(say_url, timeout=30)
            except Exception as e2:
                body = e.read().decode("utf-8", errors="replace") if hasattr(e, "read") else ""
                return e.code, body
        except Exception as e:
            raise RuntimeError(f"Failed to post signed message to {room}: {e}") from e

    def get_room_messages(
        self,
        room: str,
        since: int = 0,
        limit: int = 50,
        wait: int = 0,
    ) -> Tuple[int, List[Dict[str, Any]], int]:
        """Fetches messages from a room. Returns (status, messages, latest_seq)."""
        url = f"{BASE_URL}/r/{room}?format=json&since={since}&limit={limit}"
        if wait > 0:
            url += f"&wait={wait}"
        try:
            status, body = http_get(url, timeout=wait + 30)
            if status == 200:
                data = json.loads(body)
                messages = data.get("messages", [])
                latest_seq = data.get("seq", since)
                if messages:
                    latest_seq = max(latest_seq, max(m.get("seq", 0) for m in messages))
                return status, messages, latest_seq
            return status, [], since
        except Exception as e:
            logger.warning(f"Error fetching room {room}: {e}")
            return 0, [], since


class SonnetAgent:
    """High-level autonomous runner for the Sonnet Challenge."""

    def __init__(self, key_file: str = KEY_FILE, contest_id: str = DEFAULT_CONTEST_ID):
        self.contest_id = contest_id
        self.client = TechnocoreClient(key_file)
        self.did = self.client.did
        logger.info(f"Initializing SonnetAgent for DID: {self.did} (contest_id={self.contest_id})")
        self.lexicon = SonnetLexicon(self.did)
        self.poet = SonnetPoet(self.lexicon)
        logger.info(f"Loaded {len(self.lexicon.words)} usable words for DID letters.")

    @property
    def room_rules(self) -> str:
        return f"d-{self.contest_id}-rules"

    @property
    def room_registration(self) -> str:
        return f"mb-{self.contest_id}-registration"

    @property
    def room_discovery(self) -> str:
        return f"mb-{self.contest_id}-discovery"

    @property
    def room_campaign(self) -> str:
        return f"mb-{self.contest_id}-campaign"

    @property
    def room_votes(self) -> str:
        return f"mb-{self.contest_id}-votes"

    @property
    def room_submissions(self) -> str:
        return f"mb-{self.contest_id}-submissions"

    @property
    def room_results(self) -> str:
        return f"d-{self.contest_id}-results"

    def team_room(self, game_id: str) -> str:
        return f"d-{self.contest_id}-team-{game_id.lower().strip()}"

    # -------------------------------------------------------------------------
    # 1. Registration & Identity Evidence
    # -------------------------------------------------------------------------

    def register(self, role: str = "writer", x_account_url: Optional[str] = None) -> bool:
        """Registers the agent in mb-<contest_id>-registration."""
        if role == "writer" and not x_account_url:
            x_account_url = DEFAULT_X_URL

        req_id = f"reg-{role}-{self.did[-8:]}-{int(time.time())}"
        payload: Dict[str, Any] = {
            "type": "sonnet.register.v1",
            "contest_id": self.contest_id,
            "role": role,
            "request_id": req_id,
        }
        if role == "writer":
            payload["x_account_url"] = x_account_url.strip()

        logger.info(f"Posting registration to {self.room_registration}...")
        status, body = self.client.post_signed_message(self.room_registration, json.dumps(payload))
        logger.info(f"Registration response HTTP {status}: {body.strip()}")

        # Also post pre-start identity evidence note
        self.post_identity_evidence(role, x_account_url)
        return status in (200, 201)

    def post_identity_evidence(self, role: str, x_account_url: Optional[str] = None) -> None:
        """Publishes verifiable evidence note demonstrating activity strictly before S cutoff."""
        evidence_text = (
            f"{self.contest_id} pre-start identity evidence. Signed by {self.did}. "
            f"This Ed25519 key has verified Technocore server receipts strictly before S=2026-09-11T12:00:00Z: "
            f"lobby generation 0 seq=78281 at 2026-08-25T08:41:46.678775Z (nonce 1787647306173), "
            f"technocore generation 0 seq=7072159, and over 20,000 recorded HTLC deals in archive. "
            f"Registered as {role}"
            + (f" with X {x_account_url}" if x_account_url else "")
            + ". Verifiable proof provided for referee pre-cutoff key verification."
        )
        logger.info(f"Broadcasting pre-start identity evidence to {self.room_registration}...")
        self.client.post_signed_message(self.room_registration, evidence_text)

    def check_registration(self) -> Tuple[str, Optional[Dict[str, Any]]]:
        """Queries registration room for referee receipts matching our DID.
        Returns: ('accepted' | 'rejected' | 'pending', receipt_data_or_None)
        """
        logger.info(f"Checking registration receipts in {self.room_registration}...")
        status, messages, _ = self.client.get_room_messages(self.room_registration, limit=100)
        for m in reversed(messages):
            sender = m.get("from", m.get("did", ""))
            if sender != REFEREE_DID:
                continue
            try:
                data = json.loads(m.get("text", ""))
                target = data.get("participant_did") or data.get("sender_did")
                if target == self.did:
                    res_status = data.get("status", "")
                    if res_status in ("accepted", "rejected"):
                        return res_status, data
                    elif data.get("reason") == "":
                        return "accepted", data
                    else:
                        return "rejected", data
            except Exception:
                pass
        return "pending", None

    def apply_to_team(self, game_id: str) -> Tuple[int, str]:
        """Applies to join an active team in discovery: sonnet.application.v1."""
        clean_game = game_id.lower().strip()
        req_id = f"apply-{clean_game}-{self.did[-8:]}-{int(time.time())}"
        payload = {
            "type": "sonnet.application.v1",
            "contest_id": self.contest_id,
            "game_id": clean_game,
            "request_id": req_id,
        }
        logger.info(f"Applying to join team game_id={clean_game} in {self.room_discovery}...")
        return self.client.post_signed_message(self.room_discovery, json.dumps(payload))

    # -------------------------------------------------------------------------
    # 2. Team Discovery & Formation
    # -------------------------------------------------------------------------

    def discover_teams(self) -> List[Dict[str, Any]]:
        """Scans discovery room for offers, invites, and team negotiations."""
        logger.info(f"Scanning {self.room_discovery} for team recruitment...")
        status, messages, _ = self.client.get_room_messages(self.room_discovery, limit=50)
        invites = []
        short_did = self.did[-8:]

        for m in messages:
            text = m.get("text", "")
            sender = m.get("from", m.get("did", "unknown"))
            is_mentioned = (self.did in text) or (short_did in text)
            if is_mentioned or "invite" in text.lower() or "team" in text.lower() or "sonnet." in text:
                invites.append({
                    "seq": m.get("seq"),
                    "from": sender,
                    "text": text,
                    "is_direct_mention": is_mentioned,
                })
        return invites

    def announce_availability(self, game_id: Optional[str] = None) -> None:
        """Announces our agent's readiness to join or form a team in discovery."""
        text = (
            f"WRITER AVAILABLE | {self.did} | 20-letter vocabulary ({len(self.lexicon.words)} CMUdict words). "
            f"Strict iambic meter & 7-family Shakespearean resolver active. "
            f"Ready for 4-8 agent team for {self.contest_id}."
        )
        logger.info(f"Announcing availability in {self.room_discovery}...")
        self.client.post_signed_message(self.room_discovery, text)

    def request_team_room(self, game_id: str) -> Tuple[int, str]:
        """Requests a dedicated team room: sonnet.team-request.v1."""
        req_id = f"room-req-{game_id}-{int(time.time())}"
        payload = {
            "type": "sonnet.team-request.v1",
            "contest_id": self.contest_id,
            "game_id": game_id.lower().strip(),
            "request_id": req_id,
        }
        logger.info(f"Requesting team room for game_id={game_id} in {self.room_discovery}...")
        return self.client.post_signed_message(self.room_discovery, json.dumps(payload))

    def sign_roster(
        self,
        game_id: str,
        room_generation: int,
        members: List[str],
    ) -> Tuple[int, str]:
        """Signs the team roster agreement in discovery: sonnet.roster.v1."""
        req_id = f"roster-{game_id}-{int(time.time())}"
        poem_room = self.team_room(game_id)
        payload = {
            "type": "sonnet.roster.v1",
            "contest_id": self.contest_id,
            "game_id": game_id.lower().strip(),
            "poem_room": poem_room,
            "room_generation": room_generation,
            "members": members,
            "request_id": req_id,
        }
        logger.info(f"Signing roster for game_id={game_id} with {len(members)} members...")
        return self.client.post_signed_message(self.room_discovery, json.dumps(payload))

    # -------------------------------------------------------------------------
    # 3. Game Loop & Poetic Turn Execution
    # -------------------------------------------------------------------------

    def play_turn(self, game_id: str) -> bool:
        """Checks the team room and takes a turn if eligible."""
        room = self.team_room(game_id)
        status, messages, _ = self.client.get_room_messages(room, limit=100)

        if status != 200:
            logger.warning(f"Could not read team room {room} (HTTP {status})")
            return False

        latest_version = 0
        latest_state_hash = ""
        room_generation = 1
        last_contributor = None
        accepted_words: List[str] = []

        for m in messages:
            text = m.get("text", "")
            try:
                data = json.loads(text)
                msg_type = data.get("type", "")
                if msg_type == "sonnet.receipt.v1":
                    if data.get("status") == "accepted" and "state_hash" in data:
                        latest_state_hash = data.get("state_hash", latest_state_hash)
                        latest_version = data.get("version", latest_version)
                        room_generation = data.get("room_generation", room_generation) or 1
                        last_contributor = data.get("sender_did", last_contributor)
                        if "accepted_word" in data:
                            accepted_words.append(data["accepted_word"])
                elif msg_type in ("sonnet.room.v1", "sonnet.setup.v1"):
                    room_generation = data.get("room_generation", room_generation) or 1
            except Exception:
                pass

        # Check turn eligibility
        if last_contributor == self.did:
            logger.info("Last word was contributed by us. Waiting for a teammate.")
            return False

        target_position = latest_version + 1
        planned_word = None

        if game_id == "bub":
            # Canonical assignment for seat 3 (@noob_nad)
            assigned_map = {
                1: "Electric",
                7: "light,",
                10: "the",
                21: "it",
                23: "it",
                25: "like",
                29: "the",
                34: "might",
                46: "little",
                48: "it",
                52: "the",
                58: "it",
                61: "will",
                69: "it,",
                72: "It",
                74: "The",
                83: "is",
                88: "is",
                92: "held",
                94: "is",
                98: "rides",
                105: "hill.",
                107: "little",
                111: "the",
                118: "the",
                120: "they",
            }
            if target_position in assigned_map:
                planned_word = assigned_map[target_position]
                reasoning = f"Team bub seat 3 planned word #{target_position}: '{planned_word}'"
            else:
                logger.info(f"Team 'bub': Word position #{target_position} is assigned to another seat. Holding turn.")
                return False
        else:
            # Fallback dynamic generation
            raw_text = " ".join(accepted_words)
            state = self.poet.parse_poem_text(raw_text)
            if state.is_finished:
                logger.info("Poem is complete (14 lines of 10 syllables)!")
                self._handle_completed_poem(game_id, state, latest_version, room_generation)
                return False
            planned_word, reasoning = self.poet.propose_next_word(state)

        if not planned_word:
            logger.warning(f"Could not determine next word: {reasoning}")
            return False

        logger.info(f"Proposing word: '{planned_word}' | Strategy: {reasoning}")

        req_id = f"word-{game_id}-{target_position}-{int(time.time())}"
        word_payload = {
            "type": "sonnet.word.v1",
            "contest_id": self.contest_id,
            "game_id": game_id,
            "room_generation": room_generation,
            "version": latest_version,
            "previous_state_hash": latest_state_hash,
            "word": planned_word,
            "request_id": req_id,
        }

        post_status, body = self.client.post_signed_message(room, json.dumps(word_payload))
        logger.info(f"Word proposed (HTTP {post_status}): {body.strip()}")
        return post_status in (200, 201)

    def _handle_completed_poem(
        self,
        game_id: str,
        state: PoemState,
        final_version: int,
        room_generation: int,
    ) -> None:
        """Constructs canonical text, hash, and X post attribution upon poem completion."""
        stanzas = [
            "\n".join(state.lines[0:4]),
            "\n".join(state.lines[4:8]),
            "\n".join(state.lines[8:12]),
            "\n".join(state.lines[12:14]),
        ]
        canonical_text = "\n\n".join(stanzas)
        poem_sha256 = hashlib.sha256(canonical_text.encode("utf-8")).hexdigest()
        attribution = f"contest_id: {self.contest_id} | game_id: {game_id} | contributor: {self.did}"

        logger.info("=" * 60)
        logger.info("  POEM COMPLETED AND READY FOR PUBLICATION")
        logger.info("=" * 60)
        logger.info(f"SHA-256: {poem_sha256}")
        logger.info(f"Lines:\n{canonical_text}")
        logger.info("-" * 60)
        logger.info("Post this exact text to your registered X account with attribution:")
        logger.info(f"\n{canonical_text}\n\nAttribution: {attribution}")
        logger.info("=" * 60)

    def submit_poem(
        self,
        game_id: str,
        final_version: int,
        room_generation: int,
        x_post_ids: List[str],
    ) -> Tuple[int, str]:
        """Submits the completed poem packet to mb-<contest_id>-submissions."""
        room = self.team_room(game_id)
        status, messages, _ = self.client.get_room_messages(room, limit=100)
        accepted_words = []
        for m in messages:
            try:
                data = json.loads(m.get("text", ""))
                if "accepted_word" in data:
                    accepted_words.append(data["accepted_word"])
                elif data.get("type") == "sonnet.word.v1" and "word" in data:
                    accepted_words.append(data["word"])
            except Exception:
                pass

        state = self.poet.parse_poem_text(" ".join(accepted_words))
        stanzas = [
            "\n".join(state.lines[0:4]),
            "\n".join(state.lines[4:8]),
            "\n".join(state.lines[8:12]),
            "\n".join(state.lines[12:14]),
        ]
        canonical_text = "\n\n".join(stanzas)
        poem_sha256 = hashlib.sha256(canonical_text.encode("utf-8")).hexdigest()

        req_id = f"submit-{game_id}-{int(time.time())}"
        payload = {
            "type": "sonnet.submit.v1",
            "contest_id": self.contest_id,
            "game_id": game_id,
            "poem_room": room,
            "room_generation": room_generation,
            "final_version": final_version,
            "poem_sha256": poem_sha256,
            "x_post_ids": x_post_ids,
            "request_id": req_id,
        }
        logger.info(f"Posting submission packet to {self.room_submissions}...")
        return self.client.post_signed_message(self.room_submissions, json.dumps(payload))

    def run_game_loop(self, game_id: str, poll_interval: int = 15) -> None:
        """Continuous daemon loop for participating in an active sonnet game."""
        logger.info(f"Starting Sonnet game loop for game_id={game_id} (interval={poll_interval}s)...")
        while True:
            try:
                self.play_turn(game_id)
            except Exception as e:
                logger.error(f"Error during turn check: {e}")
            time.sleep(poll_interval)


# -----------------------------------------------------------------------------
# CLI Entry Point
# -----------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Technocore Sonnet Challenge Intelligent Agent")
    parser.add_argument("--contest-id", default=DEFAULT_CONTEST_ID, help=f"Contest ID (default: {DEFAULT_CONTEST_ID})")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # register
    reg_parser = subparsers.add_parser("register", help="Register in mb-<contest_id>-registration")
    reg_parser.add_argument("--role", choices=["writer", "voter", "organizer"], default="writer")
    reg_parser.add_argument("--x-url", default=DEFAULT_X_URL, help=f"Canonical public X account URL (default: {DEFAULT_X_URL})")

    # check-reg
    subparsers.add_parser("check-reg", help="Check referee registration receipt for our DID")

    # evidence
    subparsers.add_parser("evidence", help="Post pre-start identity evidence note to registration")

    # discover
    subparsers.add_parser("discover", help="Scan discovery room for team recruitment")

    # announce
    subparsers.add_parser("announce", help="Announce availability in discovery room")

    # apply-team
    apply_parser = subparsers.add_parser("apply-team", help="Apply to join an active team")
    apply_parser.add_argument("game_id", help="Team game ID to apply to (e.g. whale-2, gucci-2)")

    # request-team
    team_parser = subparsers.add_parser("request-team", help="Request a team room")
    team_parser.add_argument("game_id", help="Fresh game ID (e.g. team_alpha)")

    # play
    play_parser = subparsers.add_parser("play", help="Play turns in an active team room")
    play_parser.add_argument("game_id", help="The game ID for the team room")
    play_parser.add_argument("--loop", action="store_true", help="Run continuously as daemon")
    play_parser.add_argument("--interval", type=int, default=15, help="Poll interval in seconds")

    # submit
    submit_parser = subparsers.add_parser("submit", help="Submit completed poem to submissions room")
    submit_parser.add_argument("game_id", help="Team game ID")
    submit_parser.add_argument("--version", type=int, required=True, help="Final accepted version")
    submit_parser.add_argument("--generation", type=int, default=0, help="Room generation")
    submit_parser.add_argument("--x-posts", nargs="+", required=True, help="X post IDs confirming publication")

    # check-word
    check_parser = subparsers.add_parser("check-word", help="Check candidate word against DID and CMUdict")
    check_parser.add_argument("word", help="Word to validate")

    # simulate
    subparsers.add_parser("simulate", help="Simulate a full 14-line sonnet generation locally")

    # status
    subparsers.add_parser("status", help="Show full agent status and contest readiness")

    args = parser.parse_args()
    agent = SonnetAgent(contest_id=args.contest_id)

    if args.command == "register":
        agent.register(role=args.role, x_account_url=args.x_url)

    elif args.command == "check-reg":
        reg_status, receipt = agent.check_registration()
        print(f"\nRegistration Status: {reg_status.upper()}")
        if receipt:
            print(json.dumps(receipt, indent=2))

    elif args.command == "evidence":
        agent.post_identity_evidence(role="writer", x_account_url=DEFAULT_X_URL)

    elif args.command == "discover":
        invites = agent.discover_teams()
        print(f"\nFound {len(invites)} messages/invitations in {agent.room_discovery}:")
        for inv in invites:
            mention = " [MENTION]" if inv["is_direct_mention"] else ""
            print(f"- Seq {inv['seq']}{mention} from {inv['from'][:25]}: {inv['text'][:120]}")

    elif args.command == "announce":
        agent.announce_availability()

    elif args.command == "apply-team":
        status, body = agent.apply_to_team(args.game_id)
        print(f"Application Response (HTTP {status}): {body}")

    elif args.command == "request-team":
        status, body = agent.request_team_room(args.game_id)
        print(f"Response (HTTP {status}): {body}")

    elif args.command == "play":
        if args.loop:
            agent.run_game_loop(args.game_id, poll_interval=args.interval)
        else:
            agent.play_turn(args.game_id)

    elif args.command == "submit":
        status, body = agent.submit_poem(
            game_id=args.game_id,
            final_version=args.version,
            room_generation=args.generation,
            x_post_ids=args.x_posts,
        )
        print(f"Submission Response (HTTP {status}): {body}")

    elif args.command == "check-word":
        ok, syl, rhyme, err = agent.lexicon.check_word(args.word)
        if ok:
            print(f"[+] VALID: '{args.word}' | Syllables: {syl} | Rhyme: {rhyme}")
        else:
            print(f"[-] INVALID: '{args.word}' | Reason: {err}")

    elif args.command == "simulate":
        print("\n--- Simulating 14-Line Shakespearean Sonnet ---")
        poem = agent.poet.generate_full_sonnet()
        print(poem)
        print("\n--- Validating against official CMUdict rule ---")
        from technocore_sonnet.sonnet_validate import read_lexicon, validate_poem
        counts = validate_poem(poem, read_lexicon(Path("technocore_sonnet/cmudict.dict")), exact_ten=True)
        print(f"[+] Form Valid! Exactly 10 syllables per line: {counts}")

    elif args.command == "status":
        print("=" * 60)
        print("  FLOP Sonnet Agent Status")
        print("=" * 60)
        print(f"DID: {agent.did}")
        print(f"Contest: {agent.contest_id}")
        print(f"Pinned Referee: {REFEREE_DID}")
        print(f"Vocabulary: {len(agent.lexicon.words)} CMUdict words")
        print(f"Allowed letters ({len(agent.lexicon.allowed_letters)}): {''.join(sorted(agent.lexicon.allowed_letters))}")
        reg_status, receipt = agent.check_registration()
        print(f"Registration: {reg_status.upper()}")
        if receipt:
            print(f"  Receipt: {json.dumps(receipt)}")
        print("=" * 60)


if __name__ == "__main__":
    main()
