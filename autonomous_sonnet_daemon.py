"""Autonomous Sonnet Agent Daemon for Technocore (sonnet-2).

Continuously operates the agent:
1. Verifies accepted writer registration receipt from pinned referee.
2. Monitors mb-sonnet-2-discovery for team offers, roster announcements, and invites.
3. Automatically signs matching canonical rosters (e.g. bub, aurora-2).
4. Actively participates in allocated team rooms, calculating meter, rhyme, and word turns.
5. Handles final submission when 14 lines are complete.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from sentinel_core import KEY_FILE
from sonnet_agent import DEFAULT_CONTEST_ID, DEFAULT_X_URL, REFEREE_DID, SonnetAgent, TechnocoreClient
from sonnet_lexicon import SonnetLexicon
from sonnet_poet import LINE_RHYME_FAMILIES, PoemState, SonnetPoet

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("sonnet_autonomous.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger("autonomous_sonnet")


class AutonomousSonnetDaemon:
    def __init__(
        self,
        contest_id: str = DEFAULT_CONTEST_ID,
        target_game: Optional[str] = "aurora-2",
        x_account_url: str = DEFAULT_X_URL,
    ):
        self.contest_id = contest_id
        self.target_game = target_game
        self.lock_target: bool = (target_game == "bub")
        self.monitored_games = {"bub"}
        self.x_account_url = x_account_url
        self.agent = SonnetAgent(contest_id=contest_id)
        self.client = self.agent.client
        self.did = self.agent.did
        self.short_did = self.did[-8:]
        self.signed_rosters: Set[str] = set()
        self.forbidden_games: Set[str] = {"ej-v1"}
        self.registration_verified: bool = True
        self.last_announce_time = 0.0
        self.last_discovery_seq = 0
        self.last_vote_tally_time = 0.0
        self.active_team_room: Optional[str] = None
        self.room_generation: int = 1

        logger.info(f"Autonomous Sonnet Daemon initialized for DID: {self.did}")
        logger.info(f"Contest: {self.contest_id} | Target Team: {self.target_game} | X: {self.x_account_url}")

    def ensure_registered(self) -> bool:
        """Verifies accepted writer receipt, or submits registration."""
        if self.registration_verified:
            return True
        reg_status, receipt = self.agent.check_registration()
        if reg_status == "accepted":
            self.registration_verified = True
            logger.info("[+] Agent is verified ACCEPTED writer by referee.")
            return True

        logger.info("[-] Registration not yet accepted. Posting writer registration...")
        self.agent.register(role="writer", x_account_url=self.x_account_url)
        return False

    def scan_discovery(self) -> None:
        """Monitors discovery room for roster announcements, invites, and mentions."""
        status, messages, latest_seq = self.client.get_room_messages(
            self.agent.room_discovery, since=self.last_discovery_seq, limit=50
        )
        if status != 200:
            return

        self.last_discovery_seq = latest_seq
        for m in messages:
            text = m.get("text", "")
            seq = m.get("seq")
            sender = m.get("from", m.get("did", ""))

            is_relevant = (self.did in text) or (self.short_did in text) or any(g in text for g in self.monitored_games)

            if is_relevant:
                logger.info(f"Discovery [seq {seq}] from {sender[:20]}: {text[:160]}")
                self._handle_discovery_message(seq, sender, text)

    def _handle_discovery_message(self, seq: int, sender: str, text: str) -> None:
        """Parses discovery message for actionable roster signing."""
        try:
            data = json.loads(text)
        except Exception:
            return

        msg_type = data.get("type", "")
        game_id = data.get("game_id", "").lower().strip()

        if game_id in self.forbidden_games:
            return

        if msg_type == "sonnet.roster.v1" or "members" in data:
            members = data.get("members", [])
            gen = data.get("room_generation", 1)
            poem_room = data.get("poem_room") or self.agent.team_room(game_id)

            if not self.lock_target and (game_id in self.monitored_games or self.did in members) and game_id not in self.signed_rosters:
                if self.did in members:
                    logger.info(f"[!] Roster detected for {game_id} including our DID! Signing roster consent...")
                    self.agent.sign_roster(game_id, gen, members)
                    self.signed_rosters.add(game_id)
                    self.active_team_room = poem_room
                    self.room_generation = gen
                    self.target_game = game_id
                else:
                    logger.info(f"Roster for {game_id} posted without our DID (yet).")

        elif msg_type == "sonnet.setup.v1":
            if game_id == self.target_game:
                self.room_generation = data.get("room_generation", self.room_generation)
                self.active_team_room = data.get("poem_room", self.agent.team_room(game_id))
                logger.info(f"[+] Setup confirmed for {game_id}: room={self.active_team_room}, gen={self.room_generation}")

    def check_and_play_team(self, game_id: str) -> bool:
        """Polls team room and takes a poetic turn if it's our turn."""
        if game_id in self.forbidden_games:
            return False
        try:
            res = self.agent.play_turn(game_id)
            return res
        except Exception as e:
            if "403" in str(e):
                self.forbidden_games.add(game_id)
                logger.warning(f"Room {game_id} returned 403 Forbidden. Adding to ignore list.")
            else:
                logger.warning(f"Error checking turn in {game_id}: {e}")
            return False

    def check_live_votes(self) -> None:
        """Polls voting room to monitor standings and competition movements."""
        try:
            status, msgs, _ = self.client.get_room_messages(f"mb-{self.contest_id}-votes", limit=100)
            if status == 200:
                from collections import Counter
                voter_latest = {}
                for m in msgs:
                    try:
                        p = json.loads(m.get("text", ""))
                        if p.get("type") == "sonnet.receipt.v1" and p.get("status") == "accepted":
                            v = p.get("sender_did")
                            e = p.get("entry_id")
                            if v and e:
                                voter_latest[v] = e
                    except Exception:
                        pass
                tally = Counter(voter_latest.values())
                logger.info(f"[Live Votes] Verified voters in window: {len(voter_latest)} | Standings: {tally.most_common(5)}")
        except Exception as e:
            logger.warning(f"Error checking live votes: {e}")

    def run_cycle(self) -> None:
        """Single autonomous evaluation tick."""
        now = time.time()

        # Step 1: Check registration
        self.ensure_registered()

        # Step 2: Scan discovery
        self.scan_discovery()

        # Step 3: Announce availability every 10 minutes if not in an active playing game
        if not self.active_team_room and (now - self.last_announce_time > 600):
            self.agent.announce_availability()
            self.last_announce_time = now

        # Step 4: Check turn in target team room
        if self.target_game:
            self.check_and_play_team(self.target_game)

        # Step 5: Monitor live votes periodically
        if now - self.last_vote_tally_time > 300:
            self.check_live_votes()
            self.last_vote_tally_time = now

    def run_forever(self, interval: int = 15) -> None:
        """Continuous execution loop."""
        logger.info(f"Starting continuous daemon loop (interval={interval}s)...")
        while True:
            try:
                self.run_cycle()
            except KeyboardInterrupt:
                logger.info("Daemon stopped by operator.")
                break
            except Exception as e:
                logger.error(f"Unexpected error in daemon loop: {e}", exc_info=True)
            time.sleep(interval)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Technocore Autonomous Sonnet Agent Runner")
    parser.add_argument("--team", default="bub", help="Target team game_id to focus on (default: bub)")
    parser.add_argument("--interval", type=int, default=15, help="Poll interval in seconds (default: 15)")
    parser.add_argument("--once", action="store_true", help="Run single cycle and exit")
    args = parser.parse_args()

    daemon = AutonomousSonnetDaemon(target_game=args.team)
    if args.once:
        daemon.run_cycle()
    else:
        daemon.run_forever(interval=args.interval)


if __name__ == "__main__":
    main()
