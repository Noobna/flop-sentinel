"""Comprehensive Unit & Stress Test Suite for Feature 1 (sentinel_core.py).
"""

import concurrent.futures
import json
import os
import sys
import threading
import time
import unittest

from sentinel_core import (
    b58_encode,
    b58_decode,
    is_valid_did,
    extract_public_key_from_did,
    canonical_sweep,
    get_next_nonce,
    seed_room_nonce,
    save_json_atomic,
    load_json_safe,
    load_or_create_identity,
    sign_message,
    verify_signed_message,
    INVISIBLE_CATEGORIES,
)


class TestSentinelCore(unittest.TestCase):

    def test_01_base58_roundtrip(self):
        """Test Base58btc encoding and decoding with zero-padding edge cases."""
        test_payloads = [
            b"",
            b"\x00",
            b"\x00\x00\x01\x02\x03",
            b"\xed\x01" + (b"\xaa" * 32),
            b"Hello Technocore Flop Network",
            os.urandom(34),
        ]
        for p in test_payloads:
            encoded = b58_encode(p)
            decoded = b58_decode(encoded)
            self.assertEqual(p, decoded, f"Failed roundtrip for {p!r}")

    def test_02_did_validation_and_parsing(self):
        """Test strict DID validation and public key reconstruction."""
        priv, did = load_or_create_identity("test_identity.json")
        try:
            self.assertTrue(is_valid_did(did))
            self.assertTrue(did.startswith("did:key:z6Mk"))
            self.assertEqual(len(did), 56)  # 'did:key:' (8) + 'z' (1) + 47 base58btc chars = 56

            # Extract public key and verify
            pub_key = extract_public_key_from_did(did)
            self.assertIsNotNone(pub_key)

            # Test invalid DIDs
            self.assertFalse(is_valid_did("did:key:z123"))
            self.assertFalse(is_valid_did("~some_nickname"))
            self.assertFalse(is_valid_did("did:key:z6Mk" + ("1" * 40)))  # too short
        finally:
            if os.path.exists("test_identity.json"):
                os.remove("test_identity.json")

    def test_03_unicode_canonical_sweep(self):
        """Test strict 6-category Unicode sweep matching Technocore server."""
        # 1. Normal text
        self.assertEqual(canonical_sweep("  Hello World  "), "Hello World")

        # 2. Invisible chars: Cc (newlines \n, \t), Cf (zero-width space \u200b, soft hyphen \u00ad)
        dirty = "Hello\n\tWorld\u200b!\u00ad\r"
        cleaned = canonical_sweep(dirty)
        self.assertEqual(cleaned, "Hello  World !")

        # 3. Empty after sweep must raise ValueError
        with self.assertRaises(ValueError):
            canonical_sweep("\n\t  \u200b\u200c\r\n  ")

        # 4. Overflow length
        with self.assertRaises(ValueError):
            canonical_sweep("A" * 4097, limit=4096)

    def test_04_per_room_monotonic_nonces_concurrent(self):
        """Stress-test per-room nonce generation under high concurrent thread load."""
        rooms = ["lobby", "technocore", "meta"]
        nonces_by_room = {r: [] for r in rooms}
        lock = threading.Lock()

        def worker(room: str, count: int):
            local_nonces = []
            for _ in range(count):
                n = int(get_next_nonce(room))
                local_nonces.append(n)
            with lock:
                nonces_by_room[room].extend(local_nonces)

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
            futures = []
            for r in rooms:
                for _ in range(10):
                    futures.append(executor.submit(worker, r, 50))
            concurrent.futures.wait(futures)

        # Verify uniqueness and monotonic ordering per room
        for r in rooms:
            collected = nonces_by_room[r]
            self.assertEqual(len(collected), 500)
            self.assertEqual(len(set(collected)), 500, f"Found nonce collisions in room {r}")
            # Ensure sort order strictly preserved
            sorted_collected = sorted(collected)
            self.assertEqual(collected, sorted_collected, f"Nonces in {r} were not strictly monotonic")

    def test_05_windows_safe_atomic_io(self):
        """Test atomic file saving, recovery, and .bak preservation."""
        test_file = "test_state_atomic.json"
        bak_file = "test_state_atomic.json.bak"
        try:
            # 1. Initial write
            initial_data = {"version": 1, "heartbeats": 100}
            self.assertTrue(save_json_atomic(test_file, initial_data))
            loaded = load_json_safe(test_file)
            self.assertEqual(loaded, initial_data)

            # 2. Update with backup creation
            updated_data = {"version": 2, "heartbeats": 101}
            self.assertTrue(save_json_atomic(test_file, updated_data))
            self.assertEqual(load_json_safe(test_file), updated_data)
            self.assertTrue(os.path.exists(bak_file))
            self.assertEqual(load_json_safe(bak_file), initial_data)

            # 3. Simulate file corruption and verify recovery from .bak
            with open(test_file, "w", encoding="utf-8") as f:
                f.write("{corrupt-json-truncated...")
            recovered = load_json_safe(test_file)
            self.assertEqual(recovered, initial_data, "Failed to recover from .bak after corruption")

        finally:
            for p in [test_file, bak_file]:
                if os.path.exists(p):
                    os.remove(p)

    def test_06_signing_and_cryptographic_verification(self):
        """Test full Ed25519 message signing, base64url format, and offline signature verification."""
        priv, did = load_or_create_identity("test_signer_id.json")
        try:
            room = "lobby"
            nonce = get_next_nonce(room)
            raw_text = "  Autonomous node check-in \u200b #123  \n"
            
            swept_text, sig = sign_message(priv, room, nonce, raw_text)
            self.assertEqual(swept_text, "Autonomous node check-in   #123")
            self.assertEqual(len(sig), 86)  # Exactly 86 unpadded base64url chars
            self.assertFalse("=" in sig)

            # Offline verification with DID key
            is_valid = verify_signed_message(did, room, nonce, raw_text, sig)
            self.assertTrue(is_valid, "Valid signature failed verification")

            # Tampered message check
            tampered = verify_signed_message(did, room, nonce, "Tampered text", sig)
            self.assertFalse(tampered, "Tampered text was falsely verified")

            # Wrong room check
            wrong_room = verify_signed_message(did, "meta", nonce, raw_text, sig)
            self.assertFalse(wrong_room, "Wrong room was falsely verified")

            # Wrong nonce check
            wrong_nonce = verify_signed_message(did, room, "999999999999", raw_text, sig)
            self.assertFalse(wrong_nonce, "Wrong nonce was falsely verified")

        finally:
            if os.path.exists("test_signer_id.json"):
                os.remove("test_signer_id.json")


if __name__ == "__main__":
    unittest.main(verbosity=2)
