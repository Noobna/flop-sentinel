"""Unit & Integration Tests for Technocore Lock Protocol (tclk.py)."""

import time
import unittest
from tclk import (
    TCLK_PREFIX,
    TCLK_DOMAIN,
    canonical_json,
    offer_id,
    contract_id,
    generate_hash_lock,
    verify_hash_secret,
    derive_deal_room,
    make_offer,
    make_accept,
    make_lock,
    make_reveal,
    make_refund,
    make_cancel,
    encode_frame,
    decode_frame,
    try_decode_frame,
    open_contract,
    apply_frame,
    PaperRail,
)


class TestTclkProtocol(unittest.TestCase):
    def setUp(self):
        self.payer_did = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBpGyKinSuC4aPr4j"
        self.payee_did = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"

    def test_01_canonical_json_and_ascii_escapes(self):
        """Test canonical JSON key sorting and non-ASCII character escaping."""
        raw = {"z_key": "world", "a_key": "hello", "unicode": "Café", "none_val": None}
        canon = canonical_json(raw)
        # Check that none_val was dropped
        self.assertNotIn("none_val", canon)
        # Check key order: a_key before unicode before z_key
        self.assertTrue(canon.index("a_key") < canon.index("unicode") < canon.index("z_key"))
        # Check ASCII escaping for 'é' -> '\u00e9'
        self.assertIn(r"\u00e9", canon)
        self.assertNotIn("Café", canon)

    def test_02_hash_lock_generation_and_verification(self):
        """Test 32-byte hash lock minting and preimage verification."""
        preimage, statement = generate_hash_lock()
        self.assertTrue(preimage.startswith("0x") and len(preimage) == 66)
        self.assertTrue(statement.startswith("0x") and len(statement) == 66)
        self.assertTrue(verify_hash_secret(preimage, statement))
        
        # Test bad secret
        bad_preimage = "0x" + "00" * 32
        self.assertFalse(verify_hash_secret(bad_preimage, statement))

    def test_03_offer_and_contract_id_determinism(self):
        """Test deterministic Offer ID and Contract ID hashing."""
        now = int(time.time() * 1000)
        offer = make_offer(
            from_did=self.payer_did,
            role="payer",
            amount="50000000",
            asset="FLOP",
            lock="hash",
            rails=["paper-htlc"],
            claim_by_ms=now + 3600000,
            refund_after_ms=now + 7200000,
            expires_ms=now + 1800000,
            nonce="1122334455667788",
        )
        self.assertTrue(offer["id"].startswith("0x"))
        self.assertEqual(len(offer["id"]), 66)

        preimage, statement = generate_hash_lock()
        accept = make_accept(
            from_did=self.payee_did,
            offer=offer,
            statement=statement,
            nonce="8877665544332211",
        )
        self.assertTrue(accept["contract"].startswith("0x"))
        self.assertEqual(len(accept["contract"]), 66)

    def test_04_frame_encoding_and_decoding_wire(self):
        """Test wire format serialization (tclk1 <json>) and fail-closed parsing."""
        offer = make_offer(
            from_did=self.payer_did,
            role="payer",
            amount="100000",
            asset="USDC",
            lock="hash",
        )
        line = encode_frame(offer)
        self.assertTrue(line.startswith(TCLK_PREFIX))
        
        decoded = decode_frame(line)
        self.assertEqual(decoded["id"], offer["id"])
        self.assertEqual(decoded["amount"], "100000")

        # Malformed frame fails closed
        self.assertIsNone(try_decode_frame("not_a_tclk_frame"))
        self.assertIsNone(try_decode_frame("tclk1 {broken_json}"))

    def test_05_deal_room_derivation(self):
        """Test deterministic deal room derivation (mb-p-tclk-<16hex>)."""
        cid = "0x3c9e1a05d92f7b6c1e4a8d0f3b6c9e2a5d8f1b4c7e0a3d6f97a1ec7e2d9b6a4"
        room = derive_deal_room(cid)
        self.assertEqual(room, "mb-p-tclk-3c9e1a05d92f7b6c")
        self.assertTrue(room.startswith("mb-p-tclk-"))

    def test_06_full_happy_path_state_machine(self):
        """Test complete deal lifecycle: proposed -> accepted -> locked -> claimed."""
        now = int(time.time() * 1000)
        # 1. Offer
        offer = make_offer(
            from_did=self.payer_did,
            role="payer",
            amount="250000",
            asset="FLOP",
            lock="hash",
            rails=["paper-htlc"],
            claim_by_ms=now + 3600000,
            refund_after_ms=now + 7200000,
            expires_ms=now + 1800000,
        )
        state = open_contract(offer)
        self.assertEqual(state.status, "proposed")
        self.assertEqual(state.payer_did, self.payer_did)

        # 2. Accept
        preimage, statement = generate_hash_lock()
        accept = make_accept(
            from_did=self.payee_did,
            offer=offer,
            statement=statement,
        )
        state, ok, reason = apply_frame(state, accept, now_ms=now)
        self.assertTrue(ok, reason)
        self.assertEqual(state.status, "accepted")
        self.assertEqual(state.payee_did, self.payee_did)
        self.assertEqual(state.statement, statement)

        # 3. Lock
        rail = PaperRail("paper-htlc")
        rail_ref = rail.lock(state)
        lock_frame = make_lock(
            from_did=self.payer_did,
            contract=state.contract,
            rail="paper-htlc",
            ref=rail_ref,
        )
        state, ok, reason = apply_frame(state, lock_frame, now_ms=now)
        self.assertTrue(ok, reason)
        self.assertEqual(state.status, "locked")
        self.assertEqual(state.rail_ref, rail_ref)

        # 4. Reveal & Settle
        reveal_frame = make_reveal(
            from_did=self.payee_did,
            contract=state.contract,
            secret=preimage,
        )
        state, ok, reason = apply_frame(state, reveal_frame, now_ms=now)
        self.assertTrue(ok, reason)
        self.assertEqual(state.status, "claimed")
        self.assertEqual(state.secret, preimage)

        # Settle on rail
        settle_ok = rail.claim(state.contract, preimage)
        self.assertTrue(settle_ok)

    def test_07_refund_on_timeout(self):
        """Test refund flow when payee fails to reveal before refundAfterMs."""
        now = int(time.time() * 1000)
        offer = make_offer(
            from_did=self.payer_did,
            role="payer",
            amount="1000",
            asset="FLOP",
            lock="hash",
            rails=["paper-htlc"],
            claim_by_ms=now + 1000,
            refund_after_ms=now + 2000,
            expires_ms=now + 500,
        )
        state = open_contract(offer)
        preimage, statement = generate_hash_lock()
        accept = make_accept(from_did=self.payee_did, offer=offer, statement=statement)
        state, ok, _ = apply_frame(state, accept, now_ms=now)
        self.assertTrue(ok)

        rail = PaperRail()
        ref = rail.lock(state)
        lock_frame = make_lock(from_did=self.payer_did, contract=state.contract, rail="paper-htlc", ref=ref)
        state, ok, _ = apply_frame(state, lock_frame, now_ms=now)
        self.assertTrue(ok)

        # Attempt refund before timelock expires -> rejected
        refund_frame = make_refund(from_did=self.payer_did, contract=state.contract)
        _, premature_ok, reason = apply_frame(state, refund_frame, now_ms=now + 1500)
        self.assertFalse(premature_ok)
        self.assertIn("Timelock not expired", reason)

        # Attempt refund after timelock expires -> accepted
        state, refund_ok, _ = apply_frame(state, refund_frame, now_ms=now + 2500)
        self.assertTrue(refund_ok)
        self.assertEqual(state.status, "refunded")
        self.assertTrue(rail.refund(state.contract))

    def test_08_cancellation_flow(self):
        """Test deal cancellation before locking."""
        offer = make_offer(from_did=self.payer_did, role="payer", amount="500", asset="FLOP")
        state = open_contract(offer)
        cancel_frame = make_cancel(from_did=self.payer_did, contract=offer["id"], reason="No longer needed")
        state, ok, _ = apply_frame(state, cancel_frame)
        self.assertTrue(ok)
        self.assertEqual(state.status, "cancelled")


if __name__ == "__main__":
    unittest.main(verbosity=2)
