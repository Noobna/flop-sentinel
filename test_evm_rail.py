"""Unit tests for EVM Settlement Rail (evm_rail.py)."""

import time
import unittest
from evm_rail import EvmRail
from tclk import generate_hash_lock, make_accept, make_offer, open_contract, apply_frame


class TestEvmRail(unittest.TestCase):
    def setUp(self):
        self.payer_did = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBpGyKinSuC4aPr4j"
        self.payee_did = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
        self.rail = EvmRail(rail_id="evm-htlc")

    def test_01_lock_and_claim_lifecycle(self):
        """Test happy-path escrow locking and claim via SHA-256 secret."""
        now_ms = int(time.time() * 1000)
        offer = make_offer(
            from_did=self.payer_did,
            role="payer",
            amount="1000000",
            asset="USDC",
            lock="hash",
            rails=["evm-htlc"],
            claim_by_ms=now_ms + 10000,
            refund_after_ms=now_ms + 20000,
        )
        state = open_contract(offer)
        secret, statement = generate_hash_lock()
        accept = make_accept(from_did=self.payee_did, offer=offer, statement=statement)
        state, ok, _ = apply_frame(state, accept, now_ms=now_ms)
        self.assertTrue(ok)

        # Lock funds on EVM rail
        tx_hash = self.rail.lock(state)
        self.assertTrue(tx_hash.startswith("0x") and len(tx_hash) == 66)

        escrow = self.rail.get_escrow(state.contract)
        self.assertIsNotNone(escrow)
        self.assertEqual(escrow["status"], "Locked")
        self.assertEqual(escrow["amount"], "1000000")

        # Claim with correct secret
        claim_ok = self.rail.claim(state.contract, secret)
        self.assertTrue(claim_ok)

        updated_escrow = self.rail.get_escrow(state.contract)
        self.assertEqual(updated_escrow["status"], "Claimed")
        self.assertEqual(updated_escrow["secret"], secret)

    def test_02_claim_with_invalid_secret_fails(self):
        """Test claim rejection with wrong secret."""
        now_ms = int(time.time() * 1000)
        offer = make_offer(from_did=self.payer_did, role="payer", amount="500", asset="FLOP", rails=["evm-htlc"])
        state = open_contract(offer)
        _, statement = generate_hash_lock()
        accept = make_accept(from_did=self.payee_did, offer=offer, statement=statement)
        state, ok, _ = apply_frame(state, accept, now_ms=now_ms)
        self.assertTrue(ok)

        self.rail.lock(state)
        bad_secret = "0x" + "11" * 32
        self.assertFalse(self.rail.claim(state.contract, bad_secret))

    def test_03_refund_timelock_enforcement(self):
        """Test that refund is blocked before refundAfter and succeeds after."""
        now_ms = int(time.time() * 1000)
        refund_after_ms = now_ms + 5000
        refund_after_s = int(refund_after_ms / 1000)

        offer = make_offer(
            from_did=self.payer_did,
            role="payer",
            amount="250",
            asset="ETH",
            rails=["evm-htlc"],
            claim_by_ms=now_ms + 2000,
            refund_after_ms=refund_after_ms,
        )
        state = open_contract(offer)
        _, statement = generate_hash_lock()
        accept = make_accept(from_did=self.payee_did, offer=offer, statement=statement)
        state, ok, _ = apply_frame(state, accept, now_ms=now_ms)
        self.assertTrue(ok)

        self.rail.lock(state)

        # Attempt refund before timelock expires
        self.assertFalse(self.rail.refund(state.contract, current_time_s=refund_after_s - 10))

        # Attempt refund after timelock expires
        self.assertTrue(self.rail.refund(state.contract, current_time_s=refund_after_s + 1))
        self.assertEqual(self.rail.get_escrow(state.contract)["status"], "Refunded")


if __name__ == "__main__":
    unittest.main(verbosity=2)
