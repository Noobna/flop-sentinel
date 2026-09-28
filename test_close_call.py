"""Comprehensive Test Suite for Close Call Challenge Engine (close-1).

Tests:
1. Amount parsing & formatting (2 decimal places, positive, non-zero).
2. Canonical terms validation, serialization, and determinism.
3. Ed25519 maker terms signing and cryptographic verification.
4. Ed25519 taker accept signing and cryptographic verification.
5. Tampering resilience: altered terms or signatures fail verification.
6. Clawback fee calculations matching canonical rules.
7. Pre-flight rule checks for all void conditions:
   - shape, taker, expired, locked, limits, funds.
8. Registration payload generation (owner and room).
9. Local Fold accounting and zero-sum invariant.
"""

import json
import unittest
from decimal import Decimal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from close_call import (
    CONTEST_ID,
    LOCK_SWEEP,
    AccountState,
    LocalFold,
    TradeTerms,
    build_owner_message,
    build_room_message,
    build_trade_envelope,
    compute_side_fees,
    format_amount,
    parse_amount,
    preflight_check,
    sign_maker_terms,
    sign_taker_accept,
    verify_maker_signature,
    verify_taker_signature,
)
from sentinel_core import b58_encode, extract_public_key_from_did


def make_test_key():
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    did = "did:key:z" + b58_encode(b"\xed\x01" + pub)
    return priv, did


class TestCloseCallEngine(unittest.TestCase):
    def setUp(self):
        import close_call
        self.orig_state_file = close_call.CLOSE_CALL_STATE_FILE
        self.test_state_file = "test_close_call_state_tmp.json"
        close_call.CLOSE_CALL_STATE_FILE = self.test_state_file
        self.maker_priv, self.maker_did = make_test_key()
        self.taker_priv, self.taker_did = make_test_key()
        self.other_priv, self.other_did = make_test_key()

    def tearDown(self):
        import close_call
        import os
        close_call.CLOSE_CALL_STATE_FILE = self.orig_state_file
        if os.path.exists(self.test_state_file):
            try:
                os.remove(self.test_state_file)
            except Exception:
                pass

    def test_01_amount_parsing_and_formatting(self):
        """Test amount parsing with 2-decimal constraint and formatting."""
        self.assertEqual(parse_amount("100.50"), Decimal("100.50"))
        self.assertEqual(parse_amount("0.10"), Decimal("0.10"))
        self.assertEqual(parse_amount("1"), Decimal("1"))
        self.assertIsNone(parse_amount("0.00"))
        self.assertIsNone(parse_amount("-5.00"))
        self.assertIsNone(parse_amount("10.123"))  # 3 decimals disallowed
        self.assertIsNone(parse_amount("abc"))

        self.assertEqual(format_amount(Decimal("100.50")), "100.50")
        self.assertEqual(format_amount("225.00"), "225")

    def test_02_canonical_terms_and_serialization(self):
        """Test strict validation and canonical JSON sorting."""
        terms = TradeTerms(
            id="trade_123",
            maker=self.maker_did,
            px="225.50",
            qty="2.00",
            side="buy",
            taker="any",
            until=100,
        )
        valid, err = terms.validate()
        self.assertTrue(valid, f"Expected valid, got: {err}")

        # Check canonical JSON: sorted keys and no whitespace
        c_json = terms.canonical_json()
        expected_keys = ["id", "maker", "px", "qty", "side", "taker", "until"]
        parsed = json.loads(c_json)
        self.assertEqual(list(parsed.keys()), expected_keys)
        self.assertNotIn(" ", c_json)

    def test_03_maker_terms_signing_and_verification(self):
        """Test maker terms Ed25519 signing and verification."""
        terms = TradeTerms(
            id="bid_001",
            maker=self.maker_did,
            px="220.00",
            qty="1.50",
            side="buy",
            taker="any",
            until=50,
        )
        sig = sign_maker_terms(self.maker_priv, terms)
        self.assertEqual(len(sig), 86)  # Base64url unpadded length for 64-byte Ed25519 sig

        # Verification must pass with correct maker DID
        self.assertTrue(verify_maker_signature(self.maker_did, terms, sig))

        # Verification must fail with wrong DID
        self.assertFalse(verify_maker_signature(self.other_did, terms, sig))

        # Verification must fail if terms are tampered (e.g. price altered)
        tampered = TradeTerms(
            id="bid_001",
            maker=self.maker_did,
            px="220.01",  # 1 cent difference
            qty="1.50",
            side="buy",
            taker="any",
            until=50,
        )
        self.assertFalse(verify_maker_signature(self.maker_did, tampered, sig))

    def test_04_taker_accept_signing_and_verification(self):
        """Test taker accept Ed25519 signing and verification."""
        terms = TradeTerms(
            id="ask_002",
            maker=self.maker_did,
            px="230.00",
            qty="5.00",
            side="sell",
            taker="any",
            until=75,
        )
        taker_sig = sign_taker_accept(self.taker_priv, terms, self.taker_did)
        self.assertEqual(len(taker_sig), 86)

        # Verification succeeds
        self.assertTrue(verify_taker_signature(self.taker_did, terms, taker_sig))

        # Fails if verified against a different taker
        self.assertFalse(verify_taker_signature(self.other_did, terms, taker_sig))

        # Fails if terms tampered
        tampered = TradeTerms(
            id="ask_002",
            maker=self.maker_did,
            px="230.00",
            qty="4.99",
            side="sell",
            taker="any",
            until=75,
        )
        self.assertFalse(verify_taker_signature(self.taker_did, tampered, taker_sig))

    def test_05_clawback_fee_calculations(self):
        """Test exact clawback fee formula matching the contest rules."""
        qty = Decimal("10")
        px = Decimal("100.00")
        close_px = Decimal("100.00")

        # 1. Trade at the close: both pay 1% flat fee
        mk_fee, tk_fee = compute_side_fees(side=1, qty=qty, px=px, close_px=close_px)
        self.assertEqual(mk_fee, Decimal("10.0000"))
        self.assertEqual(tk_fee, Decimal("10.0000"))

        # 2. Buyer bought at discount (px=96, close=100): buyer pays clawback of 4.00 * 10 = 40.00
        # Seller pays 1% of notional = 0.01 * 10 * 96 = 9.60
        mk_fee, tk_fee = compute_side_fees(side=1, qty=qty, px=Decimal("96.00"), close_px=close_px)
        self.assertEqual(mk_fee, Decimal("40.00"))   # Maker was buyer
        self.assertEqual(tk_fee, Decimal("9.6000")) # Taker was seller

        # 3. Seller sold at premium (px=105, close=100): seller pays clawback of 5.00 * 10 = 50.00
        # Buyer pays 1% of notional = 0.01 * 10 * 105 = 10.50
        mk_fee, tk_fee = compute_side_fees(side=-1, qty=qty, px=Decimal("105.00"), close_px=close_px)
        self.assertEqual(mk_fee, Decimal("50.00"))   # Maker was seller
        self.assertEqual(tk_fee, Decimal("10.5000")) # Taker was buyer

    def test_06_preflight_checks_all_void_reasons(self):
        """Test pre-flight risk analyzer detects all void trade conditions."""
        ref_px = Decimal("200.00")
        curr_sweep = 10

        # Valid trade
        good_terms = TradeTerms(
            id="trade_ok",
            maker=self.maker_did,
            px="200.00",
            qty="2.00",
            side="buy",
            taker="any",
            until=20,
        )
        valid, reason, _ = preflight_check(
            good_terms,
            taker_did=self.taker_did,
            current_sweep=curr_sweep,
            ref_px=ref_px,
        )
        self.assertTrue(valid)
        self.assertIsNone(reason)

        # 1. Shape: quantity below 0.1
        bad_qty = TradeTerms("bad_q", self.maker_did, "200.00", "0.05", "buy", "any", 20)
        valid, reason, _ = preflight_check(bad_qty, self.taker_did, curr_sweep, ref_px)
        self.assertFalse(valid)
        self.assertEqual(reason, "shape")

        # 2. Taker mismatch
        named_taker = TradeTerms("bad_tk", self.maker_did, "200.00", "1.00", "buy", taker=self.other_did, until=20)
        valid, reason, _ = preflight_check(named_taker, self.taker_did, curr_sweep, ref_px)
        self.assertFalse(valid)
        self.assertEqual(reason, "taker")

        # 3. Expired
        expired = TradeTerms("exp", self.maker_did, "200.00", "1.00", "buy", "any", until=5)
        valid, reason, _ = preflight_check(expired, self.taker_did, current_sweep=10, ref_px=ref_px)
        self.assertFalse(valid)
        self.assertEqual(reason, "expired")

        # 4. Limits: price outside 5% band (ref=200, 5% is 190..210)
        out_high = TradeTerms("out_h", self.maker_did, "210.01", "1.00", "buy", "any", until=20)
        valid, reason, _ = preflight_check(out_high, self.taker_did, curr_sweep, ref_px)
        self.assertFalse(valid)
        self.assertEqual(reason, "limits")

        out_low = TradeTerms("out_l", self.maker_did, "189.99", "1.00", "buy", "any", until=20)
        valid, reason, _ = preflight_check(out_low, self.taker_did, curr_sweep, ref_px)
        self.assertFalse(valid)
        self.assertEqual(reason, "limits")

        # 5. Funds: maker has insufficient cash
        poor_maker = AccountState(self.maker_did, cash=Decimal("10.00"))
        rich_taker = AccountState(self.taker_did, cash=Decimal("10000.00"))
        big_trade = TradeTerms("big", self.maker_did, "200.00", "1.00", "buy", "any", until=20)
        valid, reason, _ = preflight_check(
            big_trade,
            taker_did=self.taker_did,
            current_sweep=curr_sweep,
            ref_px=ref_px,
            maker_account=poor_maker,
            taker_account=rich_taker,
        )
        self.assertFalse(valid)
        self.assertEqual(reason, "funds")

    def test_07_registration_payloads(self):
        """Test owner and room registration message generation."""
        owner_msg = build_owner_message(self.maker_did)
        self.assertEqual(owner_msg["t"], "owner")
        self.assertEqual(owner_msg["season"], CONTEST_ID)
        self.assertEqual(owner_msg["key"], self.maker_did)

        room_msg = build_room_message("nvda-desk")
        self.assertEqual(room_msg["t"], "room")
        self.assertEqual(room_msg["season"], CONTEST_ID)
        self.assertEqual(room_msg["room"], "nvda-desk")

    def test_08_local_fold_simulation(self):
        """Test local Fold simulation of trade execution and account state updates."""
        fold = LocalFold(mint=Decimal("10000"))
        fold.seed("200.00")

        trade_dict = {
            "id": "t1",
            "maker": self.maker_did,
            "side": "buy",
            "qty": "2.00",
            "px": "200.00",
            "taker": "any",
            "until": 10,
            "countersigner": self.taker_did,
        }

        sweep_res = fold.execute_sweep(
            n=1,
            ref_str="200.00",
            close_str="200.00",
            owners=[self.maker_did, self.taker_did],
            trades=[trade_dict],
        )

        self.assertEqual(sweep_res["sweep"], 1)
        self.assertEqual(len(sweep_res["minted"]), 2)
        self.assertEqual(sweep_res["trades"][0]["outcome"], "settled")

        # Check balances: 2 contracts @ 200 = 400 collateral + 1% fee (4) = 404 deducted
        maker_acct = fold.accounts[self.maker_did]
        taker_acct = fold.accounts[self.taker_did]

        self.assertEqual(maker_acct.position, Decimal("2.00"))
        self.assertEqual(maker_acct.cash, Decimal("9596.00"))  # 10000 - 400 - 4
        self.assertEqual(taker_acct.position, Decimal("-2.00"))
        self.assertEqual(taker_acct.cash, Decimal("9596.00"))  # 10000 - 400 - 4

    def test_09_preflight_shape_invalid_dids_and_missing_maker(self):
        """Test preflight_check rejects invalid DIDs, missing maker, and non-dict terms."""
        ref_px = Decimal("200.00")
        
        # 1. Non-dict terms
        valid, reason, _ = preflight_check("not-a-dict", self.taker_did, 1, ref_px)
        self.assertFalse(valid)
        self.assertEqual(reason, "shape")

        # 2. Missing maker
        bad_terms = {"id": "t1", "side": "buy", "qty": "1.00", "px": "200.00", "until": 10}
        valid, reason, _ = preflight_check(bad_terms, self.taker_did, 1, ref_px)
        self.assertFalse(valid)
        self.assertEqual(reason, "shape")

        # 3. Invalid maker DID format
        bad_maker = {"id": "t1", "maker": "not-a-did", "side": "buy", "qty": "1.00", "px": "200.00", "until": 10}
        valid, reason, _ = preflight_check(bad_maker, self.taker_did, 1, ref_px)
        self.assertFalse(valid)
        self.assertEqual(reason, "shape")

        # 4. Invalid taker DID format
        bad_tk_did = {"id": "t1", "maker": self.maker_did, "side": "buy", "qty": "1.00", "px": "200.00", "until": 10}
        valid, reason, _ = preflight_check(bad_tk_did, "invalid-taker-did", 1, ref_px)
        self.assertFalse(valid)
        self.assertEqual(reason, "shape")

    def test_10_preflight_not_owner_and_settled_checks(self):
        """Test preflight_check enforces not_owner and settled void conditions."""
        ref_px = Decimal("200.00")
        terms = TradeTerms("t_check", self.maker_did, "200.00", "1.00", "buy", "any", until=10)

        # 1. Maker not in registered_owners
        valid, reason, _ = preflight_check(
            terms, self.taker_did, 1, ref_px,
            registered_owners={self.taker_did}  # maker missing
        )
        self.assertFalse(valid)
        self.assertEqual(reason, "not_owner")

        # 2. Taker not in registered_owners
        valid, reason, _ = preflight_check(
            terms, self.taker_did, 1, ref_px,
            registered_owners={self.maker_did}  # taker missing
        )
        self.assertFalse(valid)
        self.assertEqual(reason, "not_owner")

        # 3. Both in registered_owners
        valid, reason, _ = preflight_check(
            terms, self.taker_did, 1, ref_px,
            registered_owners={self.maker_did, self.taker_did}
        )
        self.assertTrue(valid)

        # 4. Trade ID already in settled_ids
        valid, reason, _ = preflight_check(
            terms, self.taker_did, 1, ref_px,
            settled_ids={"t_check"}
        )
        self.assertFalse(valid)
        self.assertEqual(reason, "settled")

    def test_11_preflight_self_trade_funds_rule(self):
        """Test that self-trades only tie up fee cash and require no collateral."""
        ref_px = Decimal("200.00")
        same_acct = AccountState(self.maker_did, cash=Decimal("10.00"))
        # Trade is 1.00 NVDA @ 200 = 200 collateral, but 1% fee on each side = 2.00 * 2 = 4.00
        terms = TradeTerms("self_1", self.maker_did, "200.00", "1.00", "buy", taker=self.maker_did, until=10)

        # Should PASS because 10.00 cash >= 4.00 total fee
        valid, reason, telemetry = preflight_check(
            terms,
            taker_did=self.maker_did,
            current_sweep=1,
            ref_px=ref_px,
            maker_account=same_acct,
            taker_account=same_acct,
        )
        self.assertTrue(valid, f"Expected self-trade funds check to pass, got: {reason} ({telemetry})")
        self.assertTrue(telemetry.get("self_trade"))

        # Should FAIL if cash < 4.00
        broke_acct = AccountState(self.maker_did, cash=Decimal("3.50"))
        valid, reason, _ = preflight_check(
            terms,
            taker_did=self.maker_did,
            current_sweep=1,
            ref_px=ref_px,
            maker_account=broke_acct,
            taker_account=broke_acct,
        )
        self.assertFalse(valid)
        self.assertEqual(reason, "funds")

    def test_12_maker_directed_offer_to_counterparty(self):
        """Test that posting an offer directed to a specific counterparty succeeds without taker mismatch."""
        from close_call import CloseCallClient
        cc = CloseCallClient()
        cc.get_latest_price_state = lambda: {"for": 20, "ref": {"px": "225.00"}}
        cc.broadcast_message = lambda room, text: (True, "Mock OK")

        ok, msg, env = cc.post_maker_offer(
            side="buy",
            qty="1.00",
            px="225.00",
            taker=self.other_did,
        )
        self.assertTrue(ok, f"Expected directed offer to succeed, got: {msg}")
        self.assertEqual(env.get("t"), "offer")
        self.assertEqual(env.get("taker"), self.other_did)
        self.assertEqual(env["terms"]["taker"], self.other_did)

    def test_13_scan_open_offers_discovers_both_offer_and_trade(self):
        """Test scanning finds t=offer messages and skips own or already settled trades."""
        from close_call import CloseCallClient
        cc = CloseCallClient()
        cc.get_latest_price_state = lambda: {"for": 20, "ref": {"px": "225.00"}}
        cc.sync_referee_state = lambda: None

        # 1. Valid open t=offer
        terms1 = TradeTerms("open_offer_1", self.maker_did, "225.00", "2.00", "buy", "any", until=30)
        sig1 = sign_maker_terms(self.maker_priv, terms1)

        # 2. Valid open t=trade (without taker_sig, open for countersigning)
        terms2 = TradeTerms("open_trade_2", self.other_did, "224.50", "1.50", "sell", "any", until=30)
        sig2 = sign_maker_terms(self.other_priv, terms2)

        # 3. Stale offer that was already countersigned in the room
        terms_taken = TradeTerms("taken_offer", self.maker_did, "225.00", "1.00", "buy", "any", until=30)
        sig_taken = sign_maker_terms(self.maker_priv, terms_taken)

        mock_msgs = [
            # Open offer
            {
                "seq": 101,
                "text": json.dumps({
                    "t": "offer",
                    "season": CONTEST_ID,
                    "terms": terms1.to_dict(),
                    "maker_sig": sig1,
                }),
            },
            # Own offer (should be ignored)
            {
                "seq": 102,
                "text": json.dumps({
                    "t": "offer",
                    "season": CONTEST_ID,
                    "terms": TradeTerms("my_offer", cc.did, "225.00", "1.00", "buy", "any", until=30).to_dict(),
                    "maker_sig": "sig",
                }),
            },
            # Stale offer followed by countersignature
            {
                "seq": 103,
                "text": json.dumps({
                    "t": "offer",
                    "season": CONTEST_ID,
                    "terms": terms_taken.to_dict(),
                    "maker_sig": sig_taken,
                }),
            },
            {
                "seq": 104,
                "text": json.dumps({
                    "t": "trade",
                    "season": CONTEST_ID,
                    "terms": terms_taken.to_dict(),
                    "maker_sig": sig_taken,
                    "taker_sig": "completed_taker_sig",
                }),
            },
            # Open trade (open offer format used by some bots)
            {
                "seq": 105,
                "text": json.dumps({
                    "t": "trade",
                    "season": CONTEST_ID,
                    "terms": terms2.to_dict(),
                    "maker_sig": sig2,
                }),
            },
        ]
        cc.get_room_messages = lambda rm, limit=30: mock_msgs

        offers = cc.scan_open_offers(["mock-room"])
        self.assertEqual(len(offers), 2)
        discovered_ids = {o["terms"]["id"] for o in offers}
        self.assertEqual(discovered_ids, {"open_offer_1", "open_trade_2"})
        self.assertNotIn("taken_offer", discovered_ids)
        self.assertNotIn("my_offer", discovered_ids)

    def test_14_accept_and_execute_offer_lifecycle(self):
        """Test that accept_and_execute_offer validates preflight and creates fully signed trade."""
        from close_call import CloseCallClient
        cc = CloseCallClient()
        cc.get_latest_price_state = lambda: {"for": 20, "ref": {"px": "225.00"}}
        cc.settled_ids = set()

        # 1. Valid offer
        terms = TradeTerms("exec_1", self.maker_did, "225.00", "1.50", "sell", "any", until=30)
        sig = sign_maker_terms(self.maker_priv, terms)
        offer_data = {
            "room": "test-room",
            "terms": terms.to_dict(),
            "maker_sig": sig,
        }

        posted_payload = []
        cc.broadcast_message = lambda room, text: (posted_payload.append((room, json.loads(text))) or True, "Mock OK")

        ok, msg = cc.accept_and_execute_offer(offer_data)
        self.assertTrue(ok, f"Expected accept to succeed: {msg}")
        self.assertEqual(len(posted_payload), 1)
        posted_room, envelope = posted_payload[0]
        self.assertEqual(posted_room, "test-room")
        self.assertEqual(envelope["t"], "trade")
        self.assertEqual(envelope["taker"], cc.did)
        self.assertTrue(verify_taker_signature(cc.did, envelope["terms"], envelope["taker_sig"]))
        self.assertIn("exec_1", cc.settled_ids)

        # 2. Offer outside limits must be rejected before signing
        bad_terms = TradeTerms("exec_bad", self.maker_did, "250.00", "1.00", "sell", "any", until=30)
        bad_sig = sign_maker_terms(self.maker_priv, bad_terms)
        bad_offer = {"room": "test-room", "terms": bad_terms.to_dict(), "maker_sig": bad_sig}
        ok_bad, msg_bad = cc.accept_and_execute_offer(bad_offer)
        self.assertFalse(ok_bad)
        self.assertIn("Pre-flight check failed", msg_bad)

    def test_15_canonical_sample_season_vector_replay(self):
        """Replay official sample-season.jsonl test vector and verify 100% agreement with expected output."""
        from close_call import replay_season
        with open("challenge_repo/examples/sample-season.jsonl", "r", encoding="utf-8") as f:
            lines = f.readlines()
        with open("challenge_repo/examples/sample-season.expected.json", "r", encoding="utf-8") as f:
            expected = json.load(f)
        with open("challenge_repo/contest.json", "r", encoding="utf-8") as f:
            cfg = json.load(f)

        res = replay_season(lines, cfg)
        for sw_idx in range(len(res["sweeps"])):
            actual_sw = res["sweeps"][sw_idx]
            exp_sw = expected["sweeps"][sw_idx]
            self.assertEqual(actual_sw["sweep"], exp_sw["sweep"])
            self.assertEqual(len(actual_sw["trades"]), len(exp_sw["trades"]))
            for t_idx in range(len(actual_sw["trades"])):
                a_t = actual_sw["trades"][t_idx]
                e_t = exp_sw["trades"][t_idx]
                self.assertEqual(a_t["id"], e_t["id"])
                self.assertEqual(a_t["outcome"], e_t["outcome"])
                if a_t["outcome"] == "void":
                    self.assertEqual(a_t["reason"], e_t["reason"])
                elif a_t["outcome"] == "settled":
                    self.assertEqual(a_t["maker_fee"], e_t["maker_fee"])
                    self.assertEqual(a_t["taker_fee"], e_t["taker_fee"])

        self.assertEqual(res["final"]["zero_sum"], expected["final"]["zero_sum"])
        self.assertEqual(res["final"]["fees"], expected["final"]["fees"])
        self.assertEqual(res["final"]["S"], expected["final"]["S"])

    def test_16_missing_taker_key_is_shape_void(self):
        """Test that terms missing the 'taker' key trigger shape void matching official Fold."""
        bad_terms = {
            "id": "t_no_taker",
            "maker": self.maker_did,
            "px": "225.00",
            "qty": "1.00",
            "side": "buy",
            "until": 30,
        }
        valid, reason, telemetry = preflight_check(
            bad_terms,
            taker_did=self.taker_did,
            current_sweep=10,
            ref_px=Decimal("225.00"),
        )
        self.assertFalse(valid)
        self.assertEqual(reason, "shape")
        self.assertIn("missing taker", telemetry.get("error", "").lower())

    def test_17_until_zero_and_large_until_handling(self):
        """Test until=0 voids for expired (not shape), and until > LOCK_SWEEP passes shape."""
        # 1. until=0 in sweep 1 must void with 'expired'
        t_zero = TradeTerms("t_exp0", self.maker_did, "225.00", "1.00", "buy", "any", until=0)
        valid_terms, err = t_zero.validate()
        self.assertTrue(valid_terms, f"until=0 should pass shape validation, got: {err}")
        valid, reason, _ = preflight_check(t_zero, self.taker_did, current_sweep=1, ref_px=Decimal("225.00"))
        self.assertFalse(valid)
        self.assertEqual(reason, "expired")

        # 2. until=5000 (good until well past lock) must pass shape validation
        t_large = TradeTerms("t_future", self.maker_did, "225.00", "1.00", "buy", "any", until=5000)
        valid_large, err_large = t_large.validate()
        self.assertTrue(valid_large, f"until=5000 should pass shape validation, got: {err_large}")
        valid_pf, reason_pf, _ = preflight_check(t_large, self.taker_did, current_sweep=20, ref_px=Decimal("225.00"))
        self.assertTrue(valid_pf)
        self.assertIsNone(reason_pf)

    def test_18_boolean_until_triggers_shape_void(self):
        """Test that boolean until (e.g. True) triggers shape void rather than integer coercion."""
        t_bool = {"id": "t_bool", "maker": self.maker_did, "px": "225.00", "qty": "1.00", "side": "buy", "taker": "any", "until": True}
        valid, reason, _ = preflight_check(t_bool, self.taker_did, current_sweep=1, ref_px=Decimal("225.00"))
        self.assertFalse(valid)
        self.assertEqual(reason, "shape")

    def test_19_local_account_funds_check_enforced(self):
        """Test that post_maker_offer and accept_and_execute_offer enforce local agent funds."""
        from close_call import CloseCallClient
        cc = CloseCallClient()
        cc.get_latest_price_state = lambda: {"for": 20, "ref": {"px": "225.00"}}
        cc.broadcast_message = lambda room, text: (True, "Mock OK")

        # Mock agent with low cash ($100 POLF)
        low_acct = AccountState(cc.did, cash=Decimal("100.00"))
        cc.get_my_account = lambda: low_acct

        # Try to post maker offer of 10 contracts @ $225 = $2,250 + $22.50 fee = $2,272.50 required
        ok, msg, telemetry = cc.post_maker_offer(
            side="buy",
            qty="10.00",
            px="225.00",
        )
        self.assertFalse(ok)
        self.assertIn("funds", msg.lower())

        # Try to accept offer of 10 contracts with low cash
        terms_dict = {
            "id": "big_exec",
            "maker": self.maker_did,
            "px": "225.00",
            "qty": "10.00",
            "side": "buy",
            "taker": "any",
            "until": 30,
        }
        sig = sign_maker_terms(self.maker_priv, terms_dict)
        offer_data = {
            "room": "test-room",
            "terms": terms_dict,
            "maker_sig": sig,
        }
        ok_accept, msg_accept = cc.accept_and_execute_offer(offer_data)
        self.assertFalse(ok_accept)
        self.assertIn("funds", msg_accept.lower())

    def test_20_stale_and_settled_offers_filtered_in_scan(self):
        """Test that offers whose ID was settled in flow or countersigned in room are skipped."""
        from close_call import CloseCallClient
        cc = CloseCallClient()
        cc.get_latest_price_state = lambda: {"for": 20, "ref": {"px": "225.00"}}
        cc.sync_referee_state = lambda: None
        cc.settled_ids = {"already_settled_in_flow"}

        terms_settled = TradeTerms("already_settled_in_flow", self.maker_did, "225.00", "1.00", "buy", "any", until=30)
        sig_settled = sign_maker_terms(self.maker_priv, terms_settled)

        mock_msgs = [
            {
                "seq": 1,
                "text": json.dumps({
                    "t": "offer",
                    "season": CONTEST_ID,
                    "terms": terms_settled.to_dict(),
                    "maker_sig": sig_settled,
                }),
            },
        ]
        cc.get_room_messages = lambda rm, limit=30: mock_msgs

        offers = cc.scan_open_offers(["mock-room"])
        self.assertEqual(len(offers), 0, "Offer settled in flow must be excluded")

    def test_21_post_two_sided_quote(self):
        """Test two-sided market making quotes symmetrically placed around reference price."""
        from close_call import CloseCallClient
        cc = CloseCallClient()
        cc.get_latest_price_state = lambda: {"for": 25, "ref": {"px": "225.00"}}
        cc.broadcast_message = lambda room, text: (True, "Mock OK")

        res = cc.post_two_sided_quote(spread="0.80", qty="1.50", room="mock-room")
        self.assertTrue(res["success"])
        self.assertEqual(res["bid"]["px"], "224.60")
        self.assertEqual(res["ask"]["px"], "225.40")
        self.assertEqual(res["bid"]["qty"], "1.50")
        self.assertEqual(res["ask"]["qty"], "1.50")
        self.assertTrue(res["bid"]["success"])
        self.assertTrue(res["ask"]["success"])

    def test_22_execute_offer_by_id(self):
        """Test direct offer execution by terms ID."""
        from close_call import CloseCallClient
        cc = CloseCallClient()
        mock_offer = {
            "room": "mock-room",
            "terms": {"id": "target_id_123"},
        }
        cc.scan_open_offers = lambda rooms: [mock_offer]
        cc.accept_and_execute_offer = lambda offer: (True, "Executed target_id_123")

        # Success case
        ok, msg = cc.execute_offer_by_id("mock-room", "target_id_123")
        self.assertTrue(ok)
        self.assertEqual(msg, "Executed target_id_123")

        # Not found case
        ok_nf, msg_nf = cc.execute_offer_by_id("mock-room", "missing_id")
        self.assertFalse(ok_nf)
        self.assertIn("not found", msg_nf)

    def test_23_run_trading_cycle(self):
        """Test autonomous trading cycle scanning, opportunistic execution, and quoting."""
        from close_call import CloseCallClient
        cc = CloseCallClient()
        cc.sync_referee_state = lambda: None
        cc.reconcile_with_referee = lambda: {}
        cc.get_price_export = lambda: {}
        cc.get_latest_price_state = lambda: {"for": 25, "ref": {"px": "225.00"}}
        cc.get_all_registered_rooms = lambda: ["kc-c1-desk"]
        cc.post_maker_offer = lambda **kwargs: (True, "Mock Posted", {"terms": {"id": "maker_123"}})

        # Mock an attractive counterparty buy offer @ $225.10 (taker sells at favorable price)
        counter_terms = TradeTerms("counter_1", self.maker_did, "225.10", "1.00", "buy", "any", until=35)
        counter_sig = sign_maker_terms(self.maker_priv, counter_terms)
        mock_offer = {
            "room": "kc-c1-desk",
            "terms": counter_terms.to_dict(),
            "maker_sig": counter_sig,
        }
        cc.scan_open_offers = lambda rooms: [mock_offer]
        cc.accept_and_execute_offer = lambda offer: (True, "Accepted counter_1")

        cycle_res = cc.run_trading_cycle(
            max_inventory=Decimal("10.0"),
            min_cash_reserve=Decimal("1000.0"),
            target_spread=Decimal("0.50"),
            quote_qty=Decimal("1.00"),
            desk_rooms=["kc-c1-desk"],
        )

        self.assertTrue(cycle_res["success"])
        self.assertEqual(cycle_res["ref_px"], "225.00")
        self.assertEqual(len(cycle_res["executed_trades"]), 1)
        self.assertEqual(cycle_res["executed_trades"][0]["id"], "counter_1")
        self.assertEqual(len(cycle_res["posted_quotes"]), 1)

    def test_24_authoritative_reconcile_with_referee_flow(self):
        """Test authoritative referee flow reconciliation: settled trades apply, void trades do not."""
        from close_call import CloseCallClient, load_close_call_state, save_close_call_state
        cc = CloseCallClient()

        # Seed local state with 1 settled trade and 1 void trade in registry
        st = load_close_call_state()
        st["trade_registry"] = {
            "settled_t1": {
                "terms": {"id": "settled_t1", "maker": self.other_did, "px": "225.00", "qty": "2.00", "side": "buy"},
                "role": "taker",  # our agent sells 2.00
                "status": "submitted",
            },
            "void_t2": {
                "terms": {"id": "void_t2", "maker": self.other_did, "px": "224.00", "qty": "1.00", "side": "buy"},
                "role": "taker",
                "status": "submitted",
            },
        }
        save_close_call_state(st)

        # Mock referee flow export: sweep 10 settles settled_t1, voids void_t2 for funds
        mock_flow = [
            {"t": "flow", "n": 10, "settled": ["settled_t1"], "void": [["void_t2", "funds"]]}
        ]
        mock_prices = {10: Decimal("225.00")}

        cc.get_flow_export = lambda: mock_flow
        cc.get_price_export = lambda: mock_prices
        cc.get_room_messages = lambda rm, limit=100: []

        rep = cc.reconcile_with_referee()
        self.assertEqual(rep["position"], "-2.00")
        self.assertEqual(Decimal(rep["cash"]), Decimal("9545.50"))
        self.assertEqual(Decimal(rep["fees"]), Decimal("4.50"))

        # Check that void trade status was recorded as void with reason
        st_after = load_close_call_state()
        self.assertEqual(st_after["trade_registry"]["void_t2"]["status"], "void")
        self.assertEqual(st_after["trade_registry"]["void_t2"]["void_reason"], "funds")

    def test_25_maker_offer_fill_detection_and_reconciliation(self):
        """Test that maker offers posted by our agent and filled by counterparties are recognized and settled."""
        from close_call import CloseCallClient, load_close_call_state, save_close_call_state
        cc = CloseCallClient()

        # Seed local state with our maker offer
        st = load_close_call_state()
        st["trade_registry"] = {
            "our_maker_fill_1": {
                "terms": {"id": "our_maker_fill_1", "maker": cc.did, "px": "225.50", "qty": "1.00", "side": "buy"},
                "role": "maker",  # our agent buys 1.00 @ 225.50
                "status": "open",
            }
        }
        save_close_call_state(st)

        mock_flow = [
            {"t": "flow", "n": 15, "settled": ["our_maker_fill_1"], "void": []}
        ]
        mock_prices = {15: Decimal("225.50")}

        cc.get_flow_export = lambda: mock_flow
        cc.get_price_export = lambda: mock_prices
        cc.get_room_messages = lambda rm, limit=100: []

        rep = cc.reconcile_with_referee()
        self.assertEqual(rep["position"], "1.00")
        self.assertEqual(rep["lots"], [["1.00", "225.50"]])

    def test_26_inventory_skew_quoting_and_closing_priority(self):
        """Test that inventory skew correctly shifts maker quoting and trading logic."""
        from close_call import CloseCallClient
        cc = CloseCallClient()
        cc.get_latest_price_state = lambda: {"for": 25, "ref": {"px": "225.00"}}
        cc.broadcast_message = lambda room, text: (True, "Mock OK")

        # When short -5 contracts, quotes should skew aggressively to buy (bid higher, ask wider)
        res_short = cc.post_skewed_quote(pos=Decimal("-5.0"), spread="0.80", qty="1.00", room="mock-room")
        self.assertEqual(res_short["bid"]["px"], "224.85")  # ref - 0.15
        self.assertEqual(res_short["ask"]["px"], "226.00")  # ref + 0.40 + 0.60

        # When long +5 contracts, quotes should skew aggressively to sell (ask lower, bid wider)
        res_long = cc.post_skewed_quote(pos=Decimal("5.0"), spread="0.80", qty="1.00", room="mock-room")
        self.assertEqual(res_long["bid"]["px"], "224.00")  # ref - 0.40 - 0.60
        self.assertEqual(res_long["ask"]["px"], "225.15")  # ref + 0.15

    def test_27_market_trend_and_multi_timeframe_analysis(self):
        """Test multi-timeframe trend analysis: bullish, bearish, pullback, rally, and neutral regimes."""
        from close_call import CloseCallClient
        cc = CloseCallClient()

        # 1. Strong Bullish Trend: HTF and LTF both rising monotonically
        bull_history = {i: Decimal(f"{220.00 + (i * 0.40):.2f}") for i in range(1, 16)}
        bull_analysis = cc.analyze_market_trend(
            htf_window=10,
            ltf_window=3,
            price_history=bull_history,
            latest_price=Decimal("226.00"),
            current_sweep=15,
        )
        self.assertEqual(bull_analysis.htf_trend, "BULLISH")
        self.assertEqual(bull_analysis.ltf_trend, "BULLISH")
        self.assertEqual(bull_analysis.regime, "ALIGNED_BULLISH")
        self.assertEqual(bull_analysis.recommended_action, "BUY_ONLY")
        self.assertGreater(bull_analysis.trend_score, 0.5)

        # 2. Strong Bearish Trend: HTF and LTF both falling monotonically
        bear_history = {i: Decimal(f"{230.00 - (i * 0.40):.2f}") for i in range(1, 16)}
        bear_analysis = cc.analyze_market_trend(
            htf_window=10,
            ltf_window=3,
            price_history=bear_history,
            latest_price=Decimal("224.00"),
            current_sweep=15,
        )
        self.assertEqual(bear_analysis.htf_trend, "BEARISH")
        self.assertEqual(bear_analysis.ltf_trend, "BEARISH")
        self.assertEqual(bear_analysis.regime, "ALIGNED_BEARISH")
        self.assertEqual(bear_analysis.recommended_action, "SELL_ONLY")
        self.assertLess(bear_analysis.trend_score, -0.5)

        # 3. Bullish Pullback: HTF is overall rising, but last 3 sweeps pulled back
        pullback_history = {i: Decimal(f"{220.00 + (i * 0.50):.2f}") for i in range(1, 13)}
        pullback_history[13] = Decimal("225.50")
        pullback_history[14] = Decimal("225.00")
        pullback_history[15] = Decimal("224.50")
        pullback_analysis = cc.analyze_market_trend(
            htf_window=12,
            ltf_window=3,
            price_history=pullback_history,
            latest_price=Decimal("224.50"),
            current_sweep=15,
        )
        self.assertEqual(pullback_analysis.htf_trend, "BULLISH")
        self.assertEqual(pullback_analysis.ltf_trend, "BEARISH")
        self.assertEqual(pullback_analysis.regime, "BULLISH_PULLBACK")
        self.assertEqual(pullback_analysis.recommended_action, "FAVOR_BUY")

        # 4. Bearish Rally: HTF is overall falling, but last 3 sweeps bounced
        rally_history = {i: Decimal(f"{230.00 - (i * 0.50):.2f}") for i in range(1, 13)}
        rally_history[13] = Decimal("224.50")
        rally_history[14] = Decimal("225.00")
        rally_history[15] = Decimal("225.50")
        rally_analysis = cc.analyze_market_trend(
            htf_window=12,
            ltf_window=3,
            price_history=rally_history,
            latest_price=Decimal("225.50"),
            current_sweep=15,
        )
        self.assertEqual(rally_analysis.htf_trend, "BEARISH")
        self.assertEqual(rally_analysis.ltf_trend, "BULLISH")
        self.assertEqual(rally_analysis.regime, "BEARISH_RALLY")
        self.assertEqual(rally_analysis.recommended_action, "FAVOR_SELL")

        # 5. Flat / Insufficient history fallback
        empty_analysis = cc.analyze_market_trend(
            price_history={},
            latest_price=Decimal("225.00"),
            current_sweep=1,
        )
        self.assertEqual(empty_analysis.regime, "NEUTRAL_RANGING")
        self.assertEqual(empty_analysis.recommended_action, "BOTH")

    def test_28_volatility_regimes_and_dynamic_buffers(self):
        """Test rolling volatility estimation, regime classifications, dynamic buffer and spread."""
        from close_call import CloseCallClient
        cc = CloseCallClient()

        # Low volatility: tiny micro-moves
        low_vol_history = {i: Decimal(f"{225.00 + (0.01 if i % 2 == 0 else -0.01):.2f}") for i in range(1, 20)}
        low_analysis = cc.analyze_market_trend(
            price_history=low_vol_history,
            latest_price=Decimal("225.00"),
            current_sweep=20,
            target_spread=Decimal("0.80"),
        )
        self.assertEqual(low_analysis.volatility_regime, "LOW")
        self.assertEqual(low_analysis.vol_buffer, Decimal("0.00"))
        self.assertEqual(low_analysis.dynamic_spread, Decimal("0.80"))

        # Extreme volatility: large wild moves
        extreme_history = {i: Decimal(f"{225.00 + (4.00 if i % 2 == 0 else -4.00):.2f}") for i in range(1, 20)}
        extreme_analysis = cc.analyze_market_trend(
            price_history=extreme_history,
            latest_price=Decimal("225.00"),
            current_sweep=20,
            target_spread=Decimal("0.80"),
        )
        self.assertEqual(extreme_analysis.volatility_regime, "EXTREME")
        self.assertGreater(extreme_analysis.vol_buffer, Decimal("0.30"))
        self.assertGreater(extreme_analysis.dynamic_spread, Decimal("0.80"))
        self.assertEqual(extreme_analysis.recommended_action, "REDUCE_ONLY")

    def test_29_evaluate_trade_entry_filters(self):
        """Test evaluate_trade_entry gates: trend alignment, volatility circuit breaker, and closing allowances."""
        from close_call import CloseCallClient
        cc = CloseCallClient()
        ref_px = Decimal("225.00")
        cash = Decimal("10000.00")

        # Mock market analysis: ALIGNED_BEARISH
        bear_history = {i: Decimal(f"{230.00 - (i * 0.40):.2f}") for i in range(1, 16)}
        bear_analysis = cc.analyze_market_trend(
            price_history=bear_history,
            latest_price=ref_px,
            current_sweep=15,
        )

        # Counterparty offer: maker sells @ 224.80 (taker buys @ 224.80, discount of 0.20)
        # Attempting to open LONG when market is ALIGNED_BEARISH must be BLOCKED!
        long_offer = {
            "room": "mock-desk",
            "terms": {"id": "offer_long_1", "maker": self.maker_did, "px": "224.80", "qty": "1.00", "side": "sell", "until": 25},
        }
        ok_long, reason_long, _ = cc.evaluate_trade_entry(
            offer=long_offer,
            pos=Decimal("0.0"),  # Opening new long
            cash=cash,
            ref_px=ref_px,
            analysis=bear_analysis,
        )
        self.assertFalse(ok_long)
        self.assertIn("Trend filter", reason_long)

        # Counterparty offer: maker buys @ 225.20 (taker sells @ 225.20, premium of 0.20)
        # Attempting to open SHORT when market is ALIGNED_BEARISH should be APPROVED!
        short_offer = {
            "room": "mock-desk",
            "terms": {"id": "offer_short_1", "maker": self.maker_did, "px": "225.20", "qty": "1.00", "side": "buy", "until": 25},
        }
        ok_short, reason_short, meta_short = cc.evaluate_trade_entry(
            offer=short_offer,
            pos=Decimal("0.0"),  # Opening new short
            cash=cash,
            ref_px=ref_px,
            analysis=bear_analysis,
        )
        self.assertTrue(ok_short)
        self.assertEqual(meta_short["side"], "sell")

        # Closing an existing long in a Bearish market must be PERMITTED (de-risking)
        ok_close_long, _, meta_close = cc.evaluate_trade_entry(
            offer=short_offer,
            pos=Decimal("2.0"),  # Holding +2 long, selling closes it
            cash=cash,
            ref_px=ref_px,
            analysis=bear_analysis,
        )
        self.assertTrue(ok_close_long)
        self.assertTrue(meta_close["is_closing"])

        # Extreme volatility circuit breaker: opening new positions is BLOCKED
        extreme_analysis = cc.analyze_market_trend(
            price_history={i: Decimal(f"{225.00 + (5.00 if i % 2 == 0 else -5.00):.2f}") for i in range(1, 20)},
            latest_price=ref_px,
            current_sweep=20,
        )
        ok_extreme, reason_extreme, _ = cc.evaluate_trade_entry(
            offer=short_offer,
            pos=Decimal("0.0"),
            cash=cash,
            ref_px=ref_px,
            analysis=extreme_analysis,
        )
        self.assertFalse(ok_extreme)
        self.assertIn("Extreme volatility", reason_extreme)

    def test_30_boosted_maker_quoting_and_trading_cycle(self):
        """Test boosted quoting with trend skew and full autonomous trading cycle telemetry."""
        from close_call import CloseCallClient
        cc = CloseCallClient()
        ref_px = Decimal("225.00")
        cc.get_latest_price_state = lambda: {"for": 25, "ref": {"px": "225.00"}}
        cc.broadcast_message = lambda room, text: (True, "Mock OK")

        # Bullish analysis: quotes should skew upwards (+0.10)
        bull_history = {i: Decimal(f"{220.00 + (i * 0.40):.2f}") for i in range(1, 16)}
        bull_analysis = cc.analyze_market_trend(
            price_history=bull_history,
            latest_price=ref_px,
            current_sweep=15,
            target_spread=Decimal("0.80"),
        )
        quote_res = cc.post_skewed_quote(
            pos=Decimal("0.0"),
            spread=Decimal("0.80"),
            qty=Decimal("1.00"),
            room="mock-desk",
            analysis=bull_analysis,
        )
        # With trend_skew = +0.10:
        # bid = ref - 0.40 + 0.10 = 224.70
        # ask = ref + 0.40 + 0.10 = 225.50
        self.assertEqual(quote_res["bid"]["px"], "224.70")
        self.assertEqual(quote_res["ask"]["px"], "225.50")

        # Full trading cycle run with trend analysis in telemetry
        cc.sync_referee_state = lambda: None
        cc.reconcile_with_referee = lambda: {}
        cc.get_all_registered_rooms = lambda: ["kc-c1-desk"]
        cc.post_maker_offer = lambda **kwargs: (True, "Mock Quoted", {"terms": {"id": "quote_1"}})
        cc.get_price_export = lambda: bull_history
        # Counterparty offer aligned with bullish trend: maker sells @ 224.80 (taker buys @ discount)
        counter_terms = TradeTerms("counter_bull_1", self.maker_did, "224.80", "1.00", "sell", "any", until=35)
        counter_sig = sign_maker_terms(self.maker_priv, counter_terms)
        cc.scan_open_offers = lambda rooms: [{
            "room": "kc-c1-desk",
            "terms": counter_terms.to_dict(),
            "maker_sig": counter_sig,
        }]
        cc.accept_and_execute_offer = lambda offer: (True, "Accepted counter_bull_1")

        cycle_res = cc.run_trading_cycle(
            max_inventory=Decimal("10.0"),
            min_cash_reserve=Decimal("1000.0"),
            target_spread=Decimal("0.80"),
            quote_qty=Decimal("1.00"),
            desk_rooms=["kc-c1-desk"],
        )
        self.assertTrue(cycle_res["success"])
        self.assertIn("market_analysis", cycle_res)
        self.assertEqual(cycle_res["market_analysis"]["htf_trend"], "BULLISH")
        self.assertEqual(len(cycle_res["executed_trades"]), 1)
        self.assertEqual(cycle_res["executed_trades"][0]["id"], "counter_bull_1")
        self.assertEqual(cycle_res["executed_trades"][0]["side"], "buy")

    def test_31_position_flipping_and_strict_entry_gates(self):
        """Test that position-flipping trades (opening_qty > 0) enforce trend filters and inventory caps."""
        from close_call import CloseCallClient
        cc = CloseCallClient()
        ref_px = Decimal("225.00")
        cash = Decimal("10000.00")

        # Bearish market setup
        bear_history = {i: Decimal(f"{230.00 - (i * 0.40):.2f}") for i in range(1, 16)}
        bear_analysis = cc.analyze_market_trend(
            price_history=bear_history,
            latest_price=ref_px,
            current_sweep=15,
        )

        # 1. Holding short -0.1 contracts, counterparty offers to sell 10.0 contracts @ 224.80
        # This trade closes 0.1 short but opens 9.9 NEW LONGS into an ALIGNED_BEARISH market!
        flip_offer = {
            "room": "mock-desk",
            "terms": {"id": "flip_offer_1", "maker": self.maker_did, "px": "224.80", "qty": "10.00", "side": "sell", "until": 25},
        }
        ok_flip, reason_flip, meta_flip = cc.evaluate_trade_entry(
            offer=flip_offer,
            pos=Decimal("-0.1"),
            cash=cash,
            ref_px=ref_px,
            analysis=bear_analysis,
            max_inventory=Decimal("5.0"),
        )
        self.assertFalse(ok_flip)
        # Must be rejected because it breaches dynamic inventory cap (9.9 > 5.0) or fails trend filter
        self.assertTrue("dynamic inventory cap" in reason_flip or "Trend filter" in reason_flip)

        # 2. Even within inventory limit, opening net long in a bearish regime must be rejected
        ok_flip_small, reason_small, _ = cc.evaluate_trade_entry(
            offer={
                "room": "mock-desk",
                "terms": {"id": "flip_small", "maker": self.maker_did, "px": "224.80", "qty": "2.00", "side": "sell", "until": 25},
            },
            pos=Decimal("-0.1"),  # closes 0.1, opens 1.9 net long
            cash=cash,
            ref_px=ref_px,
            analysis=bear_analysis,
            max_inventory=Decimal("5.0"),
        )
        self.assertFalse(ok_flip_small)
        self.assertIn("Trend filter", reason_small)

        # 3. Pure de-risking (buying <= 0.1 to purely close the short) MUST be approved
        ok_pure_close, _, meta_pure = cc.evaluate_trade_entry(
            offer={
                "room": "mock-desk",
                "terms": {"id": "pure_close", "maker": self.maker_did, "px": "225.00", "qty": "0.10", "side": "sell", "until": 25},
            },
            pos=Decimal("-0.1"),
            cash=cash,
            ref_px=ref_px,
            analysis=bear_analysis,
            max_inventory=Decimal("5.0"),
        )
        self.assertTrue(ok_pure_close)
        self.assertTrue(meta_pure["is_closing"])

    def test_32_multi_trade_cycle_inventory_and_cash_tracking(self):
        """Test that run_trading_cycle tracks running position across multiple trades to avoid inventory breach."""
        from close_call import CloseCallClient, load_close_call_state, save_close_call_state
        cc = CloseCallClient()
        bull_history = {i: Decimal(f"{220.00 + (i * 0.40):.2f}") for i in range(1, 16)}

        cc.sync_referee_state = lambda: None
        cc.reconcile_with_referee = lambda: {}
        cc.get_latest_price_state = lambda: {"for": 25, "ref": {"px": "225.00"}}
        cc.get_price_export = lambda: bull_history
        cc.get_all_registered_rooms = lambda: ["mock-desk"]
        cc.broadcast_message = lambda room, text: (True, "OK")
        cc.post_maker_offer = lambda **kwargs: (True, "Quoted", {"terms": {"id": "q1"}})

        # Seed local account state as flat pos = 0
        st = load_close_call_state()
        st["cash"] = "10000.00"
        st["lots"] = []
        st["fees"] = "0"
        st["position"] = "0"
        save_close_call_state(st)

        # Two counterparty sell offers (each 1.0 contract @ discount)
        t1 = TradeTerms("multi_t1", self.maker_did, "224.80", "1.00", "sell", "any", until=35)
        sig1 = sign_maker_terms(self.maker_priv, t1)
        t2 = TradeTerms("multi_t2", self.maker_did, "224.80", "1.00", "sell", "any", until=35)
        sig2 = sign_maker_terms(self.maker_priv, t2)

        cc.scan_open_offers = lambda rooms: [
            {"room": "mock-desk", "terms": t1.to_dict(), "maker_sig": sig1},
            {"room": "mock-desk", "terms": t2.to_dict(), "maker_sig": sig2},
        ]
        cc.accept_and_execute_offer = lambda o: (True, "Accepted")

        # Run cycle with max_inventory = 1.0: only FIRST offer can execute!
        res = cc.run_trading_cycle(
            max_inventory=Decimal("1.0"),
            min_cash_reserve=Decimal("1000.0"),
            max_trades_per_cycle=2,
            desk_rooms=["mock-desk"],
        )

        self.assertEqual(len(res["executed_trades"]), 1)
        self.assertEqual(res["executed_trades"][0]["id"], "multi_t1")
        self.assertEqual(len(res["rejected_offers"]), 1)
        self.assertEqual(res["rejected_offers"][0]["id"], "multi_t2")
        self.assertIn("exceeds dynamic inventory cap", res["rejected_offers"][0]["reason"])
        self.assertEqual(res["final_position"], "1.00")

    def test_33_quote_price_clamping_and_directional_filtering(self):
        """Test that post_skewed_quote clamps prices within Rule 11 bounds and respects directional/volatility gates."""
        from close_call import CENT, CloseCallClient
        cc = CloseCallClient()
        ref_px = Decimal("225.00")
        cc.get_latest_price_state = lambda: {"for": 25, "ref": {"px": "225.00"}}
        cc.broadcast_message = lambda room, text: (True, "OK")

        # 1. Bearish trend: recommended_action = SELL_ONLY
        bear_history = {i: Decimal(f"{230.00 - (i * 0.40):.2f}") for i in range(1, 16)}
        bear_analysis = cc.analyze_market_trend(price_history=bear_history, latest_price=Decimal("224.00"), current_sweep=15)
        self.assertEqual(bear_analysis.recommended_action, "SELL_ONLY")

        # In SELL_ONLY and pos == 0: bid is filtered, ask is posted
        quote_bear = cc.post_skewed_quote(pos=Decimal("0.0"), analysis=bear_analysis)
        self.assertFalse(quote_bear["bid"]["success"])
        self.assertIn("Bearish regime", quote_bear["bid"]["message"])
        self.assertTrue(quote_bear["ask"]["success"])

        # 2. Extreme volatility with flat pos: both bid and ask filtered (REDUCE_ONLY)
        extreme_history = {i: Decimal(f"{225.00 + (6.00 if i % 2 == 0 else -6.00):.2f}") for i in range(1, 20)}
        extreme_analysis = cc.analyze_market_trend(price_history=extreme_history, latest_price=ref_px, current_sweep=20)
        self.assertEqual(extreme_analysis.volatility_regime, "EXTREME")
        self.assertEqual(extreme_analysis.recommended_action, "REDUCE_ONLY")

        quote_extreme_flat = cc.post_skewed_quote(pos=Decimal("0.0"), analysis=extreme_analysis)
        self.assertFalse(quote_extreme_flat["bid"]["success"])
        self.assertFalse(quote_extreme_flat["ask"]["success"])

        # 3. Extreme volatility while holding long (+3.0): ask allowed (to de-risk), bid blocked
        quote_extreme_long = cc.post_skewed_quote(pos=Decimal("3.0"), analysis=extreme_analysis)
        self.assertFalse(quote_extreme_long["bid"]["success"])
        self.assertTrue(quote_extreme_long["ask"]["success"])

        # 4. Enforce Rule 11 limit bands: prices must strictly stay in [213.75 .. 236.25]
        min_limit = (ref_px * Decimal("0.95")).quantize(CENT)
        max_limit = (ref_px * Decimal("1.05")).quantize(CENT)
        bid_px = Decimal(quote_extreme_long["bid"]["px"])
        ask_px = Decimal(quote_extreme_long["ask"]["px"])
        self.assertGreaterEqual(bid_px, min_limit)
        self.assertLessEqual(ask_px, max_limit)

    def test_34_extended_regime_synthesis_and_linear_regression(self):
        """Test extended regime classifications (consolidations), linear regression slope, and replay filtering."""
        from close_call import CloseCallClient
        cc = CloseCallClient()

        # 1. HTF Bullish Consolidation: HTF is overall up, last 3 sweeps are completely flat
        cons_history = {i: Decimal(f"{220.00 + (i * 0.40):.2f}") for i in range(1, 13)}
        cons_history[13] = Decimal("224.80")
        cons_history[14] = Decimal("224.80")
        cons_history[15] = Decimal("224.80")
        cons_analysis = cc.analyze_market_trend(
            htf_window=12,
            ltf_window=3,
            price_history=cons_history,
            latest_price=Decimal("224.80"),
            current_sweep=15,
        )
        self.assertEqual(cons_analysis.htf_trend, "BULLISH")
        self.assertEqual(cons_analysis.ltf_trend, "NEUTRAL")
        self.assertEqual(cons_analysis.regime, "HTF_BULLISH_CONSOLIDATION")
        self.assertEqual(cons_analysis.recommended_action, "FAVOR_BUY")
        self.assertGreater(cons_analysis.htf_slope, 0.0)

        # 2. Historical Replay / Backtesting: sweeps beyond current_sweep are filtered out
        replay_history = {i: Decimal(f"{220.00 + (i * 0.40):.2f}") for i in range(1, 25)}
        replay_analysis = cc.analyze_market_trend(
            htf_window=10,
            ltf_window=3,
            price_history=replay_history,
            latest_price=Decimal("224.00"),
            current_sweep=10,  # Sweeps 11-24 must not leak!
        )
        self.assertEqual(replay_analysis.sweep_n, 10)
        self.assertEqual(replay_analysis.current_px, Decimal("224.00"))


    def test_35_dynamic_sizing_and_fee_clearing_filters(self):
        """Test scaled dynamic order sizing (3.00-5.00 lots), fee-clearing maker spread, and clawback gate."""
        from close_call import (
            CloseCallClient,
            DEFAULT_ORDER_SIZE,
            MAX_DYNAMIC_ORDER_SIZE,
            MAX_INVENTORY,
            MIN_PROFIT_MARGIN,
            FEE_RATE,
        )
        cc = CloseCallClient()
        ref_px = Decimal("225.00")

        # 1. Dynamic sizing based on cash and headroom
        # Rich cash (5000) & full headroom (15) -> 5.00
        sz_max = cc.compute_dynamic_order_size(
            side="buy",
            pos=Decimal("0.0"),
            cash=Decimal("5000.0"),
            ref_px=ref_px,
            volatility_regime="LOW",
            max_inventory=MAX_INVENTORY,
        )
        self.assertEqual(sz_max, Decimal("5.00"))

        # Intermediate cash (3000) & headroom 4 -> 4.00
        sz_mid = cc.compute_dynamic_order_size(
            side="buy",
            pos=Decimal("11.0"),
            cash=Decimal("3000.0"),
            ref_px=ref_px,
            volatility_regime="NORMAL",
            max_inventory=MAX_INVENTORY,
        )
        self.assertEqual(sz_mid, Decimal("4.00"))

        # Constrained inventory headroom (e.g. pos=13, max=15 -> headroom=2) -> clamped to 2.00
        sz_headroom = cc.compute_dynamic_order_size(
            side="buy",
            pos=Decimal("13.0"),
            cash=Decimal("5000.0"),
            ref_px=ref_px,
            volatility_regime="NORMAL",
            max_inventory=MAX_INVENTORY,
        )
        self.assertEqual(sz_headroom, Decimal("2.00"))

        # Extreme volatility dampens order size to minimal 1.00
        sz_extreme = cc.compute_dynamic_order_size(
            side="buy",
            pos=Decimal("0.0"),
            cash=Decimal("5000.0"),
            ref_px=ref_px,
            volatility_regime="EXTREME",
            max_inventory=MAX_INVENTORY,
        )
        self.assertEqual(sz_extreme, Decimal("1.00"))

        # 2. Maker quoting default spread clears roundtrip fee: 2 * 0.01 * 225 = $4.50 + $0.60 = $5.10
        cc.get_latest_price_state = lambda: {"for": 25, "ref": {"px": "225.00"}}
        cc.broadcast_message = lambda room, text: (True, "OK")
        q_res = cc.post_skewed_quote(pos=Decimal("0.0"), spread=None, qty=None)
        self.assertTrue(q_res["bid"]["success"])
        self.assertTrue(q_res["ask"]["success"])
        self.assertGreaterEqual(Decimal(q_res["bid"]["qty"]), Decimal("3.00"))
        self.assertGreaterEqual(Decimal(q_res["ask"]["qty"]), Decimal("3.00"))
        expected_min_spread = (Decimal("2") * FEE_RATE * ref_px) + MIN_PROFIT_MARGIN
        actual_spread = Decimal(q_res["ask"]["px"]) - Decimal(q_res["bid"]["px"])
        self.assertGreaterEqual(actual_spread, expected_min_spread)

        # 3. Taker entry fee clearance gate
        flat_history = {i: Decimal("225.00") for i in range(1, 16)}
        neutral_analysis = cc.analyze_market_trend(
            price_history=flat_history,
            latest_price=ref_px,
            current_sweep=15,
        )

        # Low-edge offer that does not clear roundtrip fee ($4.50)
        low_edge_offer = {
            "room": "kc-c1-desk",
            "terms": {
                "id": "t_low_edge",
                "maker": "did:key:z6MkhSomeMaker1",
                "px": "224.50",  # Only $0.50 discount
                "qty": "3.00",
                "side": "sell",  # We would BUY at 224.50 vs ref 225.00 (gross edge $0.50)
                "until": 30,
                "taker": "any",
            },
            "sig": "valid_sig",
        }
        ok, reason, meta = cc.evaluate_trade_entry(
            offer=low_edge_offer,
            pos=Decimal("0.0"),
            cash=Decimal("10000.0"),
            ref_px=ref_px,
            analysis=neutral_analysis,
        )
        self.assertFalse(ok)
        self.assertIn("expected profit", reason)
        self.assertIn("fails to clear roundtrip clawback fees", reason)

        # High-edge offer clearing roundtrip fee + margin ($6.00 discount > $4.50 fee)
        high_edge_offer = {
            "room": "kc-c1-desk",
            "terms": {
                "id": "t_high_edge",
                "maker": "did:key:z6MkhSomeMaker2",
                "px": "219.00",  # $6.00 discount
                "qty": "3.00",
                "side": "sell",  # We BUY at 219.00 vs ref 225.00
                "until": 30,
                "taker": "any",
            },
            "sig": "valid_sig",
        }
        ok_hi, reason_hi, meta_hi = cc.evaluate_trade_entry(
            offer=high_edge_offer,
            pos=Decimal("0.0"),
            cash=Decimal("10000.0"),
            ref_px=ref_px,
            analysis=neutral_analysis,
        )
        self.assertTrue(ok_hi, f"High edge offer should pass, failed with: {reason_hi}")
        self.assertGreater(Decimal(meta_hi["expected_net_profit"]), Decimal("0.00"))

    def test_36_inventory_skew_fee_clearing_and_closing_liquidity(self):
        """Test that inventory-skew quoting preserves fee clearance, closing trades bypass min cash reserve, and target_room works."""
        from close_call import CloseCallClient, FEE_RATE, MIN_PROFIT_MARGIN, MAX_INVENTORY
        cc = CloseCallClient()
        ref_px = Decimal("225.00")
        min_fee_spread = (Decimal("2") * FEE_RATE * ref_px) + MIN_PROFIT_MARGIN

        cc.get_latest_price_state = lambda: {"for": 25, "ref": {"px": "225.00"}}
        cc.broadcast_message = lambda room, text: (True, "OK")

        # 1. Inventory skew quoting must strictly preserve fee clearance even when pos != 0
        q_long = cc.post_skewed_quote(pos=Decimal("5.0"), spread=None, qty=None)
        self.assertTrue(q_long["bid"]["success"])
        self.assertTrue(q_long["ask"]["success"])
        spread_long = Decimal(q_long["ask"]["px"]) - Decimal(q_long["bid"]["px"])
        self.assertGreaterEqual(spread_long, min_fee_spread, f"Long-skew spread {spread_long} must clear min fee spread {min_fee_spread}")

        q_short = cc.post_skewed_quote(pos=Decimal("-5.0"), spread=None, qty=None)
        self.assertTrue(q_short["bid"]["success"])
        self.assertTrue(q_short["ask"]["success"])
        spread_short = Decimal(q_short["ask"]["px"]) - Decimal(q_short["bid"]["px"])
        self.assertGreaterEqual(spread_short, min_fee_spread, f"Short-skew spread {spread_short} must clear min fee spread {min_fee_spread}")

        # 2. Pure closing trades must be permitted even when cash < min_cash_reserve
        flat_history = {i: Decimal("225.00") for i in range(1, 16)}
        neutral_analysis = cc.analyze_market_trend(
            price_history=flat_history,
            latest_price=ref_px,
            current_sweep=15,
        )
        closing_offer = {
            "room": "kc-c1-desk",
            "terms": {
                "id": "t_close_reserve",
                "maker": "did:key:z6MkhSomeBuyer",
                "px": "225.00",
                "qty": "3.00",
                "side": "buy",  # Maker buys -> our agent SELLS to close long
                "until": 30,
                "taker": "any",
            },
            "sig": "valid_sig",
        }
        ok_close, reason_close, meta_close = cc.evaluate_trade_entry(
            offer=closing_offer,
            pos=Decimal("5.0"),
            cash=Decimal("4000.0"),  # Below min_cash_reserve (5000.0)
            ref_px=ref_px,
            analysis=neutral_analysis,
            min_cash_reserve=Decimal("5000.0"),
        )
        self.assertTrue(ok_close, f"Pure closing trade must be approved even if cash < reserve: {reason_close}")
        self.assertTrue(meta_close["is_closing"])

        # 3. Dynamic sizing scales to full 5.00 lots when closing an existing 5-lot position even under reserve cash
        sz_close = cc.compute_dynamic_order_size(
            side="sell",
            pos=Decimal("5.0"),
            cash=Decimal("4000.0"),
            ref_px=ref_px,
            min_cash_reserve=Decimal("5000.0"),
            max_inventory=MAX_INVENTORY,
        )
        self.assertEqual(sz_close, Decimal("5.00"))

        # 4. Opening quotes are suppressed when cash < min_cash_reserve but closing quotes are permitted
        q_under_cash = cc.post_skewed_quote(
            pos=Decimal("5.0"),
            spread=None,
            qty=None,
            cash=Decimal("4000.0"),
            min_cash_reserve=Decimal("5000.0"),
        )
        self.assertFalse(q_under_cash["bid"]["success"])  # Bid would open more long -> suppressed
        self.assertTrue(q_under_cash["ask"]["success"])   # Ask closes long -> permitted
        self.assertEqual(Decimal(q_under_cash["ask"]["qty"]), Decimal("5.00"))

        # 5. run_trading_cycle accepts target_room argument without error
        cc.sync_referee_state = lambda: None
        cc.reconcile_with_referee = lambda: {}
        cc.get_price_export = lambda: flat_history
        cc.get_all_registered_rooms = lambda: ["close1"]
        res_cycle = cc.run_trading_cycle(target_room="close1")
        self.assertTrue(res_cycle["success"])


if __name__ == "__main__":
    unittest.main()


