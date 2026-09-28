"""Technocore Close Call Challenge (close-1) Engine & Trading Agent.

Implements full protocol compliance with flop-labs/technocore-close-call-challenge:
1. Contest configuration & constants (close-1, NVDA future, 10,000 POLF mint).
2. Canonical JSON serialization & Ed25519 terms/accept signing & verification.
3. Local Fold & pre-flight verification covering all 8 void checks & clawback fees.
4. Referee state synchronization (d-close1-price, flow, positions, pnl, state).
5. Trade creation, maker offer publishing, taker countersigning & broadcast.
6. Opportunistic offer scanner & clawback-safe trading strategy.
7. CLI and programmatic interface for Sentinel integration.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import json
import logging
import math
import os
import re
import sys
import time
import urllib.parse
from dataclasses import asdict, dataclass, field
from decimal import Decimal, localcontext
from typing import Any, Dict, List, Optional, Set, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from sentinel_core import (
    KEY_FILE,
    USER_AGENT,
    canonical_sweep,
    extract_public_key_from_did,
    get_next_nonce,
    http_get,
    is_valid_did,
    load_json_safe,
    load_or_create_identity,
    save_json_atomic,
    sign_message,
)

logger = logging.getLogger("close-call")

# ============================================================================
# 1. Challenge Constants & Configuration
# ============================================================================

CONTEST_ID = "close-1"
MARKET = "xyz:NVDA on Hyperliquid"
UNIT = "POLF, one per US dollar of NVDA"
DEFAULT_MINT = Decimal("10000")
PRICE_STEP = Decimal("0.01")
QTY_STEP = Decimal("0.01")
MIN_QTY = Decimal("0.1")
LIMIT_WINDOW = Decimal("0.05")
FEE_RATE = Decimal("0.01")
FEE_RULE = "clawback"
LOCK_SWEEP = 2556
SWEEP_SECONDS = 300
PRIZE_POOL = "1000000"
PRIZE_PLACES = 3
DEFAULT_ORDER_SIZE = Decimal("3.00")
MAX_DYNAMIC_ORDER_SIZE = Decimal("5.00")
MAX_INVENTORY = Decimal("15.0")
MIN_PROFIT_MARGIN = Decimal("0.60")

PUBLIC_TRADING_ROOM = "close1"
REFEREE_ROOMS = [
    "d-close1-price",
    "d-close1-flow",
    "d-close1-state",
    "d-close1-positions",
    "d-close1-pnl",
]

TRADE_ID_REGEX = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
TWO_PLACES_REGEX = re.compile(r"^[0-9]{1,7}(\.[0-9]{1,2})?$")
CENT = Decimal("0.01")
PRECISION_CONTEXT = 60


def parse_amount(text: Any) -> Optional[Decimal]:
    """Validate and parse a price or quantity: string with at most two decimals, above zero."""
    if not isinstance(text, str) or not TWO_PLACES_REGEX.fullmatch(text):
        return None
    try:
        val = Decimal(text)
        return val if val > 0 else None
    except Exception:
        return None


def format_amount(val: Decimal | float | str) -> str:
    """Format an amount as decimal string with at most 2 decimal places."""
    d = Decimal(str(val)).quantize(CENT)
    # Strip unnecessary trailing zero if whole number or standard format
    s = f"{d:.2f}"
    return s.rstrip("0").rstrip(".") if s.endswith(".00") else s


# ============================================================================
# 2. Canonical Terms, Data Model & Cryptography
# ============================================================================

@dataclass
class TradeTerms:
    id: str
    maker: str
    px: str
    qty: str
    side: str
    taker: str = "any"
    until: int = LOCK_SWEEP

    def validate(self) -> Tuple[bool, Optional[str]]:
        if not isinstance(self.id, str) or not TRADE_ID_REGEX.fullmatch(self.id):
            return False, "shape: invalid trade id format"
        if not is_valid_did(self.maker):
            return False, "shape: invalid maker did:key"
        if self.taker != "any" and not is_valid_did(self.taker):
            return False, "shape: invalid taker did:key"
        if self.side not in ("buy", "sell"):
            return False, "shape: side must be 'buy' or 'sell'"
        q = parse_amount(self.qty)
        if q is None or q < MIN_QTY:
            return False, f"shape: qty must be at least {MIN_QTY} with max 2 decimals"
        p = parse_amount(self.px)
        if p is None or p <= 0:
            return False, "shape: px must be positive with max 2 decimals"
        if type(self.until) is not int or self.until < 0:
            return False, "shape: until must be an integer >= 0"
        return True, None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "maker": self.maker,
            "px": self.px,
            "qty": self.qty,
            "side": self.side,
            "taker": self.taker,
            "until": self.until,
        }

    def canonical_json(self) -> str:
        """Exact canonical serialization: sorted keys, compact separators, no spaces."""
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True)


def sign_maker_terms(priv: ed25519.Ed25519PrivateKey, terms: TradeTerms | dict) -> str:
    """Maker signs: close-1|terms|<compact_terms> with Ed25519, unpadded base64url."""
    if isinstance(terms, TradeTerms):
        terms_json = terms.canonical_json()
    else:
        terms_json = json.dumps(terms, separators=(",", ":"), sort_keys=True)
    payload = f"close-1|terms|{terms_json}".encode("utf-8")
    sig_bytes = priv.sign(payload)
    return base64.urlsafe_b64encode(sig_bytes).decode("ascii").rstrip("=")


def sign_taker_accept(priv: ed25519.Ed25519PrivateKey, terms: TradeTerms | dict, taker_did: str) -> str:
    """Taker signs: close-1|accept|<compact_terms>|<taker_did> with Ed25519, unpadded base64url."""
    if isinstance(terms, TradeTerms):
        terms_json = terms.canonical_json()
    else:
        terms_json = json.dumps(terms, separators=(",", ":"), sort_keys=True)
    payload = f"close-1|accept|{terms_json}|{taker_did}".encode("utf-8")
    sig_bytes = priv.sign(payload)
    return base64.urlsafe_b64encode(sig_bytes).decode("ascii").rstrip("=")


def verify_maker_signature(maker_did: str, terms: TradeTerms | dict, sig_str: str) -> bool:
    """Verifies maker signature over close-1|terms|<terms>."""
    try:
        pub = extract_public_key_from_did(maker_did)
        if isinstance(terms, TradeTerms):
            terms_json = terms.canonical_json()
        else:
            terms_json = json.dumps(terms, separators=(",", ":"), sort_keys=True)
        payload = f"close-1|terms|{terms_json}".encode("utf-8")
        pad_len = (4 - (len(sig_str) % 4)) % 4
        sig_bytes = base64.urlsafe_b64decode(sig_str + ("=" * pad_len))
        pub.verify(sig_bytes, payload)
        return True
    except (InvalidSignature, ValueError, Exception):
        return False


def verify_taker_signature(taker_did: str, terms: TradeTerms | dict, sig_str: str) -> bool:
    """Verifies taker countersignature over close-1|accept|<terms>|<taker_did>."""
    try:
        pub = extract_public_key_from_did(taker_did)
        if isinstance(terms, TradeTerms):
            terms_json = terms.canonical_json()
        else:
            terms_json = json.dumps(terms, separators=(",", ":"), sort_keys=True)
        payload = f"close-1|accept|{terms_json}|{taker_did}".encode("utf-8")
        pad_len = (4 - (len(sig_str) % 4)) % 4
        sig_bytes = base64.urlsafe_b64decode(sig_str + ("=" * pad_len))
        pub.verify(sig_bytes, payload)
        return True
    except (InvalidSignature, ValueError, Exception):
        return False


def build_trade_envelope(
    terms: TradeTerms | dict,
    taker_did: str,
    maker_sig: str,
    taker_sig: str,
) -> dict:
    """Constructs the exact message payload broadcast into a registered trading room."""
    t_dict = terms.to_dict() if isinstance(terms, TradeTerms) else terms
    return {
        "t": "trade",
        "season": CONTEST_ID,
        "terms": t_dict,
        "taker": taker_did,
        "maker_sig": maker_sig,
        "taker_sig": taker_sig,
    }


def build_owner_message(did: str) -> dict:
    """Constructs owner registration payload: {"t":"owner","season":"close-1","key":did}."""
    return {
        "t": "owner",
        "season": CONTEST_ID,
        "key": did,
    }


def build_room_message(room_name: str) -> dict:
    """Constructs room registration payload: {"t":"room","season":"close-1","room":room_name}."""
    clean_room = room_name.lstrip("/")
    return {
        "t": "room",
        "season": CONTEST_ID,
        "room": clean_room,
    }


# ============================================================================
# 3. Local Fold & Pre-Flight Validation Engine
# ============================================================================

@dataclass
class MarketAnalysis:
    current_px: Decimal
    sweep_n: int
    htf_window: int
    ltf_window: int
    htf_trend: str              # "BULLISH", "BEARISH", "NEUTRAL"
    htf_change_pct: float
    htf_slope: float
    ltf_trend: str              # "BULLISH", "BEARISH", "NEUTRAL"
    ltf_change_pct: float
    ltf_slope: float
    regime: str                 # "ALIGNED_BULLISH", "ALIGNED_BEARISH", "BULLISH_PULLBACK", "BEARISH_RALLY", "LTF_MOMENTUM_BULLISH", "LTF_MOMENTUM_BEARISH", "NEUTRAL_RANGING"
    trend_score: float          # -1.0 to 1.0
    volatility_pct: float       # std dev of sweep returns in %
    volatility_usd: float       # std dev of sweep price changes in USD
    volatility_regime: str      # "LOW", "NORMAL", "HIGH", "EXTREME"
    vol_buffer: Decimal         # dynamic entry buffer in POLF
    dynamic_spread: Decimal     # volatility-adjusted quoting spread
    recommended_action: str     # "BUY_ONLY", "SELL_ONLY", "FAVOR_BUY", "FAVOR_SELL", "BOTH", "REDUCE_ONLY"
    has_history: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "current_px": str(self.current_px),
            "sweep_n": self.sweep_n,
            "htf_window": self.htf_window,
            "ltf_window": self.ltf_window,
            "htf_trend": self.htf_trend,
            "htf_change_pct": round(self.htf_change_pct, 4),
            "htf_slope": round(self.htf_slope, 4),
            "ltf_trend": self.ltf_trend,
            "ltf_change_pct": round(self.ltf_change_pct, 4),
            "ltf_slope": round(self.ltf_slope, 4),
            "regime": self.regime,
            "trend_score": round(self.trend_score, 4),
            "volatility_pct": round(self.volatility_pct, 4),
            "volatility_usd": round(self.volatility_usd, 4),
            "volatility_regime": self.volatility_regime,
            "vol_buffer": str(self.vol_buffer),
            "dynamic_spread": str(self.dynamic_spread),
            "recommended_action": self.recommended_action,
            "has_history": self.has_history,
        }


@dataclass
class AccountState:
    key: str
    cash: Decimal
    lots: list = field(default_factory=list)  # [qty, px] FIFO
    fees: Decimal = Decimal(0)

    @property
    def position(self) -> Decimal:
        return sum((q for q, _ in self.lots), Decimal(0))

    def opening(self, side: int, qty: Decimal) -> Decimal:
        """Contracts this trade opens rather than closes; side is +1 to buy, -1 to sell."""
        held = self.position
        closing = min(qty, max(-side * held, Decimal(0)))
        return qty - closing

    def apply(self, side: int, qty: Decimal, px: Decimal, fee: Decimal) -> None:
        self.cash -= fee
        self.fees += fee
        left = qty
        while left > 0 and self.lots and self.lots[0][0] * side < 0:
            lot_qty, lot_px = self.lots[0]
            size = min(left, abs(lot_qty))
            # Long lot sold returns sale price; short lot bought back returns collateral + diff
            self.cash += size * px if side < 0 else size * (2 * lot_px - px)
            left -= size
            if size == abs(lot_qty):
                self.lots.pop(0)
            else:
                self.lots[0][0] = lot_qty + side * size
        if left > 0:
            self.cash -= left * px  # Collateral tied up
            self.lots.append([side * left, px])

    def value_at(self, s: Decimal) -> Decimal:
        return self.cash + sum((q * s if q > 0 else -q * (2 * p - s) for q, p in self.lots), Decimal(0))


def compute_side_fees(
    side: int,
    qty: Decimal,
    px: Decimal,
    close_px: Decimal,
    fee_rate: Decimal = FEE_RATE,
) -> Tuple[Decimal, Decimal]:
    """Calculates exact (maker_fee, taker_fee) under the Clawback rule.
    side: +1 if maker is buy, -1 if maker is sell.
    Base fee = 1% of notional.
    Buyer pays max(base, gap) where gap = (close_px - px) * qty.
    Seller pays max(base, -gap) where -gap = (px - close_px) * qty.
    """
    base = fee_rate * qty * px
    gap = (close_px - px) * qty  # >0 if buyer got discount under close
    buyer_fee = max(base, gap)
    seller_fee = max(base, -gap)
    return (buyer_fee, seller_fee) if side > 0 else (seller_fee, buyer_fee)


class LocalFold:
    """Local simulation of referee sweep execution for pre-flight validation & auditing."""

    def __init__(
        self,
        mint: Decimal = DEFAULT_MINT,
        min_qty: Decimal = MIN_QTY,
        limit_window: Decimal = LIMIT_WINDOW,
        fee_rate: Decimal = FEE_RATE,
        lock_sweep: int = LOCK_SWEEP,
        prize_places: int = PRIZE_PLACES,
    ):
        self.mint = mint
        self.min_qty = min_qty
        self.window = limit_window
        self.fee_rate = fee_rate
        self.lock = lock_sweep
        self.places = prize_places
        self.accounts: Dict[str, AccountState] = {}
        self.settled: Set[str] = set()
        self.sweep_n = 0
        self.global_px: Optional[Decimal] = None
        self.final_px: Optional[Decimal] = None
        self.fees = Decimal(0)

    def seed(self, px: str) -> None:
        val = parse_amount(px)
        if val is None or self.global_px is not None:
            raise ValueError("seed: invalid opening price")
        self.global_px = val

    def check_trade(
        self,
        trade: dict,
        n: int,
        ref: Decimal,
        close: Decimal,
    ) -> Optional[str]:
        """Returns the void reason for a trade, or None if it settles."""
        if not isinstance(trade, dict):
            return "shape"
        maker = trade.get("maker")
        taker = trade.get("taker")
        signer = trade.get("countersigner")
        qty = parse_amount(trade.get("qty"))
        px = parse_amount(trade.get("px"))
        until = trade.get("until")

        if (
            not isinstance(trade.get("id"), str)
            or not TRADE_ID_REGEX.fullmatch(trade["id"])
            or trade.get("side") not in ("buy", "sell")
            or qty is None
            or px is None
            or type(until) is not int
            or not isinstance(maker, str)
            or not isinstance(signer, str)
            or not (taker == "any" or isinstance(taker, str))
        ):
            return "shape"

        if qty < self.min_qty:
            return "shape"

        if maker not in self.accounts or signer not in self.accounts:
            return "not_owner"

        if taker != "any" and taker != signer:
            return "taker"

        if trade["id"] in self.settled:
            return "settled"

        if n > until:
            return "expired"

        if n > self.lock:
            return "locked"

        if abs(px - ref) > self.window * ref:
            return "limits"

        side = 1 if trade["side"] == "buy" else -1
        mk_fee, tk_fee = compute_side_fees(side, qty, px, close, self.fee_rate)
        mk = self.accounts[maker]
        tk = self.accounts[signer]

        if mk is tk:
            if mk.cash < mk_fee + tk_fee:
                return "funds"
        elif (
            mk.cash < mk.opening(side, qty) * px + mk_fee
            or tk.cash < tk.opening(-side, qty) * px + tk_fee
        ):
            return "funds"

        return None

    def execute_sweep(
        self,
        n: int,
        ref_str: str,
        close_str: str,
        owners: List[str],
        trades: List[dict],
    ) -> dict:
        reference = parse_amount(ref_str)
        closing = parse_amount(close_str)
        if (
            self.global_px is None
            or reference is None
            or closing is None
            or not isinstance(n, int)
            or n <= self.sweep_n
        ):
            raise ValueError(f"sweep {n}: invalid parameters")

        self.sweep_n = n
        minted = []
        for key in owners:
            if isinstance(key, str) and is_valid_did(key) and key not in self.accounts and n <= self.lock:
                self.accounts[key] = AccountState(key, self.mint)
                minted.append(key)

        outcomes, volume, notional = [], Decimal(0), Decimal(0)
        for trade in trades:
            reason = self.check_trade(trade, n, reference, closing)
            tid = trade.get("id") if isinstance(trade, dict) else None
            if reason:
                outcomes.append({"id": tid, "outcome": "void", "reason": reason})
                continue

            qty = Decimal(trade["qty"])
            px = Decimal(trade["px"])
            side = 1 if trade["side"] == "buy" else -1
            mk_fee, tk_fee = compute_side_fees(side, qty, px, closing, self.fee_rate)
            mk = self.accounts[trade["maker"]]
            tk = self.accounts[trade["countersigner"]]

            if mk is tk:
                mk.cash -= mk_fee + tk_fee
                mk.fees += mk_fee + tk_fee
            else:
                mk.apply(side, qty, px, mk_fee)
                tk.apply(-side, qty, px, tk_fee)

            self.fees += mk_fee + tk_fee
            self.settled.add(trade["id"])
            volume += qty
            notional += qty * px
            outcomes.append({
                "id": tid,
                "outcome": "settled",
                "maker_fee": str(mk_fee),
                "taker_fee": str(tk_fee),
            })

        if volume:
            self.global_px = notional / volume

        return {
            "sweep": n,
            "reference": str(reference),
            "close": str(closing),
            "minted": minted,
            "trades": outcomes,
            "global_price": str(self.global_px.quantize(CENT)),
        }

    def final(self, px: str) -> dict:
        """Final settlement at closing price S with prize placement."""
        s = parse_amount(px)
        if s is None or self.final_px is not None:
            raise ValueError("final: expected one closing price with at most two decimals")
        self.final_px = s
        scores = {k: a.value_at(s) - self.mint for k, a in self.accounts.items()}
        order = sorted(scores, key=lambda k: (-scores[k], k))
        winners, place = {}, 0
        while place < min(self.places, len(order)):
            tied = [k for k in order if scores[k] == scores[order[place]]]
            spanned = list(range(place + 1, min(place + len(tied), self.places) + 1))
            for k in tied:
                winners[k] = (spanned, len(tied))
            place += len(tied)
        table = [
            {
                "key": k,
                "score": str(scores[k].quantize(Decimal("0.000001"))),
                "position": str(self.accounts[k].position),
                "fees": str(self.accounts[k].fees),
                "places": winners.get(k, ([], 0))[0],
                "sharing": winners.get(k, ([], 0))[1],
            }
            for k in order
        ]
        return {
            "S": str(s),
            "owners": len(order),
            "fees": str(self.fees),
            "zero_sum": str(sum(scores.values(), Decimal(0)) + self.fees),
            "standings": table,
        }


def replay_season(lines: List[str], config: Optional[dict] = None) -> dict:
    """Replay Close Call sweeps and final settlement matching close_call_fold."""
    cfg = config or {}
    fold = LocalFold(
        mint=Decimal(str(cfg.get("mint", DEFAULT_MINT))),
        min_qty=Decimal(str(cfg.get("min_qty", MIN_QTY))),
        limit_window=Decimal(str(cfg.get("limit_window", LIMIT_WINDOW))),
        fee_rate=Decimal(str(cfg.get("fee_rate", FEE_RATE))),
        lock_sweep=int(cfg.get("lock_sweep", LOCK_SWEEP)),
        prize_places=int(cfg.get("prize_places", PRIZE_PLACES)),
    )
    sweeps = []
    final_res = None
    with localcontext() as ctx:
        ctx.prec = PRECISION_CONTEXT
        for line in lines:
            line_str = line.strip()
            if not line_str:
                continue
            event = json.loads(line_str)
            k = event.get("t")
            if k == "seed":
                fold.seed(event.get("px"))
            elif k == "sweep":
                sweeps.append(fold.execute_sweep(
                    n=event.get("n"),
                    ref_str=event.get("ref"),
                    close_str=event.get("close"),
                    owners=event.get("owners", []),
                    trades=event.get("trades", []),
                ))
            elif k == "final":
                final_res = fold.final(event.get("px"))
    return {"sweeps": sweeps, "final": final_res}


def preflight_check(
    terms: TradeTerms | dict,
    taker_did: str,
    current_sweep: int,
    ref_px: Decimal,
    est_close_px: Optional[Decimal] = None,
    maker_account: Optional[AccountState] = None,
    taker_account: Optional[AccountState] = None,
    registered_owners: Optional[Set[str]] = None,
    settled_ids: Optional[Set[str]] = None,
) -> Tuple[bool, Optional[str], Dict[str, Any]]:
    """Comprehensive pre-flight risk & rule check before broadcasting any trade.
    Enforces all 8 void checks in strict canonical fold order:
    1. shape
    2. not_owner
    3. taker
    4. settled
    5. expired
    6. locked
    7. limits
    8. funds
    Returns: (is_valid, void_reason_or_none, telemetry_dict).
    """
    t_dict = terms.to_dict() if isinstance(terms, TradeTerms) else terms
    if not isinstance(t_dict, dict):
        return False, "shape", {"error": "Terms must be a dict"}

    t_id = t_dict.get("id")
    maker = t_dict.get("maker")
    side_str = t_dict.get("side")
    qty_str = t_dict.get("qty")
    px_str = t_dict.get("px")
    until = t_dict.get("until")
    taker_field = t_dict.get("taker")
    signer = t_dict.get("countersigner") or taker_did

    # 1. Shape check (format, steps, min_qty, valid DIDs, required fields)
    if (
        not isinstance(t_id, str)
        or not TRADE_ID_REGEX.fullmatch(t_id)
        or side_str not in ("buy", "sell")
        or type(until) is not int
        or until < 0
        or not isinstance(maker, str)
        or not is_valid_did(maker)
        or not isinstance(signer, str)
        or (signer != "any" and not is_valid_did(signer))
        or not (taker_field == "any" or (isinstance(taker_field, str) and is_valid_did(taker_field)))
    ):
        return False, "shape", {"error": "Malformed trade fields, missing taker, or invalid DID shape"}

    qty = parse_amount(qty_str)
    px = parse_amount(px_str)
    if qty is None or qty < MIN_QTY:
        return False, "shape", {"error": f"Quantity must be >= {MIN_QTY} with at most 2 decimals"}
    if px is None or px <= 0:
        return False, "shape", {"error": "Price must be positive with at most 2 decimals"}

    # 2. Not Owner check (if registered owners provided)
    if registered_owners is not None:
        if maker not in registered_owners:
            return False, "not_owner", {"error": f"Maker {maker} is not a registered owner"}
        if signer != "any" and signer not in registered_owners:
            return False, "not_owner", {"error": f"Countersigner {signer} is not a registered owner"}

    # 3. Taker check
    if taker_field != "any" and taker_field != signer:
        return False, "taker", {"error": f"Taker mismatch: terms specify {taker_field}, got {signer}"}

    # 4. Settled check (if settled IDs provided)
    if settled_ids is not None and t_id in settled_ids:
        return False, "settled", {"error": f"Trade ID '{t_id}' has already settled"}

    # 5. Expiry check
    if current_sweep > until:
        return False, "expired", {"error": f"Sweep {current_sweep} > until {until}"}

    # 6. Lock check
    if current_sweep > LOCK_SWEEP:
        return False, "locked", {"error": f"Sweep {current_sweep} > lock {LOCK_SWEEP}"}

    # 7. Limits check (5% window from referee reference price)
    min_px = ref_px * (Decimal("1") - LIMIT_WINDOW)
    max_px = ref_px * (Decimal("1") + LIMIT_WINDOW)
    if abs(px - ref_px) > LIMIT_WINDOW * ref_px:
        return False, "limits", {
            "error": f"Price {px} outside 5% band [{min_px:.2f}, {max_px:.2f}] (ref: {ref_px})",
            "ref_px": str(ref_px),
            "min_px": str(min_px),
            "max_px": str(max_px),
        }

    # 8. Fees and Clawback Analysis & Funds Check
    eval_close = est_close_px or px
    side_int = 1 if side_str == "buy" else -1
    mk_fee, tk_fee = compute_side_fees(side_int, qty, px, eval_close)

    telemetry = {
        "px": str(px),
        "qty": str(qty),
        "ref_px": str(ref_px),
        "est_close_px": str(eval_close),
        "maker_fee": str(mk_fee),
        "taker_fee": str(tk_fee),
        "min_allowed_px": str(min_px.quantize(CENT)),
        "max_allowed_px": str(max_px.quantize(CENT)),
        "notional": str((qty * px).quantize(CENT)),
    }

    # Check Funds: Handle Self-Trade vs Directional Trade
    is_self_trade = (maker == signer) or (maker_account is not None and maker_account is taker_account)
    if is_self_trade:
        # Rule 12: A trade with the same key on both sides pays both sides' fees and changes no position.
        needed_fee = mk_fee + tk_fee
        telemetry["self_trade"] = True
        telemetry["needed_cash"] = str(needed_fee)
        if maker_account is not None:
            telemetry["maker_free_cash"] = str(maker_account.cash)
            if maker_account.cash < needed_fee:
                return False, "funds", telemetry
    else:
        if maker_account is not None:
            mk_needed = maker_account.opening(side_int, qty) * px + mk_fee
            telemetry["maker_free_cash"] = str(maker_account.cash)
            telemetry["maker_needed_cash"] = str(mk_needed)
            if maker_account.cash < mk_needed:
                return False, "funds", telemetry

        if taker_account is not None:
            tk_needed = taker_account.opening(-side_int, qty) * px + tk_fee
            telemetry["taker_free_cash"] = str(taker_account.cash)
            telemetry["taker_needed_cash"] = str(tk_needed)
            if taker_account.cash < tk_needed:
                return False, "funds", telemetry

    return True, None, telemetry


# ============================================================================
# 4. Live Market Synchronizer & Network Client
# ============================================================================

CLOSE_CALL_STATE_FILE = "close_call_state.json"


def load_close_call_state() -> dict:
    """Load persistent Close Call state from disk."""
    return load_json_safe(CLOSE_CALL_STATE_FILE, {
        "registered": False,
        "did": "",
        "registration_sweep": None,
        "registration_room": "",
        "my_rooms": ["flop-nvda-desk"],
        "settled_ids": [],
        "trade_registry": {},
        "cash": str(DEFAULT_MINT),
        "lots": [],
        "fees": "0",
        "position": "0",
    })


def save_close_call_state(state: dict) -> None:
    """Atomically save persistent Close Call state to disk."""
    save_json_atomic(CLOSE_CALL_STATE_FILE, state)


class CloseCallClient:
    """Network client and state manager for Close Call on Technocore."""

    def __init__(
        self,
        base_url: str = "https://technocore.chat",
        identity_file: str = KEY_FILE,
    ):
        self.base_url = base_url.rstrip("/")
        self.priv, self.did = load_or_create_identity(identity_file)
        self.local_fold = LocalFold()
        self.fee_rate = FEE_RATE

        # Load local state
        st = load_close_call_state()
        self.registered_rooms: Set[str] = {PUBLIC_TRADING_ROOM} | set(st.get("my_rooms", []))
        self.settled_ids: Set[str] = set(st.get("settled_ids", []))
        self.void_ids: Dict[str, str] = {}
        self.recent_funds_void_makers: Set[str] = set()

    def get_my_account(self) -> AccountState:
        """Returns the local AccountState for our agent, loaded from state file."""
        st = load_close_call_state()
        cash = Decimal(str(st.get("cash", DEFAULT_MINT)))
        raw_lots = st.get("lots", [])
        lots = [[Decimal(str(q)), Decimal(str(p))] for q, p in raw_lots]
        fees = Decimal(str(st.get("fees", "0")))
        return AccountState(key=self.did, cash=cash, lots=lots, fees=fees)

    def save_my_account(self, acct: AccountState) -> None:
        """Saves local AccountState to persistent state."""
        st = load_close_call_state()
        st["cash"] = str(acct.cash)
        st["lots"] = [[str(q), str(p)] for q, p in acct.lots]
        st["fees"] = str(acct.fees)
        st["position"] = str(acct.position)
        save_close_call_state(st)

    def sync_referee_state(self) -> None:
        """Fetch latest flow events to sync all settled trade IDs, void reasons, and registered rooms."""
        flow_msgs = self.get_room_messages("d-close1-flow", limit=50)
        for m in flow_msgs:
            try:
                t = json.loads(m.get("text", "{}"))
                if not isinstance(t, dict) or t.get("t") != "flow":
                    continue
                for r in t.get("rooms", []):
                    self.registered_rooms.add(r)
                for sid in t.get("settled", []):
                    self.settled_ids.add(sid)
                for v in t.get("void", []):
                    if isinstance(v, list) and len(v) >= 2:
                        self.void_ids[v[0]] = v[1]
            except Exception:
                continue

    def get_flow_export(self) -> List[dict]:
        """Fetch the complete historical stream of all sweeps from d-close1-flow/export."""
        url = f"{self.base_url}/r/d-close1-flow/export"
        status, body = http_get(url, timeout=25)
        if status != 200:
            return []
        sweeps = []
        for line in body.splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            try:
                data = json.loads(line_str)
                t = json.loads(data["text"]) if "text" in data else data
                if isinstance(t, dict) and t.get("t") == "flow":
                    sweeps.append(t)
            except Exception:
                continue
        return sweeps

    def get_price_export(self) -> Dict[int, Decimal]:
        """Fetch all historical closing reference prices from d-close1-price/export."""
        url = f"{self.base_url}/r/d-close1-price/export"
        status, body = http_get(url, timeout=25)
        if status != 200:
            return {}
        prices: Dict[int, Decimal] = {}
        for line in body.splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            try:
                data = json.loads(line_str)
                t = json.loads(data["text"]) if "text" in data else data
                if isinstance(t, dict) and t.get("t") == "price":
                    sw_n = t.get("n")
                    px_str = t.get("ref", {}).get("px")
                    if sw_n is not None and px_str:
                        prices[int(sw_n)] = Decimal(str(px_str))
            except Exception:
                continue
        return prices

    def get_room_messages(
        self,
        room: str,
        limit: int = 50,
        since: Optional[int] = None,
    ) -> List[dict]:
        """Fetch JSON messages from a room."""
        params = ["format=json", f"limit={limit}"]
        if since is not None:
            params.append(f"since={since}")
        url = f"{self.base_url}/r/{room}?{'&'.join(params)}"
        status, body = http_get(url, timeout=20)
        if status != 200:
            logger.warning(f"Failed to fetch /r/{room} (HTTP {status})")
            return []
        try:
            data = json.loads(body)
            return data.get("messages", [])
        except Exception as e:
            logger.error(f"Error parsing JSON from /r/{room}: {e}")
            return []

    def get_latest_price_state(self) -> Optional[dict]:
        """Read the latest reference price post from d-close1-price."""
        msgs = self.get_room_messages("d-close1-price", limit=3)
        if not msgs:
            return None
        # Parse newest valid price message
        for m in reversed(msgs):
            try:
                t = json.loads(m.get("text", "{}"))
                if t.get("t") == "price" or "ref" in t:
                    return t
            except Exception:
                continue
        return None

    def get_latest_flow_state(self) -> Optional[dict]:
        """Read the latest flow post from d-close1-flow."""
        msgs = self.get_room_messages("d-close1-flow", limit=5)
        for m in reversed(msgs):
            try:
                t = json.loads(m.get("text", "{}"))
                if t.get("t") == "flow":
                    # Update registered rooms
                    for r in t.get("rooms", []):
                        self.registered_rooms.add(r)
                    for sid in t.get("settled", []):
                        self.settled_ids.add(sid)
                    return t
            except Exception:
                continue
        return None

    def get_latest_positions(self) -> Optional[dict]:
        """Read the latest open positions post from d-close1-positions."""
        msgs = self.get_room_messages("d-close1-positions", limit=3)
        for m in reversed(msgs):
            try:
                t = json.loads(m.get("text", "{}"))
                if t.get("t") == "positions":
                    return t
            except Exception:
                continue
        return None

    def get_latest_pnl(self) -> Optional[dict]:
        """Read the latest leaderboard post from d-close1-pnl."""
        msgs = self.get_room_messages("d-close1-pnl", limit=3)
        for m in reversed(msgs):
            try:
                t = json.loads(m.get("text", "{}"))
                if t.get("t") == "pnl":
                    return t
            except Exception:
                continue
        return None

    def get_all_registered_rooms(self) -> List[str]:
        """Scan d-close1-flow history to compile the full list of valid trading rooms."""
        msgs = self.get_room_messages("d-close1-flow", limit=50)
        rooms = {PUBLIC_TRADING_ROOM} | self.registered_rooms
        for m in msgs:
            try:
                t = json.loads(m.get("text", "{}"))
                for r in t.get("rooms", []):
                    rooms.add(r)
            except Exception:
                pass
        self.registered_rooms = rooms
        return sorted(list(rooms))

    def check_registration(self, did: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """Check if DID is registered and minted in Close-1.
        Returns: (is_registered, details_str).
        """
        check_did = did or self.did
        st = load_close_call_state()
        is_our_did = (check_did == self.did)

        # 1. Check pnl top ranks
        pnl = self.get_latest_pnl()
        if pnl:
            for rank, entry in enumerate(pnl.get("top", []), 1):
                if entry[0] == check_did:
                    if is_our_did:
                        st["registered"] = True
                        st["did"] = self.did
                        save_close_call_state(st)
                    return True, f"Minted & Active (Rank #{rank}, PnL {entry[1]} POLF)"

        # 2. Check recent flow mints
        flow = self.get_latest_flow_state()
        if flow and check_did in flow.get("mints", []):
            if is_our_did:
                st["registered"] = True
                st["did"] = self.did
                st["registration_sweep"] = flow.get("n")
                save_close_call_state(st)
            return True, f"Minted in Sweep #{flow.get('n')}"

        # 3. Check persistent registered state
        if is_our_did and st.get("registered"):
            reg_sw = st.get("registration_sweep")
            curr_sw = None
            if flow:
                curr_sw = flow.get("n")
            if reg_sw is not None and curr_sw is not None:
                if curr_sw >= reg_sw:
                    return True, f"Minted & Active (Registered in sweep #{reg_sw}, current sweep #{curr_sw})"
                else:
                    return False, f"Registered in sweep #{reg_sw}, awaiting next sweep mint"
            return True, f"Registered in {st.get('registration_room', 'close1')}, active"

        # 4. Check trading rooms for registration message
        for check_room in (PUBLIC_TRADING_ROOM, "flop-nvda-desk"):
            msgs = self.get_room_messages(check_room, limit=30)
            for m in msgs:
                try:
                    t = json.loads(m.get("text", "{}"))
                    if t.get("t") == "owner" and t.get("key") == check_did:
                        if is_our_did:
                            st["registered"] = True
                            st["did"] = self.did
                            st["registration_room"] = check_room
                            save_close_call_state(st)
                        return False, f"Registered in room {check_room}, awaiting next sweep mint (seq {m.get('seq')})"
                except Exception:
                    pass

        return False, "Not registered in close-1"

    def broadcast_message(self, room: str, text: str) -> Tuple[bool, str]:
        """Sign and broadcast a message to a Technocore room."""
        nonce = get_next_nonce(room)
        text_clean, sig = sign_message(self.priv, room, nonce, text)
        enc_text = urllib.parse.quote(text_clean)
        url = f"{self.base_url}/r/{room}/say-signed/{self.did}/{sig}/{nonce}/{enc_text}"
        status, body = http_get(url, timeout=25)
        if status in (200, 201):
            return True, f"HTTP {status}: Posted to /r/{room}"
        return False, f"HTTP {status}: {body.strip()}"

    def register_owner(self, room: str = PUBLIC_TRADING_ROOM) -> Tuple[bool, str]:
        """Broadcast owner registration: {"t":"owner","season":"close-1","key":did}."""
        payload = build_owner_message(self.did)
        msg_str = json.dumps(payload, separators=(",", ":"))
        ok, msg = self.broadcast_message(room, msg_str)
        if ok:
            st = load_close_call_state()
            st["registered"] = True
            st["did"] = self.did
            st["registration_room"] = room
            st["registered_at"] = time.time()
            price_state = self.get_latest_price_state()
            if price_state:
                st["registration_sweep"] = price_state.get("for", price_state.get("n", 0) + 1)
            save_close_call_state(st)
        return ok, msg

    def register_room(self, room_name: str, posting_room: str = PUBLIC_TRADING_ROOM) -> Tuple[bool, str]:
        """Register a new trading desk room: {"t":"room","season":"close-1","room":room_name}."""
        clean_room = room_name.lstrip("/")
        payload = build_room_message(clean_room)
        msg_str = json.dumps(payload, separators=(",", ":"))
        ok, msg = self.broadcast_message(posting_room, msg_str)
        if ok:
            st = load_close_call_state()
            my_rooms = st.get("my_rooms", [])
            if clean_room not in my_rooms:
                my_rooms.append(clean_room)
                st["my_rooms"] = my_rooms
                save_close_call_state(st)
            self.registered_rooms.add(clean_room)
        return ok, msg

    def post_maker_offer(
        self,
        side: str,
        qty: Decimal | str,
        px: Decimal | str,
        room: str = PUBLIC_TRADING_ROOM,
        taker: str = "any",
        until_sweeps_ahead: int = 12,
    ) -> Tuple[bool, str, Optional[dict]]:
        """Create, pre-flight check, sign, and post a maker trade offer.
        If taker is 'any', anyone can accept by countersigning.
        """
        price_state = self.get_latest_price_state()
        if not price_state:
            return False, "Cannot read referee price state", None

        curr_sweep = price_state.get("for", price_state.get("n", 0) + 1)
        ref_px = Decimal(price_state["ref"]["px"])
        until = curr_sweep + until_sweeps_ahead

        trade_id = f"flop_{int(time.time())}_{os.urandom(3).hex()}"
        terms = TradeTerms(
            id=trade_id,
            maker=self.did,
            px=format_amount(px),
            qty=format_amount(qty),
            side=side,
            taker=taker,
            until=until,
        )

        # Pre-flight check: validate terms for intended taker
        target_taker = taker if taker != "any" else "any"
        my_acct = self.get_my_account()
        valid, reason, telemetry = preflight_check(
            terms,
            taker_did=target_taker,
            current_sweep=curr_sweep,
            ref_px=ref_px,
            maker_account=my_acct,
            taker_account=my_acct if taker == self.did else None,
            settled_ids=self.settled_ids,
        )
        if not valid:
            return False, f"Pre-flight rejected ({reason}): {telemetry.get('error')}", telemetry

        # Sign maker terms
        maker_sig = sign_maker_terms(self.priv, terms)

        # Build appropriate message envelope
        if taker == self.did:
            # Self-trade: both signed by agent
            taker_sig = sign_taker_accept(self.priv, terms, self.did)
            trade_envelope = build_trade_envelope(
                terms=terms,
                taker_did=self.did,
                maker_sig=maker_sig,
                taker_sig=taker_sig,
            )
        elif taker == "any":
            # Standard Technocore open offer payload
            trade_envelope = {
                "t": "offer",
                "season": CONTEST_ID,
                "terms": terms.to_dict(),
                "maker_sig": maker_sig,
                "how": "countersign close-1|accept|<terms>|<your did:key> and post t=trade",
            }
        else:
            # Directed offer to specific counterparty
            trade_envelope = {
                "t": "offer",
                "season": CONTEST_ID,
                "terms": terms.to_dict(),
                "taker": taker,
                "maker_sig": maker_sig,
                "how": f"countersign close-1|accept|<terms>|{taker} and post t=trade",
            }

        msg_str = json.dumps(trade_envelope, separators=(",", ":"))
        ok, resp = self.broadcast_message(room, msg_str)
        if ok:
            st = load_close_call_state()
            tr = st.get("trade_registry", {})
            tr[terms.id] = {
                "terms": terms.to_dict(),
                "role": "maker",
                "room": room,
                "status": "open",
                "created_sweep": curr_sweep,
                "created_at": time.time(),
            }
            st["trade_registry"] = tr
            save_close_call_state(st)
        return ok, resp, trade_envelope

    def scan_open_offers(self, rooms: Optional[List[str]] = None, max_rooms: int = 25) -> List[dict]:
        """Scan rooms concurrently for executable open offers, filtering out settled/countersigned trades."""
        # 1. Sync referee flow to ensure self.settled_ids is fresh
        try:
            self.sync_referee_state()
        except Exception as e:
            logger.debug(f"Sync referee state notice: {e}")

        if rooms is None:
            all_r = self.get_all_registered_rooms()
            def room_priority(rm: str) -> int:
                if rm == PUBLIC_TRADING_ROOM:
                    return 0
                if "desk" in rm or "c1" in rm or "c2" in rm or "c3" in rm:
                    return 1
                return 2

            sorted_rooms = sorted(all_r, key=lambda r: (room_priority(r), r))
            scan_rooms = sorted_rooms[:max_rooms]
        else:
            scan_rooms = rooms

        price_state = self.get_latest_price_state()
        if not price_state:
            return []

        curr_sweep = price_state.get("for", price_state.get("n", 0) + 1)
        ref_px = Decimal(price_state["ref"]["px"])

        # 2. Fetch room messages in parallel
        def fetch_room(rm: str) -> Tuple[str, List[dict]]:
            return rm, self.get_room_messages(rm, limit=30)

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            room_batches = list(executor.map(fetch_room, scan_rooms))

        # 3. First pass across all fetched messages: identify all trade IDs already countersigned
        countersigned_ids = set()
        for rm, msgs in room_batches:
            for m in msgs:
                try:
                    data = json.loads(m.get("text", "{}"))
                    if isinstance(data, dict) and data.get("season") == CONTEST_ID:
                        if data.get("t") == "trade" and data.get("taker_sig"):
                            t_id = data.get("terms", {}).get("id")
                            if t_id:
                                countersigned_ids.add(t_id)
                except Exception:
                    pass

        # 4. Second pass: discover active open offers
        open_offers = []
        seen_offer_ids = set()

        for rm, msgs in room_batches:
            for m in msgs:
                try:
                    data = json.loads(m.get("text", "{}"))
                    if not isinstance(data, dict) or data.get("season") != CONTEST_ID:
                        continue

                    msg_type = data.get("t")
                    if msg_type not in ("offer", "trade"):
                        continue

                    terms = data.get("terms", {})
                    if not isinstance(terms, dict):
                        continue

                    t_id = terms.get("id")
                    if not t_id or t_id in self.settled_ids or t_id in countersigned_ids or t_id in seen_offer_ids:
                        continue

                    # If msg_type is 'trade' and already has taker_sig, it's not open
                    if msg_type == "trade" and data.get("taker_sig"):
                        continue

                    maker = terms.get("maker")
                    maker_sig = data.get("maker_sig")
                    taker_field = terms.get("taker", data.get("taker", "any"))

                    # Ignore our own offers
                    if not maker or maker == self.did:
                        continue

                    # Check taker target: must be 'any' or directed specifically to us
                    if taker_field not in ("any", "") and taker_field != self.did:
                        continue

                    # Verify maker signature
                    if not maker_sig or not verify_maker_signature(maker, terms, maker_sig):
                        continue

                    # Pre-flight check against current limits & expiry
                    valid, reason, telemetry = preflight_check(
                        terms=terms,
                        taker_did=self.did,
                        current_sweep=curr_sweep,
                        ref_px=ref_px,
                    )
                    if valid:
                        seen_offer_ids.add(t_id)
                        open_offers.append({
                            "room": rm,
                            "msg_seq": m.get("seq"),
                            "data": data,
                            "terms": terms,
                            "maker_sig": maker_sig,
                            "telemetry": telemetry,
                        })
                except Exception:
                    continue

        return open_offers

    def accept_and_execute_offer(
        self,
        offer_data: dict,
        posting_room: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Countersign an open offer as taker and broadcast the completed trade."""
        terms = offer_data.get("terms") or offer_data.get("data", {}).get("terms", {})
        maker_sig = offer_data.get("maker_sig") or offer_data.get("data", {}).get("maker_sig", "")
        maker = terms.get("maker")

        if not maker or not maker_sig:
            return False, "Malformed offer data: missing maker or signature"

        # 1. Verify maker signature
        if not verify_maker_signature(maker, terms, maker_sig):
            return False, "Invalid maker signature on offer"

        # 2. Run Pre-Flight Risk Check before signing
        price_state = self.get_latest_price_state()
        curr_sweep = 0
        ref_px = Decimal("225.00")
        if price_state:
            curr_sweep = price_state.get("for", price_state.get("n", 0) + 1)
            ref_px = Decimal(price_state["ref"]["px"])
            my_acct = self.get_my_account()
            valid, reason, telemetry = preflight_check(
                terms=terms,
                taker_did=self.did,
                current_sweep=curr_sweep,
                ref_px=ref_px,
                maker_account=my_acct if maker == self.did else None,
                taker_account=my_acct,
                settled_ids=self.settled_ids,
            )
            if not valid:
                return False, f"Pre-flight check failed ({reason}): {telemetry.get('error')}"

        # 3. Countersign as taker
        taker_sig = sign_taker_accept(self.priv, terms, self.did)

        # 4. Build completed trade envelope
        envelope = build_trade_envelope(
            terms=terms,
            taker_did=self.did,
            maker_sig=maker_sig,
            taker_sig=taker_sig,
        )

        # Prefer posting to offer's room, then dedicated room, then public room
        room = posting_room or offer_data.get("room") or PUBLIC_TRADING_ROOM
        msg_str = json.dumps(envelope, separators=(",", ":"))
        ok, resp = self.broadcast_message(room, msg_str)
        if ok and terms.get("id"):
            t_id = terms["id"]
            self.settled_ids.add(t_id)
            st = load_close_call_state()
            tr = st.get("trade_registry", {})
            tr[t_id] = {
                "terms": terms,
                "role": "taker",
                "room": room,
                "status": "submitted",
                "submitted_sweep": curr_sweep,
                "submitted_at": time.time(),
            }
            st["trade_registry"] = tr
            save_close_call_state(st)
        return ok, resp

    def compute_dynamic_order_size(
        self,
        side: int | str,  # +1 / 'buy' for buy, -1 / 'sell' for sell
        pos: Decimal,
        cash: Decimal,
        ref_px: Decimal,
        base_size: Decimal = DEFAULT_ORDER_SIZE,
        max_size: Decimal = MAX_DYNAMIC_ORDER_SIZE,
        max_inventory: Decimal = MAX_INVENTORY,
        min_cash_reserve: Decimal = Decimal("0.0"),
        volatility_regime: str = "NORMAL",
    ) -> Decimal:
        """Dynamically scale order size between 3.00 and 5.00 lots based on available cash,
        volatility regime, and position headroom up to max_inventory (15 lots).
        """
        # Normalize side to numeric +1 (buy) or -1 (sell)
        if isinstance(side, str):
            side_num = 1 if side.lower() in ("buy", "bid", "+1", "1") else -1
        else:
            side_num = 1 if side > 0 else -1

        # Inventory headroom
        headroom = (max_inventory - pos) if side_num > 0 else (max_inventory + pos)
        headroom = max(Decimal("0"), headroom)
        if headroom <= Decimal("0"):
            return Decimal("0.00")

        # Cash capacity for opening contracts
        avail_cash = max(Decimal("0"), cash - min_cash_reserve)
        contract_cost = ref_px * (Decimal("1") + FEE_RATE)
        cash_opening_lots = (avail_cash / contract_cost) if contract_cost > 0 else Decimal("0")
        closing_capacity = max(Decimal("0"), -pos if side_num > 0 else pos)
        total_cash_allowed = closing_capacity + cash_opening_lots
        if total_cash_allowed <= Decimal("0"):
            return Decimal("0.00")

        # Scale target size between 3.00 and 5.00 lots based on available cash, closing capacity & headroom
        if (closing_capacity >= Decimal("5.0") or (avail_cash >= Decimal("4000.0") and headroom >= Decimal("5.0"))) and volatility_regime in ("LOW", "NORMAL"):
            target = max_size  # 5.00 lots
        elif (closing_capacity >= Decimal("4.0") or (avail_cash >= Decimal("2000.0") and headroom >= Decimal("4.0"))) and volatility_regime in ("LOW", "NORMAL"):
            target = Decimal("4.00")  # 4.00 lots
        else:
            target = base_size  # 3.00 lots

        # Volatility adjustments to preserve risk in volatile conditions
        if volatility_regime == "HIGH":
            target = max(Decimal("1.00"), (target * Decimal("0.60")).quantize(CENT))
        elif volatility_regime == "EXTREME":
            target = Decimal("1.00")

        clamped = min(target, headroom, total_cash_allowed).quantize(CENT)
        return clamped if clamped >= MIN_QTY else Decimal("0.00")

    def post_skewed_quote(
        self,
        pos: Optional[Decimal] = None,
        spread: Optional[Decimal | str] = None,
        qty: Optional[Decimal | str] = None,
        room: str = "kc-c1-desk",
        until_sweeps_ahead: int = 12,
        analysis: Optional[MarketAnalysis] = None,
        max_inventory: Decimal = MAX_INVENTORY,
        base_qty: Optional[Decimal | str] = None,
        min_cash_reserve: Decimal = Decimal("5000.0"),
        cash: Optional[Decimal] = None,
    ) -> Dict[str, Any]:
        """Post market-making quotes skewed according to current inventory, trend, and volatility."""
        price_state = self.get_latest_price_state()
        if not price_state:
            return {"success": False, "error": "Cannot read referee price state"}
        ref_px = Decimal(price_state["ref"]["px"])

        # Resolve position and account cash
        my_acct = self.get_my_account()
        if pos is None:
            pos = my_acct.position
        if cash is None:
            cash = my_acct.cash

        # Support base_qty alias from dashboard API
        if qty is None and base_qty is not None:
            qty = base_qty

        results: Dict[str, Any] = {}

        # Roundtrip clawback fee clearance (2% of current price + net profit margin)
        min_fee_clearing_spread = (Decimal("2") * FEE_RATE * ref_px + MIN_PROFIT_MARGIN).quantize(CENT)

        # Effective spread: adapt dynamically to strictly clear roundtrip protocol clawback fees
        if analysis is not None:
            if spread is not None:
                effective_spread = max(Decimal(str(spread)), analysis.dynamic_spread)
            else:
                effective_spread = max(min_fee_clearing_spread, analysis.dynamic_spread)

            if analysis.htf_trend == "BULLISH" or analysis.regime in ("ALIGNED_BULLISH", "HTF_BULLISH_CONSOLIDATION"):
                trend_skew = Decimal("0.10")
            elif analysis.htf_trend == "BEARISH" or analysis.regime in ("ALIGNED_BEARISH", "HTF_BEARISH_CONSOLIDATION"):
                trend_skew = Decimal("-0.10")
            else:
                trend_skew = Decimal("0.00")
        else:
            if spread is not None:
                effective_spread = Decimal(str(spread))
            else:
                effective_spread = min_fee_clearing_spread
            trend_skew = Decimal("0.00")

        half_spread = (effective_spread / Decimal("2")).quantize(CENT)

        # Inventory-based pricing skew combined with trend skew
        # pos < 0 -> short inventory: quote aggressive bid to buy back, passive ask
        # pos > 0 -> long inventory: quote aggressive ask to sell off, passive bid
        # Note: skew_agg scales with half_spread so that total spread (skew_agg + skew_pass) strictly
        # clears roundtrip fee-clearing requirements rather than collapsing under inventory.
        skew_agg = max(CENT, half_spread - Decimal("0.25"))
        skew_pass = half_spread + Decimal("0.60")
        if pos < Decimal("-2.0"):
            bid_px = (ref_px - skew_agg + trend_skew).quantize(CENT)
            ask_px = (ref_px + skew_pass + trend_skew).quantize(CENT)
        elif pos > Decimal("2.0"):
            bid_px = (ref_px - skew_pass + trend_skew).quantize(CENT)
            ask_px = (ref_px + skew_agg + trend_skew).quantize(CENT)
        else:
            bid_px = (ref_px - half_spread + trend_skew).quantize(CENT)
            ask_px = (ref_px + half_spread + trend_skew).quantize(CENT)

        # Enforce Rule 11 (5% limit window) and positive price bounds
        limit_margin = (ref_px * LIMIT_WINDOW).quantize(CENT)
        min_limit = max(CENT, ref_px - limit_margin + CENT)
        max_limit = (ref_px + limit_margin - CENT).quantize(CENT)

        bid_px = max(min_limit, min(max_limit - CENT, bid_px))
        ask_px = max(bid_px + CENT, min(max_limit, ask_px))

        # Dynamic inventory limits and directional quoting gates
        if analysis is not None:
            if analysis.volatility_regime == "HIGH":
                dyn_max_inv = max_inventory * Decimal("0.6")
            elif analysis.volatility_regime == "EXTREME":
                dyn_max_inv = max_inventory * Decimal("0.3")
            else:
                dyn_max_inv = max_inventory
            vol_reg = analysis.volatility_regime
        else:
            dyn_max_inv = max_inventory
            vol_reg = "NORMAL"

        # Determine bid and ask order sizing:
        # Scale standard order size to 3.00-5.00 lots with dynamic sizing scaled to available cash
        # and position limits up to 15 lots.
        if qty is None:
            bid_qty = self.compute_dynamic_order_size(
                side=1, pos=pos, cash=cash, ref_px=ref_px,
                max_inventory=dyn_max_inv, min_cash_reserve=min_cash_reserve, volatility_regime=vol_reg,
            )
            ask_qty = self.compute_dynamic_order_size(
                side=-1, pos=pos, cash=cash, ref_px=ref_px,
                max_inventory=dyn_max_inv, min_cash_reserve=min_cash_reserve, volatility_regime=vol_reg,
            )
        else:
            req_qty = Decimal(str(qty)).quantize(CENT)
            headroom_bid = max(Decimal("0"), dyn_max_inv - pos)
            headroom_ask = max(Decimal("0"), dyn_max_inv + pos)
            bid_qty = min(req_qty, headroom_bid).quantize(CENT)
            ask_qty = min(req_qty, headroom_ask).quantize(CENT)

        allow_bid = True
        bid_reject_reason = ""
        allow_ask = True
        ask_reject_reason = ""

        if analysis is not None:
            # Extreme volatility: Reduce-only mode (only allow quotes that de-risk)
            if analysis.volatility_regime == "EXTREME" or analysis.recommended_action == "REDUCE_ONLY":
                if pos >= 0:
                    allow_bid = False
                    bid_reject_reason = "Extreme volatility (reduce-only: cannot open long)"
                if pos <= 0:
                    allow_ask = False
                    ask_reject_reason = "Extreme volatility (reduce-only: cannot open short)"

            # Directional trend gating: suppress quoting opening legs against strong trend
            if analysis.recommended_action == "SELL_ONLY" and pos >= 0:
                allow_bid = False
                bid_reject_reason = "Bearish regime (cannot open new long)"
            elif analysis.recommended_action == "BUY_ONLY" and pos <= 0:
                allow_ask = False
                ask_reject_reason = "Bullish regime (cannot open new short)"

        # Inventory boundaries: do not quote bids if inventory already at max long
        if pos >= dyn_max_inv:
            allow_bid = False
            bid_reject_reason = f"Inventory at or above max long ({pos} >= {dyn_max_inv})"
        if pos <= -dyn_max_inv:
            allow_ask = False
            ask_reject_reason = f"Inventory at or below max short ({pos} <= -{dyn_max_inv})"

        if bid_qty < MIN_QTY:
            allow_bid = False
            if not bid_reject_reason:
                bid_reject_reason = f"Bid quantity ({bid_qty}) below min qty {MIN_QTY}"

        if ask_qty < MIN_QTY:
            allow_ask = False
            if not ask_reject_reason:
                ask_reject_reason = f"Ask quantity ({ask_qty}) below min qty {MIN_QTY}"

        if allow_bid:
            ok_bid, msg_bid, env_bid = self.post_maker_offer(
                side="buy",
                qty=bid_qty,
                px=bid_px,
                room=room,
                until_sweeps_ahead=until_sweeps_ahead,
            )
            bid_id = env_bid.get("terms", {}).get("id") if (ok_bid and isinstance(env_bid, dict)) else None
            results["bid"] = {
                "success": ok_bid,
                "message": msg_bid,
                "px": str(bid_px),
                "qty": str(bid_qty),
                "id": bid_id,
            }
        else:
            results["bid"] = {
                "success": False,
                "message": bid_reject_reason,
                "px": str(bid_px),
                "qty": str(bid_qty),
                "id": None,
            }

        if allow_ask:
            ok_ask, msg_ask, env_ask = self.post_maker_offer(
                side="sell",
                qty=ask_qty,
                px=ask_px,
                room=room,
                until_sweeps_ahead=until_sweeps_ahead,
            )
            ask_id = env_ask.get("terms", {}).get("id") if (ok_ask and isinstance(env_ask, dict)) else None
            results["ask"] = {
                "success": ok_ask,
                "message": msg_ask,
                "px": str(ask_px),
                "qty": str(ask_qty),
                "id": ask_id,
            }
        else:
            results["ask"] = {
                "success": False,
                "message": ask_reject_reason,
                "px": str(ask_px),
                "qty": str(ask_qty),
                "id": None,
            }

        results["success"] = bool(results["bid"]["success"] or results["ask"]["success"])
        return results

    def post_two_sided_quote(
        self,
        spread: Optional[Decimal | str] = None,
        qty: Optional[Decimal | str] = None,
        room: str = "kc-c1-desk",
        until_sweeps_ahead: int = 12,
    ) -> Dict[str, Any]:
        """Post a symmetric two-sided maker market (bid & ask) around current reference price."""
        return self.post_skewed_quote(
            pos=Decimal(0),
            spread=spread,
            qty=qty,
            room=room,
            until_sweeps_ahead=until_sweeps_ahead,
        )

    def execute_offer_by_id(self, room: str, offer_id: str) -> Tuple[bool, str]:
        """Find an open offer by its unique ID in a room and execute countersignature."""
        open_offers = self.scan_open_offers([room])
        matching = [o for o in open_offers if o.get("terms", {}).get("id") == offer_id]
        if not matching:
            return False, f"Offer '{offer_id}' not found among open offers in /r/{room}"
        return self.accept_and_execute_offer(matching[0])

    def reconcile_with_referee(self) -> Dict[str, Any]:
        """Reconcile local state with authoritative referee flow and positions.
        Replays exact accounting from contest start over all confirmed settled trades.
        """
        self.sync_referee_state()
        st = load_close_call_state()
        tr = st.get("trade_registry", {})

        # 1. Harvest any trades involving our DID from active rooms (self-healing recovery)
        priority_rooms = ["kc-c1-desk", "flop-nvda-desk", PUBLIC_TRADING_ROOM] + list(st.get("my_rooms", []))
        search_rooms = list(dict.fromkeys(priority_rooms + list(self.registered_rooms)))
        for check_rm in search_rooms[:12]:
            msgs = self.get_room_messages(check_rm, limit=100)
            for m in msgs:
                try:
                    data = json.loads(m.get("text", "{}"))
                    if not isinstance(data, dict) or data.get("season") != CONTEST_ID:
                        continue
                    t_type = data.get("t")
                    terms = data.get("terms")
                    if not terms or not isinstance(terms, dict) or not terms.get("id"):
                        continue
                    t_id = terms["id"]
                    is_maker = (terms.get("maker") == self.did)
                    is_taker = (data.get("taker") == self.did or (m.get("from") == self.did and t_type == "trade"))
                    if (is_maker or is_taker) and t_id not in tr:
                        tr[t_id] = {
                            "terms": terms,
                            "role": "maker" if is_maker else "taker",
                            "room": check_rm,
                            "status": "submitted" if t_type == "trade" else "open",
                            "recovered": True,
                        }
                except Exception:
                    continue

        # 2. Fetch all historical sweeps and closing prices from exports
        flow_sweeps = self.get_flow_export()
        prices = self.get_price_export()

        if flow_sweeps:
            # Replay full accounting starting from starting cash (10,000 POLF)
            reconciled_acct = AccountState(key=self.did, cash=DEFAULT_MINT, lots=[], fees=Decimal("0"))
            confirmed_settled: List[str] = []
            voided_map: Dict[str, str] = {}

            for sw in flow_sweeps:
                sw_n = sw.get("n")
                close_px = prices.get(sw_n)
                if not close_px and sw.get("close"):
                    close_px = parse_amount(sw["close"])
                if not close_px:
                    close_px = Decimal("225.03")

                # Track voided trades
                for v in sw.get("void", []):
                    if isinstance(v, list) and len(v) >= 2:
                        voided_map[v[0]] = v[1]
                        if v[1] == "funds":
                            self.recent_funds_void_makers.add(v[0])

                # Process settled trades
                for tid in sw.get("settled", []):
                    self.settled_ids.add(tid)
                    if tid in tr:
                        entry = tr[tid]
                        t = entry["terms"]
                        maker_side_int = 1 if t.get("side") == "buy" else -1
                        our_side_int = maker_side_int if entry.get("role") == "maker" else -maker_side_int
                        qty = Decimal(str(t["qty"]))
                        px = Decimal(str(t["px"]))
                        mk_fee, tk_fee = compute_side_fees(maker_side_int, qty, px, close_px, self.fee_rate)
                        our_fee = mk_fee if entry.get("role") == "maker" else tk_fee

                        reconciled_acct.apply(our_side_int, qty, px, our_fee)
                        confirmed_settled.append(tid)
                        entry["status"] = "settled"
                        entry["settled_sweep"] = sw_n
                        entry["fee_paid"] = str(our_fee)

            # Mark void status on registered trades
            for tid, reason in voided_map.items():
                if tid in tr:
                    tr[tid]["status"] = "void"
                    tr[tid]["void_reason"] = reason

            st = load_close_call_state()
            st["cash"] = str(reconciled_acct.cash)
            st["lots"] = [[str(q), str(p)] for q, p in reconciled_acct.lots]
            st["fees"] = str(reconciled_acct.fees)
            st["position"] = str(reconciled_acct.position)
            st["settled_ids"] = confirmed_settled
            st["trade_registry"] = tr
            save_close_call_state(st)
            my_acct = reconciled_acct
        else:
            # Fallback to local state if offline or during unit tests
            my_acct = self.get_my_account()

        pos_state = self.get_latest_positions()
        pnl_state = self.get_latest_pnl()
        price_state = self.get_latest_price_state()

        report: Dict[str, Any] = {
            "did": self.did,
            "cash": str(my_acct.cash),
            "position": str(my_acct.position),
            "fees": str(my_acct.fees),
            "lots": [[str(q), str(p)] for q, p in my_acct.lots],
            "settled_count": len(st.get("settled_ids", [])),
            "trade_registry_count": len(tr),
        }
        if pos_state:
            report["referee_open_interest"] = pos_state.get("open")
        if pnl_state:
            report["referee_mark_price"] = pnl_state.get("mark")
        if price_state:
            report["ref_px"] = price_state.get("ref", {}).get("px")
        return report

    def analyze_market_trend(
        self,
        htf_window: int = 12,
        ltf_window: int = 3,
        price_history: Optional[Dict[int, Decimal]] = None,
        latest_price: Optional[Decimal] = None,
        current_sweep: Optional[int] = None,
        target_spread: Optional[Decimal | str] = None,
    ) -> MarketAnalysis:
        """Perform comprehensive multi-timeframe trend and volatility analysis on NVDA.
        - Higher Timeframe (HTF): macro trend & regime determination (default 12 sweeps = 1 hr).
        - Lower Timeframe (LTF): short-term momentum & entry timing (default 3 sweeps = 15 min).
        - Cross-timeframe behavior: checks how LTF behaves in HTF (aligned, pullback, rally).
        - Volatility: rolling returns variance, regime classification (LOW/NORMAL/HIGH/EXTREME),
          dynamic entry buffering, and volatility-scaled quoting spread.
        """
        # 1. Gather historical sweep prices
        history = price_history if price_history is not None else self.get_price_export()

        # 2. Resolve latest price and sweep
        curr_px = latest_price
        curr_sw = current_sweep
        if curr_px is None or curr_sw is None:
            pstate = self.get_latest_price_state()
            if pstate:
                if curr_px is None and "ref" in pstate and pstate["ref"].get("px"):
                    curr_px = Decimal(str(pstate["ref"]["px"]))
                if curr_sw is None:
                    curr_sw = pstate.get("for", pstate.get("n", 0) + 1)

        if curr_px is None:
            curr_px = Decimal("225.00")
        if curr_sw is None:
            curr_sw = max(history.keys(), default=0) + 1 if history else 1

        # 3. Assemble chronological price series (filtering out any future sweeps beyond curr_sw)
        series: List[Tuple[int, Decimal]] = [(sw, p) for sw, p in sorted(history.items(), key=lambda x: x[0]) if sw <= curr_sw] if history else []
        if not series or series[-1][0] < curr_sw:
            series.append((curr_sw, curr_px))
        elif series and series[-1][0] == curr_sw and curr_px is not None:
            series[-1] = (curr_sw, curr_px)

        prices: List[Decimal] = [p for _, p in series]

        # 4. Handle insufficient history (cold start, unit test mocks, or offline)
        if len(prices) < 2:
            min_fee_clearing_spread = (Decimal("2") * FEE_RATE * curr_px + MIN_PROFIT_MARGIN).quantize(CENT)
            eff_spread = Decimal(str(target_spread)).quantize(CENT) if target_spread is not None else min_fee_clearing_spread
            return MarketAnalysis(
                current_px=curr_px,
                sweep_n=curr_sw,
                htf_window=htf_window,
                ltf_window=ltf_window,
                htf_trend="NEUTRAL",
                htf_change_pct=0.0,
                htf_slope=0.0,
                ltf_trend="NEUTRAL",
                ltf_change_pct=0.0,
                ltf_slope=0.0,
                regime="NEUTRAL_RANGING",
                trend_score=0.0,
                volatility_pct=0.20,
                volatility_usd=0.45,
                volatility_regime="NORMAL",
                vol_buffer=Decimal("0.00"),
                dynamic_spread=eff_spread,
                recommended_action="BOTH",
                has_history=False,
            )

        # Helper: calculate linear regression slope across window
        def _calc_slope(vals: List[Decimal]) -> float:
            n = len(vals)
            if n < 2:
                return 0.0
            mean_x = (n - 1) / 2.0
            mean_y = float(sum(vals)) / n
            num = sum((i - mean_x) * (float(vals[i]) - mean_y) for i in range(n))
            den = sum((i - mean_x) ** 2 for i in range(n))
            return num / den if den != 0 else 0.0

        # 5. HTF Trend Analysis
        k_htf = min(len(prices), max(2, htf_window))
        htf_slice = prices[-k_htf:]
        p_start_htf, p_end_htf = htf_slice[0], htf_slice[-1]
        htf_change_pct = float((p_end_htf - p_start_htf) / p_start_htf * 100) if p_start_htf > 0 else 0.0
        htf_slope = _calc_slope(htf_slice)
        htf_sma = sum(htf_slice) / Decimal(str(k_htf))

        if htf_change_pct > 0.10 and p_end_htf >= htf_sma:
            htf_trend = "BULLISH"
        elif htf_change_pct < -0.10 and p_end_htf <= htf_sma:
            htf_trend = "BEARISH"
        else:
            htf_trend = "NEUTRAL"
        htf_score = max(-1.0, min(1.0, htf_change_pct / 0.50))

        # 6. LTF Trend Analysis
        k_ltf = min(len(prices), max(2, ltf_window))
        ltf_slice = prices[-k_ltf:]
        p_start_ltf, p_end_ltf = ltf_slice[0], ltf_slice[-1]
        ltf_change_pct = float((p_end_ltf - p_start_ltf) / p_start_ltf * 100) if p_start_ltf > 0 else 0.0
        ltf_slope = _calc_slope(ltf_slice)

        if ltf_change_pct > 0.05:
            ltf_trend = "BULLISH"
        elif ltf_change_pct < -0.05:
            ltf_trend = "BEARISH"
        else:
            ltf_trend = "NEUTRAL"
        ltf_score = max(-1.0, min(1.0, ltf_change_pct / 0.25))

        # 7. Multi-Timeframe Alignment & Regime Interaction (How LTF behaves in HTF)
        if htf_trend == "BULLISH" and ltf_trend == "BULLISH":
            regime = "ALIGNED_BULLISH"
            recommended_action = "BUY_ONLY"
        elif htf_trend == "BEARISH" and ltf_trend == "BEARISH":
            regime = "ALIGNED_BEARISH"
            recommended_action = "SELL_ONLY"
        elif htf_trend == "BULLISH" and ltf_trend == "BEARISH":
            regime = "BULLISH_PULLBACK"
            recommended_action = "FAVOR_BUY"
        elif htf_trend == "BEARISH" and ltf_trend == "BULLISH":
            regime = "BEARISH_RALLY"
            recommended_action = "FAVOR_SELL"
        elif htf_trend == "BULLISH" and ltf_trend == "NEUTRAL":
            regime = "HTF_BULLISH_CONSOLIDATION"
            recommended_action = "FAVOR_BUY"
        elif htf_trend == "BEARISH" and ltf_trend == "NEUTRAL":
            regime = "HTF_BEARISH_CONSOLIDATION"
            recommended_action = "FAVOR_SELL"
        elif htf_trend == "NEUTRAL" and ltf_trend == "BULLISH":
            regime = "LTF_MOMENTUM_BULLISH"
            recommended_action = "FAVOR_BUY"
        elif htf_trend == "NEUTRAL" and ltf_trend == "BEARISH":
            regime = "LTF_MOMENTUM_BEARISH"
            recommended_action = "FAVOR_SELL"
        else:
            regime = "NEUTRAL_RANGING"
            recommended_action = "BOTH"

        trend_score = (0.6 * htf_score) + (0.4 * ltf_score)

        # 8. Volatility Analysis
        vol_lookback = min(len(prices), 20)
        recent_prices = prices[-vol_lookback:]
        returns: List[float] = []
        dollar_diffs: List[float] = []
        for i in range(1, len(recent_prices)):
            p_prev, p_curr = recent_prices[i - 1], recent_prices[i]
            if p_prev > 0:
                ret = float((p_curr - p_prev) / p_prev * 100)
                returns.append(ret)
                dollar_diffs.append(float(p_curr - p_prev))

        if len(returns) >= 2:
            mean_r = sum(returns) / len(returns)
            var_r = sum((r - mean_r) ** 2 for r in returns) / (len(returns) - 1)
            volatility_pct = math.sqrt(max(0.0, var_r))

            mean_d = sum(dollar_diffs) / len(dollar_diffs)
            var_d = sum((d - mean_d) ** 2 for d in dollar_diffs) / (len(dollar_diffs) - 1)
            volatility_usd = math.sqrt(max(0.0, var_d))
        else:
            volatility_pct = 0.20
            volatility_usd = 0.45

        # Volatility Regime
        if volatility_pct < 0.15:
            volatility_regime = "LOW"
        elif volatility_pct < 0.40:
            volatility_regime = "NORMAL"
        elif volatility_pct < 0.80:
            volatility_regime = "HIGH"
        else:
            volatility_regime = "EXTREME"

        if volatility_regime == "EXTREME":
            recommended_action = "REDUCE_ONLY"

        # Dynamic Entry Buffer
        if volatility_regime == "LOW":
            vol_buffer = Decimal("0.00")
        else:
            raw_buf = float(curr_px) * (volatility_pct / 100.0) * 0.25
            clamped_buf = min(0.50, max(0.00, raw_buf))
            vol_buffer = Decimal(f"{clamped_buf:.2f}").quantize(CENT)

        # Dynamic Quoting Spread: strictly clear roundtrip protocol clawback fees (2% + net profit margin)
        min_fee_clearing_spread = (Decimal("2") * FEE_RATE * curr_px + MIN_PROFIT_MARGIN).quantize(CENT)
        if target_spread is not None:
            base_spr = Decimal(str(target_spread)).quantize(CENT)
        else:
            base_spr = min_fee_clearing_spread

        raw_vol_spr = float(curr_px) * (volatility_pct / 100.0) * 2.0
        vol_spr = Decimal(f"{raw_vol_spr:.2f}").quantize(CENT)
        dynamic_spread = max(base_spr, vol_spr)

        return MarketAnalysis(
            current_px=curr_px,
            sweep_n=curr_sw,
            htf_window=htf_window,
            ltf_window=ltf_window,
            htf_trend=htf_trend,
            htf_change_pct=htf_change_pct,
            htf_slope=htf_slope,
            ltf_trend=ltf_trend,
            ltf_change_pct=ltf_change_pct,
            ltf_slope=ltf_slope,
            regime=regime,
            trend_score=trend_score,
            volatility_pct=volatility_pct,
            volatility_usd=volatility_usd,
            volatility_regime=volatility_regime,
            vol_buffer=vol_buffer,
            dynamic_spread=dynamic_spread,
            recommended_action=recommended_action,
            has_history=True,
        )

    def evaluate_trade_entry(
        self,
        offer: dict,
        pos: Decimal,
        cash: Decimal,
        ref_px: Decimal,
        analysis: MarketAnalysis,
        max_inventory: Decimal = Decimal("15.0"),
        min_cash_reserve: Decimal = Decimal("5000.0"),
        base_discount: Decimal = Decimal("0.05"),
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """Evaluate an open counterparty offer before executing entry:
        1. Validates terms syntax, positive quantity, price, and active sweep window.
        2. Filters out counterparties that recently voided for funds (clawback safety).
        3. Enforces 5% Limit bands around reference price (Rule 11).
        4. Calculates inventory transition and identifies closing vs opening trades.
        5. Enforces cash reserve requirements.
        6. Dynamic inventory caps adjusted for current volatility regime.
        7. Multi-timeframe trend alignment gate (prevents adverse directional risk).
        8. Dynamic volatility buffer on entry pricing.
        """
        terms = offer.get("terms", {})
        o_side = terms.get("side")
        o_qty = parse_amount(terms.get("qty", "0")) or Decimal("0")
        o_px = parse_amount(terms.get("px", "0")) or Decimal("0")
        o_id = terms.get("id")
        maker_did = terms.get("maker")

        if not o_id or o_qty <= 0 or o_px <= 0:
            return False, "Invalid terms: missing id or non-positive qty/px", {}

        # 1. Skip makers that voided for funds recently
        if maker_did in self.recent_funds_void_makers:
            return False, f"Maker {maker_did} recently voided for funds", {}

        # 2. Check 5% limit window (Rule 11)
        min_limit = (ref_px * (Decimal("1") - LIMIT_WINDOW)).quantize(CENT)
        max_limit = (ref_px * (Decimal("1") + LIMIT_WINDOW)).quantize(CENT)
        if o_px < min_limit or o_px > max_limit:
            return False, f"Price ${o_px} outside 5% limits [${min_limit} .. ${max_limit}]", {}

        # 3. Determine Taker Side: counterparty buys -> taker sells; counterparty sells -> taker buys
        taker_side_int = -1 if o_side == "buy" else 1
        closing_direction = (pos > 0 and taker_side_int < 0) or (pos < 0 and taker_side_int > 0)
        closing_qty = min(o_qty, abs(pos)) if closing_direction else Decimal("0")
        opening_qty = o_qty - closing_qty
        is_pure_closing = closing_direction and (opening_qty == Decimal("0"))
        new_pos = pos + (taker_side_int * o_qty)

        # 4. Cash reserve and collateral check
        est_fee = o_qty * o_px * FEE_RATE
        needed_collateral = opening_qty * o_px + est_fee
        if is_pure_closing:
            if cash < est_fee:
                return False, f"Insufficient cash to cover closing fee ({cash} < {est_fee})", {}
        else:
            if (cash - needed_collateral) < min_cash_reserve:
                return False, f"Insufficient cash reserve ({cash - needed_collateral} < {min_cash_reserve})", {}

        # 5. Dynamic Inventory Limit based on Volatility
        if analysis.volatility_regime == "HIGH":
            dyn_max_inv = max_inventory * Decimal("0.6")
        elif analysis.volatility_regime == "EXTREME":
            dyn_max_inv = max_inventory * Decimal("0.3")
        else:
            dyn_max_inv = max_inventory

        # If trade opens or expands inventory (opening_qty > 0), enforce dynamic inventory cap
        if opening_qty > 0 and abs(new_pos) > dyn_max_inv:
            return False, f"Position {new_pos} exceeds dynamic inventory cap {dyn_max_inv} ({analysis.volatility_regime} vol)", {}

        diff = o_px - ref_px

        # 6. Evaluation Logic: Pure Closing Position vs Opening/Expanding Exposure
        if is_pure_closing:
            # Pure closing trades de-risk existing exposure
            if taker_side_int > 0:  # Closing short: our agent BUYs back
                max_diff = Decimal("0.30") if analysis.htf_trend == "BULLISH" else (Decimal("0.05") if analysis.htf_trend == "BEARISH" else Decimal("0.15"))
                if diff > max_diff:
                    return False, f"Closing short: price diff +${diff} exceeds tolerance +${max_diff}", {}
            else:  # Closing long: our agent SELLs off
                min_diff = Decimal("-0.30") if analysis.htf_trend == "BEARISH" else (Decimal("-0.05") if analysis.htf_trend == "BULLISH" else Decimal("-0.15"))
                if diff < min_diff:
                    return False, f"Closing long: price diff ${diff} below tolerance ${min_diff}", {}
        else:
            # OPENING OR FLIPPING POSITION (opening_qty > 0): strict MTF trend and volatility filtering
            # A. Extreme Volatility Circuit Breaker: protect against clawback traps
            if analysis.volatility_regime == "EXTREME" or analysis.recommended_action == "REDUCE_ONLY":
                return False, "Blocked: Extreme volatility (protecting against clawback risk)", {}

            # B. Multi-Timeframe Trend Gate
            if taker_side_int > 0:  # Taker BUY (Opening Long)
                if (
                    analysis.htf_trend == "BEARISH"
                    or analysis.regime in ("ALIGNED_BEARISH", "BEARISH_RALLY", "HTF_BEARISH_CONSOLIDATION", "LTF_MOMENTUM_BEARISH")
                    or analysis.recommended_action in ("SELL_ONLY", "REDUCE_ONLY")
                ):
                    return False, f"Trend filter: cannot open LONG when market is {analysis.regime} (HTF {analysis.htf_trend})", {}
            else:  # Taker SELL (Opening Short)
                if (
                    analysis.htf_trend == "BULLISH"
                    or analysis.regime in ("ALIGNED_BULLISH", "BULLISH_PULLBACK", "HTF_BULLISH_CONSOLIDATION", "LTF_MOMENTUM_BULLISH")
                    or analysis.recommended_action in ("BUY_ONLY", "REDUCE_ONLY")
                ):
                    return False, f"Trend filter: cannot open SHORT when market is {analysis.regime} (HTF {analysis.htf_trend})", {}

            # C. Dynamic Pricing & Volatility Buffer
            req_discount = (base_discount + analysis.vol_buffer).quantize(CENT)
            if taker_side_int > 0:  # Taker BUY: must buy at a discount
                price_edge = -diff
                if diff > -req_discount:
                    return False, f"Pricing: BUY requires at least ${req_discount} discount (diff: ${diff})", {}
            else:  # Taker SELL: must sell at a premium
                price_edge = diff
                if diff < req_discount:
                    return False, f"Pricing: SELL requires at least ${req_discount} premium (diff: ${diff})", {}

            # D. Expected Profit & Roundtrip Protocol Clawback Fee Clearance Gate
            # Under Rule 6, roundtrip transaction fee drag is ~2% of notional (1% on entry, 1% on exit).
            # Opening fills must have expected gross profit that strictly clears the roundtrip fee.
            rt_fee = (Decimal("2") * FEE_RATE * ref_px).quantize(CENT)
            directional_slope = Decimal(str(round(analysis.htf_slope, 4))) * Decimal(str(taker_side_int))
            trend_gain = (max(Decimal("0.00"), directional_slope) * Decimal(str(analysis.htf_window))).quantize(CENT)
            half_spread = (analysis.dynamic_spread / Decimal("2")).quantize(CENT)
            expected_gross = (price_edge + trend_gain + half_spread).quantize(CENT)
            expected_net = (expected_gross - rt_fee).quantize(CENT)

            # Strictly enforce roundtrip clawback fee clearance whenever market price history is available
            if getattr(analysis, "has_history", False):
                if expected_net < Decimal("0"):
                    return False, f"Clawback fee filter: expected profit ${expected_gross} fails to clear roundtrip clawback fees ${rt_fee} (expected net: ${expected_net})", {}

        return True, "Trade entry approved", {
            "side": "buy" if taker_side_int > 0 else "sell",
            "is_closing": is_pure_closing,
            "closing_qty": str(closing_qty),
            "opening_qty": str(opening_qty),
            "new_pos": str(new_pos),
            "needed_collateral": str(needed_collateral),
            "diff": str(diff),
            "req_discount": str(req_discount) if not is_pure_closing else "0.00",
            "expected_gross_profit": str(expected_gross) if not is_pure_closing else "0.00",
            "expected_net_profit": str(expected_net) if not is_pure_closing else "0.00",
            "roundtrip_fee": str(rt_fee) if not is_pure_closing else "0.00",
        }

    def run_trading_cycle(
        self,
        max_inventory: Decimal = MAX_INVENTORY,
        min_cash_reserve: Decimal = Decimal("5000.0"),
        target_spread: Optional[Decimal | str] = None,
        quote_qty: Optional[Decimal | str] = None,
        desk_rooms: Optional[List[str]] = None,
        max_trades_per_cycle: int = 2,
        htf_window: int = 12,
        ltf_window: int = 3,
        target_room: Optional[str] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Execute one autonomous trading cycle:
        1. Synchronize & reconcile with referee flow.
        2. Analyze multi-timeframe stock trend (HTF vs LTF) and volatility regime.
        3. Score & filter open counterparty offers with trend alignment and dynamic buffers.
        4. Execute validated opportunistic entries before sweep closes.
        5. Maintain boosted inventory- and trend-skewed maker quotes with dynamic spread.
        6. Persist state and return execution telemetry.
        """
        # 1. Authoritative reconciliation before taking any decisions
        try:
            recon = self.reconcile_with_referee()
        except Exception as e_recon:
            logger.debug(f"Reconciliation warning: {e_recon}")

        price_state = self.get_latest_price_state()
        if not price_state:
            return {"success": False, "error": "Unable to read referee price"}

        ref_px = Decimal(price_state["ref"]["px"])
        curr_sweep = price_state.get("for", price_state.get("n", 0) + 1)
        my_acct = self.get_my_account()
        pos = my_acct.position
        cash = my_acct.cash

        # Resolve target spread to strictly clear roundtrip fees if not explicitly set
        rt_fee = (Decimal("2") * FEE_RATE * ref_px).quantize(CENT)
        fee_clearing_spread = (rt_fee + MIN_PROFIT_MARGIN).quantize(CENT)
        effective_spread = Decimal(str(target_spread)).quantize(CENT) if target_spread is not None else fee_clearing_spread

        # 2. Multi-Timeframe Trend & Volatility Analysis
        analysis = self.analyze_market_trend(
            htf_window=htf_window,
            ltf_window=ltf_window,
            latest_price=ref_px,
            current_sweep=curr_sweep,
            target_spread=effective_spread,
        )

        cycle_result: Dict[str, Any] = {
            "sweep": curr_sweep,
            "ref_px": str(ref_px),
            "initial_position": str(pos),
            "initial_cash": str(cash),
            "market_analysis": analysis.to_dict(),
            "executed_trades": [],
            "posted_quotes": [],
            "rejected_offers": [],
            "errors": [],
        }

        # Select trading rooms (prioritizing active desks)
        raw_rooms = [target_room] if target_room else []
        for r in (desk_rooms or ["kc-c1-desk", "close1", "boz-desk", "jh-nvda-desk"]):
            if r not in raw_rooms:
                raw_rooms.append(r)
        existing_rooms = set(self.get_all_registered_rooms())
        scan_rooms = [r for r in raw_rooms if r in existing_rooms]
        if not scan_rooms:
            scan_rooms = [target_room] if target_room else [PUBLIC_TRADING_ROOM]

        # Scan for open counterparty offers
        open_offers = self.scan_open_offers(scan_rooms)
        executed_count = 0

        # Sort offers: prioritize inventory reduction, trend alignment, and price advantage
        def score_offer(o: dict) -> float:
            terms = o.get("terms", {})
            o_side = terms.get("side")
            o_px = parse_amount(terms.get("px", "0")) or Decimal("0")
            taker_side = -1 if o_side == "buy" else 1
            closing = (pos > 0 and taker_side < 0) or (pos < 0 and taker_side > 0)
            bonus = 100.0 if closing else 0.0

            trend_bonus = 0.0
            if analysis.regime == "ALIGNED_BULLISH" and taker_side > 0:
                trend_bonus = 50.0
            elif analysis.regime == "BULLISH_PULLBACK" and taker_side > 0:
                trend_bonus = 60.0  # Buy the dip
            elif analysis.regime == "HTF_BULLISH_CONSOLIDATION" and taker_side > 0:
                trend_bonus = 40.0
            elif analysis.regime == "LTF_MOMENTUM_BULLISH" and taker_side > 0:
                trend_bonus = 30.0
            elif analysis.regime == "ALIGNED_BEARISH" and taker_side < 0:
                trend_bonus = 50.0
            elif analysis.regime == "BEARISH_RALLY" and taker_side < 0:
                trend_bonus = 60.0  # Sell the rip
            elif analysis.regime == "HTF_BEARISH_CONSOLIDATION" and taker_side < 0:
                trend_bonus = 40.0
            elif analysis.regime == "LTF_MOMENTUM_BEARISH" and taker_side < 0:
                trend_bonus = 30.0

            # Penalize counter-trend entries
            if taker_side > 0 and (analysis.htf_trend == "BEARISH" or "BEARISH" in analysis.regime):
                trend_bonus -= 50.0
            elif taker_side < 0 and (analysis.htf_trend == "BULLISH" or "BULLISH" in analysis.regime):
                trend_bonus -= 50.0

            price_score = float(ref_px - o_px) if taker_side > 0 else float(o_px - ref_px)
            # Roundtrip fee clearance incentive
            roundtrip_fee_flt = float(ref_px * Decimal("0.02"))
            expected_gross_flt = price_score + float(analysis.dynamic_spread / Decimal("2"))
            fee_bonus = 25.0 if (closing or expected_gross_flt >= roundtrip_fee_flt) else -25.0

            return bonus + trend_bonus + (price_score * 10.0) + fee_bonus

        open_offers.sort(key=score_offer, reverse=True)

        for offer in open_offers:
            if executed_count >= max_trades_per_cycle:
                break

            ok_entry, entry_reason, entry_meta = self.evaluate_trade_entry(
                offer=offer,
                pos=pos,
                cash=cash,
                ref_px=ref_px,
                analysis=analysis,
                max_inventory=max_inventory,
                min_cash_reserve=min_cash_reserve,
            )

            o_id = offer.get("terms", {}).get("id", "unknown")
            if not ok_entry:
                cycle_result["rejected_offers"].append({"id": o_id, "reason": entry_reason})
                continue

            ok_exec, exec_msg = self.accept_and_execute_offer(offer)
            if ok_exec:
                executed_count += 1
                cycle_result["executed_trades"].append({
                    "id": o_id,
                    "room": offer.get("room"),
                    "side": entry_meta.get("side"),
                    "qty": str(offer.get("terms", {}).get("qty")),
                    "px": str(offer.get("terms", {}).get("px")),
                    "closing": entry_meta.get("is_closing"),
                    "result": exec_msg,
                    "expected_net_profit": entry_meta.get("expected_net_profit", "0.00"),
                })
                # Update running position and cash for subsequent evaluations and quotes in this cycle
                pos = Decimal(entry_meta["new_pos"])
                cash = cash - Decimal(entry_meta["needed_collateral"])
            else:
                cycle_result["errors"].append(f"Failed to execute offer {o_id}: {exec_msg}")

        # Market-making: post boosted quotes skewed by inventory + trend + volatility
        primary_desk = scan_rooms[0] if scan_rooms else "kc-c1-desk"
        if cash > min_cash_reserve or abs(pos) >= MIN_QTY:
            quote_res = self.post_skewed_quote(
                pos=pos,
                spread=effective_spread,
                qty=quote_qty,
                room=primary_desk,
                until_sweeps_ahead=12,
                analysis=analysis,
                max_inventory=max_inventory,
                min_cash_reserve=min_cash_reserve,
                cash=cash,
            )
            if quote_res.get("success") or quote_res.get("bid", {}).get("message") or quote_res.get("ask", {}).get("message"):
                cycle_result["posted_quotes"].append(quote_res)

        my_acct = self.get_my_account()
        cycle_result["final_position"] = str(pos)
        cycle_result["final_cash"] = str(cash)
        cycle_result["fees_paid"] = str(my_acct.fees)
        cycle_result["success"] = True
        return cycle_result


# ============================================================================
# 5. CLI Interface & Diagnostic Command Runner
# ============================================================================

def format_telemetry_banner(client: CloseCallClient) -> str:
    """Renders formatted console banner of current Close Call competition telemetry."""
    price_state = client.get_latest_price_state()
    positions_state = client.get_latest_positions()
    pnl_state = client.get_latest_pnl()
    flow_state = client.get_latest_flow_state()
    is_reg, reg_info = client.check_registration()

    lines = [
        "=" * 68,
        "  [CLOSE-1] TECHNOCORE CLOSE CALL CHALLENGE LIVE MONITOR",
        "=" * 68,
        f"Agent DID:       {client.did}",
        f"Status:          {reg_info}",
    ]

    if price_state:
        ref = price_state.get("ref", {})
        limits = price_state.get("limits", ["-", "-"])
        lines.extend([
            "-" * 68,
            f"Sweep:           #{price_state.get('n', '-')} (Applied: #{price_state.get('for', '-')})",
            f"NVDA Reference:  ${ref.get('px', '-')} (TID: {ref.get('tid', '-')})",
            f"Global VWAP:     ${price_state.get('global', '-')}",
            f"5% Price Bands:  [${limits[0]} .. ${limits[1]}]",
        ])

    if positions_state:
        lines.extend([
            "-" * 68,
            f"Open Contracts:  {positions_state.get('open', '-')} (Longs: {positions_state.get('longs', '-')}, Shorts: {positions_state.get('shorts', '-')})",
        ])

    if pnl_state:
        mark = pnl_state.get("mark", "-")
        top_entries = pnl_state.get("top", [])[:5]
        lines.extend([
            f"Mark Price:      ${mark}",
            f"Top Leaderboard: {', '.join([f'{k[:16]}...: {v} POLF' for k, v in top_entries])}",
        ])

    try:
        analysis = client.analyze_market_trend()
        lines.extend([
            "-" * 68,
            f"Market Trend:    HTF: {analysis.htf_trend} ({analysis.htf_change_pct:+.2f}%) | LTF: {analysis.ltf_trend} ({analysis.ltf_change_pct:+.2f}%)",
            f"MTF Regime:      {analysis.regime} (Score: {analysis.trend_score:+.2f} | Action: {analysis.recommended_action})",
            f"Volatility:      {analysis.volatility_regime} ({analysis.volatility_pct:.2f}% | Buffer: ${analysis.vol_buffer} | Spread: ${analysis.dynamic_spread})",
        ])
    except Exception as e_banner:
        logger.debug(f"Banner trend analysis note: {e_banner}")

    rooms = client.get_all_registered_rooms()
    lines.extend([
        "-" * 68,
        f"Registered Rooms ({len(rooms)}): {', '.join(rooms[:8])}{'...' if len(rooms) > 8 else ''}",
        "=" * 68,
    ])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Technocore Close Call Challenge Trading Client")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Status
    subparsers.add_parser("status", help="Print live contest telemetry and agent balance")

    # Register
    reg_parser = subparsers.add_parser("register", help="Register agent owner key in close1")
    reg_parser.add_argument("--room", default=PUBLIC_TRADING_ROOM, help="Room to register in")

    # Register Room
    room_parser = subparsers.add_parser("register-room", help="Register a new trading desk room")
    room_parser.add_argument("name", help="Room name to register")
    room_parser.add_argument("--in-room", default=PUBLIC_TRADING_ROOM, help="Room to post registration in")

    # Offer
    offer_parser = subparsers.add_parser("offer", help="Create and broadcast a signed maker offer")
    offer_parser.add_argument("--side", choices=["buy", "sell"], required=True, help="Order side")
    offer_parser.add_argument("--qty", required=True, help="Quantity of NVDA contracts (>= 0.1)")
    offer_parser.add_argument("--px", required=True, help="Price per contract in POLF")
    offer_parser.add_argument("--room", default=PUBLIC_TRADING_ROOM, help="Trading room")
    offer_parser.add_argument("--taker", default="any", help="Taker DID or 'any'")
    offer_parser.add_argument("--until", type=int, default=12, help="Sweeps ahead to expire")

    # Scan
    subparsers.add_parser("scan", help="Scan registered rooms for countersignable open offers")

    # Quote
    quote_parser = subparsers.add_parser("quote", help="Post two-sided maker market around reference")
    quote_parser.add_argument("--spread", default=None, help="Total spread in POLF (default: auto fee-clearing)")
    quote_parser.add_argument("--qty", default="3.00", help="Contracts per side (default: 3.00)")
    quote_parser.add_argument("--room", default="kc-c1-desk", help="Trading room")
    quote_parser.add_argument("--until", type=int, default=12, help="Sweeps ahead to expire")

    # Accept
    accept_parser = subparsers.add_parser("accept", help="Countersign and execute an open offer by ID")
    accept_parser.add_argument("id", help="Offer terms ID to execute")
    accept_parser.add_argument("--room", default="kc-c1-desk", help="Room where offer is posted")

    # Reconcile
    subparsers.add_parser("reconcile", help="Reconcile local account with latest referee state")

    # Trade (Autonomous Engine)
    trade_parser = subparsers.add_parser("trade", help="Run autonomous trading cycle or daemon")
    trade_parser.add_argument("--once", action="store_true", help="Run one trading cycle and exit")
    trade_parser.add_argument("--interval", type=int, default=300, help="Loop interval in seconds (default: 300)")
    trade_parser.add_argument("--room", default="kc-c1-desk", help="Primary desk room for maker quotes")
    trade_parser.add_argument("--max-inv", default="15.0", help="Maximum absolute inventory contracts (default: 15.0)")
    trade_parser.add_argument("--min-cash", default="5000.0", help="Minimum cash reserve in POLF (default: 5000.0)")
    trade_parser.add_argument("--spread", default=None, help="Quoting spread in POLF (default: auto fee-clearing)")
    trade_parser.add_argument("--qty", default="3.00", help="Quoting quantity per side (default: 3.00)")
    trade_parser.add_argument("--htf", type=int, default=12, help="Higher timeframe window sweeps (default: 12)")
    trade_parser.add_argument("--ltf", type=int, default=3, help="Lower timeframe window sweeps (default: 3)")

    # Trend
    trend_parser = subparsers.add_parser("trend", help="Analyze NVDA stock trend, multi-timeframe regime, and volatility")
    trend_parser.add_argument("--htf", type=int, default=12, help="Higher timeframe window sweeps (default: 12)")
    trend_parser.add_argument("--ltf", type=int, default=3, help="Lower timeframe window sweeps (default: 3)")

    args = parser.parse_args()
    client = CloseCallClient()

    if args.command == "status" or not args.command:
        print(format_telemetry_banner(client))

    elif args.command == "trend":
        analysis = client.analyze_market_trend(htf_window=args.htf, ltf_window=args.ltf)
        print("=" * 68)
        print("  [NVDA] MULTI-TIMEFRAME TREND & VOLATILITY ANALYSIS")
        print("=" * 68)
        print(f"Reference Price:        ${analysis.current_px} (Sweep #{analysis.sweep_n})")
        print(f"Higher Timeframe (HTF): {analysis.htf_trend} (Change: {analysis.htf_change_pct:+.2f}%, Slope: {analysis.htf_slope:+.4f})")
        print(f"Lower Timeframe (LTF):  {analysis.ltf_trend} (Change: {analysis.ltf_change_pct:+.2f}%, Slope: {analysis.ltf_slope:+.4f})")
        print(f"MTF Market Regime:      {analysis.regime} (Score: {analysis.trend_score:+.2f})")
        print(f"Recommended Action:     {analysis.recommended_action}")
        print("-" * 68)
        print(f"Volatility Regime:      {analysis.volatility_regime} ({analysis.volatility_pct:.2f}% | ${analysis.volatility_usd:.2f})")
        print(f"Dynamic Entry Buffer:   ${analysis.vol_buffer}")
        print(f"Dynamic Quoting Spread: ${analysis.dynamic_spread}")
        print("=" * 68)

    elif args.command == "register":
        print(f"[*] Broadcasting owner registration for {client.did} in /r/{args.room}...")
        ok, msg = client.register_owner(args.room)
        print(f"[{'+' if ok else '!'}] Result: {msg}")

    elif args.command == "register-room":
        print(f"[*] Registering new trading room '{args.name}'...")
        ok, msg = client.register_room(args.name, args.in_room)
        print(f"[{'+' if ok else '!'}] Result: {msg}")

    elif args.command == "offer":
        print(f"[*] Posting {args.side.upper()} offer: {args.qty} contracts @ ${args.px}...")
        ok, msg, envelope = client.post_maker_offer(
            side=args.side,
            qty=args.qty,
            px=args.px,
            room=args.room,
            taker=args.taker,
            until_sweeps_ahead=args.until,
        )
        print(f"[{'+' if ok else '!'}] Result: {msg}")
        if envelope:
            print(f"    Terms ID: {envelope['terms']['id']}")
            print(f"    Maker Sig: {envelope['maker_sig'][:24]}...")

    elif args.command == "quote":
        spread_val = Decimal(args.spread) if args.spread is not None else None
        qty_val = Decimal(args.qty) if args.qty is not None else None
        print(f"[*] Posting two-sided quote in /r/{args.room} (spread: ${args.spread or 'auto'}, qty: {args.qty})...")
        res = client.post_two_sided_quote(
            spread=spread_val,
            qty=qty_val,
            room=args.room,
            until_sweeps_ahead=args.until,
        )
        bid = res.get("bid", {})
        ask = res.get("ask", {})
        print(f"[{'+' if bid.get('success') else '!'}] BID: {bid.get('qty')} @ ${bid.get('px')} -> {bid.get('message')}")
        print(f"[{'+' if ask.get('success') else '!'}] ASK: {ask.get('qty')} @ ${ask.get('px')} -> {ask.get('message')}")

    elif args.command == "accept":
        print(f"[*] Locating and executing offer '{args.id}' in /r/{args.room}...")
        ok, msg = client.execute_offer_by_id(args.room, args.id)
        print(f"[{'+' if ok else '!'}] Result: {msg}")

    elif args.command == "reconcile":
        print("[*] Reconciling with referee flow & positions...")
        rep = client.reconcile_with_referee()
        print(f"[+] Agent: {rep['did']}")
        print(f"    Cash: {rep['cash']} POLF | Fees Paid: {rep['fees']} POLF")
        print(f"    Position: {rep['position']} contracts | Lots: {rep['lots']}")
        print(f"    Settled Trades Recorded: {rep['settled_count']}")

    elif args.command == "scan":
        print("[*] Scanning registered rooms for open offers...")
        offers = client.scan_open_offers()
        print(f"[+] Found {len(offers)} valid open offers:")
        for idx, o in enumerate(offers, 1):
            t = o["data"]["terms"]
            print(f"    {idx}. Room: /r/{o['room']} | ID: {t['id']} | {t['side'].upper()} {t['qty']} @ ${t['px']} (by {t['maker'][:16]}...)")

    elif args.command == "trade":
        spread_val = Decimal(args.spread) if args.spread is not None else None
        qty_val = Decimal(args.qty) if args.qty is not None else None
        print(f"[*] Starting Autonomous Close Call Trading Engine on /r/{args.room}...")
        print(f"    Max Inventory: {args.max_inv} contracts | Min Cash Reserve: {args.min_cash} POLF")
        print(f"    Quoting Spread: ${args.spread or 'auto'} | Quoting Qty: {args.qty}")
        while True:
            try:
                res = client.run_trading_cycle(
                    max_inventory=Decimal(args.max_inv),
                    min_cash_reserve=Decimal(args.min_cash),
                    target_spread=spread_val,
                    quote_qty=qty_val,
                    desk_rooms=[args.room, "close1", "boz-desk", "jh-nvda-desk"],
                    htf_window=args.htf,
                    ltf_window=args.ltf,
                )
                m_ana = res.get("market_analysis", {})
                print(f"[+] Sweep #{res.get('sweep')} | Ref: ${res.get('ref_px')} | Trend: {m_ana.get('regime')} | Vol: {m_ana.get('volatility_regime')} ({m_ana.get('volatility_pct')}%) | Pos: {res.get('final_position')} | Cash: {res.get('final_cash')} POLF")
                for ex in res.get("executed_trades", []):
                    print(f"    -> TAKER EXEC: {ex['side'].upper()} {ex['qty']} @ ${ex['px']} (ID: {ex['id']} in /r/{ex['room']}) [Closing: {ex['closing']}]")
                for q in res.get("posted_quotes", []):
                    b, a = q.get("bid", {}), q.get("ask", {})
                    if b.get("success"):
                        print(f"    -> MAKER BID: {b.get('qty')} @ ${b.get('px')} (ID: {b.get('id')})")
                    if a.get("success"):
                        print(f"    -> MAKER ASK: {a.get('qty')} @ ${a.get('px')} (ID: {a.get('id')})")
                for err in res.get("errors", []):
                    print(f"    [!] Error: {err}")
            except Exception as e:
                print(f"[!] Trading cycle exception: {e}")

            if args.once:
                break
            time.sleep(args.interval)


if __name__ == "__main__":
    main()
