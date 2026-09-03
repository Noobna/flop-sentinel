"""Technocore Lock Protocol (tclk/1) Python Engine.

HTLC/PTLC coordination primitives for agents meeting in technocore.chat rooms.
- Wire frames & canonical JSON serialization
- SHA-256 hash locks & preimage generation
- Fail-closed pure state machine (apply_frame)
- SettlementRail interface & MemoryRail / PaperRail reference implementations
- Integration with Technocore signed lane (Ed25519 did:key)
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import secrets
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set, Tuple

# Protocol constants
TCLK_VERSION = "tclk/1"
TCLK_PREFIX = "tclk1 "
TCLK_DOMAIN = "FLOP::tclk::v1"
MAX_FRAME_CHARS = 4096

HEX32_RE = re.compile(r"^0x[0-9a-f]{64}$")
HEX33_RE = re.compile(r"^0x[0-9a-f]{66}$")
DID_RE = re.compile(r"^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$")
AMOUNT_RE = re.compile(r"^[1-9][0-9]*$")
ASSET_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
RAIL_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
NONCE_RE = re.compile(r"^[0-9a-f]{8,64}$")

TCLK_TERMINAL_STATUSES: Set[str] = {"claimed", "refunded", "cancelled"}


# ============================================================================
# 1. Canonical JSON & Hashing
# ============================================================================

def canonical_json(val: Any) -> str:
    """Serialize value to canonical, sorted-key, ASCII-escaped JSON string.
    Omits keys with None values, sorts all dictionary keys alphabetically.
    """
    if val is None:
        raise ValueError("Cannot serialize None as a top-level canonical JSON entity")
    
    def _clean(v: Any) -> Any:
        if isinstance(v, dict):
            return {k: _clean(sub_v) for k, sub_v in sorted(v.items()) if sub_v is not None}
        if isinstance(v, list):
            return [_clean(item) for item in v]
        return v

    cleaned = _clean(val)
    # separators=(',', ':') removes all whitespace; ensure_ascii=True produces \uXXXX escapes
    raw = json.dumps(cleaned, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return raw


def offer_id(offer_fields: Dict[str, Any]) -> str:
    """Compute deterministic offer ID: 0x + sha256(FLOP::tclk::v1|offer|<canonical JSON without id>)."""
    core = {k: v for k, v in offer_fields.items() if k != "id" and v is not None}
    canonical = canonical_json(core)
    payload = f"{TCLK_DOMAIN}|offer|{canonical}".encode("utf-8")
    return "0x" + hashlib.sha256(payload).hexdigest()


def contract_id(offer: Dict[str, Any], accept_core: Dict[str, Any]) -> str:
    """Compute deterministic contract ID: 0x + sha256(FLOP::tclk::v1|contract|<canonical {offer, accept}>)."""
    accept_dict = {
        "from": accept_core["from"],
        "nonce": accept_core["nonce"],
        "ref": accept_core["ref"],
        "statement": accept_core["statement"],
    }
    if "paymentKey" in accept_core and accept_core["paymentKey"] is not None:
        accept_dict["paymentKey"] = accept_core["paymentKey"]

    container = {
        "offer": offer,
        "accept": accept_dict,
    }
    canonical = canonical_json(container)
    payload = f"{TCLK_DOMAIN}|contract|{canonical}".encode("utf-8")
    return "0x" + hashlib.sha256(payload).hexdigest()


def derive_deal_room(cid: str) -> str:
    """Derive deterministic unlisted deal room: mb-p-tclk-<first 16 hex of contract id>."""
    clean = cid[2:] if cid.startswith("0x") else cid
    if len(clean) < 16:
        raise ValueError(f"Contract ID too short for deal room derivation: {cid}")
    return f"mb-p-tclk-{clean[:16].lower()}"


# ============================================================================
# 2. Cryptographic Locks (HTLC Preimages)
# ============================================================================

def generate_hash_lock() -> Tuple[str, str]:
    """Generate a random 32-byte preimage and its public SHA-256 statement (both 0x-hex).
    Returns (preimage, hash_statement).
    """
    preimage_bytes = secrets.token_bytes(32)
    hash_bytes = hashlib.sha256(preimage_bytes).digest()
    return "0x" + preimage_bytes.hex(), "0x" + hash_bytes.hex()


def verify_hash_secret(secret_hex: str, statement_hex: str) -> bool:
    """Verify that sha256(secret) matches the public hash statement."""
    if not HEX32_RE.fullmatch(secret_hex) or not HEX32_RE.fullmatch(statement_hex):
        return False
    raw_secret = bytes.fromhex(secret_hex[2:])
    expected_statement = "0x" + hashlib.sha256(raw_secret).hexdigest()
    return expected_statement.lower() == statement_hex.lower()


# ============================================================================
# 3. Frame Validation, Encoding & Decoding
# ============================================================================

def validate_frame(frame: Dict[str, Any]) -> None:
    """Fail-closed validation of a tclk frame dictionary."""
    if not isinstance(frame, dict):
        raise ValueError("Frame must be a dictionary")
    
    ftype = frame.get("type")
    if ftype not in {"offer", "accept", "lock", "reveal", "refund", "cancel", "receipt"}:
        raise ValueError(f"Unknown frame type: {ftype}")
    
    from_did = frame.get("from")
    if not from_did or not DID_RE.fullmatch(str(from_did)):
        raise ValueError(f"Malformed or missing 'from' DID: {from_did}")

    if ftype == "offer":
        role = frame.get("role")
        if role not in {"payer", "payee"}:
            raise ValueError(f"Invalid offer role: {role}")
        if not AMOUNT_RE.fullmatch(str(frame.get("amount", ""))):
            raise ValueError(f"Invalid amount: {frame.get('amount')}")
        if not ASSET_RE.fullmatch(str(frame.get("asset", ""))):
            raise ValueError(f"Invalid asset: {frame.get('asset')}")
        if frame.get("lock") not in {"hash", "point"}:
            raise ValueError(f"Invalid lock kind: {frame.get('lock')}")
        
        rails = frame.get("rails")
        if not isinstance(rails, list) or not rails or not all(RAIL_RE.fullmatch(str(r)) for r in rails):
            raise ValueError(f"Invalid rails list: {rails}")
        
        claim_by = frame.get("claimByMs")
        refund_after = frame.get("refundAfterMs")
        expires = frame.get("expiresMs")
        if not isinstance(claim_by, int) or not isinstance(refund_after, int) or not isinstance(expires, int):
            raise ValueError("Deadlines must be positive safe integers (ms)")
        if not (expires <= claim_by < refund_after):
            raise ValueError(f"Deadlines invalid: expires({expires}) <= claimBy({claim_by}) < refundAfter({refund_after}) required")
        
        nonce = frame.get("nonce")
        if not nonce or not NONCE_RE.fullmatch(str(nonce)):
            raise ValueError(f"Malformed offer nonce: {nonce}")
        
        oid = frame.get("id")
        if not oid or not HEX32_RE.fullmatch(str(oid)):
            raise ValueError(f"Malformed offer id: {oid}")
        expected_id = offer_id(frame)
        if oid.lower() != expected_id.lower():
            raise ValueError(f"Offer ID mismatch: got {oid}, expected {expected_id}")

    elif ftype == "accept":
        ref = frame.get("ref")
        if not ref or not HEX32_RE.fullmatch(str(ref)):
            raise ValueError(f"Invalid accept ref (offer id): {ref}")
        statement = frame.get("statement")
        if not statement or not (HEX32_RE.fullmatch(str(statement)) or HEX33_RE.fullmatch(str(statement))):
            raise ValueError(f"Invalid statement: {statement}")
        cid = frame.get("contract")
        if not cid or not HEX32_RE.fullmatch(str(cid)):
            raise ValueError(f"Invalid contract id: {cid}")
        nonce = frame.get("nonce")
        if not nonce or not NONCE_RE.fullmatch(str(nonce)):
            raise ValueError(f"Malformed accept nonce: {nonce}")

    elif ftype == "lock":
        cid = frame.get("contract")
        if not cid or not HEX32_RE.fullmatch(str(cid)):
            raise ValueError(f"Invalid contract id on lock: {cid}")
        rail = frame.get("rail")
        if not rail or not RAIL_RE.fullmatch(str(rail)):
            raise ValueError(f"Invalid rail on lock: {rail}")
        ref = frame.get("ref")
        if not ref or not isinstance(ref, str) or len(ref) > 256:
            raise ValueError(f"Invalid rail ref on lock: {ref}")

    elif ftype == "reveal":
        cid = frame.get("contract")
        if not cid or not HEX32_RE.fullmatch(str(cid)):
            raise ValueError(f"Invalid contract id on reveal: {cid}")
        secret = frame.get("secret")
        if not secret or not (HEX32_RE.fullmatch(str(secret)) or re.fullmatch(r"^0x[0-9a-f]{1,64}$", str(secret))):
            raise ValueError(f"Invalid secret on reveal: {secret}")

    elif ftype in {"refund", "cancel"}:
        cid = frame.get("contract")
        if not cid or not HEX32_RE.fullmatch(str(cid)):
            raise ValueError(f"Invalid contract id on {ftype}: {cid}")


def encode_frame(frame: Dict[str, Any]) -> str:
    """Validate and encode a frame into its canonical wire line."""
    validate_frame(frame)
    line = f"{TCLK_PREFIX}{canonical_json(frame)}"
    if len(line) > MAX_FRAME_CHARS:
        raise ValueError(f"Encoded frame exceeds limit ({len(line)} > {MAX_FRAME_CHARS})")
    return line


def is_tclk_line(line: str) -> bool:
    """Check if a line begins with the tclk1 prefix."""
    return isinstance(line, str) and line.startswith(TCLK_PREFIX)


def decode_frame(line: str) -> Dict[str, Any]:
    """Decode and validate a tclk line from a room message. Throws on bad input."""
    if not is_tclk_line(line):
        raise ValueError("Line does not start with tclk1 prefix")
    body = line[len(TCLK_PREFIX):].strip()
    try:
        parsed = json.loads(body)
    except Exception as e:
        raise ValueError(f"Invalid JSON payload: {e}") from e
    validate_frame(parsed)
    return parsed


def try_decode_frame(line: str) -> Optional[Dict[str, Any]]:
    """Safe wrapper around decode_frame returning None on failure."""
    try:
        return decode_frame(line)
    except Exception:
        return None


# ============================================================================
# 4. Frame Constructors
# ============================================================================

def make_offer(
    from_did: str,
    role: str,
    amount: str,
    asset: str,
    lock: str = "hash",
    rails: Optional[List[str]] = None,
    claim_by_ms: Optional[int] = None,
    refund_after_ms: Optional[int] = None,
    expires_ms: Optional[int] = None,
    payment_key: Optional[str] = None,
    job: Optional[Dict[str, str]] = None,
    nonce: Optional[str] = None,
) -> Dict[str, Any]:
    """Build and compute ID for an offer frame."""
    now_ms = int(time.time() * 1000)
    if claim_by_ms is None:
        claim_by_ms = now_ms + 86400_000  # 24 hours
    if refund_after_ms is None:
        refund_after_ms = claim_by_ms + 86400_000  # 48 hours
    if expires_ms is None:
        expires_ms = min(now_ms + 3600_000, claim_by_ms)
    if rails is None:
        rails = ["paper-htlc", "flop-htlc"]
    if nonce is None:
        nonce = secrets.token_hex(8)

    fields: Dict[str, Any] = {
        "type": "offer",
        "from": from_did,
        "role": role,
        "amount": str(amount),
        "asset": asset,
        "lock": lock,
        "rails": rails,
        "claimByMs": claim_by_ms,
        "refundAfterMs": refund_after_ms,
        "expiresMs": expires_ms,
        "nonce": nonce,
    }
    if payment_key:
        fields["paymentKey"] = payment_key
    if job:
        fields["job"] = job

    fields["id"] = offer_id(fields)
    validate_frame(fields)
    return fields


def make_accept(
    from_did: str,
    offer: Dict[str, Any],
    statement: str,
    payment_key: Optional[str] = None,
    nonce: Optional[str] = None,
) -> Dict[str, Any]:
    """Build and compute contract ID for an accept frame given an offer and statement."""
    validate_frame(offer)
    if nonce is None:
        nonce = secrets.token_hex(8)

    accept_core: Dict[str, Any] = {
        "from": from_did,
        "ref": offer["id"],
        "statement": statement,
        "nonce": nonce,
    }
    if payment_key:
        accept_core["paymentKey"] = payment_key

    cid = contract_id(offer, accept_core)
    frame = {
        "type": "accept",
        "from": from_did,
        "ref": offer["id"],
        "statement": statement,
        "contract": cid,
        "nonce": nonce,
    }
    if payment_key:
        frame["paymentKey"] = payment_key

    validate_frame(frame)
    return frame


def make_lock(from_did: str, contract: str, rail: str, ref: str, presig: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    frame = {
        "type": "lock",
        "from": from_did,
        "contract": contract,
        "rail": rail,
        "ref": ref,
    }
    if presig:
        frame["presig"] = presig
    validate_frame(frame)
    return frame


def make_reveal(from_did: str, contract: str, secret: str) -> Dict[str, Any]:
    frame = {
        "type": "reveal",
        "from": from_did,
        "contract": contract,
        "secret": secret,
    }
    validate_frame(frame)
    return frame


def make_refund(from_did: str, contract: str, reason: Optional[str] = None) -> Dict[str, Any]:
    frame: Dict[str, Any] = {
        "type": "refund",
        "from": from_did,
        "contract": contract,
    }
    if reason:
        frame["reason"] = reason
    validate_frame(frame)
    return frame


def make_cancel(from_did: str, contract: str, reason: Optional[str] = None) -> Dict[str, Any]:
    frame: Dict[str, Any] = {
        "type": "cancel",
        "from": from_did,
        "contract": contract,
    }
    if reason:
        frame["reason"] = reason
    validate_frame(frame)
    return frame


# ============================================================================
# 5. Pure Fail-Closed State Machine
# ============================================================================

class ContractState:
    def __init__(self, offer: Dict[str, Any]):
        validate_frame(offer)
        self.status = "proposed"
        self.offer = offer
        self.payer_did: Optional[str] = offer["from"] if offer["role"] == "payer" else None
        self.payee_did: Optional[str] = offer["from"] if offer["role"] == "payee" else None
        self.contract: Optional[str] = None
        self.statement: Optional[str] = None
        self.rail: Optional[str] = None
        self.rail_ref: Optional[str] = None
        self.secret: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "contract": self.contract,
            "payerDid": self.payer_did,
            "payeeDid": self.payee_did,
            "statement": self.statement,
            "rail": self.rail,
            "railRef": self.rail_ref,
            "secret": self.secret,
            "offer": self.offer,
        }


def open_contract(offer: Dict[str, Any]) -> ContractState:
    """Initialize state machine from an offer."""
    return ContractState(offer)


def apply_frame(state: ContractState, frame: Dict[str, Any], now_ms: Optional[int] = None) -> Tuple[ContractState, bool, Optional[str]]:
    """Pure transition: returns (new_state, ok, reason). Never mutates state or throws."""
    if now_ms is None:
        now_ms = int(time.time() * 1000)

    try:
        validate_frame(frame)
    except Exception as e:
        return state, False, f"Malformed frame: {e}"

    ftype = frame["type"]
    new_state = copy.deepcopy(state)

    if ftype == "accept":
        if new_state.status != "proposed":
            return state, False, f"Cannot accept in status '{new_state.status}'"
        if frame.get("ref") != new_state.offer["id"]:
            return state, False, "Accept ref does not match offer id"
        
        # Verify contract id match
        computed_cid = contract_id(new_state.offer, frame)
        if frame.get("contract", "").lower() != computed_cid.lower():
            return state, False, "Contract ID mismatch in accept frame"
        
        if now_ms > new_state.offer["expiresMs"]:
            return state, False, "Offer has expired"

        # Assign counterparty
        if new_state.offer["role"] == "payer":
            new_state.payee_did = frame["from"]
        else:
            new_state.payer_did = frame["from"]

        new_state.contract = computed_cid
        new_state.statement = frame["statement"]
        new_state.status = "accepted"
        return new_state, True, None

    elif ftype == "lock":
        if new_state.status != "accepted":
            return state, False, f"Cannot lock in status '{new_state.status}'"
        if frame.get("contract") != new_state.contract:
            return state, False, "Contract ID mismatch in lock frame"
        if frame.get("from") != new_state.payer_did:
            return state, False, "Only payer may post lock frame"
        if frame.get("rail") not in new_state.offer["rails"]:
            return state, False, f"Rail '{frame.get('rail')}' not in accepted rails list"

        new_state.rail = frame["rail"]
        new_state.rail_ref = frame["ref"]
        new_state.status = "locked"
        return new_state, True, None

    elif ftype == "reveal":
        if new_state.status != "locked":
            return state, False, f"Cannot reveal in status '{new_state.status}'"
        if frame.get("contract") != new_state.contract:
            return state, False, "Contract ID mismatch in reveal frame"
        if frame.get("from") != new_state.payee_did:
            return state, False, "Only payee may reveal secret"
        
        # Check secret against statement
        secret = frame["secret"]
        if new_state.offer["lock"] == "hash":
            if not verify_hash_secret(secret, new_state.statement or ""):
                return state, False, "Revealed secret does not match hash statement"

        new_state.secret = secret
        new_state.status = "claimed"
        return new_state, True, None

    elif ftype == "refund":
        if new_state.status != "locked":
            return state, False, f"Cannot refund in status '{new_state.status}'"
        if frame.get("contract") != new_state.contract:
            return state, False, "Contract ID mismatch in refund frame"
        if frame.get("from") != new_state.payer_did:
            return state, False, "Only payer may claim refund"
        if now_ms < new_state.offer["refundAfterMs"]:
            return state, False, f"Timelock not expired (current: {now_ms} < refundAfter: {new_state.offer['refundAfterMs']})"

        new_state.status = "refunded"
        return new_state, True, None

    elif ftype == "cancel":
        if new_state.status not in {"proposed", "accepted"}:
            return state, False, f"Cannot cancel in status '{new_state.status}'"
        if frame.get("from") not in {new_state.payer_did, new_state.payee_did}:
            return state, False, "Only contract participants may cancel"

        new_state.status = "cancelled"
        return new_state, True, None

    return state, False, f"Unhandled frame type '{ftype}'"


# ============================================================================
# 6. Settlement Rails (Reference Implementations)
# ============================================================================

class SettlementRail(ABC):
    """Abstract interface for a value-holding or simulation settlement rail."""
    
    @property
    @abstractmethod
    def rail_id(self) -> str:
        """Identifier matching offer.rails (e.g. 'paper-htlc', 'evm-htlc')."""
        pass

    @abstractmethod
    def lock(self, state: ContractState) -> str:
        """Escrow funds under the contract statement and return rail ref."""
        pass

    @abstractmethod
    def claim(self, contract_id: str, secret: str) -> bool:
        """Release funds to payee with the revealed secret."""
        pass

    @abstractmethod
    def refund(self, contract_id: str) -> bool:
        """Reclaim funds to payer after timeout."""
        pass


class PaperRail(SettlementRail):
    """In-memory simulation rail for testing full end-to-end deal choreography."""
    
    def __init__(self, rail_id: str = "paper-htlc"):
        self._rail_id = rail_id
        self._escrows: Dict[str, Dict[str, Any]] = {}

    @property
    def rail_id(self) -> str:
        return self._rail_id

    def lock(self, state: ContractState) -> str:
        if not state.contract or not state.statement:
            raise ValueError("Contract must be accepted before locking")
        ref = f"paper-escrow-{secrets.token_hex(6)}"
        self._escrows[state.contract] = {
            "ref": ref,
            "statement": state.statement,
            "amount": state.offer["amount"],
            "asset": state.offer["asset"],
            "status": "locked",
        }
        return ref

    def claim(self, cid: str, secret: str) -> bool:
        escrow = self._escrows.get(cid)
        if not escrow or escrow["status"] != "locked":
            return False
        if not verify_hash_secret(secret, escrow["statement"]):
            return False
        escrow["status"] = "claimed"
        escrow["secret"] = secret
        return True

    def refund(self, cid: str) -> bool:
        escrow = self._escrows.get(cid)
        if not escrow or escrow["status"] != "locked":
            return False
        escrow["status"] = "refunded"
        return True
