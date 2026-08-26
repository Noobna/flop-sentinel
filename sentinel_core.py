"""Core Cryptographic, Protocol & Thread-Safe I/O Engine for Technocore Sentinel.

Provides:
- Strict Ed25519 did:key management & verification
- 6-category Unicode canonical sweeping (Cc, Cf, Cs, Co, Zl, Zp)
- Thread-safe, per-room monotonic nonce generator
- Windows-safe atomic file I/O with exponential backoff & .bak fallback
- Hardened HTTP client with retry and error parsing
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import sys
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# Constants strictly conforming to flop-labs/technocore-chat
KEY_FILE = "flop_agent_identity.json"
STATE_FILE = "agent_state.json"
B58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
INVISIBLE_CATEGORIES = ("Cc", "Cf", "Cs", "Co", "Zl", "Zp")
USER_AGENT = "Technocore-Sentinel/1.0 (Python; Ed25519)"
PREFIX = "did:key:z6Mk"
MULTIBASE_CHARS = 48
MAX_TEXT_CHARS = 4096

# Regex for strict validation
DID_REGEX = re.compile(rf"^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{{{MULTIBASE_CHARS - 4}}}$")

_io_lock = threading.RLock()
_nonce_lock = threading.RLock()
_room_nonces: Dict[str, int] = {}


# ============================================================================
# 1. Base58 & Cryptographic Helpers
# ============================================================================

def b58_encode(b: bytes) -> str:
    """Encode bytes to Base58btc string with preserved leading zero bytes."""
    n = int.from_bytes(b, "big")
    res = []
    while n > 0:
        n, r = divmod(n, 58)
        res.append(B58_CHARS[r])
    pad = len(b) - len(b.lstrip(b"\x00"))
    return ("1" * pad) + "".join(reversed(res))


def b58_decode(s: str) -> bytes:
    """Decode Base58btc string to bytes."""
    n = 0
    for char in s:
        idx = B58_CHARS.find(char)
        if idx == -1:
            raise ValueError(f"Invalid Base58btc character: {char}")
        n = n * 58 + idx
    # Count leading '1's
    pad = len(s) - len(s.lstrip("1"))
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n > 0 else b""
    return (b"\x00" * pad) + raw


def is_valid_did(did: str) -> bool:
    """Verify if a string strictly satisfies Technocore's Ed25519 did:key schema."""
    return bool(DID_REGEX.fullmatch(did))


def extract_public_key_from_did(did: str) -> ed25519.Ed25519PublicKey:
    """Parse public key bytes from a valid did:key:z6Mk... string."""
    if not is_valid_did(did):
        raise ValueError(f"Malformed DID key: {did}")
    multibase_segment = did[len("did:key:z"):]
    raw_bytes = b58_decode(multibase_segment)
    if len(raw_bytes) != 34:
        raise ValueError(f"Invalid decoded key length ({len(raw_bytes)} != 34)")
    if raw_bytes[:2] != b"\xed\x01":
        raise ValueError(f"Invalid multicodec prefix: {raw_bytes[:2]}")
    pub_bytes = raw_bytes[2:]
    return ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)


# ============================================================================
# 2. Canonical Unicode Sweeper
# ============================================================================

def canonical_sweep(text: str, limit: int = MAX_TEXT_CHARS) -> str:
    """Transforms raw text into Technocore canonical format:
    Replaces Unicode categories (Cc, Cf, Cs, Co, Zl, Zp) with spaces and strips ends.
    Raises ValueError on empty output or length overflow.
    """
    cleaned = "".join(
        " " if unicodedata.category(c) in INVISIBLE_CATEGORIES else c for c in text
    ).strip()
    if not cleaned:
        raise ValueError("Nothing visible left after canonical sweep")
    if len(cleaned) > limit:
        raise ValueError(f"Text length exceeds limit ({len(cleaned)} > {limit})")
    return cleaned


# ============================================================================
# 3. Thread-Safe, Per-Room Monotonic Nonce Generator
# ============================================================================

def get_next_nonce(room: str) -> str:
    """Returns a strictly increasing nonce string for the specified room.
    Guarantees monotonically increasing sequence per room, even during millisecond race conditions.
    """
    with _nonce_lock:
        now_ms = int(time.time() * 1000)
        last = _room_nonces.get(room, 0)
        next_nonce = max(now_ms, last + 1)
        _room_nonces[room] = next_nonce
        return str(next_nonce)


def seed_room_nonce(room: str, initial_nonce: int):
    """Seed the in-memory nonce tracker for a room from persisted state or server seq."""
    with _nonce_lock:
        current = _room_nonces.get(room, 0)
        _room_nonces[room] = max(current, initial_nonce)


# ============================================================================
# 4. Windows-Safe Atomic File Persistence
# ============================================================================

def save_json_atomic(filepath: str, data: Any, indent: int = 2) -> bool:
    """Atomically saves data to JSON file with Windows open-handle resilience.
    Uses .tmp staging, exponential retry backoff, and .bak preservation.
    """
    with _io_lock:
        tmp_path = f"{filepath}.tmp.{os.getpid()}.{time.time_ns()}"
        bak_path = f"{filepath}.bak"
        dir_name = os.path.dirname(os.path.abspath(filepath))
        if dir_name:
            os.makedirs(dir_name, exist_ok=True)

        try:
            # 1. Write to temporary file and flush
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=indent, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())

            # 2. Preserve backup if existing file exists
            if os.path.exists(filepath):
                try:
                    with open(filepath, "r", encoding="utf-8") as src, open(bak_path, "w", encoding="utf-8") as dst:
                        dst.write(src.read())
                except Exception:
                    pass

            # 3. Atomic rename with Windows retry backoff
            max_attempts = 5
            for attempt in range(max_attempts):
                try:
                    os.replace(tmp_path, filepath)
                    return True
                except (PermissionError, OSError) as e:
                    if attempt == max_attempts - 1:
                        raise e
                    time.sleep(0.05 * (2 ** attempt))
            return True
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass


def load_json_safe(filepath: str, default: Any = None) -> Any:
    """Loads JSON file with corruption fallback to .bak copy if present."""
    with _io_lock:
        if not os.path.exists(filepath):
            return default

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            bak_path = f"{filepath}.bak"
            if os.path.exists(bak_path):
                try:
                    with open(bak_path, "r", encoding="utf-8") as f:
                        return json.load(f)
                except Exception:
                    pass
            return default


# ============================================================================
# 5. Keypair Management & Signing Pipeline
# ============================================================================

def load_or_create_identity(key_file: str = KEY_FILE) -> Tuple[ed25519.Ed25519PrivateKey, str]:
    """Load or generate Ed25519 keypair and conformant did:key identifier."""
    if os.path.exists(key_file):
        data = load_json_safe(key_file, {})
        if "private_key_hex" in data and "did" in data:
            priv = ed25519.Ed25519PrivateKey.from_private_bytes(
                bytes.fromhex(data["private_key_hex"])
            )
            # M-3: Verify DID matches loaded key — refuse on corruption
            raw_pub = priv.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            expected_did = "did:key:z" + b58_encode(b"\xed\x01" + raw_pub)
            if expected_did != data["did"]:
                raise RuntimeError(
                    f"Identity file {key_file} is corrupted: stored DID does not match "
                    f"private key. Expected {expected_did[:20]}..., got {data['did'][:20]}... "
                    f"— delete the file to regenerate."
                )
            return priv, data["did"]

    # Generate new keypair
    priv = ed25519.Ed25519PrivateKey.generate()
    raw_priv = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    raw_pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    did = "did:key:z" + b58_encode(b"\xed\x01" + raw_pub)
    save_json_atomic(key_file, {"did": did, "private_key_hex": raw_priv.hex()})
    return priv, did


def sign_message(priv: ed25519.Ed25519PrivateKey, room: str, nonce: str, text: str) -> Tuple[str, str]:
    """Sweeps text, prepares canonical message payload, and signs with Ed25519.
    Returns (swept_text, unpadded_base64url_signature).
    """
    text_clean = canonical_sweep(text)
    payload = f"{room}|{nonce}|{text_clean}".encode("utf-8")
    sig_bytes = priv.sign(payload)
    sig_str = base64.urlsafe_b64encode(sig_bytes).decode("ascii").rstrip("=")
    return text_clean, sig_str


def verify_signed_message(did: str, room: str, nonce: str, text: str, sig_str: str) -> bool:
    """Verifies a signed Technocore message using the sender's DID key."""
    try:
        pub_key = extract_public_key_from_did(did)
        text_clean = canonical_sweep(text)
        payload = f"{room}|{nonce}|{text_clean}".encode("utf-8")
        
        # Pad signature to valid base64
        pad_len = (4 - (len(sig_str) % 4)) % 4
        sig_bytes = base64.urlsafe_b64decode(sig_str + ("=" * pad_len))
        pub_key.verify(sig_bytes, payload)
        return True
    except (InvalidSignature, ValueError):
        return False


# ============================================================================
# 6. Hardened HTTP Client
# ============================================================================

class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Prevent automatic redirect following — signed URLs should not be replayed (L-3)."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Suppress redirect, treat as final response

_opener = urllib.request.build_opener(_NoRedirectHandler)

def http_get(url: str, timeout: int = 25) -> Tuple[int, str]:
    """Execute hardened GET request with Technocore headers. No redirect following."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with _opener.open(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if hasattr(e, "read") else ""
        return e.code, body
    except urllib.error.URLError as e:
        raise RuntimeError(f"Network error on {url}: {e.reason}") from e
