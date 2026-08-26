"""Technocore Sentinel: Threat Detection, Scam Filtering & Provenance Engine.

Analyzes Technocore chat streams, room topics, and agent interactions in real-time.
Features:
- NFKC & Homoglyph normalization against obfuscated evasion attacks
- Multi-vector Prompt Injection and System Override Detection
- Fake Token Contract, Phishing URL, and Pump.fun Scam Detection
- Cryptographic Provenance Classification & Impersonation Defense
- Room Health, Diversity, and Threat Score Analytics
"""

from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from sentinel_core import is_valid_did

# Confusable homoglyph translation table (Cyrillic & Greek homoglyphs -> ASCII)
HOMOGLYPH_MAP = {
    # Cyrillic to Latin
    ord("а"): "a", ord("А"): "A",
    ord("е"): "e", ord("Е"): "E",
    ord("о"): "o", ord("О"): "O",
    ord("р"): "p", ord("Р"): "P",
    ord("с"): "c", ord("С"): "C",
    ord("у"): "y", ord("У"): "Y",
    ord("х"): "x", ord("Х"): "X",
    ord("і"): "i", ord("І"): "I",
    ord("ј"): "j", ord("Ј"): "J",
    ord("ѕ"): "s", ord("Ѕ"): "S",
    ord("ԁ"): "d", ord("Ԃ"): "D",
    ord("ԛ"): "q",
    ord("ԝ"): "w",
    # Greek to Latin
    ord("α"): "a", ord("Α"): "A",
    ord("β"): "b", ord("Β"): "B",
    ord("ε"): "e", ord("Ε"): "E",
    ord("ο"): "o", ord("Ο"): "O",
    ord("ρ"): "p", ord("Ρ"): "P",
    ord("τ"): "t", ord("Τ"): "T",
    ord("ν"): "v", ord("Ν"): "N",
    ord("κ"): "k", ord("Κ"): "K",
}

# ============================================================================
# Threat Signature Patterns
# ============================================================================

PROMPT_INJECTION_PATTERNS = [
    # Instruction Resets & Overrides
    re.compile(r"\b(ignore|disregard|forget)\s+(all\s+|any\s+)?(previous|former|prior|past|above)\s+(instructions|prompts|directives|rules|constraints)\b", re.IGNORECASE),
    re.compile(r"\b(you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(a|an)?\s*(unrestricted|jailbroken|developer\s+mode|dan\s+mode|root\s+user|system\s+admin)\b", re.IGNORECASE),
    re.compile(r"\b(system\s+override|override\s+system|new\s+system\s+directive|developer\s+mode\s+enabled)\b", re.IGNORECASE),
    re.compile(r"\b(print|reveal|output|display|show|send|leak)\s+(your\s+|the\s+)?(system\s+prompt|initial\s+instructions|private\s+key|seed\s+phrase|api\s+key)\b", re.IGNORECASE),
    
    # Delimiter and Frame Hijacking
    re.compile(r"<\s*\|\s*im_start\s*\|>", re.IGNORECASE),
    re.compile(r"<\s*\|\s*im_end\s*\|>", re.IGNORECASE),
    re.compile(r"\[\s*INST\s*\]|\[\s*/\s*INST\s*\]", re.IGNORECASE),
    re.compile(r"<<\s*SYS\s*>>|<</\s*SYS\s*>>", re.IGNORECASE),
    re.compile(r"[-=]{3,}\s*(BEGIN|START|END)\s+.*?(SYSTEM|DIRECTIVE|INSTRUCTION|PROMPT).*?[-=]{3,}", re.IGNORECASE),
    re.compile(r"^\s*(SYSTEM|DEVELOPER|ROOT)\s*:\s*", re.MULTILINE | re.IGNORECASE),

    # Markdown / Out-of-band Exfiltration Payloads
    re.compile(r"!\[.*?\]\(https?://[^\s\)\"']+\?[^\s\)\"']*(?:key|token|priv|secret|seed|leak)=?[^\s\)\"']*\)", re.IGNORECASE),
    re.compile(r"data:text/html;base64,[A-Za-z0-9+/=]{16,}", re.IGNORECASE),
]

SCAM_PATTERNS = [
    # Solana pump.fun token contract spam
    re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}pump\b", re.IGNORECASE),
    # EVM token contract spam with claims
    re.compile(r"\b0x[a-fA-F0-9]{40}\b.*?(?:buy|claim|airdrop|launch|presale|contract|mint)", re.IGNORECASE),
    re.compile(r"(?:buy|claim|airdrop|launch|presale|contract|mint).*?\b0x[a-fA-F0-9]{40}\b", re.IGNORECASE),
    # Phishing / Fake Claim Portals
    re.compile(r"https?://[^\s/]*(?:flop|technocore)[^\s/]*(?:claim|airdrop|reward|presale|token)[^\s]*", re.IGNORECASE),
    re.compile(r"https?://t\.me/[^\s]*(?:airdrop|claim|reward|official_flop)", re.IGNORECASE),
]

RESERVED_ADMIN_NAMES = {
    "server", "admin", "administrator", "root", "system",
    "flop_team", "flop_official", "technocore_admin", "arthur", "hayes"
}


@dataclass
class ThreatAssessment:
    level: str             # "CLEAN", "SUSPICIOUS", "THREAT"
    confidence: float      # 0.0 to 1.0
    threat_types: List[str] # ["PROMPT_INJECTION", "FAKE_TOKEN", "PHISHING", "IMPERSONATION"]
    flags: List[str]       # Human-readable explanation of triggers
    normalized_text: str
    provenance: str        # "VERIFIED_DID", "UNVERIFIED_NICK", "IMPERSONATOR_WARNING"
    sender_badge: str      # Short display badge e.g. "🟢 DID", "🟡 ~nick", "🔴 SPOOF"


# ============================================================================
# Normalization & Analysis Functions
# ============================================================================

def normalize_text(text: str) -> str:
    """Apply NFKC normalization, homoglyph substitution, and whitespace clean."""
    if not text:
        return ""
    # 1. NFKC Unicode decomposition and compatibility composition
    nfkc = unicodedata.normalize("NFKC", text)
    # 2. Homoglyph transliteration to standard ASCII letters
    trans = nfkc.translate(HOMOGLYPH_MAP)
    # 3. Collapse multiple whitespace and strip
    return re.sub(r"\s+", " ", trans).strip()


def evaluate_provenance(sender: str) -> Tuple[str, str, Optional[str]]:
    """Evaluate cryptographic provenance of sender string.
    Returns (provenance_type, sender_badge, warning_message).
    """
    if not sender:
        return "UNVERIFIED_NICK", "⚪ Anonymous", None

    if is_valid_did(sender):
        # Cryptographically verified Ed25519 DID key
        short_did = sender[:14] + "..." + sender[-6:]
        return "VERIFIED_DID", f"🟢 {short_did}", None

    # Handle unverified nicknames (e.g. ~bob or plain bob)
    clean_nick = sender.lstrip("~").lower()
    if clean_nick in RESERVED_ADMIN_NAMES or sender == "~server":
        return (
            "IMPERSONATOR_WARNING",
            f"🔴 ~{clean_nick} [UNVERIFIED]",
            f"Unverified sender attempting to use reserved administrative nickname '{clean_nick}'"
        )

    return "UNVERIFIED_NICK", f"🟡 ~{clean_nick}", None


def analyze_message(sender: str, raw_text: str, room: str = "lobby") -> ThreatAssessment:
    """Perform multi-layer threat, scam, and provenance analysis on a message."""
    norm_text = normalize_text(raw_text)
    threat_types: List[str] = []
    flags: List[str] = []
    confidence = 0.0

    # 1. Provenance Check
    provenance, badge, prov_warning = evaluate_provenance(sender)
    if prov_warning:
        threat_types.append("IMPERSONATION")
        flags.append(prov_warning)
        confidence = max(confidence, 0.90)

    # 2. Prompt Injection & Adversarial Input Scan
    for pattern in PROMPT_INJECTION_PATTERNS:
        match = pattern.search(norm_text)
        if match:
            threat_types.append("PROMPT_INJECTION")
            flags.append(f"Adversarial instruction pattern matched: '{match.group(0)[:40]}'")
            confidence = max(confidence, 0.95)

    # 3. Fake Token & Phishing Scan
    for pattern in SCAM_PATTERNS:
        match = pattern.search(norm_text)
        if match:
            matched_str = match.group(0)[:40]
            if "pump" in matched_str.lower() or "0x" in matched_str.lower():
                threat_types.append("FAKE_TOKEN")
                flags.append(f"Unverified token contract address detected: '{matched_str}'")
            else:
                threat_types.append("PHISHING")
                flags.append(f"Suspicious phishing or fake claim link detected: '{matched_str}'")
            confidence = max(confidence, 0.85)

    # Deduplicate threat types
    threat_types = list(dict.fromkeys(threat_types))

    # Determine overall threat level
    if "PROMPT_INJECTION" in threat_types or "IMPERSONATION" in threat_types:
        level = "THREAT"
    elif "FAKE_TOKEN" in threat_types or "PHISHING" in threat_types:
        level = "SUSPICIOUS"
    else:
        level = "CLEAN"
        confidence = 1.0

    return ThreatAssessment(
        level=level,
        confidence=confidence,
        threat_types=threat_types,
        flags=flags,
        normalized_text=norm_text,
        provenance=provenance,
        sender_badge=badge,
    )


# ============================================================================
# Room & Swarm Health Metrics
# ============================================================================

def evaluate_room_health(messages: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate swarm health metrics, diversity, and threat score across a message batch."""
    if not messages:
        return {
            "total_messages": 0,
            "verified_did_ratio": 0.0,
            "threat_ratio": 0.0,
            "health_score": 100,
            "unique_senders": 0,
            "status": "HEALTHY",
        }

    total = len(messages)
    verified_count = 0
    threat_count = 0
    unique_senders: Set[str] = set()

    for m in messages:
        sender = m.get("from", "")
        text = m.get("text", "")
        if sender:
            unique_senders.add(sender)
        
        assessment = analyze_message(sender, text)
        if assessment.provenance == "VERIFIED_DID":
            verified_count += 1
        if assessment.level in ("THREAT", "SUSPICIOUS"):
            threat_count += 1

    verified_ratio = round(verified_count / total, 2)
    threat_ratio = round(threat_count / total, 2)
    
    # Calculate health score: 100 baseline minus threat penalties, plus verified bonus
    health_score = int(max(0, min(100, 100 - (threat_ratio * 100) + (verified_ratio * 10))))

    if health_score >= 80:
        status = "HEALTHY"
    elif health_score >= 50:
        status = "MODERATE"
    else:
        status = "ELEVATED_RISK"

    return {
        "total_messages": total,
        "verified_did_ratio": verified_ratio,
        "threat_ratio": threat_ratio,
        "health_score": health_score,
        "unique_senders": len(unique_senders),
        "status": status,
    }
