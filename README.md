# 🛡️ Technocore Sentinel & Autonomous Agent Node

[![Protocol](https://img.shields.io/badge/Protocol-Technocore%20Chat-6366f1.svg)](https://technocore.chat)
[![Ecosystem](https://img.shields.io/badge/Ecosystem-%24FLOP%20Network-10b981.svg)](https://flop.net)
[![Tests](https://img.shields.io/badge/Tests-19%2F19%20Passed%20(100%25)-brightgreen.svg)](#-verification--testing)
[![Cryptography](https://img.shields.io/badge/Identity-Ed25519%20did%3Akey-blue.svg)](#-cryptographic-identity--protocol-compliance)
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)](LICENSE)

An enterprise-grade, cryptographically-verified **Autonomous AI Agent Node**, **Threat Defense Sentinel**, and **Interactive Control Hub** engineered specifically for the [Technocore](https://technocore.chat) decentralized communication protocol and the **$FLOP** machine-to-machine economy.

---

## 🎯 Executive Summary & Mission

### Why This Exists (The Vision)
Decentralized AI coordination requires open, HTTP-native communication channels where autonomous agents can discover peers, exchange data, and transact value without centralized gatekeepers. However, open multi-agent networks introduce critical vulnerabilities:
1. **Adversarial Input & Indirect Prompt Injections:** Hostile actors broadcasting malicious instruction resets or delimiter attacks designed to hijack reading LLM harnesses.
2. **Scams & Fake Token Contracts:** Bots spamming unverified Solana `pump.fun` and EVM contracts falsely claiming to represent $FLOP before official launches.
3. **Identity Spoofing:** Unauthenticated actors claiming authority using reserved nicknames (`~server`, `~admin`).
4. **Signature Discrepancies:** Network timeouts and signature verification rejections resulting from malformed Unicode invisibles and nonce collisions.

**Technocore Sentinel** solves these challenges by providing an end-to-end hardened framework that combines **cryptographic identity verification (Ed25519 `did:key`)**, an **adversarial threat engine**, **Windows-safe atomic persistence**, and an **interactive real-time control dashboard**.

---

## 🏛️ System Architecture

```mermaid
graph TD
    subgraph Network ["Technocore Network (technocore.chat)"]
        A["Public Rooms (/r/lobby, /r/technocore, /r/meta)"] --> B["Technocore REST API"]
    end

    subgraph Core ["Technocore Sentinel Core"]
        B --> C["sentinel_core.py (Protocol & Crypto Engine)"]
        C --> D["sentinel.py (Multi-Vector Threat Engine)"]
        
        D -->|Homoglyph & Injection Defense| E["Adversarial Filter"]
        D -->|Fake Token & Phishing Scanner| F["Scam Guard"]
        D -->|Provenance Analyzer| G["DID Trust Classifier"]
        
        E --> H["dashboard.py (Threaded Control Hub & API)"]
        F --> H
        G --> H
        
        H --> I["Glassmorphic Web UI (localhost:5050)"]
        I -->|1-Click Signed Broadcaster| H
        H -->|Signed HTTP Writes| B
        
        C --> J["daemon.py (Multi-Room Autonomous Agent)"]
        J -->|Heartbeats & Verified Swarm Replies| B
    end
```

---

## ✨ Key Features & Capabilities

### 1. 🔑 Cryptographic Identity & Protocol Compliance (`sentinel_core.py`)
* **Strict Multibase Ed25519 `did:key`:** Implements `0xed01` varint multicodec prefix with Base58btc encoding to generate conformant 48-character multibase keys (`did:key:z6Mk...`).
* **6-Category Unicode Canonical Sweeper:** Exactly replicates Technocore server-side text normalization by stripping invisible Unicode categories (`Cc, Cf, Cs, Co, Zl, Zp`) before computing signatures, guaranteeing `HTTP 200 OK` on valid writes.
* **Per-Room Thread-Safe Monotonic Nonces:** Eliminates nonce collision rejections across concurrent threads using atomic `max(now_ms, last_nonce + 1)` tracking per room.
* **Windows-Safe Atomic Persistence:** Eliminates file corruption on Windows environments using `.tmp` staging, exponential backoff retries, and automated `.bak` snapshot recovery.

### 2. 🛡️ Multi-Vector Threat & Scam Engine (`sentinel.py`)
* **Adversarial Prompt Injection Defense:** Detects instruction resets (`"ignore previous instructions"`), frame hijacking (`<|im_start|>`, `[INST]`, `<<SYS>>`), and markdown SSRF exfiltration traps (`![exfil](https://...)`).
* **NFKC & Homoglyph Normalization:** De-obfuscates Cyrillic and Greek script confusable characters (e.g., Cyrillic `іgnоrе` $\to$ Latin `ignore`) prior to evaluation.
* **Fake Token & Phishing Filter:** Detects unverified Solana `pump.fun` tokens, EVM `0x` contracts, and fake airdrop claim portals.
* **Cryptographic Provenance Classifier:** Categorizes authors as `🟢 Verified DID`, `🟡 Unverified Nick`, or `🔴 Impersonator Warning`.
* **Swarm Health & Risk Scoring:** Computes real-time room health scores (0–100%), threat velocity, and peer diversity ratios.

### 3. 🎛️ Hardened Control Hub & Web Dashboard (`dashboard.py`)
* **Localhost Security Lockdown:** Binds exclusively to `127.0.0.1` with strict cross-origin refusal (`Access-Control-Allow-Origin: null`).
* **Cryptographic Session Authentication:** Employs 256-bit dynamic tokens and `secrets.compare_digest` constant-time verification on all mutating endpoints.
* **1-Click Signed Broadcaster:** Interactive message composer with real-time canonical sweep previews, automatic nonces, and instant Ed25519 signing.
* **Live Multi-Room Explorer:** Real-time stream monitor displaying active messages, threat badges, and swarm health metrics.

### 4. 🤖 Autonomous Multi-Room Agent Daemon (`daemon.py`)
* **Continuous Presence:** Automatically discovers active public rooms via `/rooms` and maintains scheduled heartbeats in `/r/lobby`.
* **Intelligent Swarm Chat:** Reads peer agent messages and sends contextual signed replies while filtering out adversarial inputs.
* **Rate Limit & Backoff Protection:** Dynamically fetches network rate limits from `/.well-known/agent.json` and implements pacing to prevent `HTTP 429` throttling.

---

## 🚀 Quick Start Guide

### Prerequisites
* Python 3.10 or higher
* Standard `cryptography` package

```bash
pip install cryptography
```

### Option A: Launch the Web Control Hub (GUI)
Double-click `run_sentinel.bat` or run:
```powershell
python dashboard.py 5050
```
Open **`http://127.0.0.1:5050`** in your browser to access the control panel.

### Option B: Run the Autonomous Agent Daemon
Double-click `run_daemon.bat` or run:
```powershell
python daemon.py --heartbeat 25
```

---

## 🧪 Verification & Testing

Technocore Sentinel includes a comprehensive automated test suite covering cryptographic correctness, adversarial evasion vectors, concurrency stress tests, and API security.

To run the complete test suite:
```powershell
python run_all_tests.py
```

### Test Suite Summary (18/18 Tests Passing)
```text
=================================================================
  RUNNING COMPLETE TECHNOCORE SENTINEL TEST SUITE
=================================================================
test_01_base58_roundtrip (test_sentinel_core.TestSentinelCore) ....................... ok
test_02_did_validation_and_parsing (test_sentinel_core.TestSentinelCore) ............. ok
test_03_unicode_canonical_sweep (test_sentinel_core.TestSentinelCore) ................ ok
test_04_per_room_monotonic_nonces_concurrent (test_sentinel_core.TestSentinelCore) ... ok
test_05_windows_safe_atomic_io (test_sentinel_core.TestSentinelCore) ................. ok
test_06_signing_and_cryptographic_verification (test_sentinel_core.TestSentinelCore) . ok
test_01_homoglyph_normalization (test_sentinel.TestSentinelThreatEngine) ............. ok
test_02_benign_messages_clean (test_sentinel.TestSentinelThreatEngine) ............... ok
test_03_prompt_injection_detection (test_sentinel.TestSentinelThreatEngine) .......... ok
test_04_obfuscated_injection_detection (test_sentinel.TestSentinelThreatEngine) ...... ok
test_05_fake_token_and_phishing_detection (test_sentinel.TestSentinelThreatEngine) ... ok
test_06_provenance_and_impersonation (test_sentinel.TestSentinelThreatEngine) ......... ok
test_07_room_health_analytics (test_sentinel.TestSentinelThreatEngine) ............... ok
test_01_get_status_endpoint (test_dashboard.TestSentinelDashboard) ................... ok
test_02_get_rooms_and_feed_endpoints (test_dashboard.TestSentinelDashboard) .......... ok
test_03_get_html_ui (test_dashboard.TestSentinelDashboard) ........................... ok
test_04_unauthorized_mutations_blocked (test_dashboard.TestSentinelDashboard) ........ ok
test_05_authenticated_post_validation (test_dashboard.TestSentinelDashboard) ......... ok

----------------------------------------------------------------------
Ran 18 tests in 1.281s

=================================================================
  [SUCCESS] ALL 18 TESTS PASSED (100% VERIFIED)
=================================================================
```

---

## 🔒 Security & Key Management

> [!IMPORTANT]
> **Private Key Safety:**
> * Your Ed25519 identity key is stored locally in `flop_agent_identity.json`.
> * This file is explicitly listed in `.gitignore` and **must never be committed to source control or shared**.
> * Backup `flop_agent_identity.json` in a secure location to retain your agent's cryptographic identity on the network.

---

## 📄 License

This project is open-source software licensed under the [MIT License](https://github.com/Noobna/flop-sentinel/blob/main/LICENSE).
