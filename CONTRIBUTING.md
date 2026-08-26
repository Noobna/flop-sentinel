# Contributing to Technocore Sentinel

Thank you for your interest in contributing to **Technocore Sentinel**! This document provides guidelines, architectural standards, and testing procedures for developers and security researchers looking to expand the project.

---

## 🧭 Project Principles

1. **Zero External Overhead:** The core protocol engine and threat filters must run entirely on standard Python 3 libraries + standard `cryptography`. Avoid introducing heavy third-party frameworks.
2. **Strict Protocol Compliance:** All message sweeping, nonce generation, and multibase Ed25519 formatting must match the official `technocore-chat` specifications byte-for-byte.
3. **Defense-in-Depth:** Every input received from Technocore streams must be treated as untrusted data. We normalize, classify, and sanitize all streams before displaying or responding.
4. **Resilience & Thread Safety:** Operations involving disk I/O, state persistence, and nonce generation must remain strictly thread-safe and resilient against operating system quirks (such as Windows open-handle locks).

---

## 🛠️ Development Setup & Testing

### 1. Environment Setup
Ensure you have Python 3.10+ installed. Install the single dependency:
```bash
pip install cryptography
```

### 2. Running Automated Tests
Before submitting any pull request or commit, verify that all test suites pass with 100% success:
```powershell
python run_all_tests.py
```

### 3. Individual Test Suites
* **Core & Crypto Tests:** `python test_sentinel_core.py`
* **Threat Engine Tests:** `python test_sentinel.py`
* **Dashboard & API Security Tests:** `python test_dashboard.py`

---

## 🛡️ Adding New Threat Signatures

We actively welcome contributions that expand Sentinel's threat detection capabilities against novel adversarial attacks.

When contributing new threat patterns to `sentinel.py`:
1. **Homoglyph & Unicode Normalization:** Ensure your patterns account for de-obfuscation performed by `normalize_text()`.
2. **Regex Performance:** Avoid catastrophic backtracking in regular expressions. Use bounded character ranges.
3. **Unit Test Requirements:** Every new threat pattern MUST include corresponding test cases in `test_sentinel.py` covering:
   * Direct trigger string
   * Obfuscated / homoglyph variant
   * False positive test (ensuring benign developer messages are not falsely flagged)

---

## 🔐 Security Best Practices & Key Safety

* **Never commit identity keys:** Ensure `flop_agent_identity.json`, `*.key`, and `*.bak` files remain in `.gitignore`.
* **Local Binding:** The control dashboard must never bind to `0.0.0.0` or open external network ports. It is designed solely as a secure local interface (`127.0.0.1`).
* **Responsible Disclosure:** If you discover a critical protocol vulnerability or remote code execution vector in Technocore integration, please report it securely to the maintainers.

---

## 📜 Code Style Guidelines

* Adhere to **PEP 8** standards.
* Use explicit type annotations on public functions (`Tuple`, `List`, `Dict`, `Optional`).
* Document all non-obvious design decisions with clear docstrings.
* Ensure cross-platform compatibility across Windows, Linux, and macOS.
