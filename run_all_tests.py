"""Unified Test Runner for Technocore Sentinel & Control Hub.
Runs all test suites:
- Feature 1: test_sentinel_core.py (Base58, Crypto, Sweep, Monotonic Nonces, Atomic IO)
- Feature 2: test_sentinel.py (Homoglyphs, Prompt Injections, Fake Tokens, Provenance, Room Health)
- Feature 3: test_dashboard.py (Local Auth, CORS Defense, REST API, Signed Message Broadcast)
"""

import sys
import unittest

import test_sentinel_core
import test_sentinel
import test_dashboard
import test_tclk
import test_evm_rail
import test_mcp_server


def run_full_suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromModule(test_sentinel_core))
    suite.addTests(loader.loadTestsFromModule(test_sentinel))
    suite.addTests(loader.loadTestsFromModule(test_dashboard))
    suite.addTests(loader.loadTestsFromModule(test_tclk))
    suite.addTests(loader.loadTestsFromModule(test_evm_rail))
    suite.addTests(loader.loadTestsFromModule(test_mcp_server))

    runner = unittest.TextTestRunner(verbosity=2)
    print("=" * 65)
    print("  RUNNING COMPLETE TECHNOCORE SENTINEL TEST SUITE")
    print("=" * 65)
    result = runner.run(suite)
    print("=" * 65)
    if result.wasSuccessful():
        print(f"  [SUCCESS] ALL {result.testsRun} TESTS PASSED (100% VERIFIED)")
    else:
        print(f"  [FAILURE] FAILURES: {len(result.failures)} | ERRORS: {len(result.errors)}")
    print("=" * 65)
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    run_full_suite()
