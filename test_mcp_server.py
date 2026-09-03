"""Unit tests for TCLK MCP Server (tclk_mcp_server.py)."""

import json
import unittest
from tclk_mcp_server import TclkMcpServer, MCP_TOOLS


class TestTclkMcpServer(unittest.TestCase):
    def setUp(self):
        self.server = TclkMcpServer()

    def test_01_tools_list(self):
        """Verify MCP tools/list returns complete tool catalog."""
        res = self.server.dispatch_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
        })
        self.assertIn("result", res)
        tools = res["result"]["tools"]
        tool_names = [t["name"] for t in tools]
        self.assertIn("tclk_make_offer", tool_names)
        self.assertIn("tclk_accept_offer", tool_names)
        self.assertIn("tclk_make_lock", tool_names)
        self.assertIn("tclk_make_reveal", tool_names)
        self.assertIn("tclk_verify_transcript", tool_names)

    def test_02_end_to_end_mcp_tool_deal(self):
        """Verify complete deal negotiation via MCP tools/call."""
        # 1. Make Offer
        offer_call = self.server.dispatch_request({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "tclk_make_offer",
                "arguments": {
                    "role": "payer",
                    "amount": "10000",
                    "asset": "FLOP",
                },
            },
        })
        self.assertIn("result", offer_call)
        offer_data = json.loads(offer_call["result"]["content"][0]["text"])
        offer = offer_data["offer"]
        offer_line = offer_data["wireLine"]
        self.assertTrue(offer["id"].startswith("0x"))

        # 2. Accept Offer
        accept_call = self.server.dispatch_request({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "tclk_accept_offer",
                "arguments": {"offer": offer},
            },
        })
        accept_data = json.loads(accept_call["result"]["content"][0]["text"])
        contract_id = accept_data["contractId"]
        secret_preimage = accept_data["secretPreimage"]
        accept_line = accept_data["wireLine"]
        self.assertTrue(contract_id.startswith("0x"))
        self.assertTrue(secret_preimage.startswith("0x"))

        # 3. Lock
        lock_call = self.server.dispatch_request({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "tclk_make_lock",
                "arguments": {
                    "contract": contract_id,
                    "rail": "paper-htlc",
                    "ref": "paper-ref-1234",
                },
            },
        })
        lock_data = json.loads(lock_call["result"]["content"][0]["text"])
        lock_line = lock_data["wireLine"]

        # 4. Reveal
        reveal_call = self.server.dispatch_request({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "tclk_make_reveal",
                "arguments": {
                    "contract": contract_id,
                    "secret": secret_preimage,
                },
            },
        })
        reveal_data = json.loads(reveal_call["result"]["content"][0]["text"])
        reveal_line = reveal_data["wireLine"]

        # 5. Verify Transcript
        transcript_call = self.server.dispatch_request({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "tclk_verify_transcript",
                "arguments": {
                    "messages": [offer_line, accept_line, lock_line, reveal_line],
                },
            },
        })
        transcript_data = json.loads(transcript_call["result"]["content"][0]["text"])
        self.assertEqual(transcript_data["finalStatus"], "claimed")
        self.assertEqual(transcript_data["contractState"]["contract"], contract_id)


if __name__ == "__main__":
    unittest.main(verbosity=2)
