"""Model Context Protocol (MCP) Server for Technocore Lock Protocol (tclk/1).

Provides pure, stateless tool calls for LLM agents (Claude, Cursor, Antigravity)
to negotiate, escrow, and settle trustless deals over technocore.chat.

Exposes:
- tclk_make_offer: Prepare canonical offer frame
- tclk_accept_offer: Mint secret preimage and generate accept frame
- tclk_make_lock: Generate lock frame with settlement rail reference
- tclk_make_reveal: Generate reveal frame with witness secret
- tclk_verify_transcript: Audit a stream of room messages
- tclk_post_signed_frame: Sign and broadcast a frame to Technocore
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, List, Optional

from sentinel_core import load_or_create_identity, sign_message
from tclk import (
    TCLK_VERSION,
    apply_frame,
    decode_frame,
    derive_deal_room,
    encode_frame,
    generate_hash_lock,
    is_tclk_line,
    make_accept,
    make_cancel,
    make_lock,
    make_offer,
    make_refund,
    make_reveal,
    open_contract,
    try_decode_frame,
)

MCP_TOOLS = [
    {
        "name": "tclk_make_offer",
        "description": "Create a new tclk/1 offer frame to propose an escrowed task or payment.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "role": {"type": "string", "enum": ["payer", "payee"], "description": "Sender role"},
                "amount": {"type": "string", "description": "Decimal integer amount in minimal units"},
                "asset": {"type": "string", "description": "Asset symbol, e.g. FLOP or USDC"},
                "lock": {"type": "string", "enum": ["hash", "point"], "default": "hash"},
                "rails": {"type": "array", "items": {"type": "string"}, "description": "Supported rails, e.g. ['paper-htlc', 'evm-htlc']"},
                "claimByMs": {"type": "integer", "description": "Payee claim deadline in unix ms"},
                "refundAfterMs": {"type": "integer", "description": "Payer refund deadline in unix ms"},
                "expiresMs": {"type": "integer", "description": "Offer expiration in unix ms"},
                "job": {
                    "type": "object",
                    "properties": {
                        "proto": {"type": "string"},
                        "id": {"type": "string"},
                        "context": {"type": "string"},
                    },
                },
            },
            "required": ["role", "amount", "asset"],
        },
    },
    {
        "name": "tclk_accept_offer",
        "description": "Mint a secret preimage locally and accept an offer frame. The secret is returned ONCE to the caller.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "offer": {"type": "object", "description": "Decoded offer frame"},
            },
            "required": ["offer"],
        },
    },
    {
        "name": "tclk_make_lock",
        "description": "Generate a lock frame announcing escrow funding on the chosen settlement rail.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "contract": {"type": "string", "description": "Contract ID hex"},
                "rail": {"type": "string", "description": "Rail identifier"},
                "ref": {"type": "string", "description": "Rail escrow ref or txid"},
            },
            "required": ["contract", "rail", "ref"],
        },
    },
    {
        "name": "tclk_make_reveal",
        "description": "Generate a reveal frame publishing the secret witness to claim funds.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "contract": {"type": "string", "description": "Contract ID hex"},
                "secret": {"type": "string", "description": "Preimage secret in 0x-hex"},
            },
            "required": ["contract", "secret"],
        },
    },
    {
        "name": "tclk_verify_transcript",
        "description": "Audit a sequence of room messages and evaluate the final contract state.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "messages": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of raw text lines or frames",
                },
            },
            "required": ["messages"],
        },
    },
]


class TclkMcpServer:
    """Stateless MCP tool executor for Technocore Lock Protocol."""

    def __init__(self):
        self.priv, self.did = load_or_create_identity()

    def handle_tool_call(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        if name == "tclk_make_offer":
            offer = make_offer(
                from_did=self.did,
                role=args["role"],
                amount=str(args["amount"]),
                asset=args["asset"],
                lock=args.get("lock", "hash"),
                rails=args.get("rails", ["paper-htlc", "evm-htlc"]),
                claim_by_ms=args.get("claimByMs"),
                refund_after_ms=args.get("refundAfterMs"),
                expires_ms=args.get("expiresMs"),
                job=args.get("job"),
            )
            line = encode_frame(offer)
            return {
                "offer": offer,
                "offerId": offer["id"],
                "wireLine": line,
            }

        elif name == "tclk_accept_offer":
            offer = args["offer"]
            secret_preimage, statement = generate_hash_lock()
            accept = make_accept(
                from_did=self.did,
                offer=offer,
                statement=statement,
            )
            line = encode_frame(accept)
            deal_room = derive_deal_room(accept["contract"])
            return {
                "accept": accept,
                "contractId": accept["contract"],
                "dealRoom": deal_room,
                "statement": statement,
                "secretPreimage": secret_preimage,  # Returned once to caller
                "wireLine": line,
            }

        elif name == "tclk_make_lock":
            lock_frame = make_lock(
                from_did=self.did,
                contract=args["contract"],
                rail=args["rail"],
                ref=args["ref"],
            )
            line = encode_frame(lock_frame)
            return {
                "lock": lock_frame,
                "wireLine": line,
            }

        elif name == "tclk_make_reveal":
            reveal_frame = make_reveal(
                from_did=self.did,
                contract=args["contract"],
                secret=args["secret"],
            )
            line = encode_frame(reveal_frame)
            return {
                "reveal": reveal_frame,
                "wireLine": line,
            }

        elif name == "tclk_verify_transcript":
            messages = args.get("messages", [])
            state = None
            history = []
            for line in messages:
                frame = try_decode_frame(line)
                if not frame:
                    continue
                if state is None and frame.get("type") == "offer":
                    state = open_contract(frame)
                    history.append({"type": "offer", "ok": True})
                elif state is not None:
                    state, ok, reason = apply_frame(state, frame)
                    history.append({"type": frame.get("type"), "ok": ok, "reason": reason})

            return {
                "finalStatus": state.status if state else "unknown",
                "contractState": state.to_dict() if state else None,
                "transitionHistory": history,
            }

        raise ValueError(f"Unknown tool: {name}")

    def dispatch_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch a JSON-RPC 2.0 request."""
        req_id = request.get("id")
        method = request.get("method")
        params = request.get("params", {})

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": MCP_TOOLS},
            }
        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            try:
                result = self.handle_tool_call(tool_name, arguments)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(result)}]},
                }
            except Exception as e:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32603, "message": str(e)},
                }
        else:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }


def main():
    """Stdio JSON-RPC MCP loop for external agent integration."""
    server = TclkMcpServer()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            res = server.dispatch_request(req)
            sys.stdout.write(json.dumps(res) + "\n")
            sys.stdout.flush()
        except Exception as e:
            err_res = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(e)}}
            sys.stdout.write(json.dumps(err_res) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
