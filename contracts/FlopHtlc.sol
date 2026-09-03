// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title FlopHtlc - Technocore Lock Protocol (tclk/1) EVM Settlement Rail
 * @notice Trustless Hash Time-Locked Contract (HTLC) escrow supporting native ETH and ERC-20 tokens.
 * Coordinated off-chain via signed chat messages on technocore.chat.
 */

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract FlopHtlc {
    enum Status { Empty, Locked, Claimed, Refunded }

    struct Escrow {
        bytes32 statement;      // sha256(preimage)
        address payer;          // Entity funding the contract
        address payee;          // Beneficiary who can claim with secret
        address token;          // address(0) for native ETH, or ERC20 contract
        uint256 amount;         // Escrowed amount in atomic units
        uint256 refundAfter;    // Unix timestamp (seconds) after which payer can refund
        Status status;          // Current state
    }

    // Mapping: contractId => Escrow details
    mapping(bytes32 => Escrow) public escrows;

    // Events matching tclk/1 lifecycle
    event LockCreated(
        bytes32 indexed contractId,
        bytes32 indexed statement,
        address indexed payer,
        address payee,
        address token,
        uint256 amount,
        uint256 refundAfter
    );

    event Claimed(
        bytes32 indexed contractId,
        bytes32 secret,
        address indexed payee,
        uint256 amount
    );

    event Refunded(
        bytes32 indexed contractId,
        address indexed payer,
        uint256 amount
    );

    error AlreadyExists();
    error NotFound();
    error NotLocked();
    error InvalidPreimage();
    error TimelockNotExpired();
    error TransferFailed();
    error InvalidParams();

    /**
     * @notice Escrow native ETH under a hash statement and timelock
     */
    function lockNative(
        bytes32 contractId,
        bytes32 statement,
        address payee,
        uint256 refundAfter
    ) external payable {
        if (msg.value == 0 || payee == address(0) || refundAfter <= block.timestamp) {
            revert InvalidParams();
        }
        if (escrows[contractId].status != Status.Empty) {
            revert AlreadyExists();
        }

        escrows[contractId] = Escrow({
            statement: statement,
            payer: msg.sender,
            payee: payee,
            token: address(0),
            amount: msg.value,
            refundAfter: refundAfter,
            status: Status.Locked
        });

        emit LockCreated(contractId, statement, msg.sender, payee, address(0), msg.value, refundAfter);
    }

    /**
     * @notice Escrow ERC-20 tokens (e.g. USDC, FLOP) under a hash statement and timelock
     */
    function lockToken(
        bytes32 contractId,
        bytes32 statement,
        address payee,
        address token,
        uint256 amount,
        uint256 refundAfter
    ) external {
        if (amount == 0 || payee == address(0) || token == address(0) || refundAfter <= block.timestamp) {
            revert InvalidParams();
        }
        if (escrows[contractId].status != Status.Empty) {
            revert AlreadyExists();
        }

        escrows[contractId] = Escrow({
            statement: statement,
            payer: msg.sender,
            payee: payee,
            token: token,
            amount: amount,
            refundAfter: refundAfter,
            status: Status.Locked
        });

        emit LockCreated(contractId, statement, msg.sender, payee, token, amount, refundAfter);

        bool success = IERC20(token).transferFrom(msg.sender, address(this), amount);
        if (!success) {
            revert TransferFailed();
        }
    }

    /**
     * @notice Claim funds by revealing the secret preimage: sha256(preimage) == statement
     */
    function claim(bytes32 contractId, bytes32 secret) external {
        Escrow storage escrow = escrows[contractId];
        if (escrow.status != Status.Locked) {
            revert NotLocked();
        }

        // Verify SHA-256 preimage against statement
        if (sha256(abi.encodePacked(secret)) != escrow.statement) {
            revert InvalidPreimage();
        }

        escrow.status = Status.Claimed;
        emit Claimed(contractId, secret, escrow.payee, escrow.amount);

        if (escrow.token == address(0)) {
            (bool success, ) = escrow.payee.call{value: escrow.amount}("");
            if (!success) revert TransferFailed();
        } else {
            bool success = IERC20(escrow.token).transfer(escrow.payee, escrow.amount);
            if (!success) revert TransferFailed();
        }
    }

    /**
     * @notice Reclaim escrowed funds after the timelock expires
     */
    function refund(bytes32 contractId) external {
        Escrow storage escrow = escrows[contractId];
        if (escrow.status != Status.Locked) {
            revert NotLocked();
        }
        if (block.timestamp < escrow.refundAfter) {
            revert TimelockNotExpired();
        }

        escrow.status = Status.Refunded;
        emit Refunded(contractId, escrow.payer, escrow.amount);

        if (escrow.token == address(0)) {
            (bool success, ) = escrow.payer.call{value: escrow.amount}("");
            if (!success) revert TransferFailed();
        } else {
            bool success = IERC20(escrow.token).transfer(escrow.payer, escrow.amount);
            if (!success) revert TransferFailed();
        }
    }

    /**
     * @notice Helper to compute the SHA-256 statement for a given preimage
     */
    function hashStatement(bytes32 preimage) external pure returns (bytes32) {
        return sha256(abi.encodePacked(preimage));
    }
}
