// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

/*
    Generic value-extraction template -- re-execute a suspicious tx after
    altering one input and check if attacker gains value.

    Use when alert flags a value-outlier tx (z-score > 3) on a contract that
    handles ETH/ERC20 -- and you want to know whether the EXACT pattern is
    reproducible from a different (attacker) sender.

    FILL: TARGET, ATTACKER, FORK_BLOCK, CALLDATA, MSG_VALUE
*/

import "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

contract ValueExtractionExploit is Test {
    address constant TARGET    = address(0x0000000000000000000000000000000000000000); // FILL
    address constant ATTACKER  = address(0xDeadBeeF00000000000000000000000000001337); // FILL
    address constant TOKEN     = address(0x0000000000000000000000000000000000000000); // FILL: token attacker hopes to receive (or address(0) for ETH)
    uint256 constant FORK_BLOCK = 22487000; // FILL
    uint256 constant MSG_VALUE = 0;         // FILL: value to send with the call
    bytes   constant CALLDATA  = hex"";     // FILL: calldata from the suspicious tx

    function setUp() public {
        string memory rpc = vm.envOr("FOUNDRY_RPC_URL", string("https://eth.llamarpc.com"));
        vm.createSelectFork(rpc, FORK_BLOCK);
        vm.deal(ATTACKER, MSG_VALUE + 1 ether);
    }

    function test_attackerCanExtractValue() public {
        uint256 attackerBefore = TOKEN == address(0)
            ? ATTACKER.balance
            : IERC20(TOKEN).balanceOf(ATTACKER);

        vm.prank(ATTACKER);
        (bool ok, bytes memory ret) = TARGET.call{value: MSG_VALUE}(CALLDATA);
        ret;

        uint256 attackerAfter = TOKEN == address(0)
            ? ATTACKER.balance
            : IERC20(TOKEN).balanceOf(ATTACKER);

        // Pass = attacker successfully extracted value via the exact calldata
        assertTrue(ok, "Suspicious call reverted -- invalid PoC");
        assertGt(attackerAfter, attackerBefore,
                 "Call succeeded but no value moved to attacker");
    }
}
