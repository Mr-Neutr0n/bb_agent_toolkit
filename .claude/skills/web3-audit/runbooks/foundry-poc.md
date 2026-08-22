# Foundry PoC Template

Fork mainnet at a specific block, fund accounts, execute the exploit, assert the
impact. Chain interaction is intrusive — confirm program scope before running.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/VulnerableContract.sol";

contract ExploitTest is Test {
    VulnerableContract target;
    address attacker = makeAddr("attacker");
    address victim = makeAddr("victim");

    function setUp() public {
        // Fork mainnet at specific block
        vm.createSelectFork("mainnet", BLOCK_NUMBER);
        target = VulnerableContract(TARGET_ADDRESS);
        deal(address(token), attacker, INITIAL_BALANCE);
        deal(address(token), victim, VICTIM_BALANCE);
    }

    function test_exploit() public {
        console.log("Attacker balance before:", token.balanceOf(attacker));
        vm.startPrank(attacker);
        // Step 1: Setup conditions
        // Step 2: Execute exploit
        // Step 3: Verify impact
        vm.stopPrank();
        console.log("Attacker balance after:", token.balanceOf(attacker));
        assertGt(token.balanceOf(attacker), INITIAL_BALANCE, "Exploit failed");
    }
}
```

## Key cheatcodes

| Cheatcode | Purpose |
|---|---|
| `vm.prank(address)` | Next call from address |
| `vm.startPrank(address)` | All calls from address until stopPrank() |
| `vm.deal(address, amount)` | Set ETH balance |
| `deal(token, address, amount)` | Set ERC20 balance |
| `vm.warp(timestamp)` | Set block.timestamp |
| `vm.roll(blockNumber)` | Set block.number |
| `vm.createSelectFork("mainnet", n)` | Fork mainnet at block n |
| `vm.expectRevert(bytes)` | Next call should revert |

## Running

```bash
forge test --match-test test_exploit -vvvv
forge test --match-test test_exploit -vvvv --fork-url $MAINNET_RPC
forge test --gas-report
forge coverage --report summary
```
