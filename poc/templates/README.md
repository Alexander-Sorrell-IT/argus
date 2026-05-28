# Foundry exploit templates

Five parameterized `.t.sol` templates for common DeFi attack classes. Copy
the relevant template into `poc/findings/<finding_id>/Exploit.t.sol`, fill
in the placeholders, and run via `poc/validate_finding.py`.

| Template | Attack class | When to use |
|---|---|---|
| `Replay.t.sol` | Cross-chain message replay | Same message ID seen on >1 chain or >1 block on the same chain |
| `DvnBypass.t.sol` | Decentralized verifier bypass | Packet delivered without sufficient DVN signatures |
| `AdminKeyGrant.t.sol` | Unauthorized owner / config change | `transferOwnership` or `setConfig` from non-admin |
| `Reentrancy.t.sol` | Cross-contract reentrancy | External call before state update |
| `ValueExtraction.t.sol` | Generic drain / unauthorized withdrawal | Anomalously large value transfer w/ unknown sender |

## How to use

1. Copy the template into a new finding directory:
   ```bash
   mkdir -p poc/findings/$(date +%Y%m%d-%H%M)-mybug
   cp poc/templates/Replay.t.sol poc/findings/$(date +%Y%m%d-%H%M)-mybug/Exploit.t.sol
   ```
2. Edit the file — find every `// FILL:` and replace with actual addresses / block / args.
3. Validate against an Anvil fork:
   ```bash
   python poc/validate_finding.py \
       --tx-hash 0xabc... \
       --chain ethereum \
       --fork-block <block before suspicious tx> \
       --foundry-test poc/findings/<id>/Exploit.t.sol \
       --target <victim contract> \
       --attacker <attacker EOA>
   ```
4. If the test passes (exploit reproduces) AND fork-validator confirms
   value movement → automatic submission template lands in the same dir.

## Common to every template

- All tests inherit `forge-std/Test.sol`
- All read `FOUNDRY_RPC_URL` from env (passed by the validator)
- All use `vm.createSelectFork(rpc, blockNumber)` to fork
- All `assertGt(attackerBalanceAfter, attackerBalanceBefore)` or equivalent — never `assertTrue(true)`
- None of them write to mainnet — local fork only, per LayerZero Immunefi rules
