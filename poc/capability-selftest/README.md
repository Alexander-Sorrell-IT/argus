# Capability self-test — the CONFIRMED path, end-to-end

**This is NOT a real LayerZero finding.** It is a deliberately-vulnerable contract
(a classic reentrancy: external call before the state update) plus a Foundry exploit
test that genuinely drains it. Its only job is to prove Argus's
`detect → fork-validate → CONFIRMED` path reaches a *real* green CONFIRMED on an
actual exploit — so the validator's CONFIRMED verdict is trustworthy, not a stub.

## Run it
```bash
cd poc/capability-selftest
forge install foundry-rs/forge-std --no-git   # provides lib/forge-std
forge test --match-contract ArgusCapabilitySelfTest -vv
```
Expected: `[PASS] test_reentrancyDrainConfirmsExploit` with
`ATTACKER_NET_GAIN_WEI: 5.000000000000000000` — the attacker deposited 1 ETH and
walked away with 6 (the victim's 5 ETH), reproducing the exploit.

## Through the validator
```bash
python3 poc/validate_finding.py \
  --finding-id capability-selftest-confirmed \
  --tx-hash 0x...selftest --chain ethereum --fork-block <any forkable block> \
  --foundry-test poc/capability-selftest/Exploit.t.sol
```
The validator forks mainnet with Anvil, runs the test, and — because the test's own
assertions pass — writes a `layerzero:fork_result` with `status=CONFIRMED`. A
legitimate large transfer, by contrast, yields an honest `REJECTED` (access control
holds; "not a bug"). Argus never fabricates a verdict and never reports gains it did
not measure (`attacker_gain_eth` is `null` unless asserted inside the test).
