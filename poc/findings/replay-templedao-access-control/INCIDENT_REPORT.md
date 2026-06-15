# Argus incident report — TempleDAO StaxLPStaking (CONFIRMED)

| | |
|---|---|
| **Verdict** | ✅ **CONFIRMED** — fork-validated by a real Foundry `[PASS]` |
| **Protocol** | TempleDAO — `StaxLPStaking` |
| **Vulnerability class** | `access_control` (unprotected, callback-trusting function) |
| **Chain / date** | Ethereum · 2022-10-11 |
| **Attack tx** | `0x8c3f442fc6d640a6ff3ea0b12be64f1d4609ea94edd2966f42c01cd9bdcf04b5` |
| **Fork block** | 15725066 (state immediately before the attack) |
| **Attacker** | `0x9C9fb3100a2A521985f0C47DE3b4598dafd25B01` |
| **Victim contract** | `0xd2869042E12a3506100af1D192b5b04D65137941` (StaxLPStaking) |
| **Reported loss** | ~$2.3M ([rekt.news/templedao-rekt](https://rekt.news/templedao-rekt/)) |

## Mechanism
`StaxLPStaking.migrateStake(oldStaking, amount)` had **no access control** and blindly trusted the
caller-supplied `oldStaking` address: it called `oldStaking.migrateWithdraw(...)` (an attacker-controlled
callback) and then credited `msg.sender` with `amount` staked LP via `_applyStake`. The attacker passed
their own contract as `oldStaking` (a no-op `migrateWithdraw`) plus the full LP balance as `amount`,
getting credited with LP they never deposited, then called `withdrawAll(false)` to transfer the real LP
tokens out — in a single transaction.

## How Argus reaches CONFIRMED
1. **Detect** — the on-chain footprint is a privileged `migrateStake` call; Argus's mechanism-aware
   **Privileged Function Call** detection flags selector `0xbdcd9c80` on a monitored contract.
2. **Prove** — `| forkvalidate` forks mainnet with Anvil at block 15725066 and runs the Foundry exploit
   test. It writes **CONFIRMED only on a real `[PASS]`**.

```
status        : CONFIRMED
test_passed   : True
confidence    : 0.7
fork_block    : 15725066
attacker_gain : 321154.865567124596801893 xFraxTempleLP  (asserted by the test, not measured via fork balances)
```

## Honesty notes
- The verdict is **deterministic** — CONFIRMED comes from the Foundry test's own `assertGt(gain, 0, ...)`
  passing on a real fork, **not** from any AI or fabricated number.
- `attacker_gain` is the value the test **asserted/emitted**, not an independent fork-balance measurement —
  labelled as such. Economic loss above is the public reported figure, not an Argus measurement.
- This is a **replay** of a known public exploit (proving the detect→prove pipeline reaches a real
  CONFIRMED on a true exploit) — it is not a novel discovery by Argus.

_Generated from `context.json` + `validator_result.json` in this directory._
