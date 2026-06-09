# Replay — TempleDAO (STAX) broken access control

**This is a REPLAY of a KNOWN, PUBLIC historical exploit. It is NOT a novel discovery.**

The real on-chain attack against TempleDAO's STAX `StaxLPStaking` contract
(Ethereum mainnet, Oct 11 2022, ~$2.3M loss) is reproduced here against forked
mainnet state to prove one thing: `poc/validate_finding.py` reaches a genuine,
real-`forge`-`[PASS]` **CONFIRMED** on an actual exploit. Nothing about the
discovery is novel — the bug, the attacker, and the loss are all public history.

## What happened (the historical bug)

`StaxLPStaking.migrateStake(oldStaking, amount)` was meant to let the *old*
staking contract migrate a user's position. But it has **no access control** and
**blindly trusts the caller-supplied `oldStaking` address**:

1. it calls `oldStaking.migrateWithdraw(msg.sender, amount)` — an
   attacker-controlled callback, and
2. then credits `msg.sender` with `amount` staked LP via `_applyStake`.

The attacker passes their **own** contract as `oldStaking` (whose
`migrateWithdraw` is a no-op) plus the full LP balance as `amount`, gets credited
with LP they never deposited, then calls `withdrawAll(false)` to transfer the
real `xFraxTempleLP` tokens out. Single transaction.

## Provenance

| Field | Value |
|---|---|
| Protocol | TempleDAO (STAX) |
| Mechanism | Broken access control / unprotected callback-trusting function |
| Attack tx | `0x8c3f442fc6d640a6ff3ea0b12be64f1d4609ea94edd2966f42c01cd9bdcf04b5` |
| Attack block | 15725067 (fork at 15725066 — state just before the attack) |
| Attacker | `0x9C9fb3100a2A521985f0C47DE3b4598dafd25B01` |
| Attack contract | `0x2df9C154Fe24D081cFE568645fb4075d725431E0` |
| Vulnerable contract | `0xd2869042E12a3506100af1D192b5b04D65137941` (StaxLPStaking) |
| Prize token | `0xBcB8b7FC9197fEDa75C101fA69d3211b5a30dCD9` (xFraxTempleLP) |
| Loss | ~$2.3M |
| Public source | https://rekt.news/templedao-rekt/ |
| Adapted from | Public DeFiHackLabs PoC (`SunWeb3Sec/DeFiHackLabs`, `src/test/2022-10/Templedao_exp.sol`) |

## Result

`validate_finding.py` returned **CONFIRMED** from a real `forge [PASS]` — not
hand-edited, not weakened. The PoC drained `321154.865567124596801893`
xFraxTempleLP (the entire staking-contract balance) in a single tx. The
validator's independent `cast`-run re-trace of the **real** attack tx shows the
identical flow and identical amount (see `trace_summary` in
`validator_result.json`), confirming the PoC reproduces the genuine mechanism.

Files in this directory:

- `Exploit.t.sol` — the working Foundry test (a copy of the live project at
  `poc/replays/templedao-access-control/`).
- `validator_result.json` — the validator's JSON output (status CONFIRMED,
  `test_passed: true`, with the real-attack-tx `trace_summary`).
- `context.json` — full provenance record.

### Reproduce

```bash
cd ~/Desktop/omni-guard
set -a && source .env && set +a
python3 poc/validate_finding.py \
  --tx-hash 0x8c3f442fc6d640a6ff3ea0b12be64f1d4609ea94edd2966f42c01cd9bdcf04b5 \
  --chain ethereum \
  --fork-block 15725066 \
  --foundry-test poc/replays/templedao-access-control/Exploit.t.sol \
  --no-splunk
```

Expected: `status: CONFIRMED`, `ATTACKER_LP_GAIN: 321154.865567124596801893`.

## The honesty pair — "it cannot bluff"

This CONFIRMED is paired with a real **REJECTED** at
[`poc/findings/2026-05-27-puffer-001`](../2026-05-27-puffer-001/):

- **CONFIRMED here:** a real exploit (TempleDAO STAX), replayed, fork-reproduced,
  green only because the attacker genuinely walks away with the LP.
- **REJECTED there:** a real on-chain outlier (Puffer pufETH 58,766 ETH transfer)
  that the *same* validator could **not** turn into an exploit — the recipient
  enforces access control via a Gnosis Safe multisig, so the attacker hypothesis
  does not reproduce.

Same validator, same fork-and-test pipeline. It confirms a true exploit and
rejects a non-exploit. **The validator cannot bluff — the honesty is the
product.**
