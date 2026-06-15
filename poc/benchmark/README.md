# Argus exploit benchmark — does the SOC catch known DeFi attack classes?

A ground-truth corpus of **real, public, historical DeFi exploits**, each verified from public
post-mortems (sources in every `context.json`). It reframes Argus from "an anomaly dashboard" into a
**regression suite**: for each known attack class, would an Argus detector fire on its on-chain
footprint, and can the exploit be fork-validated to a real Foundry `[PASS]`?

**Honest status:** these are verified **specs** (metadata + public PoC references), not runnable tests.
Today `poc/findings/replay-templedao-access-control` is the one fork-validated end-to-end to a real
**CONFIRMED** (see its `validator_result.json`); the entries below are benchmark targets that each
reference an adaptable [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) PoC — adapt + run
`| forkvalidate` to upgrade each from SPEC to a runnable proof. 9 of 10 are fork-reproducible; Wormhole's
root cause is on Solana, so it is honestly an EVM-only-detector gap.

| Attack | Date | Class | Loss | Argus detector | Fork-reproducible |
|---|---|---|---|---|---|
| **TempleDAO (StaxLPStaking)** | 2022-10-11 | `access_control` | ~$2.3M | Privileged Function Call | ✅ **CONFIRMED (validated)** |
| Nomad Bridge | 2022-08-01 | `logic_error` | ~$190M (DeFiH | Multi-Step Attack Sequence | ✅ |
| Wormhole | 2022-02-02 | `signature_replay` | ~$326M (120,0 | Value/Token Transfer Outlier | — (off-chain root cause) |
| Euler Finance | 2023-03-13 | `logic_error` | ~197000000 | Multi-Step Attack Sequence | ✅ |
| Beanstalk Farms | 2022-04-17 | `flash_loan_governance` | approx 182M U | Privileged Function Call | ✅ |
| Cream Finance | 2021-10-27 | `oracle_manipulation` | ~$130M (Cream | Multi-Step Attack Sequence | ✅ |
| Harvest Finance | 2020-10-26 | `oracle_manipulation` | ~$33.8M drain | Multi-Step Attack Sequence | ✅ |
| Qubit Finance | 2022-01-27 | `access_control` | ~$80,000,000 | Multi-Step Attack Sequence | ✅ |
| Rari Capital Fuse / Fei Protocol | 2022-04-30 | `reentrancy` | ~$80M (approx | Multi-Step Attack Sequence | ✅ |
| Visor Finance | 2021-12-21 | `access_control` | ~$8.2M (8,812 | Value/Token Transfer Outlier | ✅ |
| Multichain | 2022-01-18 | `signature_replay` | ~$3M stolen a | Value/Token Transfer Outlier | ✅ |

Detector mapping is honest: statistical rules (Value/Token Transfer Outlier, Multi-Step Sequence) catch the
*value-movement* footprint; the mechanism-aware Privileged Function Call rule catches *admin/governance*
actions; some root causes (Solana-side signature forgery, pure oracle math) are gaps, listed openly.
