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

`vulnerability_class` uses a standard external taxonomy; the detector column names the Argus saved search
(e.g. `Argus - Value Transfer Outlier` / `Argus - Token Transfer Outlier`) whose footprint would fire.

| Attack | Date | Class | Loss | Argus detector | Fork-reproducible |
|---|---|---|---|---|---|
| **TempleDAO (StaxLPStaking)** | 2022-10-11 | `access_control` | ~$2.3M | Privileged Function Call | ✅ **CONFIRMED (validated)** |
| Nomad Bridge | 2022-08-01 | `logic_error` | ~$190M | Multi-Step Attack Sequence | ✅ |
| Wormhole | 2022-02-02 | `signature_replay` | ~$326M | Value/Token Transfer Outlier | — (off-chain root cause) |
| Euler Finance | 2023-03-13 | `logic_error` | ~$197M | Multi-Step Attack Sequence | ✅ |
| Beanstalk Farms | 2022-04-17 | `flash_loan_governance` | ~$182M | Privileged Function Call | ✅ |
| Cream Finance | 2021-10-27 | `oracle_manipulation` | ~$130M | Multi-Step Attack Sequence | ✅ |
| Harvest Finance | 2020-10-26 | `oracle_manipulation` | ~$34M | Multi-Step Attack Sequence | ✅ |
| Qubit Finance | 2022-01-27 | `access_control` | ~$80M | Multi-Step Attack Sequence | ✅ |
| Rari Capital Fuse / Fei Protoc | 2022-04-30 | `reentrancy` | ~$80M | Multi-Step Attack Sequence | ✅ |
| Visor Finance | 2021-12-21 | `access_control` | ~$8.2M | Value/Token Transfer Outlier | ✅ |
| Multichain | 2022-01-18 | `signature_replay` | ~$3M | Value/Token Transfer Outlier | ✅ |
