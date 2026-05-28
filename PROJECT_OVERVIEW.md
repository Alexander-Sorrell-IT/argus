# Argus — Splunk Agentic Ops for Cross-Chain Protocol Security

> *In Greek mythology, Argus Panoptes had 100 eyes — none of them ever slept.*
>
> Built for the **Splunk Agentic Ops Hackathon 2026** (Security track).
> Argus is a Splunk-native AI security platform that monitors arbitrary DeFi
> protocols via a single YAML config. It detects on-chain anomalies with SPL,
> filters out already-documented findings against a local audit corpus,
> hypothesizes vulnerabilities via the Splunk-hosted LLM, and validates
> exploits locally against an Anvil mainnet fork.

---

## What this is

A reproducible bug-finding pipeline that uses **only Splunk-native primitives**
for analysis — no external AI as a primary brain. Drop a YAML pointing at a
protocol → the pipeline ingests its on-chain history, indexes its source code
and audit reports, runs statistical detections, cross-references findings
against existing audits, and ends in a fork-validated exploit attempt.

**LayerZero is the demo protocol.** The architecture is protocol-agnostic:
swap `protocols/<name>.yaml` and point it at any DeFi protocol (Aave,
Compound, Uniswap, EigenLayer, etc.).

> Internal codebase prefix is still `omni_guard` for the Splunk app namespace.
> "Argus" is the product/submission name; `omni_guard` is the implementation
> identifier (changing it would require renaming hundreds of references inside
> the installed Splunk app — not worth the churn).

---

## Splunk-native architecture

Every layer leans on Splunk's own primitives, not external code:

| Layer | Splunk primitive used |
|---|---|
| Detection | SPL `anomalydetection`, `cluster`, `outlier`, `streamstats`, `predict`, `transaction`, `eventstats` (z-score per contract) |
| Filtering | SPL JOIN against `layerzero:audit_finding` index (112 audits, 1,276 chunks) |
| Source code analysis | `layerzero:source` indexed (197 Solidity files), SPL pattern matching |
| Enrichment | `bad_addresses.csv` lookup (chainabuse + OFAC) |
| State | Splunk kvstore (`contract_baselines` collection) — nightly rebuild via saved search |
| AI reasoning | Splunk MCP Server (official) + Splunk AI Assistant (`saia_ask_splunk_question`, `saia_generate_spl`, `saia_explain_spl`, `saia_optimize_spl`) |
| Agent orchestration | Argus agent talks to Splunk only through MCP — no direct REST, no external creds in code |
| Output | Typed sourcetypes: `:transaction`, `:event`, `:source`, `:audit_finding`, `:scope`, `:alert`, `:ai_report`, `:fork_result`, `:confirmed_finding`, `:poc_trigger`, `:static_finding` |
| Notifications | macOS notify + `findings_feed.log` + Slack alert action |

---

## End-to-end pipeline

```
   KNOWLEDGE LOAD (one-time)
   ────────────────────────
   protocols/<name>.yaml      ─── contracts, chains, source path, audit path
   on-chain history           ─── tx + events + internal tx since deploy
   Solidity source            ─── parsed into indexable per-file events
   audit corpus (112 PDFs → 1,290 indexed chunks) ─── extracted, structured fields
   Immunefi rules             ─── scope contracts + impact tiers + bounty caps
                              │
                              ▼
   DETECTION (10 saved searches, cron 5m–6h)
   ─────────────────────────────────────────
   1. Value Outlier (z-score per contract, kvstore baseline)
   2. Sender Behavior Outlier
   3. Replay / Duplicate Message ID
   4. Rare Transaction Pattern Cluster (SPL `cluster`)
   5. Cross-Contract Sender Correlation
   6. Failed Tx Burst vs Baseline (streamstats)
   7. Tx Volume Forecast Deviation (SPL `predict`)
   8. Known-Bad Address Touched (lookup)
   9. Multi-Step Attack Sequence (SPL `transaction`)
   10. VaR Exposure Rollup (informational)
                              │
                              ▼
   FILTER (Splunk-native audit cross-reference)
   ────────────────────────────────────────────
   For each candidate alert, SPL query against layerzero:audit_finding:
     • If matched across N auditors → demote (already known)
     • If novel → keep as candidate finding
                              │
                              ▼
   AI INVESTIGATION (Splunk AI Assistant via MCP)
   ──────────────────────────────────────────────
   • saia_ask_splunk_question — hypothesis + severity classification
   • saia_generate_spl — auto-build a follow-up detection from natural language
   • Uses Splunk-hosted LLM via cloud-connected mode (no GPU, no external API)
                              │
                              ▼
   FORK VALIDATION (Anvil mainnet fork + Foundry test)
   ────────────────────────────────────────────────────
   • Spin Anvil at block N-1 of suspicious tx
   • Run generated/template-based exploit test against fork
   • Diff attacker/target balances → CONFIRMED | REJECTED
   • Writes layerzero:fork_result event
                              │
                              ▼ if CONFIRMED
   STRUCTURED OUTPUT
   ─────────────────
   • layerzero:confirmed_finding event indexed
   • Immunefi submission.md draft auto-generated in poc/findings/<id>/
   • macOS notification fires
   • findings_feed.log appended
   • Manual review → submit privately to Immunefi
```

---

## Installed Splunk apps (12)

| App | Purpose |
|---|---|
| Splunk MCP Server (1.1.3) | Official MCP interface, 14 tools exposed |
| Splunk AI Assistant (2.0.0) | Cloud-connected LLM tier — `saia_*` tools |
| Splunk AI Toolkit (5.7.4) | Advanced SPL ML commands |
| Splunk AI Canvas (1.4.1) | AI workspace |
| Python for Scientific Computing (Apple Silicon 4.3.2) | Runtime for AI Toolkit |
| Splunk Security Essentials (3.8.3) | Pre-built security patterns library |
| InfoSec App (1.7.1) | Security dashboards |
| Generic LLM Connector | Optional alternative LLM path |
| TA-Triage | `\| triage` SPL command |
| Slack Alerts (2.3.2) | Optional Slack notifications |
| Argus / OmniGuard Security Monitor (this app) | Custom searches + dashboard + lookups |
| Audit Trail (1.0.0) | Default Splunk audit log |

---

## Indexed data inventory

| Sourcetype | Count | Purpose |
|---|---|---|
| `layerzero:transaction` | ~1.2M+ (growing) | On-chain transactions |
| `layerzero:event` | 86k+ | On-chain events / logs |
| `layerzero:source` | 197 | Solidity source files |
| `layerzero:audit_finding` | 1,290 | Audit corpus chunks (17 auditors) |
| `layerzero:scope` | 28 | Immunefi scope + reward tiers |
| `layerzero:alert` | growing | SPL detection hits |
| `layerzero:ai_report` | 0 (until SAIA live) | LLM investigation outputs |
| `layerzero:fork_result` | growing | Anvil PoC validation results |
| `layerzero:confirmed_finding` | 0 (waiting) | Validated exploits |
| `bad_addresses.csv` lookup | 10 | Known-malicious sender list |
| `contract_baselines` kvstore | 5+ (growing) | Per-contract statistical baselines |

---

## Hackathon prize alignment

| Prize | $ | How Argus hits it |
|---|---|---|
| Grand Prize | 7,000 | Productizable platform; YAML-configurable for any protocol; novel fork-validation workflow |
| Best of Security | 3,000 | Real cross-chain protocol security tool, ground-truth validation, MITRE-mappable |
| Best Use of Splunk MCP Server | 1,000 | Agent talks to Splunk only through official MCP Server (14 tools, encrypted token auth) |
| Best Use of Splunk Hosted Models | 1,000 | Tier-1 triage + hypothesis generation via Splunk AI Assistant cloud-connected mode |
| Best Use of Splunk Developer Tools | 1,000 | AI Assistant used for SPL generation during build, documented in repo |
| Most Valuable Feedback | 200 | Detailed feedback to Splunk team on app integration friction |
| **Ceiling** | **~13,200** | |

---

## Six-month roadmap

Hackathon deadline is **Jun 15, 2026**. Dev license + SAIA are valid for **6 months**, so Argus runs through **Nov 2026**.

- **Weeks 1-3 (now → Jun 15):** ship hackathon submission, demo polish, video, architecture diagram, Devpost
- **Months 1-2 post-hackathon:** continuous LayerZero monitoring, tune detections based on actual signal, expand to multi-protocol YAML configs
- **Months 3-4:** apply Argus to additional Immunefi protocols (Aave, Compound, Uniswap, EigenLayer)
- **Months 5-6:** harden, document, consider commercialization

---

## Status

- ✅ Pipeline plumbing complete end-to-end
- ✅ All Splunk-native principles satisfied
- ✅ 12 Splunk apps installed and configured
- ✅ Audit corpus indexed and SPL-queryable
- ✅ Anvil fork validation working
- ✅ Immunefi submission template generation
- ⏳ Waiting on SAIA tenant activation (estimated Tue May 27)
- ⏳ Historical scan continuing in background
- ⏳ Demo video script + recording (last week before deadline)

---

## License + author

- **Author:** Alexander Sorrell (alexander.sorrell.it@gmail.com)
- **License:** AGPL-3.0 (open source; commercial use requires separate license from author)
- **Repo:** local; publishes Jun 15 2026 for hackathon submission
- **Commercial license:** available, contact author
