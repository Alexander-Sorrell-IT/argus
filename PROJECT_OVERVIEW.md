# Argus — Splunk Agentic Ops for Cross-Chain Protocol Security

> *In Greek mythology, Argus Panoptes had 100 eyes — none of them ever slept.*
>
> Built for the **Splunk Agentic Ops Hackathon 2026** (Security track).
> Argus is a Splunk-native AI security platform that monitors arbitrary DeFi
> protocols via a single YAML config. It detects on-chain anomalies with SPL,
> filters out already-documented findings against a local audit corpus,
> triages each novel candidate with an in-app AI agent (a Splunk modular
> input running deterministic, Splunk-native tier-0 scoring), and validates
> exploits locally against an Anvil mainnet fork. Zero external AI in the
> live path.

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
| Detection | SPL `eventstats` (z-score per contract), `streamstats`, `predict`, `cluster`, MLTK DBSCAN — ~14 SPL detections |
| Filtering | SPL JOIN against `layerzero:audit_finding` index (1,288 audit chunks) |
| Source code analysis | `layerzero:source` indexed (197 Solidity files), SPL pattern matching |
| Enrichment | `bad_addresses.csv` lookup (chainabuse + OFAC) |
| State | Splunk kvstore (`contract_baselines` collection) — nightly rebuild via saved search |
| AI agent (live) | `argus_agent.py` modular input running in `splunkd` via the Splunk Python SDK; 5-min interval; deterministic Splunk-native tier-0 triage (`reasoning_engine = splunk_native_tier0`); writes `layerzero:ai_report` + `layerzero:poc_trigger`, KV-deduped by finding signature |
| AI reasoning (roadmap) | local-MLX Foundation-Sec LLM (`agent/splunk_ai.py`) + official MCP Server + Splunk AI Assistant (SAIA) — integrated but **not** the live reasoning path |
| Output | Typed sourcetypes: `:transaction`, `:event`, `:source`, `:audit_finding`, `:scope`, `:alert`, `:ai_report`, `:fork_result`, `:poc_trigger`, `:static_finding` |
| Notifications | macOS notify + `findings_feed.log` + Slack alert action |

---

## End-to-end pipeline

```
   KNOWLEDGE LOAD (one-time)
   ────────────────────────
   protocols/<name>.yaml      ─── contracts, chains, source path, audit path
   on-chain history           ─── tx + events + internal tx since deploy
   Solidity source            ─── parsed into indexable per-file events
   audit corpus (→ 1,288 indexed chunks) ─── extracted, structured fields
   Immunefi rules             ─── scope contracts + impact tiers + bounty caps
                              │
                              ▼
   DETECTION (~14 SPL detections, cron 5m–6h)
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
   AI AGENT TRIAGE (in-app modular input — LIVE)
   ──────────────────────────────────────────────
   • argus_agent.py runs in splunkd every 5 min via the Splunk Python SDK
   • Pulls distinct recent findings from layerzero:alert (deduped by signature)
   • Triages each into a structured verdict: severity → vulnerability class,
     confidence, recommended action (deterministic Splunk-native tier-0)
   • Writes layerzero:ai_report + layerzero:poc_trigger; KV-deduped so a
     re-firing alert never floods or re-works
   • No external model in the loop (reasoning_engine = splunk_native_tier0).
     Foundation-Sec LLM / MCP / SAIA are integrated but roadmap, not live.
                              │
                              ▼
   FORK VALIDATION (Anvil mainnet fork + Foundry test)
   ────────────────────────────────────────────────────
   • poc/validate_finding.py spins Anvil, forking ETH mainnet at block N-1
   • Run template-based exploit test against fork
   • Diff attacker/target balances → honest CONFIRMED | REJECTED
     (gain reported null, never fabricated)
   • Writes layerzero:fork_result event
                              │
                              ▼ if CONFIRMED
   STRUCTURED OUTPUT
   ─────────────────
   • Immunefi submission.md draft auto-generated in poc/findings/<id>/
   • macOS notification fires
   • findings_feed.log appended
   • Manual review → submit privately to Immunefi
```

---

## Installed Splunk apps (12)

| App | Purpose |
|---|---|
| Argus Security Monitor (this app) | Custom SPL detections + dashboard + lookups + the live `argus_agent` modular input |
| Splunk AI Toolkit (5.7.4) | MLTK ML-SPL commands (DBSCAN clustering) |
| Python for Scientific Computing (Apple Silicon 4.3.2) | Runtime for AI Toolkit |
| Splunk Security Essentials (3.8.3) | Pre-built security patterns library |
| Splunk MCP Server (1.1.3) | Official MCP interface — integrated, **roadmap** reasoning path (not the live agent) |
| Splunk AI Assistant (2.0.0) | Cloud-connected LLM tier (SAIA) — integrated but **never activated**; roadmap, not live |
| Splunk AI Canvas (1.4.1) | AI workspace (roadmap) |
| InfoSec App (1.7.1) | Security dashboards |
| Generic LLM Connector | Optional alternative LLM path (roadmap) |
| TA-Triage | `\| triage` SPL command |
| Slack Alerts (2.3.2) | Optional Slack notifications |
| Audit Trail (1.0.0) | Default Splunk audit log |

---

## Indexed data inventory

| Sourcetype | Count | Purpose |
|---|---|---|
| `layerzero:transaction` | ~335k (growing) | On-chain transactions |
| `layerzero:event` | ~907k | On-chain events / logs |
| `layerzero:source` | 197 | Solidity source files |
| `layerzero:audit_finding` | 1,288 | Audit corpus chunks |
| `layerzero:scope` | growing | Immunefi scope + reward tiers |
| `layerzero:alert` | growing | SPL detection hits (9 value-manipulation candidates surfaced) |
| `layerzero:ai_report` | 21 | In-app agent triage verdicts (live, Splunk-native tier-0) |
| `layerzero:poc_trigger` | growing | Fork-validation triggers emitted by the agent |
| `layerzero:fork_result` | growing | Anvil PoC validation results (honest CONFIRMED/REJECTED) |
| `bad_addresses.csv` lookup | 10 | Known-malicious sender list |
| `contract_baselines` kvstore | growing | Per-contract statistical baselines (15 contracts monitored) |

---

## Hackathon prize alignment

| Prize | $ | How Argus hits it |
|---|---|---|
| Grand Prize | 7,000 | Productizable platform; YAML-configurable for any protocol; novel fork-validation workflow |
| Best of Security | 3,000 | Real cross-chain protocol security tool, ground-truth validation, MITRE-mappable |
| Best AI Agent for Splunk Apps | — | **Live, scored capability.** `argus_agent.py` is an in-app modular input running inside `splunkd` via the Splunk Python SDK: it drives Splunk end-to-end (read findings → triage → write `:ai_report` → trigger fork validation), KV-deduped and idempotent. Deterministic, Splunk-native, sovereign (zero external AI) |
| Best Use of Splunk MCP Server | 1,000 | **Roadmap, not live.** MCP Server is installed and integrated as an alternative reasoning path (`agent/mcp_agent.py`); the live triage loop does not depend on it |
| Best Use of Splunk Hosted Models | 1,000 | **Roadmap, not live.** SAIA / hosted-model and the local-MLX Foundation-Sec LLM (`agent/splunk_ai.py`) are integrated but never activated; live verdicts come from deterministic Splunk-native scoring |
| Most Valuable Feedback | 200 | Detailed feedback to Splunk team on app integration friction |

---

## Six-month roadmap

Hackathon deadline is **Jun 15, 2026**. Dev license is valid for **6 months**, so Argus runs through **Nov 2026**.

- **Weeks 1-3 (now → Jun 15):** ship hackathon submission, demo polish, video, architecture diagram, Devpost
- **Months 1-2 post-hackathon:** continuous LayerZero monitoring, tune detections based on actual signal, expand to multi-protocol YAML configs
- **Months 3-4:** activate the roadmap reasoning path — wire the in-app agent to the local-MLX Foundation-Sec LLM and/or SAIA via MCP for richer (non-deterministic) hypothesis generation, on top of the deterministic tier-0 floor
- **Months 5-6:** apply Argus to additional Immunefi protocols (Aave, Compound, Uniswap, EigenLayer); harden, document, consider commercialization

---

## Status

- ✅ Pipeline plumbing complete end-to-end
- ✅ All Splunk-native principles satisfied (sovereign: zero external AI in the live path)
- ✅ In-app AI agent live as a `splunkd` modular input — 21 real `layerzero:ai_report` verdicts written
- ✅ Audit corpus indexed and SPL-queryable (1,288 chunks)
- ✅ Anvil fork validation working — proven this session with a real, honest REJECTED on a legitimate large transfer
- ✅ Immunefi submission template generation
- 🛣️ Roadmap: activate local-MLX Foundation-Sec LLM / SAIA / MCP reasoning path on top of the deterministic floor
- ⏳ Historical scan continuing in background
- ⏳ Demo video script + recording (last week before deadline)

---

## License + author

- **Author:** Alexander Sorrell (alexander.sorrell.it@gmail.com)
- **License:** AGPL-3.0 (open source; commercial use requires separate license from author)
- **Repo:** local; publishes Jun 15 2026 for hackathon submission
- **Commercial license:** available, contact author
