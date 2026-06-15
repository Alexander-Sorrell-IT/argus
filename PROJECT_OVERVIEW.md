# Argus — Splunk Agentic Ops for Cross-Chain Protocol Security

> *In Greek mythology, Argus Panoptes had 100 eyes — none of them ever slept.*
>
> Built for the **Splunk Agentic Ops Hackathon 2026** (Security track).
> Argus is a Splunk-native AI security platform that monitors arbitrary DeFi
> protocols via a single YAML config. It detects on-chain anomalies with SPL,
> filters out already-documented findings against a local audit corpus,
> triages each novel candidate with an in-app AI agent (a Splunk modular
> input running deterministic, Splunk-native tier-0 scoring), and validates
> exploits locally against an Anvil mainnet fork. The production AI path is
> Splunk's own — deterministic SPL for the verdicts, and Splunk's hosted
> **SAIA** model to author the detections. (An experimental local-MLX tier
> sits off the verdict path; see roadmap.)
>
> **Naming:** *Argus* is the product; *`omni_guard`* is its Splunk-native engine
> (the `omni_guard_security` index, SPL detections, KV state, the in-app agent,
> and the `| forkvalidate` command), with `TA-triage-v1` as the ingest/triage
> add-on. Argus = the app; `omni_guard` = the engine it runs on — intentional
> layers, not a half-finished rename.

---

## What this is

A reproducible bug-finding pipeline that uses **only Splunk-native primitives**
for analysis — the verdicts are deterministic SPL, and the production LLM in the
system is Splunk's own hosted **SAIA** (used to author detections). An
experimental local-MLX tier sits off the verdict path (see roadmap). Drop a YAML pointing at a
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

Every layer leans on Splunk's own primitives:

| Layer | Splunk primitive used |
|---|---|
| Detection | SPL `eventstats` (z-score per contract), `streamstats`, `predict`, `cluster`, + a mechanism-aware privileged-call rule (`lookup` of admin selectors) — 13 detections + 3 scoring/baseline jobs (16 saved searches; an optional MLTK clustering search ships disabled) |
| Filtering | SPL cross-reference against `layerzero:audit_finding` (ingestion pipeline included; corpus not bundled in this repo) |
| Source code analysis | `layerzero:source` indexed (197 Solidity files), SPL pattern matching |
| Enrichment | `bad_addresses.csv` lookup (chainabuse + OFAC) |
| State | Splunk kvstore (`contract_baselines` collection) — nightly rebuild via saved search |
| AI agent (live) | `argus_agent.py` modular input running in `splunkd` via the Splunk Python SDK; 5-min interval; deterministic Splunk-native tier-0 triage (`reasoning_engine = splunk_native_tier0`); writes `layerzero:ai_report` + `layerzero:poc_trigger`, KV-deduped by finding signature |
| AI detection authoring (live) | **Splunk AI Assistant (SAIA)** — Splunk's hosted LLM — **writes new SPL detections** from plain-English threat descriptions and **explains existing SPL**, via the SAIA `/predict` API (`agent/saia_generate_detection.py`, verified live, ~15s; output in `splunk/generated/`). Invoked on demand, not in the 5-min tick. (Free-form finding-*judgment* via SAIA's "tell me" mode — `agent/llm_enrich.py` — is experimental and unreliable for this tenant: it deflects or times out, so it is **not** in the verdict path. Local-MLX Foundation-Sec stays roadmap.) |
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
   audit corpus (pipeline included; corpus not bundled) ─── extracted, structured fields
   Immunefi rules             ─── scope contracts + impact tiers + bounty caps
                              │
                              ▼
   DETECTION (12 active detections + 3 scoring/baseline jobs, cron 5m–6h)
   ─────────────────────────────────────────
   1. Value Outlier (z-score per contract, kvstore baseline)
   2. Sender Behavior Outlier
   3. Replay / Duplicate Message ID  (removed — flagged ordinary LZ message delivery as FPs)
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
   • Verdicts come from the deterministic floor (reasoning_engine =
     splunk_native_tier0). Separately — and live — the Splunk AI Assistant
     (SAIA) authors/explains the SPL detections themselves (not the verdicts).
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
| Splunk MCP Server (1.1.3) | Official MCP interface — integrated (`agent/splunk_mcp_client.py` speaks JSON-RPC to `/services/mcp` for Splunk tool calls); the in-app agent uses the SDK directly |
| Splunk AI Assistant (2.0.0) | Cloud-connected LLM (SAIA) — **LIVE**: authors + explains SPL detections from plain English via `/predict` (verified, ~15s) |
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
| `layerzero:transaction` | 418 (bundled sample; live ingester scales to full history) | On-chain transactions |
| `layerzero:event` | 400 (bundled sample) | On-chain events / logs |
| `layerzero:source` | Solidity source files (when ingested) | Solidity source files |
| `layerzero:audit_finding` | 0 bundled — pipeline included, supply your own corpus | Audit corpus chunks |
| `layerzero:scope` | growing | Immunefi scope + reward tiers |
| `layerzero:alert` | growing | SPL detection hits (9 value-manipulation candidates surfaced) |
| `layerzero:ai_report` | 21 | In-app agent triage verdicts (live, Splunk-native tier-0) |
| `layerzero:poc_trigger` | growing | Fork-validation triggers emitted by the agent |
| `layerzero:fork_result` | growing | Anvil PoC validation results (honest CONFIRMED/REJECTED) |
| `bad_addresses.csv` lookup | 10 | Known-malicious sender list |
| `contract_baselines` kvstore | growing | Per-contract statistical baselines (13 contracts monitored) |

---

## Hackathon prize alignment

| Prize | $ | How Argus hits it |
|---|---|---|
| Grand Prize | 7,000 | Productizable platform; YAML-configurable for any protocol; novel fork-validation workflow |
| Best of Security | 3,000 | Real cross-chain protocol security tool, ground-truth validation, MITRE-mappable |
| Best AI Agent for Splunk Apps | — | **Live, scored capability.** `argus_agent.py` is an in-app modular input running inside `splunkd` via the Splunk Python SDK: it drives Splunk end-to-end (read findings → triage → write `:ai_report` → trigger fork validation), KV-deduped and idempotent. Deterministic and Splunk-native — the verdict path makes zero AI calls |
| Best Use of Splunk MCP Server | 1,000 | Integrated — `agent/splunk_mcp_client.py` drives the official MCP Server (`/services/mcp`, encrypted token) for Splunk tool calls; the in-app agent itself uses the SDK directly |
| Best Use of Splunk Hosted Models | 1,000 | **LIVE.** The Splunk AI Assistant (SAIA), on Splunk's hosted LLM, authors new SPL detections from plain English and explains existing SPL (`agent/saia_generate_detection.py`, verified running live, ~15s), on top of the deterministic tier-0 floor |
| Best Use of Splunk Developer Tools | 1,000 | **LIVE.** SAIA generates and explains SPL detections from plain-English threat descriptions via `/predict` — AI-assisted detection authoring (`agent/saia_generate_detection.py`) |
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
- ✅ All Splunk-native principles satisfied (verdict path makes zero AI calls; the production LLM is Splunk's own hosted SAIA, used to author detections — the local-MLX tier is experimental and off the verdict path)
- ✅ In-app AI agent live as a `splunkd` modular input — 21 real `layerzero:ai_report` verdicts written
- 🔲 Audit corpus: ingestion pipeline included, but the corpus is not bundled in this repo (supply your own audit reports to populate `layerzero:audit_finding`)
- ✅ Anvil fork validation working — proven this session with a real, honest REJECTED on a legitimate large transfer
- ✅ Immunefi submission template generation
- ✅ Splunk AI Assistant (SAIA) LIVE — authors new SPL detections from plain English and explains existing SPL (verified, ~15s; output in `splunk/generated/`)
- 🛣️ Roadmap: SAIA free-form finding-judgment (today it deflects/times out for this tenant — 1/30 usable, so it is **not** in the verdict path); local-MLX Foundation-Sec for fully-offline reasoning; richer MCP-driven agent orchestration
- ⏳ Historical scan continuing in background
- ⏳ Demo video script + recording (last week before deadline)

---

## License + author

- **Author:** Alexander Sorrell (alexander.sorrell.it@gmail.com)
- **License:** AGPL-3.0 (open source; commercial use requires separate license from author)
- **Repo:** local; publishes Jun 15 2026 for hackathon submission
- **Commercial license:** available, contact author
