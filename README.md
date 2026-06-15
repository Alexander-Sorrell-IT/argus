# Argus 👁️

> **A Splunk-native security operations platform for cross-chain DeFi protocols.**
>
> *In Greek mythology, Argus Panoptes had 100 eyes — none of them ever slept.*

Built for the **Splunk Agentic Ops Hackathon 2026** (Security track).

Argus turns Splunk into a security operations center for production smart
contracts. Point it at any DeFi protocol via a single YAML config and get
continuous monitoring, statistical anomaly detection, audit-aware
filtering, an in-app AI agent that triages every novel candidate, and
ground-truth exploit validation against a local mainnet fork — all using
Splunk's native primitives. The AI agent runs *inside* Splunk as a
modular input; its triage is deterministic and Splunk-native, so the
verdict path makes zero AI calls. The LLM in the production loop is
Splunk's own hosted **SAIA**, which authors the SPL detections; a local
experimental tier (MLX Qwen2.5 / Foundation-Sec) remains tagged in the
index (`reasoning_engine`) but is not the production verdict path.

### Naming: Argus vs. `omni_guard`
**Argus is the product; `omni_guard` is its Splunk-native engine** — the app and
the roads it runs on. The engine is a Splunk app whose id is `omni_guard`: the
`omni_guard_security` index (the data plane), the SPL detections, the KV-store
state, the in-app modular-input agent, and the `| forkvalidate` custom search
command — with the `TA-triage-v1` add-on handling ingest/triage. So every
`omni_guard` you see in SPL and config **is** Argus's engine under the hood. The
two names are intentional layers — product on top, Splunk engine underneath —
not a half-finished rename.

LayerZero is the demo protocol. The architecture is protocol-agnostic.

---

## Why this matters

Smart contracts are deployed once and run for years. There is no `tail -f`
for production protocols. Security incidents surface in Telegram an hour
after $50M is gone. Argus closes that gap:

- **Continuous ingestion** of every transaction and event touching the
  contracts you care about.
- **SPL anomaly detection** runs on a cron — z-score, cluster, outlier,
  forecast deviation — surfacing only what's unusual.
- **Audit cross-reference** (pipeline included — `ingest_audit_findings.py`)
  can demote issues that LayerZero's auditors already flagged by indexing
  audit reports as `layerzero:audit_finding`. The audit corpus itself is
  *not bundled* in this repo — supply your own reports to populate it.
- **In-app AI agent** — a Splunk modular input (`argus_agent.py`) runs in
  `splunkd` every 5 minutes, triages each novel candidate into a
  structured verdict, assigns a vulnerability class, and decides whether
  it's worth a proof-of-concept. The triage is deterministic and
  Splunk-native (verdict driven by SPL severity; `reasoning_engine =
  splunk_native_tier0`) — no external model in the production verdict
  path (a local MLX Qwen2.5 / Foundation-Sec tier was experimental only).
- **Anvil mainnet fork** validates the exploit hypothesis locally —
  ground truth, no hallucination at the final step. Results are honest
  CONFIRMED / REJECTED (gain is reported null, never fabricated).
- **Structured output** ready for the on-call operations team.

---

## Splunk-native architecture

Every layer leans on Splunk primitives. The agent contains zero
detection logic — Splunk does all the analysis — and its triage is
deterministic Splunk-native scoring, not an external LLM.

| Layer | Splunk primitive |
|---|---|
| Detection | `eventstats` (z-score), `streamstats`, `predict`, `cluster`, + a mechanism-aware privileged-call rule (`lookup` of admin/ownership/upgrade/LZ-config selectors — catches the access-control class z-scores miss) — 13 detections + 3 scoring/baseline jobs (16 saved searches, pure SPL; an optional MLTK-DBSCAN search ships disabled, needs the ML Toolkit) |
| Filtering | SPL cross-reference against an audit corpus (`layerzero:audit_finding`) — ingestion pipeline included; corpus not bundled in this repo |
| Source analysis | SPL pattern matching against indexed Solidity (`layerzero:source`) |
| Enrichment | CSV lookup (`bad_addresses.csv`) |
| State | Splunk kvstore (`contract_baselines`) — nightly rebuild |
| AI agent (live) | `argus_agent.py` modular input running in `splunkd` (Python SDK), 5-min interval, deterministic tier-0 triage → `layerzero:ai_report` |
| AI detection authoring (live) | **Splunk AI Assistant (SAIA)**, Splunk's hosted LLM — **writes new SPL detections** from plain English + explains existing SPL via `/predict` (`agent/saia_generate_detection.py`; verified live, ~15s). Invoked on demand. (SAIA free-form finding-*judgment* via `agent/llm_enrich.py` is experimental — deflects/times out for this tenant, so it is **not** in the verdict path. Local-MLX Foundation-Sec stays roadmap.) |
| Output | 10 typed sourcetypes (`:transaction`, `:event`, `:source`, `:audit_finding`, `:scope`, `:alert`, `:ai_report`, `:fork_result`, `:poc_trigger`, `:static_finding`), persistent in Splunk's index |

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full diagram and
sequence flow.

---

## Detection coverage (attack class → detection → ground truth)

Honest mapping of what fires on what. Statistical rules catch anomalous
*amounts*; the mechanism-aware rule catches anomalous *actions*; fork-validation
proves whether a candidate is a real exploit. Gaps are listed, not hidden.

| Attack class | Detected by | Type | Fork-provable |
|---|---|---|---|
| Value drain / whale transfer | Value Transfer Outlier, Token Transfer Outlier | statistical (z-score) | ✅ |
| Anomalous sender / multi-contract sweep | Sender Behavior Outlier, Cross-Contract Correlation, Multi-Step Sequence | statistical | ✅ |
| Failed-tx burst (griefing / probing) | Failed Tx Burst vs Baseline | statistical | — |
| Access control / config tamper | **Privileged Function Call** | mechanism (selector lookup) | ✅ (e.g. TempleDAO `migrateStake`) |
| Proxy upgrade / ownership change | **Privileged Function Call** | mechanism | ✅ |
| LayerZero config (`setPeer` / `setDelegate` / DVN) | **Privileged Function Call** | mechanism | ✅ |
| Known-bad / sanctioned address | Known-Bad Address Touched | threat-intel lookup | — |
| Reentrancy | — (no direct SPL signal) | — | ✅ (proven at fork-validation, not detected) |
| Message / packet replay | _removed — false-positived on normal LZ delivery_ | — | — _(gap / backlog)_ |
| Oracle / price manipulation | _not yet covered_ | — | — _(gap / backlog)_ |

---

## What's installed

The hackathon entry's primary surface is the custom app and its in-app
agent. Several Splunk apps are installed alongside it:

- **Argus Security Monitor** (this app) — custom SPL detections,
  dashboard, lookups, and the live `argus_agent.py` modular input
- **Splunk AI Toolkit (5.7.4)** + Python for Scientific Computing — provides
  MLTK DBSCAN. The optional clustering detection ships **disabled** and needs
  this toolkit installed to enable; every other detection is pure SPL
- **Splunk Security Essentials (3.8.3)** — security pattern library
- **Splunk MCP Server (1.1.3)** — official MCP interface (integrated for
  Splunk tool calls; the in-app agent uses the SDK directly)
- **Splunk AI Assistant (2.0.0)** — cloud-connected LLM (SAIA), **LIVE**:
  authors + explains SPL detections from plain English via `/predict` (~15s)

---

## Quick start

### Prerequisites
- Splunk Enterprise 10.x or higher with Developer License (10 GB/day)
- Python 3.11+
- [Foundry](https://getfoundry.sh/) (`anvil`, `forge`, `cast`)
- Etherscan + Alchemy API keys
- (Optional, roadmap) Splunk AI Assistant cloud-connected tenant and/or
  local-MLX Foundation-Sec weights — not required for the live pipeline

### Install

```bash
# 1. Get the LayerZero source + audits (not vendored to keep this repo small)
mkdir -p layerzero-src/audits
# clone LayerZero-Labs/LayerZero, LayerZero-Labs/LayerZero-v2, and Audits

# 2. Install Splunk apps from Splunkbase
# Splunk MCP Server (7931), AI Assistant (7245), AI Toolkit (2890),
# Python for Scientific Computing (Apple Silicon = 6785; Linux = 2882; etc.),
# Splunk Security Essentials (3435)

# 3. Install the Argus app (Splunk app namespace is still `omni_guard`)
cp -r splunk/ $SPLUNK_HOME/etc/apps/omni_guard/
$SPLUNK_HOME/bin/splunk restart
# The argus_agent modular input auto-starts on restart (5-min interval)

# 4. Configure
cp .env.example .env
# Edit .env with your tokens / keys

# 5. Install Python deps
pip install -r requirements.txt
```

### Run the pipeline

```bash
# Ingest LayerZero source code → Splunk
python ingestion/ingest_source.py

# Extract + index audit PDFs → Splunk
python agent/extract_audits.py
python ingestion/ingest_audit_findings.py

# Index Immunefi scope rules
python ingestion/ingest_immunefi.py

# Backfill on-chain history (long-running)
python ingestion/historical_scan.py
```

The live AI agent does **not** run as a standalone process — it is the
`argus_agent` modular input that `splunkd` schedules every 5 minutes once
the app is installed. (`agent/mcp_agent.py` is the older MCP-driven path
and is roadmap, not the live triage loop.)

### Validate a candidate finding

```bash
python poc/validate_finding.py \
    --tx-hash 0xabc... \
    --chain ethereum \
    --fork-block 22487000 \
    --foundry-test poc/findings/your-finding-id/Exploit.t.sol \
    --target 0xVictimContract \
    --attacker 0xAttackerEOA
```

---

## What you see when it works

- **Splunk dashboard** (`Apps → Argus → Argus Security Monitor`):
  KPI tiles, real-time alert table, contract event breakdown,
  in-app agent triage log (`layerzero:ai_report`).
- **macOS notification** when a fork-validated finding lands.
- **`logs/findings_feed.log`** — append-only `tail -f`able stream of
  every confirmed finding.
- **`poc/findings/<id>/`** — Foundry exploit test + auto-drafted
  incident report for the operations team.

---

## License

[**AGPL-3.0**](LICENSE) — anyone running Argus as a service must publish
their fork (and any modifications) under the same license. This is
deliberate: keeps the platform open while preventing closed-source
re-sale.

A separate commercial license is available — contact the author below if
you need to run Argus without AGPL obligations.

## Author

Alexander Sorrell · alexander.sorrell.it@gmail.com

Built for the Splunk Agentic Ops Hackathon 2026.
