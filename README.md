# Argus 👁️

> **A Splunk-native security operations platform for cross-chain DeFi protocols.**
>
> *In Greek mythology, Argus Panoptes had 100 eyes — none of them ever slept.*

Built for the **Splunk Agentic Ops Hackathon 2026** (Security track).

Argus turns Splunk into a security operations center for production smart
contracts. Point it at any DeFi protocol via a single YAML config and get
continuous monitoring, statistical anomaly detection, audit-aware
filtering, AI-driven investigation via the Splunk-hosted LLM, and
ground-truth exploit validation against a local mainnet fork — all using
Splunk's native primitives.

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
- **Audit cross-reference** filters out issues that any of the 17
  auditors who reviewed LayerZero already flagged. You only see *novel*
  signals.
- **Splunk-hosted LLM** triages each novel candidate, hypothesizes a
  vulnerability class, proposes a proof-of-concept.
- **Anvil mainnet fork** validates the exploit hypothesis locally —
  ground truth, no AI hallucination at the final step.
- **Structured output** ready for the on-call operations team.

---

## Splunk-native architecture

Every layer leans on Splunk primitives. The agent contains zero
detection logic — Splunk does all the analysis.

| Layer | Splunk primitive |
|---|---|
| Detection | `eventstats`, `anomalydetection`, `cluster`, `outlier`, `streamstats`, `predict`, `transaction` |
| Filtering | SPL JOIN against indexed audit corpus (`layerzero:audit_finding`) |
| Source analysis | SPL pattern matching against indexed Solidity (`layerzero:source`) |
| Enrichment | CSV lookup (`bad_addresses.csv`) |
| State | Splunk kvstore (`contract_baselines`) — nightly rebuild |
| LLM reasoning | Splunk AI Assistant via official MCP Server |
| Agent → Splunk | Splunk MCP Server (official app 7931), encrypted token auth |
| Output | 11 typed sourcetypes, persistent in Splunk's index |

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full diagram and
sequence flow.

---

## What's installed

12 Splunk apps. The hackathon entry uses 5 of them as primary:

- **Splunk MCP Server (1.1.3)** — official MCP interface
- **Splunk AI Assistant (2.0.0)** — cloud-connected LLM tier
- **Splunk AI Toolkit (5.7.4)** + Python for Scientific Computing — ML-SPL
- **Splunk Security Essentials (3.8.3)** — security pattern library
- **OmniGuard Security Monitor** (this app) — custom searches, dashboard, lookups

---

## Quick start

### Prerequisites
- Splunk Enterprise 10.x or higher with Developer License (10 GB/day)
- Splunk AI Assistant cloud-connected tenant (request at the Developer Portal)
- Python 3.11+
- [Foundry](https://getfoundry.sh/) (`anvil`, `forge`, `cast`)
- Etherscan + Alchemy API keys

### Install

```bash
# 1. Get the LayerZero source + audits (not vendored to keep this repo small)
mkdir -p layerzero-src/audits
# clone LayerZero-Labs/LayerZero, LayerZero-Labs/LayerZero-v2, and Audits

# 2. Install Splunk apps from Splunkbase
# Splunk MCP Server (7931), AI Assistant (7245), AI Toolkit (2890),
# Python for Scientific Computing (Apple Silicon = 6785; Linux = 2882; etc.),
# Splunk Security Essentials (3435)

# 3. Install the OmniGuard app
cp -r splunk/ $SPLUNK_HOME/etc/apps/omni_guard/
$SPLUNK_HOME/bin/splunk restart

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

# Run the agent in watch mode
python agent/mcp_agent.py --watch
```

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

- **Splunk dashboard** (`Apps → OmniGuard → OmniGuard Security Monitor`):
  KPI tiles, real-time alert table, contract event breakdown,
  investigation log.
- **macOS notification** when a `layerzero:confirmed_finding` event
  lands.
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
