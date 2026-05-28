# Argus — Architecture

Splunk-native security operations platform for cross-chain DeFi protocols.
Every analysis layer leans on Splunk primitives; external code only fills
gaps Splunk doesn't natively cover (chain RPC ingestion, Anvil fork
validation).

## High-level

```mermaid
graph TD
    subgraph SOURCES["📥 Data sources"]
        A1[On-chain RPC<br/>Etherscan + Alchemy]
        A2[Solidity source code<br/>LayerZero repo]
        A3[Audit reports<br/>112 PDFs from 17 auditors]
        A4[Immunefi scope rules]
    end

    subgraph INGEST["🔁 Ingestion (Python, one-time + streaming)"]
        B1[ingest_transactions.py<br/>+ historical_scan.py]
        B2[ingest_source.py]
        B3[extract_audits.py<br/>+ ingest_audit_findings.py]
        B4[ingest_immunefi.py]
    end

    subgraph SPLUNK["📊 Splunk Enterprise — the brain"]
        C1[("Index: omni_guard_security<br/>:transaction · :event<br/>:source · :audit_finding<br/>:scope · :alert · :ai_report<br/>:fork_result · :confirmed_finding")]
        C2[Saved searches<br/>10 SPL detections<br/>anomalydetection · cluster<br/>outlier · streamstats · predict]
        C3[kvstore<br/>contract_baselines]
        C4[Lookups<br/>bad_addresses.csv]
        C5[Splunk AI Assistant<br/>cloud-connected to Splunk's<br/>managed AI cloud]
        C6[Splunk MCP Server<br/>14 tools exposed:<br/>splunk_*, saia_*]
    end

    subgraph AGENT["🤖 Argus Agent (orchestrator)"]
        D1[mcp_agent.py<br/>polls + investigates]
        D2[splunk_mcp_client.py<br/>JSON-RPC to MCP]
        D3[audit_xref.py<br/>SPL query against<br/>:audit_finding]
        D4[validate_finding.py<br/>Anvil + Foundry]
    end

    subgraph OUT["📋 Outputs"]
        E1[OmniGuard Dashboard<br/>Splunk Web]
        E2[macOS notify +<br/>findings_feed.log]
        E3[poc/findings/&lt;id&gt;/<br/>Exploit.t.sol + submission.md]
        E4[Manual review → submit<br/>privately to Immunefi]
    end

    A1 --> B1 --> C1
    A2 --> B2 --> C1
    A3 --> B3 --> C1
    A4 --> B4 --> C1

    C1 --> C2
    C2 -.fires alerts.-> C1
    C2 -.scheduled rebuild.-> C3
    C2 --> C4

    C6 --> D2
    D2 --> D1
    D1 --> D3
    D3 -.SPL query.-> C1
    D1 --> D4
    D1 -.tier-1 triage.-> C5
    C5 --> D1
    D4 -.fork result.-> C1

    C1 --> E1
    C1 -.alert action.-> E2
    D4 --> E3
    E3 --> E4

    style SPLUNK fill:#0f3460,color:#fff
    style AGENT fill:#533483,color:#fff
    style OUT fill:#16213e,color:#fff
```

## The investigation loop (one alert)

```mermaid
sequenceDiagram
    participant SPL as Splunk SPL search
    participant Idx as Splunk index
    participant Agent as Argus agent
    participant MCP as Splunk MCP Server
    participant SAIA as Splunk AI Assistant
    participant Anvil as Local Anvil fork

    SPL->>Idx: anomalydetection / cluster / outlier
    SPL->>Idx: writes layerzero:alert event
    Agent->>MCP: tools/call splunk_run_query<br/>("look for new :alert events")
    MCP->>Idx: SPL via official client
    Idx-->>MCP: alert rows
    MCP-->>Agent: alert dicts

    Agent->>MCP: tools/call splunk_run_query<br/>(":audit_finding contracts=X vuln=Y")
    MCP->>Idx: audit cross-reference query
    Idx-->>MCP: 0 chunks (NOVEL)
    MCP-->>Agent: novel candidate

    Agent->>MCP: tools/call saia_ask_splunk_question<br/>(alert + source context)
    MCP->>SAIA: prompt + context
    SAIA-->>MCP: hypothesis + vuln class + PoC steps
    MCP-->>Agent: verdict

    Agent->>Agent: pick Foundry template,<br/>fill in addresses + block
    Agent->>Anvil: start fork at block N-1
    Agent->>Anvil: forge test exploit
    Anvil-->>Agent: PASS / FAIL + state diff

    alt CONFIRMED
        Agent->>Idx: write layerzero:confirmed_finding
        Agent->>Agent: generate submission.md draft
        Agent->>Agent: fire macOS notification
    else REJECTED
        Agent->>Idx: write layerzero:fork_result (rejected)
    end
```

## Splunk-native principles (what makes this "use Splunk correctly")

| Principle | How Argus implements it |
|---|---|
| Detection is data-driven, not threshold-driven | `eventstats avg/stdev by contract` → z-score → flag |
| SPL does the work, not Python | Agent only orchestrates; all analysis is SPL |
| Splunk index = state store | Investigations, fork results, confirmed findings all indexed |
| Lookups for enrichment | `bad_addresses.csv` joined on every tx |
| Saved searches drive scheduling | Cron-scheduled SPL → alert events → agent reacts |
| kvstore for structured state | `contract_baselines` rebuilt nightly |
| Sourcetypes typed by intent | 11 typed sourcetypes, props.conf declared |
| Agent should be dumb, Splunk is smart | Agent contains no detection logic — all SPL |

## Splunk apps used (12 total)

| App | Role |
|---|---|
| Splunk MCP Server (1.1.3) | Official MCP interface — 14 tools |
| Splunk AI Assistant (2.0.0) | Cloud-connected LLM tier (saia_* tools) |
| Splunk AI Toolkit (5.7.4) | ML-SPL commands (fit/apply, DBSCAN, etc.) |
| Python for Scientific Computing (4.3.2) | Runtime for AI Toolkit |
| Splunk AI Canvas (1.4.1) | AI workspace |
| Splunk Security Essentials (3.8.3) | Security pattern library |
| InfoSec App (1.7.1) | Security dashboards |
| Generic LLM Connector | Optional alternative LLM path |
| TA-Triage | `\| triage` SPL command |
| Slack Alerts (2.3.2) | Optional Slack notifications |
| OmniGuard Security Monitor | This project's app — searches + dashboard + lookups |
| Audit Trail (1.0.0) | Default Splunk audit log |

## External components (not Splunk)

- **Anvil** (Foundry) — local mainnet fork for ground-truth exploit validation
- **Etherscan + Alchemy** — chain data ingestion
- **Python ingestion scripts** — translate RPC responses into Splunk events

Everything else is Splunk.
