# Argus — 3-min demo video script

> Target: under 3:00, hits every prize category, lands the "Splunk-native" message.
> Record on macOS with the OmniGuard dashboard + a terminal + briefly the source code.

---

## 0:00–0:15 · Hook

**[Screen: Argus dashboard, KPI tiles + alert table visible]**

> "Smart contracts are deployed once and run for years. When something breaks
>  it usually surfaces on Telegram an hour after $50 million is gone. There's
>  no `tail -f` for production protocols."

**[Pause; cut to LayerZero scope page on Immunefi]**

> "This is Argus. It turns Splunk into a security operations center for
>  cross-chain DeFi protocols. Drop in a YAML, point it at any protocol,
>  and you get continuous monitoring with AI-driven investigation."

---

## 0:15–0:45 · The Splunk-native architecture

**[Screen: ARCHITECTURE.md Mermaid diagram, scrolling]**

> "Argus is intentionally Splunk-native. Every analysis layer runs on
>  Splunk's own primitives, not external code."

> "Detection is SPL — anomalydetection, cluster, outlier, predict —
>  not hardcoded thresholds.
>  Filtering is an SPL query against 1,276 audit chunks I indexed from
>  17 different auditors. The audits ARE data.
>  State lives in Splunk — kvstore baselines per contract, rebuilt
>  nightly.
>  LLM reasoning goes through Splunk AI Assistant via the official
>  MCP Server. No external API calls.
>  The agent itself contains zero detection logic. Splunk is the brain."

**[Cut to splunk_mcp_client.py briefly showing the JSON-RPC call]**

---

## 0:45–1:30 · Live detection walkthrough

**[Screen: OmniGuard dashboard, then click into a candidate row]**

> "Here it is running on the LayerZero protocol. 32 in-scope contracts,
>  2.7 million transactions indexed."

**[Trigger savedsearch: Value Transfer Outlier]**

> "Each detection is a saved search on a cron. This one is the value
>  outlier detector — it uses eventstats to build a per-contract baseline,
>  then flags anything more than 3 standard deviations above. No hardcoded
>  threshold; the contract teaches Splunk what's normal."

**[Show 4 surfaced candidates]**

> "It just surfaced four candidate findings — large transfers on Puffer
>  pufETH and USDT0. We don't know yet if these are real bugs or just
>  treasury moves. That's why the next step is automatic."

---

## 1:30–2:15 · Splunk AI Assistant + audit cross-reference

**[Screen: terminal, run `python audit_xref.py` against the candidates]**

> "For each candidate, Argus queries the indexed audit corpus through MCP.
>  If 17 auditors already documented this exact pattern, the candidate gets
>  demoted. If not, it's a NOVEL candidate worth deep investigation."

**[Show audit_xref output: "0 chunks matched → NOVEL"]**

> "These four candidates are not in any of the 112 LayerZero audits.
>  That's our shortlist."

**[Switch to Splunk Web → AI Assistant chat panel]**

> "Now we ask Splunk's AI Assistant — running on Splunk's own hosted LLM,
>  via the official MCP server — to triage this candidate."

**[Type: "Analyze this Puffer pufETH transfer for security concerns"]**

> "It pulls source code, audit absence, and on-chain context. It returns a
>  vulnerability hypothesis and a recommended PoC approach."

**[Show SAIA response]**

---

## 2:15–2:45 · Ground-truth validation via Anvil fork

**[Screen: terminal, run `validate_finding.py`]**

> "Hypothesis is theory. Validation is fact. Argus takes the AI's
>  proposed exploit, generates a Foundry test, and runs it against an
>  Anvil mainnet fork at the block just before the suspicious transaction."

**[Show forge test PASSED]**

> "If the exploit reproduces — attacker balance went up, target balance
>  went down — it's CONFIRMED. Written back to Splunk as a typed event,
>  fires a macOS notification, drops a structured incident report in
>  poc/findings."

**[Show notification banner + findings_feed.log entry]**

> "The operations team sees the alert in seconds. They have everything
>  they need: the alert, the AI's hypothesis, the validated PoC, the
>  state diff."

---

## 2:45–3:00 · Close

**[Screen: README.md, scroll to license + prize alignment]**

> "Argus is open source under AGPL-3.0. Splunk Cloud teams can plug it
>  into existing SOC workflows. Audit firms can use it to continuously
>  monitor protocols they've audited. Protocol teams can run it on their
>  own deployments.
>
>  This is what 'use Splunk correctly' looks like — Splunk does the
>  pattern work, Splunk hosts the AI, Splunk holds the state, and the
>  agent is the orchestrator. Everything else is just glue."

**[End card: Argus · github.com/your-handle/argus · Splunk Agentic Ops Hackathon 2026]**

---

## Recording notes

- **Screen res:** 1920×1080 minimum
- **OBS or QuickTime** with macOS mic
- **Cursor highlight on** — judges follow what you click
- **Pre-stage all terminal windows** before recording — no scrolling through
  history live
- **Pre-trigger SAIA** on the same query you'll demo so the response is
  cached + appears instantly
- **2-3 takes** then pick the cleanest

## Devpost submission text (≤ 300 words)

> **Argus — A Splunk-native security operations platform for cross-chain DeFi protocols.**
>
> Smart contracts are deployed once and run for years; there is no `tail -f`
> for production protocols. Incidents surface on Telegram an hour after the
> funds are gone. Argus turns Splunk into a SOC for smart contracts.
>
> Drop a single YAML config pointing at any DeFi protocol. Argus ingests
> the contract source code, the audit reports, the Immunefi scope rules,
> and the on-chain transaction history — every artifact becomes a typed
> Splunk sourcetype. From there, every layer of analysis runs on Splunk's
> own primitives. Statistical detection uses SPL's `eventstats`,
> `anomalydetection`, `cluster`, `outlier`, and `predict`. Filtering is an
> SPL query against the indexed audit corpus (1,276 chunks from 17
> auditors). The agent talks to Splunk only through the official Splunk
> MCP Server, and AI reasoning runs through Splunk AI Assistant on the
> hosted LLM — no external API.
>
> When a novel candidate survives the SPL detection and the audit cross-
> reference, Argus generates a Foundry exploit test, runs it against a
> local Anvil mainnet fork, diffs attacker/target state — and only writes
> a CONFIRMED finding when the exploit actually reproduces. Operations
> teams get a ground-truth signal in minutes instead of hours.
>
> Argus is what "use Splunk correctly" looks like — Splunk does the
> pattern work, Splunk hosts the AI, Splunk holds the state. The agent
> orchestrates. Everything else is glue.
>
> Built for the Splunk Agentic Ops Hackathon 2026 (Security track).
> Open source under AGPL-3.0. LayerZero is the demo protocol; the
> architecture is protocol-agnostic.
