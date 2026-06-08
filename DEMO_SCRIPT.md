# Argus — demo video script (≤ 3:00)

> Honest shooting script. Narration matches the **as-built** system: the live AI
> agent is the in-app Splunk **modular input** doing **deterministic Splunk-native
> tier-0** triage (it produces the verdicts, with zero AI calls); separately, the
> **Splunk AI Assistant (SAIA)** — Splunk's hosted LLM — is live for **writing and
> explaining the SPL detections themselves**. (SAIA free-form finding-judgment is
> experimental and not in the verdict path.) Record on macOS with the Argus
> dashboard + a terminal.
>
> Per-scene narration to read aloud: `demo/RECORD_THIS.md`. Captions: `demo/argus_demo.srt`.

---

## 0:00–0:15 · Hook
**[Screen: Argus dashboard — KPI tiles + Investigation Log]**
> Smart contracts run for years, and there's no `tail -f` for a live protocol. When
> something breaks, you usually hear about it on Telegram — an hour after the funds
> are gone. Argus turns Splunk into a security operations center for cross-chain DeFi.

## 0:15–0:45 · Splunk-native architecture
**[Screen: `architecture.png`]**
> Every analysis layer runs on Splunk's own primitives. Ingestion turns on-chain
> transactions, events, contract source, and audit reports into typed Splunk
> sourcetypes — hundreds of thousands of transactions and ~900k events indexed.
> Detection is pure SPL: per-contract z-score outliers, streamstats baselines,
> `predict`, and MLTK clustering — data-driven baselines with conservative fixed floors
> to suppress dust and noise. State lives in the Splunk KV store. Detections are authored by
> SAIA (Splunk's hosted model); verdicts come from a deterministic Splunk-native tier-0.

## 0:45–1:15 · Detection + honest baseline
**[Screen: dashboard — Largest Value Transactions; run a saved search]**
> Each detection is a saved search on a cron. And Argus is honest: it separates real
> anomalies from normal protocol lifecycle. We found and disabled a rule that was
> flagging ordinary LayerZero message delivery as replay attacks. A clean baseline
> beats crying wolf.

## 1:15–1:50 · The in-app agent
**[Screen: Investigation Log populated with verdicts]**
> The agentic part runs inside the Splunk app itself — a modular input on the Splunk
> Python SDK. It triages each detection in-process and writes its verdict back as a
> Splunk event, deduplicated in the KV store. Here it surfaced nine value-manipulation
> candidates, led by Puffer pufETH. The in-app triage is a fast deterministic
> tier-0 floor that produces the verdicts. And the detections themselves are written by AI:
> the Splunk AI Assistant — Splunk's own hosted model — takes a plain-English description of
> a threat and writes a brand-new SPL detection for it, in about fifteen seconds. The AI
> builds the security logic; Splunk runs it.

## 1:50–2:25 · Fork-validation (ground truth)
**[Screen: terminal `validate_finding.py`; then the PoC Fork Test Queue panel]**
> High-severity candidates are fork-validated. Argus forks Ethereum mainnet with Anvil
> at the suspicious block, runs a Foundry exploit test, and writes CONFIRMED only when
> the test's own assertions reproduce the exploit — otherwise an honest REJECTED. In
> testing it correctly cleared a large legitimate transfer as "not a bug." It never
> fabricates a result.

## 2:25–2:45 · Close
**[Screen: README / `architecture.png`]**
> Everything runs on Splunk — Splunk does the pattern work, holds the state, runs the
> agent, and even writes its own detections with Splunk's hosted AI. SAIA authors the
> detections; verdicts are deterministic Splunk-native logic (an experimental local-model
> tier stays tagged in the index but off the verdict path).
> Argus is what using Splunk correctly looks like.
> Open source under AGPL-3.0, built for the Splunk Agentic Ops Hackathon.

**[End card: Argus · github.com/Alexander-Sorrell-IT/argus · Splunk Agentic Ops Hackathon 2026]**

---

## Devpost submission text (≤ 300 words)

> **Argus — A Splunk-native security operations platform for cross-chain DeFi protocols.**
>
> Smart contracts are deployed once and run for years; there is no `tail -f` for
> production protocols. Incidents surface on Telegram an hour after the funds are gone.
> Argus turns Splunk into a SOC for smart contracts.
>
> A protocol config (YAML) points Argus at a DeFi protocol. It ingests contract source,
> audit reports, Immunefi scope, and on-chain history — every artifact becomes a typed
> Splunk sourcetype. From there every analysis layer runs on Splunk's own primitives:
> statistical detection in SPL (`eventstats` z-scores, `streamstats` baselines, `predict`,
> `cluster`, MLTK DBSCAN), per-contract baselines in the KV store, and an audit-corpus
> cross-reference (1,288 indexed chunks) that demotes already-documented issues.
>
> The agentic part runs INSIDE the Splunk app: a modular input on the Splunk Python SDK
> triages each detection in-process and writes its verdict back as a Splunk event,
> KV-deduplicated — a deterministic floor that makes zero AI calls. The AI lives one level
> up: the Splunk AI Assistant (SAIA), Splunk's hosted LLM, takes a plain-English threat
> description and authors a brand-new SPL detection (~15s) — the AI builds the security
> logic, not just labels a row.
>
> High-severity candidates are fork-validated: Argus forks Ethereum mainnet with Anvil
> at the suspicious block, runs a Foundry exploit test, and writes CONFIRMED only when
> the test's own assertions reproduce the exploit — otherwise an honest REJECTED. It never
> fabricates a result (in testing it correctly cleared a large legitimate transfer as
> "not a bug").
>
> Argus is what "use Splunk correctly" looks like — Splunk does the pattern work, holds
> the state, runs the agent, and writes its own detections with Splunk's hosted AI. No
> third-party model.
>
> Built for the Splunk Agentic Ops Hackathon 2026 (Security track). Open source under
> AGPL-3.0. LayerZero is the demo protocol; the config layer is protocol-agnostic.
>
> Repo: `[REPO URL]` · Demo video: `[VIDEO URL]`

---

## Recording notes
- Read the per-scene narration from `demo/RECORD_THIS.md` (6 scenes); captions in `demo/argus_demo.srt`.
- 1920×1080, cursor highlight on; pre-stage terminal windows.
- The dashboard is live at `http://localhost:8000/en-US/app/omni_guard/omni_guard`.
