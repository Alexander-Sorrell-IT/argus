# Argus — Devpost submission

> Paste each section into the matching Devpost field. Every claim here matches the
> **as-built** system (see `DEMO_SCRIPT.md`): the in-app agent's triage is a
> deterministic Splunk-native floor that produces the verdicts with **zero AI calls**;
> the one live LLM in the production loop is **SAIA** (Splunk's hosted model), which
> **authors the SPL detections** (an experimental local MLX Qwen2.5 / Foundation-Sec
> tier remains tagged in the index but is not on the production verdict path). Don't
> inflate these — the honesty *is* the pitch.

---

## Track
Security

## Project name
Argus

## Tagline (≤ 60 chars)
A Splunk-native security operations center for smart contracts.

## Elevator pitch / "What it does" (one-liner)
Argus turns Splunk into a SOC for cross-chain DeFi protocols: it ingests on-chain
activity, contract source, and audit reports as typed sourcetypes, detects anomalies
in pure SPL, triages them with an agent that runs *inside* Splunk, and confirms or
clears the serious ones against a live Ethereum mainnet fork.

---

## Inspiration
Smart contracts are deployed once and then run for years, holding hundreds of millions
of dollars — and there is no `tail -f` for a live protocol. When something breaks, you
usually find out on Telegram, an hour after the funds are already gone. SOC teams have
mature tooling for servers and SaaS; on-chain protocols have almost none of that muscle
memory. We wanted to know: if you took Splunk — a platform built for exactly this kind
of continuous detection and response — and pointed it at a production DeFi protocol,
how far could you get using *only* Splunk's own primitives? The production loop leans on
Splunk's own AI — SAIA authors the detections and a deterministic Splunk-native tier-0
produces the verdicts (an experimental local MLX Qwen2.5 / Foundation-Sec tier stays
tagged in the index but off the verdict path). Just Splunk, used correctly.

## What it does
Argus is a five-stage funnel that runs end-to-end on Splunk:

1. **Ingest** — On-chain transactions, events, contract source, audit reports, and the
   Immunefi scope all become typed Splunk sourcetypes. This repo bundles a runnable
   ~800-event LayerZero sample (`samples/`) so detections fire on a fresh clone; the
   live ingester (`ingestion/`) scales to full history.
2. **Detect** — 12 detection saved searches written in pure SPL (plus 3 scoring/baseline
   jobs; 15 total) find anomalies with data-driven per-contract baselines (not magic
   numbers), tempered by conservative fixed floors (e.g. `value_eth>0.1`, `zscore>3`,
   `fails_10m>5`) to suppress dust and noise: per-contract z-score outliers (`eventstats`),
   `streamstats` baselines, `predict`, and `cluster`. Per-contract baselines live in the KV
   store and rebuild nightly. (An optional MLTK-DBSCAN search ships disabled — it needs the
   ML Toolkit.)
3. **Cross-reference** — A pipeline (`ingest_audit_findings.py`) can index audit reports as
   `layerzero:audit_finding` so already-documented, accepted-risk issues get demoted instead
   of re-alerted. The audit corpus is not bundled in this repo.
4. **Triage (the in-app agent)** — A Splunk **modular input** on the Splunk Python SDK
   triages each surviving detection *in-process* and writes its verdict back as a Splunk
   event, deduplicated in the KV store. This triage is a fast, deterministic tier-0
   floor — it makes **zero AI calls**, so its verdicts are reproducible.
5. **Validate** — High-severity candidates are fork-validated: Argus forks Ethereum
   mainnet with Anvil at the suspicious block, runs a Foundry exploit test, and writes
   **CONFIRMED only when the test's own assertions reproduce the exploit** — otherwise an
   honest **REJECTED**. It never fabricates a result. In testing it correctly cleared a
   large legitimate transfer as "not a bug."

The AI lives one level up, where it adds the most leverage: the **Splunk AI Assistant
(SAIA)**, Splunk's hosted LLM, takes a plain-English threat description and **authors a
brand-new SPL detection** in ~15 seconds. The AI builds the security logic; Splunk runs
it. That's the difference between "AI labels a row" and "AI writes the detector."

Argus is **protocol-agnostic by config**: drop a YAML file describing any DeFi protocol
(contracts, audit path, Immunefi scope) and a loader emits the lookups and scope Splunk
consumes. LayerZero is the demo protocol; an example Aave config ships alongside it to
prove the layer is real.

## How I built it
- **Naming:** *Argus* is the product; its Splunk-native **engine** is the `omni_guard`
  app — the `omni_guard_security` index, the SPL detections, the KV-store state, the
  in-app agent, and the `| forkvalidate` command — with the `TA-triage-v1` add-on for
  ingest/triage. (Argus = the app; `omni_guard` = the engine it runs on.)
- **Splunk Enterprise 10.4** with a Developer License as the entire runtime.
- **Detection** entirely in SPL across 12 saved searches on cron schedules, writing
  results with `collect`; state in KV store collections (e.g. `contract_baselines`),
  rebuilt nightly.
- **In-app agent** as a `splunklib.modularinput.Script` modular input deployed in the
  app's `bin/`, registered via `inputs.conf` (interval 300s). It runs the
  detect → triage → write loop in-process against live `splunkd` using the Splunk
  Python SDK (splunklib 2.1.1, vendored).
- **AI detection authoring** via SAIA's `/predict` endpoint (cloud-connected mode),
  turning English threat descriptions into runnable SPL.
- **Fork validation** with Anvil + Foundry, forking mainnet at the flagged block and
  asserting on the exploit — the only component that stays *outside* splunkd (you can't
  run a mainnet fork inside Splunk), consuming the agent's `poc_trigger` events.
- **Protocol layer**: a YAML schema + `load_protocol.py` that emits the lookup CSV and
  scope files the dashboard and agent already read.
- **Dashboard**: Simple XML reading protocol name and totals from the lookup so nothing
  is hardcoded to one protocol.

## Challenges I ran into
- **Telling real anomalies from normal protocol lifecycle.** An early rule flagged
  ordinary LayerZero message delivery as "replay attacks" and buried everything in false
  positives. Fixing this — disabling the bad rule and tightening the baseline — became a
  feature: a clean baseline beats crying wolf.
- **Drawing the agent's boundary honestly.** It was tempting to claim "AI judges every
  finding." The honest, reproducible design is a deterministic tier-0 triage for the
  verdict path and AI where it genuinely earns its place — *writing* the detections.
- **Running an agent inside Splunk.** Getting a modular input to run the full loop
  in-process meant vendoring a working splunklib and validating it under Splunk's
  bundled Python.
- **Ground truth.** "Probably a bug" isn't good enough — wiring up Anvil/Foundry so a
  finding is only CONFIRMED when an exploit test actually reproduces it.

## Accomplishments that I'm proud of
- The whole production pipeline genuinely runs on Splunk primitives — detection, state,
  the agent, and even authoring new detections — with **SAIA (Splunk's hosted model) the
  only LLM in the loop and verdicts produced by a deterministic Splunk-native tier-0**
  (an experimental local MLX Qwen2.5 / Foundation-Sec tier remains tagged in the index
  but never reaches the verdict path).
- An AI that *writes* SPL detectors from English, not one that just classifies rows.
- A validation step that returns an honest REJECTED and refuses to fabricate a CONFIRMED.
- A protocol-agnostic config layer proven with a second protocol, not just promised.

## What I learned
Splunk is far more capable as an *application platform* than as just a log search box —
modular inputs, the KV store, SPL, MLTK, and SAIA compose into a real detection-and-
response system. And the hardest, most valuable engineering in security tooling is
restraint: suppressing false positives and being honest about what the system actually
proves is worth more than any flashy claim.

## What's next for Argus
- Wire the experimental LLM reasoning path into triage for HIGH/CRITICAL candidates as a
  *tier-2* on top of the deterministic floor (kept out of the verdict path until it's
  trustworthy).
- Broaden cross-chain coverage beyond the Ethereum-heavy demo dataset.
- Add more shipped protocol configs and a guided "add your protocol" flow.
- Take fork-validation from demo to a continuously-running queue.

## Built With
splunk, splunk-enterprise, spl, splunk-ai-assistant, splunk-mltk, python, splunk-sdk,
foundry, anvil, solidity, ethereum, layerzero, kvstore, yaml

## Links
- **GitHub repo:** `https://github.com/Alexander-Sorrell-IT/argus`  *(must be PUBLIC)*
- **Demo video:** `[ PASTE YOUTUBE/VIMEO URL ]`
- **License:** AGPL-3.0
