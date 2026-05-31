# Argus demo — narration to record (read these aloud)

How to record: open **Voice Memos** (or QuickTime → File → New Audio Recording).
Record **one scene per file**, name them `s1.m4a` … `s6.m4a`, drop them in
`~/Desktop/omni-guard/demo/voice/`. Then tell me — I auto-restitch them into the
video (I'll re-time each slide to your take, so don't worry about hitting the
seconds exactly; the targets are just a guide for pacing).

Tips: speak a touch slower than feels natural; pause ~1s between sentences;
it's fine to do several takes — I'll use the cleanest file you keep.

---

### s1 · Hook  (~15s)
> Smart contracts run for years, and there's no `tail -f` for a live protocol.
> When something breaks, you usually hear about it on Telegram — an hour after
> the funds are gone. Argus turns Splunk into a security operations center for
> cross-chain DeFi.

### s2 · What it is  (~16s)
> This is Argus monitoring LayerZero, live in Splunk. Every on-chain transaction,
> event, source file, and audit report becomes a typed Splunk sourcetype —
> millions of transactions indexed across fifteen in-scope contracts.

### s3 · Detection + honesty  (~25s)
> Detection is pure SPL. Per-contract z-score outliers on transfer value and
> decoded token amount — no hardcoded thresholds; the contract teaches Splunk
> what's normal. And Argus is honest: it separates real anomalies from ordinary
> protocol lifecycle. We found and disabled a rule that was flagging normal
> LayerZero message delivery as replay attacks. A clean baseline beats crying wolf.

### s4 · In-app agent + AI-written detections  (~24s)
> An agent runs inside the Splunk app itself — a modular input on the Splunk
> Python SDK. It triages each finding in-process and writes its verdict back as a
> Splunk event, deduplicated in the KV store. Here it surfaced nine
> value-manipulation candidates on Puffer pufETH and Ethena USDe. And the
> detections themselves are written by Splunk's own AI: I describe a threat in
> plain English, and the Splunk AI Assistant writes the SPL detection for it in
> about fifteen seconds. The AI builds the security logic; Splunk runs it.

### s5 · Fork validation  (~22s)
> High-severity candidates become proof-of-concept triggers. An external Anvil
> mainnet fork runs a Foundry exploit test — and Argus marks a finding confirmed
> only when the test's own assertions reproduce the exploit. When they don't, it
> says so. Never a guess, never a fabricated number.

### s6 · Close  (~15s)
> Everything runs on Splunk — Splunk does the pattern work, holds the state, runs
> the agent, and even writes its own detections with Splunk's hosted AI. No
> third-party model. Argus is what using Splunk correctly looks like. Open
> source, built for the Splunk Agentic Ops Hackathon.

---
Total target ≈ 1:50. Record naturally; I handle the timing.
