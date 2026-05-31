# Argus — full video transcript (trailer + demo, ~2:25)

Combined cut: `demo/argus_full.mp4` = the 38-second animated trailer (silent, on-screen
text) followed by the 1:47 narrated walkthrough. Under the hackathon's 3-minute limit.

---

## PART 1 — Trailer (0:00–0:38, on-screen text, no voiceover)

**0:00 · Live Protocol Monitoring**
> Smart contracts run for years.
> `$ tail -f /protocol/live.log`
> There is no `tail -f` for a live protocol.

**0:07**
> $Billions move between chains every day.
> When something breaks, you hear about it on Telegram — an hour too late.

**0:15 · Logo**
> ARGUS
> a SOC for smart contracts — built entirely in Splunk.

**0:24 · Inside Argus**
> SPL detections · In-app AI agent · Fork-validated on mainnet · Zero external AI

**0:31 · End card**
> ARGUS
> Splunk Agentic Ops Hackathon 2026 · Security

---

## PART 2 — Demo walkthrough (0:38–2:25, voiceover)

**0:38 · Hook**
> Smart contracts run for years, and there's no `tail -f` for a live protocol. When
> something breaks, you usually hear about it on Telegram — an hour after the funds are
> gone. Argus turns Splunk into a security operations center for cross-chain DeFi.

**0:53 · What it is**
> This is Argus monitoring LayerZero, live in Splunk. Every on-chain transaction,
> event, source file, and audit report becomes a typed Splunk sourcetype — hundreds of
> thousands of transactions and ~900k events indexed across fifteen in-scope contracts.

**1:09 · Detection + honesty**
> Detection is pure SPL — per-contract z-score outliers on transfer value and decoded
> token amount, no hardcoded thresholds; the contract teaches Splunk what's normal. And
> Argus is honest: it separates real anomalies from ordinary protocol lifecycle. We
> found and disabled a rule that was flagging normal LayerZero message delivery as
> replay attacks. A clean baseline beats crying wolf.

**1:34 · In-app agent**
> An agent runs inside the Splunk app itself — a modular input on the Splunk Python SDK.
> It triages each finding in-process and writes its verdict back as a Splunk event,
> deduplicated in the KV store. Here it surfaced nine value-manipulation candidates on
> Puffer pufETH and Ethena USDe.

**1:54 · Fork validation**
> High-severity candidates become proof-of-concept triggers. An external Anvil mainnet
> fork runs a Foundry exploit test — and Argus marks a finding confirmed only when the
> test's own assertions reproduce the exploit. When they don't, it says so. Never a
> guess, never a fabricated number.

**2:16 · Close**
> Everything runs on Splunk — Splunk does the pattern work, holds the state, and runs
> the agent, with zero external AI. Argus is what using Splunk correctly looks like.
> Open source, built for the Splunk Agentic Ops Hackathon.

---
*Demo narration is voiced by `say` in the current cut; replace by recording
`demo/RECORD_THIS.md` into `demo/voice/` and I re-stitch. SRT captions: `demo/argus_demo.srt`.*
