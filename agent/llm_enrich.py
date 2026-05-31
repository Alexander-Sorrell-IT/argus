"""llm_enrich.py — REAL local-LLM second-pass reasoning over Argus candidates.

The live in-app agent (splunk/bin/argus_agent.py) does fast deterministic tier-0
triage. This adds a genuine LLM reasoning pass on top, running a LOCAL model via
MLX (sovereign — no external API), and writes an enriched layerzero:ai_report
(reasoning_engine=mlx:<model>) with the model's actual hypothesis + rationale.

This makes "the AI agent reasons about findings" literally true and demonstrable.
The production Splunk-lineup model is Cisco Foundation-Sec (see agent/splunk_ai.py);
set ARGUS_LLM_MODEL to swap. Default is a small instruct model so it runs on 16GB.

Run:  splunk cmd python3 agent/llm_enrich.py     (needs SPLUNK_USER/PASS in env)
"""
import os, sys, json, time, re
sys.path.insert(0, "/Applications/Splunk/etc/apps/omni_guard/lib")
import splunklib.client as client
import splunklib.results as results
from mlx_lm import load, generate

MODEL = os.getenv("ARGUS_LLM_MODEL", "mlx-community/Qwen2.5-1.5B-Instruct-4bit")
INDEX = "omni_guard_security"

SYS = (
    "You are a DeFi / cross-chain security triage analyst. A statistical detector "
    "flagged an on-chain anomaly; decide whether it is actually a vulnerability. "
    "Be rigorous and HONEST: a large transfer is NOT itself an exploit — if access "
    "control held and no exploit primitive (reentrancy, missing auth, oracle/price "
    "manipulation, replay) is present, it is most likely a legitimate large transfer "
    "(verdict LOW or FALSE_POSITIVE). Only escalate when there is a concrete exploit "
    "hypothesis. Return STRICT JSON and nothing else: "
    '{"verdict":"CRITICAL|HIGH|MEDIUM|LOW|FALSE_POSITIVE",'
    '"vulnerability_class":"snake_case",'
    '"reasoning":"2-3 sentence rationale",'
    '"recommended_action":"short",'
    '"poc_worthwhile":true|false}'
)


def connect():
    return client.connect(host="localhost", port=8089,
                          username=os.environ["SPLUNK_USER"],
                          password=os.environ["SPLUNK_PASS"], scheme="https")


def oneshot(svc, spl, e="-3650d", c=50):
    j = svc.jobs.oneshot(spl, earliest_time=e, latest_time="now", count=c, output_mode="json")
    return [r for r in results.JSONResultsReader(j) if isinstance(r, dict)]


def reason(model, tok, alert):
    ctx = {k: alert.get(k) for k in ("alert_type", "severity", "chain", "contract_name",
                                     "vulnerability_class", "summary", "source_tx_hash")}
    msgs = [{"role": "system", "content": SYS},
            {"role": "user", "content": "Anomaly:\n" + json.dumps(ctx, default=str) + "\n\nReturn the JSON verdict."}]
    p = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
    out = generate(model, tok, prompt=p, max_tokens=240, verbose=False)
    m = re.search(r"\{.*\}", out, re.S)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            pass
    return {"verdict": "MEDIUM", "vulnerability_class": "unknown",
            "reasoning": out.strip()[:400], "recommended_action": "manual review",
            "poc_worthwhile": False}


def main():
    svc = connect()
    cands = oneshot(svc, f'search index={INDEX} sourcetype=layerzero:ai_report '
                          f'reasoning_engine=splunk_native_tier0 | spath | dedup source_tx_hash '
                          f'| head 9 | table source_tx_hash contract_name chain alert_type verdict '
                          f'vulnerability_class summary')
    # spath can emit multivalue fields — coerce each to its first value
    cands = [{k: (v[0] if isinstance(v, list) and v else v) for k, v in a.items()} for a in cands]
    if not cands:
        print("no tier-0 candidates to enrich"); return
    print(f"loading {MODEL} (local, sovereign) ...", flush=True)
    t = time.time()
    model, tok = load(MODEL)
    print(f"model ready in {time.time()-t:.0f}s; reasoning over {len(cands)} candidates\n", flush=True)
    eng = "mlx:" + MODEL.split("/")[-1]
    n = 0
    for a in cands:
        v = reason(model, tok, a)
        ev = {
            "timestamp": int(time.time()), "agent": "Argus-llm-enrich", "reasoning_engine": eng,
            "source_tx_hash": a.get("source_tx_hash"), "contract_name": a.get("contract_name"),
            "chain": a.get("chain"), "alert_type": a.get("alert_type"),
            "tier0_verdict": a.get("verdict"),
            "verdict": v.get("verdict"), "vulnerability_class": v.get("vulnerability_class"),
            "summary": v.get("reasoning"), "recommended_action": v.get("recommended_action"),
            "poc_worthwhile": v.get("poc_worthwhile"),
        }
        svc.indexes[INDEX].submit(json.dumps(ev), sourcetype="layerzero:ai_report", source="llm_enrich")
        print(f"  tier0={str(a.get('verdict')):8} -> LLM={str(v.get('verdict')):14} "
              f"{a.get('contract_name')}: {str(v.get('reasoning'))[:90]}", flush=True)
        n += 1
    print(f"\nDONE — wrote {n} LLM-reasoned ai_reports (reasoning_engine={eng})")


if __name__ == "__main__":
    main()
