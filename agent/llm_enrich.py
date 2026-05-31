"""llm_enrich.py — SAIA reasoning pass over Argus candidates.

The live in-app agent (splunk/bin/argus_agent.py) does fast deterministic tier-0
triage. This adds a real LLM reasoning pass using the **Splunk AI Assistant (SAIA)**
— the Splunk-hosted model, cloud-connected — via the same /predict + /chathistory
flow the SAIA UI uses (see agent/splunk_mcp_client.py). SAIA's verdict + rationale
are written back as an enriched layerzero:ai_report (reasoning_engine=splunk_ai_assistant).

This is the live "Splunk Hosted Models / AI Assistant" capability: SAIA reads each
flagged anomaly and decides whether it is actually a vulnerability — correctly
downgrading large-but-legitimate transfers that the statistical tier-0 over-flags.

Run:  python3 agent/llm_enrich.py     (needs SPLUNK_USER/PASS in env)
"""
import os, sys, json, time, re
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, "/Applications/Splunk/etc/apps/omni_guard/lib")
import splunklib.client as client
import splunklib.results as results
from splunk_mcp_client import SplunkMCPClient

INDEX = "omni_guard_security"

PROMPT_TMPL = (
    "Context: this is a security alert stored in Splunk (index=omni_guard_security), "
    "produced by Argus, a Splunk-native security monitor for cross-chain DeFi "
    "protocols. Acting as the DeFi security analyst, judge whether this flagged "
    "on-chain anomaly is actually a vulnerability. Be honest and rigorous: a large "
    "transfer is NOT itself an exploit if access control held and there is no exploit "
    "primitive (reentrancy, missing auth, oracle/price manipulation, message replay) "
    "- in that case it is a legitimate large transfer.\n\nAlert:\n{ctx}\n\n"
    "Respond with ONLY these four lines, nothing else:\n"
    "SEVERITY: <CRITICAL|HIGH|MEDIUM|LOW|FALSE_POSITIVE>\n"
    "CLASS: <short vulnerability class or none>\nRATIONALE: <2 sentences>\n"
    "POC_WORTHWHILE: <yes|no>"
)

SEV_RE = re.compile(r"SEVERITY:\s*\**\s*(CRITICAL|HIGH|MEDIUM|LOW|FALSE[_ ]?POSITIVE)", re.I)
CLS_RE = re.compile(r"CLASS:\s*\**\s*([^\n*]+)", re.I)
POC_RE = re.compile(r"POC_WORTHWHILE:\s*\**\s*(yes|no)", re.I)


def connect():
    return client.connect(host="localhost", port=8089,
                          username=os.environ["SPLUNK_USER"],
                          password=os.environ["SPLUNK_PASS"], scheme="https")


def oneshot(svc, spl):
    j = svc.jobs.oneshot(spl, earliest_time="-3650d", latest_time="now", count=50, output_mode="json")
    return [r for r in results.JSONResultsReader(j) if isinstance(r, dict)]


def main():
    svc = connect()
    saia = SplunkMCPClient()
    n_max = int(os.getenv("ARGUS_SAIA_N", "9"))
    cands = oneshot(svc, f'search index={INDEX} sourcetype=layerzero:ai_report '
                         f'reasoning_engine=splunk_native_tier0 | spath | dedup source_tx_hash '
                         f'| head {n_max} | table source_tx_hash contract_name chain alert_type verdict summary')
    cands = [{k: (v[0] if isinstance(v, list) and v else v) for k, v in a.items()} for a in cands]
    if not cands:
        print("no tier-0 candidates"); return
    print(f"asking Splunk AI Assistant (SAIA, tellme mode) to reason over {len(cands)} candidates ...\n", flush=True)
    n = 0
    for a in cands:
        # natural-language context (the summary carries the contract/finding details)
        ctx = (a.get("summary") or
               f"{a.get('alert_type')} on {a.get('chain')} (tier-0 severity {a.get('verdict')})")
        t = time.time()
        # classification=2 = SAIA "tell me" general-Q&A mode (won't deflect); it is slow, so poll long
        ans = saia._saia_predict(PROMPT_TMPL.format(ctx=ctx), classification=2, poll_seconds=420)
        sev = SEV_RE.search(ans or "")
        verdict = (sev.group(1).upper().replace(" ", "_") if sev else "MEDIUM")
        cls = CLS_RE.search(ans or "")
        poc = POC_RE.search(ans or "")
        ev = {
            "timestamp": int(time.time()), "agent": "Argus-saia-enrich",
            "reasoning_engine": "splunk_ai_assistant",
            "source_tx_hash": a.get("source_tx_hash"), "contract_name": a.get("contract_name"),
            "chain": a.get("chain"), "alert_type": a.get("alert_type"),
            "tier0_verdict": a.get("verdict"), "verdict": verdict,
            "vulnerability_class": (cls.group(1).strip() if cls else "unknown"),
            "summary": (ans or "")[:1200],
            "poc_worthwhile": (poc.group(1).lower() == "yes") if poc else False,
        }
        svc.indexes[INDEX].submit(json.dumps(ev), sourcetype="layerzero:ai_report", source="saia_enrich")
        print(f"  tier0={str(a.get('verdict')):8} -> SAIA={verdict:14} ({time.time()-t:.0f}s) "
              f"{a.get('contract_name')}", flush=True)
        n += 1
    print(f"\nDONE — SAIA reasoned over {n} candidates -> layerzero:ai_report (reasoning_engine=splunk_ai_assistant)")


if __name__ == "__main__":
    main()
