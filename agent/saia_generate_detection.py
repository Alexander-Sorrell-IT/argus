"""saia_generate_detection.py — use the LIVE Splunk AI Assistant (SAIA) to GENERATE
a new SPL detection from a plain-English threat description.

This is the live "AI Assistant / Developer Tools" capability: SAIA — Splunk's own
hosted model — WRITES the security logic, Argus saves it as a candidate detection.
Fast (~15s) via the /predict generate_spl path (the sync /generatespl SCS endpoint
400s for this tenant, so we use /predict). See agent/splunk_mcp_client.py.

Run:  python3 agent/saia_generate_detection.py "<threat description>"
"""
import sys, os, re, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
from splunk_mcp_client import SplunkMCPClient

DEFAULT_ASK = (
    "Write a Splunk SPL detection over index=omni_guard_security "
    "sourcetype=layerzero:transaction that flags, per contract_name, any value_eth "
    "more than 4 standard deviations above that contract's own mean. Use eventstats "
    "to build the per-contract baseline (mean and stdev), compute a z-score, keep only "
    "rows with z-score > 4, and output _time, tx_hash, contract_name, chain, value_eth "
    "and the z-score."
)


def main():
    ask = " ".join(sys.argv[1:]).strip() or DEFAULT_ASK
    saia = SplunkMCPClient()
    print("Asking SAIA (Splunk AI Assistant) to write a detection...\n", flush=True)
    t = time.time()
    answer = saia.generate_spl(ask)
    dt = time.time() - t
    print(f"--- SAIA responded in {dt:.0f}s ---\n{answer}\n")

    m = re.search(r"```(?:splunk-spl|spl)?\s*(.+?)```", answer, re.S)
    spl = (m.group(1).strip() if m else answer.strip())
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "splunk", "generated")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "saia_generated_detection.spl")
    header = ("# Detection AUTHORED BY the Splunk AI Assistant (SAIA) from a plain-English\n"
              "# threat description, via Argus. Review before scheduling.\n# Prompt: " + ask + "\n\n")
    with open(out, "w") as f:
        f.write(header + spl + "\n")
    print(f"saved generated detection -> splunk/generated/saia_generated_detection.spl")
    return spl


if __name__ == "__main__":
    main()
