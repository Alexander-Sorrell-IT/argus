#!/usr/bin/env python3
"""argus_agent.py — Argus in-app AI security agent (Splunk modular input).

This is the "AI agents for Splunk apps" capability: an agentic workflow that
lives INSIDE the Splunk app and drives Splunk through the Splunk Python SDK
(splunklib) — no external orchestrator process.

Splunk-effective data architecture:
  • READS raw facts from the omni_guard_security index (append-only; never altered).
  • WRITES derived verdicts as layerzero:ai_report events (append-only).
  • KEEPS mutable working state in a KV Store collection (argus_agent_state),
    keyed by a finding SIGNATURE so the same alert re-firing every scheduled
    run collapses to ONE finding (idempotent — no flooding, no re-work).

Each interval the agent:
  1. Pulls distinct recent findings from layerzero:alert (deduped by signature)
  2. Skips any finding already in KV state
  3. Triages each into a structured verdict (Splunk-native, severity-driven)
  4. Writes a layerzero:ai_report event back into the index (in-process)
  5. Emits layerzero:poc_trigger for the external Anvil/Foundry validator
     (that fork sandbox must stay out of splunkd)
  6. Records the finding in KV state so it is never re-processed

Dependencies are limited to splunklib (vendored in ../lib) + stdlib so the
script runs inside the splunkd embedded Python interpreter.
"""
import os
import sys
import json
import time
import hashlib
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))

import splunklib.client as client          # noqa: E402
import splunklib.results as results        # noqa: E402
from splunklib.modularinput import (       # noqa: E402
    Script, Scheme, Argument,
)

INDEX = "omni_guard_security"
STATE_COLLECTION = "argus_agent_state"

# Real alert_type (from SPL detections) -> vulnerability_class.
# Unknown types fall back to the normalized alert_type string.
VULN_CLASS = {
    "replay_attack":         "message_replay",
    "large_value_transfer":  "value_manipulation",
    "duplicate_message_id":  "message_replay",
    "known_bad_address":     "known_malicious_actor",
    "multi_step_attack":     "multi_step_exploit",
}

SEVERITY_RANK = {"FALSE_POSITIVE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# ── Auto-router: close the loop in-process (detect → triage → poc_trigger →
# fork-validate → verdict) with NO human running the validator. OFF by default so the
# stock agent behaviour is unchanged; enable with ARGUS_AUTO_VALIDATE=1.
AUTO_VALIDATE = os.getenv("ARGUS_AUTO_VALIDATE", "0") == "1"
# When auto-validating, also let SAIA DRAFT an exploit test for candidates with no
# pre-written one (the generation half of the loop). On by default once AUTO_VALIDATE is
# on. SAIA only drafts the hypothesis — the verdict still comes from a real Foundry [PASS].
SAIA_DRAFT = os.getenv("ARGUS_SAIA_DRAFT", "1") == "1"
SYS_PYTHON = os.getenv("ARGUS_SYS_PYTHON") or shutil.which("python3") or sys.executable

def _argus_repo():
    for c in (os.getenv("ARGUS_HOME"), os.path.expanduser("~/argus"),
              os.path.expanduser("~/Desktop/omni-guard"), os.getcwd()):
        if c and os.path.exists(os.path.join(c, "poc", "validate_finding.py")):
            return c
    return os.getenv("ARGUS_HOME") or ""

def _match_exploit_test(repo, tx_hash):
    """Best-effort: find a known exploit test (.t.sol) whose finding matches this tx
    (poc/findings/*/context.json mentioning the tx). Returns the Exploit.t.sol path or
    None. None → the validator records a trace and returns INCONCLUSIVE, the honest
    outcome when no exploit hypothesis exists for a candidate."""
    import glob
    tx = (tx_hash or "").lower()
    if not tx:
        return None
    for ctx in glob.glob(os.path.join(repo, "poc", "findings", "*", "context.json")):
        try:
            if tx in open(ctx).read().lower():
                t = os.path.join(os.path.dirname(ctx), "Exploit.t.sol")
                if os.path.exists(t):
                    return t
        except Exception:
            continue
    return None

def _ensure_runnable(proj_dir, repo):
    """Make an exploit dir runnable: ensure foundry.toml + lib/forge-std so `forge test`
    compiles the .t.sol (the findings/ evidence copy ships without build deps)."""
    ft = os.path.join(proj_dir, "foundry.toml")
    if not os.path.exists(ft):
        try:
            with open(ft, "w") as f:
                f.write('[profile.default]\nsrc="."\ntest="."\nout="out"\nlibs=["lib"]\n')
        except Exception:
            pass
    libstd = os.path.join(proj_dir, "lib", "forge-std")
    if not os.path.exists(libstd):
        for src in (os.path.join(repo, "layerzero-src", "LayerZero-v2", "lib", "forge-std"),
                    os.path.join(repo, "poc", "capability-selftest", "lib", "forge-std")):
            if os.path.exists(src):
                try:
                    os.makedirs(os.path.join(proj_dir, "lib"), exist_ok=True)
                    os.symlink(src, libstd)
                except Exception:
                    pass
                break


def _saia_draft_test(repo, trig, log):
    """Generation half of the closed loop: for a candidate with NO pre-written test, ask
    SAIA (via poc/draft_exploit.py, run under the system interpreter) to draft an
    Exploit.t.sol. Returns the path if SAIA produced a usable Foundry test, else None
    (→ honest INCONCLUSIVE). SAIA drafts the hypothesis; the verdict still comes from a
    real Foundry [PASS] — never from SAIA."""
    sig = str(trig.get("finding_signature") or trig.get("tx_hash") or "adhoc")[:16]
    out_dir = os.path.join(repo, "poc", "findings", ".auto", sig)
    cmd = [SYS_PYTHON, os.path.join(repo, "poc", "draft_exploit.py"),
           "--tx-hash", str(trig.get("tx_hash", "")), "--chain", str(trig.get("chain", "ethereum")),
           "--alert-type", str(trig.get("source_alert", "")),
           "--vuln-class", str(trig.get("vulnerability_class", "")),
           "--contract", str(trig.get("contract", "")),
           "--description", str(trig.get("description", "")), "--out-dir", out_dir]
    blk = trig.get("block_number")
    if blk:
        try:
            cmd += ["--fork-block", str(int(blk) - 1)]
        except Exception:
            pass
    log("  no pre-written test — asking SAIA to draft an exploit hypothesis…")
    try:
        import subprocess
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300, cwd=repo)
        lines = [ln for ln in (r.stdout or "").splitlines() if ln.strip()]
        path = lines[-1].strip() if lines else ""
        if path and os.path.exists(path):
            log(f"  SAIA drafted a test → {os.path.relpath(path, repo)} (fork-validating it)")
            return path
        log("  SAIA produced no usable test → INCONCLUSIVE (no fabrication)")
    except Exception as e:
        log(f"  SAIA draft error: {e}")
    return None


# ── helpers ──────────────────────────────────────────────────────────────────────
def oneshot(service, spl, earliest="-24h", latest="now", count=0):
    """Run a oneshot search in-process and return a list of result dicts."""
    job = service.jobs.oneshot(
        spl, earliest_time=earliest, latest_time=latest,
        count=count, output_mode="json",
    )
    return [r for r in results.JSONResultsReader(job) if isinstance(r, dict)]


def write_event(service, event, sourcetype):
    """Append a single typed event into the index, in-process."""
    service.indexes[INDEX].submit(json.dumps(event), sourcetype=sourcetype, source="argus_agent")


def finding_signature(alert):
    """Stable identity for a finding so the same alert re-firing across many
    scheduled runs collapses to ONE finding."""
    raw = "|".join([
        (alert.get("tx_hashes") or alert.get("tx_hash") or "").strip(),
        alert.get("alert_type", ""),
        alert.get("chain", ""),
    ])
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def primary_tx(alert):
    txs = (alert.get("tx_hashes") or alert.get("tx_hash") or "").split()
    return txs[0] if txs else ""


def ensure_state_collection(service):
    """Create the KV Store state collection if it does not yet exist (runtime,
    no Splunk restart needed)."""
    if STATE_COLLECTION not in service.kvstore:
        service.kvstore.create(STATE_COLLECTION, fields={
            "signature": "string", "primary_tx": "string", "alert_type": "string",
            "severity": "string", "chain": "string", "verdict": "string",
            "confidence": "number", "poc_worthwhile": "string",
            "triaged_epoch": "number",
        })
    return service.kvstore[STATE_COLLECTION]


# ── core agentic cycle ─────────────────────────────────────────────────────────
def fetch_unprocessed_findings(service, state, lookback="-6h", log=None):
    """Distinct findings (deduped by tx_hashes+type+chain) not yet in KV state."""
    # Coalesce tx_hashes (plural, used by replay-family alerts) with tx_hash
    # (singular, used by large_value_transfer alerts) into one identity field.
    # Deduping on tx_hashes alone silently DROPPED every large_value_transfer
    # alert (its tx_hashes is null, and null dedup keys are discarded).
    findings = oneshot(
        service,
        # Exclude the disabled/invalid replay_attack class (mirrors Candidate Scoring)
        # so the ~12.7k stale replay false positives don't get re-triaged and re-flood
        # ai_report + poc_trigger. Remove this once GUID-level replay is re-ingested.
        f'search index={INDEX} sourcetype=layerzero:alert alert_type!="replay_attack" '
        f'| eval tx_id=coalesce(tx_hashes, tx_hash) '
        f'| dedup tx_id alert_type chain '
        f'| table _time alert_type severity chain tx_hashes tx_hash tx_id search_name description topic1',
        earliest=lookback,
    )
    try:
        processed = {row["_key"] for row in state.data.query(fields="_key")}
    except Exception:
        processed = set()

    fresh = [f for f in findings if finding_signature(f) not in processed]
    if log:
        log(f"distinct_findings={len(findings)} already_processed={len(processed)} fresh={len(fresh)}")
    return fresh


def lookup_block(service, tx_hash):
    """Best-effort: find the block number for a tx so the PoC trigger can fork."""
    if not tx_hash:
        return None
    rows = oneshot(
        service,
        f'search index={INDEX} sourcetype=layerzero:transaction tx_hash="{tx_hash}" '
        f'| head 1 | table block_number',
        earliest="-3650d", count=1,
    )
    if rows:
        try:
            return int(rows[0].get("block_number"))
        except Exception:
            return None
    return None


def lookup_block_any(service, tx_hashes):
    """Try each tx hash until one resolves to a block. Replay alerts list
    multiple hashes and the first often isn't in the tx index; using only
    the first silently dropped a large share of replay PoC triggers."""
    toks = (tx_hashes or "").split()
    for tx in toks:
        b = lookup_block(service, tx)
        if b is not None:
            return b, tx
    return None, (toks[0] if toks else "")


def triage(service, alert):
    """Splunk-native severity-driven verdict. Trusts the SPL detection's own
    severity, maps the alert_type to a vulnerability class, and decides whether
    a fork-validation PoC is worthwhile."""
    alert_type = alert.get("alert_type", "unknown")
    sev = (alert.get("severity") or "MEDIUM").upper()
    if sev not in SEVERITY_RANK:
        sev = "MEDIUM"
    vuln_class = VULN_CLASS.get(alert_type, alert_type or "unknown")

    rank = SEVERITY_RANK[sev]
    confidence = round(min(0.95, 0.5 + 0.11 * rank), 3)
    poc_worthwhile = rank >= SEVERITY_RANK["HIGH"]

    raw = alert.get("tx_id") or alert.get("tx_hashes") or alert.get("tx_hash") or ""
    if poc_worthwhile:
        block, tx = lookup_block_any(service, raw)
    else:
        block, tx = None, primary_tx(alert)

    return {
        "verdict": sev,
        "confidence": confidence,
        "vulnerability_class": vuln_class,
        "summary": (f"{vuln_class.replace('_', ' ')} on {alert.get('chain', '?')} "
                    f"via {alert_type} (severity {sev}); "
                    f"{(alert.get('description') or '')[:160]}").strip(),
        "evidence": [f"detection={alert.get('search_name', alert_type)}",
                     f"severity={sev}", f"chain={alert.get('chain', '?')}"],
        "recommended_action": "fork-validate" if poc_worthwhile else "monitor",
        "poc_worthwhile": poc_worthwhile,
        "poc_block_number": block,
        "poc_tx_hash": tx,
        "reasoning_engine": "splunk_native_tier0",
    }


def auto_validate(service, trig, log=None, write=True):
    """Run fork-validation IN-PROCESS for a poc_trigger and (optionally) write the verdict
    back as layerzero:fork_result — closing the detect→prove loop with no human step. The
    agent (in splunkd) orchestrates the host EVM tooling via the system interpreter; the
    verdict is DETERMINISTIC (no AI). A matched exploit test yields CONFIRMED/REJECTED;
    otherwise the validator records a trace (INCONCLUSIVE)."""
    log = log or (lambda m: None)
    repo = _argus_repo()
    validator = os.path.join(repo, "poc", "validate_finding.py")
    if not repo or not os.path.exists(validator):
        log("  auto-validate skipped: Argus repo not found (set ARGUS_HOME)")
        return None
    tx = trig.get("tx_hash"); blk = trig.get("block_number"); chain = trig.get("chain", "ethereum")
    cmd = [SYS_PYTHON, validator, "--tx-hash", str(tx), "--chain", str(chain), "--no-splunk"]
    if blk:
        try:
            cmd += ["--fork-block", str(int(blk) - 1)]
        except Exception:
            pass
    test = _match_exploit_test(repo, tx)
    if not test and SAIA_DRAFT:
        test = _saia_draft_test(repo, trig, log)
    if test:
        _ensure_runnable(os.path.dirname(test), repo)
        cmd += ["--foundry-test", test]
    log(f"  auto-validate → forking {chain} @ {str(tx)[:18]}…"
        f"{' (exploit test matched)' if test else ' (trace only)'}")
    try:
        import subprocess
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300, cwd=repo)
        out = r.stdout or ""
        data = json.loads(out[out.index("{"):]) if "{" in out else {"status": "ERROR", "reason": "no JSON from validator"}
    except Exception as e:
        data = {"status": "ERROR", "reason": f"auto-validate error: {e}"}
    data.setdefault("timestamp", int(time.time()))
    data["auto_routed"] = True
    if write and service is not None:
        write_event(service, data, "layerzero:fork_result")
    log(f"  auto-validate verdict → {data.get('status')}")
    return data.get("status")


def run_cycle(service, lookback="-6h", log=None, write=True):
    """One agentic cycle. Returns (#findings triaged, list of verdict summaries)."""
    log = log or (lambda m: None)
    state = ensure_state_collection(service)
    findings = fetch_unprocessed_findings(service, state, lookback=lookback, log=log)
    if not findings:
        log("no fresh findings")
        return 0, []

    summaries = []
    now = int(time.time())
    for alert in findings:
        sig = finding_signature(alert)
        v = triage(service, alert)

        report = {
            "timestamp": now,
            "agent": "Argus-inapp-v1",
            "finding_signature": sig,
            "source_tx_hash": v["poc_tx_hash"],
            "alert_type": alert.get("alert_type", "unknown"),
            "chain": alert.get("chain", ""),
            "verdict": v["verdict"],
            "confidence": v["confidence"],
            "vulnerability_class": v["vulnerability_class"],
            "summary": v["summary"],
            "evidence": " | ".join(v["evidence"]),
            "recommended_action": v["recommended_action"],
            "poc_worthwhile": v["poc_worthwhile"],
            "poc_block_number": v["poc_block_number"],
            "poc_tx_hash": v["poc_tx_hash"],
            "reasoning_engine": v["reasoning_engine"],
        }

        if write:
            write_event(service, report, "layerzero:ai_report")
            if v["poc_worthwhile"] and v["poc_block_number"]:
                write_event(service, {
                    "timestamp": now, "trigger_type": "poc_fork_test",
                    "finding_signature": sig,
                    "source_alert": alert.get("alert_type", "unknown"),
                    "tx_hash": v["poc_tx_hash"], "block_number": v["poc_block_number"],
                    "vulnerability_class": v["vulnerability_class"],
                    "chain": alert.get("chain", "ethereum"), "status": "PENDING",
                }, "layerzero:poc_trigger")
                if AUTO_VALIDATE:
                    # Close the loop in one motion: fork-validate this candidate now.
                    auto_validate(service, {
                        "tx_hash": v["poc_tx_hash"],
                        "block_number": v["poc_block_number"],
                        "chain": alert.get("chain", "ethereum"),
                        "finding_signature": sig,
                        "vulnerability_class": v["vulnerability_class"],
                        "source_alert": alert.get("alert_type", ""),
                        "contract": alert.get("contract_name", ""),
                        "description": (alert.get("description") or v.get("summary") or "")[:500],
                    }, log=log)
            # Record idempotent state so this finding is never re-processed.
            state.data.batch_save({
                "_key": sig, "signature": sig, "primary_tx": v["poc_tx_hash"],
                "alert_type": alert.get("alert_type", ""), "severity": v["verdict"],
                "chain": alert.get("chain", ""), "verdict": v["verdict"],
                "confidence": v["confidence"],
                "poc_worthwhile": str(v["poc_worthwhile"]), "triaged_epoch": now,
            })

        summaries.append(f"[{v['verdict']}] {v['vulnerability_class']} "
                          f"{(v['poc_tx_hash'] or '')[:18]}… poc={v['poc_worthwhile']}"
                          f"{'' if v['poc_block_number'] is None else ' blk='+str(v['poc_block_number'])}")
        log("  " + summaries[-1])

    return len(findings), summaries


# ── Splunk modular-input wrapper ────────────────────────────────────────────────
class ArgusAgent(Script):
    def get_scheme(self):
        scheme = Scheme("Argus In-App Security Agent")
        scheme.description = ("Agentic security workflow that triages SPL detection "
                              "findings in-process and writes verdicts back to Splunk.")
        scheme.use_external_validation = False
        scheme.use_single_instance = False
        lookback = Argument("lookback")
        lookback.title = "Alert lookback window"
        lookback.description = "How far back to scan for un-triaged findings (e.g. -6h)."
        lookback.data_type = Argument.data_type_string
        lookback.required_on_create = False
        scheme.add_argument(lookback)
        return scheme

    def stream_events(self, inputs, ew):
        service = self.service  # authenticated via the session key Splunk passes in
        for name, item in inputs.inputs.items():
            lookback = (item.get("lookback") or "-6h").strip()
            try:
                n, _ = run_cycle(service, lookback=lookback,
                                 log=lambda m: ew.log("INFO", f"argus_agent: {m}"))
                ew.log("INFO", f"argus_agent: cycle complete, {n} finding(s) triaged")
            except Exception as e:
                ew.log("ERROR", f"argus_agent: cycle failed: {e}")


if __name__ == "__main__":
    # Prove the auto-router in-process (no human, no SPL):
    #   splunk cmd python3 argus_agent.py --validate-tx <hash> --block <attack_block> [--write]
    if "--validate-tx" in sys.argv:
        a = sys.argv
        tx = a[a.index("--validate-tx") + 1]
        blk = int(a[a.index("--block") + 1]) if "--block" in a else None
        svc = None
        if "--write" in a:
            svc = client.connect(host=os.getenv("SPLUNK_HOST", "localhost"),
                                 port=int(os.getenv("SPLUNK_PORT", "8089")),
                                 username=os.getenv("SPLUNK_USER", "admin"),
                                 password=os.getenv("SPLUNK_PASS", ""), scheme="https")
        status = auto_validate(svc, {"tx_hash": tx, "block_number": blk, "chain": "ethereum"},
                               log=lambda m: print(f"[argus] {m}"), write=("--write" in a))
        print(f"[argus] auto-router verdict: {status}")
        sys.exit(0)

    # Standalone harness:  splunk cmd python3 argus_agent.py --test [--dry-run]
    if "--test" in sys.argv:
        svc = client.connect(
            host=os.getenv("SPLUNK_HOST", "localhost"),
            port=int(os.getenv("SPLUNK_PORT", "8089")),
            username=os.getenv("SPLUNK_USER", "admin"),
            password=os.getenv("SPLUNK_PASS", ""),
            scheme="https",
        )
        do_write = "--dry-run" not in sys.argv
        n, summ = run_cycle(svc, lookback=os.getenv("ARGUS_LOOKBACK", "-30d"),
                            log=lambda m: print(f"[argus] {m}"), write=do_write)
        print(f"[argus] DONE — {n} finding(s) triaged (write={do_write})")
        sys.exit(0)
    sys.exit(ArgusAgent().run(sys.argv))
