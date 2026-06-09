"""splunk_mcp_client.py — minimal JSON-RPC client for the OFFICIAL Splunk
MCP Server app (installed at /services/mcp on Splunk's management port).

Replaces our earlier custom-MCP SSE client. Uses the encrypted bearer
token issued by /services/mcp_token.
"""
from __future__ import annotations
import os, json, time, logging
from pathlib import Path
import requests
from typing import Optional

from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parents[1] / ".env")

log = logging.getLogger(__name__)

def _env_at_call(name, default=""):
    return os.getenv(name, default)
SPLUNK_MGMT_URL = _env_at_call("SPLUNK_MGMT_URL", "https://localhost:8089").rstrip("/")
SPLUNK_USER     = _env_at_call("SPLUNK_USER", "")
SPLUNK_PASS     = _env_at_call("SPLUNK_PASS", "")
TOKEN_TTL_SECS  = int(os.getenv("MCP_TOKEN_TTL_SECS", "3600"))
VERIFY_TLS      = os.getenv("SPLUNK_VERIFY_TLS", "false").lower() == "true"


class SplunkMCPClient:
    """JSON-RPC over HTTPS client for the official Splunk MCP Server.

    Caches the encrypted MCP token for the configured TTL; auto-refetches
    when expired.
    """

    def __init__(self, mgmt_url: str = SPLUNK_MGMT_URL,
                 user: str = SPLUNK_USER, password: str = SPLUNK_PASS):
        self.mgmt_url = mgmt_url
        self.user     = user
        self.password = password
        self._token: Optional[str] = None
        self._token_at: float = 0.0
        self._req_id  = 0
        self._initialized = False

    # ── auth ───────────────────────────────────────────────────────────
    def _get_token(self) -> str:
        if self._token and (time.time() - self._token_at) < TOKEN_TTL_SECS:
            return self._token
        url = f"{self.mgmt_url}/services/mcp_token"
        r = requests.get(url, params={"output_mode": "json", "username": self.user},
                         auth=(self.user, self.password), verify=VERIFY_TLS, timeout=10)
        r.raise_for_status()
        self._token = r.json()["token"]
        self._token_at = time.time()
        log.debug("MCP token refreshed")
        return self._token

    # ── core JSON-RPC ──────────────────────────────────────────────────
    def _rpc(self, method: str, params: Optional[dict] = None,
             notify: bool = False) -> Optional[dict]:
        self._req_id += 1
        body = {"jsonrpc": "2.0", "method": method}
        if not notify:
            body["id"] = self._req_id
        if params is not None:
            body["params"] = params
        r = requests.post(
            f"{self.mgmt_url}/services/mcp",
            headers={
                "Authorization": f"Bearer {self._get_token()}",
                "Content-Type": "application/json",
            },
            json=body, verify=VERIFY_TLS, timeout=60,
        )
        r.raise_for_status()
        if notify:
            return None
        resp = r.json()
        if "error" in resp:
            raise RuntimeError(f"MCP error: {resp['error']}")
        return resp.get("result")

    def _ensure_init(self):
        if self._initialized:
            return
        self._rpc("initialize", {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "omniguard", "version": "1.0"},
        })
        # MCP requires a notifications/initialized after init
        try:
            self._rpc("notifications/initialized", {}, notify=True)
        except Exception as e:
            log.debug(f"initialized-notification skipped: {e}")
        self._initialized = True

    # ── tools ──────────────────────────────────────────────────────────
    def list_tools(self) -> list[dict]:
        self._ensure_init()
        result = self._rpc("tools/list", {})
        return result.get("tools", [])

    def call_tool(self, name: str, arguments: Optional[dict] = None) -> dict:
        self._ensure_init()
        result = self._rpc("tools/call", {"name": name, "arguments": arguments or {}})
        return result

    # ── convenience: SPL search ────────────────────────────────────────
    def search(self, spl: str, earliest: str = "-24h", latest: str = "now",
               max_results: int = 100) -> list[dict]:
        """Run an SPL query via the official MCP tool. Returns list of result dicts."""
        # Ensure query is prefixed correctly
        q = spl if spl.lstrip().lower().startswith(("search ", "|")) else f"search {spl}"
        out = self.call_tool("splunk_run_query", {
            "query": q,
            "earliest_time": earliest,
            "latest_time": latest,
            "max_results": max_results,
        })
        # Tool returns {"content": [{"type":"text","text": "..."}]} where text is the JSON-encoded result
        try:
            content = out.get("content", [])
            for c in content:
                if c.get("type") == "text":
                    txt = c.get("text", "")
                    if not txt:
                        continue
                    try:
                        payload = json.loads(txt)
                    except Exception:
                        return [{"raw": txt}]
                    # Splunk usually returns {"results": [...]} or {"events": [...]}
                    if isinstance(payload, dict):
                        return payload.get("results") or payload.get("events") or [payload]
                    if isinstance(payload, list):
                        return payload
        except Exception as e:
            log.warning(f"search parse failed: {e}")
        return []

    # ── convenience: saved-search ───────────────────────────────────────
    def run_saved_search(self, name: str, trigger_actions: bool = False) -> list[dict]:
        out = self.call_tool("splunk_run_saved_search", {
            "saved_search_name": name,
            "trigger_actions": trigger_actions,
        })
        # Same content parsing as search()
        try:
            for c in out.get("content", []):
                if c.get("type") == "text":
                    payload = json.loads(c["text"])
                    if isinstance(payload, dict):
                        return payload.get("results") or payload.get("events") or [payload]
                    return payload
        except Exception as e:
            log.warning(f"run_saved_search parse failed: {e}")
        return []

    # ── AI Assistant pass-throughs ─────────────────────────────────────
    def ask_splunk_question(self, prompt: str, context: Optional[dict] = None,
                            poll_seconds: int = 240) -> str:
        """Use the Splunk-hosted LLM (SAIA) via the cloud-connected /predict
        endpoint. SAIA is async: /predict returns a job_id, the actual answer
        lands in the /chathistory store keyed by chat_id. We poll until the
        record with our job_id has loadingState==2 (complete).
        """
        import uuid, time
        chat_id = str(uuid.uuid4())
        body = {
            "prompt": prompt,
            "chat_id": chat_id,
            "classification": 0,         # 0 = SPL/general writer; matches UI
            "rewrite_content": True,
        }
        if context:
            body["additional_context"] = json.dumps(context)[:8000]

        # 1. submit
        submit_url = f"{self.mgmt_url}/servicesNS/nobody/Splunk_AI_Assistant_Cloud/predict"
        r = requests.post(submit_url, json=body,
                          headers={"source-app-id": "Splunk_AI_Assistant_Cloud"},
                          auth=(self.user, self.password),
                          verify=VERIFY_TLS, timeout=30)
        if r.status_code != 200:
            return json.dumps({"error": f"submit {r.status_code}", "body": r.text[:500]})
        job_id = r.json().get("job_id")
        if not job_id:
            return json.dumps({"error": "no job_id", "body": r.text[:500]})

        # 2. poll chat_history until job_id appears with loadingState=2
        hist_url = f"{self.mgmt_url}/servicesNS/nobody/Splunk_AI_Assistant_Cloud/chathistory"
        deadline = time.time() + poll_seconds
        while time.time() < deadline:
            time.sleep(2)
            hr = requests.get(hist_url + "?output_mode=json",
                              headers={"source-app-id": "Splunk_AI_Assistant_Cloud"},
                              auth=(self.user, self.password),
                              verify=VERIFY_TLS, timeout=15)
            if hr.status_code != 200:
                continue
            try:
                payload = hr.json()
            except Exception:
                continue
            # walk every thread, every record, find one with matching id
            threads = payload.get("chat_history", {})
            for thread_id, thread in threads.items():
                for mode, records in (thread.get("records") or {}).items():
                    for rec in records or []:
                        if rec.get("id") == job_id and rec.get("loadingState") == 2:
                            content = rec.get("content", "")
                            meta = rec.get("metadata", {}) or {}
                            srcs = meta.get("sourceUrls", []) or []
                            if srcs:
                                content += f"\n\nSources: {', '.join(srcs[:3])}"
                            return content
                        if rec.get("id") == job_id and rec.get("loadingState") == 3:
                            return json.dumps({"error": "saia error",
                                               "record": str(rec)[:500]})
        return json.dumps({"error": "timeout waiting for SAIA response",
                           "job_id": job_id, "chat_id": chat_id})

    # The REAL Argus index schema — fed to SAIA so it writes SPL that binds to
    # live data instead of inventing sourcetype/field names. Verified against the
    # live index (omni_guard_security): 10 populated layerzero:* sourcetypes.
    ARGUS_SCHEMA = {
        "index": "omni_guard_security",
        "sourcetypes": {
            "layerzero:transaction": ["contract_name", "contract_address", "chain", "value_eth",
                                       "value_usd_est", "gas_used", "is_error", "failed_tx", "high_gas",
                                       "large_value", "method_id", "tx_type", "tx_hash", "from_address",
                                       "to_address", "block_number", "timestamp"],
            "layerzero:event":       ["contract_name", "contract_address", "chain", "tx_hash", "topic0",
                                       "topic1", "topic2", "data", "log_index", "event_type", "block_number"],
            "layerzero:alert":       ["severity", "alert_type", "chain", "tx_hashes", "search_name",
                                       "time_span_secs", "description"],
            "layerzero:ai_report":   ["verdict", "confidence", "vulnerability_class", "contract_name",
                                       "chain", "summary", "reasoning_engine", "source_tx_hash"],
        },
        "notes": "Sourcetypes use a COLON (sourcetype=\"layerzero:transaction\"). Chains seen: "
                 "ethereum, polygon, avalanche. Fields are JSON in _raw, KV_MODE=auto.",
    }

    def generate_spl(self, prompt: str, spl_only: bool = True, schema_aware: bool = True) -> str:
        """Generate SPL via SAIA (classification=0, the live write path). When
        schema_aware, the REAL Argus schema is supplied to SAIA as additional_context
        AND in-prompt, then a deterministic post-processor binds sourcetype/field
        names to the live index — so the output runs against real data, not a
        hallucinated schema. SAIA drafts the logic; the post-processor binds it."""
        if not schema_aware:
            return self.ask_splunk_question(f"Generate SPL for this: {prompt}")

        sc = self.ARGUS_SCHEMA
        schema_text = "\n".join(
            f'  sourcetype="{st}": {", ".join(fields)}' for st, fields in sc["sourcetypes"].items()
        )
        enriched = (
            "Write a single Splunk SPL detection for the Argus app. Use ONLY this real schema "
            f"(index={sc['index']}); do not invent sourcetypes or fields:\n{schema_text}\n"
            f"{sc['notes']}\nAlways begin with index={sc['index']} and a colon-form sourcetype. "
            f"Threat to detect: {prompt}\nReturn only the SPL."
        )
        draft = self.ask_splunk_question(enriched, context=sc)
        return self._bind_to_schema(draft)

    def _bind_to_schema(self, spl: str) -> str:
        """Deterministically rewrite the common SAIA schema-drift back to the live
        index: underscore sourcetypes -> colon form, known plurals -> singular, and
        ensure the index is set. This is a binder, NOT a generator — it never invents
        detection logic, it only repairs names so SAIA's draft actually runs."""
        import re
        s = spl
        # layerzero_events / layerzero_transactions / layerzero_xxx -> layerzero:xxx
        s = re.sub(r'sourcetype\s*=\s*"?layerzero[_:](\w+)"?',
                   lambda m: 'sourcetype="layerzero:%s"' % {
                       "events": "event", "transactions": "transaction",
                       "alerts": "alert", "ai_reports": "ai_report",
                   }.get(m.group(1), m.group(1)), s)
        # ensure the Argus index is present if SAIA omitted it / used index=*
        if re.search(r'index\s*=\s*\*', s):
            s = re.sub(r'index\s*=\s*\*', 'index=%s' % self.ARGUS_SCHEMA["index"], s, count=1)
        elif "index=" not in s and "index =" not in s:
            s = "index=%s " % self.ARGUS_SCHEMA["index"] + s.lstrip()
        return s

    def explain_spl(self, spl: str) -> str:
        """Explain SPL via SAIA. Uses the same /predict + ask_splunk_question
        path with a wrapper prompt (cloud's classification=4 path returns 500
        for our tenant; classification=0 works for both generation + explanation)."""
        return self.ask_splunk_question(
            f"Explain step-by-step what this SPL query does and what it returns:\n\n{spl}"
        )

    def _saia_predict(self, prompt: str, classification: int = 0,
                      poll_seconds: int = 60) -> str:
        """Lower-level predict helper used by generate_spl + explain_spl."""
        import uuid, time
        chat_id = str(uuid.uuid4())
        body = {
            "prompt": prompt,
            "chat_id": chat_id,
            "classification": classification,
            "rewrite_content": True,
        }
        url = f"{self.mgmt_url}/servicesNS/nobody/Splunk_AI_Assistant_Cloud/predict"
        r = requests.post(url, json=body,
                          headers={"source-app-id": "Splunk_AI_Assistant_Cloud"},
                          auth=(self.user, self.password),
                          verify=VERIFY_TLS, timeout=30)
        if r.status_code != 200:
            return json.dumps({"error": f"submit {r.status_code}", "body": r.text[:500]})
        job_id = r.json().get("job_id")
        hist_url = f"{self.mgmt_url}/servicesNS/nobody/Splunk_AI_Assistant_Cloud/chathistory"
        deadline = time.time() + poll_seconds
        while time.time() < deadline:
            time.sleep(2)
            hr = requests.get(hist_url + "?output_mode=json",
                              headers={"source-app-id": "Splunk_AI_Assistant_Cloud"},
                              auth=(self.user, self.password),
                              verify=VERIFY_TLS, timeout=15)
            if hr.status_code != 200:
                continue
            payload = hr.json()
            for thread in payload.get("chat_history", {}).values():
                for records in (thread.get("records") or {}).values():
                    for rec in records or []:
                        if rec.get("id") == job_id and rec.get("loadingState") == 2:
                            return rec.get("content", "")
        return json.dumps({"error": "timeout", "job_id": job_id})


# ── smoke test ────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    c = SplunkMCPClient()
    tools = c.list_tools()
    print(f"Tools available: {len(tools)}")
    for t in tools:
        print(f"  {t['name']}")
    print()
    r = c.search("index=omni_guard_security | stats count by sourcetype",
                 earliest="-30d", max_results=10)
    print("Search result:")
    for row in r:
        print(f"  {row}")
