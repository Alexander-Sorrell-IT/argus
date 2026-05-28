"""
splunk_hec.py — Send events to Splunk HTTP Event Collector
"""
import os
import json
import time
import logging
import requests
from typing import Any
from dotenv import load_dotenv

load_dotenv()
log = logging.getLogger(__name__)

HEC_URL = os.getenv("SPLUNK_HEC_URL", "https://localhost:8088")
HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "")
SSL_VERIFY = os.getenv("SPLUNK_HEC_SSL_VERIFY", "false").lower() != "false"

BATCH_SIZE = 100


class SplunkHEC:
    def __init__(self):
        if not HEC_TOKEN:
            raise ValueError("SPLUNK_HEC_TOKEN not set in environment")
        self.endpoint = f"{HEC_URL}/services/collector/event"
        self.headers = {
            "Authorization": f"Splunk {HEC_TOKEN}",
            "Content-Type": "application/json",
        }
        self._batch: list[dict] = []

    def send(self, event: dict[str, Any], sourcetype: str = "layerzero:transaction",
             index: str = "omni_guard_security", source: str = "omni-guard"):
        payload = {
            "time": event.get("timestamp", int(time.time())),
            "host": "omni-guard",
            "source": source,
            "sourcetype": sourcetype,
            "index": index,
            "event": event,
        }
        self._batch.append(payload)
        if len(self._batch) >= BATCH_SIZE:
            self.flush()

    def flush(self):
        if not self._batch:
            return
        body = "\n".join(json.dumps(p) for p in self._batch)
        try:
            resp = requests.post(
                self.endpoint, data=body, headers=self.headers,
                verify=SSL_VERIFY, timeout=10
            )
            if resp.status_code == 200:
                log.info(f"Flushed {len(self._batch)} events to Splunk HEC")
            else:
                log.warning(f"HEC batch rejected ({resp.status_code}): {resp.text} — retrying one-by-one")
                self._send_one_by_one()
        except requests.RequestException as e:
            log.error(f"HEC send failed: {e}")
        finally:
            self._batch.clear()

    def _send_one_by_one(self):
        ok = 0
        for payload in self._batch:
            # Clamp timestamp to valid Unix range
            ts = payload.get("time", 0)
            if not ts or ts > 9999999999:
                payload["time"] = int(time.time())
            # Truncate oversized event fields
            ev = payload.get("event", {})
            for k, v in ev.items():
                if isinstance(v, str) and len(v) > 4096:
                    ev[k] = v[:4096] + "...[truncated]"
            try:
                r = requests.post(
                    self.endpoint, data=json.dumps(payload),
                    headers=self.headers, verify=SSL_VERIFY, timeout=10
                )
                if r.status_code == 200:
                    ok += 1
            except Exception:
                pass
        log.info(f"One-by-one fallback: {ok}/{len(self._batch)} events sent")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.flush()
