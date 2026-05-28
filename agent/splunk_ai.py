"""splunk_ai.py — local-hosted Splunk-lineup AI models.

Two engines, lazy-loaded singletons:

  1. FoundationSec — Cisco Foundation-Sec 1.1 8B Instruct (security-tuned LLM)
     Used for tier-1 alert triage AND Foundry exploit-test generation.
     Loaded via mlx-lm for Apple Silicon performance.

  2. CiscoTimeSeries — Cisco Time Series Model 1.0-preview (TimesFM2.0)
     Used for forecasting expected on-chain metric values; deviations
     surface as anomaly candidates *before* SPL detections fire.

Both are open-source weights of the same models Splunk lists in their
hosted-model lineup — running locally for dev, drop-in to Splunk Cloud
API when that path is available.
"""
from __future__ import annotations
import os, json, time, logging, threading
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

REPO          = Path(__file__).resolve().parents[1]
MODELS_DIR    = REPO / "models"
FSEC_MODEL    = os.getenv("FSEC_MODEL", "fdtn-ai/Foundation-Sec-1.1-8B-Instruct")
CISCO_TS_DIR  = MODELS_DIR / "cisco-ts"


# ─── Foundation-Sec (security-tuned LLM) ────────────────────────────────────────
class FoundationSec:
    _instance = None
    _lock = threading.Lock()

    def __init__(self):
        from mlx_lm import load
        log.info(f"Loading Foundation-Sec from {FSEC_MODEL} (mlx-lm; first run downloads ~5GB)")
        self.model, self.tokenizer = load(FSEC_MODEL)
        log.info("Foundation-Sec ready")

    @classmethod
    def get(cls) -> "FoundationSec":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def _generate(self, prompt: str, system: str = "", max_tokens: int = 512,
                  temperature: float = 0.2) -> str:
        from mlx_lm import generate
        from mlx_lm.sample_utils import make_sampler
        # Build chat-format prompt
        msgs = []
        if system: msgs.append({"role": "system", "content": system})
        msgs.append({"role": "user", "content": prompt})
        try:
            chat_prompt = self.tokenizer.apply_chat_template(
                msgs, tokenize=False, add_generation_prompt=True
            )
        except Exception:
            chat_prompt = (f"<|system|>\n{system}\n<|user|>\n{prompt}\n<|assistant|>\n"
                           if system else f"<|user|>\n{prompt}\n<|assistant|>\n")
        sampler = make_sampler(temp=temperature)
        return generate(self.model, self.tokenizer, prompt=chat_prompt,
                        max_tokens=max_tokens, sampler=sampler, verbose=False)

    def triage(self, alert: dict, context: dict) -> dict:
        """Tier-1 triage. Returns structured verdict (replaces Claude path)."""
        system = ("You are OmniGuard's tier-1 security triage. You analyze a single "
                  "DeFi/cross-chain on-chain anomaly with supporting context and "
                  "return ONLY a JSON object with keys: verdict (CRITICAL|HIGH|MEDIUM|LOW|"
                  "FALSE_POSITIVE), confidence (0..1), vulnerability_class (snake_case), "
                  "summary (1-2 sentences), evidence (list of short strings), "
                  "recommended_action (string), poc_worthwhile (bool), poc_block_number "
                  "(int|null), poc_tx_hash (string|null). No prose outside the JSON.")
        user = (f"ALERT:\n{json.dumps(alert, indent=2, default=str)}\n\n"
                f"CONTEXT:\n{json.dumps(context, indent=2, default=str)[:6000]}\n\n"
                "Respond with ONLY the JSON object.")
        raw = self._generate(user, system=system, max_tokens=800, temperature=0.2)
        return _parse_json_loosely(raw, fallback={
            "verdict": "MEDIUM", "confidence": 0.4,
            "vulnerability_class": "unknown",
            "summary": "Foundation-Sec parse failed; manual review recommended.",
            "evidence": [], "recommended_action": "manual review",
            "poc_worthwhile": False, "poc_block_number": None,
            "poc_tx_hash": alert.get("tx_hash"),
        })

    def write_foundry_test(self, alert: dict, verdict: dict,
                           source_excerpts: list[dict],
                           chain: str, fork_block: int,
                           contract_address: str = "") -> str:
        """Generate a .t.sol exploit test as a string. Same surface as the
        old foundry_gen.generate_exploit_test but driven by Foundation-Sec."""
        system = ("You are a Foundry exploit-PoC code generator. Given an alert, a "
                  "vulnerability hypothesis, and relevant Solidity source, you emit "
                  "ONE complete .t.sol Foundry test file that ATTEMPTS to reproduce "
                  "the exploit on a local mainnet fork.\n\n"
                  "STRICT RULES:\n"
                  " - Output ONLY Solidity. No prose, no fences.\n"
                  " - Inherits forge-std/Test.sol. Uses vm.createSelectFork.\n"
                  " - Reads RPC URL from env via vm.envString(\"FOUNDRY_RPC_URL\").\n"
                  " - Asserts concrete attacker gain or target loss; no always-pass asserts.\n"
                  " - NO broadcast, NO key import, NO mainnet writes. Local fork only.")
        user = (f"ALERT:\n{json.dumps(alert, indent=2, default=str)}\n\n"
                f"VERDICT:\n{json.dumps(verdict, indent=2, default=str)}\n\n"
                f"CHAIN: {chain}\nFORK_BLOCK: {fork_block}\n"
                f"CONTRACT_ADDRESS: {contract_address}\n\n"
                f"RELEVANT SOLIDITY SOURCE:\n{_fmt_sources(source_excerpts)}\n\n"
                "Write the test file now. Solidity only.")
        return self._generate(user, system=system, max_tokens=3000, temperature=0.3)


# ─── Cisco Time Series (forecasting / anomaly prediction) ──────────────────────
class CiscoTimeSeries:
    _instance = None
    _lock = threading.Lock()

    def __init__(self):
        log.info("Loading Cisco Time Series Model from local snapshot")
        # Load via transformers / safetensors from local snapshot dir
        try:
            from transformers import AutoModel
            self.model = AutoModel.from_pretrained(str(CISCO_TS_DIR), trust_remote_code=True)
            self.ready = True
            log.info("Cisco TS model ready")
        except Exception as e:
            log.warning(f"Cisco TS load failed: {e} — forecasting disabled")
            self.model = None
            self.ready = False

    @classmethod
    def get(cls) -> "CiscoTimeSeries":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def forecast(self, series: list[float], horizon: int = 64) -> dict:
        """Forecast `horizon` steps ahead from a list of historical values.
        Returns {forecast: [...], anomalies: [{idx, observed, expected, deviation}]}"""
        if not self.ready or self.model is None:
            return {"forecast": [], "anomalies": [], "error": "model not loaded"}
        try:
            import torch
            x = torch.tensor(series, dtype=torch.float32).unsqueeze(0)  # [1, T]
            with torch.no_grad():
                # Model's forward signature varies; try common patterns
                if hasattr(self.model, "forecast"):
                    out = self.model.forecast(x, horizon=horizon)
                elif hasattr(self.model, "generate"):
                    out = self.model.generate(x, max_length=horizon)
                else:
                    out = self.model(x)
            fc = out.detach().cpu().numpy().flatten().tolist() if hasattr(out,"detach") else list(out)
            return {"forecast": fc[:horizon], "anomalies": [], "horizon": horizon}
        except Exception as e:
            return {"forecast": [], "anomalies": [], "error": str(e)}


# ─── helpers ────────────────────────────────────────────────────────────────────
def _parse_json_loosely(raw: str, fallback: dict) -> dict:
    """Try hard to find a JSON object in the LLM output."""
    if not raw: return fallback
    s = raw.strip()
    # strip code fences
    if s.startswith("```"):
        parts = s.split("```")
        if len(parts) >= 2:
            s = parts[1]
            if s.startswith("json"): s = s[4:]
    # find first { ... last }
    i, j = s.find("{"), s.rfind("}")
    if i >= 0 and j > i:
        try: return json.loads(s[i:j+1])
        except Exception: pass
    return fallback


def _fmt_sources(excerpts: list[dict]) -> str:
    if not excerpts: return "(none)"
    parts = []
    for e in excerpts[:6]:
        parts.append(f"=== {e.get('rel_path','?')} ===\n"
                     f"contracts: {e.get('contracts')}\n"
                     f"functions: {e.get('functions',[])[:30]}\n\n"
                     f"{(e.get('source_code') or '')[:6000]}\n")
    return "\n".join(parts)
