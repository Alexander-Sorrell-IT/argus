"""audit_xref.py — Splunk-native audit cross-reference.

Given a candidate finding (contract + vulnerability class), query the
layerzero:audit_finding index to decide whether the issue is already
documented in any of the 112 indexed audit chunks.

This used to grep .txt files in Python. Now it's pure SPL over the
indexed audit corpus — properly using Splunk as the data engine.
"""
from __future__ import annotations
import os, re, json, asyncio, logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from mcp.client.sse import sse_client
from mcp import ClientSession

log = logging.getLogger(__name__)

MCP_URL = os.getenv("MCP_SERVER_URL", "http://127.0.0.1:8050").rstrip("/") + "/sse"
INDEX   = "omni_guard_security"

# Map a vulnerability class to the keywords auditors use, AND extra raw
# excerpt-text terms to substring-match. The Splunk query joins both.
VULN_HINTS = {
    "replay_attack":       ["replay", "duplicate message", "nonce reuse"],
    "admin_key_change":    ["transferOwnership", "renounceOwnership",
                            "centralization", "owner privilege"],
    "dvn_bypass":          ["dvn bypass", "verifier bypass", "quorum bypass"],
    "large_drain":         ["drain", "unauthorized withdraw", "asset theft"],
    "fee_manipulation":    ["fee bypass", "underpriced", "gas griefing"],
    "oracle_manipulation": ["oracle manipulation", "stale price"],
    "config_change":       ["setConfig", "configuration change"],
    "high_gas_dos_probe":  ["denial of service", "unbounded loop", "out of gas"],
    "reentrancy":          ["reentrancy", "reentrant"],
    "access_control":      ["access control", "missing modifier"],
    "front_running":       ["front-running", "frontrun", "mev"],
    "logic_error":         ["incorrect logic", "off-by-one"],
    "large_value_transfer": ["value handling", "rounding error"],
    "unknown":             [],
}


@dataclass
class AuditMatch:
    is_known: bool
    confidence: float
    matched_audits: list[str] = field(default_factory=list)
    matched_auditors: list[str] = field(default_factory=list)
    match_count: int = 0
    snippets: list[str] = field(default_factory=list)
    spl_used: str = ""
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "is_known":          self.is_known,
            "confidence":        self.confidence,
            "matched_audits":    self.matched_audits,
            "matched_auditors":  self.matched_auditors,
            "match_count":       self.match_count,
            "snippet_count":     len(self.snippets),
            "reason":            self.reason,
        }


def _strip_paren(name: str) -> str:
    return re.sub(r"\s*\(.*?\)\s*", "", name or "").strip()


def _normalize_contract_name(name: str) -> list[str]:
    """Return search terms to try. Strips parentheticals, splits camelCase a bit."""
    base = _strip_paren(name)
    out = {base}
    # Add a few well-known synonyms
    if "UltraLightNodeV2" in base:
        out.update(["UltraLightNodeV2", "ULNv2", "UltraLightNode"])
    if "EndpointV2" in base:
        out.update(["EndpointV2", "Endpoint V2"])
    if "EndpointV1" in base or base == "Endpoint":
        out.update(["EndpointV1", "Endpoint"])
    if "OFT" in base:
        out.update(["OFT"])
    return [t for t in out if t and len(t) >= 3]


class AuditCrossReference:
    """SPL-backed audit cross-reference. Replaces filesystem grep.

    Public surface is unchanged so the rest of the agent doesn't have to
    care about the rewrite — only the implementation moved into Splunk.
    """

    def __init__(self, mcp_url: str = MCP_URL):
        self.sse_url = mcp_url

    # ── async core ─────────────────────────────────────────────────────
    async def _asearch(self, spl: str, earliest: str = "-365d") -> list[dict]:
        async with sse_client(self.sse_url) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                r = await session.call_tool("search_oneshot", {
                    "query": spl,
                    "earliest_time": earliest,
                    "latest_time": "now",
                    "max_count": 25,
                    "output_format": "json",
                })
                payload = json.loads(r.content[0].text)
                return payload.get("events", [])

    # ── public sync surface ───────────────────────────────────────────
    def lookup(
        self,
        contract_name: str = "",
        vulnerability_class: str = "unknown",
        keywords: Iterable[str] | None = None,
        min_audit_matches: int = 1,
    ) -> AuditMatch:
        contract_terms = _normalize_contract_name(contract_name)
        vuln_terms = list(keywords or []) + VULN_HINTS.get(vulnerability_class, [])
        vuln_terms = [t for t in vuln_terms if t]

        if not contract_terms and not vuln_terms:
            return AuditMatch(is_known=False, confidence=0.0,
                              reason="no search terms")

        # Build SPL that matches if EITHER a structured `contracts` array entry
        # OR a raw-text mention of any contract term is present, AND a vuln
        # hint is present (either structured or text).
        contract_or_clause = " OR ".join(f'"{t}"' for t in contract_terms) if contract_terms else ""
        vuln_or_clause     = " OR ".join(f'"{t}"' for t in vuln_terms) if vuln_terms else ""

        if vulnerability_class and vulnerability_class != "unknown":
            structured_vuln = f'OR vuln_classes{{}}="{vulnerability_class}"'
        else:
            structured_vuln = ""

        spl = (
            f'index={INDEX} sourcetype=layerzero:audit_finding '
            + (f'({contract_or_clause}) ' if contract_or_clause else '')
            + (f'AND ({vuln_or_clause} {structured_vuln}) ' if vuln_or_clause or structured_vuln else '')
            + '| stats count, values(file_name) as files, values(auditor) as auditors, '
            'values(excerpt) as excerpts'
        )

        try:
            rows = asyncio.run(self._asearch(spl))
        except Exception as e:
            log.warning(f"audit_xref MCP query failed: {e}")
            return AuditMatch(is_known=False, confidence=0.0,
                              reason=f"query error: {e}", spl_used=spl)

        if not rows:
            return AuditMatch(is_known=False, confidence=0.0,
                              reason="no audit chunks matched", spl_used=spl)

        row = rows[0]
        count = int(row.get("count", 0) or 0)
        files = _to_list(row.get("files"))
        auditors = _to_list(row.get("auditors"))
        excerpts = _to_list(row.get("excerpts"))[:5]

        is_known = count >= min_audit_matches
        # Confidence scales with corroborating auditors (more auditors found
        # the same kind of issue → more confidently "known").
        confidence = min(1.0, 0.5 + 0.1 * min(len(auditors), 5))

        return AuditMatch(
            is_known=is_known,
            confidence=round(confidence, 2) if is_known else 0.1,
            matched_audits=files[:5],
            matched_auditors=auditors,
            match_count=count,
            snippets=[(e[:300] if isinstance(e,str) else str(e)[:300]) for e in excerpts],
            spl_used=spl,
            reason=(f"{count} audit chunk(s) matched across {len(auditors)} auditor(s)"
                    if is_known else f"{count} chunks matched (need {min_audit_matches})"),
        )


def _to_list(v) -> list:
    if v is None: return []
    if isinstance(v, list): return v
    return [v]


# ── smoke test ────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    x = AuditCrossReference()
    print("Splunk-native audit cross-reference (queries layerzero:audit_finding)\n")
    cases = [
        ("UltraLightNodeV2", "replay_attack"),
        ("EndpointV2",       "admin_key_change"),
        ("DVN",              "dvn_bypass"),
        ("OFT",              "reentrancy"),
        ("RandomContractThatDoesNotExist", "unknown"),
    ]
    for name, cls in cases:
        m = x.lookup(name, cls)
        print(f"[{name}] vuln_class={cls}")
        print(f"  is_known={m.is_known} confidence={m.confidence}")
        print(f"  {m.reason}")
        if m.matched_auditors:
            print(f"  auditors: {m.matched_auditors}")
        if m.matched_audits:
            print(f"  files:    {m.matched_audits[:3]}")
        print()
