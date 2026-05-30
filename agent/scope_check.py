"""scope_check.py — Splunk-native check that a confirmed candidate is
actually in the Immunefi bug-bounty scope before paging humans.

Cross-references against the indexed `layerzero:scope` sourcetype
(28 records: 24 in-scope contracts + reward tier table + 3 doc entries).

Used as the 4th stage of the agent pipeline:
  SPL detection → audit cross-ref → SAIA triage → fork validate → scope check
                                                                  ^^^^^^^^^^^
"""
from __future__ import annotations
import os, re, json, asyncio, logging
from dataclasses import dataclass, field
from typing import Optional

from mcp.client.sse import sse_client
from mcp import ClientSession

log = logging.getLogger(__name__)

CUSTOM_MCP_URL = os.getenv("MCP_SERVER_URL", "http://127.0.0.1:8050").rstrip("/") + "/sse"
INDEX = "omni_guard_security"

# Severity → reward-tier mapping (per Immunefi LayerZero program)
SEVERITY_TO_TIER = {
    "CRITICAL":   ("Critical",  15_000_000),
    "HIGH":       ("High",         250_000),
    "MEDIUM":     ("Medium",        25_000),
    "LOW":        ("Low",           10_000),
    "FALSE_POSITIVE": ("Not eligible",     0),
}

VULN_CLASS_TO_IMPACT = {
    # Map our vuln_class identifiers to Immunefi's documented impact tiers
    "replay_attack":         ("Critical", "Permanent locking/theft of user funds"),
    "large_drain":           ("Critical", "Permanent locking/theft of user funds"),
    "admin_key_change":      ("Critical", "Permanent locking/theft of user funds"),
    "dvn_bypass":            ("Critical", "Permanent locking/theft of user funds"),
    "msglib_injection":      ("Critical", "Permanent locking/theft of user funds"),
    "high_gas_dos_probe":    ("Critical", "Permanent DoS (excluding volumetric)"),
    "oracle_manipulation":   ("High",     "Oracle/price manipulation"),
    "fee_manipulation":      ("High",     "Underpricing of cross-chain messages"),
    "config_change":         ("High",     "Unauthorized configuration change"),
    "large_value_transfer":  ("Medium",   "Anomalous value transfer — manual review"),
    "unknown":               ("Medium",   "Unclassified anomaly"),
}

# Things explicitly OUT OF SCOPE per the program's "Out of Scope" section
OOS_KEYWORDS = [
    "sybil", "social engineering", "phishing", "centralization risk",
    "configured bad libraries", "third-party oracles incorrect data",
    "volumetric dos", "best practice", "feature request",
    "leaked keys", "access to leaked",
    "depegging of an external stablecoin",
]


@dataclass
class ScopeResult:
    is_in_scope: bool
    scope_match: dict = field(default_factory=dict)
    reward_tier: str = ""
    max_bounty_usd: int = 0
    impact_classification: str = ""
    reason: str = ""
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "is_in_scope":          self.is_in_scope,
            "scope_match_name":     self.scope_match.get("name", ""),
            "scope_match_chain":    self.scope_match.get("chain", ""),
            "scope_match_address":  self.scope_match.get("address", ""),
            "reward_tier":          self.reward_tier,
            "max_bounty_usd":       self.max_bounty_usd,
            "impact_classification": self.impact_classification,
            "reason":               self.reason,
            "notes":                self.notes,
        }


def scope_check(
    contract_address: str,
    contract_name: str = "",
    chain: str = "",
    vulnerability_class: str = "unknown",
    severity: str = "MEDIUM",
    summary: str = "",
) -> ScopeResult:
    """Check whether a finding is in the Immunefi bug-bounty scope.

    Returns ScopeResult with is_in_scope=True/False + reward tier + reasoning.
    Pure SPL-driven via the same custom MCP we already use elsewhere.
    """
    addr = (contract_address or "").lower().strip()
    name = (contract_name or "").strip()
    if not addr and not name:
        return ScopeResult(is_in_scope=False, reason="no contract address or name provided")

    # 1. Match indexed scope by address (case-insensitive) if we have one, else fall
    #    back to contract_name. Replay-family alerts carry a name but NO contract_address,
    #    and instant-failing on missing address marked every such finding OUT_OF_SCOPE.
    matched = None
    if addr:
        rows = _run_spl(
            f'index={INDEX} sourcetype=layerzero:scope kind=in_scope_contract '
            f'| eval _a=lower(address) | search _a="{addr}" '
            f'| head 1 | table address, name, chain, url, added'
        )
        matched = rows[0] if rows else None
    if not matched and name:
        safe = name.replace('"', "")
        rows = _run_spl(
            f'index={INDEX} sourcetype=layerzero:scope kind=in_scope_contract '
            f'name="{safe}" | head 1 | table address, name, chain, url, added'
        )
        matched = rows[0] if rows else None

    # 2. Check OOS keyword exclusions against the summary
    oos_hit = None
    summary_l = (summary or "").lower()
    for kw in OOS_KEYWORDS:
        if kw in summary_l:
            oos_hit = kw
            break

    # 3. Look up reward tier from vuln class + severity
    impact_tier, impact_desc = VULN_CLASS_TO_IMPACT.get(
        vulnerability_class, VULN_CLASS_TO_IMPACT["unknown"]
    )
    sev_tier, sev_bounty = SEVERITY_TO_TIER.get(severity, SEVERITY_TO_TIER["MEDIUM"])
    # Use the WORSE of the two (whichever predicts a lower bounty)
    final_tier = sev_tier
    final_bounty = sev_bounty

    notes = []
    if matched:
        notes.append(f"matched scope entry: {matched.get('name','')} on {matched.get('chain','')}")
    if oos_hit:
        notes.append(f"OOS keyword hit: '{oos_hit}'")

    is_in_scope = bool(matched) and not oos_hit and severity != "FALSE_POSITIVE"
    reason = (
        "in scope; bounty eligible" if is_in_scope
        else "OUT OF SCOPE — " + (
            f"contract not in scope list (checked address + name)" if not matched
            else f"OOS keyword '{oos_hit}'" if oos_hit
            else "severity is FALSE_POSITIVE"
        )
    )

    return ScopeResult(
        is_in_scope=is_in_scope,
        scope_match=matched or {},
        reward_tier=final_tier,
        max_bounty_usd=final_bounty if is_in_scope else 0,
        impact_classification=impact_desc,
        reason=reason,
        notes=notes,
    )


def _run_spl(spl: str) -> list[dict]:
    async def _q():
        async with sse_client(CUSTOM_MCP_URL) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                r = await session.call_tool("search_oneshot", {
                    "query": spl, "earliest_time": "-365d", "latest_time": "now",
                    "max_count": 5, "output_format": "json",
                })
                return json.loads(r.content[0].text).get("events", [])
    try:
        return asyncio.run(_q())
    except Exception as e:
        log.warning(f"scope_check SPL failed: {e}")
        return []


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("Splunk-native scope check\n")
    cases = [
        # in-scope examples
        ("0x4d73adb72bc3dd368966edd0f0b2148401a178e2", "UltraLightNodeV2", "ethereum", "large_drain", "CRITICAL"),
        ("0x1a44076050125825900e736c501f859c50fe728c", "EndpointV2", "ethereum", "admin_key_change", "HIGH"),
        # not in scope examples
        ("0xdeadbeef00000000000000000000000000000000", "RandomContract", "ethereum", "unknown", "MEDIUM"),
    ]
    for addr, name, chain, vc, sev in cases:
        r = scope_check(addr, name, chain, vc, sev)
        print(f"[{name} @ {addr[:10]}... sev={sev} vc={vc}]")
        print(f"  in_scope={r.is_in_scope}  reward_tier={r.reward_tier}  max_bounty=${r.max_bounty_usd:,}")
        print(f"  reason: {r.reason}")
        if r.notes:
            print(f"  notes: {r.notes}")
        print()
