"""ingest_immunefi.py — load the LayerZero Immunefi bug-bounty program
documents into Splunk as sourcetype layerzero:scope.

Indexes 3 files from ~/Desktop/rhis/:
  - LayerZero-Assets in Scope.txt    (25 contracts, impact tiers, OOS list)
  - LayerZero-Information.txt        (reward amounts, PoC requirements)
  - LayerZero-Resources.txt          (docs links)

Also emits parsed-out per-contract records so the agent can filter findings
by in-scope status with a simple SPL lookup.
"""
import os, re, time, logging
from pathlib import Path
from dotenv import load_dotenv
from splunk_hec import SplunkHEC

load_dotenv()
logging.basicConfig(level=os.getenv("LOG_LEVEL","INFO"),
                    format="%(asctime)s  %(levelname)-8s  %(message)s")
log = logging.getLogger(__name__)

RHIS = Path.home() / "Desktop/rhis"
FILES = {
    "scope":     RHIS / "LayerZero-Assets in Scope.txt",
    "info":      RHIS / "LayerZero-Information.txt",
    "resources": RHIS / "LayerZero-Resources.txt",
}

# Parse each scope-doc line for contract metadata
SCOPE_LINE_RE = re.compile(
    r"(?:Target\s*-?\s*)?(?P<url>https?://\S+?)(?:[?&]utm_source=immunefi)?#?\S*\s+"
    r"Name\s*-\s*(?P<name>[^A]+?)\s+Added\s+On\s*-?\s*(?P<date>.+?)$",
    re.MULTILINE | re.IGNORECASE,
)
ADDR_RE  = re.compile(r"0x[a-fA-F0-9]{40}")
SOLANA_ADDR_RE = re.compile(r"/address/([1-9A-HJ-NP-Za-km-z]{32,44})")
TON_ADDR_RE = re.compile(r"/(0:[a-fA-F0-9]{64})")
APTOS_ADDR_RE = re.compile(r"/account/(0x[a-fA-F0-9]{64})")

def chain_for_url(url: str) -> str:
    u = url.lower()
    if "etherscan.io" in u:     return "ethereum"
    if "arbiscan" in u:          return "arbitrum"
    if "polygonscan" in u:       return "polygon"
    if "optimistic.etherscan" in u: return "optimism"
    if "snowtrace" in u or "avascan" in u: return "avalanche"
    if "explorer.solana.com" in u or "solana" in u: return "solana"
    if "aptoscan" in u or "aptos" in u: return "aptos"
    if "tonviewer" in u or "tonscan" in u: return "ton"
    if "github.com" in u:        return "github"
    return "unknown"

def extract_address(url: str) -> str:
    for rx in (ADDR_RE, APTOS_ADDR_RE, TON_ADDR_RE, SOLANA_ADDR_RE):
        m = rx.search(url)
        if m:
            return m.group(1) if m.lastindex else m.group(0)
    return ""

def parse_scope_contracts(text: str) -> list[dict]:
    """Find every 'Target ... Name ... Added On ...' tuple in the doc."""
    out = []
    # The scope doc isn't perfectly line-broken; use a permissive line walk.
    for line in text.splitlines():
        # Each row mentions both a Target URL and a Name
        if "Target" in line and "Name" in line:
            url_m = re.search(r"https?://\S+", line)
            name_m = re.search(r"Name\s*-?\s*([^A]+?)(?:\s+Added|$)", line)
            date_m = re.search(r"Added\s+On\s*-?\s*(.+?)\s*$", line)
            if not url_m:
                continue
            url = url_m.group(0).rstrip(".,;:")
            name = name_m.group(1).strip() if name_m else ""
            date = date_m.group(1).strip() if date_m else ""
            out.append({
                "url":     url,
                "address": extract_address(url),
                "chain":   chain_for_url(url),
                "name":    name,
                "added":   date,
            })
    return out

def parse_rewards(text: str) -> dict:
    """Pull the reward-tier amounts out of the Information.txt."""
    tiers = {}
    cur = None
    for line in text.splitlines():
        line = line.strip()
        if line in ("Critical","High","Medium","Low"):
            cur = line.lower()
        elif line.startswith("Up to:") and cur:
            amt = line.replace("Up to:","").strip()
            tiers[cur] = amt
    return tiers

def main():
    now = int(time.time())
    with SplunkHEC() as hec:
        # 1) Full-text record per file
        for kind, path in FILES.items():
            if not path.exists():
                log.warning(f"missing {path}")
                continue
            txt = path.read_text(encoding="utf-8", errors="ignore")
            hec.send({
                "timestamp":   now,
                "kind":        kind,
                "source_file": str(path),
                "byte_size":   len(txt),
                "content":     txt[:80_000],
                "program":     "Immunefi LayerZero",
            }, sourcetype="layerzero:scope")
            log.info(f"  indexed {kind} ({len(txt)} bytes)")

        # 2) Parsed per-contract records (for fast in-scope checks)
        scope_txt = FILES["scope"].read_text(encoding="utf-8", errors="ignore")
        contracts = parse_scope_contracts(scope_txt)
        for c in contracts:
            hec.send({
                "timestamp": now,
                "kind":      "in_scope_contract",
                "program":   "Immunefi LayerZero",
                **c,
            }, sourcetype="layerzero:scope")
        log.info(f"  indexed {len(contracts)} in-scope contracts")

        # 3) Reward tiers
        info_txt = FILES["info"].read_text(encoding="utf-8", errors="ignore")
        tiers = parse_rewards(info_txt)
        if tiers:
            hec.send({
                "timestamp": now,
                "kind":      "reward_tiers",
                "program":   "Immunefi LayerZero",
                "tiers":     tiers,
                "max_critical_usd": 15_000_000,
            }, sourcetype="layerzero:scope")
            log.info(f"  indexed reward tiers: {tiers}")
        hec.flush()

if __name__ == "__main__":
    main()
