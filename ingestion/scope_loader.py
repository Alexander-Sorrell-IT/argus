"""
scope_loader.py — Load and resolve in-scope LayerZero contracts from scope.json
"""
import json
import os
import sys
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

SCOPE_FILE = Path(__file__).parent / "scope.json"

CHAIN_ID_MAP = {
    "ethereum": 1,
    "arbitrum": 42161,
    "optimism": 10,
    "polygon": 137,
    "avalanche": 43114,
    "bsc": 56,
    "fantom": 250,
    "base": 8453,
    "solana": None,
    "aptos": None,
    "ton": None,
}

# Etherscan V2 unified endpoint — pass chainid param per chain
ETHERSCAN_V2_BASE = "https://api.etherscan.io/v2/api"

ETHERSCAN_API_MAP = {
    "ethereum":  ETHERSCAN_V2_BASE,
    "arbitrum":  ETHERSCAN_V2_BASE,
    "optimism":  ETHERSCAN_V2_BASE,
    "polygon":   ETHERSCAN_V2_BASE,
    "avalanche": ETHERSCAN_V2_BASE,
    "bsc":       ETHERSCAN_V2_BASE,
    "base":      ETHERSCAN_V2_BASE,
}

def _rpc_map() -> dict:
    """Build Alchemy RPC map lazily so dotenv has time to load first."""
    k = os.getenv("ALCHEMY_API_KEY", "")
    return {
        "ethereum":  f"https://eth-mainnet.g.alchemy.com/v2/{k}",
        "arbitrum":  f"https://arb-mainnet.g.alchemy.com/v2/{k}",
        "optimism":  f"https://opt-mainnet.g.alchemy.com/v2/{k}",
        "polygon":   f"https://polygon-mainnet.g.alchemy.com/v2/{k}",
        "avalanche": f"https://avax-mainnet.g.alchemy.com/v2/{k}",
        "bsc":       f"https://bnb-mainnet.g.alchemy.com/v2/{k}",
        "base":      f"https://base-mainnet.g.alchemy.com/v2/{k}",
    }


@dataclass
class Contract:
    name: str
    address: str
    chain: str
    chain_id: Optional[int] = None
    explorer_api: Optional[str] = None
    rpc_url: Optional[str] = None
    evm: bool = field(init=False)

    def __post_init__(self):
        self.chain_id = CHAIN_ID_MAP.get(self.chain)
        self.explorer_api = ETHERSCAN_API_MAP.get(self.chain)
        self.rpc_url = _rpc_map().get(self.chain)
        self.evm = self.chain in ETHERSCAN_API_MAP


def _scope_data() -> dict:
    """Return the scope.json-shaped dict to load contracts from.

    If PROTOCOL=<name> is set, prefer the human-authored protocols/<name>.yaml
    (via protocols/load_protocol.py) so swapping the YAML re-points the whole
    pipeline. Falls back to the existing ingestion/scope.json path — and the
    yaml/load_protocol imports stay lazy so the default path keeps working
    with no PyYAML dependency.
    """
    protocol = os.getenv("PROTOCOL", "").strip()
    if protocol:
        protocols_dir = Path(__file__).resolve().parent.parent / "protocols"
        if str(protocols_dir) not in sys.path:
            sys.path.insert(0, str(protocols_dir))
        try:
            import load_protocol  # lazy: only when PROTOCOL is set
            return load_protocol.emit_scope(protocol)
        except FileNotFoundError as e:
            # Unknown protocol name — fail loudly rather than silently scanning LZ
            raise SystemExit(f"PROTOCOL={protocol!r} but no config found: {e}")
    return json.loads(SCOPE_FILE.read_text())


def load_scope() -> list[Contract]:
    data = _scope_data()
    contracts = []
    for c in data.get("contracts", []):
        contracts.append(Contract(
            name=c["name"],
            address=c["address"].lower(),
            chain=c.get("chain_hint", "ethereum"),
        ))
    return contracts


def evm_contracts(scope: list[Contract]) -> list[Contract]:
    """Return only EVM contracts that have an Etherscan-compatible explorer."""
    return [c for c in scope if c.evm]
