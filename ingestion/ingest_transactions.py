"""
ingest_transactions.py — Fetch LayerZero in-scope contract transactions via Etherscan
and stream them to Splunk HEC for AI-powered anomaly detection.

Run:  python ingest_transactions.py [--once]
"""
import os
import time
import logging
import argparse
import requests
from dotenv import load_dotenv
from scope_loader import load_scope, evm_contracts
from splunk_hec import SplunkHEC

load_dotenv()
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s  %(levelname)-8s  %(message)s",
)
log = logging.getLogger(__name__)

ETHERSCAN_KEY = os.getenv("ETHERSCAN_API_KEY", "")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL_SECONDS", "60"))
LOOKBACK_BLOCKS = int(os.getenv("LOOKBACK_BLOCKS", "1000"))

# Track last processed block per contract to avoid re-ingesting
_last_block: dict[str, int] = {}


def fetch_transactions(contract_addr: str, explorer_api: str,
                       chain_id: int = 1, start_block: int = 0) -> list[dict]:
    """Fetch normal + internal txns from Etherscan V2."""
    txns = []
    for action in ("txlist", "txlistinternal"):
        params = {
            "chainid": chain_id,
            "module": "account",
            "action": action,
            "address": contract_addr,
            "startblock": start_block,
            "endblock": 99999999,
            "sort": "asc",
            "apikey": ETHERSCAN_KEY,
        }
        try:
            resp = requests.get(explorer_api, params=params, timeout=15)
            data = resp.json()
            if data.get("status") == "1" and data.get("result"):
                for tx in data["result"]:
                    tx["_tx_type"] = action
                    txns.append(tx)
        except Exception as e:
            log.warning(f"Failed fetching {action} for {contract_addr}: {e}")
    return txns


def fetch_events(contract_addr: str, explorer_api: str,
                 chain_id: int = 1, start_block: int = 0) -> list[dict]:
    """Fetch contract event logs via Etherscan V2 getLogs."""
    params = {
        "chainid": chain_id,
        "module": "logs",
        "action": "getLogs",
        "address": contract_addr,
        "fromBlock": start_block,
        "toBlock": "latest",
        "apikey": ETHERSCAN_KEY,
    }
    try:
        resp = requests.get(explorer_api, params=params, timeout=15)
        data = resp.json()
        if data.get("status") == "1" and data.get("result"):
            return data["result"]
    except Exception as e:
        log.warning(f"Failed fetching events for {contract_addr}: {e}")
    return []


def enrich_transaction(tx: dict, contract_name: str, chain: str) -> dict:
    """Normalize and enrich a raw Etherscan transaction for Splunk."""
    value_eth = int(tx.get("value", "0")) / 1e18
    gas_used = int(tx.get("gasUsed", "0"))
    block_number = int(tx.get("blockNumber", "0"))
    ts = int(tx.get("timeStamp", "0"))

    return {
        "timestamp": ts,
        "block_number": block_number,
        "chain": chain,
        "contract_name": contract_name,
        "contract_address": tx.get("to", "").lower(),
        "tx_hash": tx.get("hash", ""),
        "from_address": tx.get("from", "").lower(),
        "to_address": tx.get("to", "").lower(),
        "value_eth": value_eth,
        "value_usd_est": value_eth * 2400,  # rough ETH price
        "gas_used": gas_used,
        "is_error": tx.get("isError", "0") == "1",
        "method_id": tx.get("input", "0x")[:10] if tx.get("input") else "0x",
        "tx_type": tx.get("_tx_type", "txlist"),
        # Anomaly signals
        "large_value": value_eth > 10,
        "high_gas": gas_used > 500_000,
        "failed_tx": tx.get("isError", "0") == "1",
    }


def enrich_event(event: dict, contract_name: str, chain: str) -> dict:
    """Normalize a raw Etherscan event log for Splunk."""
    return {
        "timestamp": int(event.get("timeStamp", "0"), 16)
        if event.get("timeStamp", "").startswith("0x")
        else int(event.get("timeStamp", "0")),
        "block_number": int(event.get("blockNumber", "0"), 16),
        "chain": chain,
        "contract_name": contract_name,
        "contract_address": event.get("address", "").lower(),
        "tx_hash": event.get("transactionHash", ""),
        "topic0": event.get("topics", [""])[0],
        "topic1": event.get("topics", [None, None])[1] if len(event.get("topics", [])) > 1 else None,
        "topic2": event.get("topics", [None, None, None])[2] if len(event.get("topics", [])) > 2 else None,
        "data": event.get("data", ""),
        "log_index": event.get("logIndex", ""),
        "event_type": "contract_event",
    }


def ingest_once(hec: SplunkHEC):
    scope = evm_contracts(load_scope())
    log.info(f"Ingesting {len(scope)} EVM contracts")
    total_tx = 0
    total_ev = 0

    for contract in scope:
        start_block = _last_block.get(contract.address, 0)
        if start_block == 0:
            # Use Alchemy RPC for reliable block tip (faster than Etherscan)
            try:
                rpc = contract.rpc_url or ""
                if rpc:
                    tip_resp = requests.post(rpc, json={
                        "jsonrpc": "2.0", "method": "eth_blockNumber",
                        "params": [], "id": 1
                    }, timeout=10).json()
                    tip = int(tip_resp["result"], 16)
                else:
                    tip_resp = requests.get(
                        contract.explorer_api,
                        params={"chainid": contract.chain_id, "module": "proxy",
                                "action": "eth_blockNumber", "apikey": ETHERSCAN_KEY},
                        timeout=10
                    ).json()
                    tip = int(tip_resp.get("result", "0x0"), 16)
                start_block = max(0, tip - LOOKBACK_BLOCKS)
            except Exception:
                start_block = 0

        log.info(f"  {contract.name} ({contract.chain}) from block {start_block}")

        # Transactions
        txns = fetch_transactions(contract.address, contract.explorer_api,
                                  chain_id=contract.chain_id or 1,
                                  start_block=start_block)
        for tx in txns:
            enriched = enrich_transaction(tx, contract.name, contract.chain)
            hec.send(enriched, sourcetype="layerzero:transaction")
            max_block = max(_last_block.get(contract.address, 0),
                            enriched["block_number"] + 1)
            _last_block[contract.address] = max_block
        total_tx += len(txns)

        # Events
        events = fetch_events(contract.address, contract.explorer_api,
                              chain_id=contract.chain_id or 1,
                              start_block=start_block)
        for ev in events:
            enriched = enrich_event(ev, contract.name, contract.chain)
            hec.send(enriched, sourcetype="layerzero:event")
        total_ev += len(events)

        time.sleep(0.25)  # respect Etherscan 5 calls/sec free tier

    hec.flush()
    log.info(f"Ingestion complete: {total_tx} transactions, {total_ev} events")


def main():
    parser = argparse.ArgumentParser(description="OmniGuard LayerZero ingestion")
    parser.add_argument("--once", action="store_true",
                        help="Run once then exit (default: continuous poll)")
    args = parser.parse_args()

    with SplunkHEC() as hec:
        if args.once:
            ingest_once(hec)
        else:
            log.info(f"Starting continuous ingestion (poll every {POLL_INTERVAL}s)")
            while True:
                ingest_once(hec)
                log.info(f"Sleeping {POLL_INTERVAL}s...")
                time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
