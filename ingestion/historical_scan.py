"""
historical_scan.py — Full history scan for all LayerZero in-scope contracts.

Fetches ALL transactions and events from deployment block to latest,
in paginated 10k-block chunks. Saves progress to STATE_FILE so it
can be interrupted and resumed safely.

Usage:
    python historical_scan.py                  # scan everything
    python historical_scan.py --chain ethereum # one chain only
    python historical_scan.py --days 180       # limit to last N days
    python historical_scan.py --reset          # clear state, restart
"""
import os
import sys
import json
import time
import logging
import argparse
import requests
from pathlib import Path
from dotenv import load_dotenv
from scope_loader import load_scope, evm_contracts
from splunk_hec import SplunkHEC

load_dotenv()
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s  %(levelname)-8s  %(message)s",
)
log = logging.getLogger(__name__)

ETHERSCAN_KEY    = os.getenv("ETHERSCAN_API_KEY", "")
CHUNK_SIZE       = int(os.getenv("HIST_CHUNK_SIZE", "10000"))
RATE_DELAY       = float(os.getenv("HIST_RATE_DELAY", "0.22"))   # ~4.5 calls/sec
STATE_FILE       = Path(os.getenv("HIST_STATE_FILE",
                        os.path.expanduser("~/.omni-guard-scan-state.json")))
MAX_PAGE_RESULTS = 10_000   # Etherscan txlist/account hard cap per page
GETLOGS_CAP      = 1_000    # Etherscan getLogs hard cap per page (must paginate)

# Native-asset USD price per chain — value_usd_est reflects NATIVE value only
# (ETH/MATIC/AVAX/BNB), NOT ERC-20 token amounts. None => emit no USD estimate.
NATIVE_PRICE = {"ethereum": 2400, "arbitrum": 2400, "optimism": 2400, "base": 2400,
                "polygon": 0.5, "avalanche": 35, "bnb": 600, "bsc": 600}

# Approximate blocks/day per chain for the --days start-block estimate. Arbitrum
# produces ~330k blocks/day; a flat 43200 under-counted L2 windows ~6-8x.
BLOCKS_PER_DAY = {"ethereum": 7200, "arbitrum": 330000, "optimism": 43200,
                  "polygon": 43200, "avalanche": 43200, "base": 43200,
                  "bnb": 28800, "bsc": 28800, "fantom": 86400}


def _load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {}


def _save_state(state: dict):
    STATE_FILE.write_text(json.dumps(state, indent=2))


def _get_current_block(contract) -> int:
    """Use Alchemy RPC for fast block tip; fall back to Etherscan V2."""
    if contract.rpc_url:
        try:
            r = requests.post(contract.rpc_url, json={
                "jsonrpc": "2.0", "method": "eth_blockNumber",
                "params": [], "id": 1
            }, timeout=10).json()
            return int(r["result"], 16)
        except Exception as e:
            log.warning(f"Alchemy block fetch failed ({contract.chain}): {e}")
    # Etherscan V2 fallback
    try:
        r = requests.get(contract.explorer_api, params={
            "chainid": contract.chain_id,
            "module": "proxy", "action": "eth_blockNumber",
            "apikey": ETHERSCAN_KEY,
        }, timeout=10).json()
        return int(r.get("result", "0x0"), 16)
    except Exception as e:
        log.warning(f"Could not fetch current block: {e}")
        return 0


def _get_deployment_block(address: str, explorer_api: str, chain_id: int) -> int:
    """Get the block the contract was first seen in (Etherscan V2)."""
    try:
        r = requests.get(explorer_api, params={
            "chainid": chain_id,
            "module": "account", "action": "txlist",
            "address": address,
            "startblock": 0, "endblock": 99999999,
            "page": 1, "offset": 1, "sort": "asc",
            "apikey": ETHERSCAN_KEY,
        }, timeout=15).json()
        if r.get("status") == "1" and r.get("result"):
            return max(0, int(r["result"][0].get("blockNumber", 0)) - 1)
    except Exception as e:
        log.warning(f"Deployment block lookup failed for {address}: {e}")
    return 0


def _fetch_page(explorer_api: str, address: str, action: str,
                start_block: int, end_block: int, chain_id: int = 1) -> list[dict]:
    """Fetch one page of txns or events for a block range (Etherscan V2)."""
    if action == "getLogs":
        params = {
            "chainid": chain_id,
            "module": "logs", "action": "getLogs",
            "address": address,
            "fromBlock": start_block, "toBlock": end_block,
            "apikey": ETHERSCAN_KEY,
        }
    else:
        params = {
            "chainid": chain_id,
            "module": "account", "action": action,
            "address": address,
            "startblock": start_block, "endblock": end_block,
            "sort": "asc",
            "apikey": ETHERSCAN_KEY,
        }
    try:
        r = requests.get(explorer_api, params=params, timeout=20).json()
        if r.get("status") == "1" and r.get("result"):
            return r["result"]
    except Exception as e:
        log.warning(f"  API error ({action} {start_block}-{end_block}): {e}")
    return []


def _enrich_tx(tx: dict, name: str, address: str, chain: str, tx_type: str) -> dict:
    value_eth = int(tx.get("value", "0")) / 1e18
    gas_used  = int(tx.get("gasUsed", "0"))
    ts_raw    = tx.get("timeStamp", "0")
    ts = int(ts_raw, 16) if str(ts_raw).startswith("0x") else int(ts_raw or 0)
    native_price = NATIVE_PRICE.get(chain)
    return {
        "timestamp": ts,
        "block_number": int(tx.get("blockNumber", "0")),
        "chain": chain,
        "contract_name": name,
        # monitored contract's own address, NOT tx.to (the counterparty). See #21.
        "contract_address": (address or "").lower(),
        "tx_hash": tx.get("hash", ""),
        "from_address": tx.get("from", "").lower(),
        "to_address": (tx.get("to") or "").lower(),
        "value_eth": value_eth,
        "value_usd_est": round(value_eth * native_price, 2) if native_price else None,
        "gas_used": gas_used,
        "is_error": tx.get("isError", "0") == "1",
        "method_id": (tx.get("input") or "0x")[:10],
        "tx_type": tx_type,
        "large_value": value_eth > 10,
        "high_gas": gas_used > 500_000,
        "failed_tx": tx.get("isError", "0") == "1",
        "historical": True,
    }


def _enrich_event(ev: dict, name: str, chain: str) -> dict:
    ts_raw = ev.get("timeStamp", "0")
    ts = int(ts_raw, 16) if str(ts_raw).startswith("0x") else int(ts_raw or 0)
    topics = ev.get("topics", [])
    return {
        "timestamp": ts,
        "block_number": int(ev.get("blockNumber", "0"), 16)
                        if str(ev.get("blockNumber","0")).startswith("0x")
                        else int(ev.get("blockNumber", "0")),
        "chain": chain,
        "contract_name": name,
        "contract_address": ev.get("address", "").lower(),
        "tx_hash": ev.get("transactionHash", ""),
        "topic0": topics[0] if topics else None,
        "topic1": topics[1] if len(topics) > 1 else None,
        "topic2": topics[2] if len(topics) > 2 else None,
        "data": ev.get("data", "")[:512],   # cap raw data
        "log_index": ev.get("logIndex", ""),
        "event_type": "contract_event",
        "historical": True,
    }


def _fetch_logs_paged(api, address, start_block, end_block, chain_id) -> list:
    """Paginate getLogs by block. Etherscan caps getLogs at 1000 records/page, so
    a single 10k-block window with >1000 logs was silently truncated. Re-issue
    advancing fromBlock past the last returned log's block until a page is short."""
    def _bn(p):
        b = p.get("blockNumber", "0")
        return int(b, 16) if str(b).startswith("0x") else int(b or 0)
    out, frm, guard = [], start_block, 0
    while frm <= end_block and guard < 10000:
        guard += 1
        page = _fetch_page(api, address, "getLogs", frm, end_block, chain_id)
        time.sleep(RATE_DELAY)
        if not page:
            break
        out.extend(page)
        if len(page) < GETLOGS_CAP:
            break
        last_bn = max(_bn(p) for p in page)
        if last_bn <= frm:
            log.warning(f"  >{GETLOGS_CAP} logs in block {frm} for {address} — "
                        f"rest of that block may be truncated")
            frm = frm + 1
        else:
            frm = last_bn + 1
    return out


def scan_contract(contract, hec: SplunkHEC, state: dict,
                  start_block_override: int = None) -> int:
    """
    Scan one contract's full history. Returns total events sent.
    Uses adaptive chunking: txlist/account pages halve on the 10k cap; getLogs
    is paginated by block (1000-record cap) via _fetch_logs_paged.
    """
    key   = f"{contract.chain}:{contract.address}"
    saved = state.get(key, {})
    chain_id = contract.chain_id or 1

    if start_block_override is not None:
        start = start_block_override
    elif saved.get("completed"):
        log.info(f"  [{contract.chain}] {contract.name} — already complete, skipping")
        return 0
    elif saved.get("last_block"):
        start = saved["last_block"] + 1   # +1: last_block was fully fetched (no 1-block overlap)
        log.info(f"  [{contract.chain}] {contract.name} — resuming from block {start}")
    else:
        deploy = _get_deployment_block(contract.address, contract.explorer_api, chain_id)
        start  = deploy
        log.info(f"  [{contract.chain}] {contract.name} — deployment block {deploy}")
        time.sleep(RATE_DELAY)

    current = _get_current_block(contract)
    time.sleep(RATE_DELAY)
    if current == 0:
        log.warning(f"  Could not get current block for {contract.chain}, skipping")
        return 0

    total = 0
    chunk_start = start

    while chunk_start < current:
        chunk_end = min(chunk_start + CHUNK_SIZE, current)

        for action in ("txlist", "txlistinternal", "getLogs"):
            if action == "getLogs":
                # getLogs caps at 1000/page — paginate by block instead of relying
                # on the (unreachable) 10k halving guard, which truncated event logs.
                results = _fetch_logs_paged(contract.explorer_api, contract.address,
                                            chunk_start, chunk_end, chain_id)
            else:
                results = _fetch_page(contract.explorer_api, contract.address,
                                      action, chunk_start, chunk_end, chain_id)
                time.sleep(RATE_DELAY)
                # If we hit the account-page cap, halve the range and retry.
                if len(results) >= MAX_PAGE_RESULTS:
                    log.debug(f"  Hit page cap at {chunk_start}-{chunk_end}, halving range")
                    mid = (chunk_start + chunk_end) // 2
                    results = _fetch_page(contract.explorer_api, contract.address,
                                          action, chunk_start, mid, chain_id)
                    chunk_end = mid
                    time.sleep(RATE_DELAY)

            for item in results:
                if action == "getLogs":
                    enriched = _enrich_event(item, contract.name, contract.chain)
                    hec.send(enriched, sourcetype="layerzero:event")
                else:
                    item["_tx_type"] = action
                    enriched = _enrich_tx(item, contract.name, contract.address, contract.chain, action)
                    hec.send(enriched, sourcetype="layerzero:transaction")
                total += 1

        # Checkpoint after each chunk
        state[key] = {"last_block": chunk_end, "chain": contract.chain}
        _save_state(state)

        if total % 1000 == 0 and total > 0:
            log.info(f"    ...{total} events so far (block {chunk_end}/{current})")

        chunk_start = chunk_end + 1

    hec.flush()
    state[key] = {"last_block": current, "completed": True, "chain": contract.chain}
    _save_state(state)
    log.info(f"  [{contract.chain}] {contract.name} — done, {total} events")
    return total


def main():
    parser = argparse.ArgumentParser(description="OmniGuard full historical scan")
    parser.add_argument("--chain",  help="Scan only this chain (ethereum/avalanche/...)")
    parser.add_argument("--days",   type=int, help="Limit to last N days of history")
    parser.add_argument("--reset",  action="store_true", help="Clear state and restart")
    args = parser.parse_args()

    state = {}
    if not args.reset:
        state = _load_state()
    else:
        log.info("Resetting scan state")
        _save_state({})

    scope = evm_contracts(load_scope())
    if args.chain:
        scope = [c for c in scope if c.chain == args.chain]
        log.info(f"Filtered to {len(scope)} {args.chain} contracts")
    else:
        log.info(f"Scanning {len(scope)} EVM contracts")

    # If --days, compute start block per chain
    start_override = None
    if args.days:
        log.info(f"Limiting to last {args.days} days")
        # Will compute per-contract inside scan_contract via current_block
        start_override = -args.days  # sentinel: negative = days lookback

    grand_total = 0
    with SplunkHEC() as hec:
        for i, contract in enumerate(scope, 1):
            log.info(f"[{i}/{len(scope)}] {contract.name} ({contract.chain})")
            sb = None
            if isinstance(start_override, int) and start_override < 0:
                # Compute start block from days
                current = _get_current_block(contract)
                time.sleep(RATE_DELAY)
                # per-chain block rate; flat 43200 under-counted Arbitrum ~6-8x
                blocks_per_day = BLOCKS_PER_DAY.get(contract.chain, 43200)
                sb = max(0, current - (abs(start_override) * blocks_per_day))
            grand_total += scan_contract(contract, hec, state, start_block_override=sb)

    log.info(f"Historical scan complete — {grand_total} total events sent to Splunk")


if __name__ == "__main__":
    main()
