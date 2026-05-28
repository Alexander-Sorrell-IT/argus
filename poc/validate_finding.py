"""validate_finding.py — fork-replay a suspicious tx and decide if it's exploitable.

For a given finding (tx hash + chain + block + candidate Foundry test):
  1. Start Anvil forked at block N-1 of the suspicious tx
  2. Run `cast run --rpc-url <anvil>` to re-execute and get a trace
  3. If a Foundry test (.t.sol) is provided, run `forge test --fork-url <anvil>`
  4. Compare original state vs post-attack state for value extraction
  5. Emit a layerzero:fork_result event to Splunk
  6. Return CONFIRMED | REJECTED | INCONCLUSIVE

CRITICAL: Never sends a tx to mainnet. Only reads + local fork.
Honors LayerZero Immunefi rule: fork-local validation only.

Usage (CLI):
    python validate_finding.py \
        --finding-id 2026-05-23-ENDV2-001 \
        --tx-hash 0xabc... \
        --chain ethereum \
        --foundry-test poc/findings/2026-05-23-ENDV2-001/Exploit.t.sol

Library:
    from validate_finding import ForkValidator
    v = ForkValidator()
    result = v.validate(tx_hash="0xabc", chain="ethereum",
                        foundry_test=Path("poc/findings/x/Exploit.t.sol"))
"""
from __future__ import annotations
import os, sys, json, time, subprocess, signal, argparse, logging
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

REPO   = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "ingestion"))
from splunk_hec import SplunkHEC

load_dotenv(REPO / ".env")
logging.basicConfig(level=os.getenv("LOG_LEVEL","INFO"),
                    format="%(asctime)s  %(levelname)-8s  %(message)s")
log = logging.getLogger(__name__)

CHAIN_RPC = {
    "ethereum":  os.getenv("ETHEREUM_RPC_URL") or os.getenv("ETH_RPC_URL"),
    "arbitrum":  os.getenv("ARBITRUM_RPC_URL") or os.getenv("ARB_RPC_URL"),
    "optimism":  os.getenv("OPTIMISM_RPC_URL") or os.getenv("OPT_RPC_URL"),
    "polygon":   os.getenv("POLYGON_RPC_URL"),
    "avalanche": os.getenv("AVALANCHE_RPC_URL") or os.getenv("AVAX_RPC_URL"),
    "base":      os.getenv("BASE_RPC_URL"),
    "bnb":       os.getenv("BNB_RPC_URL"),
}

ANVIL_PORT      = int(os.getenv("FORK_PORT", "8545"))
ANVIL_RPC       = f"http://127.0.0.1:{ANVIL_PORT}"
ANVIL_BIN       = os.path.expanduser("~/.foundry/bin/anvil")
CAST_BIN        = os.path.expanduser("~/.foundry/bin/cast")
FORGE_BIN       = os.path.expanduser("~/.foundry/bin/forge")
ANVIL_BOOT_SECS = int(os.getenv("ANVIL_BOOT_SECS","6"))


@dataclass
class ForkResult:
    finding_id: str
    tx_hash: str
    chain: str
    fork_block: int
    status: str                       # CONFIRMED | REJECTED | INCONCLUSIVE | ERROR
    confidence: float
    state_diff: dict = field(default_factory=dict)
    attacker_gain_eth: float = 0.0
    target_loss_eth: float = 0.0
    test_passed: Optional[bool] = None
    test_output: str = ""
    trace_summary: str = ""
    reason: str = ""
    duration_secs: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


class ForkValidator:
    def __init__(self, splunk: bool = True):
        self.write_to_splunk = splunk

    # ── Anvil lifecycle ────────────────────────────────────────────────────────
    def _start_anvil(self, chain: str, block: int) -> subprocess.Popen:
        rpc = CHAIN_RPC.get(chain)
        if not rpc:
            raise RuntimeError(f"no RPC configured for chain {chain}")
        args = [
            ANVIL_BIN,
            "--fork-url", rpc,
            "--fork-block-number", str(block),
            "--port", str(ANVIL_PORT),
            "--accounts", "10",
            "--balance", "10000",
            "--gas-limit", "30000000",
            "--chain-id", "1" if chain == "ethereum" else "0",
            "--silent",
        ]
        log.info(f"  starting anvil → fork {chain} @ block {block}")
        proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(ANVIL_BOOT_SECS)
        if proc.poll() is not None:
            raise RuntimeError("anvil exited immediately — check RPC URL / port")
        return proc

    def _stop_anvil(self, proc: subprocess.Popen):
        try:
            proc.send_signal(signal.SIGINT)
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.info("  anvil stopped")

    # ── Tooling ────────────────────────────────────────────────────────────────
    def _cast(self, *args: str) -> str:
        cmd = [CAST_BIN, *args]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return (r.stdout or r.stderr).strip()
        except Exception as e:
            return f"[cast error] {e}"

    def _trace_tx(self, tx_hash: str) -> str:
        return self._cast("run", "--rpc-url", ANVIL_RPC, tx_hash, "--quick")

    def _balance(self, addr: str) -> int:
        out = self._cast("balance", addr, "--rpc-url", ANVIL_RPC)
        try:
            return int(out)
        except Exception:
            return 0

    # ── Optional Foundry test run ──────────────────────────────────────────────
    def _run_foundry_test(self, test_path: Path) -> tuple[bool, str]:
        if not test_path.exists():
            return False, f"test file not found: {test_path}"
        project_dir = test_path.parent
        # Minimal foundry.toml if absent so `forge test` works standalone
        ftoml = project_dir / "foundry.toml"
        if not ftoml.exists():
            ftoml.write_text(
                '[profile.default]\nsrc="."\ntest="."\nout="out"\n'
                'eth_rpc_url="' + ANVIL_RPC + '"\n'
            )
        cmd = [FORGE_BIN, "test", "--fork-url", ANVIL_RPC,
               "-vvv", "--root", str(project_dir)]
        # Forward FOUNDRY_RPC_URL so vm.envOr("FOUNDRY_RPC_URL", ...) inside the
        # test resolves to our local Anvil instance instead of a public fallback
        # that gets Cloudflare-rate-limited.
        env = {**os.environ, "FOUNDRY_RPC_URL": ANVIL_RPC}
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=180, env=env)
            out = r.stdout + "\n" + r.stderr
            passed = ("PASSED" in out and "FAILED" not in out) or r.returncode == 0
            return passed, out[-4000:]
        except subprocess.TimeoutExpired:
            return False, "forge test timed out after 180s"
        except Exception as e:
            return False, f"forge test error: {e}"

    # ── Main ───────────────────────────────────────────────────────────────────
    def validate(
        self,
        tx_hash: str,
        chain: str = "ethereum",
        fork_block: Optional[int] = None,
        target_address: Optional[str] = None,
        attacker_address: Optional[str] = None,
        foundry_test: Optional[Path] = None,
        finding_id: str = "",
    ) -> ForkResult:
        t0 = time.time()
        finding_id = finding_id or f"ad-hoc-{int(t0)}"
        # If no fork block given, fetch the tx's block from real RPC and use N-1
        if fork_block is None:
            block = self._fetch_tx_block(tx_hash, chain)
            if block <= 0:
                return self._fail(finding_id, tx_hash, chain, 0,
                                  "could not resolve tx block — wrong chain?")
            fork_block = block - 1

        anvil = None
        try:
            anvil = self._start_anvil(chain, fork_block)

            # Pre-state balances
            pre = {}
            if target_address:    pre[target_address]    = self._balance(target_address)
            if attacker_address:  pre[attacker_address]  = self._balance(attacker_address)

            # Re-trace the suspicious tx against the fork (read-only baseline)
            trace = self._trace_tx(tx_hash)
            trace_summary = trace[:1500] if trace else ""

            # Run the Foundry exploit test if supplied
            test_passed, test_out = (None, "")
            if foundry_test:
                test_passed, test_out = self._run_foundry_test(foundry_test)
                log.info(f"  forge test → {'PASSED' if test_passed else 'FAILED'}")

            # Post-state balances
            post = {}
            if target_address:    post[target_address]    = self._balance(target_address)
            if attacker_address:  post[attacker_address]  = self._balance(attacker_address)

            attacker_gain = (post.get(attacker_address,0) - pre.get(attacker_address,0)) / 1e18 \
                            if attacker_address else 0.0
            target_loss   = (pre.get(target_address,0) - post.get(target_address,0)) / 1e18 \
                            if target_address else 0.0

            # Decision
            if test_passed and (attacker_gain > 0.01 or target_loss > 0.01):
                status, conf, reason = "CONFIRMED", 0.9, \
                    f"forge test passed + attacker gained {attacker_gain:.4f} ETH"
            elif test_passed:
                status, conf, reason = "CONFIRMED", 0.6, "forge test passed (no state extraction observed)"
            elif test_passed is False:
                status, conf, reason = "REJECTED", 0.8, "forge test failed — exploit hypothesis did not reproduce"
            else:
                status, conf, reason = "INCONCLUSIVE", 0.3, "no test supplied; trace recorded for review"

            result = ForkResult(
                finding_id=finding_id, tx_hash=tx_hash, chain=chain, fork_block=fork_block,
                status=status, confidence=conf,
                state_diff={"pre": pre, "post": post},
                attacker_gain_eth=round(attacker_gain, 6),
                target_loss_eth=round(target_loss, 6),
                test_passed=test_passed, test_output=test_out,
                trace_summary=trace_summary, reason=reason,
                duration_secs=round(time.time() - t0, 2),
            )
        except Exception as e:
            result = self._fail(finding_id, tx_hash, chain, fork_block or 0, f"validator error: {e}")
        finally:
            if anvil: self._stop_anvil(anvil)

        self._report(result)
        return result

    def _fetch_tx_block(self, tx_hash: str, chain: str) -> int:
        rpc = CHAIN_RPC.get(chain)
        if not rpc:
            return 0
        out = self._cast("tx", tx_hash, "--rpc-url", rpc, "blockNumber")
        try:
            return int(out, 16) if out.startswith("0x") else int(out)
        except Exception:
            return 0

    def _fail(self, finding_id, tx_hash, chain, block, msg) -> ForkResult:
        return ForkResult(
            finding_id=finding_id, tx_hash=tx_hash, chain=chain, fork_block=block,
            status="ERROR", confidence=0.0, reason=msg,
        )

    def _report(self, r: ForkResult):
        log.info(f"  → {r.status} ({r.confidence:.0%}) — {r.reason}")
        if not self.write_to_splunk: return
        try:
            with SplunkHEC() as hec:
                payload = r.to_dict()
                payload["timestamp"] = int(time.time())
                hec.send(payload, sourcetype="layerzero:fork_result")
                hec.flush()
        except Exception as e:
            log.warning(f"  splunk write failed: {e}")


def _cli():
    p = argparse.ArgumentParser()
    p.add_argument("--finding-id", default="")
    p.add_argument("--tx-hash",     required=True)
    p.add_argument("--chain",       default="ethereum")
    p.add_argument("--fork-block",  type=int, default=None)
    p.add_argument("--target",      default=None,  help="target/victim address for state diff")
    p.add_argument("--attacker",    default=None,  help="attacker address for state diff")
    p.add_argument("--foundry-test", default=None, help="path to .t.sol exploit test")
    p.add_argument("--no-splunk", action="store_true")
    a = p.parse_args()

    v = ForkValidator(splunk=not a.no_splunk)
    r = v.validate(
        finding_id=a.finding_id, tx_hash=a.tx_hash, chain=a.chain,
        fork_block=a.fork_block, target_address=a.target,
        attacker_address=a.attacker,
        foundry_test=Path(a.foundry_test) if a.foundry_test else None,
    )
    print(json.dumps(r.to_dict(), indent=2, default=str))


if __name__ == "__main__":
    _cli()
