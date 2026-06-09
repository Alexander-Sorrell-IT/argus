#!/usr/bin/env python
"""
forkvalidate — a Splunk custom search command that runs Argus's fork-validation
INSIDE the Splunk pipeline. It reproduces a suspected exploit against a mainnet
fork (Anvil + Foundry) on the Splunk host and returns the verdict as SPL events.

    | forkvalidate tx_hash="0x..." fork_block=15725066 foundry_test="poc/replays/x/Exploit.t.sol"

Honesty: the verdict is DETERMINISTIC — CONFIRMED only when the Foundry test's own
assertions reproduce the exploit (a real [PASS]); otherwise REJECTED. No AI, no
fabricated numbers. Splunk's Python orchestrates the host EVM tooling (anvil/forge)
via the system python3 (which carries the validator's deps); splunkd itself does not
execute the EVM. Self-hosted Splunk Enterprise only (Splunk Cloud cannot spawn anvil).
"""
import sys, os, json, time, subprocess

APP_HOME = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(APP_HOME, "lib"))

from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators


@Configuration()
class ForkValidateCommand(GeneratingCommand):
    """Generate a fork-validation verdict for a suspected exploit transaction."""

    tx_hash      = Option(require=True, doc="attack/suspect transaction hash")
    chain        = Option(require=False, default="ethereum")
    fork_block   = Option(require=False, validate=validators.Integer(), doc="fork at this block (default tx_block-1)")
    foundry_test = Option(require=False, doc="path to the Exploit.t.sol (absolute, or relative to the Argus repo)")
    repo         = Option(require=False, doc="Argus repo root (default $ARGUS_HOME or the known install path)")

    # The validator carries deps (dotenv, web3 stack) that splunkd's bundled Python
    # lacks, so we drive it through the system interpreter — Splunk orchestrating the
    # host tool, which is exactly the integration boundary.
    SYS_PYTHON = os.environ.get("ARGUS_SYS_PYTHON", "/usr/local/bin/python3")

    def generate(self):
        repo = self.repo or os.environ.get("ARGUS_HOME") or "/Users/broodierchip-m1air/Desktop/omni-guard"
        validator = os.path.join(repo, "poc", "validate_finding.py")

        cmd = [self.SYS_PYTHON, validator, "--tx-hash", self.tx_hash,
               "--chain", self.chain, "--no-splunk"]
        if self.fork_block is not None:
            cmd += ["--fork-block", str(self.fork_block)]
        if self.foundry_test:
            ft = self.foundry_test
            if not os.path.isabs(ft):
                ft = os.path.join(repo, ft)
            cmd += ["--foundry-test", ft]

        t0 = time.time()
        data, err = {}, ""
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=300, cwd=repo)
            out = r.stdout or ""
            err = (r.stderr or "")[-600:]
            if "{" in out:
                data = json.loads(out[out.index("{"):])   # validator prints its ForkResult JSON
            else:
                data = {"status": "ERROR", "reason": "validator produced no JSON"}
        except subprocess.TimeoutExpired:
            data = {"status": "ERROR", "reason": "fork validation timed out (300s)"}
        except Exception as e:
            data = {"status": "ERROR", "reason": "forkvalidate wrapper error: %s" % e}

        yield {
            "_time":         time.time(),
            "_raw":          json.dumps(data),
            "status":        data.get("status"),
            "test_passed":   data.get("test_passed"),
            "confidence":    data.get("confidence"),
            "tx_hash":       data.get("tx_hash", self.tx_hash),
            "chain":         data.get("chain", self.chain),
            "fork_block":    data.get("fork_block"),
            "reason":        data.get("reason"),
            "duration_secs": data.get("duration_secs", round(time.time() - t0, 2)),
            "stderr_tail":   err,
        }


dispatch(ForkValidateCommand, sys.argv, sys.stdin, sys.stdout, __name__)
