#!/usr/bin/env bash
#
# reproduce.sh — verify every headline Argus claim against the LIVE system and print a
# PASS/FAIL table. The point: every number in the docs should be EMITTED by this script,
# not typed by a human. Run after scripts/quickstart.sh (and the agent has cycled once).
#
#   ./scripts/reproduce.sh              # full run (includes a real | forkvalidate, ~30s)
#   ./scripts/reproduce.sh --no-fork    # skip the fork-validation step
#
set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV=.env
U=$(grep -E '^SPLUNK_USER=' "$ENV" | cut -d= -f2-)
P=$(grep -E '^SPLUNK_PASS=' "$ENV" | cut -d= -f2-)
NS="https://localhost:8089/servicesNS/nobody/omni_guard"
PASS=0; FAIL=0

q() { curl -sk -u "$U:$P" "$NS/search/jobs/export" --data-urlencode "search=$1" \
        -d output_mode=csv -d earliest_time=0 -d latest_time=now 2>/dev/null | tail -1 | tr -d '"\r'; }

check() {  # $1=label  $2=actual  $3=test expr (uses $A)   prints PASS/FAIL
  local label="$1" A="$2" expr="$3"
  if [ -n "$A" ] && eval "[ $expr ]" 2>/dev/null; then
    printf "  \033[32m✓ PASS\033[0m  %-44s = %s\n" "$label" "$A"; PASS=$((PASS+1))
  else
    printf "  \033[31m✗ FAIL\033[0m  %-44s = %s\n" "$label" "${A:-<none>}"; FAIL=$((FAIL+1))
  fi
}

echo "── Argus reproduce.sh — verifying headline claims against the live system ──"

code=$(curl -sk -u "$U:$P" -o /dev/null -w "%{http_code}" "https://localhost:8089/services/server/info" 2>/dev/null)
check "Splunk reachable + authenticated (HTTP 200)" "$code" '"$A" = "200"'

check "Source data: layerzero:transaction events"  "$(q 'search index=omni_guard_security sourcetype=layerzero:transaction | stats count')" '"$A" -ge 300'
check "Source data: layerzero:event events"        "$(q 'search index=omni_guard_security sourcetype=layerzero:event | stats count')"       '"$A" -ge 300'
check "Detections: saved searches in the app"      "$(curl -sk -u "$U:$P" "$NS/saved/searches?count=0&output_mode=json" 2>/dev/null | python3 -c 'import sys,json;print(sum(1 for e in json.load(sys.stdin)["entry"] if e["name"].startswith("Argus -")))')" '"$A" -ge 16'
check "Detections produced real alerts"            "$(q 'search index=omni_guard_security sourcetype=layerzero:alert | stats count')"       '"$A" -ge 1'
check "Agent verdicts (layerzero:ai_report)"       "$(q 'search index=omni_guard_security sourcetype=layerzero:ai_report | stats count')"   '"$A" -ge 1'
check "KV dedup state == distinct verdicts"        "$(curl -sk -u "$U:$P" "$NS/storage/collections/data/argus_agent_state" 2>/dev/null | python3 -c 'import sys,json;print(len(json.load(sys.stdin)))')" '"$A" -ge 1'
check "Lookup: protocol_config rows"               "$(q '| inputlookup protocol_config.csv | stats count')"  '"$A" -ge 10'
check "Lookup: bad_addresses (verified threat-intel)" "$(q '| inputlookup bad_addresses | stats count')"     '"$A" -ge 1'
check "Lookup: privileged_selectors"               "$(q '| inputlookup privileged_selectors | stats count')" '"$A" -ge 13'
check "SAIA cloud connection active (scs_token)"   "$(curl -sk -u "$U:$P" "https://localhost:8089/servicesNS/nobody/Splunk_AI_Assistant_Cloud/storage/collections/data/cloud_connected_configurations" 2>/dev/null | python3 -c 'import sys,json;d=json.load(sys.stdin);print("yes" if d and d[0].get("scs_token") else "no")')" '"$A" = "yes"'

if [ "${1:-}" != "--no-fork" ]; then
  echo "  … running a real | forkvalidate (forks mainnet + Foundry, ~30s) …"
  FV=$(q '| forkvalidate tx_hash="0xself" fork_block=25308000 foundry_test="poc/capability-selftest/Exploit.t.sol" | head 1 | table status')
  check "forkvalidate self-test -> CONFIRMED"      "$FV" '"$A" = "CONFIRMED"'
fi

echo "────────────────────────────────────────────────────────────────────"
printf "  %d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] && echo "  ✅ every headline claim reproduced." || echo "  ⚠ some checks failed — see above."
exit "$FAIL"
