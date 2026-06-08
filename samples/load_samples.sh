#!/usr/bin/env bash
#
# load_samples.sh — reconstitute a runnable Argus dataset into a fresh Splunk.
#
# Ingests the bundled sample LayerZero transactions/events and loads the
# contract_baselines KV snapshot, so detections fire on a fresh clone with no
# access to the original live index.
#
# WHAT THIS LOADS
#   layerzero_transaction.jsonl  -> sourcetype=layerzero:transaction (~408 recs)
#   layerzero_event.jsonl        -> sourcetype=layerzero:event       (~400 recs)
#   contract_baselines.kv.json   -> KV collection contract_baselines  (13 rows)
#
# PREREQUISITE (recommended): install the `omni_guard` Splunk app first. It
# supplies the sourcetype field-extractions (props.conf), the index, and the
# contract_baselines KV collection definition (collections.conf). With the app
# installed, everything below "just works". If the app is NOT installed this
# script creates the index and the KV collection itself (best-effort) so the
# raw data still ingests, but for full fidelity install the app.
#
#   cp -r <repo>/splunk $SPLUNK_HOME/etc/apps/omni_guard && $SPLUNK_HOME/bin/splunk restart
#
# USAGE
#   ./load_samples.sh                      # uses defaults below
#   SPLUNK_HOME=/opt/splunk ./load_samples.sh
#   SPLUNK_USER=admin SPLUNK_PASS=changeme ./load_samples.sh
#
# After loading, run detections over ALL TIME (earliest=0). The sample events
# carry their original (historical) timestamps, so the default real-time /
# last-15-minutes window finds nothing — search "All time".
#
set -euo pipefail

# ── config (override via env) ────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SPLUNK_HOME="${SPLUNK_HOME:-/Applications/Splunk}"
SPLUNK_BIN="${SPLUNK_BIN:-$SPLUNK_HOME/bin/splunk}"
MGMT="${SPLUNK_MGMT:-https://localhost:8089}"
INDEX="${SPLUNK_INDEX:-omni_guard_security}"
APP="${SPLUNK_APP:-omni_guard}"
SPLUNK_USER="${SPLUNK_USER:-admin}"
SPLUNK_PASS="${SPLUNK_PASS:-}"

TX_FILE="$SCRIPT_DIR/layerzero_transaction.jsonl"
EV_FILE="$SCRIPT_DIR/layerzero_event.jsonl"
KV_FILE="$SCRIPT_DIR/contract_baselines.kv.json"

echo "==> Argus sample loader"
echo "    SPLUNK_HOME = $SPLUNK_HOME"
echo "    index       = $INDEX   app = $APP"

# ── credentials ──────────────────────────────────────────────────────
if [[ -z "$SPLUNK_PASS" ]]; then
  read -r -s -p "Splunk password for user '$SPLUNK_USER': " SPLUNK_PASS; echo
fi
AUTH=(-u "$SPLUNK_USER:$SPLUNK_PASS")

curl_mgmt() { curl -sk "${AUTH[@]}" "$@"; }

# ── 0. sanity: files present ─────────────────────────────────────────
for f in "$TX_FILE" "$EV_FILE" "$KV_FILE"; do
  [[ -f "$f" ]] || { echo "ERROR: missing sample file: $f" >&2; exit 1; }
done

# ── 1. ensure index exists (no-op if the app already defines it) ──────
if ! curl_mgmt "$MGMT/services/data/indexes/$INDEX?output_mode=json" | grep -q "\"name\":\"$INDEX\""; then
  echo "==> index '$INDEX' not found — creating it"
  curl_mgmt "$MGMT/services/data/indexes" -d name="$INDEX" >/dev/null || true
fi

# ── 2. ensure KV collection exists (no-op if the app defines it) ──────
COLL_URL="$MGMT/servicesNS/nobody/$APP/storage/collections/config/contract_baselines"
if ! curl_mgmt "$COLL_URL?output_mode=json" | grep -q contract_baselines; then
  echo "==> KV collection contract_baselines not found — creating it"
  curl_mgmt "$MGMT/servicesNS/nobody/$APP/storage/collections/config" \
       -d name=contract_baselines >/dev/null || true
fi

# ── 3. ingest transactions + events (oneshot re-indexes _raw identically) ──
ingest() {  # $1=file  $2=sourcetype
  local file="$1" st="$2"
  if [[ -x "$SPLUNK_BIN" ]]; then
    echo "==> oneshot $st  <-  $(basename "$file")"
    "$SPLUNK_BIN" add oneshot "$file" \
        -index "$INDEX" -sourcetype "$st" \
        -auth "$SPLUNK_USER:$SPLUNK_PASS" >/dev/null
  else
    echo "==> splunk CLI not at $SPLUNK_BIN — falling back to HEC for $st"
    : "${HEC_URL:?set HEC_URL (e.g. https://localhost:8088) and HEC_TOKEN to use the HEC fallback}"
    : "${HEC_TOKEN:?set HEC_TOKEN to use the HEC fallback}"
    while IFS= read -r raw; do
      [[ -z "$raw" ]] && continue
      curl -sk "$HEC_URL/services/collector/event" \
        -H "Authorization: Splunk $HEC_TOKEN" \
        -d "$(python3 - "$raw" "$st" "$INDEX" <<'PY'
import json,sys
raw,st,idx=sys.argv[1],sys.argv[2],sys.argv[3]
print(json.dumps({"event":raw,"sourcetype":st,"index":idx}))
PY
)" >/dev/null
    done < "$file"
  fi
}

ingest "$TX_FILE" "layerzero:transaction"
ingest "$EV_FILE" "layerzero:event"

# ── 4. load contract_baselines KV (batch_save preserves _key) ─────────
echo "==> loading contract_baselines KV ($(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))))' "$KV_FILE") rows)"
curl_mgmt "$MGMT/servicesNS/nobody/$APP/storage/collections/data/contract_baselines/batch_save" \
     -H 'Content-Type: application/json' \
     --data-binary "@$KV_FILE" >/dev/null
KVN=$(curl_mgmt "$MGMT/servicesNS/nobody/$APP/storage/collections/data/contract_baselines?output_mode=json" \
      | python3 -c 'import sys,json;print(len(json.load(sys.stdin)))')
echo "    KV rows now present: $KVN"

cat <<EOF

==> Done. Verify in Splunk (search over ALL TIME / earliest=0):

  index=$INDEX sourcetype=layerzero:transaction | stats count
  index=$INDEX sourcetype=layerzero:event       | stats count

  # value-transfer outlier detection should fire:
  index=$INDEX sourcetype=layerzero:transaction value_eth>0 earliest=0 latest=now
    | lookup contract_baselines contract_name OUTPUT mean_value_eth, stdev_value_eth, tx_count_30d
    | where isnotnull(mean_value_eth) AND tx_count_30d>=30 AND stdev_value_eth>0
    | eval zscore=(value_eth-mean_value_eth)/stdev_value_eth
    | where zscore>3 AND value_eth>0.1
    | stats count

Note: SAIA (the in-app AI agent) needs a Splunk Cloud tenant; everything
above runs offline on this sample.
EOF
