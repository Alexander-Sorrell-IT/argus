#!/usr/bin/env bash
#
# quickstart.sh — stand up Argus (omni_guard) on a local Splunk Enterprise in one shot.
#
# Deploys the custom app, restarts Splunk (so the index + the argus_agent modular
# input register), loads the bundled LayerZero sample, and prints the dashboard URL.
# Re-runnable: safe to run again to redeploy.
#
# USAGE
#   ./scripts/quickstart.sh
#   SPLUNK_HOME=/opt/splunk SPLUNK_USER=admin SPLUNK_PASS=changeme ./scripts/quickstart.sh
#
# PREREQS: a local Splunk Enterprise 10.x install, and Foundry (anvil/forge) on PATH
# only if you want to run `| forkvalidate`. The detections, agent, and dashboard need
# neither Foundry nor any cloud key.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPLUNK_HOME="${SPLUNK_HOME:-$HOME/splunk}"      # this project runs Splunk at ~/splunk
SPLUNK_BIN="${SPLUNK_BIN:-$SPLUNK_HOME/bin/splunk}"
SPLUNK_USER="${SPLUNK_USER:-admin}"
SPLUNK_PASS="${SPLUNK_PASS:-}"
APP="omni_guard"
APP_DIR="$SPLUNK_HOME/etc/apps/$APP"

echo "==> Argus quickstart"
echo "    repo        = $REPO_ROOT"
echo "    SPLUNK_HOME = $SPLUNK_HOME"

if [[ ! -x "$SPLUNK_BIN" ]]; then
  echo "ERROR: Splunk CLI not found at '$SPLUNK_BIN'." >&2
  echo "       Install Splunk Enterprise 10.x and/or set SPLUNK_HOME, then re-run." >&2
  exit 1
fi

# 1. Deploy the app (the repo's splunk/ dir IS the omni_guard app).
echo "==> Deploying the $APP app -> $APP_DIR"
mkdir -p "$APP_DIR"
cp -r "$REPO_ROOT/splunk/." "$APP_DIR/"

# 2. Restart so the index + the argus_agent modular input register.
echo "==> Restarting Splunk (registers index + argus_agent modular input)..."
"$SPLUNK_BIN" restart

# 3. Load the bundled LayerZero sample so detections have data on a fresh clone.
echo "==> Loading the bundled LayerZero sample..."
SPLUNK_HOME="$SPLUNK_HOME" SPLUNK_BIN="$SPLUNK_BIN" \
  SPLUNK_USER="$SPLUNK_USER" SPLUNK_PASS="$SPLUNK_PASS" \
  bash "$REPO_ROOT/samples/load_samples.sh"

cat <<EOF

==> Done.
    Dashboard:  http://localhost:8000/en-US/app/$APP/$APP
    Login:      $SPLUNK_USER

    The sample events carry their original (historical) timestamps, so run searches
    over "All time" (earliest=0) the first time. The in-app agent triages on a 5-min
    cadence; to seed verdicts immediately:
      $SPLUNK_BIN cmd python3 $APP_DIR/bin/argus_agent.py --test

    Optional: \`| forkvalidate ...\` needs Foundry (anvil/forge) on PATH and the env
    vars ARGUS_HOME + ARGUS_SYS_PYTHON (a python with web3/dotenv). See README.
EOF
