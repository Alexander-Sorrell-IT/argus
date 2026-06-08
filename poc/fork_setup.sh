#!/usr/bin/env bash
# fork_setup.sh — Spin up a local Anvil mainnet fork for LayerZero PoC testing
# Usage: ./poc/fork_setup.sh [block_number]
set -euo pipefail

source "$(dirname "$0")/../.env" 2>/dev/null || true

BLOCK_NUMBER=${1:-"latest"}
FORK_PORT=${FORK_PORT:-8545}

if ! command -v anvil &>/dev/null; then
  echo "ERROR: anvil not found. Install Foundry: https://getfoundry.sh/"
  exit 1
fi

echo "============================================="
echo "  Argus — Local Mainnet Fork"
echo "  RPC: http://127.0.0.1:${FORK_PORT}"
echo "  Block: ${BLOCK_NUMBER}"
echo "  Chain: Ethereum mainnet"
echo "============================================="
echo ""
echo "Key LayerZero contracts loaded:"
echo "  UltraLightNodeV2: 0x4d73adb72bc3dd368966edd0f0b2148401a178e2"
echo "  EndpointV2:       0x1a44076050125825900e736c501f859c50fe728c"
echo "  Endpoint V1:      0x66A71Dcef29A0fFBDBE3c6a460a3B5BC225Cd675"
echo "  DVN:              0x589dedbd617e0cbcb916a9223f4d1300c294236b"
echo ""
echo "Starting Anvil fork... (Ctrl+C to stop)"
echo ""

FORK_ARGS=(
  "--fork-url" "${ETH_RPC_URL:-https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY}"
  "--port" "${FORK_PORT}"
  "--accounts" "10"
  "--balance" "10000"
  "--gas-limit" "30000000"
  "--chain-id" "1"
)

if [ "${BLOCK_NUMBER}" != "latest" ]; then
  FORK_ARGS+=("--fork-block-number" "${BLOCK_NUMBER}")
fi

anvil "${FORK_ARGS[@]}"
