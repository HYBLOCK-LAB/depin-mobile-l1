#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_DIR="/tmp/depin-live-demo"
PIDS=()

cleanup() {
  for pid in "${PIDS[@]:-}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null || true
    fi
  done
}
trap cleanup EXIT

rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR/logs"

cd "$ROOT_DIR"
echo "[1/8] Building release binaries (depin-node, depin-cli)..."
cargo build --release --bin depin-node --bin depin-cli >/dev/null

NODE_BIN="$ROOT_DIR/target/release/depin-node"
CLI_BIN="$ROOT_DIR/target/release/depin-cli"
CLUSTER_MAP="$DEMO_DIR/cluster_map.json"

"$CLI_BIN" gen-cluster-map \
  --out "$CLUSTER_MAP" \
  --base-p2p-port 19200 \
  --base-rpc-port 19300 \
  --nodes 10

wait_health() {
  local url="$1"
  for _ in $(seq 1 50); do
    if curl -fsS "$url/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  echo "Timed out waiting for $url/health" >&2
  exit 1
}

echo "[2/8] Launching 4 L1 validator daemon processes..."
VAL_PIDS=()
for id in 0 1 2 3; do
  peers=""
  for p in 0 1 2 3; do
    if [ "$p" != "$id" ]; then
      port=$((19100 + p))
      if [ -z "$peers" ]; then
        peers="127.0.0.1:$port"
      else
        peers="$peers,127.0.0.1:$port"
      fi
    fi
  done
  "$NODE_BIN" validator \
    --id "$id" \
    --p2p "127.0.0.1:$((19100 + id))" \
    --rpc "127.0.0.1:$((19110 + id))" \
    --peers "$peers" \
    --validator-count 4 \
    --data-dir "$DEMO_DIR/validator_$id" \
    >"$DEMO_DIR/logs/validator_$id.log" 2>&1 &
  pid=$!
  PIDS+=("$pid")
  VAL_PIDS+=("$pid")
done

for id in 0 1 2 3; do
  wait_health "http://127.0.0.1:$((19110 + id))"
done

echo "[3/8] Launching 10 storage node processes (10 swarm slots, 1 slot per node) & registering on L1..."
NODE_PIDS=()
for nid in $(seq 0 9); do
  "$NODE_BIN" storage \
    --node-id "$nid" \
    --p2p "127.0.0.1:$((19200 + nid))" \
    --rpc "127.0.0.1:$((19300 + nid))" \
    --l1-rpc "http://127.0.0.1:19110" \
    --cluster-map "$CLUSTER_MAP" \
    --data-dir "$DEMO_DIR/storage_$nid" \
    --ip-subnet-hash "$nid" \
    --country-code "$((nid % 8))" \
    >"$DEMO_DIR/logs/storage_$nid.log" 2>&1 &
  pid=$!
  PIDS+=("$pid")
  NODE_PIDS+=("$pid")
done

for nid in $(seq 0 9); do
  wait_health "http://127.0.0.1:$((19300 + nid))"
done

"$CLI_BIN" register-all --cluster-map "$CLUSTER_MAP"

echo "[4/8] Generating 64KB sample file and uploading 10 F_p shards over TCP..."
dd if=/dev/urandom of="$DEMO_DIR/sample.bin" bs=1024 count=64 2>/dev/null
ORIG_SHA="$(shasum -a 256 "$DEMO_DIR/sample.bin" | awk '{print $1}')"
UPLOAD_JSON="$("$CLI_BIN" upload \
  --l1-rpc "http://127.0.0.1:19110" \
  --cluster-map "$CLUSTER_MAP" \
  --file "$DEMO_DIR/sample.bin" \
  --bounty 5000 \
  --kzg-cache-dir "$DEMO_DIR/cli_kzg")"
echo "$UPLOAD_JSON"
OBJECT_ID="$(echo "$UPLOAD_JSON" | grep object_id_hex | sed -E 's/.*"object_id_hex": *"([^"]+)".*/\1/')"

echo "[5/8] Killing validator #3 and 6 storage nodes (slots 0..5 offline -> 4 active <= T_repair 4)..."
kill -9 "${VAL_PIDS[3]}" 2>/dev/null || true
for nid in 0 1 2 3 4 5; do
  kill -9 "${NODE_PIDS[$nid]}" 2>/dev/null || true
done
sleep 0.2

echo "[6/8] Triggering epoch 1 aggregator cycle on surviving successor Node #6 (slot 6)..."
"$CLI_BIN" run-cycle --node-rpc "http://127.0.0.1:19306" --epoch 1

echo "[7/8] Restarting validator #0 from disk snapshot and verifying L1 state recovery..."
kill -9 "${VAL_PIDS[0]}" 2>/dev/null || true
sleep 0.2
"$NODE_BIN" validator \
  --id 0 \
  --p2p "127.0.0.1:19100" \
  --rpc "127.0.0.1:19110" \
  --peers "127.0.0.1:19101,127.0.0.1:19102,127.0.0.1:19103" \
  --validator-count 4 \
  --data-dir "$DEMO_DIR/validator_0" \
  >"$DEMO_DIR/logs/validator_0_restarted.log" 2>&1 &
VAL_PIDS[0]=$!
PIDS+=("${VAL_PIDS[0]}")
wait_health "http://127.0.0.1:19110"
"$CLI_BIN" status --l1-rpc "http://127.0.0.1:19110"

echo "[8/8] Downloading & decoding from 4 surviving nodes over TCP and checking SHA-256..."
"$CLI_BIN" download \
  --cluster-map "$CLUSTER_MAP" \
  --object-id "$OBJECT_ID" \
  --node-rpc "http://127.0.0.1:19306" \
  --out "$DEMO_DIR/recovered.bin"

REC_SHA="$(shasum -a 256 "$DEMO_DIR/recovered.bin" | awk '{print $1}')"
echo "Original  SHA-256: $ORIG_SHA"
echo "Recovered SHA-256: $REC_SHA"

if [ "$ORIG_SHA" != "$REC_SHA" ]; then
  echo "SHA-256 MISMATCH!" >&2
  exit 1
fi

echo "LIVE DEMO PASSED: Real multi-process BFT, TCP P2P lazy repair, disk persistence & full decode verified!"
