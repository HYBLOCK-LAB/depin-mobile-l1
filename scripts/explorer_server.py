#!/usr/bin/env python3
"""DePIN Mobile L1 — General-Purpose Block & Swarm Explorer (Python 3.8+ stdlib only)."""

import argparse
import base64
import glob
import hashlib
import json
import mimetypes
import os
import re
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_L1_RPC = (
    "http://127.0.0.1:19110,"
    "http://127.0.0.1:19111,"
    "http://127.0.0.1:19112,"
    "http://127.0.0.1:19113"
)

CONFIG = {
    "l1_rpcs": [u.strip().rstrip("/") for u in DEFAULT_L1_RPC.split(",") if u.strip()],
    "wal_path": "/tmp/depin-multihost/validator_2/blocks.jsonl",
    "cli_bin": "/tmp/depin-bin/depin-cli",
    "kzg_cache": "/tmp/depin-multihost/explorer_kzg",
    "data_root": "/tmp/depin-multihost",
    "objects_registry": "/tmp/depin-multihost/explorer_objects.json",
}


def http_get_json(url, timeout=1.2):
    t0 = time.time()
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        latency_ms = round((time.time() - t0) * 1000.0, 1)
        return data, latency_ms


def probe_validator(idx_and_url):
    idx, rpc = idx_and_url
    result = {
        "index": idx,
        "id": None,
        "rpc": rpc,
        "online": False,
        "latency_ms": None,
        "height": None,
        "last_block_hash_hex": "",
        "registered_nodes": 0,
        "swarm_count": 0,
    }
    try:
        health, _ = http_get_json(rpc + "/health", timeout=1.0)
        status, status_lat = http_get_json(rpc + "/status", timeout=1.5)
        result["id"] = health.get("validator_id", status.get("validator_id", idx))
        result["online"] = bool(health.get("ok"))
        result["latency_ms"] = status_lat
        result["height"] = status.get("height", 0)
        result["last_block_hash_hex"] = status.get("last_block_hash_hex", "")
        result["registered_nodes"] = status.get("registered_nodes", 0)
        result["swarm_count"] = status.get("swarm_count", 0)
        result["_status"] = status
    except Exception as exc:
        result["error"] = str(exc)
    return result


def probe_storage_node(node):
    rpc_addr = node.get("rpc_addr", "")
    info = {
        "pubkey_hex": node.get("pubkey_hex", ""),
        "p2p_addr": node.get("p2p_addr", ""),
        "rpc_addr": rpc_addr,
        "ip_subnet_hash": node.get("ip_subnet_hash", 0),
        "country_code": node.get("country_code", 0),
        "stake": node.get("stake", 0),
        "reward_balance": node.get("reward_balance", 0),
        "consecutive_offline_epochs": node.get("consecutive_offline_epochs", 0),
        "slashed": node.get("slashed", False),
        "ema_uptime_bps": node.get("ema_uptime_bps", 0),
        "online": False,
        "latency_ms": None,
        "node_id": None,
        "manifest": None,
    }
    if not rpc_addr:
        return info
    base = "http://" + rpc_addr
    try:
        health, lat = http_get_json(base + "/health", timeout=0.9)
        info["online"] = bool(health.get("ok"))
        info["latency_ms"] = lat
        info["node_id"] = health.get("node_id")
        manifests = []
        try:
            items, _ = http_get_json(base + "/manifests", timeout=0.9)
            if isinstance(items, list):
                manifests.extend(items)
        except Exception:
            pass
        if not manifests:
            try:
                manifest, _ = http_get_json(base + "/manifest", timeout=0.9)
                if isinstance(manifest, dict) and manifest.get("object_id_hex"):
                    manifests.append(manifest)
            except Exception:
                pass
        info["manifests"] = manifests
    except Exception:
        info["online"] = False
    return info


def load_object_registry():
    meta = {}
    reg_path = CONFIG.get("objects_registry")
    if reg_path and os.path.exists(reg_path):
        try:
            with open(reg_path, "r", encoding="utf-8") as f:
                saved = json.load(f)
                if isinstance(saved, dict):
                    for k, v in saved.items():
                        if isinstance(k, str) and re.fullmatch(r"[0-9a-fA-F]{64}", k):
                            meta[k.lower()] = str(v) if v else ""
                elif isinstance(saved, list):
                    for item in saved:
                        if isinstance(item, str) and re.fullmatch(r"[0-9a-fA-F]{64}", item):
                            meta[item.lower()] = ""
        except Exception:
            pass
    data_root = CONFIG.get("data_root")
    if data_root and os.path.isdir(data_root):
        pattern = os.path.join(data_root, "*", "manifests", "manifest_*.json")
        for path in glob.glob(pattern):
            m = re.search(r"manifest_([0-9a-fA-F]{64})\.json$", path)
            if m:
                meta.setdefault(m.group(1).lower(), "")
    return meta


def save_object_registry(meta):
    reg_path = CONFIG.get("objects_registry")
    if not reg_path:
        return
    try:
        parent = os.path.dirname(reg_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(reg_path, "w", encoding="utf-8") as f:
            json.dump(dict(sorted(meta.items())), f)
    except Exception:
        pass


def detect_extension_and_mime(raw):
    if raw.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png", "image/png"
    if raw.startswith(b"\xff\xd8\xff"):
        return ".jpg", "image/jpeg"
    if raw.startswith((b"GIF87a", b"GIF89a")):
        return ".gif", "image/gif"
    if len(raw) >= 12 and raw[:4] == b"RIFF" and raw[8:12] == b"WEBP":
        return ".webp", "image/webp"
    if len(raw) >= 12 and raw[:4] == b"RIFF" and raw[8:12] == b"WAVE":
        return ".wav", "audio/wav"
    if raw.startswith(b"%PDF-"):
        return ".pdf", "application/pdf"
    if raw.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return ".zip", "application/zip"
    if raw.startswith(b"\x1f\x8b\x08"):
        return ".gz", "application/gzip"
    if len(raw) >= 262 and raw[257:262] == b"ustar":
        return ".tar", "application/x-tar"
    if raw.startswith(b"\x00asm"):
        return ".wasm", "application/wasm"
    if len(raw) >= 12 and raw[4:8] == b"ftyp":
        return ".mp4", "video/mp4"
    if raw.startswith(b"ID3") or (len(raw) >= 2 and raw[0] == 0xFF and (raw[1] & 0xE0) == 0xE0):
        return ".mp3", "audio/mpeg"
    if raw.startswith(b"OggS"):
        return ".ogg", "audio/ogg"
    try:
        txt = raw.decode("utf-8")
        stripped = txt.lstrip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                json.loads(stripped)
                return ".json", "application/json; charset=utf-8"
            except Exception:
                pass
        lower_head = stripped[:64].lower()
        if lower_head.startswith(("<!doctype html", "<html")):
            return ".html", "text/html; charset=utf-8"
        if lower_head.startswith("<svg"):
            return ".svg", "image/svg+xml"
        if all(ch.isprintable() or ch in "\r\n\t" for ch in txt[:512]):
            return ".txt", "text/plain; charset=utf-8"
    except Exception:
        pass
    return ".bin", "application/octet-stream"


def read_wal_blocks(wal_path, limit=80):
    blocks = []
    if not wal_path or not os.path.exists(wal_path):
        return blocks, 0
    try:
        with open(wal_path, "r", encoding="utf-8") as f:
            lines = [ln.strip() for ln in f if ln.strip()]
    except Exception:
        return blocks, 0
    total = len(lines)
    for ln in reversed(lines[-limit:]):
        try:
            blocks.append(json.loads(ln))
        except Exception:
            continue
    return blocks, total


def summarize_block(b):
    hdr = b.get("header", {})
    txs = b.get("txs", [])
    receipts = b.get("receipts", [])
    tx_kinds = []
    details = []
    for i, tx in enumerate(txs):
        if isinstance(tx, str):
            tx_kinds.append(tx)
            details.append({"kind": tx})
        elif isinstance(tx, dict):
            kind = next(iter(tx.keys()), "Unknown")
            tx_kinds.append(kind)
            payload = tx.get(kind, {})
            summary = {"kind": kind}
            if kind == "SubmitSwarmCheckpoint":
                bitmap_int = int(payload.get("uptime_bitmap", "0"))
                summary.update({
                    "swarm_id": payload.get("swarm_id"),
                    "epoch": payload.get("epoch"),
                    "aggregator_slot": payload.get("aggregator_slot"),
                    "online_count": bin(bitmap_int).count("1"),
                    "uptime_bitmap": payload.get("uptime_bitmap"),
                    "repair_count": len(payload.get("repair_log", [])),
                    "sample_index": payload.get("sample_index"),
                })
            elif kind == "RegisterMobileNode":
                summary.update({
                    "pubkey_hex": payload.get("pubkey_hex", "")[:16],
                    "p2p_addr": payload.get("p2p_addr"),
                    "stake": payload.get("stake"),
                })
            elif kind == "DepositStorageBounty":
                summary.update({
                    "swarm_id": payload.get("swarm_id"),
                    "amount": payload.get("amount"),
                })
            elif kind == "SubmitHeartbeatFaultProof":
                summary.update({
                    "swarm_id": payload.get("swarm_id"),
                    "epoch": payload.get("epoch"),
                    "node_slot": payload.get("node_slot"),
                    "aggregator_slot": payload.get("aggregator_slot"),
                })
            if i < len(receipts):
                summary["receipt"] = receipts[i]
            details.append(summary)
    return {
        "height": hdr.get("height"),
        "block_hash_hex": b.get("block_hash_hex", ""),
        "prev_hash_hex": hdr.get("prev_hash_hex", ""),
        "proposer_id": hdr.get("proposer_id"),
        "tx_count": hdr.get("tx_count", len(txs)),
        "state_root_hex": hdr.get("state_root_hex", ""),
        "precommits": len(b.get("precommits", [])),
        "tx_kinds": tx_kinds,
        "details": details,
        "receipts": receipts,
    }


def collect_overview():
    rpcs = CONFIG["l1_rpcs"]
    with ThreadPoolExecutor(max_workers=max(1, len(rpcs))) as pool:
        val_results = list(pool.map(probe_validator, list(enumerate(rpcs))))

    primary_status = None
    for v in val_results:
        if v.get("online") and "_status" in v:
            primary_status = v["_status"]
            break

    clean_validators = [
        {k: val for k, val in v.items() if k != "_status"}
        for v in val_results
    ]

    nodes_raw = primary_status.get("nodes", []) if primary_status else []
    with ThreadPoolExecutor(max_workers=16) as pool:
        node_results = list(pool.map(probe_storage_node, nodes_raw))

    nodes_by_pk = {n["pubkey_hex"].lower(): n for n in node_results}

    manifests_by_obj = {}
    object_registry = load_object_registry()
    for n in node_results:
        for m in n.pop("manifests", []):
            obj_id = (m.get("object_id_hex") or "").lower()
            if not obj_id:
                continue
            object_registry.setdefault(obj_id, "")
            entry = manifests_by_obj.get(obj_id)
            if not entry:
                manifests_by_obj[obj_id] = {
                    "object_id_hex": obj_id,
                    "filename": object_registry.get(obj_id, ""),
                    "swarm_id": m.get("swarm_id"),
                    "root_hex": m.get("root_hex"),
                    "custodian_owners": m.get("custodian_owners", {}),
                    "slot_generations": m.get("slot_generations", {}),
                    "seen_on_nodes": 1,
                }
            else:
                entry["seen_on_nodes"] += 1

    # Query /manifest/<object_id> on online nodes for objects not returned by single /manifest
    extra_queries = []
    for n in node_results:
        if n.get("online") and n.get("rpc_addr"):
            for obj_id in object_registry.keys():
                extra_queries.append((obj_id, n["rpc_addr"]))

    if extra_queries:
        def fetch_obj_manifest(item):
            obj_id, rpc_addr = item
            try:
                m, _ = http_get_json(f"http://{rpc_addr}/manifest/{obj_id}", timeout=0.8)
                return obj_id, rpc_addr, m
            except Exception:
                return obj_id, rpc_addr, None

        with ThreadPoolExecutor(max_workers=16) as pool:
            fetched = list(pool.map(fetch_obj_manifest, extra_queries))
        counts = {}
        sample_manifest = {}
        for obj_id, _, m in fetched:
            if m and m.get("object_id_hex"):
                counts[obj_id] = counts.get(obj_id, 0) + 1
                sample_manifest.setdefault(obj_id, m)
        for obj_id, m in sample_manifest.items():
            manifests_by_obj[obj_id] = {
                "object_id_hex": obj_id,
                "filename": object_registry.get(obj_id, ""),
                "swarm_id": m.get("swarm_id"),
                "root_hex": m.get("root_hex"),
                "custodian_owners": m.get("custodian_owners", {}),
                "slot_generations": m.get("slot_generations", {}),
                "seen_on_nodes": counts.get(obj_id, 1),
            }

    if object_registry:
        save_object_registry(object_registry)

    swarms_view = []
    roster_pks_all = set()
    total_bounty_pool = 0
    total_active_slots = 0

    if primary_status:
        for sw in primary_status.get("swarms", []):
            st = sw.get("state", {})
            roster = sw.get("roster_pubkeys_hex", [])
            settlements = sw.get("recent_settlements", [])
            latest_agg = settlements[-1].get("aggregator_slot") if settlements else None
            total_bounty_pool += int(st.get("storage_bounty_pool", 0))
            total_active_slots += len(roster)

            custodian_map = {}
            generation_map = {}
            for m in manifests_by_obj.values():
                if m.get("swarm_id") == sw.get("swarm_id"):
                    for k, v in m.get("custodian_owners", {}).items():
                        custodian_map[str(k)] = v
                    for k, v in m.get("slot_generations", {}).items():
                        generation_map[str(k)] = v

            slots = []
            online_count = 0
            accessible_count = 0
            for idx, pk in enumerate(roster):
                roster_pks_all.add(pk.lower())
                nd = nodes_by_pk.get(pk.lower(), {})
                is_online = bool(nd.get("online", False))
                cust_slot = custodian_map.get(str(idx))
                cust_online = False
                if cust_slot is not None and 0 <= int(cust_slot) < len(roster):
                    cust_nd = nodes_by_pk.get(roster[int(cust_slot)].lower(), {})
                    cust_online = bool(cust_nd.get("online", False))
                if is_online:
                    online_count += 1
                if is_online or cust_online:
                    accessible_count += 1
                slots.append({
                    "slot": idx,
                    "pubkey_hex": pk,
                    "node_id": nd.get("node_id"),
                    "p2p_addr": nd.get("p2p_addr", ""),
                    "rpc_addr": nd.get("rpc_addr", ""),
                    "ip_subnet_hash": nd.get("ip_subnet_hash", 0),
                    "country_code": nd.get("country_code", 0),
                    "online": is_online,
                    "latency_ms": nd.get("latency_ms"),
                    "stake": nd.get("stake", 0),
                    "reward_balance": nd.get("reward_balance", 0),
                    "ema_uptime_bps": nd.get("ema_uptime_bps", 0),
                    "consecutive_offline_epochs": nd.get("consecutive_offline_epochs", 0),
                    "slashed": nd.get("slashed", False),
                    "is_aggregator": latest_agg == idx,
                    "custodian_slot": cust_slot,
                    "generation": generation_map.get(str(idx), 0),
                })

            member_root_hex = bytes(st.get("member_verkle_root", [])).hex()
            active_blobs_hex = bytes(st.get("active_blobs_root", [])).hex()
            swarms_view.append({
                "swarm_id": sw.get("swarm_id"),
                "state": {
                    "swarm_size_n": st.get("swarm_size_n"),
                    "min_threshold_k": st.get("min_threshold_k"),
                    "lazy_repair_trigger": st.get("lazy_repair_trigger"),
                    "lazy_repair_target": st.get("lazy_repair_target"),
                    "last_epoch_settled": st.get("last_epoch_settled"),
                    "total_bond_balance": st.get("total_bond_balance"),
                    "storage_bounty_pool": st.get("storage_bounty_pool"),
                    "member_verkle_root_hex": member_root_hex,
                    "active_blobs_root_hex": active_blobs_hex,
                },
                "online_count": online_count,
                "accessible_count": accessible_count,
                "latest_aggregator_slot": latest_agg,
                "recent_settlements": settlements[-10:],
                "slots": slots,
            })

    standby_nodes = [n for n in node_results if n["pubkey_hex"].lower() not in roster_pks_all]
    slashed_count = sum(1 for n in node_results if n.get("slashed"))
    total_stake = sum(int(n.get("stake", 0)) for n in node_results)
    total_rewards = sum(int(n.get("reward_balance", 0)) for n in node_results)

    raw_blocks, total_blocks = read_wal_blocks(CONFIG["wal_path"], limit=80)
    blocks = [summarize_block(b) for b in raw_blocks]

    online_vals = [v for v in clean_validators if v.get("online")]
    consensus_hashes = set(v.get("last_block_hash_hex", "") for v in online_vals)
    quorum_needed = (len(clean_validators) * 2) // 3 + 1 if clean_validators else 1

    return {
        "timestamp": int(time.time()),
        "chain_id": primary_status.get("chain_id", 0) if primary_status else 0,
        "height": primary_status.get("height", 0) if primary_status else 0,
        "last_block_hash_hex": primary_status.get("last_block_hash_hex", "") if primary_status else "",
        "epoch_seed_hex": primary_status.get("epoch_seed_hex", "") if primary_status else "",
        "registered_nodes": primary_status.get("registered_nodes", 0) if primary_status else 0,
        "swarm_count": primary_status.get("swarm_count", 0) if primary_status else 0,
        "total_active_slots": total_active_slots,
        "total_bounty_pool": total_bounty_pool,
        "total_stake": total_stake,
        "total_rewards": total_rewards,
        "slashed_nodes": slashed_count,
        "validators": clean_validators,
        "validators_online": len(online_vals),
        "quorum_needed": quorum_needed,
        "consensus_synced": len(consensus_hashes) <= 1 and len(online_vals) >= quorum_needed,
        "swarms": swarms_view,
        "standby_nodes": standby_nodes,
        "objects": list(manifests_by_obj.values()),
        "total_wal_blocks": total_blocks,
        "blocks": blocks,
    }


def get_block_by_height(height):
    wal_path = CONFIG["wal_path"]
    if not wal_path or not os.path.exists(wal_path):
        return None
    with open(wal_path, "r", encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            try:
                b = json.loads(ln)
                if b.get("header", {}).get("height") == height:
                    return b
            except Exception:
                continue
    return None


HTML_PAGE = r"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>DePIN Mobile L1 Explorer</title>
<style>
  :root {
    --bg: #0b1020;
    --panel: #121933;
    --panel2: #172042;
    --border: #243056;
    --text: #e6ecf8;
    --muted: #8fa0c9;
    --accent: #38bdf8;
    --green: #34d399;
    --amber: #fbbf24;
    --red: #f87171;
    --purple: #a78bfa;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Noto Sans KR", sans-serif;
    background: radial-gradient(circle at top right, #16224a 0%, var(--bg) 55%);
    color: var(--text); min-height: 100vh;
  }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  header {
    padding: 16px 26px; border-bottom: 1px solid var(--border);
    display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 14px;
    background: rgba(11, 16, 32, 0.88); backdrop-filter: blur(8px); position: sticky; top: 0; z-index: 20;
  }
  .brand { display: flex; align-items: center; gap: 12px; }
  .logo {
    width: 36px; height: 36px; border-radius: 10px;
    background: linear-gradient(135deg, var(--accent), var(--purple));
    display: grid; place-items: center; font-weight: 800; color: #071124; font-size: 15px;
  }
  .brand h1 { margin: 0; font-size: 18px; letter-spacing: -0.3px; }
  .brand small { color: var(--muted); font-size: 12px; }
  .header-right { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .pill {
    display: inline-flex; align-items: center; gap: 6px; padding: 6px 12px;
    border-radius: 999px; font-size: 12px; border: 1px solid var(--border); background: var(--panel);
  }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--green); box-shadow: 0 0 8px var(--green); }
  .dot.warn { background: var(--amber); box-shadow: 0 0 8px var(--amber); }
  .dot.off { background: var(--red); box-shadow: none; }
  main { max-width: 1440px; margin: 0 auto; padding: 20px 24px 56px; display: flex; flex-direction: column; gap: 18px; }
  .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 14px; }
  .stat-card {
    background: var(--panel); border: 1px solid var(--border); border-radius: 14px; padding: 14px 18px;
  }
  .stat-label { font-size: 12px; color: var(--muted); margin-bottom: 6px; }
  .stat-value { font-size: 22px; font-weight: 700; letter-spacing: -0.4px; }
  .stat-sub { font-size: 12px; color: var(--muted); margin-top: 5px; }
  .section {
    background: var(--panel); border: 1px solid var(--border); border-radius: 16px; padding: 18px 20px;
  }
  .section-head {
    display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 10px;
    margin-bottom: 14px;
  }
  .section-title { font-size: 15px; font-weight: 700; display: flex; align-items: center; gap: 8px; }
  .val-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px; }
  .val-card {
    background: var(--panel2); border: 1px solid var(--border); border-radius: 12px; padding: 13px 15px;
    display: flex; flex-direction: column; gap: 6px;
  }
  .val-top { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
  .badge {
    font-size: 11px; padding: 2px 8px; border-radius: 999px; font-weight: 600;
    border: 1px solid rgba(255,255,255,0.12);
  }
  .badge-ok { background: rgba(52, 211, 153, 0.14); color: var(--green); border-color: rgba(52, 211, 153, 0.35); }
  .badge-off { background: rgba(248, 113, 113, 0.14); color: var(--red); border-color: rgba(248, 113, 113, 0.35); }
  .badge-info { background: rgba(56, 189, 248, 0.14); color: var(--accent); border-color: rgba(56, 189, 248, 0.35); }
  .badge-purple { background: rgba(167, 139, 250, 0.16); color: var(--purple); border-color: rgba(167, 139, 250, 0.35); }
  .badge-amber { background: rgba(251, 191, 36, 0.16); color: var(--amber); border-color: rgba(251, 191, 36, 0.35); }
  .gauge-wrap {
    background: var(--panel2); border: 1px solid var(--border); border-radius: 12px; padding: 14px 16px; margin-bottom: 14px;
  }
  .gauge-bar {
    position: relative; height: 18px; background: #0c1328; border-radius: 999px; overflow: hidden;
    border: 1px solid var(--border); margin: 10px 0 8px;
  }
  .gauge-fill {
    height: 100%; background: linear-gradient(90deg, #38bdf8, #34d399); transition: width 0.35s ease;
  }
  .gauge-fill.danger { background: linear-gradient(90deg, #f87171, #fbbf24); }
  .gauge-marker {
    position: absolute; top: 0; bottom: 0; width: 2px; background: #fff; opacity: 0.85;
  }
  .slots-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(235px, 1fr)); gap: 11px; }
  .slot-card {
    background: var(--panel2); border: 1px solid var(--border); border-radius: 12px; padding: 12px 14px;
    display: flex; flex-direction: column; gap: 5px;
  }
  .slot-card.offline { opacity: 0.62; border-color: rgba(248, 113, 113, 0.45); }
  .slot-card.agg { border-color: rgba(251, 191, 36, 0.7); box-shadow: 0 0 0 1px rgba(251, 191, 36, 0.25); }
  .kv { display: flex; justify-content: space-between; font-size: 12px; color: var(--muted); gap: 8px; }
  .kv strong { color: var(--text); font-weight: 600; }
  .two-col { display: grid; grid-template-columns: 1fr 1.45fr; gap: 18px; }
  @media (max-width: 1050px) { .two-col { grid-template-columns: 1fr; } }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--border); vertical-align: middle; }
  th { color: var(--muted); font-weight: 600; font-size: 12px; }
  tr.clickable:hover { background: rgba(56, 189, 248, 0.08); cursor: pointer; }
  button {
    background: linear-gradient(135deg, #0284c7, #2563eb); color: #fff; border: none;
    border-radius: 8px; padding: 8px 13px; font-size: 12px; font-weight: 600; cursor: pointer;
  }
  button:hover { filter: brightness(1.1); }
  button.secondary { background: var(--panel2); border: 1px solid var(--border); color: var(--text); }
  input[type="text"], input[type="file"], select {
    background: #0c1328; border: 1px solid var(--border); color: var(--text);
    border-radius: 8px; padding: 7px 10px; font-size: 12px;
  }
  .modal-bg {
    position: fixed; inset: 0; background: rgba(4, 7, 17, 0.75); display: none;
    align-items: center; justify-content: center; padding: 20px; z-index: 50;
  }
  .modal-bg.open { display: flex; }
  .modal {
    background: var(--panel); border: 1px solid var(--border); border-radius: 16px;
    max-width: 880px; width: 100%; max-height: 85vh; display: flex; flex-direction: column;
  }
  .modal-head {
    padding: 14px 18px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center;
  }
  .modal-body { padding: 16px 18px; overflow: auto; }
  pre {
    background: #090e1c; border: 1px solid var(--border); border-radius: 10px; padding: 12px;
    overflow: auto; font-size: 12px; line-height: 1.45; margin: 0; color: #cbd5e1;
  }
  .upload-box {
    background: var(--panel2); border: 1px dashed var(--border); border-radius: 12px; padding: 13px;
    display: flex; flex-direction: column; gap: 9px; margin-bottom: 14px;
  }
  .header-meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 8px; margin-bottom: 12px; }
  .meta-chip { background: #0c1328; border: 1px solid var(--border); border-radius: 8px; padding: 8px 10px; font-size: 12px; }
  .tabs { display: flex; gap: 8px; flex-wrap: wrap; }
  .tab { padding: 5px 12px; border-radius: 8px; background: var(--panel2); border: 1px solid var(--border); color: var(--muted); cursor: pointer; font-size: 12px; }
  .tab.active { color: var(--text); border-color: var(--accent); background: rgba(56, 189, 248, 0.14); }
</style>
</head>
<body>
<header>
  <div class="brand">
    <div class="logo">DL1</div>
    <div>
      <h1>DePIN Mobile L1 — Block &amp; Swarm Explorer</h1>
      <small>On-Chain Consensus, Virtual Swarms &amp; Storage State</small>
    </div>
  </div>
  <div class="header-right">
    <span class="pill"><span id="syncDot" class="dot"></span><span id="syncText">Connecting...</span></span>
    <span class="pill mono">Chain <strong id="chainId">-</strong></span>
    <span class="pill mono" id="lastUpdated">--:--:--</span>
    <button class="secondary" onclick="refreshAll()">새로고침</button>
  </div>
</header>

<main>
  <section class="stats-grid">
    <div class="stat-card">
      <div class="stat-label">Block Height</div>
      <div class="stat-value mono" id="statHeight">-</div>
      <div class="stat-sub mono" id="statHash">-</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Validators</div>
      <div class="stat-value mono" id="statValidators">-</div>
      <div class="stat-sub" id="statQuorumSub">-</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Swarms</div>
      <div class="stat-value mono" id="statSwarms">-</div>
      <div class="stat-sub" id="statSwarmsSub">-</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Storage Nodes</div>
      <div class="stat-value mono" id="statNodes">-</div>
      <div class="stat-sub" id="statNodesSub">-</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Stake / Bounty Pool</div>
      <div class="stat-value mono" id="statStake">-</div>
      <div class="stat-sub mono" id="statBounty">-</div>
    </div>
  </section>

  <section class="section">
    <div class="section-head">
      <div class="section-title">Validators</div>
      <span class="badge badge-info mono" id="walCount">WAL: - blocks</span>
    </div>
    <div class="val-grid" id="validatorsGrid"></div>
  </section>

  <section class="section">
    <div class="section-head">
      <div class="section-title">Virtual Swarms</div>
      <div class="tabs" id="swarmTabs"></div>
    </div>
    <div id="swarmsContainer"></div>
  </section>

  <div class="two-col">
    <section class="section">
      <div class="section-head">
        <div class="section-title">Objects &amp; Verification</div>
      </div>
      <div class="upload-box">
        <div style="font-size:13px;font-weight:600;">Upload &amp; Download Object</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;">
          <input type="file" id="uploadFileInput" style="flex:1;min-width:180px;" />
          <button onclick="uploadSelectedFile()">파일 업로드</button>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;">
          <input type="text" id="uploadTextInput" placeholder="테스트 텍스트 입력..." style="flex:1;min-width:180px;" />
          <button class="secondary" onclick="uploadQuickText()">텍스트 업로드</button>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;">
          <input type="text" id="directObjectId" placeholder="Object ID (64-hex) 입력..." class="mono" style="flex:1;min-width:180px;" />
          <button onclick="downloadByInput()">체인에서 다운로드</button>
        </div>
        <div id="uploadStatus" class="mono" style="font-size:12px;color:var(--muted);"></div>
      </div>
      <div id="objectsList"></div>
      <div id="downloadResult" style="margin-top:12px;"></div>
    </section>

    <section class="section">
      <div class="section-head">
        <div class="section-title">Blocks</div>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
          <select id="txTypeFilter" onchange="renderBlocksOnly()">
            <option value="">All Tx Types</option>
            <option value="SubmitSwarmCheckpoint">SubmitSwarmCheckpoint</option>
            <option value="RegisterMobileNode">RegisterMobileNode</option>
            <option value="DepositStorageBounty">DepositStorageBounty</option>
            <option value="SubmitHeartbeatFaultProof">SubmitHeartbeatFaultProof</option>
            <option value="TriggerShuffle">TriggerShuffle</option>
          </select>
          <input type="text" id="blockSearch" placeholder="Height / Hash 검색" style="width:155px;" oninput="renderBlocksOnly()" />
        </div>
      </div>
      <div style="overflow-x:auto;">
        <table>
          <thead>
            <tr>
              <th>Height</th>
              <th>Block Hash</th>
              <th>Proposer</th>
              <th>Transaction</th>
              <th>Precommits</th>
            </tr>
          </thead>
          <tbody id="blocksTbody"></tbody>
        </table>
      </div>
    </section>
  </div>
</main>

<div class="modal-bg" id="blockModal" onclick="if(event.target===this) closeModal()">
  <div class="modal">
    <div class="modal-head">
      <strong class="mono" id="modalTitle">Block Detail</strong>
      <button class="secondary" onclick="closeModal()">닫기</button>
    </div>
    <div class="modal-body">
      <pre id="modalJson" class="mono"></pre>
    </div>
  </div>
</div>

<script>
let lastData = null;
let selectedSwarmId = null;

const shortHex = (h, n=10) => !h ? "-" : (h.length <= n*2 ? h : h.slice(0, n) + "…" + h.slice(-6));
const escapeHtml = (s) => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

function selectSwarm(id) {
  selectedSwarmId = id;
  if (lastData) renderSwarms(lastData);
}

function renderSwarms(data) {
  const tabsEl = document.getElementById("swarmTabs");
  const contEl = document.getElementById("swarmsContainer");
  if (!data.swarms || data.swarms.length === 0) {
    tabsEl.innerHTML = "";
    contEl.innerHTML = `<div style="color:var(--muted);">편성된 가상 스웜이 없습니다.</div>`;
    return;
  }
  if (selectedSwarmId === null || !data.swarms.some(s => s.swarm_id === selectedSwarmId)) {
    selectedSwarmId = data.swarms[0].swarm_id;
  }
  tabsEl.innerHTML = data.swarms.map(s => `
    <span class="tab mono ${s.swarm_id === selectedSwarmId ? 'active' : ''}" onclick="selectSwarm(${s.swarm_id})">
      Swarm #${s.swarm_id} (n=${s.state.swarm_size_n}, e=${s.state.last_epoch_settled})
    </span>
  `).join("");

  const sw = data.swarms.find(s => s.swarm_id === selectedSwarmId) || data.swarms[0];
  const st = sw.state;
  const n = st.swarm_size_n || 1;
  const k = st.min_threshold_k || 1;
  const trig = st.lazy_repair_trigger || 0;
  const targ = st.lazy_repair_target || 0;
  const acc = sw.accessible_count;
  const pct = Math.min(100, Math.round((acc / n) * 100));
  const trigPct = Math.round((trig / n) * 100);
  const kPct = Math.round((k / n) * 100);
  const inRepairZone = acc <= trig;

  const slotsHtml = sw.slots.map(s => {
    const cls = "slot-card " + (s.online ? "" : "offline ") + (s.is_aggregator ? "agg" : "");
    return `
      <div class="${cls}">
        <div class="val-top">
          <strong>Slot #${s.slot} ${s.is_aggregator ? '👑' : ''}</strong>
          <span class="badge ${s.online ? 'badge-ok' : 'badge-off'}">${s.online ? ('ONLINE' + (s.latency_ms !== null ? ' · ' + s.latency_ms + 'ms' : '')) : 'OFFLINE'}</span>
        </div>
        <div style="display:flex;gap:5px;flex-wrap:wrap;">
          ${s.node_id !== null && s.node_id !== undefined ? `<span class="badge badge-info mono">node_id=${s.node_id}</span>` : ''}
          ${s.is_aggregator ? '<span class="badge badge-amber">Aggregator</span>' : ''}
          ${s.custodian_slot !== null && s.custodian_slot !== undefined ? `<span class="badge badge-purple">Custodian → #${s.custodian_slot}</span>` : ''}
          ${s.slashed ? '<span class="badge badge-off">Slashed</span>' : ''}
        </div>
        <div class="kv"><span>Pubkey</span><span class="mono">${shortHex(s.pubkey_hex, 6)}</span></div>
        <div class="kv"><span>P2P</span><span class="mono">${escapeHtml(s.p2p_addr || '-')}</span></div>
        <div class="kv"><span>Subnet / Country</span><span class="mono">${s.ip_subnet_hash} / ${s.country_code}</span></div>
        <div class="kv"><span>Stake / Reward</span><strong class="mono">${s.stake} / +${s.reward_balance}</strong></div>
        <div class="kv"><span>Uptime EMA / Gen</span><strong class="mono">${(s.ema_uptime_bps / 100).toFixed(1)}% · g${s.generation}</strong></div>
      </div>
    `;
  }).join("");

  const standbyHtml = data.standby_nodes.length === 0 ? "" : `
    <div style="margin-top:14px;">
      <div style="font-size:13px;font-weight:600;color:var(--muted);margin-bottom:8px;">Standby Pool (${data.standby_nodes.length})</div>
      <div class="slots-grid">
        ${data.standby_nodes.map(s => `
          <div class="slot-card ${s.online ? '' : 'offline'}">
            <div class="val-top">
              <strong>Standby ${s.node_id !== null && s.node_id !== undefined ? '(id=' + s.node_id + ')' : ''}</strong>
              <span class="badge ${s.online ? 'badge-ok' : 'badge-off'}">${s.online ? 'ONLINE' : 'OFFLINE'}</span>
            </div>
            <div class="kv"><span>Pubkey</span><span class="mono">${shortHex(s.pubkey_hex, 6)}</span></div>
            <div class="kv"><span>P2P</span><span class="mono">${escapeHtml(s.p2p_addr || '-')}</span></div>
            <div class="kv"><span>Subnet / Country</span><span class="mono">${s.ip_subnet_hash} / ${s.country_code}</span></div>
            <div class="kv"><span>Stake / Reward</span><strong class="mono">${s.stake} / +${s.reward_balance}</strong></div>
          </div>
        `).join("")}
      </div>
    </div>
  `;

  contEl.innerHTML = `
    <div class="gauge-wrap">
      <div style="display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;font-size:13px;">
        <div>
          <strong>Shard Availability:</strong>
          <span class="mono" style="color:${inRepairZone ? 'var(--amber)' : 'var(--green)'};font-weight:700;">${acc} / ${n}</span>
          (Online ${sw.online_count} · ${inRepairZone ? 'Repair Zone (≤ T_repair)' : 'Above T_repair'})
        </div>
        <div class="mono" style="color:var(--muted);">k=${k} · T_repair=${trig} · T_target=${targ}</div>
      </div>
      <div class="gauge-bar">
        <div class="gauge-fill ${inRepairZone ? 'danger' : ''}" style="width:${pct}%"></div>
        <div class="gauge-marker" style="left:${kPct}%" title="k=${k}"></div>
        <div class="gauge-marker" style="left:${trigPct}%;background:var(--amber);" title="T_repair=${trig}"></div>
      </div>
      <div class="header-meta-grid">
        <div class="meta-chip"><span style="color:var(--muted)">member_verkle_root</span><br/><span class="mono">${shortHex(st.member_verkle_root_hex, 12)}</span></div>
        <div class="meta-chip"><span style="color:var(--muted)">active_blobs_root</span><br/><span class="mono">${shortHex(st.active_blobs_root_hex, 12)}</span></div>
        <div class="meta-chip"><span style="color:var(--muted)">Last Epoch Settled</span><br/><strong class="mono">Epoch #${st.last_epoch_settled} (Agg #${sw.latest_aggregator_slot ?? '-'})</strong></div>
        <div class="meta-chip"><span style="color:var(--muted)">Bond / Bounty Pool</span><br/><strong class="mono">${st.total_bond_balance} / ${st.storage_bounty_pool}</strong></div>
      </div>
    </div>
    <div class="slots-grid">${slotsHtml}</div>
    ${standbyHtml}
  `;
}

function renderBlocksOnly() {
  if (!lastData) return;
  const filterKind = document.getElementById("txTypeFilter").value;
  const search = document.getElementById("blockSearch").value.trim().toLowerCase();
  const filtered = lastData.blocks.filter(b => {
    const first = b.details[0] || {};
    const kind = first.kind || (b.tx_kinds[0] || "Empty");
    if (filterKind && kind !== filterKind) return false;
    if (search) {
      const hay = `${b.height} ${b.block_hash_hex} ${kind}`.toLowerCase();
      if (!hay.includes(search)) return false;
    }
    return true;
  });

  document.getElementById("blocksTbody").innerHTML = filtered.map(b => {
    const first = b.details[0] || {};
    const kind = first.kind || (b.tx_kinds[0] || "Empty");
    let desc = "";
    let badgeCls = "badge-info";
    if (kind === "SubmitSwarmCheckpoint") {
      badgeCls = first.repair_count > 0 ? "badge-amber" : "badge-ok";
      desc = `Swarm #${first.swarm_id} · Epoch #${first.epoch} · Agg #${first.aggregator_slot} · Online ${first.online_count} · Repairs ${first.repair_count}`;
    } else if (kind === "RegisterMobileNode") {
      badgeCls = "badge-purple";
      desc = `${first.p2p_addr || ''} · Stake ${first.stake || ''}`;
    } else if (kind === "DepositStorageBounty") {
      desc = `Swarm #${first.swarm_id} · +${first.amount}`;
    } else if (kind === "SubmitHeartbeatFaultProof") {
      badgeCls = "badge-off";
      desc = `Epoch #${first.epoch} · Slot #${first.node_slot} vs Agg #${first.aggregator_slot}`;
    }
    return `
      <tr class="clickable" onclick="openBlock(${b.height})">
        <td class="mono"><strong>#${b.height}</strong></td>
        <td class="mono">${shortHex(b.block_hash_hex, 8)}</td>
        <td class="mono">Val #${b.proposer_id}</td>
        <td><span class="badge ${badgeCls}">${escapeHtml(kind)}</span> <span style="font-size:12px;color:var(--muted);">${escapeHtml(desc)}</span></td>
        <td class="mono">${b.precommits}</td>
      </tr>
    `;
  }).join("");
}

function renderOverview(data) {
  lastData = data;
  document.getElementById("chainId").textContent = data.chain_id || "-";
  document.getElementById("lastUpdated").textContent = new Date(data.timestamp * 1000).toLocaleTimeString();

  const dot = document.getElementById("syncDot");
  const syncText = document.getElementById("syncText");
  if (data.consensus_synced) {
    dot.className = "dot";
    syncText.textContent = "Consensus Synced";
  } else if (data.validators_online > 0) {
    dot.className = "dot warn";
    syncText.textContent = "Degraded / Syncing";
  } else {
    dot.className = "dot off";
    syncText.textContent = "Offline";
  }

  document.getElementById("statHeight").textContent = "#" + data.height;
  document.getElementById("statHash").textContent = shortHex(data.last_block_hash_hex, 12);
  document.getElementById("statValidators").textContent = data.validators_online + " / " + data.validators.length;
  document.getElementById("statQuorumSub").textContent = "Quorum >= " + data.quorum_needed;
  document.getElementById("statSwarms").textContent = data.swarm_count;
  document.getElementById("statSwarmsSub").textContent = "Assigned Slots " + data.total_active_slots;
  document.getElementById("statNodes").textContent = data.registered_nodes;
  document.getElementById("statNodesSub").textContent = "Standby " + data.standby_nodes.length + " · Slashed " + data.slashed_nodes;
  document.getElementById("statStake").textContent = String(data.total_stake);
  document.getElementById("statBounty").textContent = "Bounty " + data.total_bounty_pool + " · Rewards " + data.total_rewards;
  document.getElementById("walCount").textContent = "WAL: " + data.total_wal_blocks + " blocks";

  document.getElementById("validatorsGrid").innerHTML = data.validators.map(v => `
    <div class="val-card">
      <div class="val-top">
        <strong>Validator #${v.id !== null ? v.id : v.index}</strong>
        <span class="badge ${v.online ? 'badge-ok' : 'badge-off'}">${v.online ? 'ONLINE · ' + v.latency_ms + 'ms' : 'OFFLINE'}</span>
      </div>
      <div class="kv"><span>RPC</span><strong class="mono">${escapeHtml(v.rpc.replace('http://',''))}</strong></div>
      <div class="kv"><span>Height</span><strong class="mono">#${v.height !== null ? v.height : '-'}</strong></div>
      <div class="kv"><span>Last Hash</span><strong class="mono">${shortHex(v.last_block_hash_hex, 8)}</strong></div>
    </div>
  `).join("");

  renderSwarms(data);

  if (data.objects.length === 0) {
    document.getElementById("objectsList").innerHTML = `<div style="color:var(--muted);font-size:13px;">업로드된 객체가 없습니다.</div>`;
  } else {
    document.getElementById("objectsList").innerHTML = `
      <table>
        <thead><tr><th>Object ID</th><th>KZG Root</th><th>Swarm</th><th>Nodes</th><th>Actions</th></tr></thead>
        <tbody>
          ${data.objects.map(o => `
            <tr>
              <td class="mono">${shortHex(o.object_id_hex, 8)}${o.filename ? `<br/><span style="font-size:11px;color:var(--muted);">${escapeHtml(o.filename)}</span>` : ''}</td>
              <td class="mono">${shortHex(o.root_hex, 6)}</td>
              <td class="mono">#${o.swarm_id}</td>
              <td class="mono">${o.seen_on_nodes}</td>
              <td style="display:flex;gap:6px;flex-wrap:wrap;">
                <button onclick="downloadFile('${o.object_id_hex}')">다운로드</button>
                <button class="secondary" onclick="verifyDownload('${o.object_id_hex}')">검증</button>
              </td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    `;
  }

  renderBlocksOnly();
}

async function refreshAll() {
  try {
    const resp = await fetch("/api/overview");
    const data = await resp.json();
    renderOverview(data);
  } catch (err) {
    document.getElementById("syncDot").className = "dot off";
    document.getElementById("syncText").textContent = "Explorer Error";
  }
}

async function openBlock(height) {
  const modal = document.getElementById("blockModal");
  document.getElementById("modalTitle").textContent = "Block #" + height;
  document.getElementById("modalJson").textContent = "Loading...";
  modal.classList.add("open");
  const resp = await fetch("/api/block?height=" + height);
  const data = await resp.json();
  document.getElementById("modalJson").textContent = JSON.stringify(data, null, 2);
}

function closeModal() {
  document.getElementById("blockModal").classList.remove("open");
}

async function doUpload(filename, base64Content) {
  const statusEl = document.getElementById("uploadStatus");
  statusEl.textContent = "Uploading...";
  const resp = await fetch("/api/upload", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({filename, content_base64: base64Content, bounty: 5000}),
  });
  const data = await resp.json();
  if (data.ok) {
    statusEl.textContent = `Uploaded: block=#${data.block_height} object_id=${data.object_id_hex}`;
    refreshAll();
  } else {
    statusEl.textContent = "Error: " + (data.error || "unknown error");
  }
}

function uploadSelectedFile() {
  const input = document.getElementById("uploadFileInput");
  if (!input.files || input.files.length === 0) return;
  const file = input.files[0];
  const reader = new FileReader();
  reader.onload = () => {
    const b64 = reader.result.split(",")[1];
    doUpload(file.name, b64);
  };
  reader.readAsDataURL(file);
}

function uploadQuickText() {
  const txt = document.getElementById("uploadTextInput").value.trim();
  if (!txt) return;
  const bytes = new TextEncoder().encode(txt);
  let bin = "";
  bytes.forEach(b => bin += String.fromCharCode(b));
  doUpload("note.txt", btoa(bin));
}

function downloadFile(objectId) {
  window.location.href = "/api/download_file?object_id=" + encodeURIComponent(objectId);
}

function downloadByInput() {
  const val = document.getElementById("directObjectId").value.trim();
  if (!/^[0-9a-fA-F]{64}$/.test(val)) {
    document.getElementById("uploadStatus").textContent = "Error: 64자리 hex Object ID를 입력하세요.";
    return;
  }
  downloadFile(val);
}

async function verifyDownload(objectId) {
  const el = document.getElementById("downloadResult");
  el.innerHTML = `<div class="meta-chip mono">Downloading &amp; decoding (${shortHex(objectId, 10)})...</div>`;
  const resp = await fetch("/api/download?object_id=" + encodeURIComponent(objectId));
  const data = await resp.json();
  if (data.ok) {
    const match = data.sha256.toLowerCase() === objectId.toLowerCase();
    el.innerHTML = `
      <div class="meta-chip">
        <div><strong>${match ? 'SHA-256 Verified' : 'Hash Mismatch'}</strong></div>
        <div class="mono" style="margin-top:4px;">bytes=${data.bytes} · shards_collected=${data.shards_collected} · sha256=${data.sha256}</div>
        ${data.preview_utf8 ? `<div style="margin-top:6px;color:var(--muted);">preview: <span class="mono">${escapeHtml(data.preview_utf8)}</span></div>` : ''}
      </div>
    `;
  } else {
    el.innerHTML = `<div class="meta-chip" style="color:var(--red);">Failed: ${escapeHtml(data.error || '')}</div>`;
  }
}

refreshAll();
setInterval(refreshAll, 2000);
</script>
</body>
</html>
"""


class ExplorerHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def send_json(self, code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html):
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/":
            self.send_html(HTML_PAGE)
        elif parsed.path == "/api/overview":
            self.send_json(200, collect_overview())
        elif parsed.path == "/api/block":
            qs = urllib.parse.parse_qs(parsed.query)
            try:
                height = int(qs.get("height", ["0"])[0])
            except ValueError:
                self.send_json(400, {"error": "invalid height"})
                return
            block = get_block_by_height(height)
            if block is None:
                self.send_json(404, {"error": "block not found"})
            else:
                self.send_json(200, block)
        elif parsed.path == "/api/download":
            qs = urllib.parse.parse_qs(parsed.query)
            obj_id = qs.get("object_id", [""])[0].strip()
            if not re.fullmatch(r"[0-9a-fA-F]{64}", obj_id):
                self.send_json(400, {"ok": False, "error": "invalid object_id"})
                return
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                out_path = tmp.name
            try:
                proc = subprocess.run(
                    [
                        CONFIG["cli_bin"],
                        "download",
                        "--l1-rpc",
                        ",".join(CONFIG["l1_rpcs"]),
                        "--object-id",
                        obj_id,
                        "--out",
                        out_path,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if proc.returncode != 0:
                    self.send_json(500, {"ok": False, "error": proc.stderr or proc.stdout})
                    return
                with open(out_path, "rb") as f:
                    raw = f.read()
                sha = hashlib.sha256(raw).hexdigest()
                m = re.search(r"shards_collected=(\d+)", proc.stdout)
                shards_collected = int(m.group(1)) if m else 0
                preview = ""
                try:
                    txt = raw[:240].decode("utf-8")
                    if all(ch.isprintable() or ch in "\r\n\t" for ch in txt):
                        preview = txt
                except Exception:
                    pass
                self.send_json(200, {
                    "ok": True,
                    "bytes": len(raw),
                    "shards_collected": shards_collected,
                    "sha256": sha,
                    "preview_utf8": preview,
                })
            finally:
                if os.path.exists(out_path):
                    os.remove(out_path)
        elif parsed.path == "/api/download_file":
            qs = urllib.parse.parse_qs(parsed.query)
            obj_id = qs.get("object_id", [""])[0].strip().lower()
            if not re.fullmatch(r"[0-9a-f]{64}", obj_id):
                self.send_json(400, {"ok": False, "error": "invalid object_id"})
                return
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                out_path = tmp.name
            try:
                proc = subprocess.run(
                    [
                        CONFIG["cli_bin"],
                        "download",
                        "--l1-rpc",
                        ",".join(CONFIG["l1_rpcs"]),
                        "--object-id",
                        obj_id,
                        "--out",
                        out_path,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if proc.returncode != 0:
                    self.send_json(500, {"ok": False, "error": proc.stderr or proc.stdout})
                    return
                with open(out_path, "rb") as f:
                    raw = f.read()
                reg = load_object_registry()
                fname = os.path.basename(reg.get(obj_id, ""))
                if not fname:
                    ext, mime = detect_extension_and_mime(raw)
                    fname = f"{obj_id[:12]}{ext}"
                    reg[obj_id] = fname
                    save_object_registry(reg)
                else:
                    mime = mimetypes.guess_type(fname)[0] or detect_extension_and_mime(raw)[1]
                ascii_name = re.sub(r"[^A-Za-z0-9._-]", "_", fname)
                utf8_name = urllib.parse.quote(fname)
                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(len(raw)))
                self.send_header(
                    "Content-Disposition",
                    f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{utf8_name}",
                )
                self.end_headers()
                self.wfile.write(raw)
            finally:
                if os.path.exists(out_path):
                    os.remove(out_path)
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/api/upload":
            self.send_json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > 8 * 1024 * 1024:
            self.send_json(400, {"ok": False, "error": "invalid payload size"})
            return
        body = json.loads(self.rfile.read(length).decode("utf-8"))
        raw = base64.b64decode(body.get("content_base64", ""))
        bounty = int(body.get("bounty", 5000))
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(raw)
            in_path = tmp.name
        try:
            proc = subprocess.run(
                [
                    CONFIG["cli_bin"],
                    "upload",
                    "--l1-rpc",
                    ",".join(CONFIG["l1_rpcs"]),
                    "--file",
                    in_path,
                    "--bounty",
                    str(bounty),
                    "--kzg-cache-dir",
                    CONFIG["kzg_cache"],
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if proc.returncode != 0:
                self.send_json(500, {"ok": False, "error": proc.stderr or proc.stdout})
                return
            out = json.loads(proc.stdout)
            obj_id = (out.get("object_id_hex") or "").lower()
            if obj_id:
                reg = load_object_registry()
                reg[obj_id] = os.path.basename(str(body.get("filename", "")))
                save_object_registry(reg)
            out["ok"] = True
            self.send_json(200, out)
        finally:
            if os.path.exists(in_path):
                os.remove(in_path)


def main():
    parser = argparse.ArgumentParser(description="DePIN Mobile L1 Explorer Server")
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=19080)
    parser.add_argument("--extra-port", type=int, default=0)
    parser.add_argument(
        "--l1-rpc",
        default=os.environ.get("DEPIN_L1_RPC", DEFAULT_L1_RPC),
        help="Comma-separated L1 validator RPC URLs",
    )
    parser.add_argument("--wal-path", default=CONFIG["wal_path"])
    parser.add_argument("--cli-bin", default=CONFIG["cli_bin"])
    parser.add_argument("--kzg-cache", default=CONFIG["kzg_cache"])
    parser.add_argument("--data-root", default=CONFIG["data_root"])
    args = parser.parse_args()

    CONFIG["l1_rpcs"] = [u.strip().rstrip("/") for u in args.l1_rpc.split(",") if u.strip()]
    CONFIG["wal_path"] = args.wal_path
    CONFIG["cli_bin"] = args.cli_bin
    CONFIG["kzg_cache"] = args.kzg_cache
    CONFIG["data_root"] = args.data_root
    CONFIG["objects_registry"] = os.path.join(args.data_root, "explorer_objects.json")

    if args.extra_port > 0 and args.extra_port != args.port:
        extra_server = ThreadingHTTPServer((args.bind, args.extra_port), ExplorerHandler)
        threading.Thread(target=extra_server.serve_forever, daemon=True).start()
        print(f"EXPLORER_EXTRA http://{args.bind}:{args.extra_port}", flush=True)

    server = ThreadingHTTPServer((args.bind, args.port), ExplorerHandler)
    print(f"EXPLORER_READY http://{args.bind}:{args.port} rpcs={len(CONFIG['l1_rpcs'])}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
