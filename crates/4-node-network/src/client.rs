use crate::storage_daemon::sorted_slot_keys;
use crate::wire::{
    decode_fixed_hex, http_request_json, send_p2p, FinalizedBlockDto, InitSwarmRequest,
    L1StatusDto, P2pRequest, P2pResponse, ShardDto, SlotAssignmentDto, SwarmClusterMapDto,
    SwarmManifestDto, TxDto,
};
use crate::{Error, Result};
use l1_state_engine::shuffler::{route_file_to_swarm, swarm_params};
use l1_state_engine::state_db::{
    compute_member_verkle_root, NativeTransaction, DEFAULT_UPTIME_BPS, MAX_SWARM_SIZE,
    MIN_SWARM_SIZE,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use tokio::task::JoinSet;
use verkle_fountain::fountain::{decode, encode, Shard};
use verkle_fountain::verkle_kzg::{scalar_to_bytes, Kzg, KzgProof, Scalar};

pub fn build_cluster_map(
    swarm_id: u64,
    chain_id: u64,
    node_endpoints: &[(u64, SocketAddr, SocketAddr)],
) -> Result<SwarmClusterMapDto> {
    let n = node_endpoints.len();
    if !(MIN_SWARM_SIZE..=MAX_SWARM_SIZE).contains(&n) {
        return Err(Error::Network(format!(
            "node count {n} must be within {MIN_SWARM_SIZE}..={MAX_SWARM_SIZE}"
        )));
    }
    let slots = sorted_slot_keys(n)
        .into_iter()
        .zip(node_endpoints)
        .enumerate()
        .map(|(slot, ((_, _, pk), &(node_id, p2p_addr, rpc_addr)))| SlotAssignmentDto {
            slot: slot as u8,
            node_id,
            p2p_addr: p2p_addr.to_string(),
            rpc_addr: rpc_addr.to_string(),
            pubkey_hex: hex::encode(pk),
        })
        .collect();
    Ok(SwarmClusterMapDto {
        swarm_id,
        chain_id,
        slots,
    })
}

pub fn slots_for_node(cluster_map: &SwarmClusterMapDto, node_id: u64) -> Vec<u8> {
    cluster_map
        .slots
        .iter()
        .filter(|s| s.node_id == node_id)
        .map(|s| s.slot)
        .collect()
}

pub async fn register_cluster_via_nodes(cluster_map: &SwarmClusterMapDto) -> Result<usize> {
    let mut seen_rpc = BTreeSet::new();
    let mut rpc_urls = Vec::new();
    for entry in &cluster_map.slots {
        if seen_rpc.insert(entry.rpc_addr.clone()) {
            rpc_urls.push(format!("http://{}", entry.rpc_addr));
        }
    }

    let mut total_txs = 0usize;
    for url in rpc_urls {
        let block: FinalizedBlockDto =
            http_request_json::<(), FinalizedBlockDto>(&url, "POST", "/register_slots", None)
                .await?;
        total_txs += block.header.tx_count;
    }
    Ok(total_txs)
}

pub async fn upload_payload(
    l1_rpc_url: &str,
    cluster_map: &SwarmClusterMapDto,
    kzg: &Kzg,
    payload: &[u8],
    initial_bounty: u128,
    seed: u64,
) -> Result<(SwarmManifestDto, Option<FinalizedBlockDto>)> {
    let status: L1StatusDto =
        http_request_json::<(), L1StatusDto>(l1_rpc_url, "GET", "/status", None).await?;
    let epoch_seed = decode_fixed_hex::<32>(&status.epoch_seed_hex)?;
    let object_id: [u8; 32] = Sha256::digest(payload).into();
    let target_swarm_id = route_file_to_swarm(&object_id, &epoch_seed, status.swarm_count.max(1))?;

    let target_swarm = if status.swarms.is_empty() {
        None
    } else {
        Some(
            status
                .swarms
                .iter()
                .find(|s| s.swarm_id == target_swarm_id)
                .unwrap_or_else(|| &status.swarms[(target_swarm_id as usize) % status.swarms.len()]),
        )
    };
    let roster_pubkeys_hex: Vec<String> = match target_swarm {
        Some(sw) => sw.roster_pubkeys_hex.clone(),
        None => cluster_map
            .slots
            .iter()
            .map(|s| s.pubkey_hex.clone())
            .collect(),
    };
    let ema_by_pubkey: BTreeMap<&str, u16> = status
        .nodes
        .iter()
        .map(|n| (n.pubkey_hex.as_str(), n.ema_uptime_bps))
        .collect();
    let n = roster_pubkeys_hex.len();
    let uptime_sum: u64 = roster_pubkeys_hex
        .iter()
        .map(|pk| u64::from(ema_by_pubkey.get(pk.as_str()).copied().unwrap_or(DEFAULT_UPTIME_BPS)))
        .sum();
    let params = swarm_params(n, (uptime_sum / n.max(1) as u64) as u16)?;

    let shards = encode(payload, params.k as usize, n, seed)?;
    let fps: Vec<Scalar> = shards.iter().map(|s| s.fingerprint()).collect();
    let root = kzg.commit(&fps)?;
    let proofs: Vec<KzgProof> = kzg.open_all(&fps)?;
    let root_hex = hex::encode(root);

    let (swarm_id, roster_pubkeys_opt, maybe_block) = if let Some(target_swarm) = target_swarm {
        let chosen_id = target_swarm.swarm_id;
        let block = if initial_bounty > 0 {
            let tx = TxDto::from_native(&NativeTransaction::DepositStorageBounty {
                swarm_id: chosen_id,
                amount: initial_bounty,
            });
            Some(
                http_request_json::<TxDto, FinalizedBlockDto>(
                    l1_rpc_url,
                    "POST",
                    "/tx/submit",
                    Some(&tx),
                )
                .await?,
            )
        } else {
            None
        };
        (chosen_id, Some(roster_pubkeys_hex), block)
    } else {
        let roster_pks: Vec<[u8; 33]> = roster_pubkeys_hex
            .iter()
            .map(|h| decode_fixed_hex::<33>(h))
            .collect::<Result<Vec<_>>>()?;
        let member_verkle_root = compute_member_verkle_root(kzg, &roster_pks)?;
        let init_req = InitSwarmRequest {
            swarm_id: cluster_map.swarm_id,
            roster_pubkeys_hex,
            member_verkle_root_hex: hex::encode(member_verkle_root),
            active_blobs_root_hex: root_hex.clone(),
            initial_bounty,
        };
        let block: FinalizedBlockDto =
            http_request_json(l1_rpc_url, "POST", "/swarm/init", Some(&init_req)).await?;
        (cluster_map.swarm_id, None, Some(block))
    };

    let manifest = SwarmManifestDto {
        swarm_id,
        object_id_hex: hex::encode(shards[0].object_id),
        root_hex,
        slot_fps_hex: fps
            .iter()
            .map(|s| hex::encode(scalar_to_bytes(s)))
            .collect(),
        slot_proofs_hex: proofs.iter().map(hex::encode).collect(),
        custodian_owners: BTreeMap::new(),
        slot_generations: BTreeMap::new(),
    };

    let pubkey_to_slot: BTreeMap<&str, &SlotAssignmentDto> = cluster_map
        .slots
        .iter()
        .map(|s| (s.pubkey_hex.as_str(), s))
        .collect();

    let mut target_p2p_addrs = Vec::with_capacity(shards.len());
    for slot_idx in 0..shards.len() {
        let slot_entry = roster_pubkeys_opt
            .as_ref()
            .and_then(|r| r.get(slot_idx))
            .and_then(|pk| pubkey_to_slot.get(pk.as_str()).copied())
            .or_else(|| cluster_map.slots.get(slot_idx))
            .ok_or_else(|| Error::Network("missing slot entry in cluster_map".into()))?;
        let addr: SocketAddr = slot_entry
            .p2p_addr
            .parse()
            .map_err(|_| Error::Network("invalid slot p2p addr".into()))?;
        target_p2p_addrs.push(addr);
    }

    let mut store_set = JoinSet::new();
    for (slot_idx, shard) in shards.iter().enumerate() {
        let addr = target_p2p_addrs[slot_idx];
        let dto = ShardDto::from_shard(shard);
        let proof_hex = manifest.slot_proofs_hex[slot_idx].clone();
        store_set.spawn(async move {
            let reply = send_p2p(
                addr,
                &P2pRequest::StoreShard {
                    slot: slot_idx as u8,
                    is_custodian: false,
                    generation: 0,
                    shard: dto,
                    proof_hex,
                },
            )
            .await?;
            match reply {
                P2pResponse::StoreAck { ok: true, .. } => Ok(()),
                other => Err(Error::Network(format!("StoreShard failed: {other:?}"))),
            }
        });
    }
    while let Some(res) = store_set.join_next().await {
        res.map_err(|e| Error::Network(e.to_string()))??;
    }

    let unique_p2p: BTreeSet<SocketAddr> = target_p2p_addrs.into_iter().collect();
    let mut manifest_set = JoinSet::new();
    for addr in unique_p2p {
        let m = manifest.clone();
        manifest_set.spawn(async move {
            let reply = send_p2p(addr, &P2pRequest::StoreManifest { manifest: m }).await?;
            match reply {
                P2pResponse::Ack { ok: true } => Ok(()),
                other => Err(Error::Network(format!("StoreManifest failed: {other:?}"))),
            }
        });
    }
    while let Some(res) = manifest_set.join_next().await {
        res.map_err(|e| Error::Network(e.to_string()))??;
    }

    Ok((manifest, maybe_block))
}

async fn fetch_live_manifest(
    cluster_map: &SwarmClusterMapDto,
    object_id_hex: &str,
    preferred_node_rpc: Option<&str>,
) -> Option<SwarmManifestDto> {
    let per_object_path = format!("/manifest/{object_id_hex}");
    if let Some(url) = preferred_node_rpc {
        if let Ok(m) =
            http_request_json::<(), SwarmManifestDto>(url, "GET", &per_object_path, None).await
        {
            return Some(m);
        }
    }
    let unique_rpc: BTreeSet<String> = cluster_map
        .slots
        .iter()
        .map(|s| format!("http://{}", s.rpc_addr))
        .collect();
    for url in &unique_rpc {
        if let Ok(m) =
            http_request_json::<(), SwarmManifestDto>(url, "GET", &per_object_path, None).await
        {
            return Some(m);
        }
    }
    if let Some(url) = preferred_node_rpc {
        if let Ok(m) = http_request_json::<(), SwarmManifestDto>(url, "GET", "/manifest", None).await
        {
            if m.object_id_hex.eq_ignore_ascii_case(object_id_hex) {
                return Some(m);
            }
        }
    }
    for url in unique_rpc {
        if let Ok(m) =
            http_request_json::<(), SwarmManifestDto>(&url, "GET", "/manifest", None).await
        {
            if m.object_id_hex.eq_ignore_ascii_case(object_id_hex) {
                return Some(m);
            }
        }
    }
    None
}

pub async fn download_payload(
    cluster_map: &SwarmClusterMapDto,
    object_id_hex: &str,
    preferred_node_rpc: Option<&str>,
) -> Result<(Vec<u8>, usize)> {
    let manifest = fetch_live_manifest(cluster_map, object_id_hex, preferred_node_rpc).await;
    let custodian_owners = manifest
        .as_ref()
        .map(|m| m.custodian_owners.clone())
        .unwrap_or_default();

    let mut fetch_targets: Vec<(u8, SocketAddr)> = Vec::new();
    for entry in &cluster_map.slots {
        if let Some(&cust_slot) = custodian_owners.get(&entry.slot) {
            if let Some(cust_entry) = cluster_map.slots.iter().find(|s| s.slot == cust_slot) {
                if let Ok(addr) = cust_entry.p2p_addr.parse::<SocketAddr>() {
                    fetch_targets.push((entry.slot, addr));
                }
            }
        }
        if let Ok(addr) = entry.p2p_addr.parse::<SocketAddr>() {
            fetch_targets.push((entry.slot, addr));
        }
    }

    let mut set = JoinSet::new();
    for (slot, addr) in fetch_targets {
        let obj = object_id_hex.to_string();
        set.spawn(async move {
            let reply = send_p2p(
                addr,
                &P2pRequest::FetchShard {
                    slot,
                    object_id_hex: obj,
                },
            )
            .await;
            (slot, reply)
        });
    }

    let mut collected_map: BTreeMap<u8, Shard> = BTreeMap::new();
    while let Some(res) = set.join_next().await {
        if let Ok((slot, Ok(P2pResponse::ShardData { found: true, shard: Some(dto), .. }))) = res {
            if let Ok(sh) = dto.to_shard() {
                collected_map.entry(slot).or_insert(sh);
            }
        }
    }

    let shards: Vec<Shard> = collected_map.into_values().collect();
    let count = shards.len();
    let recovered = decode(&shards)?;
    Ok((recovered, count))
}
