use crate::persistence::{compressed_pubkey, deterministic_signing_key};
use crate::storage_daemon::slot_key_seed;
use crate::wire::{
    decode_fixed_hex, http_request_json, send_p2p, FinalizedBlockDto, InitSwarmRequest, P2pRequest,
    P2pResponse, ShardDto, SlotAssignmentDto, SwarmClusterMapDto, SwarmManifestDto,
};
use crate::{Error, Result};
use l1_state_engine::state_db::{compute_member_verkle_root, SWARM_SIZE};
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
    if node_endpoints.is_empty() {
        return Err(Error::Network("node_endpoints cannot be empty".into()));
    }
    let mut slots = Vec::with_capacity(SWARM_SIZE);
    let n = node_endpoints.len();
    for slot in 0..SWARM_SIZE {
        let node_idx = (slot * n) / SWARM_SIZE;
        let (node_id, p2p_addr, rpc_addr) = node_endpoints[node_idx];
        let sk = deterministic_signing_key(slot_key_seed(slot as u8));
        let pk = compressed_pubkey(&sk);
        slots.push(SlotAssignmentDto {
            slot: slot as u8,
            node_id,
            p2p_addr: p2p_addr.to_string(),
            rpc_addr: rpc_addr.to_string(),
            pubkey_hex: hex::encode(pk),
        });
    }
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
) -> Result<(SwarmManifestDto, FinalizedBlockDto)> {
    let shards = encode(payload, 30, SWARM_SIZE, seed)?;
    let fps: Vec<Scalar> = shards.iter().map(|s| s.fingerprint()).collect();
    let root = kzg.commit(&fps)?;
    let proofs: Vec<KzgProof> = (0..SWARM_SIZE)
        .map(|i| kzg.open(&fps, i))
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let roster_pubkeys_hex: Vec<String> = cluster_map
        .slots
        .iter()
        .map(|s| s.pubkey_hex.clone())
        .collect();
    let roster_pks: Vec<[u8; 33]> = roster_pubkeys_hex
        .iter()
        .map(|h| decode_fixed_hex::<33>(h))
        .collect::<Result<Vec<_>>>()?;
    let member_verkle_root = compute_member_verkle_root(kzg, &roster_pks)?;
    let root_hex = hex::encode(root);
    let init_req = InitSwarmRequest {
        swarm_id: cluster_map.swarm_id,
        roster_pubkeys_hex,
        member_verkle_root_hex: hex::encode(member_verkle_root),
        active_blobs_root_hex: root_hex.clone(),
        initial_bounty,
    };

    let block: FinalizedBlockDto =
        http_request_json(l1_rpc_url, "POST", "/swarm/init", Some(&init_req)).await?;

    let manifest = SwarmManifestDto {
        swarm_id: cluster_map.swarm_id,
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

    let mut store_set = JoinSet::new();
    for (slot_idx, shard) in shards.iter().enumerate() {
        let addr: SocketAddr = cluster_map.slots[slot_idx]
            .p2p_addr
            .parse()
            .map_err(|_| Error::Network("invalid slot p2p addr".into()))?;
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

    let unique_p2p: BTreeSet<SocketAddr> = cluster_map
        .slots
        .iter()
        .filter_map(|s| s.p2p_addr.parse::<SocketAddr>().ok())
        .collect();
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

    Ok((manifest, block))
}

async fn fetch_live_manifest(
    cluster_map: &SwarmClusterMapDto,
    preferred_node_rpc: Option<&str>,
) -> Option<SwarmManifestDto> {
    if let Some(url) = preferred_node_rpc {
        if let Ok(m) = http_request_json::<(), SwarmManifestDto>(url, "GET", "/manifest", None).await
        {
            return Some(m);
        }
    }
    let unique_rpc: BTreeSet<String> = cluster_map
        .slots
        .iter()
        .map(|s| format!("http://{}", s.rpc_addr))
        .collect();
    for url in unique_rpc {
        if let Ok(m) = http_request_json::<(), SwarmManifestDto>(&url, "GET", "/manifest", None).await
        {
            return Some(m);
        }
    }
    None
}

pub async fn download_payload(
    cluster_map: &SwarmClusterMapDto,
    object_id_hex: &str,
    preferred_node_rpc: Option<&str>,
) -> Result<(Vec<u8>, usize)> {
    let manifest = fetch_live_manifest(cluster_map, preferred_node_rpc).await;
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
