use crate::persistence::NodeStorage;
use crate::storage_daemon::sorted_slot_keys;
use crate::wire::{
    decode_fixed_hex, http_request_json, send_p2p, FinalizedBlockDto, L1StatusDto, P2pRequest,
    P2pResponse, ShardDto, SlotAssignmentDto, SwarmClusterMapDto, SwarmManifestDto,
    SwarmSummaryDto, TxDto,
};
use crate::{Error, Result};
use l1_state_engine::shuffler::route_file_to_swarm;
use l1_state_engine::state_db::{NativeTransaction, MAX_SWARM_SIZE, MIN_SWARM_SIZE};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::Path;
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
        .map(
            |(slot, ((_, _, pk), &(node_id, p2p_addr, rpc_addr)))| SlotAssignmentDto {
                slot: slot as u8,
                node_id,
                p2p_addr: p2p_addr.to_string(),
                rpc_addr: rpc_addr.to_string(),
                pubkey_hex: hex::encode(pk),
            },
        )
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

#[derive(Clone, Debug)]
pub struct RosterMember {
    pub slot: u8,
    pub pubkey_hex: String,
    pub p2p_addr: SocketAddr,
    pub rpc_addr: SocketAddr,
}

fn endpoint_index(
    status: &L1StatusDto,
    fallback: Option<&SwarmClusterMapDto>,
) -> BTreeMap<String, (String, String)> {
    let mut index: BTreeMap<String, (String, String)> = fallback
        .into_iter()
        .flat_map(|map| &map.slots)
        .map(|entry| {
            (
                entry.pubkey_hex.to_ascii_lowercase(),
                (entry.p2p_addr.clone(), entry.rpc_addr.clone()),
            )
        })
        .collect();
    for node in &status.nodes {
        if !node.p2p_addr.is_empty() && !node.rpc_addr.is_empty() {
            index.insert(
                node.pubkey_hex.to_ascii_lowercase(),
                (node.p2p_addr.clone(), node.rpc_addr.clone()),
            );
        }
    }
    index
}

fn parse_addr(addr: &str) -> Result<SocketAddr> {
    addr.parse()
        .map_err(|_| Error::Network(format!("invalid node address: {addr}")))
}

pub fn resolve_roster(
    status: &L1StatusDto,
    roster_pubkeys: &[String],
    fallback: Option<&SwarmClusterMapDto>,
) -> Result<Vec<RosterMember>> {
    let index = endpoint_index(status, fallback);
    roster_pubkeys
        .iter()
        .enumerate()
        .map(|(slot, pubkey)| {
            let (p2p, rpc) = index.get(&pubkey.to_ascii_lowercase()).ok_or_else(|| {
                Error::Network(format!("roster member {pubkey} has no registered endpoint"))
            })?;
            Ok(RosterMember {
                slot: slot as u8,
                pubkey_hex: pubkey.clone(),
                p2p_addr: parse_addr(p2p)?,
                rpc_addr: parse_addr(rpc)?,
            })
        })
        .collect()
}

pub fn locate_node(status: &L1StatusDto, pubkey_hex: &str) -> Option<(u64, u8)> {
    status.swarms.iter().find_map(|swarm| {
        swarm
            .roster_pubkeys_hex
            .iter()
            .position(|pk| pk.eq_ignore_ascii_case(pubkey_hex))
            .map(|slot| (swarm.swarm_id, slot as u8))
    })
}

pub async fn fetch_l1_status(l1_rpc_url: &str) -> Result<L1StatusDto> {
    http_request_json::<(), L1StatusDto>(l1_rpc_url, "GET", "/status", None).await
}

fn unique_cluster_rpc_urls(cluster_map: &SwarmClusterMapDto) -> Vec<String> {
    let mut seen_rpc = BTreeSet::new();
    let mut rpc_urls = Vec::new();
    for entry in &cluster_map.slots {
        if seen_rpc.insert(entry.rpc_addr.clone()) {
            rpc_urls.push(format!("http://{}", entry.rpc_addr));
        }
    }
    rpc_urls
}

pub async fn register_cluster_via_nodes(cluster_map: &SwarmClusterMapDto) -> Result<usize> {
    let mut total_txs = 0usize;
    for url in unique_cluster_rpc_urls(cluster_map) {
        let block: FinalizedBlockDto =
            http_request_json::<(), FinalizedBlockDto>(&url, "POST", "/register_slots", None)
                .await?;
        total_txs += block.header.tx_count;
    }
    Ok(total_txs)
}

/// Collects signed registration transactions from every node and submits them in a single L1 batch block.
pub async fn register_cluster_batch_via_nodes(
    l1_rpc_url: &str,
    cluster_map: &SwarmClusterMapDto,
) -> Result<FinalizedBlockDto> {
    let mut all_txs = Vec::new();
    for url in unique_cluster_rpc_urls(cluster_map) {
        let txs: Vec<TxDto> =
            http_request_json::<(), Vec<TxDto>>(&url, "GET", "/registration_txs", None).await?;
        all_txs.extend(txs);
    }
    if all_txs.is_empty() {
        return Err(Error::Network(
            "no registration transactions collected".into(),
        ));
    }
    http_request_json::<Vec<TxDto>, FinalizedBlockDto>(
        l1_rpc_url,
        "POST",
        "/tx/batch",
        Some(&all_txs),
    )
    .await
}

pub async fn upload_payload(
    l1_rpc_url: &str,
    cluster_map: Option<&SwarmClusterMapDto>,
    kzg: &Kzg,
    payload: &[u8],
    initial_bounty: u128,
    seed: u64,
) -> Result<(SwarmManifestDto, Option<FinalizedBlockDto>)> {
    let status = fetch_l1_status(l1_rpc_url).await?;
    let epoch_seed = decode_fixed_hex::<32>(&status.epoch_seed_hex)?;
    let object_id: [u8; 32] = Sha256::digest(payload).into();
    let target_swarm_id = route_file_to_swarm(&object_id, &epoch_seed, status.swarm_count.max(1))?;
    let target_swarm = status
        .swarms
        .iter()
        .find(|s| s.swarm_id == target_swarm_id)
        .or_else(|| {
            status
                .swarms
                .get((target_swarm_id as usize) % status.swarms.len().max(1))
        })
        .ok_or_else(|| Error::Network("no swarm has been formed on L1".into()))?;
    let roster_pubkeys_hex = target_swarm.roster_pubkeys_hex.clone();
    let target_p2p_addrs: Vec<SocketAddr> =
        resolve_roster(&status, &roster_pubkeys_hex, cluster_map)?
            .iter()
            .map(|member| member.p2p_addr)
            .collect();
    let n = roster_pubkeys_hex.len();
    let k = target_swarm.state.min_threshold_k as usize;

    let shards = encode(payload, k, n, seed)?;
    let fps: Vec<Scalar> = shards.iter().map(|s| s.fingerprint()).collect();
    let root = kzg.commit(&fps)?;
    let proofs: Vec<KzgProof> = kzg.open_all(&fps)?;
    let root_hex = hex::encode(root);

    let swarm_id = target_swarm.swarm_id;

    let manifest = SwarmManifestDto {
        swarm_id,
        object_id_hex: hex::encode(shards[0].object_id),
        root_hex,
        roster_pubkeys_hex,
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

    let maybe_block = if initial_bounty > 0 {
        let tx = TxDto::from_native(&NativeTransaction::RegisterObject {
            swarm_id,
            object_id,
            object_root: root,
            bounty: initial_bounty,
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

    Ok((manifest, maybe_block))
}

pub async fn fetch_live_manifest(
    rpc_urls: &BTreeSet<String>,
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
    for url in rpc_urls {
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
    for url in rpc_urls {
        if let Ok(m) =
            http_request_json::<(), SwarmManifestDto>(url, "GET", "/manifest", None).await
        {
            if m.object_id_hex.eq_ignore_ascii_case(object_id_hex) {
                return Some(m);
            }
        }
    }
    None
}

pub async fn download_payload(
    l1_rpc_url: &str,
    cluster_map: Option<&SwarmClusterMapDto>,
    object_id_hex: &str,
    preferred_node_rpc: Option<&str>,
) -> Result<(Vec<u8>, usize)> {
    let status = fetch_l1_status(l1_rpc_url).await?;
    let rpc_urls: BTreeSet<String> = endpoint_index(&status, cluster_map)
        .into_values()
        .map(|(_, rpc)| format!("http://{rpc}"))
        .collect();
    let manifest = fetch_live_manifest(&rpc_urls, object_id_hex, preferred_node_rpc).await;
    let custodian_owners = manifest
        .as_ref()
        .map(|m| m.custodian_owners.clone())
        .unwrap_or_default();

    let roster_pubkeys_hex = match manifest.as_ref() {
        Some(manifest) if !manifest.roster_pubkeys_hex.is_empty() => {
            manifest.roster_pubkeys_hex.clone()
        }
        _ => {
            let object_id = decode_fixed_hex::<32>(object_id_hex)?;
            let epoch_seed = decode_fixed_hex::<32>(&status.epoch_seed_hex)?;
            let swarm_id = route_file_to_swarm(&object_id, &epoch_seed, status.swarm_count.max(1))?;
            status
                .swarms
                .iter()
                .find(|s| s.swarm_id == swarm_id)
                .ok_or_else(|| Error::Network(format!("swarm {swarm_id} not found on L1")))?
                .roster_pubkeys_hex
                .clone()
        }
    };
    let roster: BTreeMap<u8, RosterMember> =
        resolve_roster(&status, &roster_pubkeys_hex, cluster_map)?
            .into_iter()
            .map(|member| (member.slot, member))
            .collect();

    let mut fetch_targets: Vec<(u8, SocketAddr)> = Vec::new();
    for (&slot, member) in &roster {
        if let Some(custodian) = custodian_owners
            .get(&slot)
            .and_then(|cust| roster.get(cust))
        {
            fetch_targets.push((slot, custodian.p2p_addr));
        }
        fetch_targets.push((slot, member.p2p_addr));
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

pub async fn submit_native_tx(
    l1_rpc_url: &str,
    tx: &NativeTransaction,
) -> Result<FinalizedBlockDto> {
    http_request_json(
        l1_rpc_url,
        "POST",
        "/tx/submit",
        Some(&TxDto::from_native(tx)),
    )
    .await
}

pub fn fault_proof_txs(
    swarm: &SwarmSummaryDto,
    node_slot: u8,
    data_dir: &Path,
) -> Result<Vec<(u64, NativeTransaction)>> {
    let mut txs = Vec::new();
    for settlement in &swarm.recent_settlements {
        let bitmap: u128 = settlement
            .uptime_bitmap
            .parse()
            .map_err(|_| Error::Network("invalid u128 uptime_bitmap".into()))?;
        if bitmap & (1u128 << node_slot) != 0 {
            continue;
        }
        if let Some((aggregator_slot, signed_pong_receipt)) =
            NodeStorage::load_heartbeat_receipt(data_dir, settlement.epoch, node_slot)?
        {
            if aggregator_slot == settlement.aggregator_slot {
                txs.push((
                    settlement.epoch,
                    NativeTransaction::SubmitHeartbeatFaultProof {
                        swarm_id: swarm.swarm_id,
                        epoch: settlement.epoch,
                        node_slot,
                        aggregator_slot,
                        signed_pong_receipt,
                    },
                ));
            }
        }
    }
    Ok(txs)
}

pub async fn request_handoff(
    l1_rpc_url: &str,
    object_id_hex: &str,
    slot: u8,
) -> Result<P2pResponse> {
    let status = fetch_l1_status(l1_rpc_url).await?;
    let rpc_urls: BTreeSet<String> = endpoint_index(&status, None)
        .into_values()
        .map(|(_, rpc)| format!("http://{rpc}"))
        .collect();
    let manifest = fetch_live_manifest(&rpc_urls, object_id_hex, None)
        .await
        .ok_or_else(|| Error::Network(format!("manifest for object {object_id_hex} not found")))?;
    let custodian_slot = *manifest.custodian_owners.get(&slot).ok_or_else(|| {
        Error::Network(format!(
            "slot {slot} has no custodian for object {object_id_hex}"
        ))
    })?;
    let swarm = status
        .swarms
        .iter()
        .find(|s| s.swarm_id == manifest.swarm_id)
        .ok_or_else(|| Error::Network(format!("swarm {} not found on L1", manifest.swarm_id)))?;
    let roster = resolve_roster(&status, &swarm.roster_pubkeys_hex, None)?;
    let member = |slot: u8| {
        roster
            .get(slot as usize)
            .ok_or_else(|| Error::Network(format!("slot {slot} is outside the L1 roster")))
    };
    send_p2p(
        member(custodian_slot)?.p2p_addr,
        &P2pRequest::HandoffShard {
            slot,
            object_id_hex: object_id_hex.to_string(),
            target_p2p_addr: member(slot)?.p2p_addr.to_string(),
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::SettlementDto;
    use l1_state_engine::state_db::VirtualSwarmState;

    fn swarm(settlements: Vec<(u64, u8, u128)>) -> SwarmSummaryDto {
        SwarmSummaryDto {
            swarm_id: 0,
            state: VirtualSwarmState {
                swarm_id: 0,
                member_verkle_root: [0; 48],
                active_blobs_root: [0; 48],
                total_bond_balance: 0,
                storage_bounty_pool: 0,
                last_epoch_settled: 0,
                swarm_size_n: 0,
                min_threshold_k: 0,
                lazy_repair_trigger: 0,
                lazy_repair_target: 0,
            },
            roster_pubkeys_hex: Vec::new(),
            object_ids_hex: Vec::new(),
            recent_settlements: settlements
                .into_iter()
                .map(|(epoch, aggregator_slot, bitmap)| SettlementDto {
                    epoch,
                    aggregator_slot,
                    uptime_bitmap: bitmap.to_string(),
                })
                .collect(),
        }
    }

    #[test]
    fn fault_proof_txs_select_only_zero_bit_settlements_with_matching_receipt() {
        let dir =
            std::env::temp_dir().join(format!("depin_fault_proof_txs_{}", std::process::id()));
        let sig_hex = "11".repeat(64);
        NodeStorage::save_heartbeat_receipt(&dir, 0, 1, 2, 0, &sig_hex).unwrap();
        NodeStorage::save_heartbeat_receipt(&dir, 0, 2, 2, 0, &sig_hex).unwrap();
        NodeStorage::save_heartbeat_receipt(&dir, 0, 3, 2, 5, &sig_hex).unwrap();

        let txs = fault_proof_txs(
            &swarm(vec![
                (1, 0, 0b011),
                (2, 0, 0b111),
                (3, 0, 0b011),
                (4, 0, 0b011),
            ]),
            2,
            &dir,
        )
        .unwrap();
        std::fs::remove_dir_all(&dir).unwrap();

        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].0, 1);
        assert!(matches!(
            txs[0].1,
            NativeTransaction::SubmitHeartbeatFaultProof {
                epoch: 1,
                node_slot: 2,
                aggregator_slot: 0,
                ..
            }
        ));
    }
}
