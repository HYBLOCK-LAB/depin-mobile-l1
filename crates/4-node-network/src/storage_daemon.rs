use crate::client::{
    fault_proof_txs, fetch_l1_status, locate_node, resolve_roster, submit_native_tx, RosterMember,
};
use crate::l1_daemon::{DEFAULT_EPOCH_SEED, DEFAULT_KZG_SEED};
use crate::persistence::{
    compressed_pubkey, deterministic_signing_key, load_or_create_random_signing_key,
    load_or_create_signing_key, NodeStorage, ValidatorStorage, KEYS_DIR,
};
use crate::wire::{
    decode_fixed_hex, http_request_json, proof_from_hex, read_frame, read_http_request,
    root_from_hex, send_p2p, spawn_tcp_server, write_frame, write_http_json, CycleReportDto,
    FinalizedBlockDto, L1StatusDto, P2pRequest, P2pResponse, ShardDto, SwarmClusterMapDto,
    SwarmManifestDto, TxDto,
};
use crate::{Error, Result};
use l1_state_engine::executor::{
    expected_repair_audit_index, expected_sample_index, expected_unchanged_slot_index,
    heartbeat_signing_bytes, sign_registration,
};
use l1_state_engine::shuffler::score_node;
use l1_state_engine::state_db::{NativeTransaction, RepairAuditProof, RepairEntry, MAX_SWARM_SIZE};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;
use verkle_fountain::fountain::{rank, repair_local_field, Shard};
use verkle_fountain::pollution_guard::{verify_homomorphic_repair, AuthenticatedShard};
use verkle_fountain::verkle_kzg::{bytes_to_scalar, scalar_to_bytes, Kzg, KzgProof, Scalar};

const REGISTRATION_STAKE: u128 = 1_500;
const NODE_KEY_FILE: &str = "node.hex";

#[derive(Clone, Debug)]
pub struct PublicEndpoints {
    pub p2p_addr: SocketAddr,
    pub rpc_addr: SocketAddr,
}

#[derive(Clone, Debug)]
pub struct StorageDaemonConfig {
    pub node_id: u64,
    pub slots: Vec<u8>,
    pub p2p_addr: SocketAddr,
    pub rpc_addr: SocketAddr,
    pub l1_rpc_url: String,
    pub cluster_map: Option<SwarmClusterMapDto>,
    pub auto_register: Option<PublicEndpoints>,
    pub data_dir: PathBuf,
    pub ip_subnet_hash: u16,
    pub country_code: u8,
    pub kzg_seed: u64,
    pub auto_epoch_interval: Option<Duration>,
}

struct NodeIdentity {
    key: SigningKey,
    pubkey_hex: String,
    p2p_addr: String,
    rpc_addr: String,
}

struct StorageRuntimeState {
    node_id: u64,
    l1_rpc_url: String,
    cluster_map: Option<SwarmClusterMapDto>,
    identities: Vec<NodeIdentity>,
    kzg: Arc<Kzg>,
    data_dir: PathBuf,
    ip_subnet_hash: u16,
    country_code: u8,
}

pub struct StorageDaemonHandle {
    pub node_id: u64,
    pub p2p_addr: SocketAddr,
    pub rpc_addr: SocketAddr,
    pub rpc_url: String,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl StorageDaemonHandle {
    pub async fn shutdown(mut self) {
        for task in self.tasks.drain(..) {
            task.abort();
            let _ = task.await;
        }
    }
}

#[derive(Serialize)]
struct NodeHealthResponse {
    ok: bool,
    node_id: u64,
    pubkeys_hex: Vec<String>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Deserialize)]
struct RunCycleBody {
    epoch: u64,
    #[serde(default)]
    object_id_hex: Option<String>,
}

pub fn sorted_slot_keys(n: usize) -> Vec<(u64, SigningKey, [u8; 33])> {
    let mut entries: Vec<(u64, SigningKey, [u8; 33], [u8; 32])> = (0..n)
        .map(|i| {
            let raw_seed = 5000 + i as u64;
            let sk = deterministic_signing_key(raw_seed);
            let pk = compressed_pubkey(&sk);
            let score = score_node(&pk, &DEFAULT_EPOCH_SEED);
            (raw_seed, sk, pk, score)
        })
        .collect();
    entries.sort_by(|a, b| a.3.cmp(&b.3).then_with(|| a.2.cmp(&b.2)));
    entries
        .into_iter()
        .map(|(seed, sk, pk, _)| (seed, sk, pk))
        .collect()
}

pub fn slot_key_seed(slot: u8, n: usize) -> u64 {
    sorted_slot_keys(n)
        .get(slot as usize)
        .map(|(seed, _, _)| *seed)
        .unwrap_or(5000 + slot as u64)
}

fn load_identities(config: &StorageDaemonConfig) -> Result<Vec<NodeIdentity>> {
    let keys_dir = config.data_dir.join(KEYS_DIR);
    if let Some(public) = &config.auto_register {
        if public.p2p_addr.ip().is_unspecified() || public.rpc_addr.ip().is_unspecified() {
            return Err(Error::Network(
                "public p2p and rpc addresses must be reachable, not unspecified".into(),
            ));
        }
        let key = load_or_create_random_signing_key(&keys_dir.join(NODE_KEY_FILE))?;
        return Ok(vec![NodeIdentity {
            pubkey_hex: hex::encode(compressed_pubkey(&key)),
            key,
            p2p_addr: public.p2p_addr.to_string(),
            rpc_addr: public.rpc_addr.to_string(),
        }]);
    }
    config
        .slots
        .iter()
        .map(|&slot| {
            let map = config
                .cluster_map
                .as_ref()
                .ok_or_else(|| Error::Network("cluster map is required for map slots".into()))?;
            let entry = map
                .slots
                .iter()
                .find(|entry| entry.slot == slot)
                .ok_or_else(|| Error::Network(format!("slot {slot} missing from cluster map")))?;
            let key = load_or_create_signing_key(
                &keys_dir.join(format!("slot_{slot}.hex")),
                slot_key_seed(slot, map.slots.len()),
            )?;
            Ok(NodeIdentity {
                pubkey_hex: hex::encode(compressed_pubkey(&key)),
                key,
                p2p_addr: entry.p2p_addr.clone(),
                rpc_addr: entry.rpc_addr.clone(),
            })
        })
        .collect()
}

pub async fn start_storage_daemon(config: StorageDaemonConfig) -> Result<StorageDaemonHandle> {
    std::fs::create_dir_all(&config.data_dir)?;
    let identities = load_identities(&config)?;

    let kzg_seed = if config.kzg_seed == 0 {
        DEFAULT_KZG_SEED
    } else {
        config.kzg_seed
    };
    let kzg = Arc::new(ValidatorStorage::load_or_create_kzg(
        &config.data_dir,
        MAX_SWARM_SIZE - 1,
        kzg_seed,
    )?);

    let p2p_listener = TcpListener::bind(config.p2p_addr).await?;
    let rpc_listener = TcpListener::bind(config.rpc_addr).await?;
    let actual_p2p = p2p_listener.local_addr()?;
    let actual_rpc = rpc_listener.local_addr()?;

    let state = Arc::new(StorageRuntimeState {
        node_id: config.node_id,
        l1_rpc_url: config.l1_rpc_url,
        cluster_map: config.cluster_map,
        identities,
        kzg,
        data_dir: config.data_dir,
        ip_subnet_hash: config.ip_subnet_hash,
        country_code: config.country_code,
    });

    let p2p_task = spawn_tcp_server(p2p_listener, Arc::clone(&state), handle_storage_p2p);
    let rpc_task = spawn_tcp_server(rpc_listener, Arc::clone(&state), handle_storage_rpc);

    if config.auto_register.is_some() {
        if let Err(e) = register_self(&state).await {
            p2p_task.abort();
            rpc_task.abort();
            return Err(e);
        }
    }

    let mut tasks = vec![p2p_task, rpc_task];
    if let Some(interval) = config.auto_epoch_interval {
        tasks.push(tokio::spawn(auto_epoch_loop(Arc::clone(&state), interval)));
    }

    Ok(StorageDaemonHandle {
        node_id: config.node_id,
        p2p_addr: actual_p2p,
        rpc_addr: actual_rpc,
        rpc_url: format!("http://{actual_rpc}"),
        tasks,
    })
}

fn find_hosted<'a>(
    state: &'a StorageRuntimeState,
    status: &L1StatusDto,
    target_slot: u8,
) -> Option<(u64, &'a NodeIdentity)> {
    state.identities.iter().find_map(|identity| {
        locate_node(status, &identity.pubkey_hex)
            .filter(|&(_, slot)| slot == target_slot)
            .map(|(swarm_id, _)| (swarm_id, identity))
    })
}

async fn handle_storage_p2p(mut stream: TcpStream, state: Arc<StorageRuntimeState>) -> Result<()> {
    let req: P2pRequest = read_frame(&mut stream).await?;
    let resp = match req {
        P2pRequest::Ping {
            from_slot,
            target_slot,
            target_map_slot: _,
            epoch,
            aggregator_sig_hex,
        } => {
            let status = fetch_l1_status(&state.l1_rpc_url).await?;
            if let Some((swarm_id, identity)) = find_hosted(&state, &status, target_slot) {
                if !aggregator_sig_hex.is_empty() {
                    NodeStorage::save_heartbeat_receipt(
                        &state.data_dir,
                        swarm_id,
                        epoch,
                        target_slot,
                        from_slot,
                        &aggregator_sig_hex,
                    )?;
                }
                let msg = heartbeat_signing_bytes(swarm_id, epoch, target_slot);
                let sig: Signature = identity.key.sign(&msg);
                let sig_bytes: [u8; 64] = sig.to_bytes().into();
                P2pResponse::Pong {
                    slot: target_slot,
                    epoch,
                    sig_hex: hex::encode(sig_bytes),
                }
            } else {
                P2pResponse::Error {
                    message: format!("slot {target_slot} not hosted on node {}", state.node_id),
                }
            }
        }
        P2pRequest::IssueHeartbeatReceipt {
            swarm_id,
            epoch,
            target_slot,
            target_map_slot: _,
            aggregator_slot,
            sig_hex,
        } => {
            let status = fetch_l1_status(&state.l1_rpc_url).await?;
            match find_hosted(&state, &status, target_slot) {
                Some((hosted_swarm_id, _)) if hosted_swarm_id != swarm_id => P2pResponse::Error {
                    message: format!(
                        "swarm_id mismatch: expected {hosted_swarm_id}, got {swarm_id}"
                    ),
                },
                Some(_) => {
                    NodeStorage::save_heartbeat_receipt(
                        &state.data_dir,
                        swarm_id,
                        epoch,
                        target_slot,
                        aggregator_slot,
                        &sig_hex,
                    )?;
                    P2pResponse::Ack { ok: true }
                }
                None => P2pResponse::Error {
                    message: format!("slot {target_slot} not hosted on node {}", state.node_id),
                },
            }
        }
        P2pRequest::StoreShard {
            slot,
            is_custodian,
            generation,
            shard,
            proof_hex,
        } => {
            let parsed = shard.to_shard()?;
            parsed.validate()?;
            let ok = NodeStorage::save_shard(
                &state.data_dir,
                slot,
                is_custodian,
                generation,
                &shard,
                &proof_hex,
            )?;
            P2pResponse::StoreAck {
                ok,
                message: if ok {
                    "stored".into()
                } else {
                    "rejected by generation guard".into()
                },
            }
        }
        P2pRequest::HandoffShard {
            slot,
            object_id_hex,
            target_p2p_addr,
        } => handoff_shard(&state, slot, &object_id_hex, &target_p2p_addr).await?,
        P2pRequest::FetchShard {
            slot,
            object_id_hex,
        } => match NodeStorage::load_shard(&state.data_dir, slot, &object_id_hex)? {
            Some((shard, proof_hex)) => P2pResponse::ShardData {
                found: true,
                shard: Some(ShardDto::from_shard(&shard.to_shard()?)),
                proof_hex: Some(proof_hex),
            },
            None => P2pResponse::ShardData {
                found: false,
                shard: None,
                proof_hex: None,
            },
        },
        P2pRequest::StoreManifest { manifest } => {
            NodeStorage::save_manifest(&state.data_dir, &manifest)?;
            P2pResponse::Ack { ok: true }
        }
        _ => P2pResponse::Error {
            message: "unsupported p2p message for storage node".into(),
        },
    };
    write_frame(&mut stream, &resp).await?;
    Ok(())
}

async fn handoff_shard(
    state: &StorageRuntimeState,
    slot: u8,
    object_id_hex: &str,
    target_p2p_addr: &str,
) -> Result<P2pResponse> {
    let loaded_shard = NodeStorage::load_shard_by_role(&state.data_dir, slot, true, object_id_hex)?;
    let loaded_meta =
        NodeStorage::load_slot_meta_for_object(&state.data_dir, slot, true, object_id_hex)?;
    let ack = |ok: bool, message: String| P2pResponse::StoreAck { ok, message };
    let (Some((shard, proof_hex)), Some(meta)) = (loaded_shard, loaded_meta) else {
        return Ok(ack(false, "custodian shard not found".into()));
    };
    let Ok(target_addr) = target_p2p_addr.parse::<SocketAddr>() else {
        return Ok(ack(
            false,
            format!("invalid target_p2p_addr: {target_p2p_addr}"),
        ));
    };
    let reply = send_p2p(
        target_addr,
        &P2pRequest::StoreShard {
            slot,
            is_custodian: false,
            generation: meta.generation.saturating_add(1),
            shard,
            proof_hex,
        },
    )
    .await;
    Ok(match reply {
        Ok(P2pResponse::StoreAck { ok: true, .. }) => {
            NodeStorage::remove_custodian_shard(&state.data_dir, slot, object_id_hex)?;
            ack(true, "handoff complete".into())
        }
        Ok(P2pResponse::StoreAck { ok: false, message }) => {
            ack(false, format!("target rejected shard: {message}"))
        }
        Ok(other) => ack(false, format!("unexpected target response: {other:?}")),
        Err(e) => ack(false, format!("handoff transfer failed: {e}")),
    })
}

fn registration_tx(state: &StorageRuntimeState, identity: &NodeIdentity, chain_id: u64) -> TxDto {
    let (pk, sig) = sign_registration(
        &identity.key,
        chain_id,
        state.ip_subnet_hash,
        state.country_code,
        REGISTRATION_STAKE,
        &identity.p2p_addr,
        &identity.rpc_addr,
    );
    TxDto::from_native(&NativeTransaction::RegisterMobileNode {
        pubkey_p256: pk,
        hw_attestation_sig: sig,
        ip_subnet_hash: state.ip_subnet_hash,
        country_code: state.country_code,
        stake: REGISTRATION_STAKE,
        p2p_addr: identity.p2p_addr.clone(),
        rpc_addr: identity.rpc_addr.clone(),
    })
}

async fn build_registration_txs(state: &StorageRuntimeState) -> Result<Vec<TxDto>> {
    let chain_id = fetch_l1_status(&state.l1_rpc_url).await?.chain_id;
    Ok(state
        .identities
        .iter()
        .map(|identity| registration_tx(state, identity, chain_id))
        .collect())
}

async fn register_self(state: &StorageRuntimeState) -> Result<()> {
    let status = fetch_l1_status(&state.l1_rpc_url).await?;
    for identity in &state.identities {
        let registered = status
            .nodes
            .iter()
            .any(|node| node.pubkey_hex.eq_ignore_ascii_case(&identity.pubkey_hex));
        if !registered {
            http_request_json::<TxDto, FinalizedBlockDto>(
                &state.l1_rpc_url,
                "POST",
                "/tx/submit",
                Some(&registration_tx(state, identity, status.chain_id)),
            )
            .await?;
        }
    }
    Ok(())
}

async fn handle_storage_rpc(mut stream: TcpStream, state: Arc<StorageRuntimeState>) -> Result<()> {
    let (method, path, body) = read_http_request(&mut stream).await?;
    match (method.as_str(), path.as_str()) {
        ("GET", "/health") => {
            write_http_json(
                &mut stream,
                200,
                &NodeHealthResponse {
                    ok: true,
                    node_id: state.node_id,
                    pubkeys_hex: state
                        .identities
                        .iter()
                        .map(|identity| identity.pubkey_hex.clone())
                        .collect(),
                },
            )
            .await?;
        }
        ("GET", "/manifest") => match NodeStorage::load_manifest(&state.data_dir)? {
            Some(manifest) => write_http_json(&mut stream, 200, &manifest).await?,
            None => {
                write_http_json(
                    &mut stream,
                    404,
                    &ErrorResponse {
                        error: "manifest not initialized".into(),
                    },
                )
                .await?
            }
        },
        ("GET", p) if p.starts_with("/manifest/") => {
            let object_id_hex = p.strip_prefix("/manifest/").unwrap_or("");
            if object_id_hex.is_empty()
                || !object_id_hex.bytes().all(|b| b.is_ascii_hexdigit())
            {
                write_http_json(
                    &mut stream,
                    400,
                    &ErrorResponse {
                        error: "invalid object_id_hex".into(),
                    },
                )
                .await?;
            } else {
                match NodeStorage::load_manifest_for_object(&state.data_dir, Some(object_id_hex))? {
                    Some(manifest) => write_http_json(&mut stream, 200, &manifest).await?,
                    None => {
                        write_http_json(
                            &mut stream,
                            404,
                            &ErrorResponse {
                                error: format!("manifest not found for object {object_id_hex}"),
                            },
                        )
                        .await?
                    }
                }
            }
        }
        ("GET", "/registration_txs") => match build_registration_txs(&state).await {
            Ok(txs) => write_http_json(&mut stream, 200, &txs).await?,
            Err(e) => {
                write_http_json(
                    &mut stream,
                    400,
                    &ErrorResponse {
                        error: e.to_string(),
                    },
                )
                .await?
            }
        },
        ("POST", "/register_slots") => {
            let result = match build_registration_txs(&state).await {
                Ok(txs) => {
                    http_request_json::<Vec<TxDto>, FinalizedBlockDto>(
                        &state.l1_rpc_url,
                        "POST",
                        "/tx/batch",
                        Some(&txs),
                    )
                    .await
                }
                Err(e) => Err(e),
            };
            match result {
                Ok(block) => write_http_json(&mut stream, 200, &block).await?,
                Err(e) => {
                    write_http_json(&mut stream, 400, &ErrorResponse { error: e.to_string() })
                        .await?
                }
            }
        }
        ("POST", "/aggregator/run_cycle") => {
            let req: RunCycleBody = serde_json::from_slice(&body)
                .map_err(|e| Error::Network(format!("invalid run_cycle json: {e}")))?;
            match execute_aggregator_cycle(&state, req.epoch, req.object_id_hex.as_deref()).await {
                Ok(report) => write_http_json(&mut stream, 200, &report).await?,
                Err(e) => {
                    write_http_json(&mut stream, 400, &ErrorResponse { error: e.to_string() })
                        .await?
                }
            }
        }
        _ => {
            write_http_json(
                &mut stream,
                404,
                &ErrorResponse {
                    error: format!("unknown route: {method} {path}"),
                },
            )
            .await?;
        }
    }
    Ok(())
}

async fn ping_all_slots(
    roster: &[RosterMember],
    from_slot: u8,
    epoch: u64,
) -> Result<BTreeSet<u8>> {
    let mut set = JoinSet::new();
    for member in roster {
        let l1_slot = member.slot;
        let addr = member.p2p_addr;
        set.spawn(async move {
            let ok = matches!(
                send_p2p(
                    addr,
                    &P2pRequest::Ping {
                        from_slot,
                        target_slot: l1_slot,
                        target_map_slot: None,
                        epoch,
                        aggregator_sig_hex: String::new(),
                    }
                )
                .await,
                Ok(P2pResponse::Pong { slot: reply_slot, .. }) if reply_slot == l1_slot
            );
            (l1_slot, ok)
        });
    }
    let mut online = BTreeSet::new();
    while let Some(res) = set.join_next().await {
        if let Ok((slot, true)) = res {
            online.insert(slot);
        }
    }
    Ok(online)
}

async fn fetch_accessible_shards(
    slots: &[RosterMember],
    online_slots: &BTreeSet<u8>,
    custodian_owners: &BTreeMap<u8, u8>,
    object_id_hex: &str,
) -> Result<Vec<(usize, Shard)>> {
    let mut targets: Vec<(u8, SocketAddr)> = Vec::new();
    for slot in 0..slots.len() as u8 {
        let holder_slot = if online_slots.contains(&slot) {
            Some(slot)
        } else if let Some(&cust) = custodian_owners.get(&slot) {
            online_slots.contains(&cust).then_some(cust)
        } else {
            None
        };
        if let Some(h_slot) = holder_slot {
            if let Some(holder) = slots.get(h_slot as usize) {
                targets.push((slot, holder.p2p_addr));
            }
        }
    }

    let obj = object_id_hex.to_string();
    let mut set = JoinSet::new();
    for (slot, addr) in targets {
        let obj_id = obj.clone();
        set.spawn(async move {
            let reply = send_p2p(
                addr,
                &P2pRequest::FetchShard {
                    slot,
                    object_id_hex: obj_id,
                },
            )
            .await;
            (slot, reply)
        });
    }

    let mut out = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Ok((slot, Ok(P2pResponse::ShardData { found: true, shard: Some(dto), .. }))) = res {
            if let Ok(sh) = dto.to_shard() {
                out.push((slot as usize, sh));
            }
        }
    }
    out.sort_by_key(|(s, _)| *s);
    Ok(out)
}

fn select_cycle_manifest(
    state: &StorageRuntimeState,
    swarm_id: u64,
    l1_status: &L1StatusDto,
    requested_object_id: Option<&str>,
) -> Result<SwarmManifestDto> {
    if requested_object_id.is_some() {
        return NodeStorage::load_manifest_for_object(&state.data_dir, requested_object_id)?
            .ok_or_else(|| Error::Network("requested object manifest missing on node".into()));
    }
    if let Some(sw) = l1_status.swarms.iter().find(|s| s.swarm_id == swarm_id) {
        if sw.state.active_blobs_root != [0u8; 48] {
            let target_root_hex = hex::encode(sw.state.active_blobs_root);
            if let Some(latest) = NodeStorage::load_manifest(&state.data_dir)? {
                if latest.root_hex == target_root_hex {
                    return Ok(latest);
                }
            }
            for m in NodeStorage::list_manifests(&state.data_dir)? {
                if m.root_hex == target_root_hex {
                    return Ok(m);
                }
            }
        }
    }
    NodeStorage::load_manifest(&state.data_dir)?
        .ok_or_else(|| Error::Network("swarm manifest missing on node".into()))
}

fn sync_manifest_roster(manifest: &mut SwarmManifestDto, l1_roster: &[String]) {
    let recorded = std::mem::replace(&mut manifest.roster_pubkeys_hex, l1_roster.to_vec());
    for &slot in manifest.custodian_owners.keys() {
        if let (Some(old), Some(new)) = (
            recorded.get(slot as usize),
            manifest.roster_pubkeys_hex.get_mut(slot as usize),
        ) {
            *new = old.clone();
        }
    }
}

async fn broadcast_manifest(
    manifest: &SwarmManifestDto,
    peers: impl IntoIterator<Item = SocketAddr>,
) {
    let unique_addrs: BTreeSet<SocketAddr> = peers.into_iter().collect();
    let mut sync_set = JoinSet::new();
    for addr in unique_addrs {
        let m_clone = manifest.clone();
        sync_set.spawn(async move {
            let _ = send_p2p(addr, &P2pRequest::StoreManifest { manifest: m_clone }).await;
        });
    }
    while sync_set.join_next().await.is_some() {}
}

fn plan_handoffs(
    manifest: &SwarmManifestDto,
    hosted_slots: &BTreeSet<u8>,
    l1_roster: &[String],
) -> Vec<u8> {
    manifest
        .custodian_owners
        .iter()
        .filter(|(_, custodian)| hosted_slots.contains(custodian))
        .filter(|(&slot, _)| {
            match (
                manifest.roster_pubkeys_hex.get(slot as usize),
                l1_roster.get(slot as usize),
            ) {
                (Some(recorded), Some(current)) => !recorded.eq_ignore_ascii_case(current),
                _ => false,
            }
        })
        .map(|(&slot, _)| slot)
        .collect()
}

async fn handoff_to_replaced_nodes(
    state: &StorageRuntimeState,
    status: &L1StatusDto,
) -> Result<()> {
    for mut manifest in NodeStorage::list_manifests(&state.data_dir)? {
        let Some(swarm) = status
            .swarms
            .iter()
            .find(|s| s.swarm_id == manifest.swarm_id)
        else {
            continue;
        };
        let hosted_slots: BTreeSet<u8> = state
            .identities
            .iter()
            .filter_map(|identity| locate_node(status, &identity.pubkey_hex))
            .filter(|&(swarm_id, _)| swarm_id == swarm.swarm_id)
            .map(|(_, slot)| slot)
            .collect();
        let slots = plan_handoffs(&manifest, &hosted_slots, &swarm.roster_pubkeys_hex);
        if slots.is_empty() {
            continue;
        }
        let roster = resolve_roster(
            status,
            &swarm.roster_pubkeys_hex,
            state.cluster_map.as_ref(),
        )?;
        let mut changed = false;
        for slot in slots {
            let target = roster[slot as usize].p2p_addr.to_string();
            match handoff_shard(state, slot, &manifest.object_id_hex, &target).await? {
                P2pResponse::StoreAck { ok: true, .. } => {
                    manifest.custodian_owners.remove(&slot);
                    manifest.roster_pubkeys_hex[slot as usize] =
                        swarm.roster_pubkeys_hex[slot as usize].clone();
                    changed = true;
                    println!(
                        "HANDOFF_COMPLETE node_id={} object={} slot={slot} target={target}",
                        state.node_id, manifest.object_id_hex
                    );
                }
                other => eprintln!(
                    "handoff of slot {slot} on node {} failed: {other:?}",
                    state.node_id
                ),
            }
        }
        if changed {
            NodeStorage::save_manifest(&state.data_dir, &manifest)?;
            broadcast_manifest(&manifest, roster.iter().map(|member| member.p2p_addr)).await;
        }
    }
    Ok(())
}

async fn submit_pending_fault_proofs(
    state: &StorageRuntimeState,
    status: &L1StatusDto,
    submitted: &mut BTreeSet<(u64, u64, u8)>,
) -> Result<()> {
    for identity in &state.identities {
        let Some((swarm_id, slot)) = locate_node(status, &identity.pubkey_hex) else {
            continue;
        };
        let Some(swarm) = status.swarms.iter().find(|s| s.swarm_id == swarm_id) else {
            continue;
        };
        for (epoch, tx) in fault_proof_txs(swarm, slot, &state.data_dir)? {
            if submitted.contains(&(swarm_id, epoch, slot)) {
                continue;
            }
            submit_native_tx(&state.l1_rpc_url, &tx).await?;
            submitted.insert((swarm_id, epoch, slot));
            println!(
                "FAULT_PROOF_SUBMITTED node_id={} swarm={swarm_id} epoch={epoch} slot={slot}",
                state.node_id
            );
        }
    }
    Ok(())
}

#[derive(Default)]
struct SettlementWatch {
    seen: Option<(u64, u64)>,
    stale_ticks: usize,
}

impl SettlementWatch {
    fn observe(&mut self, swarm_id: u64, last_epoch_settled: u64) -> usize {
        if self.seen == Some((swarm_id, last_epoch_settled)) {
            self.stale_ticks += 1;
        } else {
            self.seen = Some((swarm_id, last_epoch_settled));
            self.stale_ticks = 0;
        }
        self.stale_ticks
    }
}

async fn run_epoch_if_aggregator(
    state: &StorageRuntimeState,
    status: &L1StatusDto,
    watch: &mut SettlementWatch,
) -> Result<()> {
    let (swarm_id, local_slot) = state
        .identities
        .iter()
        .find_map(|identity| locate_node(status, &identity.pubkey_hex))
        .ok_or_else(|| {
            Error::Network(format!("node {} is not in any swarm roster", state.node_id))
        })?;
    let swarm = status
        .swarms
        .iter()
        .find(|s| s.swarm_id == swarm_id)
        .ok_or_else(|| Error::Network("swarm missing on L1".into()))?;
    if usize::from(local_slot) > watch.observe(swarm_id, swarm.state.last_epoch_settled) {
        return Ok(());
    }
    let epoch = swarm.state.last_epoch_settled + 1;
    let lower_slots: Vec<RosterMember> = resolve_roster(
        status,
        &swarm.roster_pubkeys_hex,
        state.cluster_map.as_ref(),
    )?
    .into_iter()
    .filter(|member| member.slot < local_slot)
    .collect();
    if !ping_all_slots(&lower_slots, local_slot, epoch).await?.is_empty() {
        return Ok(());
    }
    let report = execute_aggregator_cycle(state, epoch, None).await?;
    println!(
        "EPOCH_SETTLED node_id={} swarm={} epoch={} aggregator_slot={} online_slots={} repaired_slots={:?}",
        state.node_id,
        report.swarm_id,
        report.epoch,
        report.aggregator_slot,
        report.online_slots,
        report.repaired_slots
    );
    Ok(())
}

async fn auto_epoch_loop(state: Arc<StorageRuntimeState>, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut submitted_fault_proofs = BTreeSet::new();
    let mut settlement_watch = SettlementWatch::default();
    loop {
        ticker.tick().await;
        let status = match fetch_l1_status(&state.l1_rpc_url).await {
            Ok(status) => status,
            Err(e) => {
                eprintln!(
                    "auto epoch: node {} status fetch failed: {e}",
                    state.node_id
                );
                continue;
            }
        };
        let results = [
            (
                "fault proof",
                submit_pending_fault_proofs(&state, &status, &mut submitted_fault_proofs).await,
            ),
            ("handoff", handoff_to_replaced_nodes(&state, &status).await),
            (
                "epoch cycle",
                run_epoch_if_aggregator(&state, &status, &mut settlement_watch).await,
            ),
        ];
        for (step, result) in results {
            if let Err(e) = result {
                eprintln!("auto epoch: node {} {step} failed: {e}", state.node_id);
            }
        }
    }
}

async fn execute_aggregator_cycle(
    state: &StorageRuntimeState,
    epoch: u64,
    object_id_hex: Option<&str>,
) -> Result<CycleReportDto> {
    let l1_status = fetch_l1_status(&state.l1_rpc_url).await?;
    let epoch_seed = decode_fixed_hex::<32>(&l1_status.epoch_seed_hex)?;
    let (swarm_id, local_slot) = state
        .identities
        .iter()
        .find_map(|identity| locate_node(&l1_status, &identity.pubkey_hex))
        .ok_or_else(|| {
            Error::Network(format!("node {} is not in any swarm roster", state.node_id))
        })?;
    let swarm = l1_status
        .swarms
        .iter()
        .find(|s| s.swarm_id == swarm_id)
        .ok_or_else(|| Error::Network("swarm missing on L1".into()))?;
    let n = swarm.state.swarm_size_n as usize;
    if n != swarm.roster_pubkeys_hex.len() || n > MAX_SWARM_SIZE {
        return Err(Error::Network("invalid L1 swarm roster length".into()));
    }
    let trigger = swarm.state.lazy_repair_trigger as usize;
    let target = swarm.state.lazy_repair_target as usize;
    let roster = resolve_roster(
        &l1_status,
        &swarm.roster_pubkeys_hex,
        state.cluster_map.as_ref(),
    )?;

    let online_slots = ping_all_slots(&roster, local_slot, epoch).await?;
    let aggregator_slot = *online_slots
        .iter()
        .next()
        .ok_or_else(|| Error::Network("no online slots in swarm".into()))?;

    let (_, agg_identity) = find_hosted(state, &l1_status, aggregator_slot).ok_or_else(|| {
        Error::Network(format!(
            "slot {aggregator_slot} is elected aggregator, not hosted on node {}",
            state.node_id
        ))
    })?;
    let agg_key = &agg_identity.key;

    // Heartbeat receipts are indexed by L1 slot, even if a peer's local key slot differs.
    let mut receipt_set = JoinSet::new();
    for &target_slot in &online_slots {
        let addr = roster[target_slot as usize].p2p_addr;
        let msg = heartbeat_signing_bytes(swarm_id, epoch, target_slot);
        let sig: Signature = agg_key.sign(&msg);
        let sig_hex = hex::encode(sig.to_bytes());
        receipt_set.spawn(async move {
            let _ = send_p2p(
                addr,
                &P2pRequest::IssueHeartbeatReceipt {
                    swarm_id,
                    epoch,
                    target_slot,
                    target_map_slot: None,
                    aggregator_slot,
                    sig_hex,
                },
            )
            .await;
        });
    }
    while receipt_set.join_next().await.is_some() {}

    let mut manifest = select_cycle_manifest(state, swarm_id, &l1_status, object_id_hex)?;
    if manifest.swarm_id != swarm_id {
        return Err(Error::Network("manifest belongs to a different swarm".into()));
    }

    let old_root = root_from_hex(&manifest.root_hex)?;
    let old_fps: Vec<Scalar> = manifest
        .slot_fps_hex
        .iter()
        .map(|h| Ok(bytes_to_scalar(&decode_fixed_hex::<32>(h)?)?))
        .collect::<Result<Vec<_>>>()?;
    let old_proofs: Vec<KzgProof> = manifest
        .slot_proofs_hex
        .iter()
        .map(|h| proof_from_hex(h))
        .collect::<Result<Vec<_>>>()?;
    if old_fps.len() != n || old_proofs.len() != n {
        return Err(Error::Network("manifest length mismatch".into()));
    }

    let mut accessible = fetch_accessible_shards(
        &roster,
        &online_slots,
        &manifest.custodian_owners,
        &manifest.object_id_hex,
    )
    .await?;
    let accessible_before = accessible.len();
    let k = accessible
        .first()
        .map(|(_, s)| s.k)
        .ok_or_else(|| Error::Network("no accessible shards found".into()))?;

    let rows: Vec<Vec<Scalar>> = accessible.iter().map(|(_, s)| s.coefficients.clone()).collect();
    if rank(&rows, k) < k {
        return Err(Error::Network("insufficient linear rank across live shards".into()));
    }

    let mut new_fps = old_fps.clone();
    let mut repair_log: Vec<RepairEntry> = Vec::new();
    let online_vec: Vec<u8> = online_slots.iter().copied().collect();

    if accessible_before <= trigger {
        let accessible_set: BTreeSet<usize> = accessible.iter().map(|(s, _)| *s).collect();
        let target_slots: Vec<u8> = (0..n)
            .filter(|i| !accessible_set.contains(i))
            .map(|i| i as u8)
            .collect();
        let needed = target
            .saturating_sub(accessible_before)
            .min(target_slots.len());
        let parent_pool = accessible.clone();
        let m = parent_pool.len();

        for idx in 0..needed {
            let (pa, shard_a) = &parent_pool[idx % m];
            let mut b_idx = (idx * 7 + 1 + idx / m) % m;
            if b_idx == idx % m {
                b_idx = (idx % m + 1) % m;
            }
            for _ in 0..m {
                if parent_pool[b_idx].1.coefficients != shard_a.coefficients {
                    break;
                }
                b_idx = (b_idx + 1) % m;
            }
            let (pb, shard_b) = &parent_pool[b_idx];
            let factor_b = Scalar::from(idx as u64 + 2);

            let repaired = repair_local_field(shard_a, shard_b, factor_b)?;
            verify_homomorphic_repair(
                &state.kzg,
                &old_root,
                AuthenticatedShard {
                    shard: shard_a,
                    index: *pa,
                    proof: &old_proofs[*pa],
                },
                AuthenticatedShard {
                    shard: shard_b,
                    index: *pb,
                    proof: &old_proofs[*pb],
                },
                factor_b,
                &repaired,
            )?;

            let target_slot = target_slots[idx];
            let custodian = online_vec[idx % online_vec.len()];
            let custodian_addr = roster[custodian as usize].p2p_addr;

            let next_gen = manifest.slot_generations.get(&target_slot).copied().unwrap_or(0) + 1;
            let store_reply = send_p2p(
                custodian_addr,
                &P2pRequest::StoreShard {
                    slot: target_slot,
                    is_custodian: true,
                    generation: next_gen,
                    shard: ShardDto::from_shard(&repaired),
                    proof_hex: String::new(),
                },
            )
            .await?;
            match store_reply {
                P2pResponse::StoreAck { ok: true, .. } => {}
                other => {
                    return Err(Error::Network(format!(
                        "custodian StoreShard failed for slot {target_slot}: {other:?}"
                    )));
                }
            }

            new_fps[target_slot as usize] = repaired.fingerprint();
            manifest.custodian_owners.insert(target_slot, custodian);
            manifest.slot_generations.insert(target_slot, next_gen);
            repair_log.push(RepairEntry {
                repaired_slot: target_slot,
                parent_slot_a: *pa as u8,
                parent_slot_b: *pb as u8,
                factor_b: scalar_to_bytes(&factor_b),
            });
            accessible.push((target_slot as usize, repaired));
        }
    }

    let (new_blobs_root, new_proofs) = if repair_log.is_empty() {
        (old_root, old_proofs.clone())
    } else {
        let root = state.kzg.commit(&new_fps)?;
        let proofs = state.kzg.open_all(&new_fps)?;
        (root, proofs)
    };

    let sample_index = expected_sample_index(&epoch_seed, swarm_id, epoch, n);
    let sample_eval = scalar_to_bytes(&new_fps[sample_index as usize]);
    let kzg_sample_proof = new_proofs[sample_index as usize];

    let repair_audit = if repair_log.is_empty() {
        None
    } else {
        let entry_index =
            expected_repair_audit_index(&epoch_seed, swarm_id, epoch, repair_log.len());
        let entry = &repair_log[entry_index];
        let pa = entry.parent_slot_a as usize;
        let pb = entry.parent_slot_b as usize;
        let pr = entry.repaired_slot as usize;
        let unchanged_slot =
            expected_unchanged_slot_index(&epoch_seed, swarm_id, epoch, &repair_log, n)
                .ok_or_else(|| {
                    Error::Network("no unchanged slot available for repair audit".into())
                })?;
        let unchanged_idx = unchanged_slot as usize;

        Some(RepairAuditProof {
            entry_index,
            old_blobs_root: old_root,
            parent_a_eval: scalar_to_bytes(&old_fps[pa]),
            parent_a_proof: old_proofs[pa],
            parent_b_eval: scalar_to_bytes(&old_fps[pb]),
            parent_b_proof: old_proofs[pb],
            repaired_eval: scalar_to_bytes(&new_fps[pr]),
            repaired_proof: new_proofs[pr],
            unchanged_slot,
            unchanged_eval: scalar_to_bytes(&old_fps[unchanged_idx]),
            unchanged_old_proof: old_proofs[unchanged_idx],
            unchanged_new_proof: new_proofs[unchanged_idx],
        })
    };

    let mut uptime_bitmap = 0u128;
    for &s in &online_slots {
        uptime_bitmap |= 1u128 << s;
    }

    let msg = NativeTransaction::checkpoint_signing_bytes(
        swarm_id,
        epoch,
        aggregator_slot,
        &new_blobs_root,
        &repair_log,
        uptime_bitmap,
        sample_index,
        &sample_eval,
    );
    let sig: Signature = agg_key.sign(&msg);
    let ckpt_tx = NativeTransaction::SubmitSwarmCheckpoint {
        swarm_id,
        epoch,
        aggregator_slot,
        new_blobs_root,
        repair_log: repair_log.clone(),
        uptime_bitmap,
        sample_index,
        sample_eval,
        kzg_sample_proof,
        repair_audit,
        aggregator_p256_sig: sig.to_bytes().into(),
    };

    let block: FinalizedBlockDto = http_request_json(
        &state.l1_rpc_url,
        "POST",
        "/tx/submit",
        Some(&TxDto::from_native(&ckpt_tx)),
    )
    .await?;

    manifest.root_hex = hex::encode(new_blobs_root);
    sync_manifest_roster(&mut manifest, &swarm.roster_pubkeys_hex);
    manifest.slot_fps_hex = new_fps
        .iter()
        .map(|s| hex::encode(scalar_to_bytes(s)))
        .collect();
    manifest.slot_proofs_hex = new_proofs.iter().map(hex::encode).collect();
    NodeStorage::save_manifest(&state.data_dir, &manifest)?;

    broadcast_manifest(
        &manifest,
        online_slots
            .iter()
            .map(|&slot| roster[slot as usize].p2p_addr),
    )
    .await;

    let repaired_slots = repair_log.iter().map(|r| r.repaired_slot).collect();
    let bonus = block
        .receipts
        .first()
        .map(|r| r.aggregator_bonus)
        .unwrap_or(0);

    Ok(CycleReportDto {
        swarm_id,
        epoch,
        aggregator_slot,
        online_slots: online_slots.len(),
        accessible_shards_before: accessible_before,
        repaired_slots,
        accessible_shards_after: accessible.len(),
        new_blobs_root_hex: manifest.root_hex,
        block_height: block.header.height,
        aggregator_bonus: bonus,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settlement_watch_counts_stale_ticks_and_resets_on_progress() {
        let mut watch = SettlementWatch::default();
        assert_eq!(watch.observe(0, 3), 0);
        assert_eq!(watch.observe(0, 3), 1);
        assert_eq!(watch.observe(0, 3), 2);
        assert_eq!(watch.observe(0, 4), 0);
        assert_eq!(watch.observe(1, 4), 0);
    }

    fn manifest(roster: &[&str], custodians: &[(u8, u8)]) -> SwarmManifestDto {
        SwarmManifestDto {
            swarm_id: 0,
            object_id_hex: "ab".into(),
            root_hex: String::new(),
            roster_pubkeys_hex: roster.iter().map(|s| s.to_string()).collect(),
            slot_fps_hex: Vec::new(),
            slot_proofs_hex: Vec::new(),
            custodian_owners: custodians.iter().copied().collect(),
            slot_generations: BTreeMap::new(),
        }
    }

    fn roster(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn plan_handoffs_selects_replaced_slots_held_by_local_custodian() {
        let m = manifest(&["aa", "bb", "cc", "dd"], &[(0, 2), (1, 3), (3, 2)]);
        let hosted = BTreeSet::from([2u8]);
        let current = roster(&["AA", "b2", "cc", "d2"]);
        assert_eq!(plan_handoffs(&m, &hosted, &current), vec![3]);
    }

    #[test]
    fn plan_handoffs_ignores_unchanged_roster_and_foreign_custodians() {
        let m = manifest(&["aa", "bb"], &[(0, 1)]);
        assert!(plan_handoffs(&m, &BTreeSet::from([1u8]), &roster(&["AA", "bb"])).is_empty());
        assert!(plan_handoffs(&m, &BTreeSet::from([0u8]), &roster(&["a2", "bb"])).is_empty());
        assert!(plan_handoffs(&m, &BTreeSet::from([1u8]), &roster(&[])).is_empty());
    }

    #[test]
    fn sync_manifest_roster_keeps_recorded_key_for_pending_custodian_slots() {
        let mut m = manifest(&["aa", "bb", "cc"], &[(1, 2)]);
        sync_manifest_roster(&mut m, &roster(&["a2", "b2", "c2"]));
        assert_eq!(m.roster_pubkeys_hex, roster(&["a2", "bb", "c2"]));
    }

    #[test]
    fn sync_manifest_roster_adopts_l1_roster_when_none_recorded() {
        let mut m = manifest(&[], &[(1, 2)]);
        sync_manifest_roster(&mut m, &roster(&["a2", "b2"]));
        assert_eq!(m.roster_pubkeys_hex, roster(&["a2", "b2"]));
    }
}
