use crate::l1_daemon::{DEFAULT_EPOCH_SEED, DEFAULT_KZG_SEED};
use crate::persistence::{
    compressed_pubkey, deterministic_signing_key, load_or_create_signing_key, NodeStorage,
    ValidatorStorage,
};
use crate::wire::{
    decode_fixed_hex, http_request_json, proof_from_hex, read_frame, read_http_request,
    root_from_hex, send_p2p, spawn_tcp_server, write_frame, write_http_json, CycleReportDto,
    FinalizedBlockDto, L1StatusDto, P2pRequest, P2pResponse, ShardDto, SlotAssignmentDto,
    SwarmClusterMapDto, SwarmManifestDto, TxDto,
};
use crate::{Error, Result};
use l1_state_engine::executor::{
    expected_repair_audit_index, expected_sample_index, expected_unchanged_slot_index,
    heartbeat_signing_bytes, sign_registration,
};
use l1_state_engine::shuffler::score_node;
use l1_state_engine::state_db::{
    NativeTransaction, RepairAuditProof, RepairEntry, MAX_SWARM_SIZE,
};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use verkle_fountain::fountain::{rank, repair_local_field, Shard};
use verkle_fountain::pollution_guard::{verify_homomorphic_repair, AuthenticatedShard};
use verkle_fountain::verkle_kzg::{bytes_to_scalar, scalar_to_bytes, Kzg, KzgProof, Scalar};

#[derive(Clone, Debug)]
pub struct StorageDaemonConfig {
    pub node_id: u64,
    pub slots: Vec<u8>,
    pub swarm_id: u64,
    pub p2p_addr: SocketAddr,
    pub rpc_addr: SocketAddr,
    pub l1_rpc_url: String,
    pub cluster_map: SwarmClusterMapDto,
    pub data_dir: PathBuf,
    pub ip_subnet_hash: u16,
    pub country_code: u8,
    pub kzg_seed: u64,
}

#[derive(Clone)]
struct StorageRuntimeState {
    node_id: u64,
    swarm_id: u64,
    l1_rpc_url: String,
    cluster_map: SwarmClusterMapDto,
    slot_keys: BTreeMap<u8, SigningKey>,
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
    slots: Vec<u8>,
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

pub async fn start_storage_daemon(config: StorageDaemonConfig) -> Result<StorageDaemonHandle> {
    std::fs::create_dir_all(&config.data_dir)?;
    let mut slot_keys = BTreeMap::new();
    for &slot in &config.slots {
        let key_path = config.data_dir.join("keys").join(format!("slot_{slot}.hex"));
        let key =
            load_or_create_signing_key(&key_path, slot_key_seed(slot, config.cluster_map.slots.len()))?;
        slot_keys.insert(slot, key);
    }

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
        swarm_id: config.swarm_id,
        l1_rpc_url: config.l1_rpc_url,
        cluster_map: config.cluster_map,
        slot_keys,
        kzg,
        data_dir: config.data_dir,
        ip_subnet_hash: config.ip_subnet_hash,
        country_code: config.country_code,
    });

    let p2p_task = spawn_tcp_server(p2p_listener, Arc::clone(&state), handle_storage_p2p);
    let rpc_task = spawn_tcp_server(rpc_listener, state, handle_storage_rpc);

    Ok(StorageDaemonHandle {
        node_id: config.node_id,
        p2p_addr: actual_p2p,
        rpc_addr: actual_rpc,
        rpc_url: format!("http://{actual_rpc}"),
        tasks: vec![p2p_task, rpc_task],
    })
}

async fn handle_storage_p2p(mut stream: TcpStream, state: Arc<StorageRuntimeState>) -> Result<()> {
    let req: P2pRequest = read_frame(&mut stream).await?;
    let resp = match req {
        P2pRequest::Ping {
            from_slot,
            target_slot,
            epoch,
            aggregator_sig_hex,
        } => {
            if let Some(key) = state.slot_keys.get(&target_slot) {
                if !aggregator_sig_hex.is_empty() {
                    NodeStorage::save_heartbeat_receipt(
                        &state.data_dir,
                        state.swarm_id,
                        epoch,
                        target_slot,
                        from_slot,
                        &aggregator_sig_hex,
                    )?;
                }
                let msg = heartbeat_signing_bytes(state.swarm_id, epoch, target_slot);
                let sig: Signature = key.sign(&msg);
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
            aggregator_slot,
            sig_hex,
        } => {
            if swarm_id != state.swarm_id {
                P2pResponse::Error {
                    message: format!(
                        "swarm_id mismatch: expected {}, got {swarm_id}",
                        state.swarm_id
                    ),
                }
            } else if state.slot_keys.contains_key(&target_slot) {
                NodeStorage::save_heartbeat_receipt(
                    &state.data_dir,
                    swarm_id,
                    epoch,
                    target_slot,
                    aggregator_slot,
                    &sig_hex,
                )?;
                P2pResponse::Ack { ok: true }
            } else {
                P2pResponse::Error {
                    message: format!("slot {target_slot} not hosted on node {}", state.node_id),
                }
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
        } => {
            let loaded_shard =
                NodeStorage::load_shard_by_role(&state.data_dir, slot, true, &object_id_hex)?;
            let loaded_meta = NodeStorage::load_slot_meta_for_object(
                &state.data_dir,
                slot,
                true,
                &object_id_hex,
            )?;
            match (loaded_shard, loaded_meta) {
                (Some((shard, proof_hex)), Some(meta)) => {
                    match target_p2p_addr.parse::<SocketAddr>() {
                        Ok(target_addr) => {
                            let generation = meta.generation.saturating_add(1);
                            match send_p2p(
                                target_addr,
                                &P2pRequest::StoreShard {
                                    slot,
                                    is_custodian: false,
                                    generation,
                                    shard,
                                    proof_hex,
                                },
                            )
                            .await
                            {
                                Ok(P2pResponse::StoreAck { ok: true, .. }) => {
                                    NodeStorage::remove_custodian_shard(
                                        &state.data_dir,
                                        slot,
                                        &object_id_hex,
                                    )?;
                                    P2pResponse::StoreAck {
                                        ok: true,
                                        message: "handoff complete".into(),
                                    }
                                }
                                Ok(P2pResponse::StoreAck { ok: false, message }) => {
                                    P2pResponse::StoreAck {
                                        ok: false,
                                        message: format!("target rejected shard: {message}"),
                                    }
                                }
                                Ok(other) => P2pResponse::StoreAck {
                                    ok: false,
                                    message: format!("unexpected target response: {other:?}"),
                                },
                                Err(e) => P2pResponse::StoreAck {
                                    ok: false,
                                    message: format!("handoff transfer failed: {e}"),
                                },
                            }
                        }
                        Err(_) => P2pResponse::StoreAck {
                            ok: false,
                            message: format!("invalid target_p2p_addr: {target_p2p_addr}"),
                        },
                    }
                }
                _ => P2pResponse::StoreAck {
                    ok: false,
                    message: "custodian shard not found".into(),
                },
            }
        }
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
                    slots: state.slot_keys.keys().copied().collect(),
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
        ("POST", "/register_slots") => {
            let mut txs = Vec::with_capacity(state.slot_keys.len());
            for sk in state.slot_keys.values() {
                let (pk, sig) = sign_registration(
                    sk,
                    state.cluster_map.chain_id,
                    state.ip_subnet_hash,
                    state.country_code,
                    1_500,
                );
                txs.push(TxDto::from_native(&NativeTransaction::RegisterMobileNode {
                    pubkey_p256: pk,
                    hw_attestation_sig: sig,
                    ip_subnet_hash: state.ip_subnet_hash,
                    country_code: state.country_code,
                    stake: 1_500,
                }));
            }
            match http_request_json::<Vec<TxDto>, FinalizedBlockDto>(
                &state.l1_rpc_url,
                "POST",
                "/tx/batch",
                Some(&txs),
            )
            .await
            {
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
    slots: &[SlotAssignmentDto],
    from_slot: u8,
    epoch: u64,
) -> Result<BTreeSet<u8>> {
    let mut set = JoinSet::new();
    for entry in slots {
        let slot = entry.slot;
        let addr: SocketAddr = entry
            .p2p_addr
            .parse()
            .map_err(|_| Error::Network(format!("invalid p2p addr: {}", entry.p2p_addr)))?;
        set.spawn(async move {
            let ok = matches!(
                send_p2p(
                    addr,
                    &P2pRequest::Ping {
                        from_slot,
                        target_slot: slot,
                        epoch,
                        aggregator_sig_hex: String::new(),
                    }
                )
                .await,
                Ok(P2pResponse::Pong { .. })
            );
            (slot, ok)
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
    slots: &[SlotAssignmentDto],
    online_slots: &BTreeSet<u8>,
    custodian_owners: &BTreeMap<u8, u8>,
    object_id_hex: &str,
) -> Result<Vec<(usize, Shard)>> {
    let mut targets: Vec<(u8, SocketAddr)> = Vec::new();
    for entry in slots {
        let holder_slot = if online_slots.contains(&entry.slot) {
            Some(entry.slot)
        } else if let Some(&cust) = custodian_owners.get(&entry.slot) {
            online_slots.contains(&cust).then_some(cust)
        } else {
            None
        };
        if let Some(h_slot) = holder_slot {
            if let Some(holder) = slots.iter().find(|s| s.slot == h_slot) {
                let addr: SocketAddr = holder
                    .p2p_addr
                    .parse()
                    .map_err(|_| Error::Network("invalid p2p addr".into()))?;
                targets.push((entry.slot, addr));
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
    l1_status: &L1StatusDto,
    requested_object_id: Option<&str>,
) -> Result<SwarmManifestDto> {
    if requested_object_id.is_some() {
        return NodeStorage::load_manifest_for_object(&state.data_dir, requested_object_id)?
            .ok_or_else(|| Error::Network("requested object manifest missing on node".into()));
    }
    if let Some(sw) = l1_status.swarms.iter().find(|s| s.swarm_id == state.swarm_id) {
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

async fn execute_aggregator_cycle(
    state: &StorageRuntimeState,
    epoch: u64,
    object_id_hex: Option<&str>,
) -> Result<CycleReportDto> {
    let local_hint_slot = *state
        .slot_keys
        .keys()
        .next()
        .ok_or_else(|| Error::Network("no slots hosted on node".into()))?;

    let online_slots =
        ping_all_slots(&state.cluster_map.slots, local_hint_slot, epoch).await?;
    let aggregator_slot = *online_slots
        .iter()
        .next()
        .ok_or_else(|| Error::Network("no online slots in swarm".into()))?;

    let agg_key = state.slot_keys.get(&aggregator_slot).ok_or_else(|| {
        Error::Network(format!(
            "slot {aggregator_slot} is elected aggregator, not hosted on node {}",
            state.node_id
        ))
    })?;

    // 선출된 반장이 온라인 피어 슬롯들에 서명된 Heartbeat 생존 확인 영수증을 발급·저장 요청
    let mut receipt_set = JoinSet::new();
    for &target_slot in &online_slots {
        if let Some(entry) = state.cluster_map.slots.iter().find(|s| s.slot == target_slot) {
            if let Ok(addr) = entry.p2p_addr.parse::<SocketAddr>() {
                let msg = heartbeat_signing_bytes(state.swarm_id, epoch, target_slot);
                let sig: Signature = agg_key.sign(&msg);
                let sig_bytes: [u8; 64] = sig.to_bytes().into();
                let sig_hex = hex::encode(sig_bytes);
                let swarm_id = state.swarm_id;
                receipt_set.spawn(async move {
                    let _ = send_p2p(
                        addr,
                        &P2pRequest::IssueHeartbeatReceipt {
                            swarm_id,
                            epoch,
                            target_slot,
                            aggregator_slot,
                            sig_hex,
                        },
                    )
                    .await;
                });
            }
        }
    }
    while receipt_set.join_next().await.is_some() {}

    let l1_status: L1StatusDto =
        http_request_json::<(), L1StatusDto>(&state.l1_rpc_url, "GET", "/status", None).await?;
    let epoch_seed = decode_fixed_hex::<32>(&l1_status.epoch_seed_hex)?;

    let swarm_state = &l1_status
        .swarms
        .iter()
        .find(|s| s.swarm_id == state.swarm_id)
        .ok_or_else(|| Error::Network("swarm missing on L1".into()))?
        .state;
    let n = swarm_state.swarm_size_n as usize;
    let trigger = swarm_state.lazy_repair_trigger as usize;
    let target = swarm_state.lazy_repair_target as usize;

    let mut manifest = select_cycle_manifest(state, &l1_status, object_id_hex)?;

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
        &state.cluster_map.slots,
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
        let needed = target.saturating_sub(accessible_before).min(target_slots.len());
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
            let custodian_addr: SocketAddr = state
                .cluster_map
                .slots
                .iter()
                .find(|s| s.slot == custodian)
                .ok_or_else(|| Error::Network("missing custodian in cluster map".into()))?
                .p2p_addr
                .parse()
                .map_err(|_| Error::Network("invalid custodian addr".into()))?;

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

    let sample_index = expected_sample_index(&epoch_seed, state.swarm_id, epoch, n);
    let sample_eval = scalar_to_bytes(&new_fps[sample_index as usize]);
    let kzg_sample_proof = new_proofs[sample_index as usize];

    let repair_audit = if repair_log.is_empty() {
        None
    } else {
        let entry_index =
            expected_repair_audit_index(&epoch_seed, state.swarm_id, epoch, repair_log.len());
        let entry = &repair_log[entry_index];
        let pa = entry.parent_slot_a as usize;
        let pb = entry.parent_slot_b as usize;
        let pr = entry.repaired_slot as usize;
        let unchanged_slot = expected_unchanged_slot_index(
            &epoch_seed,
            state.swarm_id,
            epoch,
            &repair_log,
            n,
        )
        .ok_or_else(|| Error::Network("no unchanged slot available for repair audit".into()))?;
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
        state.swarm_id,
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
        swarm_id: state.swarm_id,
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
    manifest.slot_fps_hex = new_fps
        .iter()
        .map(|s| hex::encode(scalar_to_bytes(s)))
        .collect();
    manifest.slot_proofs_hex = new_proofs.iter().map(hex::encode).collect();
    NodeStorage::save_manifest(&state.data_dir, &manifest)?;

    // 살아있는 피어 노드들에 갱신된 매니페스트 동기화
    let unique_online_addrs: BTreeSet<SocketAddr> = state
        .cluster_map
        .slots
        .iter()
        .filter(|s| online_slots.contains(&s.slot))
        .filter_map(|s| s.p2p_addr.parse::<SocketAddr>().ok())
        .collect();
    let mut sync_set = JoinSet::new();
    for addr in unique_online_addrs {
        let m_clone = manifest.clone();
        sync_set.spawn(async move {
            let _ = send_p2p(addr, &P2pRequest::StoreManifest { manifest: m_clone }).await;
        });
    }
    while sync_set.join_next().await.is_some() {}

    let repaired_slots = repair_log.iter().map(|r| r.repaired_slot).collect();
    let bonus = block
        .receipts
        .first()
        .map(|r| r.aggregator_bonus)
        .unwrap_or(0);

    Ok(CycleReportDto {
        swarm_id: state.swarm_id,
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
