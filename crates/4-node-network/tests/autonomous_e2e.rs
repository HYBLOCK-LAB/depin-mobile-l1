use l1_state_engine::executor::{expected_sample_index, heartbeat_signing_bytes};
use l1_state_engine::shuffler::{swarm_params, swarm_sizes};
use l1_state_engine::state_db::{NativeTransaction, DEFAULT_UPTIME_BPS, MAX_SWARM_SIZE};
use node_network::client::{
    build_cluster_map, download_payload, register_cluster_batch_via_nodes,
    register_cluster_via_nodes, slots_for_node, upload_payload,
};
use node_network::l1_daemon::{
    start_validator_daemon, ValidatorDaemonConfig, ValidatorDaemonHandle, DEFAULT_EPOCH_SEED,
    DEFAULT_KZG_SEED,
};
use node_network::persistence::{deterministic_signing_key, NodeStorage, ValidatorStorage};
use node_network::storage_daemon::{
    slot_key_seed, start_storage_daemon, StorageDaemonConfig, StorageDaemonHandle,
};
use node_network::wire::{
    decode_fixed_hex, http_request_json, send_p2p, FinalizedBlockDto, L1StatusDto, P2pRequest,
    SwarmClusterMapDto, TxDto,
};
use p256::ecdsa::{signature::Signer, Signature};
use std::collections::BTreeMap;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::time::{Duration, Instant};

const NODE_COUNT: usize = 10;
const AUTO_EPOCH: Duration = Duration::from_secs(1);
const WAIT_TIMEOUT: Duration = Duration::from_secs(300);
const POLL_INTERVAL: Duration = Duration::from_millis(500);

fn reserve_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral bind");
    listener.local_addr().expect("local addr")
}

struct TempDirGuard {
    path: PathBuf,
}

impl TempDirGuard {
    fn new(name: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("depin_{name}_{}_{nanos}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

async fn start_validators(tmp: &TempDirGuard, epoch_seed: [u8; 32]) -> Vec<ValidatorDaemonHandle> {
    let validator_seeds: Vec<(u64, u64)> = (0..4).map(|id| (id, 900 + id)).collect();
    let val_p2p: Vec<SocketAddr> = (0..4).map(|_| reserve_addr()).collect();
    let val_rpc: Vec<SocketAddr> = (0..4).map(|_| reserve_addr()).collect();
    let mut validators = Vec::new();
    for id in 0..4usize {
        let peers = val_p2p
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != id)
            .map(|(_, addr)| *addr)
            .collect();
        validators.push(
            start_validator_daemon(ValidatorDaemonConfig {
                validator_id: id as u64,
                p2p_addr: val_p2p[id],
                rpc_addr: val_rpc[id],
                peer_p2p_addrs: peers,
                validator_seeds: validator_seeds.clone(),
                data_dir: tmp.path.join(format!("validator_{id}")),
                epoch_seed,
                kzg_seed: DEFAULT_KZG_SEED,
            })
            .await
            .expect("start validator"),
        );
    }
    validators
}

async fn start_storage_nodes(
    tmp: &TempDirGuard,
    l1_rpc: &str,
    node_count: usize,
    auto_epoch_interval: impl Fn(u64) -> Option<Duration>,
) -> (SwarmClusterMapDto, Vec<StorageDaemonHandle>) {
    let endpoints: Vec<(u64, SocketAddr, SocketAddr)> = (0..node_count as u64)
        .map(|id| (id, reserve_addr(), reserve_addr()))
        .collect();
    let cluster_map = build_cluster_map(0, 2602, &endpoints).expect("build cluster map");
    let mut nodes = Vec::new();
    for (node_id, p2p_addr, rpc_addr) in &endpoints {
        nodes.push(
            start_storage_daemon(StorageDaemonConfig {
                node_id: *node_id,
                slots: slots_for_node(&cluster_map, *node_id),
                p2p_addr: *p2p_addr,
                rpc_addr: *rpc_addr,
                l1_rpc_url: l1_rpc.to_string(),
                cluster_map: Some(cluster_map.clone()),
                auto_register: None,
                data_dir: tmp.path.join(format!("storage_{node_id}")),
                ip_subnet_hash: *node_id as u16,
                country_code: (*node_id % 8) as u8,
                kzg_seed: DEFAULT_KZG_SEED,
                auto_epoch_interval: auto_epoch_interval(*node_id),
            })
            .await
            .expect("start storage node"),
        );
    }
    (cluster_map, nodes)
}

async fn l1_status(l1_rpc: &str) -> L1StatusDto {
    http_request_json::<(), L1StatusDto>(l1_rpc, "GET", "/status", None)
        .await
        .expect("l1 status")
}

async fn wait_for_status(
    l1_rpc: &str,
    what: &str,
    mut done: impl FnMut(&L1StatusDto) -> bool,
) -> L1StatusDto {
    let deadline = Instant::now() + WAIT_TIMEOUT;
    loop {
        let status = l1_status(l1_rpc).await;
        if done(&status) {
            return status;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

fn latest_aggregator_slot(status: &L1StatusDto) -> Option<u8> {
    status.swarms[0]
        .recent_settlements
        .last()
        .map(|s| s.aggregator_slot)
}

fn client_kzg(tmp: &TempDirGuard) -> verkle_fountain::verkle_kzg::Kzg {
    ValidatorStorage::load_or_create_kzg(
        &tmp.path.join("client_kzg"),
        MAX_SWARM_SIZE - 1,
        DEFAULT_KZG_SEED,
    )
    .expect("client kzg")
}

#[test]
fn auto_epoch_loop_succeeds_aggregator_without_manual_run_cycle_e2e() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        let tmp = TempDirGuard::new("auto_epoch_succession");
        let validators = start_validators(&tmp, DEFAULT_EPOCH_SEED).await;
        let l1_rpc = validators[0].rpc_url.clone();
        let (cluster_map, mut nodes) =
            start_storage_nodes(&tmp, &l1_rpc, NODE_COUNT, |_| Some(AUTO_EPOCH)).await;
        register_cluster_via_nodes(&cluster_map)
            .await
            .expect("register all nodes");

        let payload: Vec<u8> = (0..8_192).map(|i| ((i * 13 + 7) % 251) as u8).collect();
        upload_payload(&l1_rpc, Some(&cluster_map), &client_kzg(&tmp), &payload, 10_000, 311)
            .await
            .expect("upload payload");

        let status = wait_for_status(&l1_rpc, "two epochs settled by slot 0", |s| {
            s.swarms[0].state.last_epoch_settled >= 2 && latest_aggregator_slot(s) == Some(0)
        })
        .await;
        let baseline = status.swarms[0].state.last_epoch_settled;

        let first_aggregator = cluster_map.slots[0].node_id;
        let idx = nodes
            .iter()
            .position(|h| h.node_id == first_aggregator)
            .expect("slot 0 node");
        nodes.remove(idx).shutdown().await;

        let status = wait_for_status(&l1_rpc, "slot 1 to succeed as aggregator", |s| {
            s.swarms[0].state.last_epoch_settled >= baseline + 2
                && latest_aggregator_slot(s) == Some(1)
        })
        .await;
        assert!(status.swarms[0].state.last_epoch_settled >= baseline + 2);

        for v in validators {
            v.shutdown().await;
        }
        for n in nodes {
            n.shutdown().await;
        }
    });
}

#[test]
fn victim_node_auto_submits_fault_proof_against_forged_attendance_e2e() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        let tmp = TempDirGuard::new("auto_fault_proof");
        let validators = start_validators(&tmp, DEFAULT_EPOCH_SEED).await;
        let l1_rpc = validators[0].rpc_url.clone();
        let (cluster_map, nodes) =
            start_storage_nodes(&tmp, &l1_rpc, NODE_COUNT, |node_id| {
                (node_id != 0).then_some(AUTO_EPOCH)
            })
            .await;
        register_cluster_via_nodes(&cluster_map)
            .await
            .expect("register all nodes");

        let payload: Vec<u8> = (0..8_192).map(|i| ((i * 17 + 5) % 251) as u8).collect();
        let (manifest, _) =
            upload_payload(&l1_rpc, Some(&cluster_map), &client_kzg(&tmp), &payload, 10_000, 902)
                .await
                .expect("upload payload");

        let agg_key = deterministic_signing_key(slot_key_seed(0, NODE_COUNT));
        let receipt_sig: Signature = agg_key.sign(&heartbeat_signing_bytes(0, 1, 1));
        let receipt_reply = send_p2p(
            nodes[1].p2p_addr,
            &P2pRequest::IssueHeartbeatReceipt {
                swarm_id: 0,
                epoch: 1,
                target_slot: 1,
                target_map_slot: None,
                aggregator_slot: 0,
                sig_hex: hex::encode(receipt_sig.to_bytes()),
            },
        )
        .await
        .expect("issue receipt");
        assert!(matches!(receipt_reply, node_network::wire::P2pResponse::Ack { ok: true }));

        let status = l1_status(&l1_rpc).await;
        let epoch_seed = decode_fixed_hex::<32>(&status.epoch_seed_hex).expect("epoch seed");
        let root = decode_fixed_hex::<48>(&manifest.root_hex).expect("root");
        let sample_index = expected_sample_index(&epoch_seed, 0, 1, NODE_COUNT);
        let sample_eval =
            decode_fixed_hex::<32>(&manifest.slot_fps_hex[sample_index as usize]).expect("eval");
        let kzg_sample_proof =
            decode_fixed_hex::<48>(&manifest.slot_proofs_hex[sample_index as usize]).expect("proof");
        let forged_bitmap = ((1u128 << NODE_COUNT) - 1) & !(1u128 << 1);
        let ckpt_sig: Signature = agg_key.sign(&NativeTransaction::checkpoint_signing_bytes(
            0,
            1,
            0,
            &root,
            &[],
            forged_bitmap,
            sample_index,
            &sample_eval,
        ));
        let aggregator_pubkey = cluster_map.slots[0].pubkey_hex.clone();
        let stake_of = |s: &L1StatusDto| {
            s.nodes
                .iter()
                .find(|n| n.pubkey_hex == aggregator_pubkey)
                .expect("aggregator account")
                .stake
        };
        let stake_before = stake_of(&status);

        let forged = NativeTransaction::SubmitSwarmCheckpoint {
            swarm_id: 0,
            epoch: 1,
            aggregator_slot: 0,
            new_blobs_root: root,
            repair_log: Vec::new(),
            uptime_bitmap: forged_bitmap,
            sample_index,
            sample_eval,
            kzg_sample_proof,
            repair_audit: None,
            aggregator_p256_sig: ckpt_sig.to_bytes().into(),
        };
        let _: FinalizedBlockDto =
            http_request_json(&l1_rpc, "POST", "/tx/submit", Some(&TxDto::from_native(&forged)))
                .await
                .expect("submit forged checkpoint");

        let status = wait_for_status(&l1_rpc, "aggregator stake slashed by fault proof", |s| {
            stake_of(s) < stake_before
        })
        .await;
        assert_eq!(stake_of(&status), stake_before - 500);

        for v in validators {
            v.shutdown().await;
        }
        for n in nodes {
            n.shutdown().await;
        }
    });
}

#[test]
fn custodian_auto_hands_off_shards_to_standby_nodes_after_slashing_e2e() {
    const BATCH_NODE_COUNT: usize = 16;
    const STANDBY_COUNT: usize = 2;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        let tmp = TempDirGuard::new("auto_handoff");
        let validators = start_validators(&tmp, [0xCDu8; 32]).await;
        let l1_rpc = validators[0].rpc_url.clone();
        let (cluster_map, nodes) =
            start_storage_nodes(&tmp, &l1_rpc, BATCH_NODE_COUNT, |_| Some(AUTO_EPOCH)).await;
        register_cluster_batch_via_nodes(&l1_rpc, &cluster_map)
            .await
            .expect("batch register");

        let status = l1_status(&l1_rpc).await;
        let initial_roster = status.swarms[0].roster_pubkeys_hex.clone();
        let n = swarm_sizes(BATCH_NODE_COUNT)[0];
        let params = swarm_params(n, DEFAULT_UPTIME_BPS).expect("swarm params");
        assert_eq!(initial_roster.len(), n);

        let payload: Vec<u8> = (0..9_000).map(|i| ((i * 23 + 11) % 251) as u8).collect();
        let (manifest, _) =
            upload_payload(&l1_rpc, Some(&cluster_map), &client_kzg(&tmp), &payload, 5_000, 777)
                .await
                .expect("upload payload");

        let node_id_of: BTreeMap<String, u64> = cluster_map
            .slots
            .iter()
            .map(|s| (s.pubkey_hex.clone(), s.node_id))
            .collect();
        let down_count = n - params.t_repair as usize;
        let mut live: BTreeMap<u64, StorageDaemonHandle> =
            nodes.into_iter().map(|h| (h.node_id, h)).collect();
        for pubkey in &initial_roster[..down_count] {
            live.remove(&node_id_of[pubkey]).expect("roster node").shutdown().await;
        }

        let handed_off = (params.t_target - params.t_repair) as usize;
        let handed_off = handed_off.min(STANDBY_COUNT);
        let status = wait_for_status(&l1_rpc, "standby nodes to replace slashed slots", |s| {
            (0..STANDBY_COUNT).all(|slot| s.swarms[0].roster_pubkeys_hex[slot] != initial_roster[slot])
        })
        .await;
        let new_roster = status.swarms[0].roster_pubkeys_hex.clone();

        let deadline = Instant::now() + WAIT_TIMEOUT;
        for slot in 0..handed_off {
            let dir = tmp.path.join(format!("storage_{}", node_id_of[&new_roster[slot]]));
            while NodeStorage::load_shard_by_role(&dir, slot as u8, false, &manifest.object_id_hex)
                .expect("load handed-off shard")
                .is_none()
            {
                assert!(Instant::now() < deadline, "slot {slot} was not handed off");
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        }

        let any_live_rpc = live.values().next().expect("live node").rpc_url.clone();
        let (decoded, _) = download_payload(
            &l1_rpc,
            Some(&cluster_map),
            &manifest.object_id_hex,
            Some(&any_live_rpc),
        )
        .await
        .expect("download after handoff");
        assert_eq!(decoded, payload);

        for v in validators {
            v.shutdown().await;
        }
        for (_, n) in live {
            n.shutdown().await;
        }
    });
}
