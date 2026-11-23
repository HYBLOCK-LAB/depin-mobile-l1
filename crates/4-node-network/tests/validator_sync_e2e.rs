use l1_state_engine::executor::{expected_sample_index, heartbeat_signing_bytes};
use l1_state_engine::state_db::{NativeTransaction, MAX_SWARM_SIZE};
use node_network::client::{
    build_cluster_map, register_cluster_via_nodes, slots_for_node, upload_payload,
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
    P2pResponse, TxDto,
};
use p256::ecdsa::{signature::Signer, Signature};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;

const NODE_COUNT: usize = 10;
const VALIDATOR_COUNT: usize = 4;

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
        let path =
            std::env::temp_dir().join(format!("depin_{name}_{}_{nanos}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

struct Net {
    root: PathBuf,
    seeds: Vec<(u64, u64)>,
    p2p: Vec<SocketAddr>,
    rpc: Vec<SocketAddr>,
}

impl Net {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            seeds: (0..VALIDATOR_COUNT as u64)
                .map(|id| (id, 900 + id))
                .collect(),
            p2p: (0..VALIDATOR_COUNT).map(|_| reserve_addr()).collect(),
            rpc: (0..VALIDATOR_COUNT).map(|_| reserve_addr()).collect(),
        }
    }

    async fn start_validator(&self, id: usize) -> ValidatorDaemonHandle {
        let peers = self
            .p2p
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != id)
            .map(|(_, addr)| *addr)
            .collect();
        start_validator_daemon(ValidatorDaemonConfig {
            validator_id: id as u64,
            p2p_addr: self.p2p[id],
            rpc_addr: self.rpc[id],
            peer_p2p_addrs: peers,
            validator_seeds: self.seeds.clone(),
            data_dir: self.root.join(format!("validator_{id}")),
            epoch_seed: DEFAULT_EPOCH_SEED,
            kzg_seed: DEFAULT_KZG_SEED,
        })
        .await
        .expect("start validator")
    }

    async fn start_validators(&self) -> Vec<ValidatorDaemonHandle> {
        let mut validators = Vec::new();
        for id in 0..VALIDATOR_COUNT {
            validators.push(self.start_validator(id).await);
        }
        validators
    }

    async fn restart_validator(&self, validators: &mut Vec<ValidatorDaemonHandle>, id: usize) {
        validators.remove(id).shutdown().await;
        validators.insert(id, self.start_validator(id).await);
    }

    fn rpc_url(&self, id: usize) -> String {
        format!("http://{}", self.rpc[id])
    }

    async fn status(&self, id: usize) -> L1StatusDto {
        http_request_json::<(), L1StatusDto>(&self.rpc_url(id), "GET", "/status", None)
            .await
            .expect("validator status")
    }

    async fn assert_same_tip(&self, ids: &[usize]) -> L1StatusDto {
        let reference = self.status(ids[0]).await;
        for &id in &ids[1..] {
            let other = self.status(id).await;
            assert_eq!(other.height, reference.height, "height of validator {id}");
            assert_eq!(
                other.last_block_hash_hex, reference.last_block_hash_hex,
                "last_block_hash of validator {id}"
            );
        }
        reference
    }
}

async fn start_storage_nodes(
    net: &Net,
    cluster_map: &node_network::wire::SwarmClusterMapDto,
    node_endpoints: &[(u64, SocketAddr, SocketAddr)],
) -> Vec<StorageDaemonHandle> {
    let mut storage_nodes = Vec::new();
    for (node_id, p2p_addr, rpc_addr) in node_endpoints {
        storage_nodes.push(
            start_storage_daemon(StorageDaemonConfig {
                node_id: *node_id,
                slots: slots_for_node(cluster_map, *node_id),
                p2p_addr: *p2p_addr,
                rpc_addr: *rpc_addr,
                l1_rpc_url: net.rpc_url(0),
                cluster_map: Some(cluster_map.clone()),
                auto_register: None,
                data_dir: net.root.join(format!("storage_{node_id}")),
                ip_subnet_hash: *node_id as u16,
                country_code: (*node_id % 8) as u8,
                kzg_seed: DEFAULT_KZG_SEED,
                auto_epoch_interval: None,
            })
            .await
            .expect("start storage node"),
        );
    }
    storage_nodes
}

fn deposit_tx() -> TxDto {
    TxDto::from_native(&NativeTransaction::DepositStorageBounty {
        swarm_id: 0,
        amount: 1,
    })
}

async fn submit(net: &Net, validator: usize, tx: &TxDto) -> FinalizedBlockDto {
    http_request_json(&net.rpc_url(validator), "POST", "/tx/submit", Some(tx))
        .await
        .expect("submit tx")
}

#[test]
fn restarted_validator_replays_wal_syncs_missed_blocks_and_rejoins_consensus() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        let tmp = TempDirGuard::new("validator_sync");
        let net = Net::new(tmp.path.clone());
        let mut validators = net.start_validators().await;

        let node_endpoints: Vec<(u64, SocketAddr, SocketAddr)> = (0..NODE_COUNT as u64)
            .map(|id| (id, reserve_addr(), reserve_addr()))
            .collect();
        let cluster_map = build_cluster_map(0, 2602, &node_endpoints).expect("cluster map");
        let storage_nodes = start_storage_nodes(&net, &cluster_map, &node_endpoints).await;
        register_cluster_via_nodes(&cluster_map)
            .await
            .expect("register all nodes");

        validators.remove(3).shutdown().await;
        for _ in 0..2 {
            submit(&net, 0, &deposit_tx()).await;
        }
        let behind = net.status(0).await.height;
        assert_eq!(behind, NODE_COUNT as u64 + 2);

        validators.push(net.start_validator(3).await);
        let synced = net.assert_same_tip(&[0, 1, 2, 3]).await;
        assert_eq!(synced.height, behind);

        let next = submit(&net, 0, &deposit_tx()).await;
        assert_eq!(next.header.height, behind + 1);
        assert_eq!(next.precommits.len(), VALIDATOR_COUNT);
        let tip = net.assert_same_tip(&[0, 1, 2, 3]).await;
        assert_eq!(tip.height, behind + 1);

        net.restart_validator(&mut validators, 3).await;
        assert_eq!(net.assert_same_tip(&[0, 1, 2, 3]).await.height, tip.height);

        for v in validators {
            v.shutdown().await;
        }
        for s in storage_nodes {
            s.shutdown().await;
        }
    });
}

#[test]
fn restarted_validator_restores_settled_history_for_fault_proof() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        let tmp = TempDirGuard::new("validator_settled_history");
        let net = Net::new(tmp.path.clone());
        let mut validators = net.start_validators().await;

        let node_endpoints: Vec<(u64, SocketAddr, SocketAddr)> = (0..NODE_COUNT as u64)
            .map(|id| (id, reserve_addr(), reserve_addr()))
            .collect();
        let cluster_map = build_cluster_map(0, 2602, &node_endpoints).expect("cluster map");
        let storage_nodes = start_storage_nodes(&net, &cluster_map, &node_endpoints).await;
        register_cluster_via_nodes(&cluster_map)
            .await
            .expect("register all nodes");

        let kzg = ValidatorStorage::load_or_create_kzg(
            &tmp.path.join("client_kzg"),
            MAX_SWARM_SIZE - 1,
            DEFAULT_KZG_SEED,
        )
        .expect("client kzg");
        let payload: Vec<u8> = (0..8_192).map(|i| ((i * 17 + 5) % 251) as u8).collect();
        let (manifest, _) =
            upload_payload(&net.rpc_url(0), Some(&cluster_map), &kzg, &payload, 10_000, 902)
                .await
                .expect("upload payload");

        let agg0_key = deterministic_signing_key(slot_key_seed(0, NODE_COUNT));
        let hb_sig: Signature = agg0_key.sign(&heartbeat_signing_bytes(0, 1, 1));
        let hb_sig_bytes: [u8; 64] = hb_sig.to_bytes().into();
        let issue_resp = send_p2p(
            storage_nodes[1].p2p_addr,
            &P2pRequest::IssueHeartbeatReceipt {
                swarm_id: 0,
                epoch: 1,
                target_slot: 1,
                target_map_slot: None,
                aggregator_slot: 0,
                sig_hex: hex::encode(hb_sig_bytes),
            },
        )
        .await
        .expect("issue heartbeat receipt");
        assert!(matches!(issue_resp, P2pResponse::Ack { ok: true }));

        let status = net.status(0).await;
        let epoch_seed = decode_fixed_hex::<32>(&status.epoch_seed_hex).expect("epoch seed");
        let root_bytes = decode_fixed_hex::<48>(&manifest.root_hex).expect("root bytes");
        let sample_index = expected_sample_index(&epoch_seed, 0, 1, NODE_COUNT);
        let sample_eval =
            decode_fixed_hex::<32>(&manifest.slot_fps_hex[sample_index as usize]).expect("eval");
        let kzg_sample_proof =
            decode_fixed_hex::<48>(&manifest.slot_proofs_hex[sample_index as usize])
                .expect("proof");
        let malicious_bitmap = ((1u128 << NODE_COUNT) - 1) & !(1u128 << 1);
        let ckpt_sig: Signature = agg0_key.sign(&NativeTransaction::checkpoint_signing_bytes(
            0,
            1,
            0,
            &root_bytes,
            &[],
            malicious_bitmap,
            sample_index,
            &sample_eval,
        ));
        let checkpoint = NativeTransaction::SubmitSwarmCheckpoint {
            swarm_id: 0,
            epoch: 1,
            aggregator_slot: 0,
            new_blobs_root: root_bytes,
            repair_log: Vec::new(),
            uptime_bitmap: malicious_bitmap,
            sample_index,
            sample_eval,
            kzg_sample_proof,
            repair_audit: None,
            aggregator_p256_sig: ckpt_sig.to_bytes().into(),
        };
        submit(&net, 0, &TxDto::from_native(&checkpoint)).await;

        net.restart_validator(&mut validators, 1).await;
        net.assert_same_tip(&[0, 1, 2, 3]).await;

        let (stored_agg_slot, stored_sig) =
            NodeStorage::load_heartbeat_receipt(&tmp.path.join("storage_1"), 1, 1)
                .expect("load receipt")
                .expect("receipt on disk");
        let fault_tx = NativeTransaction::SubmitHeartbeatFaultProof {
            swarm_id: 0,
            epoch: 1,
            node_slot: 1,
            aggregator_slot: stored_agg_slot,
            signed_pong_receipt: stored_sig,
        };
        let fault_block = submit(&net, 0, &TxDto::from_native(&fault_tx)).await;
        assert_eq!(fault_block.receipts[0].slashed_amount, 500);
        assert_eq!(fault_block.precommits.len(), VALIDATOR_COUNT);

        let tip = net.assert_same_tip(&[0, 1, 2, 3]).await;
        assert_eq!(tip.height, fault_block.header.height);

        for v in validators {
            v.shutdown().await;
        }
        for s in storage_nodes {
            s.shutdown().await;
        }
    });
}
