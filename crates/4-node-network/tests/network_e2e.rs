use l1_state_engine::executor::{expected_sample_index, heartbeat_signing_bytes};
use l1_state_engine::state_db::{compute_member_verkle_root, NativeTransaction, MAX_SWARM_SIZE};
use node_network::client::{
    build_cluster_map, download_payload, register_cluster_batch_via_nodes,
    register_cluster_via_nodes, slots_for_node, upload_payload,
};
use node_network::l1_daemon::{
    start_validator_daemon, ValidatorDaemonConfig, DEFAULT_EPOCH_SEED, DEFAULT_KZG_SEED,
};
use node_network::persistence::{deterministic_signing_key, NodeStorage, ValidatorStorage};
use node_network::storage_daemon::{slot_key_seed, start_storage_daemon, StorageDaemonConfig};
use node_network::wire::{
    decode_fixed_hex, http_request_json, send_p2p, CycleReportDto, FinalizedBlockDto, L1StatusDto,
    P2pRequest, P2pResponse, TxDto,
};
use p256::ecdsa::{signature::Signer, Signature};
use serde::Serialize;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;

const NODE_COUNT: usize = 10;
const K: usize = 2;
const T_REPAIR: usize = 4;
const T_TARGET: usize = 6;
const DOWN_NODES: usize = NODE_COUNT - T_REPAIR;

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

#[derive(Serialize)]
struct RunCycleReq {
    epoch: u64,
}

#[test]
fn distributed_bft_lazy_repair_crash_recovery_and_download_e2e() {
    const REGISTERED_COUNT: usize = NODE_COUNT + 1;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        let tmp = TempDirGuard::new("network_e2e");

        let validator_seeds: Vec<(u64, u64)> = (0..4).map(|id| (id, 900 + id)).collect();
        let val_p2p: Vec<SocketAddr> = (0..4).map(|_| reserve_addr()).collect();
        let val_rpc: Vec<SocketAddr> = (0..4).map(|_| reserve_addr()).collect();

        let mut validators = Vec::new();
        for id in 0..4usize {
            let peers: Vec<SocketAddr> = val_p2p
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != id)
                .map(|(_, addr)| *addr)
                .collect();
            let handle = start_validator_daemon(ValidatorDaemonConfig {
                validator_id: id as u64,
                p2p_addr: val_p2p[id],
                rpc_addr: val_rpc[id],
                peer_p2p_addrs: peers,
                validator_seeds: validator_seeds.clone(),
                data_dir: tmp.path.join(format!("validator_{id}")),
                epoch_seed: DEFAULT_EPOCH_SEED,
                kzg_seed: DEFAULT_KZG_SEED,
            })
            .await
            .expect("start validator");
            validators.push(handle);
        }

        let node_endpoints: Vec<(u64, SocketAddr, SocketAddr)> = (0..REGISTERED_COUNT as u64)
            .map(|id| (id, reserve_addr(), reserve_addr()))
            .collect();
        let cluster_map =
            build_cluster_map(0, 2602, &node_endpoints).expect("build cluster map");

        let mut storage_nodes = Vec::new();
        for (node_id, p2p_addr, rpc_addr) in &node_endpoints {
            let slots = slots_for_node(&cluster_map, *node_id);
            let handle = start_storage_daemon(StorageDaemonConfig {
                node_id: *node_id,
                slots,
                p2p_addr: *p2p_addr,
                rpc_addr: *rpc_addr,
                l1_rpc_url: validators[0].rpc_url.clone(),
                cluster_map: Some(cluster_map.clone()),
                auto_register: None,
                data_dir: tmp.path.join(format!("storage_{node_id}")),
                ip_subnet_hash: *node_id as u16,
                country_code: (*node_id % 8) as u8,
                kzg_seed: DEFAULT_KZG_SEED,
            })
            .await
            .expect("start storage node");
            storage_nodes.push(handle);
        }

        // Register map slot 0 last so it stays on standby and L1 slots differ from map slots.
        let mut registration_map = cluster_map.clone();
        registration_map.slots.rotate_left(1);
        let reg_count = register_cluster_via_nodes(&registration_map)
            .await
            .expect("register all nodes");
        assert_eq!(reg_count, REGISTERED_COUNT);

        let status_after_reg: L1StatusDto =
            http_request_json::<(), L1StatusDto>(&validators[2].rpc_url, "GET", "/status", None)
                .await
                .expect("status on follower validator");
        assert_eq!(status_after_reg.registered_nodes, REGISTERED_COUNT);
        assert_eq!(status_after_reg.height, REGISTERED_COUNT as u64);
        assert_eq!(status_after_reg.swarm_count, 1);
        let expected_roster: Vec<String> = cluster_map.slots[1..]
            .iter()
            .map(|s| s.pubkey_hex.clone())
            .collect();
        assert_eq!(status_after_reg.swarms[0].roster_pubkeys_hex, expected_roster);

        // 2. 원본 파일 인코딩, Zero-Tx 라우팅(+바운티 예치), 10조각 실제 TCP P2P 분산 업로드
        let kzg = ValidatorStorage::load_or_create_kzg(
            &tmp.path.join("client_kzg"),
            MAX_SWARM_SIZE - 1,
            DEFAULT_KZG_SEED,
        )
        .expect("client kzg");
        let payload: Vec<u8> = (0..12_345).map(|i| ((i * 29 + 7) % 253) as u8).collect();
        let (manifest, init_block) = upload_payload(
            &validators[0].rpc_url,
            Some(&cluster_map),
            &kzg,
            &payload,
            5_000,
            901,
        )
        .await
        .expect("upload payload");
        let init_block = init_block.expect("bounty deposit block");
        assert_eq!(init_block.header.height, REGISTERED_COUNT as u64 + 1);

        // 디스크 영속화 검증
        assert!(NodeStorage::load_shard(&tmp.path.join("storage_1"), 0, &manifest.object_id_hex)
            .expect("load shard 0")
            .is_some());
        assert!(tmp.path.join("validator_0/l1_snapshot.json").exists());
        assert!(tmp.path.join("validator_0/blocks.jsonl").exists());

        // Leave the standby online while the first six L1 roster members go offline.
        let v3 = validators.pop().expect("v3");
        v3.shutdown().await;
        let down_nodes: Vec<_> = storage_nodes.drain(1..=DOWN_NODES).collect();
        for node in down_nodes {
            node.shutdown().await;
        }

        let report: CycleReportDto = http_request_json(
            &storage_nodes[1].rpc_url,
            "POST",
            "/aggregator/run_cycle",
            Some(&RunCycleReq { epoch: 1 }),
        )
        .await
        .expect("run aggregator cycle");

        assert_eq!(report.aggregator_slot, DOWN_NODES as u8);
        assert_eq!(report.online_slots, T_REPAIR);
        assert_eq!(report.accessible_shards_before, T_REPAIR);
        assert_eq!(
            report.repaired_slots,
            (0..(T_TARGET - T_REPAIR) as u8).collect::<Vec<_>>()
        );
        assert_eq!(report.accessible_shards_after, T_TARGET);
        assert_eq!(report.aggregator_bonus, 50);
        assert_eq!(report.block_height, REGISTERED_COUNT as u64 + 2);
        assert_ne!(report.new_blobs_root_hex, manifest.root_hex);

        // L1 slot 7 uses the key and endpoint from cluster map slot 8.
        let (receipt_agg_slot, receipt_sig) =
            NodeStorage::load_heartbeat_receipt(&tmp.path.join("storage_8"), 1, 7)
                .expect("load heartbeat receipt")
                .expect("online peer must persist aggregator heartbeat receipt");
        assert_eq!(receipt_agg_slot, DOWN_NODES as u8);
        assert_ne!(receipt_sig, [0u8; 64]);

        // 좀비 generation 가드: custodian node 6에 generation=0 과거 덮어쓰기 시도 (custodian 아닌 일반 슬롯 6에 대해서는 rejection 검증)
        let (slot6_shard, _) =
            NodeStorage::load_shard(&tmp.path.join("storage_7"), 6, &manifest.object_id_hex)
                .expect("read slot 6")
                .expect("slot 6 exists");
        // slot 6의 meta generation을 1로 높인 뒤 generation=0 덮어쓰기 거부 확인
        assert!(NodeStorage::save_shard(
            &tmp.path.join("storage_7"),
            6,
            false,
            1,
            &slot6_shard,
            ""
        )
        .expect("upgrade gen"));
        let stale_reply = send_p2p(
            storage_nodes[1].p2p_addr,
            &P2pRequest::StoreShard {
                slot: 6,
                is_custodian: false,
                generation: 0,
                shard: slot6_shard,
                proof_hex: String::new(),
            },
        )
        .await
        .expect("stale reply");
        assert!(matches!(stale_reply, P2pResponse::StoreAck { ok: false, .. }));

        // 5. L1 리더 검증자(v0)를 내렸다가 동일 data_dir에서 재기동 -> 디스크 스냅샷 복구 검증
        let v0 = validators.remove(0);
        let v0_rpc = v0.rpc_addr;
        let v0_p2p = v0.p2p_addr;
        v0.shutdown().await;

        let v0_restarted = start_validator_daemon(ValidatorDaemonConfig {
            validator_id: 0,
            p2p_addr: v0_p2p,
            rpc_addr: v0_rpc,
            peer_p2p_addrs: vec![val_p2p[1], val_p2p[2], val_p2p[3]],
            validator_seeds,
            data_dir: tmp.path.join("validator_0"),
            epoch_seed: DEFAULT_EPOCH_SEED,
            kzg_seed: DEFAULT_KZG_SEED,
        })
        .await
        .expect("restart v0");

        let recovered_status: L1StatusDto =
            http_request_json::<(), L1StatusDto>(&v0_restarted.rpc_url, "GET", "/status", None)
                .await
                .expect("status after restart");
        assert_eq!(recovered_status.height, REGISTERED_COUNT as u64 + 2);
        assert_eq!(recovered_status.registered_nodes, REGISTERED_COUNT);
        let expected_roster_pks: Vec<[u8; 33]> = cluster_map.slots[1..]
            .iter()
            .map(|s| decode_fixed_hex::<33>(&s.pubkey_hex).expect("slot pubkey hex"))
            .collect();
        assert_eq!(
            recovered_status.swarms[0].state.member_verkle_root,
            compute_member_verkle_root(&kzg, &expected_roster_pks).expect("member verkle root")
        );
        assert_eq!(
            hex::encode(recovered_status.swarms[0].state.active_blobs_root),
            report.new_blobs_root_hex
        );

        // 6. 살아있는 4대 노드(6개 접근 가능 조각 = 4 원본 + 2 복구 조각)에서 실제 TCP로 받아 원본 100% 복원
        let (decoded, collected) = download_payload(
            &validators[0].rpc_url,
            Some(&cluster_map),
            &manifest.object_id_hex,
            Some(&storage_nodes[1].rpc_url),
        )
        .await
        .expect("download & decode");
        assert_eq!(collected, T_TARGET);
        assert_eq!(decoded, payload);

        v0_restarted.shutdown().await;
        for v in validators {
            v.shutdown().await;
        }
        for s in storage_nodes {
            s.shutdown().await;
        }
    });
}

#[test]
fn p2p_heartbeat_receipt_fault_proof_and_custodian_handoff_e2e() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        let tmp = TempDirGuard::new("hb_handoff_e2e");

        let validator_seeds: Vec<(u64, u64)> = (0..4).map(|id| (id, 900 + id)).collect();
        let val_p2p: Vec<SocketAddr> = (0..4).map(|_| reserve_addr()).collect();
        let val_rpc: Vec<SocketAddr> = (0..4).map(|_| reserve_addr()).collect();

        let mut validators = Vec::new();
        for id in 0..4usize {
            let peers: Vec<SocketAddr> = val_p2p
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != id)
                .map(|(_, addr)| *addr)
                .collect();
            let handle = start_validator_daemon(ValidatorDaemonConfig {
                validator_id: id as u64,
                p2p_addr: val_p2p[id],
                rpc_addr: val_rpc[id],
                peer_p2p_addrs: peers,
                validator_seeds: validator_seeds.clone(),
                data_dir: tmp.path.join(format!("validator_{id}")),
                epoch_seed: DEFAULT_EPOCH_SEED,
                kzg_seed: DEFAULT_KZG_SEED,
            })
            .await
            .expect("start validator");
            validators.push(handle);
        }

        let node_endpoints: Vec<(u64, SocketAddr, SocketAddr)> = (0..NODE_COUNT as u64)
            .map(|id| (id, reserve_addr(), reserve_addr()))
            .collect();
        let cluster_map =
            build_cluster_map(0, 2602, &node_endpoints).expect("build cluster map");

        let mut storage_nodes = Vec::new();
        for (node_id, p2p_addr, rpc_addr) in &node_endpoints {
            let slots = slots_for_node(&cluster_map, *node_id);
            let handle = start_storage_daemon(StorageDaemonConfig {
                node_id: *node_id,
                slots,
                p2p_addr: *p2p_addr,
                rpc_addr: *rpc_addr,
                l1_rpc_url: validators[0].rpc_url.clone(),
                cluster_map: Some(cluster_map.clone()),
                auto_register: None,
                data_dir: tmp.path.join(format!("storage_{node_id}")),
                ip_subnet_hash: *node_id as u16,
                country_code: (*node_id % 8) as u8,
                kzg_seed: DEFAULT_KZG_SEED,
            })
            .await
            .expect("start storage node");
            storage_nodes.push(handle);
        }

        let reg_count = register_cluster_via_nodes(&cluster_map)
            .await
            .expect("register all nodes");
        assert_eq!(reg_count, NODE_COUNT);

        let kzg = ValidatorStorage::load_or_create_kzg(
            &tmp.path.join("client_kzg"),
            MAX_SWARM_SIZE - 1,
            DEFAULT_KZG_SEED,
        )
        .expect("client kzg");
        let payload: Vec<u8> = (0..8_192).map(|i| ((i * 17 + 5) % 251) as u8).collect();
        let (manifest, _) = upload_payload(
            &validators[0].rpc_url,
            Some(&cluster_map),
            &kzg,
            &payload,
            10_000,
            902,
        )
        .await
        .expect("upload payload");

        // 1. 반장(슬롯 0)이 피어(슬롯 1, storage_1)에게 IssueHeartbeatReceipt 발급 & Ping 영수증 저장 검증
        let agg0_key = deterministic_signing_key(slot_key_seed(0, NODE_COUNT));
        let hb_msg_1 = heartbeat_signing_bytes(0, 1, 1);
        let hb_sig_1: Signature = agg0_key.sign(&hb_msg_1);
        let hb_sig_1_bytes: [u8; 64] = hb_sig_1.to_bytes().into();

        let issue_resp = send_p2p(
            storage_nodes[1].p2p_addr,
            &P2pRequest::IssueHeartbeatReceipt {
                swarm_id: 0,
                epoch: 1,
                target_slot: 1,
                target_map_slot: None,
                aggregator_slot: 0,
                sig_hex: hex::encode(hb_sig_1_bytes),
            },
        )
        .await
        .expect("send IssueHeartbeatReceipt");
        assert!(matches!(issue_resp, P2pResponse::Ack { ok: true }));

        // 미보유 슬롯(0번)에 대한 발급 요청은 거부되어야 함
        let invalid_slot_resp = send_p2p(
            storage_nodes[1].p2p_addr,
            &P2pRequest::IssueHeartbeatReceipt {
                swarm_id: 0,
                epoch: 1,
                target_slot: 0,
                target_map_slot: None,
                aggregator_slot: 0,
                sig_hex: hex::encode(hb_sig_1_bytes),
            },
        )
        .await
        .expect("send IssueHeartbeatReceipt invalid slot");
        assert!(matches!(invalid_slot_resp, P2pResponse::Error { .. }));

        // Ping에 실려 온 aggregator_sig_hex 역시 피어 디스크에 저장되는지 확인 (슬롯 2, storage_2)
        let hb_msg_2 = heartbeat_signing_bytes(0, 1, 2);
        let hb_sig_2: Signature = agg0_key.sign(&hb_msg_2);
        let hb_sig_2_bytes: [u8; 64] = hb_sig_2.to_bytes().into();
        let ping_resp = send_p2p(
            storage_nodes[2].p2p_addr,
            &P2pRequest::Ping {
                from_slot: 0,
                target_slot: 2,
                target_map_slot: None,
                epoch: 1,
                aggregator_sig_hex: hex::encode(hb_sig_2_bytes),
            },
        )
        .await
        .expect("send Ping with receipt");
        assert!(matches!(ping_resp, P2pResponse::Pong { slot: 2, epoch: 1, .. }));
        assert_eq!(
            NodeStorage::load_heartbeat_receipt(&tmp.path.join("storage_2"), 1, 2)
                .expect("load slot 2 receipt"),
            Some((0, hb_sig_2_bytes))
        );

        // 2. 반장(슬롯 0)이 에포크 1 정산 시 슬롯 1을 결석(0)으로 허위 보고 -> 디스크 영수증으로 Fault Proof 슬래싱!
        let status: L1StatusDto =
            http_request_json::<(), L1StatusDto>(&validators[0].rpc_url, "GET", "/status", None)
                .await
                .expect("get status");
        let epoch_seed = decode_fixed_hex::<32>(&status.epoch_seed_hex).expect("epoch seed");
        let root_bytes = decode_fixed_hex::<48>(&manifest.root_hex).expect("root bytes");
        let sample_index = expected_sample_index(&epoch_seed, 0, 1, NODE_COUNT);
        let sample_eval =
            decode_fixed_hex::<32>(&manifest.slot_fps_hex[sample_index as usize]).expect("eval");
        let kzg_sample_proof =
            decode_fixed_hex::<48>(&manifest.slot_proofs_hex[sample_index as usize])
                .expect("proof");
        let malicious_bitmap = ((1u128 << NODE_COUNT) - 1) & !(1u128 << 1);
        let ckpt_msg = NativeTransaction::checkpoint_signing_bytes(
            0,
            1,
            0,
            &root_bytes,
            &[],
            malicious_bitmap,
            sample_index,
            &sample_eval,
        );
        let ckpt_sig: Signature = agg0_key.sign(&ckpt_msg);
        let malicious_ckpt = NativeTransaction::SubmitSwarmCheckpoint {
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
        let _: FinalizedBlockDto = http_request_json(
            &validators[0].rpc_url,
            "POST",
            "/tx/submit",
            Some(&TxDto::from_native(&malicious_ckpt)),
        )
        .await
        .expect("submit malicious checkpoint");

        let (stored_agg_slot, stored_sig) =
            NodeStorage::load_heartbeat_receipt(&tmp.path.join("storage_1"), 1, 1)
                .expect("load slot 1 receipt")
                .expect("slot 1 receipt must exist on disk");
        assert_eq!(stored_agg_slot, 0);

        let fault_tx = NativeTransaction::SubmitHeartbeatFaultProof {
            swarm_id: 0,
            epoch: 1,
            node_slot: 1,
            aggregator_slot: stored_agg_slot,
            signed_pong_receipt: stored_sig,
        };
        let fault_block: FinalizedBlockDto = http_request_json(
            &validators[0].rpc_url,
            "POST",
            "/tx/submit",
            Some(&TxDto::from_native(&fault_tx)),
        )
        .await
        .expect("submit heartbeat fault proof");
        assert_eq!(fault_block.receipts.len(), 1);
        assert_eq!(fault_block.receipts[0].tx_kind, "SubmitHeartbeatFaultProof");
        assert_eq!(fault_block.receipts[0].slashed_amount, 500);
        assert_eq!(fault_block.receipts[0].distributed_reward, 500);

        // 3. 노드 0..5 중단 후 에포크 2 복구 실행 -> storage_6가 custodian으로 보관한 슬롯 0 조각을 대기 노드(standby_10)로 HandoffShard 이관
        for _ in 0..DOWN_NODES {
            let h = storage_nodes.remove(0);
            h.shutdown().await;
        }
        let report: CycleReportDto = http_request_json(
            &storage_nodes[0].rpc_url,
            "POST",
            "/aggregator/run_cycle",
            Some(&RunCycleReq { epoch: 2 }),
        )
        .await
        .expect("run epoch 2 repair cycle");
        assert!(report.repaired_slots.contains(&0));
        assert!(
            NodeStorage::load_heartbeat_receipt(&tmp.path.join("storage_7"), 2, 7)
                .expect("load epoch 2 receipt")
                .is_some()
        );

        let cust_meta = NodeStorage::load_slot_meta(&tmp.path.join("storage_6"), 0, true)
            .expect("load custodian meta")
            .expect("storage_6 must hold custodian meta for slot 0");
        assert!(cust_meta.is_custodian);
        let (cust_shard, _) = NodeStorage::load_shard_by_role(
            &tmp.path.join("storage_6"),
            0,
            true,
            &manifest.object_id_hex,
        )
        .expect("load custodian shard")
        .expect("storage_6 must hold custodian shard for slot 0");

        let standby = start_storage_daemon(StorageDaemonConfig {
            node_id: 10,
            slots: vec![0],
            p2p_addr: reserve_addr(),
            rpc_addr: reserve_addr(),
            l1_rpc_url: validators[0].rpc_url.clone(),
            cluster_map: Some(cluster_map),
            auto_register: None,
            data_dir: tmp.path.join("standby_10"),
            ip_subnet_hash: NODE_COUNT as u16,
            country_code: 2,
            kzg_seed: DEFAULT_KZG_SEED,
        })
        .await
        .expect("start standby node");

        let handoff_reply = send_p2p(
            storage_nodes[0].p2p_addr,
            &P2pRequest::HandoffShard {
                slot: 0,
                object_id_hex: manifest.object_id_hex.clone(),
                target_p2p_addr: standby.p2p_addr.to_string(),
            },
        )
        .await
        .expect("send HandoffShard");
        assert!(matches!(handoff_reply, P2pResponse::StoreAck { ok: true, .. }));

        // 기존 custodian 복사본 및 메타가 정리되었는지 확인
        assert!(NodeStorage::load_slot_meta(&tmp.path.join("storage_6"), 0, true)
            .expect("check custodian meta removed")
            .is_none());
        assert!(NodeStorage::load_shard_by_role(
            &tmp.path.join("storage_6"),
            0,
            true,
            &manifest.object_id_hex,
        )
        .expect("check custodian shard removed")
        .is_none());

        // 신규 standby 노드에 정식 슬롯(is_custodian=false)으로 이관되었는지 확인
        let target_meta = NodeStorage::load_slot_meta(&tmp.path.join("standby_10"), 0, false)
            .expect("load target meta")
            .expect("standby must hold target slot meta");
        assert!(!target_meta.is_custodian);
        assert_eq!(target_meta.generation, cust_meta.generation + 1);
        let (target_shard, _) = NodeStorage::load_shard_by_role(
            &tmp.path.join("standby_10"),
            0,
            false,
            &manifest.object_id_hex,
        )
        .expect("load target shard")
        .expect("standby must hold handed-off shard");
        assert_eq!(target_shard.to_shard().unwrap(), cust_shard.to_shard().unwrap());

        // 이미 이관 완료된 슬롯에 대한 재요청은 실패 응답
        let repeat_reply = send_p2p(
            storage_nodes[0].p2p_addr,
            &P2pRequest::HandoffShard {
                slot: 0,
                object_id_hex: manifest.object_id_hex,
                target_p2p_addr: standby.p2p_addr.to_string(),
            },
        )
        .await
        .expect("repeat HandoffShard");
        assert!(matches!(
            repeat_reply,
            P2pResponse::StoreAck { ok: false, ref message } if message == "custodian shard not found"
        ));

        standby.shutdown().await;
        for v in validators {
            v.shutdown().await;
        }
        for s in storage_nodes {
            s.shutdown().await;
        }
    });
}

#[test]
fn auto_shuffle_zero_tx_routing_and_multifile_upload_download_e2e() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        let tmp = TempDirGuard::new("network_multifile_e2e");

        let validator_seeds: Vec<(u64, u64)> = (0..4).map(|id| (id, 900 + id)).collect();
        let val_p2p: Vec<SocketAddr> = (0..4).map(|_| reserve_addr()).collect();
        let val_rpc: Vec<SocketAddr> = (0..4).map(|_| reserve_addr()).collect();

        let mut validators = Vec::new();
        for id in 0..4usize {
            let peers: Vec<SocketAddr> = val_p2p
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != id)
                .map(|(_, addr)| *addr)
                .collect();
            let handle = start_validator_daemon(ValidatorDaemonConfig {
                validator_id: id as u64,
                p2p_addr: val_p2p[id],
                rpc_addr: val_rpc[id],
                peer_p2p_addrs: peers,
                validator_seeds: validator_seeds.clone(),
                data_dir: tmp.path.join(format!("validator_{id}")),
                epoch_seed: DEFAULT_EPOCH_SEED,
                kzg_seed: DEFAULT_KZG_SEED,
            })
            .await
            .expect("start validator");
            validators.push(handle);
        }

        let node_endpoints: Vec<(u64, SocketAddr, SocketAddr)> = (0..NODE_COUNT as u64)
            .map(|id| (id, reserve_addr(), reserve_addr()))
            .collect();
        let cluster_map =
            build_cluster_map(0, 2602, &node_endpoints).expect("build cluster map");

        let mut storage_nodes = Vec::new();
        for (node_id, p2p_addr, rpc_addr) in &node_endpoints {
            let slots = slots_for_node(&cluster_map, *node_id);
            let handle = start_storage_daemon(StorageDaemonConfig {
                node_id: *node_id,
                slots,
                p2p_addr: *p2p_addr,
                rpc_addr: *rpc_addr,
                l1_rpc_url: validators[0].rpc_url.clone(),
                cluster_map: Some(cluster_map.clone()),
                auto_register: None,
                data_dir: tmp.path.join(format!("storage_{node_id}")),
                ip_subnet_hash: *node_id as u16,
                country_code: (*node_id % 8) as u8,
                kzg_seed: DEFAULT_KZG_SEED,
            })
            .await
            .expect("start storage node");
            storage_nodes.push(handle);
        }

        // 1. 노드 등록 완료 시 L1 셔플러가 자동으로 Swarm #0을 편성하고 키 순서가 cluster_map과 정확히 일치
        let reg_count = register_cluster_via_nodes(&cluster_map)
            .await
            .expect("register all nodes");
        assert_eq!(reg_count, NODE_COUNT);

        let status: L1StatusDto =
            http_request_json::<(), L1StatusDto>(&validators[1].rpc_url, "GET", "/status", None)
                .await
                .expect("status");
        assert_eq!(status.swarm_count, 1);
        assert_eq!(status.swarms[0].swarm_id, 0);
        assert_eq!(status.swarms[0].state.active_blobs_root, [0u8; 48]);
        let expected_roster: Vec<String> = cluster_map
            .slots
            .iter()
            .map(|s| s.pubkey_hex.clone())
            .collect();
        assert_eq!(status.swarms[0].roster_pubkeys_hex, expected_roster);
        assert_eq!(status.height, 10);

        // 2. bounty=0으로 서로 다른 2개 파일을 Zero-Tx P2P 업로드 (온체인 블록 높이 증가 없음)
        let kzg = ValidatorStorage::load_or_create_kzg(
            &tmp.path.join("client_kzg"),
            MAX_SWARM_SIZE - 1,
            DEFAULT_KZG_SEED,
        )
        .expect("client kzg");
        let payload_a: Vec<u8> = (0..8_192).map(|i| ((i * 17 + 3) % 251) as u8).collect();
        let payload_b: Vec<u8> = (0..10_500).map(|i| ((i * 31 + 11) % 247) as u8).collect();

        let (manifest_a, block_a) = upload_payload(
            &validators[0].rpc_url,
            Some(&cluster_map),
            &kzg,
            &payload_a,
            0,
            101,
        )
        .await
        .expect("upload file A");
        assert!(block_a.is_none());
        assert_eq!(manifest_a.swarm_id, 0);

        let (manifest_b, block_b) = upload_payload(
            &validators[0].rpc_url,
            Some(&cluster_map),
            &kzg,
            &payload_b,
            0,
            202,
        )
        .await
        .expect("upload file B");
        assert!(block_b.is_none());
        assert_eq!(manifest_b.swarm_id, 0);
        assert_ne!(manifest_a.object_id_hex, manifest_b.object_id_hex);

        let status_after_uploads: L1StatusDto =
            http_request_json::<(), L1StatusDto>(&validators[0].rpc_url, "GET", "/status", None)
                .await
                .expect("status after zero-tx uploads");
        assert_eq!(status_after_uploads.height, 10);

        // 3. 두 번째 파일 업로드 후에도 파일 A와 파일 B 모두 개별 매니페스트 조회로 100% 복원
        let (decoded_a, count_a) = download_payload(
            &validators[0].rpc_url,
            Some(&cluster_map),
            &manifest_a.object_id_hex,
            Some(&storage_nodes[0].rpc_url),
        )
        .await
        .expect("download file A");
        assert!(count_a >= K);
        assert_eq!(decoded_a, payload_a);

        let (decoded_b, count_b) = download_payload(
            &validators[0].rpc_url,
            Some(&cluster_map),
            &manifest_b.object_id_hex,
            Some(&storage_nodes[0].rpc_url),
        )
        .await
        .expect("download file B");
        assert!(count_b >= K);
        assert_eq!(decoded_b, payload_b);

        // 4. 6대 다운 후 Zero-Tx 초기 루트([0u8; 48])에서 지연 복구 체크포인트 전이 검증
        for _ in 0..DOWN_NODES {
            let h = storage_nodes.remove(0);
            h.shutdown().await;
        }
        let report: CycleReportDto = http_request_json(
            &storage_nodes[0].rpc_url,
            "POST",
            "/aggregator/run_cycle",
            Some(&RunCycleReq { epoch: 1 }),
        )
        .await
        .expect("run aggregator cycle from zero root");
        assert_eq!(report.aggregator_slot, DOWN_NODES as u8);
        assert_eq!(report.repaired_slots.len(), T_TARGET - T_REPAIR);
        assert_eq!(report.block_height, 11);
        assert_eq!(report.aggregator_bonus, 50);

        let status_after_cycle: L1StatusDto =
            http_request_json::<(), L1StatusDto>(&validators[0].rpc_url, "GET", "/status", None)
                .await
                .expect("status after cycle");
        assert_eq!(
            hex::encode(status_after_cycle.swarms[0].state.active_blobs_root),
            report.new_blobs_root_hex
        );

        let (decoded_a_after, _) = download_payload(
            &validators[0].rpc_url,
            Some(&cluster_map),
            &manifest_a.object_id_hex,
            Some(&storage_nodes[0].rpc_url),
        )
        .await
        .expect("download file A after node loss");
        assert_eq!(decoded_a_after, payload_a);

        let (decoded_b_after, _) = download_payload(
            &validators[0].rpc_url,
            Some(&cluster_map),
            &manifest_b.object_id_hex,
            Some(&storage_nodes[0].rpc_url),
        )
        .await
        .expect("download file B after repair");
        assert_eq!(decoded_b_after, payload_b);

        for v in validators {
            v.shutdown().await;
        }
        for s in storage_nodes {
            s.shutdown().await;
        }
    });
}

#[test]
fn batch_registration_16_nodes_forms_adaptive_14_node_swarm_and_repairs_e2e() {
    use l1_state_engine::shuffler::{swarm_params, swarm_sizes};
    use l1_state_engine::state_db::DEFAULT_UPTIME_BPS;
    use std::collections::BTreeMap;

    const BATCH_NODE_COUNT: usize = 16;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        let tmp = TempDirGuard::new("network_batch_16_e2e");
        let custom_epoch_seed = [0xCDu8; 32];

        let validator_seeds: Vec<(u64, u64)> = (0..4).map(|id| (id, 900 + id)).collect();
        let val_p2p: Vec<SocketAddr> = (0..4).map(|_| reserve_addr()).collect();
        let val_rpc: Vec<SocketAddr> = (0..4).map(|_| reserve_addr()).collect();

        let mut validators = Vec::new();
        for id in 0..4usize {
            let peers: Vec<SocketAddr> = val_p2p
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != id)
                .map(|(_, addr)| *addr)
                .collect();
            let handle = start_validator_daemon(ValidatorDaemonConfig {
                validator_id: id as u64,
                p2p_addr: val_p2p[id],
                rpc_addr: val_rpc[id],
                peer_p2p_addrs: peers,
                validator_seeds: validator_seeds.clone(),
                data_dir: tmp.path.join(format!("validator_{id}")),
                epoch_seed: custom_epoch_seed,
                kzg_seed: DEFAULT_KZG_SEED,
            })
            .await
            .expect("start validator");
            validators.push(handle);
        }

        let node_endpoints: Vec<(u64, SocketAddr, SocketAddr)> = (0..BATCH_NODE_COUNT as u64)
            .map(|id| (id, reserve_addr(), reserve_addr()))
            .collect();
        let cluster_map =
            build_cluster_map(0, 2602, &node_endpoints).expect("build cluster map");

        let mut storage_nodes = Vec::new();
        for (node_id, p2p_addr, rpc_addr) in &node_endpoints {
            let slots = slots_for_node(&cluster_map, *node_id);
            let handle = start_storage_daemon(StorageDaemonConfig {
                node_id: *node_id,
                slots,
                p2p_addr: *p2p_addr,
                rpc_addr: *rpc_addr,
                l1_rpc_url: validators[0].rpc_url.clone(),
                cluster_map: Some(cluster_map.clone()),
                auto_register: None,
                data_dir: tmp.path.join(format!("storage_{node_id}")),
                ip_subnet_hash: *node_id as u16,
                country_code: (*node_id % 8) as u8,
                kzg_seed: DEFAULT_KZG_SEED,
            })
            .await
            .expect("start storage node");
            storage_nodes.push(handle);
        }

        // Batch registration submits all 16 nodes in one block -> L1 forms a 14-node adaptive swarm + 2 standby.
        let reg_block = register_cluster_batch_via_nodes(&validators[0].rpc_url, &cluster_map)
            .await
            .expect("batch register cluster");
        assert_eq!(reg_block.header.height, 1);
        assert_eq!(reg_block.header.tx_count, BATCH_NODE_COUNT);

        let expected_n = swarm_sizes(BATCH_NODE_COUNT)[0];
        assert_eq!(expected_n, 14);
        let expected_params = swarm_params(expected_n, DEFAULT_UPTIME_BPS).expect("params");

        let status: L1StatusDto =
            http_request_json::<(), L1StatusDto>(&validators[1].rpc_url, "GET", "/status", None)
                .await
                .expect("status");
        assert_eq!(status.registered_nodes, BATCH_NODE_COUNT);
        assert_eq!(status.swarm_count, 1);
        let swarm = &status.swarms[0];
        assert_eq!(swarm.state.swarm_size_n, expected_params.n);
        assert_eq!(swarm.state.min_threshold_k, expected_params.k);
        assert_eq!(swarm.state.lazy_repair_trigger, expected_params.t_repair);
        assert_eq!(swarm.state.lazy_repair_target, expected_params.t_target);
        assert_eq!(swarm.roster_pubkeys_hex.len(), expected_n);
        assert_eq!(status.registered_nodes - swarm.roster_pubkeys_hex.len(), 2);

        // Verify Ping with target_map_slot signs Pong & persists inline receipt under the L1 slot.
        let slot_by_pubkey: BTreeMap<&str, &node_network::wire::SlotAssignmentDto> = cluster_map
            .slots
            .iter()
            .map(|s| (s.pubkey_hex.as_str(), s))
            .collect();
        let l1_slot1_entry = slot_by_pubkey[swarm.roster_pubkeys_hex[1].as_str()];
        let agg0_sk = deterministic_signing_key(slot_key_seed(
            slot_by_pubkey[swarm.roster_pubkeys_hex[0].as_str()].slot,
            BATCH_NODE_COUNT,
        ));
        let sig: Signature = agg0_sk.sign(&heartbeat_signing_bytes(0, 7, 1));
        let inline_hb_sig: [u8; 64] = sig.to_bytes().into();
        let ping_reply = send_p2p(
            l1_slot1_entry.p2p_addr.parse().expect("p2p addr"),
            &P2pRequest::Ping {
                from_slot: 0,
                target_slot: 1,
                target_map_slot: (l1_slot1_entry.slot != 1).then_some(l1_slot1_entry.slot),
                epoch: 7,
                aggregator_sig_hex: hex::encode(inline_hb_sig),
            },
        )
        .await
        .expect("mapped ping");
        assert!(matches!(
            ping_reply,
            P2pResponse::Pong {
                slot: 1,
                epoch: 7,
                ..
            }
        ));
        assert_eq!(
            NodeStorage::load_heartbeat_receipt(
                &tmp.path.join(format!("storage_{}", l1_slot1_entry.node_id)),
                7,
                1
            )
            .expect("load inline mapped receipt"),
            Some((0, inline_hb_sig))
        );

        let kzg = ValidatorStorage::load_or_create_kzg(
            &tmp.path.join("client_kzg"),
            MAX_SWARM_SIZE - 1,
            DEFAULT_KZG_SEED,
        )
        .expect("client kzg");
        let payload: Vec<u8> = (0..9_000).map(|i| ((i * 23 + 11) % 251) as u8).collect();
        let (manifest, deposit_block) = upload_payload(
            &validators[0].rpc_url,
            Some(&cluster_map),
            &kzg,
            &payload,
            5_000,
            777,
        )
        .await
        .expect("upload payload to adaptive swarm");
        assert_eq!(deposit_block.expect("bounty block").header.height, 2);
        assert_eq!(manifest.roster_pubkeys_hex.len(), expected_n);

        // Take down the first (n - t_repair) roster members while leaving remaining roster & 2 standby nodes up.
        let t_repair = expected_params.t_repair as usize;
        let t_target = expected_params.t_target as usize;
        let down_count = expected_n - t_repair;
        let mut by_node_id: BTreeMap<u64, _> = storage_nodes
            .into_iter()
            .map(|h| (h.node_id, h))
            .collect();
        for pubkey in &swarm.roster_pubkeys_hex[..down_count] {
            let node_id = slot_by_pubkey[pubkey.as_str()].node_id;
            by_node_id.remove(&node_id).expect("down node").shutdown().await;
        }
        let successor_node_id = slot_by_pubkey[swarm.roster_pubkeys_hex[down_count].as_str()].node_id;
        let successor_rpc = by_node_id[&successor_node_id].rpc_url.clone();

        let report: CycleReportDto = http_request_json(
            &successor_rpc,
            "POST",
            "/aggregator/run_cycle",
            Some(&RunCycleReq { epoch: 1 }),
        )
        .await
        .expect("run adaptive cycle with online standby nodes");
        assert_eq!(report.aggregator_slot, down_count as u8);
        assert_eq!(report.online_slots, t_repair);
        assert_eq!(report.accessible_shards_before, t_repair);
        assert_eq!(report.repaired_slots.len(), t_target - t_repair);
        assert_eq!(report.accessible_shards_after, t_target);
        assert_eq!(report.block_height, 3);

        let (decoded, collected) = download_payload(
            &validators[0].rpc_url,
            Some(&cluster_map),
            &manifest.object_id_hex,
            Some(&successor_rpc),
        )
        .await
        .expect("download & decode from adaptive swarm");
        assert_eq!(collected, t_target);
        assert_eq!(decoded, payload);

        for v in validators {
            v.shutdown().await;
        }
        for (_, s) in by_node_id {
            s.shutdown().await;
        }
    });
}
