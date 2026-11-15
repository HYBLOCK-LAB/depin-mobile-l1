use l1_state_engine::executor::{expected_sample_index, heartbeat_signing_bytes};
use l1_state_engine::state_db::{NativeTransaction, SWARM_SIZE};
use node_network::client::{
    build_cluster_map, download_payload, register_cluster_via_nodes, slots_for_node, upload_payload,
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

        let node_endpoints: Vec<(u64, SocketAddr, SocketAddr)> = (0..10u64)
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
                swarm_id: 0,
                p2p_addr: *p2p_addr,
                rpc_addr: *rpc_addr,
                l1_rpc_url: validators[0].rpc_url.clone(),
                cluster_map: cluster_map.clone(),
                data_dir: tmp.path.join(format!("storage_{node_id}")),
                trigger: 45,
                target: 60,
                kzg_seed: DEFAULT_KZG_SEED,
            })
            .await
            .expect("start storage node");
            storage_nodes.push(handle);
        }

        // 1. 10개 스토리지 노드가 각각 자신의 10개 슬롯 P-256 키로 서명하여 L1 BFT에 등록
        let reg_count = register_cluster_via_nodes(&cluster_map)
            .await
            .expect("register all nodes");
        assert_eq!(reg_count, SWARM_SIZE);

        let status_after_reg: L1StatusDto =
            http_request_json::<(), L1StatusDto>(&validators[2].rpc_url, "GET", "/status", None)
                .await
                .expect("status on follower validator");
        assert_eq!(status_after_reg.registered_nodes, SWARM_SIZE);
        assert_eq!(status_after_reg.height, 10);

        // 2. 원본 파일 인코딩, 스웜 초기화, 100조각 실제 TCP P2P 분산 업로드
        let kzg = ValidatorStorage::load_or_create_kzg(
            &tmp.path.join("client_kzg"),
            SWARM_SIZE - 1,
            DEFAULT_KZG_SEED,
        )
        .expect("client kzg");
        let payload: Vec<u8> = (0..12_345).map(|i| ((i * 29 + 7) % 253) as u8).collect();
        let (manifest, init_block) = upload_payload(
            &validators[0].rpc_url,
            &cluster_map,
            &kzg,
            &payload,
            5_000,
            901,
        )
        .await
        .expect("upload payload");
        assert_eq!(init_block.header.height, 11);

        // 디스크 영속화 검증
        assert!(NodeStorage::load_shard(&tmp.path.join("storage_0"), 0, &manifest.object_id_hex)
            .expect("load shard 0")
            .is_some());
        assert!(tmp.path.join("validator_0/l1_snapshot.json").exists());
        assert!(tmp.path.join("validator_0/blocks.jsonl").exists());

        // 3. 검증자 1대(v3) 다운 + 스토리지 노드 6대(0번 반장 포함, 슬롯 0..60) 강제 중단
        let v3 = validators.pop().expect("v3");
        v3.shutdown().await;
        for _ in 0..6 {
            let h = storage_nodes.remove(0);
            h.shutdown().await;
        }
        // 남은 storage_nodes: [node 6, node 7, node 8, node 9] (슬롯 60..100, 활성 40개)

        // 4. 생존한 최선순위 노드(node 6, 슬롯 60)가 자동으로 반장 승계 -> TCP 지연 복구 + L1 체크포인트 BFT 확정
        let report: CycleReportDto = http_request_json(
            &storage_nodes[0].rpc_url,
            "POST",
            "/aggregator/run_cycle",
            Some(&RunCycleReq { epoch: 1 }),
        )
        .await
        .expect("run aggregator cycle");

        assert_eq!(report.aggregator_slot, 60);
        assert_eq!(report.online_slots, 40);
        assert_eq!(report.accessible_shards_before, 40);
        assert_eq!(report.repaired_slots, (0..20).map(|i| i as u8).collect::<Vec<_>>());
        assert_eq!(report.accessible_shards_after, 60);
        assert_eq!(report.aggregator_bonus, 50);
        assert_eq!(report.block_height, 12);
        assert_ne!(report.new_blobs_root_hex, manifest.root_hex);

        // 반장(슬롯 60)이 온라인 피어(예: storage_7의 슬롯 72)에 발급한 Heartbeat 영수증 디스크 저장 확인
        let (receipt_agg_slot, receipt_sig) =
            NodeStorage::load_heartbeat_receipt(&tmp.path.join("storage_7"), 1, 72)
                .expect("load heartbeat receipt")
                .expect("online peer must persist aggregator heartbeat receipt");
        assert_eq!(receipt_agg_slot, 60);
        assert_ne!(receipt_sig, [0u8; 64]);

        // 좀비 generation 가드: custodian node 6에 generation=0 과거 덮어쓰기 시도 (custodian 아닌 일반 슬롯 60에 대해서는 rejection 검증)
        let (slot60_shard, _) =
            NodeStorage::load_shard(&tmp.path.join("storage_6"), 60, &manifest.object_id_hex)
                .expect("read slot 60")
                .expect("slot 60 exists");
        // slot 60의 meta generation을 1로 높인 뒤 generation=0 덮어쓰기 거부 확인
        assert!(NodeStorage::save_shard(
            &tmp.path.join("storage_6"),
            60,
            false,
            1,
            &slot60_shard,
            ""
        )
        .expect("upgrade gen"));
        let stale_reply = send_p2p(
            storage_nodes[0].p2p_addr,
            &P2pRequest::StoreShard {
                slot: 60,
                is_custodian: false,
                generation: 0,
                shard: slot60_shard,
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
        assert_eq!(recovered_status.height, 12);
        assert_eq!(recovered_status.registered_nodes, SWARM_SIZE);
        assert_eq!(
            hex::encode(recovered_status.swarms[0].state.active_blobs_root),
            report.new_blobs_root_hex
        );

        // 6. 살아있는 4대 노드(60개 접근 가능 조각 = 40 원본 + 20 복구 조각)에서 실제 TCP로 받아 원본 100% 복원
        let (decoded, collected) = download_payload(
            &cluster_map,
            &manifest.object_id_hex,
            Some(&storage_nodes[0].rpc_url),
        )
        .await
        .expect("download & decode");
        assert!(collected >= 30);
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

        let node_endpoints: Vec<(u64, SocketAddr, SocketAddr)> = (0..10u64)
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
                swarm_id: 0,
                p2p_addr: *p2p_addr,
                rpc_addr: *rpc_addr,
                l1_rpc_url: validators[0].rpc_url.clone(),
                cluster_map: cluster_map.clone(),
                data_dir: tmp.path.join(format!("storage_{node_id}")),
                trigger: 45,
                target: 60,
                kzg_seed: DEFAULT_KZG_SEED,
            })
            .await
            .expect("start storage node");
            storage_nodes.push(handle);
        }

        let reg_count = register_cluster_via_nodes(&cluster_map)
            .await
            .expect("register all nodes");
        assert_eq!(reg_count, SWARM_SIZE);

        let kzg = ValidatorStorage::load_or_create_kzg(
            &tmp.path.join("client_kzg"),
            SWARM_SIZE - 1,
            DEFAULT_KZG_SEED,
        )
        .expect("client kzg");
        let payload: Vec<u8> = (0..8_192).map(|i| ((i * 17 + 5) % 251) as u8).collect();
        let (manifest, _) = upload_payload(
            &validators[0].rpc_url,
            &cluster_map,
            &kzg,
            &payload,
            10_000,
            902,
        )
        .await
        .expect("upload payload");

        // 1. 반장(슬롯 0)이 피어(슬롯 12, storage_1)에게 IssueHeartbeatReceipt 발급 & Ping 영수증 저장 검증
        let agg0_key = deterministic_signing_key(slot_key_seed(0));
        let hb_msg_12 = heartbeat_signing_bytes(0, 1, 12);
        let hb_sig_12: Signature = agg0_key.sign(&hb_msg_12);
        let hb_sig_12_bytes: [u8; 64] = hb_sig_12.to_bytes().into();

        let issue_resp = send_p2p(
            storage_nodes[1].p2p_addr,
            &P2pRequest::IssueHeartbeatReceipt {
                swarm_id: 0,
                epoch: 1,
                target_slot: 12,
                aggregator_slot: 0,
                sig_hex: hex::encode(hb_sig_12_bytes),
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
                aggregator_slot: 0,
                sig_hex: hex::encode(hb_sig_12_bytes),
            },
        )
        .await
        .expect("send IssueHeartbeatReceipt invalid slot");
        assert!(matches!(invalid_slot_resp, P2pResponse::Error { .. }));

        // Ping에 실려 온 aggregator_sig_hex 역시 피어 디스크에 저장되는지 확인 (슬롯 25, storage_2)
        let hb_msg_25 = heartbeat_signing_bytes(0, 1, 25);
        let hb_sig_25: Signature = agg0_key.sign(&hb_msg_25);
        let hb_sig_25_bytes: [u8; 64] = hb_sig_25.to_bytes().into();
        let ping_resp = send_p2p(
            storage_nodes[2].p2p_addr,
            &P2pRequest::Ping {
                from_slot: 0,
                target_slot: 25,
                epoch: 1,
                aggregator_sig_hex: hex::encode(hb_sig_25_bytes),
            },
        )
        .await
        .expect("send Ping with receipt");
        assert!(matches!(ping_resp, P2pResponse::Pong { slot: 25, epoch: 1, .. }));
        assert_eq!(
            NodeStorage::load_heartbeat_receipt(&tmp.path.join("storage_2"), 1, 25)
                .expect("load slot 25 receipt"),
            Some((0, hb_sig_25_bytes))
        );

        // 2. 반장(슬롯 0)이 에포크 1 정산 시 슬롯 12를 결석(0)으로 허위 보고 -> 디스크 영수증으로 Fault Proof 슬래싱!
        let status: L1StatusDto =
            http_request_json::<(), L1StatusDto>(&validators[0].rpc_url, "GET", "/status", None)
                .await
                .expect("get status");
        let epoch_seed = decode_fixed_hex::<32>(&status.epoch_seed_hex).expect("epoch seed");
        let root_bytes = decode_fixed_hex::<48>(&manifest.root_hex).expect("root bytes");
        let sample_index = expected_sample_index(&epoch_seed, 0, 1, SWARM_SIZE);
        let sample_eval =
            decode_fixed_hex::<32>(&manifest.slot_fps_hex[sample_index as usize]).expect("eval");
        let kzg_sample_proof =
            decode_fixed_hex::<48>(&manifest.slot_proofs_hex[sample_index as usize])
                .expect("proof");
        let malicious_bitmap = ((1u128 << SWARM_SIZE) - 1) & !(1u128 << 12);
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
            NodeStorage::load_heartbeat_receipt(&tmp.path.join("storage_1"), 1, 12)
                .expect("load slot 12 receipt")
                .expect("slot 12 receipt must exist on disk");
        assert_eq!(stored_agg_slot, 0);

        let fault_tx = NativeTransaction::SubmitHeartbeatFaultProof {
            swarm_id: 0,
            epoch: 1,
            node_slot: 12,
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

        // 3. 노드 0..6 중단 후 에포크 2 복구 실행 -> storage_6가 custodian으로 보관한 슬롯 0 조각을 대기 노드(standby_10)로 HandoffShard 이관
        for _ in 0..6 {
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
            NodeStorage::load_heartbeat_receipt(&tmp.path.join("storage_7"), 2, 72)
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
            swarm_id: 0,
            p2p_addr: reserve_addr(),
            rpc_addr: reserve_addr(),
            l1_rpc_url: validators[0].rpc_url.clone(),
            cluster_map,
            data_dir: tmp.path.join("standby_10"),
            trigger: 45,
            target: 60,
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
