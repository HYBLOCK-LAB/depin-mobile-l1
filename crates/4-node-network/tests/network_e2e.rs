use l1_state_engine::state_db::SWARM_SIZE;
use node_network::client::{
    build_cluster_map, download_payload, register_cluster_via_nodes, slots_for_node, upload_payload,
};
use node_network::l1_daemon::{
    start_validator_daemon, ValidatorDaemonConfig, DEFAULT_EPOCH_SEED, DEFAULT_KZG_SEED,
};
use node_network::persistence::{NodeStorage, ValidatorStorage};
use node_network::storage_daemon::{start_storage_daemon, StorageDaemonConfig};
use node_network::wire::{http_request_json, send_p2p, CycleReportDto, L1StatusDto, P2pRequest, P2pResponse};
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
