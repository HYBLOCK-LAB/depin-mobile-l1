use l1_state_engine::state_db::MAX_SWARM_SIZE;
use node_network::client::{download_payload, upload_payload};
use node_network::l1_daemon::{
    start_validator_daemon, ValidatorDaemonConfig, ValidatorDaemonHandle, DEFAULT_EPOCH_SEED,
    DEFAULT_KZG_SEED,
};
use node_network::persistence::ValidatorStorage;
use node_network::storage_daemon::{start_storage_daemon, PublicEndpoints, StorageDaemonConfig};
use node_network::wire::{http_request_json, FinalizedBlockDto, L1StatusDto, TxDto};
use sha2::{Digest, Sha256};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};

const AUTO_NODE_COUNT: usize = 10;

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

async fn start_validators(root: &Path) -> Vec<ValidatorDaemonHandle> {
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
        validators.push(
            start_validator_daemon(ValidatorDaemonConfig {
                validator_id: id as u64,
                p2p_addr: val_p2p[id],
                rpc_addr: val_rpc[id],
                peer_p2p_addrs: peers,
                validator_seeds: validator_seeds.clone(),
                data_dir: root.join(format!("validator_{id}")),
                epoch_seed: DEFAULT_EPOCH_SEED,
                kzg_seed: DEFAULT_KZG_SEED,
            })
            .await
            .expect("start validator"),
        );
    }
    validators
}

async fn l1_status(rpc_url: &str) -> L1StatusDto {
    http_request_json::<(), L1StatusDto>(rpc_url, "GET", "/status", None)
        .await
        .expect("l1 status")
}

#[test]
fn auto_register_nodes_without_cluster_map_upload_and_download_via_l1_only_e2e() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        let tmp = TempDirGuard::new("multi_host_e2e");
        let validators = start_validators(&tmp.path).await;
        let l1_rpc = validators[0].rpc_url.clone();

        let mut configs = Vec::new();
        let mut nodes = Vec::new();
        for node_id in 0..AUTO_NODE_COUNT as u64 {
            let public = PublicEndpoints {
                p2p_addr: reserve_addr(),
                rpc_addr: reserve_addr(),
            };
            let config = StorageDaemonConfig {
                node_id,
                slots: Vec::new(),
                p2p_addr: SocketAddr::from(([0, 0, 0, 0], public.p2p_addr.port())),
                rpc_addr: SocketAddr::from(([0, 0, 0, 0], public.rpc_addr.port())),
                l1_rpc_url: l1_rpc.clone(),
                cluster_map: None,
                auto_register: Some(public),
                data_dir: tmp.path.join(format!("storage_{node_id}")),
                ip_subnet_hash: node_id as u16,
                country_code: (node_id % 8) as u8,
                kzg_seed: DEFAULT_KZG_SEED,
            };
            nodes.push(
                start_storage_daemon(config.clone())
                    .await
                    .expect("start auto-register storage node"),
            );
            configs.push(config);
        }

        let status = l1_status(&validators[1].rpc_url).await;
        assert_eq!(status.registered_nodes, AUTO_NODE_COUNT);
        assert_eq!(status.height, AUTO_NODE_COUNT as u64);
        assert_eq!(status.swarm_count, 1);
        assert_eq!(status.swarms[0].roster_pubkeys_hex.len(), AUTO_NODE_COUNT);
        for config in &configs {
            let public = config.auto_register.as_ref().expect("public endpoints");
            let p2p = public.p2p_addr.to_string();
            let rpc = public.rpc_addr.to_string();
            assert!(status
                .nodes
                .iter()
                .any(|n| n.p2p_addr == p2p && n.rpc_addr == rpc));
        }

        let restarted_config = configs[0].clone();
        nodes.remove(0).shutdown().await;
        nodes.insert(
            0,
            start_storage_daemon(restarted_config)
                .await
                .expect("restart node with persisted key"),
        );
        let after_restart = l1_status(&l1_rpc).await;
        assert_eq!(after_restart.height, status.height);
        assert_eq!(after_restart.registered_nodes, AUTO_NODE_COUNT);

        let kzg = ValidatorStorage::load_or_create_kzg(
            &tmp.path.join("client_kzg"),
            MAX_SWARM_SIZE - 1,
            DEFAULT_KZG_SEED,
        )
        .expect("client kzg");
        let payload: Vec<u8> = (0..20_000).map(|i| ((i * 37 + 13) % 251) as u8).collect();
        let (manifest, _) = upload_payload(&l1_rpc, None, &kzg, &payload, 0, 321)
            .await
            .expect("upload using L1 endpoints only");
        let swarm = &status.swarms[0];
        assert_eq!(manifest.swarm_id, swarm.swarm_id);
        assert_eq!(manifest.roster_pubkeys_hex, swarm.roster_pubkeys_hex);
        let (decoded, collected) = download_payload(&l1_rpc, None, &manifest.object_id_hex, None)
            .await
            .expect("download using L1 endpoints only");
        assert_eq!(collected, AUTO_NODE_COUNT);
        assert_eq!(Sha256::digest(&decoded), Sha256::digest(&payload));

        let block: FinalizedBlockDto =
            http_request_json::<(), FinalizedBlockDto>(&l1_rpc, "POST", "/swarm/shuffle", None)
                .await
                .expect("trigger shuffle");
        assert_eq!(block.header.height, status.height + 1);
        assert!(matches!(block.txs[..], [TxDto::TriggerShuffle]));
        assert_eq!(l1_status(&l1_rpc).await.swarm_count, 1);

        for v in validators {
            v.shutdown().await;
        }
        for n in nodes {
            n.shutdown().await;
        }
    });
}

#[test]
fn auto_register_rejects_unspecified_public_endpoint() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        let tmp = TempDirGuard::new("multi_host_unspecified");
        let unspecified = SocketAddr::from(([0, 0, 0, 0], 0));
        let result = start_storage_daemon(StorageDaemonConfig {
            node_id: 0,
            slots: Vec::new(),
            p2p_addr: unspecified,
            rpc_addr: unspecified,
            l1_rpc_url: "http://127.0.0.1:1".into(),
            cluster_map: None,
            auto_register: Some(PublicEndpoints {
                p2p_addr: unspecified,
                rpc_addr: reserve_addr(),
            }),
            data_dir: tmp.path.join("storage"),
            ip_subnet_hash: 0,
            country_code: 0,
            kzg_seed: DEFAULT_KZG_SEED,
        })
        .await;
        assert!(result.is_err());
    });
}
