use clap::{Parser, Subcommand};
use node_network::client::slots_for_node;
use node_network::l1_daemon::{
    start_validator_daemon, ValidatorDaemonConfig, DEFAULT_EPOCH_SEED, DEFAULT_KZG_SEED,
};
use node_network::storage_daemon::{start_storage_daemon, StorageDaemonConfig};
use node_network::wire::SwarmClusterMapDto;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "depin-node", about = "DePIN Mobile Storage L1 & Storage Swarm Node Daemon")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    Validator {
        #[arg(long)]
        id: u64,
        #[arg(long)]
        p2p: SocketAddr,
        #[arg(long)]
        rpc: SocketAddr,
        #[arg(long, default_value = "")]
        peers: String,
        #[arg(long, default_value_t = 4)]
        validator_count: u64,
        #[arg(long)]
        data_dir: PathBuf,
    },
    Storage {
        #[arg(long)]
        node_id: u64,
        #[arg(long)]
        p2p: SocketAddr,
        #[arg(long)]
        rpc: SocketAddr,
        #[arg(long)]
        l1_rpc: String,
        #[arg(long)]
        cluster_map: PathBuf,
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        ip_subnet_hash: u16,
        #[arg(long)]
        country_code: u8,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(async move {
        match cli.cmd {
            Command::Validator {
                id,
                p2p,
                rpc,
                peers,
                validator_count,
                data_dir,
            } => {
                let peer_p2p_addrs: Vec<SocketAddr> = peers
                    .split(',')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.parse::<SocketAddr>())
                    .collect::<Result<Vec<_>, _>>()?;
                let validator_seeds: Vec<(u64, u64)> =
                    (0..validator_count).map(|vid| (vid, 900 + vid)).collect();

                let handle = start_validator_daemon(ValidatorDaemonConfig {
                    validator_id: id,
                    p2p_addr: p2p,
                    rpc_addr: rpc,
                    peer_p2p_addrs,
                    validator_seeds,
                    data_dir,
                    epoch_seed: DEFAULT_EPOCH_SEED,
                    kzg_seed: DEFAULT_KZG_SEED,
                })
                .await?;
                println!(
                    "VALIDATOR_READY id={} p2p={} rpc={}",
                    handle.validator_id, handle.p2p_addr, handle.rpc_url
                );
                std::future::pending::<()>().await;
                #[allow(unreachable_code)]
                Ok::<(), Box<dyn std::error::Error>>(())
            }
            Command::Storage {
                node_id,
                p2p,
                rpc,
                l1_rpc,
                cluster_map,
                data_dir,
                ip_subnet_hash,
                country_code,
            } => {
                let map_bytes = std::fs::read(&cluster_map)?;
                let map: SwarmClusterMapDto = serde_json::from_slice(&map_bytes)?;
                let slots = slots_for_node(&map, node_id);
                let swarm_id = map.swarm_id;
                let handle = start_storage_daemon(StorageDaemonConfig {
                    node_id,
                    slots: slots.clone(),
                    swarm_id,
                    p2p_addr: p2p,
                    rpc_addr: rpc,
                    l1_rpc_url: l1_rpc,
                    cluster_map: map,
                    data_dir,
                    ip_subnet_hash,
                    country_code,
                    kzg_seed: DEFAULT_KZG_SEED,
                })
                .await?;
                println!(
                    "STORAGE_READY node_id={} slots={:?} p2p={} rpc={}",
                    handle.node_id, slots, handle.p2p_addr, handle.rpc_url
                );
                std::future::pending::<()>().await;
                #[allow(unreachable_code)]
                Ok::<(), Box<dyn std::error::Error>>(())
            }
        }
    })
}
