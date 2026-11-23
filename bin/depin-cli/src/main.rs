use clap::{Parser, Subcommand};
use l1_state_engine::state_db::MAX_SWARM_SIZE;
use node_network::client::{
    build_cluster_map, download_payload, register_cluster_batch_via_nodes, upload_payload,
};
use node_network::l1_daemon::DEFAULT_KZG_SEED;
use node_network::persistence::ValidatorStorage;
use node_network::wire::{
    http_request_json, CycleReportDto, FinalizedBlockDto, L1StatusDto, SwarmClusterMapDto,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "depin-cli", about = "DePIN Mobile Storage L1 Network CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    GenClusterMap {
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = 19200)]
        base_p2p_port: u16,
        #[arg(long, default_value_t = 19300)]
        base_rpc_port: u16,
        #[arg(long, default_value_t = 10)]
        nodes: u64,
        #[arg(long)]
        endpoints: Option<String>,
        #[arg(long, default_value_t = 0)]
        swarm_id: u64,
        #[arg(long, default_value_t = 2602)]
        chain_id: u64,
    },
    Status {
        #[arg(long)]
        l1_rpc: String,
    },
    RegisterAll {
        #[arg(long)]
        l1_rpc: String,
        #[arg(long)]
        cluster_map: PathBuf,
    },
    Shuffle {
        #[arg(long)]
        l1_rpc: String,
    },
    Upload {
        #[arg(long)]
        l1_rpc: String,
        #[arg(long)]
        cluster_map: Option<PathBuf>,
        #[arg(long)]
        file: PathBuf,
        #[arg(long, default_value_t = 5000)]
        bounty: u128,
        #[arg(long, default_value_t = 901)]
        seed: u64,
        #[arg(long)]
        kzg_cache_dir: PathBuf,
    },
    RunCycle {
        #[arg(long)]
        node_rpc: String,
        #[arg(long, default_value_t = 1)]
        epoch: u64,
    },
    Download {
        #[arg(long)]
        l1_rpc: String,
        #[arg(long)]
        cluster_map: Option<PathBuf>,
        #[arg(long)]
        object_id: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        node_rpc: Option<String>,
    },
}

#[derive(Serialize)]
struct RunCycleBody {
    epoch: u64,
}

fn read_cluster_map(path: &PathBuf) -> Result<SwarmClusterMapDto, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn parse_endpoints(
    spec: &str,
) -> Result<Vec<(u64, SocketAddr, SocketAddr)>, Box<dyn std::error::Error>> {
    spec.split(',')
        .enumerate()
        .map(|(i, entry)| {
            let mut parts = entry.trim().rsplitn(3, ':');
            let (rpc_port, p2p_port, host) = match (parts.next(), parts.next(), parts.next()) {
                (Some(rpc), Some(p2p), Some(host)) => (rpc, p2p, host),
                _ => return Err(format!("endpoint must be host:p2p_port:rpc_port: {entry}").into()),
            };
            Ok((
                i as u64,
                format!("{host}:{p2p_port}").parse()?,
                format!("{host}:{rpc_port}").parse()?,
            ))
        })
        .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(async move {
        match cli.cmd {
            Command::GenClusterMap {
                out,
                base_p2p_port,
                base_rpc_port,
                nodes,
                swarm_id,
                chain_id,
                endpoints,
            } => {
                let endpoints: Vec<(u64, SocketAddr, SocketAddr)> = match endpoints {
                    Some(spec) => parse_endpoints(&spec)?,
                    None => (0..nodes)
                        .map(|i| {
                            let p2p: SocketAddr =
                                format!("127.0.0.1:{}", base_p2p_port + i as u16).parse()?;
                            let rpc: SocketAddr =
                                format!("127.0.0.1:{}", base_rpc_port + i as u16).parse()?;
                            Ok::<_, Box<dyn std::error::Error>>((i, p2p, rpc))
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                };
                let map = build_cluster_map(swarm_id, chain_id, &endpoints)?;
                if let Some(parent) = out.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&out, serde_json::to_vec_pretty(&map)?)?;
                println!(
                    "CLUSTER_MAP_WRITTEN path={} swarm_id={} slots={}",
                    out.display(),
                    map.swarm_id,
                    map.slots.len()
                );
            }
            Command::Status { l1_rpc } => {
                let status: L1StatusDto =
                    http_request_json::<(), L1StatusDto>(&l1_rpc, "GET", "/status", None).await?;
                println!("{}", serde_json::to_string_pretty(&status)?);
            }
            Command::RegisterAll {
                l1_rpc,
                cluster_map,
            } => {
                let map = read_cluster_map(&cluster_map)?;
                let block = register_cluster_batch_via_nodes(&l1_rpc, &map).await?;
                println!("REGISTERED_SLOTS count={}", block.header.tx_count);
            }
            Command::Shuffle { l1_rpc } => {
                let block: FinalizedBlockDto = http_request_json::<(), FinalizedBlockDto>(
                    &l1_rpc,
                    "POST",
                    "/swarm/shuffle",
                    None,
                )
                .await?;
                let status: L1StatusDto =
                    http_request_json::<(), L1StatusDto>(&l1_rpc, "GET", "/status", None).await?;
                println!(
                    "SHUFFLE_TRIGGERED height={} swarms={}",
                    block.header.height, status.swarm_count
                );
            }
            Command::Upload {
                l1_rpc,
                cluster_map,
                file,
                bounty,
                seed,
                kzg_cache_dir,
            } => {
                let map = cluster_map.as_ref().map(read_cluster_map).transpose()?;
                let payload = std::fs::read(&file)?;
                let kzg = ValidatorStorage::load_or_create_kzg(
                    &kzg_cache_dir,
                    MAX_SWARM_SIZE - 1,
                    DEFAULT_KZG_SEED,
                )?;
                let (manifest, maybe_block) =
                    upload_payload(&l1_rpc, map.as_ref(), &kzg, &payload, bounty, seed).await?;
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                    "object_id_hex": manifest.object_id_hex,
                    "swarm_id": manifest.swarm_id,
                    "root_hex": manifest.root_hex,
                    "block_height": maybe_block.as_ref().map(|b| b.header.height),
                    "payload_bytes": payload.len(),
                }))?);
            }
            Command::RunCycle { node_rpc, epoch } => {
                let report: CycleReportDto = http_request_json(
                    &node_rpc,
                    "POST",
                    "/aggregator/run_cycle",
                    Some(&RunCycleBody { epoch }),
                )
                .await?;
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
            Command::Download {
                l1_rpc,
                cluster_map,
                object_id,
                out,
                node_rpc,
            } => {
                let map = cluster_map.as_ref().map(read_cluster_map).transpose()?;
                let (data, shards_used) =
                    download_payload(&l1_rpc, map.as_ref(), &object_id, node_rpc.as_deref())
                        .await?;
                if let Some(parent) = out.parent() {
                    if !parent.as_os_str().is_empty() {
                        std::fs::create_dir_all(parent)?;
                    }
                }
                std::fs::write(&out, &data)?;
                let sha_hex = hex::encode(Sha256::digest(&data));
                println!(
                    "DOWNLOAD_OK bytes={} shards_collected={} sha256={} out={}",
                    data.len(),
                    shards_used,
                    sha_hex,
                    out.display()
                );
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
