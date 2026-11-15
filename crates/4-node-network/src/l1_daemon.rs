use crate::persistence::{
    deterministic_signing_key, load_or_create_signing_key, ValidatorStorage,
};
use crate::wire::{
    decode_fixed_hex, read_frame, read_http_request, root_from_hex, send_p2p, spawn_tcp_server,
    write_frame, write_http_json, FinalizedBlockDto, InitSwarmRequest, L1StatusDto, NodeAccountDto,
    P2pRequest, P2pResponse, SwarmSummaryDto, TxDto, VoteDto,
};
use crate::{Error, Result};
use l1_state_engine::consensus::{
    compute_state_root, BftEngine, BlockHeader, FinalizedBlock, ValidatorInfo, ValidatorSigner,
    Vote, VotePhase,
};
use l1_state_engine::executor::{Executor, ExecutorConfig};
use l1_state_engine::state_db::{
    compute_member_verkle_root, NativeTransaction, MAX_SWARM_SIZE, MIN_SWARM_SIZE,
};
use p256::ecdsa::SigningKey;
use serde::Serialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use verkle_fountain::verkle_kzg::Kzg;

pub const DEFAULT_KZG_SEED: u64 = 77;
pub const DEFAULT_EPOCH_SEED: [u8; 32] = [0xAB; 32];

#[derive(Clone, Debug)]
pub struct ValidatorDaemonConfig {
    pub validator_id: u64,
    pub p2p_addr: SocketAddr,
    pub rpc_addr: SocketAddr,
    pub peer_p2p_addrs: Vec<SocketAddr>,
    pub validator_seeds: Vec<(u64, u64)>,
    pub data_dir: PathBuf,
    pub epoch_seed: [u8; 32],
    pub kzg_seed: u64,
}

struct ValidatorRuntimeState {
    exec: Executor,
    bft: BftEngine,
    signer: ValidatorSigner,
    kzg: Arc<Kzg>,
    epoch_seed: [u8; 32],
    data_dir: PathBuf,
    peer_p2p_addrs: Vec<SocketAddr>,
}

pub struct ValidatorDaemonHandle {
    pub validator_id: u64,
    pub p2p_addr: SocketAddr,
    pub rpc_addr: SocketAddr,
    pub rpc_url: String,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl ValidatorDaemonHandle {
    pub async fn shutdown(mut self) {
        for task in self.tasks.drain(..) {
            task.abort();
            let _ = task.await;
        }
    }
}

#[derive(Serialize)]
struct HealthResponse {
    ok: bool,
    validator_id: u64,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

fn build_validator_set(
    validator_id: u64,
    validator_seeds: &[(u64, u64)],
    key_path: &std::path::Path,
) -> Result<(Vec<ValidatorInfo>, ValidatorSigner)> {
    let mut infos = Vec::with_capacity(validator_seeds.len());
    let mut own_signer: Option<ValidatorSigner> = None;

    for &(id, seed) in validator_seeds {
        let sk: SigningKey = if id == validator_id {
            load_or_create_signing_key(key_path, seed)?
        } else {
            deterministic_signing_key(seed)
        };
        let signer = ValidatorSigner::new(id, 1, sk);
        infos.push(signer.info());
        if id == validator_id {
            own_signer = Some(signer);
        }
    }

    let own = own_signer.ok_or_else(|| {
        Error::Network(format!(
            "validator_id {validator_id} missing from validator_seeds"
        ))
    })?;
    Ok((infos, own))
}

fn apply_init_swarm(exec: &mut Executor, kzg: &Kzg, req: &InitSwarmRequest) -> Result<()> {
    let roster = req
        .roster_pubkeys_hex
        .iter()
        .map(|h| decode_fixed_hex::<33>(h))
        .collect::<Result<Vec<_>>>()?;
    let member_root = root_from_hex(&req.member_verkle_root_hex)?;
    let expected_member_root = compute_member_verkle_root(kzg, &roster)?;
    if member_root != expected_member_root {
        return Err(Error::L1(l1_state_engine::Error::BadProof));
    }
    let blobs_root = root_from_hex(&req.active_blobs_root_hex)?;
    exec.init_swarm(
        req.swarm_id,
        roster,
        member_root,
        blobs_root,
        req.initial_bounty,
    )?;
    Ok(())
}

fn execute_stage(
    base: &Executor,
    kzg: &Kzg,
    epoch_seed: &[u8; 32],
    init_swarms: &[InitSwarmRequest],
    txs: &[TxDto],
) -> Result<(Executor, Vec<l1_state_engine::executor::ExecutionReceipt>)> {
    let mut staged = base.clone();
    for init_req in init_swarms {
        apply_init_swarm(&mut staged, kzg, init_req)?;
    }
    let mut receipts = Vec::with_capacity(txs.len());
    let mut had_registration = false;
    for tx_dto in txs {
        let native: NativeTransaction = tx_dto.to_native()?;
        if matches!(native, NativeTransaction::RegisterMobileNode { .. }) {
            had_registration = true;
        }
        receipts.push(staged.execute(native, kzg, epoch_seed)?);
    }
    if had_registration && staged.db.standby_pool.len() >= MIN_SWARM_SIZE {
        staged.auto_shuffle_standby_swarms(kzg, epoch_seed, 10_000)?;
    }
    Ok((staged, receipts))
}

pub async fn start_validator_daemon(
    config: ValidatorDaemonConfig,
) -> Result<ValidatorDaemonHandle> {
    std::fs::create_dir_all(&config.data_dir)?;
    let kzg = Arc::new(ValidatorStorage::load_or_create_kzg(
        &config.data_dir,
        MAX_SWARM_SIZE - 1,
        config.kzg_seed,
    )?);
    let key_path = config.data_dir.join("validator_key.hex");
    let (infos, signer) =
        build_validator_set(config.validator_id, &config.validator_seeds, &key_path)?;

    let mut exec = Executor::new(ExecutorConfig::default());
    let mut bft = BftEngine::new(infos)?;
    let mut epoch_seed = config.epoch_seed;
    if let Some(loaded_seed) = ValidatorStorage::load_snapshot(&config.data_dir, &mut bft, &mut exec)?
    {
        epoch_seed = loaded_seed;
    }

    let p2p_listener = TcpListener::bind(config.p2p_addr).await?;
    let rpc_listener = TcpListener::bind(config.rpc_addr).await?;
    let actual_p2p = p2p_listener.local_addr()?;
    let actual_rpc = rpc_listener.local_addr()?;

    let state = Arc::new(Mutex::new(ValidatorRuntimeState {
        exec,
        bft,
        signer,
        kzg,
        epoch_seed,
        data_dir: config.data_dir,
        peer_p2p_addrs: config.peer_p2p_addrs,
    }));

    let p2p_task = spawn_tcp_server(p2p_listener, Arc::clone(&state), handle_p2p_conn);
    let rpc_task = spawn_tcp_server(rpc_listener, state, handle_rpc_conn);

    Ok(ValidatorDaemonHandle {
        validator_id: config.validator_id,
        p2p_addr: actual_p2p,
        rpc_addr: actual_rpc,
        rpc_url: format!("http://{actual_rpc}"),
        tasks: vec![p2p_task, rpc_task],
    })
}

async fn handle_p2p_conn(
    mut stream: TcpStream,
    state: Arc<Mutex<ValidatorRuntimeState>>,
) -> Result<()> {
    let req: P2pRequest = read_frame(&mut stream).await?;
    let resp = match req {
        P2pRequest::BftPropose {
            header,
            block_hash_hex,
            init_swarms,
            txs,
        } => {
            let guard = state.lock().await;
            let expected_height = guard.bft.height + 1;
            let parsed_header = BlockHeader::try_from(&header)?;
            let proposed_hash = decode_fixed_hex::<32>(&block_hash_hex)?;

            if parsed_header.height != expected_height
                || parsed_header.prev_hash != guard.bft.last_block_hash
                || parsed_header.block_hash() != proposed_hash
            {
                P2pResponse::BftVoteReply {
                    accepted: false,
                    prevote: None,
                    precommit: None,
                    reason: Some(format!(
                        "header mismatch: expected height {expected_height}, got {}",
                        parsed_header.height
                    )),
                }
            } else {
                match execute_stage(
                    &guard.exec,
                    &guard.kzg,
                    &parsed_header.epoch_seed,
                    &init_swarms,
                    &txs,
                ) {
                    Ok((staged, _)) => {
                        let root = compute_state_root(&staged);
                        if root != parsed_header.state_root {
                            P2pResponse::BftVoteReply {
                                accepted: false,
                                prevote: None,
                                precommit: None,
                                reason: Some("state_root mismatch".into()),
                            }
                        } else {
                            let pv = guard.signer.sign_vote(
                                parsed_header.height,
                                proposed_hash,
                                VotePhase::Prevote,
                            );
                            let pc = guard.signer.sign_vote(
                                parsed_header.height,
                                proposed_hash,
                                VotePhase::Precommit,
                            );
                            P2pResponse::BftVoteReply {
                                accepted: true,
                                prevote: Some(VoteDto::from(&pv)),
                                precommit: Some(VoteDto::from(&pc)),
                                reason: None,
                            }
                        }
                    }
                    Err(e) => P2pResponse::BftVoteReply {
                        accepted: false,
                        prevote: None,
                        precommit: None,
                        reason: Some(e.to_string()),
                    },
                }
            }
        }
        P2pRequest::BftCommit { block } => {
            let mut guard = state.lock().await;
            if guard.bft.height >= block.header.height {
                P2pResponse::Ack { ok: true }
            } else if block.header.height != guard.bft.height + 1 {
                P2pResponse::Error {
                    message: format!(
                        "unexpected block height {}, current {}",
                        block.header.height, guard.bft.height
                    ),
                }
            } else {
                let parsed_header = BlockHeader::try_from(&block.header)?;
                let block_hash = decode_fixed_hex::<32>(&block.block_hash_hex)?;
                let precommits: Vec<Vote> = block
                    .precommits
                    .iter()
                    .map(Vote::try_from)
                    .collect::<Result<Vec<_>>>()?;
                guard.bft.verify_quorum(
                    &precommits,
                    parsed_header.height,
                    &block_hash,
                    VotePhase::Precommit,
                )?;
                let (staged, receipts) = execute_stage(
                    &guard.exec,
                    &guard.kzg,
                    &parsed_header.epoch_seed,
                    &block.init_swarms,
                    &block.txs,
                )?;
                if compute_state_root(&staged) != parsed_header.state_root {
                    return Err(Error::Network("commit state_root mismatch".into()));
                }
                guard.exec = staged;
                guard.bft.height = parsed_header.height;
                guard.bft.last_block_hash = block_hash;
                guard.bft.chain.push(FinalizedBlock {
                    header: parsed_header,
                    block_hash,
                    receipts,
                    precommits,
                });
                let epoch_seed = guard.epoch_seed;
                let data_dir = guard.data_dir.clone();
                ValidatorStorage::save_snapshot(&data_dir, &guard.bft, &guard.exec, &epoch_seed)?;
                ValidatorStorage::append_block_wal(&data_dir, &block)?;
                P2pResponse::Ack { ok: true }
            }
        }
        _ => P2pResponse::Error {
            message: "unsupported request on validator p2p".into(),
        },
    };
    write_frame(&mut stream, &resp).await?;
    Ok(())
}

async fn propose_and_finalize_distributed(
    state: Arc<Mutex<ValidatorRuntimeState>>,
    init_swarms: Vec<InitSwarmRequest>,
    txs: Vec<TxDto>,
) -> Result<FinalizedBlockDto> {
    let (
        header,
        block_hash,
        peers,
        own_prevote,
        own_precommit,
        expected_height,
        staged,
        receipts,
    ) = {
        let guard = state.lock().await;
        let (staged, receipts) = execute_stage(
            &guard.exec,
            &guard.kzg,
            &guard.epoch_seed,
            &init_swarms,
            &txs,
        )?;
        let next_height = guard.bft.height + 1;
        let header = BlockHeader {
            height: next_height,
            prev_hash: guard.bft.last_block_hash,
            epoch_seed: guard.epoch_seed,
            proposer_id: guard.signer.id,
            tx_count: receipts.len(),
            state_root: compute_state_root(&staged),
        };
        let block_hash = header.block_hash();
        let pv = guard
            .signer
            .sign_vote(next_height, block_hash, VotePhase::Prevote);
        let pc = guard
            .signer
            .sign_vote(next_height, block_hash, VotePhase::Precommit);
        (
            header,
            block_hash,
            guard.peer_p2p_addrs.clone(),
            pv,
            pc,
            next_height,
            staged,
            receipts,
        )
    };

    let propose_req = P2pRequest::BftPropose {
        header: crate::wire::BlockHeaderDto::from(&header),
        block_hash_hex: hex::encode(block_hash),
        init_swarms: init_swarms.clone(),
        txs: txs.clone(),
    };

    let mut prevotes = vec![own_prevote];
    let mut precommits = vec![own_precommit];
    for peer in &peers {
        if let Ok(P2pResponse::BftVoteReply {
            accepted: true,
            prevote: Some(pv),
            precommit: Some(pc),
            ..
        }) = send_p2p(*peer, &propose_req).await
        {
            if let (Ok(pv), Ok(pc)) = (Vote::try_from(&pv), Vote::try_from(&pc)) {
                prevotes.push(pv);
                precommits.push(pc);
            }
        }
    }

    let block_dto = {
        let mut guard = state.lock().await;
        if guard.bft.height + 1 != expected_height {
            return Err(Error::Network("concurrent height advance".into()));
        }
        guard
            .bft
            .verify_quorum(&prevotes, expected_height, &block_hash, VotePhase::Prevote)?;
        guard
            .bft
            .verify_quorum(&precommits, expected_height, &block_hash, VotePhase::Precommit)?;
        guard.exec = staged;
        guard.bft.height = expected_height;
        guard.bft.last_block_hash = block_hash;
        let finalized = FinalizedBlock {
            header,
            block_hash,
            receipts,
            precommits,
        };
        guard.bft.chain.push(finalized.clone());
        let dto = FinalizedBlockDto::from_block(&finalized, init_swarms, txs);
        let epoch_seed = guard.epoch_seed;
        let data_dir = guard.data_dir.clone();
        ValidatorStorage::save_snapshot(&data_dir, &guard.bft, &guard.exec, &epoch_seed)?;
        ValidatorStorage::append_block_wal(&data_dir, &dto)?;
        dto
    };

    let commit_req = P2pRequest::BftCommit {
        block: block_dto.clone(),
    };
    for peer in peers {
        let _ = send_p2p(peer, &commit_req).await;
    }

    Ok(block_dto)
}

async fn handle_rpc_conn(
    mut stream: TcpStream,
    state: Arc<Mutex<ValidatorRuntimeState>>,
) -> Result<()> {
    let (method, path, body) = read_http_request(&mut stream).await?;
    match (method.as_str(), path.as_str()) {
        ("GET", "/health") => {
            let guard = state.lock().await;
            write_http_json(
                &mut stream,
                200,
                &HealthResponse {
                    ok: true,
                    validator_id: guard.signer.id,
                },
            )
            .await?;
        }
        ("GET", "/status") => {
            let guard = state.lock().await;
            let swarms: Vec<SwarmSummaryDto> = guard
                .exec
                .db
                .swarms
                .iter()
                .map(|(swarm_id, st)| {
                    let roster = guard
                        .exec
                        .db
                        .swarm_rosters
                        .get(swarm_id)
                        .map(|r| r.iter().map(hex::encode).collect())
                        .unwrap_or_default();
                    SwarmSummaryDto {
                        swarm_id: *swarm_id,
                        state: st.clone(),
                        roster_pubkeys_hex: roster,
                    }
                })
                .collect();
            let status = L1StatusDto {
                validator_id: guard.signer.id,
                height: guard.bft.height,
                last_block_hash_hex: hex::encode(guard.bft.last_block_hash),
                epoch_seed_hex: hex::encode(guard.epoch_seed),
                registered_nodes: guard.exec.db.nodes.len(),
                swarm_count: swarms.len(),
                swarms,
                nodes: guard
                    .exec
                    .db
                    .nodes
                    .iter()
                    .map(|(pk, acc)| NodeAccountDto::from_account(pk, acc))
                    .collect(),
            };
            write_http_json(&mut stream, 200, &status).await?;
        }
        ("POST", "/tx/submit") => match serde_json::from_slice::<TxDto>(&body) {
            Ok(tx) => match propose_and_finalize_distributed(state, Vec::new(), vec![tx]).await {
                Ok(block) => write_http_json(&mut stream, 200, &block).await?,
                Err(e) => {
                    write_http_json(&mut stream, 400, &ErrorResponse { error: e.to_string() })
                        .await?
                }
            },
            Err(e) => {
                write_http_json(&mut stream, 400, &ErrorResponse { error: e.to_string() }).await?
            }
        },
        ("POST", "/tx/batch") => match serde_json::from_slice::<Vec<TxDto>>(&body) {
            Ok(txs) => match propose_and_finalize_distributed(state, Vec::new(), txs).await {
                Ok(block) => write_http_json(&mut stream, 200, &block).await?,
                Err(e) => {
                    write_http_json(&mut stream, 400, &ErrorResponse { error: e.to_string() })
                        .await?
                }
            },
            Err(e) => {
                write_http_json(&mut stream, 400, &ErrorResponse { error: e.to_string() }).await?
            }
        },
        ("POST", "/swarm/init") => match serde_json::from_slice::<InitSwarmRequest>(&body) {
            Ok(req) => match propose_and_finalize_distributed(state, vec![req], Vec::new()).await {
                Ok(block) => write_http_json(&mut stream, 200, &block).await?,
                Err(e) => {
                    write_http_json(&mut stream, 400, &ErrorResponse { error: e.to_string() })
                        .await?
                }
            },
            Err(e) => {
                write_http_json(&mut stream, 400, &ErrorResponse { error: e.to_string() }).await?
            }
        },
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
