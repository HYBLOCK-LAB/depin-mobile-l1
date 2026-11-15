use crate::{Error, Result};
use l1_state_engine::consensus::{BlockHeader, FinalizedBlock, Vote};
use l1_state_engine::executor::ExecutionReceipt;
use l1_state_engine::state_db::{
    NativeTransaction, NodeAccount, RepairAuditProof, RepairEntry, VirtualSwarmState,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::BTreeMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use verkle_fountain::fountain::Shard;
use verkle_fountain::verkle_kzg::{bytes_to_scalar, scalar_to_bytes, KzgProof, KzgRoot, Scalar};

const MAX_FRAME_BYTES: usize = 32 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const IO_TIMEOUT: Duration = Duration::from_secs(60);
const HTTP_READ_TIMEOUT: Duration = Duration::from_secs(60);

pub fn decode_fixed_hex<const N: usize>(s: &str) -> Result<[u8; N]> {
    let raw = hex::decode(s).map_err(|e| Error::Network(format!("invalid hex: {e}")))?;
    raw.try_into()
        .map_err(|_| Error::Network(format!("expected {N} bytes")))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShardDto {
    pub object_id_hex: String,
    pub k: usize,
    pub original_len: usize,
    pub coefficients: Vec<String>,
    pub symbols: Vec<String>,
}

impl ShardDto {
    pub fn from_shard(shard: &Shard) -> Self {
        Self {
            object_id_hex: hex::encode(shard.object_id),
            k: shard.k,
            original_len: shard.original_len,
            coefficients: shard
                .coefficients
                .iter()
                .map(|s| hex::encode(scalar_to_bytes(s)))
                .collect(),
            symbols: shard
                .symbols
                .iter()
                .map(|s| hex::encode(scalar_to_bytes(s)))
                .collect(),
        }
    }

    pub fn to_shard(&self) -> Result<Shard> {
        let object_id = decode_fixed_hex::<32>(&self.object_id_hex)?;
        let coefficients: Vec<Scalar> = self
            .coefficients
            .iter()
            .map(|h| {
                let bytes = decode_fixed_hex::<32>(h)?;
                Ok(bytes_to_scalar(&bytes)?)
            })
            .collect::<Result<Vec<_>>>()?;
        let symbols: Vec<Scalar> = self
            .symbols
            .iter()
            .map(|h| {
                let bytes = decode_fixed_hex::<32>(h)?;
                Ok(bytes_to_scalar(&bytes)?)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Shard {
            object_id,
            k: self.k,
            original_len: self.original_len,
            coefficients,
            symbols,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RepairEntryDto {
    pub repaired_slot: u8,
    pub parent_slot_a: u8,
    pub parent_slot_b: u8,
    pub factor_b_hex: String,
}

impl From<&RepairEntry> for RepairEntryDto {
    fn from(e: &RepairEntry) -> Self {
        Self {
            repaired_slot: e.repaired_slot,
            parent_slot_a: e.parent_slot_a,
            parent_slot_b: e.parent_slot_b,
            factor_b_hex: hex::encode(e.factor_b),
        }
    }
}

impl TryFrom<&RepairEntryDto> for RepairEntry {
    type Error = Error;
    fn try_from(d: &RepairEntryDto) -> Result<Self> {
        Ok(Self {
            repaired_slot: d.repaired_slot,
            parent_slot_a: d.parent_slot_a,
            parent_slot_b: d.parent_slot_b,
            factor_b: decode_fixed_hex::<32>(&d.factor_b_hex)?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RepairAuditProofDto {
    pub entry_index: usize,
    #[serde(default)]
    pub old_blobs_root_hex: String,
    pub parent_a_eval_hex: String,
    pub parent_a_proof_hex: String,
    pub parent_b_eval_hex: String,
    pub parent_b_proof_hex: String,
    pub repaired_eval_hex: String,
    pub repaired_proof_hex: String,
    pub unchanged_slot: u8,
    pub unchanged_eval_hex: String,
    pub unchanged_old_proof_hex: String,
    pub unchanged_new_proof_hex: String,
}

impl From<&RepairAuditProof> for RepairAuditProofDto {
    fn from(p: &RepairAuditProof) -> Self {
        Self {
            entry_index: p.entry_index,
            old_blobs_root_hex: hex::encode(p.old_blobs_root),
            parent_a_eval_hex: hex::encode(p.parent_a_eval),
            parent_a_proof_hex: hex::encode(p.parent_a_proof),
            parent_b_eval_hex: hex::encode(p.parent_b_eval),
            parent_b_proof_hex: hex::encode(p.parent_b_proof),
            repaired_eval_hex: hex::encode(p.repaired_eval),
            repaired_proof_hex: hex::encode(p.repaired_proof),
            unchanged_slot: p.unchanged_slot,
            unchanged_eval_hex: hex::encode(p.unchanged_eval),
            unchanged_old_proof_hex: hex::encode(p.unchanged_old_proof),
            unchanged_new_proof_hex: hex::encode(p.unchanged_new_proof),
        }
    }
}

impl TryFrom<&RepairAuditProofDto> for RepairAuditProof {
    type Error = Error;
    fn try_from(d: &RepairAuditProofDto) -> Result<Self> {
        let old_blobs_root = if d.old_blobs_root_hex.is_empty() {
            [0u8; 48]
        } else {
            decode_fixed_hex::<48>(&d.old_blobs_root_hex)?
        };
        Ok(Self {
            entry_index: d.entry_index,
            old_blobs_root,
            parent_a_eval: decode_fixed_hex::<32>(&d.parent_a_eval_hex)?,
            parent_a_proof: decode_fixed_hex::<48>(&d.parent_a_proof_hex)?,
            parent_b_eval: decode_fixed_hex::<32>(&d.parent_b_eval_hex)?,
            parent_b_proof: decode_fixed_hex::<48>(&d.parent_b_proof_hex)?,
            repaired_eval: decode_fixed_hex::<32>(&d.repaired_eval_hex)?,
            repaired_proof: decode_fixed_hex::<48>(&d.repaired_proof_hex)?,
            unchanged_slot: d.unchanged_slot,
            unchanged_eval: decode_fixed_hex::<32>(&d.unchanged_eval_hex)?,
            unchanged_old_proof: decode_fixed_hex::<48>(&d.unchanged_old_proof_hex)?,
            unchanged_new_proof: decode_fixed_hex::<48>(&d.unchanged_new_proof_hex)?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TxDto {
    RegisterMobileNode {
        pubkey_hex: String,
        hw_attestation_sig_hex: String,
        ip_subnet_hash: u16,
        country_code: u8,
        stake: u128,
    },
    DepositStorageBounty {
        swarm_id: u64,
        amount: u128,
    },
    SubmitSwarmCheckpoint {
        swarm_id: u64,
        epoch: u64,
        aggregator_slot: u8,
        new_blobs_root_hex: String,
        repair_log: Vec<RepairEntryDto>,
        uptime_bitmap: String,
        sample_index: u8,
        sample_eval_hex: String,
        kzg_sample_proof_hex: String,
        repair_audit: Option<RepairAuditProofDto>,
        aggregator_p256_sig_hex: String,
    },
    SubmitHeartbeatFaultProof {
        swarm_id: u64,
        epoch: u64,
        node_slot: u8,
        aggregator_slot: u8,
        signed_pong_receipt_hex: String,
    },
}

impl TxDto {
    pub fn from_native(tx: &NativeTransaction) -> Self {
        match tx {
            NativeTransaction::RegisterMobileNode {
                pubkey_p256,
                hw_attestation_sig,
                ip_subnet_hash,
                country_code,
                stake,
            } => Self::RegisterMobileNode {
                pubkey_hex: hex::encode(pubkey_p256),
                hw_attestation_sig_hex: hex::encode(hw_attestation_sig),
                ip_subnet_hash: *ip_subnet_hash,
                country_code: *country_code,
                stake: *stake,
            },
            NativeTransaction::DepositStorageBounty { swarm_id, amount } => {
                Self::DepositStorageBounty {
                    swarm_id: *swarm_id,
                    amount: *amount,
                }
            }
            NativeTransaction::SubmitSwarmCheckpoint {
                swarm_id,
                epoch,
                aggregator_slot,
                new_blobs_root,
                repair_log,
                uptime_bitmap,
                sample_index,
                sample_eval,
                kzg_sample_proof,
                repair_audit,
                aggregator_p256_sig,
            } => Self::SubmitSwarmCheckpoint {
                swarm_id: *swarm_id,
                epoch: *epoch,
                aggregator_slot: *aggregator_slot,
                new_blobs_root_hex: hex::encode(new_blobs_root),
                repair_log: repair_log.iter().map(RepairEntryDto::from).collect(),
                uptime_bitmap: uptime_bitmap.to_string(),
                sample_index: *sample_index,
                sample_eval_hex: hex::encode(sample_eval),
                kzg_sample_proof_hex: hex::encode(kzg_sample_proof),
                repair_audit: repair_audit.as_ref().map(RepairAuditProofDto::from),
                aggregator_p256_sig_hex: hex::encode(aggregator_p256_sig),
            },
            NativeTransaction::SubmitHeartbeatFaultProof {
                swarm_id,
                epoch,
                node_slot,
                aggregator_slot,
                signed_pong_receipt,
            } => Self::SubmitHeartbeatFaultProof {
                swarm_id: *swarm_id,
                epoch: *epoch,
                node_slot: *node_slot,
                aggregator_slot: *aggregator_slot,
                signed_pong_receipt_hex: hex::encode(signed_pong_receipt),
            },
        }
    }

    pub fn to_native(&self) -> Result<NativeTransaction> {
        match self {
            Self::RegisterMobileNode {
                pubkey_hex,
                hw_attestation_sig_hex,
                ip_subnet_hash,
                country_code,
                stake,
            } => Ok(NativeTransaction::RegisterMobileNode {
                pubkey_p256: decode_fixed_hex::<33>(pubkey_hex)?,
                hw_attestation_sig: decode_fixed_hex::<64>(hw_attestation_sig_hex)?,
                ip_subnet_hash: *ip_subnet_hash,
                country_code: *country_code,
                stake: *stake,
            }),
            Self::DepositStorageBounty { swarm_id, amount } => {
                Ok(NativeTransaction::DepositStorageBounty {
                    swarm_id: *swarm_id,
                    amount: *amount,
                })
            }
            Self::SubmitSwarmCheckpoint {
                swarm_id,
                epoch,
                aggregator_slot,
                new_blobs_root_hex,
                repair_log,
                uptime_bitmap,
                sample_index,
                sample_eval_hex,
                kzg_sample_proof_hex,
                repair_audit,
                aggregator_p256_sig_hex,
            } => {
                let bitmap: u128 = uptime_bitmap
                    .parse()
                    .map_err(|_| Error::Network("invalid u128 uptime_bitmap".into()))?;
                Ok(NativeTransaction::SubmitSwarmCheckpoint {
                    swarm_id: *swarm_id,
                    epoch: *epoch,
                    aggregator_slot: *aggregator_slot,
                    new_blobs_root: decode_fixed_hex::<48>(new_blobs_root_hex)?,
                    repair_log: repair_log
                        .iter()
                        .map(RepairEntry::try_from)
                        .collect::<Result<Vec<_>>>()?,
                    uptime_bitmap: bitmap,
                    sample_index: *sample_index,
                    sample_eval: decode_fixed_hex::<32>(sample_eval_hex)?,
                    kzg_sample_proof: decode_fixed_hex::<48>(kzg_sample_proof_hex)?,
                    repair_audit: repair_audit
                        .as_ref()
                        .map(RepairAuditProof::try_from)
                        .transpose()?,
                    aggregator_p256_sig: decode_fixed_hex::<64>(aggregator_p256_sig_hex)?,
                })
            }
            Self::SubmitHeartbeatFaultProof {
                swarm_id,
                epoch,
                node_slot,
                aggregator_slot,
                signed_pong_receipt_hex,
            } => Ok(NativeTransaction::SubmitHeartbeatFaultProof {
                swarm_id: *swarm_id,
                epoch: *epoch,
                node_slot: *node_slot,
                aggregator_slot: *aggregator_slot,
                signed_pong_receipt: decode_fixed_hex::<64>(signed_pong_receipt_hex)?,
            }),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeAccountDto {
    pub pubkey_hex: String,
    pub ip_subnet_hash: u16,
    pub country_code: u8,
    pub stake: u128,
    pub reward_balance: u128,
    pub consecutive_offline_epochs: u32,
    pub slashed: bool,
}

impl NodeAccountDto {
    pub fn from_account(pk: &[u8; 33], acc: &NodeAccount) -> Self {
        Self {
            pubkey_hex: hex::encode(pk),
            ip_subnet_hash: acc.ip_subnet_hash,
            country_code: acc.country_code,
            stake: acc.stake,
            reward_balance: acc.reward_balance,
            consecutive_offline_epochs: acc.consecutive_offline_epochs,
            slashed: acc.slashed,
        }
    }

    pub fn to_account(&self) -> Result<([u8; 33], NodeAccount)> {
        let pk = decode_fixed_hex::<33>(&self.pubkey_hex)?;
        Ok((
            pk,
            NodeAccount {
                pubkey_p256: pk,
                ip_subnet_hash: self.ip_subnet_hash,
                country_code: self.country_code,
                stake: self.stake,
                reward_balance: self.reward_balance,
                consecutive_offline_epochs: self.consecutive_offline_epochs,
                slashed: self.slashed,
            },
        ))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeaderDto {
    pub height: u64,
    pub prev_hash_hex: String,
    pub epoch_seed_hex: String,
    pub proposer_id: u64,
    pub tx_count: usize,
    pub state_root_hex: String,
}

impl From<&BlockHeader> for BlockHeaderDto {
    fn from(h: &BlockHeader) -> Self {
        Self {
            height: h.height,
            prev_hash_hex: hex::encode(h.prev_hash),
            epoch_seed_hex: hex::encode(h.epoch_seed),
            proposer_id: h.proposer_id,
            tx_count: h.tx_count,
            state_root_hex: hex::encode(h.state_root),
        }
    }
}

impl TryFrom<&BlockHeaderDto> for BlockHeader {
    type Error = Error;
    fn try_from(d: &BlockHeaderDto) -> Result<Self> {
        Ok(Self {
            height: d.height,
            prev_hash: decode_fixed_hex::<32>(&d.prev_hash_hex)?,
            epoch_seed: decode_fixed_hex::<32>(&d.epoch_seed_hex)?,
            proposer_id: d.proposer_id,
            tx_count: d.tx_count,
            state_root: decode_fixed_hex::<32>(&d.state_root_hex)?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceiptDto {
    pub tx_kind: String,
    pub distributed_reward: u128,
    pub aggregator_bonus: u128,
    pub slashed_amount: u128,
    pub active_blobs_root_hex: Option<String>,
}

impl From<&ExecutionReceipt> for ReceiptDto {
    fn from(r: &ExecutionReceipt) -> Self {
        Self {
            tx_kind: r.tx_kind.to_string(),
            distributed_reward: r.distributed_reward,
            aggregator_bonus: r.aggregator_bonus,
            slashed_amount: r.slashed_amount,
            active_blobs_root_hex: r.active_blobs_root.map(hex::encode),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VoteDto {
    pub height: u64,
    pub block_hash_hex: String,
    pub phase: String,
    pub validator_id: u64,
    pub signature_hex: String,
}

impl From<&Vote> for VoteDto {
    fn from(v: &Vote) -> Self {
        Self {
            height: v.height,
            block_hash_hex: hex::encode(v.block_hash),
            phase: match v.phase {
                l1_state_engine::consensus::VotePhase::Prevote => "Prevote".into(),
                l1_state_engine::consensus::VotePhase::Precommit => "Precommit".into(),
            },
            validator_id: v.validator_id,
            signature_hex: hex::encode(v.signature),
        }
    }
}

impl TryFrom<&VoteDto> for Vote {
    type Error = Error;
    fn try_from(d: &VoteDto) -> Result<Self> {
        let phase = match d.phase.as_str() {
            "Prevote" => l1_state_engine::consensus::VotePhase::Prevote,
            "Precommit" => l1_state_engine::consensus::VotePhase::Precommit,
            _ => return Err(Error::Network("invalid vote phase".into())),
        };
        Ok(Self {
            height: d.height,
            block_hash: decode_fixed_hex::<32>(&d.block_hash_hex)?,
            phase,
            validator_id: d.validator_id,
            signature: decode_fixed_hex::<64>(&d.signature_hex)?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalizedBlockDto {
    pub header: BlockHeaderDto,
    pub block_hash_hex: String,
    pub init_swarms: Vec<InitSwarmRequest>,
    pub txs: Vec<TxDto>,
    pub receipts: Vec<ReceiptDto>,
    pub precommits: Vec<VoteDto>,
}

impl FinalizedBlockDto {
    pub fn from_block(
        block: &FinalizedBlock,
        init_swarms: Vec<InitSwarmRequest>,
        txs: Vec<TxDto>,
    ) -> Self {
        Self {
            header: BlockHeaderDto::from(&block.header),
            block_hash_hex: hex::encode(block.block_hash),
            init_swarms,
            txs,
            receipts: block.receipts.iter().map(ReceiptDto::from).collect(),
            precommits: block.precommits.iter().map(VoteDto::from).collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InitSwarmRequest {
    pub swarm_id: u64,
    pub roster_pubkeys_hex: Vec<String>,
    pub member_verkle_root_hex: String,
    pub active_blobs_root_hex: String,
    pub initial_bounty: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwarmSummaryDto {
    pub swarm_id: u64,
    pub state: VirtualSwarmState,
    pub roster_pubkeys_hex: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct L1StatusDto {
    pub validator_id: u64,
    pub height: u64,
    pub last_block_hash_hex: String,
    pub epoch_seed_hex: String,
    pub registered_nodes: usize,
    pub swarm_count: usize,
    pub swarms: Vec<SwarmSummaryDto>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlotAssignmentDto {
    pub slot: u8,
    pub node_id: u64,
    pub p2p_addr: String,
    pub rpc_addr: String,
    pub pubkey_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwarmClusterMapDto {
    pub swarm_id: u64,
    pub chain_id: u64,
    pub slots: Vec<SlotAssignmentDto>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwarmManifestDto {
    pub swarm_id: u64,
    pub object_id_hex: String,
    pub root_hex: String,
    pub slot_fps_hex: Vec<String>,
    pub slot_proofs_hex: Vec<String>,
    #[serde(default)]
    pub custodian_owners: BTreeMap<u8, u8>,
    #[serde(default)]
    pub slot_generations: BTreeMap<u8, u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CycleReportDto {
    pub swarm_id: u64,
    pub epoch: u64,
    pub aggregator_slot: u8,
    pub online_slots: usize,
    pub accessible_shards_before: usize,
    pub repaired_slots: Vec<u8>,
    pub accessible_shards_after: usize,
    pub new_blobs_root_hex: String,
    pub block_height: u64,
    pub aggregator_bonus: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum P2pRequest {
    Ping {
        from_slot: u8,
        target_slot: u8,
        epoch: u64,
        #[serde(default)]
        aggregator_sig_hex: String,
    },
    IssueHeartbeatReceipt {
        swarm_id: u64,
        epoch: u64,
        target_slot: u8,
        aggregator_slot: u8,
        sig_hex: String,
    },
    StoreShard {
        slot: u8,
        is_custodian: bool,
        generation: u64,
        shard: ShardDto,
        proof_hex: String,
    },
    HandoffShard {
        slot: u8,
        object_id_hex: String,
        target_p2p_addr: String,
    },
    FetchShard {
        slot: u8,
        object_id_hex: String,
    },
    StoreManifest {
        manifest: SwarmManifestDto,
    },
    BftPropose {
        header: BlockHeaderDto,
        block_hash_hex: String,
        init_swarms: Vec<InitSwarmRequest>,
        txs: Vec<TxDto>,
    },
    BftCommit {
        block: FinalizedBlockDto,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum P2pResponse {
    Pong {
        slot: u8,
        epoch: u64,
        sig_hex: String,
    },
    StoreAck {
        ok: bool,
        message: String,
    },
    ShardData {
        found: bool,
        shard: Option<ShardDto>,
        proof_hex: Option<String>,
    },
    BftVoteReply {
        accepted: bool,
        prevote: Option<VoteDto>,
        precommit: Option<VoteDto>,
        reason: Option<String>,
    },
    Ack {
        ok: bool,
    },
    Error {
        message: String,
    },
}

pub async fn write_frame<T: Serialize>(stream: &mut TcpStream, msg: &T) -> Result<()> {
    let bytes = serde_json::to_vec(msg)?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(Error::Network("frame too large".into()));
    }
    let len = (bytes.len() as u32).to_be_bytes();
    tokio::time::timeout(IO_TIMEOUT, async {
        stream.write_all(&len).await?;
        stream.write_all(&bytes).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| Error::Network("tcp write timeout".into()))??;
    Ok(())
}

pub async fn read_frame<T: DeserializeOwned>(stream: &mut TcpStream) -> Result<T> {
    let mut len_buf = [0u8; 4];
    tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| Error::Network("tcp read length timeout".into()))??;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_FRAME_BYTES {
        return Err(Error::Network("invalid frame length".into()));
    }
    let mut buf = vec![0u8; len];
    tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut buf))
        .await
        .map_err(|_| Error::Network("tcp read payload timeout".into()))??;
    Ok(serde_json::from_slice(&buf)?)
}

pub async fn send_p2p(addr: SocketAddr, req: &P2pRequest) -> Result<P2pResponse> {
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| Error::Network(format!("connect timeout to {addr}")))??;
    write_frame(&mut stream, req).await?;
    read_frame(&mut stream).await
}

pub fn parse_http_host_port(url: &str) -> Result<(String, String)> {
    let trimmed = url.strip_prefix("http://").unwrap_or(url);
    let (host_port, path) = match trimmed.find('/') {
        Some(idx) => (&trimmed[..idx], &trimmed[idx..]),
        None => (trimmed, "/"),
    };
    Ok((host_port.to_string(), path.to_string()))
}

pub async fn http_request_json<B: Serialize, R: DeserializeOwned>(
    base_url: &str,
    method: &str,
    path: &str,
    body: Option<&B>,
) -> Result<R> {
    let (host_port, _) = parse_http_host_port(base_url)?;
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&host_port))
        .await
        .map_err(|_| Error::Network(format!("http connect timeout to {host_port}")))??;

    let body_bytes = match body {
        Some(b) => serde_json::to_vec(b)?,
        None => Vec::new(),
    };
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host_port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body_bytes.len()
    );
    tokio::time::timeout(IO_TIMEOUT, async {
        stream.write_all(req.as_bytes()).await?;
        if !body_bytes.is_empty() {
            stream.write_all(&body_bytes).await?;
        }
        stream.flush().await
    })
    .await
    .map_err(|_| Error::Network("http write timeout".into()))??;

    let mut raw = Vec::new();
    tokio::time::timeout(HTTP_READ_TIMEOUT, stream.read_to_end(&mut raw))
        .await
        .map_err(|_| Error::Network("http read timeout".into()))??;

    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| Error::Network("malformed http response".into()))?;
    let header_str = String::from_utf8_lossy(&raw[..split]);
    let status_line = header_str.lines().next().unwrap_or("");
    let body_slice = &raw[split + 4..];

    if !status_line.contains(" 200 ") && !status_line.contains(" 201 ") {
        return Err(Error::Network(format!(
            "http error ({status_line}): {}",
            String::from_utf8_lossy(body_slice)
        )));
    }
    Ok(serde_json::from_slice(body_slice)?)
}

pub fn proof_from_hex(s: &str) -> Result<KzgProof> {
    decode_fixed_hex::<48>(s)
}

pub fn root_from_hex(s: &str) -> Result<KzgRoot> {
    decode_fixed_hex::<48>(s)
}

pub async fn read_http_request(stream: &mut TcpStream) -> Result<(String, String, Vec<u8>)> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        let n = tokio::time::timeout(IO_TIMEOUT, stream.read(&mut tmp))
            .await
            .map_err(|_| Error::Network("http request read timeout".into()))??;
        if n == 0 {
            return Err(Error::Network("unexpected EOF reading http headers".into()));
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > MAX_FRAME_BYTES {
            return Err(Error::Network("http header too large".into()));
        }
    };

    let header_str = String::from_utf8_lossy(&buf[..header_end]);
    let mut lines = header_str.lines();
    let req_line = lines
        .next()
        .ok_or_else(|| Error::Network("empty http request".into()))?;
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let path = parts
        .next()
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/")
        .to_string();

    let content_len = lines
        .find_map(|line| {
            let (k, v) = line.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    if content_len > MAX_FRAME_BYTES {
        return Err(Error::Network("http body too large".into()));
    }

    let mut body = buf[(header_end + 4)..].to_vec();
    while body.len() < content_len {
        let n = tokio::time::timeout(IO_TIMEOUT, stream.read(&mut tmp))
            .await
            .map_err(|_| Error::Network("http body read timeout".into()))??;
        if n == 0 {
            return Err(Error::Network("unexpected EOF reading http body".into()));
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_len);
    Ok((method, path, body))
}

pub async fn write_http_json<T: Serialize>(
    stream: &mut TcpStream,
    status: u16,
    body: &T,
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Internal Server Error",
    };
    let payload = serde_json::to_vec(body)?;
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    tokio::time::timeout(IO_TIMEOUT, async {
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(&payload).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| Error::Network("http write timeout".into()))??;
    Ok(())
}

/// Shared TCP accept loop helper used by P2P and RPC daemon listeners.
pub fn spawn_tcp_server<S, F, Fut>(
    listener: TcpListener,
    state: Arc<S>,
    handler: F,
) -> JoinHandle<()>
where
    S: Send + Sync + 'static,
    F: Fn(TcpStream, Arc<S>) -> Fut + Send + Sync + Copy + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let st = Arc::clone(&state);
            tokio::spawn(async move {
                let _ = handler(stream, st).await;
            });
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use verkle_fountain::fountain::encode;

    #[test]
    fn shard_dto_and_tx_dto_roundtrip_all_variants() {
        let shards = encode(b"wire dto roundtrip payload", 4, 8, 12).unwrap();
        let dto = ShardDto::from_shard(&shards[0]);
        let json = serde_json::to_vec(&dto).unwrap();
        let decoded_dto: ShardDto = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded_dto.to_shard().unwrap(), shards[0]);

        let txs = vec![
            NativeTransaction::RegisterMobileNode {
                pubkey_p256: [0x02; 33],
                hw_attestation_sig: [0x11; 64],
                ip_subnet_hash: 42,
                country_code: 82,
                stake: 5_000,
            },
            NativeTransaction::DepositStorageBounty {
                swarm_id: 3,
                amount: 12_345,
            },
            NativeTransaction::SubmitSwarmCheckpoint {
                swarm_id: 0,
                epoch: 7,
                aggregator_slot: 2,
                new_blobs_root: [0x22; 48],
                repair_log: vec![RepairEntry {
                    repaired_slot: 4,
                    parent_slot_a: 10,
                    parent_slot_b: 20,
                    factor_b: [0x33; 32],
                }],
                uptime_bitmap: u128::MAX >> 28,
                sample_index: 9,
                sample_eval: [0x44; 32],
                kzg_sample_proof: [0x55; 48],
                repair_audit: Some(RepairAuditProof {
                    entry_index: 0,
                    old_blobs_root: [0x12; 48],
                    parent_a_eval: [0x66; 32],
                    parent_a_proof: [0x77; 48],
                    parent_b_eval: [0x88; 32],
                    parent_b_proof: [0x99; 48],
                    repaired_eval: [0xAA; 32],
                    repaired_proof: [0xBB; 48],
                    unchanged_slot: 1,
                    unchanged_eval: [0xCD; 32],
                    unchanged_old_proof: [0xDE; 48],
                    unchanged_new_proof: [0xEF; 48],
                }),
                aggregator_p256_sig: [0xCC; 64],
            },
            NativeTransaction::SubmitHeartbeatFaultProof {
                swarm_id: 1,
                epoch: 8,
                node_slot: 15,
                aggregator_slot: 0,
                signed_pong_receipt: [0xDD; 64],
            },
        ];

        for tx in txs {
            let tx_dto = TxDto::from_native(&tx);
            let encoded = serde_json::to_vec(&tx_dto).unwrap();
            let parsed: TxDto = serde_json::from_slice(&encoded).unwrap();
            assert_eq!(parsed.to_native().unwrap(), tx);
        }
    }

    #[test]
    fn decode_fixed_hex_rejects_bad_length_and_invalid_hex() {
        assert!(matches!(
            decode_fixed_hex::<4>("abcd"),
            Err(Error::Network(_))
        ));
        assert!(matches!(
            decode_fixed_hex::<2>("zzzz"),
            Err(Error::Network(_))
        ));
    }

    #[derive(Serialize, Deserialize)]
    struct EchoReq {
        val: u64,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
    struct EchoResp {
        method: String,
        path: String,
        val: u64,
    }

    #[test]
    fn p2p_frame_and_http_json_loopback_over_tcp() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            // 1. P2P 프레임 루프백 테스트
            let p2p_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let p2p_addr = p2p_listener.local_addr().unwrap();
            let p2p_task = spawn_tcp_server(p2p_listener, Arc::new(()), |mut stream, _| async move {
                let req: P2pRequest = read_frame(&mut stream).await?;
                let resp = match req {
                    P2pRequest::Ping {
                        target_slot, epoch, ..
                    } => P2pResponse::Pong {
                        slot: target_slot,
                        epoch,
                        sig_hex: "aa".into(),
                    },
                    _ => P2pResponse::Error {
                        message: "unexpected".into(),
                    },
                };
                write_frame(&mut stream, &resp).await
            });

            let resp = send_p2p(
                p2p_addr,
                &P2pRequest::Ping {
                    from_slot: 1,
                    target_slot: 2,
                    epoch: 7,
                    aggregator_sig_hex: String::new(),
                },
            )
            .await
            .unwrap();
            assert!(matches!(
                resp,
                P2pResponse::Pong {
                    slot: 2,
                    epoch: 7,
                    ..
                }
            ));
            p2p_task.abort();

            // 2. HTTP JSON-RPC 루프백 테스트
            let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let http_addr = http_listener.local_addr().unwrap();
            let http_task =
                spawn_tcp_server(http_listener, Arc::new(()), |mut stream, _| async move {
                    let (method, path, body) = read_http_request(&mut stream).await?;
                    let req: EchoReq = serde_json::from_slice(&body)?;
                    write_http_json(
                        &mut stream,
                        200,
                        &EchoResp {
                            method,
                            path,
                            val: req.val,
                        },
                    )
                    .await
                });

            let echoed: EchoResp = http_request_json(
                &format!("http://{http_addr}"),
                "POST",
                "/echo?ignore=1",
                Some(&EchoReq { val: 42 }),
            )
            .await
            .unwrap();
            assert_eq!(
                echoed,
                EchoResp {
                    method: "POST".into(),
                    path: "/echo".into(),
                    val: 42,
                }
            );
            http_task.abort();
        });
    }

    #[test]
    fn p2p_ping_serde_default_and_new_variants_roundtrip() {
        // 기존 포맷(aggregator_sig_hex 생략) 역직렬화 호환성 확인
        let legacy_json = br#"{"Ping":{"from_slot":0,"target_slot":5,"epoch":2}}"#;
        let parsed: P2pRequest = serde_json::from_slice(legacy_json).unwrap();
        assert!(matches!(
            parsed,
            P2pRequest::Ping {
                from_slot: 0,
                target_slot: 5,
                epoch: 2,
                aggregator_sig_hex,
            } if aggregator_sig_hex.is_empty()
        ));

        let receipt_req = P2pRequest::IssueHeartbeatReceipt {
            swarm_id: 1,
            epoch: 4,
            target_slot: 9,
            aggregator_slot: 0,
            sig_hex: "aa".repeat(64),
        };
        let encoded_receipt = serde_json::to_vec(&receipt_req).unwrap();
        let decoded_receipt: P2pRequest = serde_json::from_slice(&encoded_receipt).unwrap();
        assert!(matches!(
            decoded_receipt,
            P2pRequest::IssueHeartbeatReceipt {
                swarm_id: 1,
                epoch: 4,
                target_slot: 9,
                aggregator_slot: 0,
                ..
            }
        ));

        let handoff_req = P2pRequest::HandoffShard {
            slot: 7,
            object_id_hex: "11".repeat(32),
            target_p2p_addr: "127.0.0.1:19999".into(),
        };
        let encoded_handoff = serde_json::to_vec(&handoff_req).unwrap();
        let decoded_handoff: P2pRequest = serde_json::from_slice(&encoded_handoff).unwrap();
        assert!(matches!(
            decoded_handoff,
            P2pRequest::HandoffShard {
                slot: 7,
                ..
            }
        ));
    }
}
