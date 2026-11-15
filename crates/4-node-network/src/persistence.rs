use crate::wire::{
    decode_fixed_hex, FinalizedBlockDto, NodeAccountDto, ShardDto, SwarmManifestDto,
    SwarmSummaryDto,
};
use crate::{Error, Result};
use l1_state_engine::consensus::BftEngine;
use l1_state_engine::executor::Executor;
use l1_state_engine::state_db::VirtualSwarmState;
use p256::ecdsa::SigningKey;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use verkle_fountain::verkle_kzg::Kzg;

pub trait AttestationProvider: Send + Sync {
    fn pubkey_compressed(&self) -> [u8; 33];
    fn signing_key(&self) -> &SigningKey;
}

pub struct SoftwareTeeKey {
    pub key: SigningKey,
}

impl AttestationProvider for SoftwareTeeKey {
    fn pubkey_compressed(&self) -> [u8; 33] {
        compressed_pubkey(&self.key)
    }

    fn signing_key(&self) -> &SigningKey {
        &self.key
    }
}

pub fn compressed_pubkey(key: &SigningKey) -> [u8; 33] {
    key.verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .expect("compressed P-256 SEC1 key is 33 bytes")
}

pub fn deterministic_signing_key(seed: u64) -> SigningKey {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    let mut rng = ChaCha8Rng::from_seed(bytes);
    SigningKey::random(&mut rng)
}

pub fn load_or_create_signing_key(path: &Path, deterministic_seed: u64) -> Result<SigningKey> {
    if path.exists() {
        let content = fs::read_to_string(path)?;
        let raw = hex::decode(content.trim())
            .map_err(|e| Error::Network(format!("invalid key hex: {e}")))?;
        return SigningKey::from_slice(&raw)
            .map_err(|e| Error::Network(format!("invalid P-256 key bytes: {e}")));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let key = deterministic_signing_key(deterministic_seed);
    atomic_write(path, hex::encode(key.to_bytes()).as_bytes())?;
    Ok(key)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(tmp, path)?;
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct L1SnapshotFile {
    pub height: u64,
    pub last_block_hash_hex: String,
    pub epoch_seed_hex: String,
    pub nodes: Vec<NodeAccountDto>,
    pub standby_pool_hex: Vec<String>,
    pub swarms: Vec<SwarmSummaryDto>,
}

pub struct ValidatorStorage;

impl ValidatorStorage {
    pub fn load_or_create_kzg(data_dir: &Path, max_degree: usize, seed: u64) -> Result<Kzg> {
        let path = data_dir.join("kzg_srs.bin");
        if path.exists() {
            let bytes = fs::read(&path)?;
            return Ok(Kzg::from_bytes(&bytes)?);
        }
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let kzg = Kzg::setup(max_degree, &mut rng);
        let bytes = kzg.to_bytes()?;
        atomic_write(&path, &bytes)?;
        Ok(kzg)
    }

    pub fn save_snapshot(
        data_dir: &Path,
        bft: &BftEngine,
        exec: &Executor,
        epoch_seed: &[u8; 32],
    ) -> Result<()> {
        let nodes = exec
            .db
            .nodes
            .iter()
            .map(|(pk, acc)| NodeAccountDto::from_account(pk, acc))
            .collect();
        let standby_pool_hex = exec.db.standby_pool.iter().map(hex::encode).collect();
        let swarms = exec
            .db
            .swarms
            .iter()
            .map(|(swarm_id, state)| {
                let roster = exec
                    .db
                    .swarm_rosters
                    .get(swarm_id)
                    .map(|r| r.iter().map(hex::encode).collect())
                    .unwrap_or_default();
                SwarmSummaryDto {
                    swarm_id: *swarm_id,
                    state: state.clone(),
                    roster_pubkeys_hex: roster,
                }
            })
            .collect();

        let snap = L1SnapshotFile {
            height: bft.height,
            last_block_hash_hex: hex::encode(bft.last_block_hash),
            epoch_seed_hex: hex::encode(epoch_seed),
            nodes,
            standby_pool_hex,
            swarms,
        };
        let bytes = serde_json::to_vec_pretty(&snap)?;
        atomic_write(&data_dir.join("l1_snapshot.json"), &bytes)
    }

    pub fn append_block_wal(data_dir: &Path, block: &FinalizedBlockDto) -> Result<()> {
        fs::create_dir_all(data_dir)?;
        let path = data_dir.join("blocks.jsonl");
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        let line = serde_json::to_string(block)?;
        writeln!(file, "{line}")?;
        file.flush()?;
        Ok(())
    }

    pub fn load_snapshot(
        data_dir: &Path,
        bft: &mut BftEngine,
        exec: &mut Executor,
    ) -> Result<Option<[u8; 32]>> {
        let path = data_dir.join("l1_snapshot.json");
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(path)?;
        let snap: L1SnapshotFile = serde_json::from_slice(&bytes)?;
        bft.height = snap.height;
        bft.last_block_hash = decode_fixed_hex::<32>(&snap.last_block_hash_hex)?;
        let epoch_seed = decode_fixed_hex::<32>(&snap.epoch_seed_hex)?;

        exec.db.nodes.clear();
        for dto in &snap.nodes {
            let (pk, acc) = dto.to_account()?;
            exec.db.nodes.insert(pk, acc);
        }
        exec.db.standby_pool.clear();
        for pk_hex in &snap.standby_pool_hex {
            exec.db.standby_pool.push(decode_fixed_hex::<33>(pk_hex)?);
        }
        exec.db.swarms.clear();
        exec.db.swarm_rosters.clear();
        for sw in &snap.swarms {
            let state: VirtualSwarmState = sw.state.clone();
            exec.db.swarms.insert(sw.swarm_id, state);
            let roster = sw
                .roster_pubkeys_hex
                .iter()
                .map(|h| decode_fixed_hex::<33>(h))
                .collect::<Result<Vec<_>>>()?;
            exec.db.swarm_rosters.insert(sw.swarm_id, roster);
        }
        Ok(Some(epoch_seed))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlotMeta {
    pub slot: u8,
    pub generation: u64,
    pub is_custodian: bool,
    pub proof_hex: String,
    pub object_id_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredShardEnvelope {
    shard: ShardDto,
    proof_hex: String,
}

pub struct NodeStorage;

impl NodeStorage {
    fn slots_dir(data_dir: &Path) -> PathBuf {
        data_dir.join("slots")
    }

    fn meta_path(data_dir: &Path, slot: u8, is_custodian: bool) -> PathBuf {
        let prefix = if is_custodian { "custodian_" } else { "" };
        Self::slots_dir(data_dir).join(format!("{prefix}slot_{slot}_meta.json"))
    }

    fn shard_path(data_dir: &Path, slot: u8, is_custodian: bool, object_id_hex: &str) -> PathBuf {
        let prefix = if is_custodian { "custodian_" } else { "" };
        Self::slots_dir(data_dir).join(format!("{prefix}slot_{slot}_shard_{object_id_hex}.json"))
    }

    pub fn save_shard(
        data_dir: &Path,
        slot: u8,
        is_custodian: bool,
        generation: u64,
        shard: &ShardDto,
        proof_hex: &str,
    ) -> Result<bool> {
        let meta_path = Self::meta_path(data_dir, slot, is_custodian);
        if !is_custodian && meta_path.exists() {
            let existing: SlotMeta = serde_json::from_slice(&fs::read(&meta_path)?)?;
            if generation < existing.generation {
                return Ok(false);
            }
        }

        let shard_path = Self::shard_path(data_dir, slot, is_custodian, &shard.object_id_hex);
        let env = StoredShardEnvelope {
            shard: shard.clone(),
            proof_hex: proof_hex.to_string(),
        };
        atomic_write(&shard_path, &serde_json::to_vec(&env)?)?;

        let meta = SlotMeta {
            slot,
            generation,
            is_custodian,
            proof_hex: proof_hex.to_string(),
            object_id_hex: shard.object_id_hex.clone(),
        };
        atomic_write(&meta_path, &serde_json::to_vec_pretty(&meta)?)?;
        Ok(true)
    }

    pub fn load_shard(
        data_dir: &Path,
        slot: u8,
        object_id_hex: &str,
    ) -> Result<Option<(ShardDto, String)>> {
        for is_custodian in [false, true] {
            let path = Self::shard_path(data_dir, slot, is_custodian, object_id_hex);
            if path.exists() {
                let env: StoredShardEnvelope = serde_json::from_slice(&fs::read(path)?)?;
                return Ok(Some((env.shard, env.proof_hex)));
            }
        }
        Ok(None)
    }

    pub fn save_manifest(data_dir: &Path, manifest: &SwarmManifestDto) -> Result<()> {
        atomic_write(
            &data_dir.join("swarm_manifest.json"),
            &serde_json::to_vec_pretty(manifest)?,
        )
    }

    pub fn load_manifest(data_dir: &Path) -> Result<Option<SwarmManifestDto>> {
        let path = data_dir.join("swarm_manifest.json");
        if !path.exists() {
            return Ok(None);
        }
        let manifest: SwarmManifestDto = serde_json::from_slice(&fs::read(path)?)?;
        Ok(Some(manifest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use l1_state_engine::consensus::{ValidatorInfo, ValidatorSigner};
    use l1_state_engine::executor::{sign_registration, ExecutorConfig};
    use l1_state_engine::state_db::NativeTransaction;
    use std::collections::BTreeMap;
    use verkle_fountain::fountain::encode;

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(label: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "depin_persist_{label}_{}_{nanos}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn signing_key_and_validator_snapshot_persistence_roundtrip() {
        let dir = TempDir::new("val");
        let key_path = dir.path.join("validator_key.hex");

        let sk1 = load_or_create_signing_key(&key_path, 777).unwrap();
        let sk2 = load_or_create_signing_key(&key_path, 999).unwrap();
        assert_eq!(sk1.to_bytes(), sk2.to_bytes());

        let kzg1 = ValidatorStorage::load_or_create_kzg(&dir.path, 7, 55).unwrap();
        let kzg2 = ValidatorStorage::load_or_create_kzg(&dir.path, 7, 99).unwrap();
        assert_eq!(kzg1.powers_g1, kzg2.powers_g1);

        let signers: Vec<ValidatorSigner> = (0..4)
            .map(|id| ValidatorSigner::new(id, 1, deterministic_signing_key(900 + id)))
            .collect();
        let infos: Vec<ValidatorInfo> = signers.iter().map(|s| s.info()).collect();
        let mut bft = BftEngine::new(infos.clone()).unwrap();
        let mut exec = Executor::new(ExecutorConfig::default());
        let seed = [0x5Au8; 32];

        let node_sk = deterministic_signing_key(12);
        let (pk, sig) = sign_registration(&node_sk, exec.config.chain_id, 1, 82, 2_000);
        let block = bft
            .propose_and_finalize(
                &mut exec,
                &kzg1,
                0,
                vec![NativeTransaction::RegisterMobileNode {
                    pubkey_p256: pk,
                    hw_attestation_sig: sig,
                    ip_subnet_hash: 1,
                    country_code: 82,
                    stake: 2_000,
                }],
                seed,
                &[&signers[0], &signers[1], &signers[2]],
            )
            .unwrap();

        ValidatorStorage::save_snapshot(&dir.path, &bft, &exec, &seed).unwrap();
        ValidatorStorage::append_block_wal(
            &dir.path,
            &FinalizedBlockDto::from_block(&block, vec![], vec![]),
        )
        .unwrap();
        assert!(dir.path.join("blocks.jsonl").exists());

        let mut bft_restored = BftEngine::new(infos).unwrap();
        let mut exec_restored = Executor::new(ExecutorConfig::default());
        let loaded_seed =
            ValidatorStorage::load_snapshot(&dir.path, &mut bft_restored, &mut exec_restored)
                .unwrap();
        assert_eq!(loaded_seed, Some(seed));
        assert_eq!(bft_restored.height, 1);
        assert_eq!(bft_restored.last_block_hash, bft.last_block_hash);
        assert_eq!(exec_restored.db.nodes.len(), 1);
        assert!(exec_restored.db.nodes.contains_key(&pk));
    }

    #[test]
    fn node_storage_shard_custodian_and_generation_guard() {
        let dir = TempDir::new("node");
        let shards = encode(b"persistence shard test", 4, 8, 3).unwrap();
        let dto0 = ShardDto::from_shard(&shards[0]);
        let dto1 = ShardDto::from_shard(&shards[1]);

        // generation=1 저장 성공
        assert!(NodeStorage::save_shard(&dir.path, 0, false, 1, &dto0, "proof1").unwrap());
        // 더 낮은 generation=0 덮어쓰기 거부
        assert!(!NodeStorage::save_shard(&dir.path, 0, false, 0, &dto1, "stale").unwrap());

        let (loaded, proof) = NodeStorage::load_shard(&dir.path, 0, &dto0.object_id_hex)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.to_shard().unwrap(), shards[0]);
        assert_eq!(proof, "proof1");

        // 더 높은 generation=2 갱신 허용
        assert!(NodeStorage::save_shard(&dir.path, 0, false, 2, &dto0, "proof2").unwrap());
        let (_, updated_proof) = NodeStorage::load_shard(&dir.path, 0, &dto0.object_id_hex)
            .unwrap()
            .unwrap();
        assert_eq!(updated_proof, "proof2");

        // custodian 임시 보관 슬롯 저장·로드
        assert!(NodeStorage::save_shard(&dir.path, 5, true, 1, &dto1, "cust_proof").unwrap());
        let (cust_loaded, cust_proof) = NodeStorage::load_shard(&dir.path, 5, &dto1.object_id_hex)
            .unwrap()
            .unwrap();
        assert_eq!(cust_loaded.to_shard().unwrap(), shards[1]);
        assert_eq!(cust_proof, "cust_proof");

        // 매니페스트 저장·로드 왕복
        let manifest = SwarmManifestDto {
            swarm_id: 0,
            object_id_hex: dto0.object_id_hex.clone(),
            root_hex: "00".repeat(48),
            slot_fps_hex: vec!["11".repeat(32)],
            slot_proofs_hex: vec!["22".repeat(48)],
            custodian_owners: BTreeMap::from([(5u8, 60u8)]),
            slot_generations: BTreeMap::from([(0u8, 2u64)]),
        };
        NodeStorage::save_manifest(&dir.path, &manifest).unwrap();
        let loaded_manifest = NodeStorage::load_manifest(&dir.path).unwrap().unwrap();
        assert_eq!(loaded_manifest.swarm_id, manifest.swarm_id);
        assert_eq!(loaded_manifest.object_id_hex, manifest.object_id_hex);
        assert_eq!(loaded_manifest.custodian_owners, manifest.custodian_owners);
        assert_eq!(loaded_manifest.slot_generations, manifest.slot_generations);
    }
}
