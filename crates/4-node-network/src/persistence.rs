use crate::wire::{decode_fixed_hex, FinalizedBlockDto, ShardDto, SwarmManifestDto};
use crate::{Error, Result};
use p256::ecdsa::SigningKey;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
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

    pub fn append_block_wal(data_dir: &Path, block: &FinalizedBlockDto) -> Result<()> {
        fs::create_dir_all(data_dir)?;
        let path = data_dir.join("blocks.jsonl");
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        let line = serde_json::to_string(block)?;
        writeln!(file, "{line}")?;
        file.flush()?;
        Ok(())
    }

    pub fn truncate_corrupt_wal_tail(data_dir: &Path) -> Result<()> {
        let path = data_dir.join("blocks.jsonl");
        if !path.exists() {
            return Ok(());
        }
        let content = fs::read(&path)?;
        let body = content.strip_suffix(b"\n").unwrap_or(&content);
        let start = body.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
        let tail = &body[start..];
        if tail.is_empty() || serde_json::from_slice::<FinalizedBlockDto>(tail).is_ok() {
            return Ok(());
        }
        eprintln!("blocks.jsonl: truncating corrupt last line at byte {start}");
        OpenOptions::new()
            .write(true)
            .open(path)?
            .set_len(start as u64)?;
        Ok(())
    }

    pub fn read_blocks(
        data_dir: &Path,
        from_height: u64,
        limit: usize,
    ) -> Result<Vec<FinalizedBlockDto>> {
        let path = data_dir.join("blocks.jsonl");
        if !path.exists() {
            return Ok(Vec::new());
        }
        let mut blocks = Vec::new();
        for line in BufReader::new(fs::File::open(path)?).lines() {
            let block: FinalizedBlockDto = serde_json::from_str(&line?)?;
            if block.header.height < from_height {
                continue;
            }
            blocks.push(block);
            if blocks.len() >= limit {
                break;
            }
        }
        Ok(blocks)
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeartbeatReceiptDto {
    pub swarm_id: u64,
    pub epoch: u64,
    pub target_slot: u8,
    pub aggregator_slot: u8,
    pub sig_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredShardEnvelope {
    shard: ShardDto,
    proof_hex: String,
}

pub struct NodeStorage;

impl NodeStorage {
    fn validate_hex_id(id: &str) -> Result<()> {
        if id.is_empty() || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Network("invalid object_id_hex".into()));
        }
        Ok(())
    }

    fn slots_dir(data_dir: &Path) -> PathBuf {
        data_dir.join("slots")
    }

    fn heartbeats_dir(data_dir: &Path) -> PathBuf {
        data_dir.join("heartbeats")
    }

    fn heartbeat_path(data_dir: &Path, epoch: u64, target_slot: u8) -> PathBuf {
        Self::heartbeats_dir(data_dir).join(format!("epoch_{epoch}_slot_{target_slot}.json"))
    }

    fn manifests_dir(data_dir: &Path) -> PathBuf {
        data_dir.join("manifests")
    }

    fn manifest_path(data_dir: &Path, object_id_hex: &str) -> Result<PathBuf> {
        Self::validate_hex_id(object_id_hex)?;
        Ok(Self::manifests_dir(data_dir).join(format!("manifest_{object_id_hex}.json")))
    }

    fn meta_path(
        data_dir: &Path,
        slot: u8,
        is_custodian: bool,
        object_id_hex: &str,
    ) -> PathBuf {
        let prefix = if is_custodian { "custodian_" } else { "" };
        Self::slots_dir(data_dir).join(format!("{prefix}slot_{slot}_{object_id_hex}_meta.json"))
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
        Self::validate_hex_id(&shard.object_id_hex)?;
        let meta_path = Self::meta_path(data_dir, slot, is_custodian, &shard.object_id_hex);
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

    pub fn load_shard_by_role(
        data_dir: &Path,
        slot: u8,
        is_custodian: bool,
        object_id_hex: &str,
    ) -> Result<Option<(ShardDto, String)>> {
        let path = Self::shard_path(data_dir, slot, is_custodian, object_id_hex);
        if !path.exists() {
            return Ok(None);
        }
        let env: StoredShardEnvelope = serde_json::from_slice(&fs::read(path)?)?;
        Ok(Some((env.shard, env.proof_hex)))
    }

    pub fn load_shard(
        data_dir: &Path,
        slot: u8,
        object_id_hex: &str,
    ) -> Result<Option<(ShardDto, String)>> {
        Self::validate_hex_id(object_id_hex)?;
        for is_custodian in [false, true] {
            if let Some(found) = Self::load_shard_by_role(data_dir, slot, is_custodian, object_id_hex)?
            {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }

    pub fn load_slot_meta_for_object(
        data_dir: &Path,
        slot: u8,
        is_custodian: bool,
        object_id_hex: &str,
    ) -> Result<Option<SlotMeta>> {
        Self::validate_hex_id(object_id_hex)?;
        let path = Self::meta_path(data_dir, slot, is_custodian, object_id_hex);
        if !path.exists() {
            return Ok(None);
        }
        let meta: SlotMeta = serde_json::from_slice(&fs::read(path)?)?;
        Ok(Some(meta))
    }

    pub fn load_slot_meta(
        data_dir: &Path,
        slot: u8,
        is_custodian: bool,
    ) -> Result<Option<SlotMeta>> {
        let dir = Self::slots_dir(data_dir);
        if !dir.exists() {
            return Ok(None);
        }
        let prefix = if is_custodian { "custodian_" } else { "" };
        let file_prefix = format!("{prefix}slot_{slot}_");
        let mut best: Option<SlotMeta> = None;
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !name.starts_with(&file_prefix) || !name.ends_with("_meta.json") {
                continue;
            }
            let meta: SlotMeta = serde_json::from_slice(&fs::read(&path)?)?;
            if meta.slot != slot || meta.is_custodian != is_custodian {
                continue;
            }
            let replace = match &best {
                None => true,
                Some(prev) => {
                    (meta.generation, &meta.object_id_hex)
                        > (prev.generation, &prev.object_id_hex)
                }
            };
            if replace {
                best = Some(meta);
            }
        }
        Ok(best)
    }

    pub fn remove_custodian_shard(
        data_dir: &Path,
        slot: u8,
        object_id_hex: &str,
    ) -> Result<()> {
        Self::validate_hex_id(object_id_hex)?;
        let shard_path = Self::shard_path(data_dir, slot, true, object_id_hex);
        if shard_path.exists() {
            fs::remove_file(shard_path)?;
        }
        let meta_path = Self::meta_path(data_dir, slot, true, object_id_hex);
        if meta_path.exists() {
            fs::remove_file(meta_path)?;
        }
        Ok(())
    }

    pub fn save_heartbeat_receipt(
        data_dir: &Path,
        swarm_id: u64,
        epoch: u64,
        target_slot: u8,
        aggregator_slot: u8,
        sig_hex: &str,
    ) -> Result<()> {
        let _ = decode_fixed_hex::<64>(sig_hex)?;
        let dto = HeartbeatReceiptDto {
            swarm_id,
            epoch,
            target_slot,
            aggregator_slot,
            sig_hex: sig_hex.to_string(),
        };
        let path = Self::heartbeat_path(data_dir, epoch, target_slot);
        atomic_write(&path, &serde_json::to_vec_pretty(&dto)?)
    }

    pub fn load_heartbeat_receipt(
        data_dir: &Path,
        epoch: u64,
        target_slot: u8,
    ) -> Result<Option<(u8, [u8; 64])>> {
        let path = Self::heartbeat_path(data_dir, epoch, target_slot);
        if !path.exists() {
            return Ok(None);
        }
        let dto: HeartbeatReceiptDto = serde_json::from_slice(&fs::read(path)?)?;
        let sig = decode_fixed_hex::<64>(&dto.sig_hex)?;
        Ok(Some((dto.aggregator_slot, sig)))
    }

    pub fn save_manifest(data_dir: &Path, manifest: &SwarmManifestDto) -> Result<()> {
        let per_file = Self::manifest_path(data_dir, &manifest.object_id_hex)?;
        let bytes = serde_json::to_vec_pretty(manifest)?;
        atomic_write(&per_file, &bytes)?;
        atomic_write(&data_dir.join("swarm_manifest.json"), &bytes)
    }

    pub fn load_manifest(data_dir: &Path) -> Result<Option<SwarmManifestDto>> {
        let path = data_dir.join("swarm_manifest.json");
        if !path.exists() {
            return Ok(None);
        }
        let manifest: SwarmManifestDto = serde_json::from_slice(&fs::read(path)?)?;
        Ok(Some(manifest))
    }

    pub fn load_manifest_for_object(
        data_dir: &Path,
        object_id_hex: Option<&str>,
    ) -> Result<Option<SwarmManifestDto>> {
        match object_id_hex {
            Some(obj_id) if !obj_id.is_empty() => {
                let path = Self::manifest_path(data_dir, obj_id)?;
                if path.exists() {
                    let manifest: SwarmManifestDto = serde_json::from_slice(&fs::read(path)?)?;
                    return Ok(Some(manifest));
                }
                if let Some(latest) = Self::load_manifest(data_dir)? {
                    if latest.object_id_hex.eq_ignore_ascii_case(obj_id) {
                        return Ok(Some(latest));
                    }
                }
                Ok(None)
            }
            _ => Self::load_manifest(data_dir),
        }
    }

    pub fn list_manifests(data_dir: &Path) -> Result<Vec<SwarmManifestDto>> {
        let dir = Self::manifests_dir(data_dir);
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut manifests = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                let m: SwarmManifestDto = serde_json::from_slice(&fs::read(&path)?)?;
                manifests.push(m);
            }
        }
        Ok(manifests)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use l1_state_engine::consensus::{BftEngine, ValidatorInfo, ValidatorSigner};
    use l1_state_engine::executor::{sign_registration, Executor, ExecutorConfig};
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
    fn signing_key_and_block_wal_persistence_roundtrip() {
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

        let dto = FinalizedBlockDto::from_block(&block, vec![], vec![]);
        ValidatorStorage::append_block_wal(&dir.path, &dto).unwrap();
        ValidatorStorage::append_block_wal(&dir.path, &dto).unwrap();

        let all = ValidatorStorage::read_blocks(&dir.path, 0, usize::MAX).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].block_hash_hex, hex::encode(bft.last_block_hash));
        assert_eq!(
            ValidatorStorage::read_blocks(&dir.path, 2, usize::MAX)
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            ValidatorStorage::read_blocks(&dir.path, 1, 1)
                .unwrap()
                .len(),
            1
        );
        assert!(exec.db.nodes.contains_key(&pk));
    }

    fn sample_block_line() -> String {
        let signers: Vec<ValidatorSigner> = (0..4)
            .map(|id| ValidatorSigner::new(id, 1, deterministic_signing_key(900 + id)))
            .collect();
        let infos: Vec<ValidatorInfo> = signers.iter().map(|s| s.info()).collect();
        let mut bft = BftEngine::new(infos).unwrap();
        let mut exec = Executor::new(ExecutorConfig::default());
        let kzg = Kzg::setup(7, &mut ChaCha8Rng::seed_from_u64(55));
        let block = bft
            .propose_and_finalize(
                &mut exec,
                &kzg,
                0,
                vec![],
                [0x5Au8; 32],
                &[&signers[0], &signers[1], &signers[2]],
            )
            .unwrap();
        serde_json::to_string(&FinalizedBlockDto::from_block(&block, vec![], vec![])).unwrap()
    }

    #[test]
    fn truncate_corrupt_wal_tail_drops_only_last_partial_line() {
        let dir = TempDir::new("walrepair");
        let line = sample_block_line();
        let wal = dir.path.join("blocks.jsonl");
        fs::write(&wal, format!("{line}\n{}", &line[..line.len() / 2])).unwrap();

        ValidatorStorage::truncate_corrupt_wal_tail(&dir.path).unwrap();

        assert_eq!(fs::read_to_string(&wal).unwrap(), format!("{line}\n"));
        assert_eq!(
            ValidatorStorage::read_blocks(&dir.path, 0, usize::MAX)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn corrupt_middle_wal_line_still_fails() {
        let dir = TempDir::new("walmiddle");
        let line = sample_block_line();
        let wal = dir.path.join("blocks.jsonl");
        let content = format!("{}\n{line}\n", &line[..line.len() / 2]);
        fs::write(&wal, &content).unwrap();

        ValidatorStorage::truncate_corrupt_wal_tail(&dir.path).unwrap();

        assert_eq!(fs::read_to_string(&wal).unwrap(), content);
        assert!(ValidatorStorage::read_blocks(&dir.path, 0, usize::MAX).is_err());
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
            roster_pubkeys_hex: Vec::new(),
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

    #[test]
    fn node_storage_heartbeat_receipt_and_custodian_cleanup_roundtrip() {
        let dir = TempDir::new("hb_cust");
        assert!(NodeStorage::load_heartbeat_receipt(&dir.path, 3, 12)
            .unwrap()
            .is_none());

        let sig_bytes = [0xABu8; 64];
        let sig_hex = hex::encode(sig_bytes);
        NodeStorage::save_heartbeat_receipt(&dir.path, 0, 3, 12, 1, &sig_hex).unwrap();
        let expected_path = dir.path.join("heartbeats/epoch_3_slot_12.json");
        assert!(expected_path.exists());

        let loaded = NodeStorage::load_heartbeat_receipt(&dir.path, 3, 12)
            .unwrap()
            .unwrap();
        assert_eq!(loaded, (1, sig_bytes));

        // Custodian 메타 조회 및 삭제 테스트
        let shards = encode(b"custodian cleanup payload", 4, 8, 9).unwrap();
        let dto = ShardDto::from_shard(&shards[0]);
        assert!(NodeStorage::save_shard(&dir.path, 4, true, 3, &dto, "cust_pf").unwrap());
        let meta = NodeStorage::load_slot_meta(&dir.path, 4, true)
            .unwrap()
            .unwrap();
        assert_eq!(meta.slot, 4);
        assert_eq!(meta.generation, 3);
        assert!(meta.is_custodian);
        assert_eq!(meta.object_id_hex, dto.object_id_hex);

        NodeStorage::remove_custodian_shard(&dir.path, 4, &dto.object_id_hex).unwrap();
        assert!(NodeStorage::load_slot_meta(&dir.path, 4, true)
            .unwrap()
            .is_none());
        assert!(NodeStorage::load_shard(&dir.path, 4, &dto.object_id_hex)
            .unwrap()
            .is_none());
    }

    #[test]
    fn node_storage_multifile_manifests_and_per_file_generations() {
        let dir = TempDir::new("multifile");
        let shards_a = encode(b"multifile payload alpha", 4, 8, 10).unwrap();
        let shards_b = encode(b"multifile payload beta", 4, 8, 20).unwrap();
        let dto_a = ShardDto::from_shard(&shards_a[0]);
        let dto_b = ShardDto::from_shard(&shards_b[0]);
        assert_ne!(dto_a.object_id_hex, dto_b.object_id_hex);

        // 파일 A를 generation=1로 저장해도 서로 다른 object_id인 파일 B의 generation=0 저장은 허용되어야 함
        assert!(NodeStorage::save_shard(&dir.path, 0, false, 1, &dto_a, "pa").unwrap());
        assert!(NodeStorage::save_shard(&dir.path, 0, false, 0, &dto_b, "pb").unwrap());
        assert!(!NodeStorage::save_shard(&dir.path, 0, false, 0, &dto_a, "stale").unwrap());

        let manifest_a = SwarmManifestDto {
            swarm_id: 0,
            object_id_hex: dto_a.object_id_hex.clone(),
            root_hex: "aa".repeat(48),
            roster_pubkeys_hex: Vec::new(),
            slot_fps_hex: vec!["11".repeat(32)],
            slot_proofs_hex: vec!["22".repeat(48)],
            custodian_owners: BTreeMap::from([(1u8, 2u8)]),
            slot_generations: BTreeMap::from([(0u8, 1u64)]),
        };
        let manifest_b = SwarmManifestDto {
            swarm_id: 0,
            object_id_hex: dto_b.object_id_hex.clone(),
            root_hex: "bb".repeat(48),
            roster_pubkeys_hex: Vec::new(),
            slot_fps_hex: vec!["33".repeat(32)],
            slot_proofs_hex: vec!["44".repeat(48)],
            custodian_owners: BTreeMap::new(),
            slot_generations: BTreeMap::new(),
        };

        NodeStorage::save_manifest(&dir.path, &manifest_a).unwrap();
        NodeStorage::save_manifest(&dir.path, &manifest_b).unwrap();

        // 최신 기본 manifest는 파일 B지만 object_id 지정 조회 시 파일 A·B 모두 독립 조회 가능
        assert_eq!(
            NodeStorage::load_manifest(&dir.path)
                .unwrap()
                .unwrap()
                .object_id_hex,
            dto_b.object_id_hex
        );
        let loaded_a =
            NodeStorage::load_manifest_for_object(&dir.path, Some(&dto_a.object_id_hex))
                .unwrap()
                .unwrap();
        assert_eq!(loaded_a.root_hex, manifest_a.root_hex);
        assert_eq!(loaded_a.custodian_owners, manifest_a.custodian_owners);

        let loaded_b =
            NodeStorage::load_manifest_for_object(&dir.path, Some(&dto_b.object_id_hex))
                .unwrap()
                .unwrap();
        assert_eq!(loaded_b.root_hex, manifest_b.root_hex);

        assert!(
            NodeStorage::load_manifest_for_object(&dir.path, Some(&"ff".repeat(32)))
                .unwrap()
                .is_none()
        );
        assert!(NodeStorage::load_manifest_for_object(&dir.path, Some("../escape")).is_err());
        assert_eq!(NodeStorage::list_manifests(&dir.path).unwrap().len(), 2);
    }
}
