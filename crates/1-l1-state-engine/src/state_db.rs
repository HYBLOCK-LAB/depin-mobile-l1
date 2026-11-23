use crate::Result;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use verkle_fountain::verkle_kzg::{
    bytes_to_scalar, digest_to_scalar, Kzg, KzgProof, KzgRoot, Scalar,
};

mod bytes48 {
    use super::*;
    pub fn serialize<S: Serializer>(v: &[u8; 48], s: S) -> std::result::Result<S::Ok, S::Error> {
        v.as_slice().serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<[u8; 48], D::Error> {
        let vec = Vec::<u8>::deserialize(d)?;
        vec.try_into()
            .map_err(|v: Vec<u8>| serde::de::Error::invalid_length(v.len(), &"48 bytes"))
    }
}

pub const MIN_SWARM_SIZE: usize = 10;
pub const MAX_SWARM_SIZE: usize = 128;
pub const DEFAULT_UPTIME_BPS: u16 = 7_500;
pub const DEFAULT_SWARM_BOUNTY: u128 = 10_000;
pub const MAX_ENDPOINT_LEN: usize = 64;

/// L1 글로벌 상태 DB에 저장되는 가상 스웜 추상화 상태 객체 (고정 크기 148 Bytes)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualSwarmState {
    pub swarm_id: u64,
    #[serde(with = "bytes48")]
    pub member_verkle_root: [u8; 48],  // 스웜 모바일 노드 공개키(P-256) 및 지분 KZG 루트
    #[serde(with = "bytes48")]
    pub active_blobs_root: [u8; 48],   // 보관 중인 파일 조각들의 KZG 루트
    pub total_bond_balance: u128,      // 스웜 공동 스테이킹 담보금
    pub storage_bounty_pool: u128,     // 유저들이 예치한 보관 보상금(Bounty) 풀
    pub last_epoch_settled: u64,       // 마지막 정산 에포크 번호
    pub swarm_size_n: u8,
    pub min_threshold_k: u8,
    pub lazy_repair_trigger: u8,
    pub lazy_repair_target: u8,
}

impl VirtualSwarmState {
    /// 직렬화된 고정 바이너리 크기 (Bytes)
    pub const fn encoded_bytes_len() -> usize {
        8 + 48 + 48 + 16 + 16 + 8 + 1 + 1 + 1 + 1 // = 148 Bytes
    }
}

/// 지연 복구 발생 시 L1에 보고되는 복구 계보 엔트리 (35 Bytes)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepairEntry {
    pub repaired_slot: u8,
    pub parent_slot_a: u8,
    pub parent_slot_b: u8,
    /// S_new = S_A + factor_b * S_B (mod p) 결합 계수
    pub factor_b: [u8; 32],
}

/// L1 VRF가 랜덤 지목한 복구 슬롯 1건에 대한 O(1) KZG 동형 감사 증명 패키지
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepairAuditProof {
    pub entry_index: usize,
    pub old_blobs_root: [u8; 48],
    pub parent_a_eval: [u8; 32],
    pub parent_a_proof: [u8; 48],
    pub parent_b_eval: [u8; 32],
    pub parent_b_proof: [u8; 48],
    pub repaired_eval: [u8; 32],
    pub repaired_proof: [u8; 48],
    pub unchanged_slot: u8,
    pub unchanged_eval: [u8; 32],
    pub unchanged_old_proof: [u8; 48],
    pub unchanged_new_proof: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeTransaction {
    RegisterMobileNode {
        pubkey_p256: [u8; 33],
        hw_attestation_sig: [u8; 64],
        ip_subnet_hash: u16,
        country_code: u8,
        stake: u128,
        p2p_addr: String,
        rpc_addr: String,
    },
    DepositStorageBounty {
        swarm_id: u64,
        amount: u128,
    },
    RegisterObject {
        swarm_id: u64,
        object_id: [u8; 32],
        object_root: [u8; 48],
        bounty: u128,
    },
    /// 6시간 에포크마다 스웜 어그리게이터(0번 슬롯 우선, 부재 시 차순위 승계)가 제출하는 체크포인트
    SubmitSwarmCheckpoint {
        swarm_id: u64,
        epoch: u64,
        aggregator_slot: u8,           // 제출자 슬롯 번호 (에포크 보상의 5% 보너스 수령)
        new_blobs_root: [u8; 48],      // 현재 스웜이 보관·복구 유지 중인 파일 조각들의 48B KZG 루트
        repair_log: Vec<RepairEntry>,  // 지연 복구 발생 시 기록되는 복구 계보 (평상시 빈 배열)
        uptime_bitmap: u128,           // 100대 노드 가동 출석부 비트맵 (1 bit = 1 node)
        sample_index: u8,              // L1 VRF가 랜덤 지목한 감사 대상 조각 인덱스 (0..99)
        sample_eval: [u8; 32],         // 해당 조각의 32B 지문(다항식 평가값)
        kzg_sample_proof: [u8; 48],    // 48B KZG 몫 다항식 인수정리 증명
        repair_audit: Option<RepairAuditProof>,
        aggregator_p256_sig: [u8; 64], // 스웜 어그리게이터의 TEE(P-256) 서명
    },
    /// 반장이 켜져 있던 노드를 결석(0)으로 허위 보고했을 때 피해 노드가 제출하는 반박 증거 (Fault Proof)
    SubmitHeartbeatFaultProof {
        swarm_id: u64,
        epoch: u64,
        node_slot: u8,
        aggregator_slot: u8,
        signed_pong_receipt: [u8; 64], // 에포크 내 반장이 서명해 준 생존 확인 영수증
    },
    TriggerShuffle,
}

pub fn object_weight(swarm_id: u64, object_id: &[u8; 32]) -> Scalar {
    let mut h = Sha256::new();
    h.update(b"depin/obj-weight/v1");
    h.update(swarm_id.to_le_bytes());
    h.update(object_id);
    digest_to_scalar(&h.finalize())
}

impl NativeTransaction {
    /// P-256 서명 및 검증용 결정론적 체크포인트 바이트 직렬화
    pub fn checkpoint_signing_bytes(
        swarm_id: u64,
        epoch: u64,
        aggregator_slot: u8,
        new_blobs_root: &[u8; 48],
        repair_log: &[RepairEntry],
        uptime_bitmap: u128,
        sample_index: u8,
        sample_eval: &[u8; 32],
    ) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(b"depin/checkpoint/v1");
        h.update(swarm_id.to_le_bytes());
        h.update(epoch.to_le_bytes());
        h.update([aggregator_slot]);
        h.update(new_blobs_root);
        h.update((repair_log.len() as u64).to_le_bytes());
        for entry in repair_log {
            h.update([entry.repaired_slot, entry.parent_slot_a, entry.parent_slot_b]);
            h.update(entry.factor_b);
        }
        h.update(uptime_bitmap.to_le_bytes());
        h.update([sample_index]);
        h.update(sample_eval);
        h.finalize().to_vec()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeAccount {
    pub pubkey_p256: [u8; 33],
    pub ip_subnet_hash: u16,
    pub country_code: u8,
    pub stake: u128,
    pub reward_balance: u128,
    pub consecutive_offline_epochs: u32,
    pub slashed: bool,
    pub ema_uptime_bps: u16,
    pub p2p_addr: String,
    pub rpc_addr: String,
}

/// [비교 Baseline] 100대 노드의 개별 주소·슬롯·상태를 온체인에 각각 기록하는 레거시 상태 DB
#[derive(Default, Clone, Debug)]
pub struct LegacyStateDB {
    /// (blob_id, slot_index) -> LegacySlotRecord
    pub shard_owners: BTreeMap<(u64, u8), LegacySlotRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacySlotRecord {
    pub node_pubkey: [u8; 33],
    pub shard_hash: [u8; 32],
    pub reward_balance: u128,
    pub last_active_epoch: u64,
}

impl LegacySlotRecord {
    pub const fn encoded_bytes_len() -> usize {
        33 + 32 + 16 + 8 // = 89 Bytes per node slot (100 nodes = 8,900 Bytes)
    }
}

impl LegacyStateDB {
    pub fn insert_blob_slots(&mut self, blob_id: u64, owners: &[[u8; 33]]) {
        for (i, pk) in owners.iter().enumerate() {
            self.shard_owners.insert(
                (blob_id, i as u8),
                LegacySlotRecord {
                    node_pubkey: *pk,
                    shard_hash: [0u8; 32],
                    reward_balance: 0,
                    last_active_epoch: 0,
                },
            );
        }
    }

    pub fn update_slot_owner(&mut self, blob_id: u64, slot: u8, new_owner: [u8; 33], epoch: u64) {
        if let Some(rec) = self.shard_owners.get_mut(&(blob_id, slot)) {
            rec.node_pubkey = new_owner;
            rec.last_active_epoch = epoch;
        }
    }

    /// 온체인 상태 트리에 보관 중인 레거시 메타데이터 총 크기 (Bytes)
    pub fn total_state_bytes(&self) -> usize {
        self.shard_owners.len() * LegacySlotRecord::encoded_bytes_len()
    }
}

/// 멤버 공개키(P-256)를 BLS12-381 스칼라 필드 원소(F_p)로 결정론적 매핑한다.
pub fn member_leaf_scalar(pubkey_p256: &[u8; 33]) -> Scalar {
    let mut h = Sha256::new();
    h.update(b"depin/member-leaf/v1");
    h.update(pubkey_p256);
    let digest = h.finalize();
    let mut buf = [0u8; 32];
    // 최상위 바이트(byte 31)를 0으로 유지해 248비트 정수로 만들어 항상 canonical < p를 보장한다.
    buf[..31].copy_from_slice(&digest[..31]);
    bytes_to_scalar(&buf).expect("valid scalar")
}

fn member_leaves(roster: &[[u8; 33]]) -> Result<Vec<Scalar>> {
    if !(MIN_SWARM_SIZE..=MAX_SWARM_SIZE).contains(&roster.len()) {
        return Err(crate::Error::InvalidInput);
    }
    Ok(roster.iter().map(member_leaf_scalar).collect())
}

/// 스웜 로스터 공개키 벡터를 48B KZG/Verkle 멤버십 루트로 커밋한다.
pub fn compute_member_verkle_root(kzg: &Kzg, roster: &[[u8; 33]]) -> Result<KzgRoot> {
    let leaves = member_leaves(roster)?;
    kzg.commit(&leaves).map_err(|_| crate::Error::BadProof)
}

/// 특정 슬롯의 멤버 공개키에 대한 48B KZG/Verkle 멤버십 오프닝 증명을 생성한다.
pub fn open_member_verkle_proof(kzg: &Kzg, roster: &[[u8; 33]], slot: usize) -> Result<KzgProof> {
    if slot >= roster.len() {
        return Err(crate::Error::InvalidInput);
    }
    let leaves = member_leaves(roster)?;
    kzg.open(&leaves, slot).map_err(|_| crate::Error::BadProof)
}

/// 멤버십 루트(`member_root`)에 대해 `slot` 위치의 공개키 멤버십 KZG 증명을 O(1) 페어링으로 검증한다.
pub fn verify_member_verkle_proof(
    kzg: &Kzg,
    member_root: &KzgRoot,
    slot: usize,
    pubkey_p256: &[u8; 33],
    proof: &KzgProof,
) -> Result<()> {
    if slot >= MAX_SWARM_SIZE {
        return Err(crate::Error::BadProof);
    }
    kzg.verify(member_root, slot, member_leaf_scalar(pubkey_p256), proof)
        .map_err(|_| crate::Error::BadProof)
}

/// [제안 구조] 가상 스웜 단위로 148B 고정 헤더(48B Member Verkle Root 포함)만 L1 합의 상태에 커밋하는 네이티브 DB
///
/// # 상태 경계 분리 (On-chain Consensus State vs Off-chain Auxiliary Index)
/// - **On-chain consensus state (`swarms`)**: 스웜당 148B 고정 크기 `VirtualSwarmState` 맵.
///   스웜 초기화 이후 `compute_state_root`는 오직 이 영역만 해시해 BFT 합의 상태 크기를 148B/스웜으로 압축한다.
/// - **Off-chain auxiliary index (`swarm_rosters`, `nodes`, `standby_pool`)**:
///   실행기/검증자/노드가 로스터 조회, 대기열 충원, 로컬 지분·보상 추적을 위해 유지하는 오프체인 보조 인덱스다.
///   온체인 스웜 상태 루트에는 직접 포함되지 않으며, 멤버십 무결성은 `VirtualSwarmState::member_verkle_root`에 대한
///   KZG/Verkle 증명으로 검증한다.
#[derive(Default, Clone, Debug)]
pub struct EnshrinedSwarmDB {
    /// [On-chain Consensus State] 스웜 ID -> 148B 고정 헤더 (BFT state_root 커밋 대상)
    pub swarms: BTreeMap<u64, VirtualSwarmState>,
    /// [Off-chain Auxiliary Index] 스웜 ID -> 슬롯별 공개키 로스터 캐시 (KZG 멤버십 증명 생성·조회용)
    pub swarm_rosters: BTreeMap<u64, Vec<[u8; 33]>>,
    /// [Off-chain Auxiliary Index] 스웜 ID -> 집계 루트에 등록된 파일 ID 집합
    pub swarm_objects: BTreeMap<u64, BTreeSet<[u8; 32]>>,
    /// [Off-chain Auxiliary Index] 노드 공개키 -> 계정·스테이킹·보상·슬래싱 로컬 인덱스
    pub nodes: BTreeMap<[u8; 33], NodeAccount>,
    /// [Off-chain Auxiliary Index] 충원 대기 중인 예비 모바일 노드 공개키 풀
    pub standby_pool: Vec<[u8; 33]>,
}

impl EnshrinedSwarmDB {
    /// L1 BFT 합의 상태 루트에 커밋되는 온체인 스웜 헤더 총 크기 (Bytes)
    pub fn onchain_consensus_bytes(&self) -> usize {
        self.swarms.len() * VirtualSwarmState::encoded_bytes_len()
    }

    /// 스웜 온체인 상태 메타데이터 총 크기 (Bytes)
    pub fn swarm_headers_bytes(&self) -> usize {
        self.onchain_consensus_bytes()
    }

    pub fn get_swarm(&self, swarm_id: u64) -> Result<&VirtualSwarmState> {
        self.swarms
            .get(&swarm_id)
            .ok_or(crate::Error::InvalidInput)
    }

    /// 특정 모바일 노드의 계정 상태를 조회한다.
    pub fn get_node(&self, pubkey: &[u8; 33]) -> Result<&NodeAccount> {
        self.nodes
            .get(pubkey)
            .ok_or(crate::Error::InvalidInput)
    }

    /// 노드가 배정된 스웜 ID와 슬롯 번호(0..99)를 역추적한다.
    pub fn find_node_slot(&self, pubkey: &[u8; 33]) -> Option<(u64, u8)> {
        self.swarm_rosters.iter().find_map(|(&swarm_id, roster)| {
            roster
                .iter()
                .position(|node_pubkey| node_pubkey == pubkey)
                .map(|slot| (swarm_id, slot as u8))
        })
    }

    /// 슬래싱되지 않은 정상 활성 노드 수를 집계한다.
    pub fn active_node_count(&self) -> usize {
        self.nodes.values().filter(|node| !node.slashed).count()
    }

    /// 네트워크 전체 노드의 스테이킹 예치금 총액을 합산한다.
    pub fn total_staked_amount(&self) -> u128 {
        self.nodes
            .values()
            .fold(0u128, |acc, node| acc.saturating_add(node.stake))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_vs_enshrined_state_size_compression() {
        assert_eq!(LegacySlotRecord::encoded_bytes_len(), 89);
        assert_eq!(VirtualSwarmState::encoded_bytes_len(), 148);

        const N: usize = 100;
        let owners: Vec<[u8; 33]> = (0..N)
            .map(|i| {
                let mut pk = [0u8; 33];
                pk[0] = 0x02;
                pk[1] = i as u8;
                pk
            })
            .collect();

        let mut legacy = LegacyStateDB::default();
        legacy.insert_blob_slots(7, &owners);
        assert_eq!(legacy.total_state_bytes(), 8_900);

        let replacement = [0xAAu8; 33];
        legacy.update_slot_owner(7, 42, replacement, 5);
        let updated = &legacy.shard_owners[&(7, 42)];
        assert_eq!(updated.node_pubkey, replacement);
        assert_eq!(updated.last_active_epoch, 5);

        let mut enshrined = EnshrinedSwarmDB::default();
        enshrined.swarms.insert(
            7,
            VirtualSwarmState {
                swarm_id: 7,
                member_verkle_root: [1u8; 48],
                active_blobs_root: [2u8; 48],
                total_bond_balance: 100_000,
                storage_bounty_pool: 5_000,
                last_epoch_settled: 0,
                swarm_size_n: 100,
                min_threshold_k: 30,
                lazy_repair_trigger: 45,
                lazy_repair_target: 60,
            },
        );
        assert_eq!(enshrined.swarm_headers_bytes(), 148);
        assert_eq!(enshrined.onchain_consensus_bytes(), 148);
        // 오프체인 보조 인덱스(rosters/nodes/standby)를 채워도 온체인 합의 크기는 148B로 유지된다.
        enshrined.swarm_rosters.insert(7, owners.clone());
        for pk in &owners {
            enshrined.nodes.insert(
                *pk,
                NodeAccount {
                    pubkey_p256: *pk,
                    ip_subnet_hash: 1,
                    country_code: 82,
                    stake: 2_000,
                    reward_balance: 0,
                    consecutive_offline_epochs: 0,
                    slashed: false,
                    ema_uptime_bps: DEFAULT_UPTIME_BPS,
                    p2p_addr: String::new(),
                    rpc_addr: String::new(),
                },
            );
        }
        enshrined.standby_pool.push([0xBBu8; 33]);
        assert_eq!(enshrined.onchain_consensus_bytes(), 148);
        assert!(enshrined.get_swarm(7).is_ok());
        assert!(matches!(
            enshrined.get_swarm(999),
            Err(crate::Error::InvalidInput)
        ));
    }

    #[test]
    fn member_verkle_root_commit_open_verify_and_rejects_tampering() {
        use rand::{rngs::StdRng, SeedableRng};

        let mut rng = StdRng::seed_from_u64(303);
        const N: usize = 100;
        let kzg = Kzg::setup(MAX_SWARM_SIZE - 1, &mut rng);

        let roster: Vec<[u8; 33]> = (0..N)
            .map(|i| {
                let mut pk = [0u8; 33];
                pk[0] = 0x02;
                pk[1] = i as u8;
                pk[32] = (i.wrapping_mul(17)) as u8;
                pk
            })
            .collect();

        // 결정론성 & 서로 다른 공개키 구분 확인
        assert_eq!(member_leaf_scalar(&roster[0]), member_leaf_scalar(&roster[0]));
        assert_ne!(member_leaf_scalar(&roster[0]), member_leaf_scalar(&roster[1]));

        // 로스터 길이 불일치 및 슬롯 범위 초과 거부
        assert!(matches!(
            compute_member_verkle_root(&kzg, &roster[..MIN_SWARM_SIZE - 1]),
            Err(crate::Error::InvalidInput)
        ));
        assert!(matches!(
            open_member_verkle_proof(&kzg, &roster[..MIN_SWARM_SIZE - 1], 0),
            Err(crate::Error::InvalidInput)
        ));
        assert!(matches!(
            open_member_verkle_proof(&kzg, &roster, N),
            Err(crate::Error::InvalidInput)
        ));

        let member_root = compute_member_verkle_root(&kzg, &roster).unwrap();
        for slot in [0, 42, 99] {
            let proof = open_member_verkle_proof(&kzg, &roster, slot).unwrap();
            verify_member_verkle_proof(&kzg, &member_root, slot, &roster[slot], &proof).unwrap();

            // 다른 공개키, 다른 슬롯, 변조된 루트, 범위 초과 슬롯 모두 거부
            let other_slot = (slot + 1) % N;
            assert!(matches!(
                verify_member_verkle_proof(&kzg, &member_root, slot, &roster[other_slot], &proof),
                Err(crate::Error::BadProof)
            ));
            assert!(matches!(
                verify_member_verkle_proof(&kzg, &member_root, other_slot, &roster[slot], &proof),
                Err(crate::Error::BadProof)
            ));

            let mut tampered_root = member_root;
            tampered_root[0] ^= 0x01;
            assert!(matches!(
                verify_member_verkle_proof(&kzg, &tampered_root, slot, &roster[slot], &proof),
                Err(crate::Error::BadProof)
            ));
        }

        let proof0 = open_member_verkle_proof(&kzg, &roster, 0).unwrap();
        assert!(matches!(
            verify_member_verkle_proof(&kzg, &member_root, MAX_SWARM_SIZE, &roster[0], &proof0),
            Err(crate::Error::BadProof)
        ));
    }

    #[test]
    fn checkpoint_signing_bytes_is_deterministic_and_sensitive_to_fields() {
        let root = [0x11u8; 48];
        let eval = [0x22u8; 32];
        let entry = RepairEntry {
            repaired_slot: 3,
            parent_slot_a: 10,
            parent_slot_b: 20,
            factor_b: [0x33u8; 32],
        };

        let base = NativeTransaction::checkpoint_signing_bytes(
            1,
            2,
            0,
            &root,
            std::slice::from_ref(&entry),
            0b1011,
            7,
            &eval,
        );
        let repeat = NativeTransaction::checkpoint_signing_bytes(
            1,
            2,
            0,
            &root,
            std::slice::from_ref(&entry),
            0b1011,
            7,
            &eval,
        );
        assert_eq!(base, repeat);

        assert_ne!(
            base,
            NativeTransaction::checkpoint_signing_bytes(
                1,
                3,
                0,
                &root,
                std::slice::from_ref(&entry),
                0b1011,
                7,
                &eval,
            )
        );
        assert_ne!(
            base,
            NativeTransaction::checkpoint_signing_bytes(
                1,
                2,
                1,
                &root,
                std::slice::from_ref(&entry),
                0b1011,
                7,
                &eval,
            )
        );
        assert_ne!(
            base,
            NativeTransaction::checkpoint_signing_bytes(
                1,
                2,
                0,
                &root,
                std::slice::from_ref(&entry),
                0b1111,
                7,
                &eval,
            )
        );
        assert_ne!(
            base,
            NativeTransaction::checkpoint_signing_bytes(1, 2, 0, &root, &[], 0b1011, 7, &eval)
        );
        let mut alt_eval = eval;
        alt_eval[0] ^= 1;
        assert_ne!(
            base,
            NativeTransaction::checkpoint_signing_bytes(
                1,
                2,
                0,
                &root,
                std::slice::from_ref(&entry),
                0b1011,
                7,
                &alt_eval,
            )
        );
    }

    #[test]
    fn enshrined_db_node_query_and_stats_helpers() {
        // 1. 빈 DB 생성
        let mut db = EnshrinedSwarmDB::default();

        assert_eq!(db.active_node_count(), 0);
        assert_eq!(db.total_staked_amount(), 0);

        // 2. 테스트용 노드 식별자 생성
        let node_a = [1u8; 33];
        let node_b = [2u8; 33];
        let node_c = [3u8; 33];
        let node_d = [4u8; 33]; // 미등록 노드 조회용

        // 3. A, B, C 등록: B만 슬래싱된 상태
        for (pubkey, stake, slashed) in [
            (node_a, 100u128, false),
            (node_b, 200u128, true),
            (node_c, 300u128, false),
        ] {
            db.nodes.insert(
                pubkey,
                NodeAccount {
                    pubkey_p256: pubkey,
                    ip_subnet_hash: 0,
                    country_code: 0,
                    stake,
                    reward_balance: 0,
                    consecutive_offline_epochs: 0,
                    slashed,
                    ema_uptime_bps: DEFAULT_UPTIME_BPS,
                    p2p_addr: String::new(),
                    rpc_addr: String::new(),
                },
            );
        }

        // 4. 스웜 7에 A와 B 배정. C는 대기열에 둠
        db.swarm_rosters.insert(7, vec![node_a, node_b]);
        db.standby_pool.push(node_c);

        // 5. 등록된 노드의 계정 조회 확인
        let account = db.get_node(&node_a).unwrap();
        assert_eq!(account.pubkey_p256, node_a);
        assert_eq!(account.stake, 100);
        assert!(!account.slashed);

        // 6. 미등록 노드를 조회하면 지정된 에러 반환
        assert!(matches!(
            db.get_node(&node_d),
            Err(crate::Error::InvalidInput)
        ));

        // 7. 스웜 및 슬롯 위치 확인
        assert_eq!(db.find_node_slot(&node_a), Some((7, 0)));
        assert_eq!(db.find_node_slot(&node_b), Some((7, 1)));
        assert_eq!(db.find_node_slot(&node_c), None);
        assert_eq!(db.find_node_slot(&node_d), None);

        // 8. 정상 노드는 A, C의 2명
        assert_eq!(db.active_node_count(), 2);

        // 9. 스테이크는 슬래싱된 B도 포함: 100 + 200 + 300
        assert_eq!(db.total_staked_amount(), 600);
    }
}
