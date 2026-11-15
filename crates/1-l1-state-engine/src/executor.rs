use crate::state_db::{
    compute_member_verkle_root, open_member_verkle_proof, verify_member_verkle_proof,
    EnshrinedSwarmDB, NativeTransaction, NodeAccount, VirtualSwarmState, SWARM_SIZE,
};
use crate::{Error, Result};
use p256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use verkle_fountain::verkle_kzg::{bytes_to_scalar, Kzg, KzgRoot, Scalar};

#[derive(Clone, Debug)]
pub struct ExecutorConfig {
    pub chain_id: u64,
    pub min_node_stake: u128,
    pub epoch_bounty_payout: u128,
    pub grace_period_epochs: u32,
    pub offline_slash_penalty: u128,
    pub aggregator_fault_slash: u128,
    pub fault_challenge_window: u64,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            chain_id: 2602,
            min_node_stake: 1_000,
            epoch_bounty_payout: 1_000,
            grace_period_epochs: 4, // 24시간(6h * 4 epoch) 유예 후 지연 슬래싱
            offline_slash_penalty: 200,
            aggregator_fault_slash: 500,
            fault_challenge_window: 4,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SettledCheckpointRecord {
    pub swarm_id: u64,
    pub epoch: u64,
    pub aggregator_slot: u8,
    pub aggregator_pubkey: [u8; 33],
    pub uptime_bitmap: u128,
    pub member_verkle_root: KzgRoot,
    pub roster_snapshot: Vec<[u8; 33]>,
    pub fault_penalized_slots: BTreeSet<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionReceipt {
    pub tx_kind: &'static str,
    pub distributed_reward: u128,
    pub aggregator_bonus: u128,
    pub slashed_amount: u128,
    pub active_blobs_root: Option<KzgRoot>,
}

pub fn registration_signing_bytes(
    chain_id: u64,
    pubkey_p256: &[u8; 33],
    ip_subnet_hash: u16,
    country_code: u8,
    stake: u128,
) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"depin/register/v1");
    h.update(chain_id.to_le_bytes());
    h.update(pubkey_p256);
    h.update(ip_subnet_hash.to_le_bytes());
    h.update([country_code]);
    h.update(stake.to_le_bytes());
    h.finalize().to_vec()
}

pub fn sign_registration(
    key: &SigningKey,
    chain_id: u64,
    ip_subnet_hash: u16,
    country_code: u8,
    stake: u128,
) -> ([u8; 33], [u8; 64]) {
    let pk: [u8; 33] = key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .expect("33-byte compressed SEC1 P-256 key");
    let msg = registration_signing_bytes(chain_id, &pk, ip_subnet_hash, country_code, stake);
    let sig: Signature = key.sign(&msg);
    (pk, sig.to_bytes().into())
}

pub fn heartbeat_signing_bytes(swarm_id: u64, epoch: u64, node_slot: u8) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"depin/heartbeat/v1");
    h.update(swarm_id.to_le_bytes());
    h.update(epoch.to_le_bytes());
    h.update([node_slot]);
    h.finalize().to_vec()
}

pub fn expected_sample_index(
    epoch_seed: &[u8; 32],
    swarm_id: u64,
    epoch: u64,
    swarm_size: usize,
) -> u8 {
    let mut h = Sha256::new();
    h.update(b"depin/vrf-sample/v1");
    h.update(epoch_seed);
    h.update(swarm_id.to_le_bytes());
    h.update(epoch.to_le_bytes());
    let digest = h.finalize();
    let val = u64::from_le_bytes(digest[..8].try_into().expect("8 bytes"));
    (val % swarm_size as u64) as u8
}

pub fn expected_repair_audit_index(
    epoch_seed: &[u8; 32],
    swarm_id: u64,
    epoch: u64,
    repair_len: usize,
) -> usize {
    let mut h = Sha256::new();
    h.update(b"depin/vrf-repair-audit/v1");
    h.update(epoch_seed);
    h.update(swarm_id.to_le_bytes());
    h.update(epoch.to_le_bytes());
    let digest = h.finalize();
    let val = u64::from_le_bytes(digest[..8].try_into().expect("8 bytes"));
    (val % repair_len as u64) as usize
}

/// VRF 시드 기반으로 복구되지 않은(unchanged) 슬롯 중 무결성 감사를 수행할 슬롯 1개를 결정론적으로 선택한다.
pub fn expected_unchanged_slot_index(
    epoch_seed: &[u8; 32],
    swarm_id: u64,
    epoch: u64,
    repair_log: &[crate::state_db::RepairEntry],
    swarm_size: usize,
) -> Option<u8> {
    if swarm_size == 0 {
        return None;
    }
    let mut h = Sha256::new();
    h.update(b"depin/vrf-unchanged/v1");
    h.update(epoch_seed);
    h.update(swarm_id.to_le_bytes());
    h.update(epoch.to_le_bytes());
    let digest = h.finalize();
    let start =
        (u64::from_le_bytes(digest[..8].try_into().expect("8 bytes")) % swarm_size as u64) as usize;
    for offset in 0..swarm_size {
        let candidate = (start + offset) % swarm_size;
        if !repair_log
            .iter()
            .any(|e| e.repaired_slot as usize == candidate)
        {
            return u8::try_from(candidate).ok();
        }
    }
    None
}

#[derive(Clone, Debug)]
pub struct Executor {
    pub config: ExecutorConfig,
    pub db: EnshrinedSwarmDB,
    pub settled_history: BTreeMap<(u64, u64), SettledCheckpointRecord>,
}

impl Executor {
    pub fn new(config: ExecutorConfig) -> Self {
        Self {
            config,
            db: EnshrinedSwarmDB::default(),
            settled_history: BTreeMap::new(),
        }
    }

    /// 제네시스 또는 에포크 셔플 후 스웜을 상태 DB에 초기화한다.
    pub fn init_swarm(
        &mut self,
        swarm_id: u64,
        roster: Vec<[u8; 33]>,
        member_verkle_root: KzgRoot,
        active_blobs_root: KzgRoot,
        initial_bounty: u128,
    ) -> Result<()> {
        if roster.len() != SWARM_SIZE {
            return Err(Error::InvalidInput);
        }
        let mut total_bond = 0u128;
        for pk in &roster {
            let acc = self.db.nodes.get(pk).ok_or(Error::Unauthorized)?;
            total_bond = total_bond
                .checked_add(acc.stake)
                .ok_or(Error::InvalidInput)?;
        }
        self.db.swarm_rosters.insert(swarm_id, roster);
        self.db.swarms.insert(
            swarm_id,
            VirtualSwarmState {
                swarm_id,
                member_verkle_root,
                active_blobs_root,
                total_bond_balance: total_bond,
                storage_bounty_pool: initial_bounty,
                last_epoch_settled: 0,
                min_threshold_k: 30,
                lazy_repair_trigger: 45,
            },
        );
        Ok(())
    }

    pub fn execute(
        &mut self,
        tx: NativeTransaction,
        kzg: &Kzg,
        epoch_seed: &[u8; 32],
    ) -> Result<ExecutionReceipt> {
        match tx {
            NativeTransaction::RegisterMobileNode {
                pubkey_p256,
                hw_attestation_sig,
                ip_subnet_hash,
                country_code,
                stake,
            } => {
                if stake < self.config.min_node_stake || self.db.nodes.contains_key(&pubkey_p256)
                {
                    return Err(Error::InvalidInput);
                }
                let vk =
                    VerifyingKey::from_sec1_bytes(&pubkey_p256).map_err(|_| Error::BadSignature)?;
                let sig =
                    Signature::from_slice(&hw_attestation_sig).map_err(|_| Error::BadSignature)?;
                let msg = registration_signing_bytes(
                    self.config.chain_id,
                    &pubkey_p256,
                    ip_subnet_hash,
                    country_code,
                    stake,
                );
                vk.verify(&msg, &sig).map_err(|_| Error::BadSignature)?;

                self.db.nodes.insert(
                    pubkey_p256,
                    NodeAccount {
                        pubkey_p256,
                        ip_subnet_hash,
                        country_code,
                        stake,
                        reward_balance: 0,
                        consecutive_offline_epochs: 0,
                        slashed: false,
                    },
                );
                self.db.standby_pool.push(pubkey_p256);

                Ok(ExecutionReceipt {
                    tx_kind: "RegisterMobileNode",
                    distributed_reward: 0,
                    aggregator_bonus: 0,
                    slashed_amount: 0,
                    active_blobs_root: None,
                })
            }

            NativeTransaction::DepositStorageBounty { swarm_id, amount } => {
                if amount == 0 {
                    return Err(Error::InvalidInput);
                }
                let swarm = self.db.swarms.get_mut(&swarm_id).ok_or(Error::InvalidInput)?;
                swarm.storage_bounty_pool = swarm
                    .storage_bounty_pool
                    .checked_add(amount)
                    .ok_or(Error::InvalidInput)?;
                Ok(ExecutionReceipt {
                    tx_kind: "DepositStorageBounty",
                    distributed_reward: 0,
                    aggregator_bonus: 0,
                    slashed_amount: 0,
                    active_blobs_root: Some(swarm.active_blobs_root),
                })
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
            } => {
                let swarm = self.db.swarms.get(&swarm_id).ok_or(Error::InvalidInput)?.clone();
                let roster = self
                    .db
                    .swarm_rosters
                    .get(&swarm_id)
                    .ok_or(Error::InvalidInput)?
                    .clone();
                if roster.len() != SWARM_SIZE {
                    return Err(Error::InvalidInput);
                }
                if epoch != swarm.last_epoch_settled + 1 {
                    return Err(Error::BadEpoch);
                }
                if (uptime_bitmap >> SWARM_SIZE) != 0 {
                    return Err(Error::InvalidInput);
                }
                let agg_idx = aggregator_slot as usize;
                if agg_idx >= SWARM_SIZE || (uptime_bitmap & (1u128 << agg_idx)) == 0 {
                    return Err(Error::Unauthorized);
                }
                if agg_idx > 0 {
                    let higher_priority_mask = (1u128 << agg_idx) - 1;
                    if (uptime_bitmap & higher_priority_mask) != 0 {
                        return Err(Error::Unauthorized);
                    }
                }

                // 0. member_verkle_root 일치 및 어그리게이터 슬롯 멤버십 KZG 증명 검증
                let expected_member_root = compute_member_verkle_root(kzg, &roster)?;
                if expected_member_root != swarm.member_verkle_root {
                    return Err(Error::BadProof);
                }
                let agg_pubkey = roster[agg_idx];
                let agg_member_proof = open_member_verkle_proof(kzg, &roster, agg_idx)?;
                verify_member_verkle_proof(
                    kzg,
                    &swarm.member_verkle_root,
                    agg_idx,
                    &agg_pubkey,
                    &agg_member_proof,
                )?;

                // 1. 제출한 어그리게이터(0번 또는 차순위 승계자)의 TEE P-256 서명 검증
                let agg_vk =
                    VerifyingKey::from_sec1_bytes(&agg_pubkey).map_err(|_| Error::BadSignature)?;
                let sig =
                    Signature::from_slice(&aggregator_p256_sig).map_err(|_| Error::BadSignature)?;
                let msg = NativeTransaction::checkpoint_signing_bytes(
                    swarm_id,
                    epoch,
                    aggregator_slot,
                    &new_blobs_root,
                    &repair_log,
                    uptime_bitmap,
                    sample_index,
                    &sample_eval,
                );
                agg_vk.verify(&msg, &sig).map_err(|_| Error::BadSignature)?;

                // 2. VRF 랜덤 감사 샘플에 대한 48B KZG 보유 증명 검증
                let expected_idx = expected_sample_index(epoch_seed, swarm_id, epoch, SWARM_SIZE);
                if sample_index != expected_idx {
                    return Err(Error::BadProof);
                }
                let sample_scalar = bytes_to_scalar(&sample_eval).map_err(|_| Error::BadProof)?;
                kzg.verify(&new_blobs_root, sample_index as usize, sample_scalar, &kzg_sample_proof)
                    .map_err(|_| Error::BadProof)?;

                // 3. 로컬 복구 발생 여부에 따른 new_blobs_root 교체 검증
                if repair_log.is_empty() {
                    if new_blobs_root != swarm.active_blobs_root {
                        return Err(Error::BadProof);
                    }
                } else {
                    let audit = repair_audit.as_ref().ok_or(Error::BadProof)?;
                    let expected_entry_idx =
                        expected_repair_audit_index(epoch_seed, swarm_id, epoch, repair_log.len());
                    if audit.entry_index != expected_entry_idx {
                        return Err(Error::BadProof);
                    }
                    let entry = &repair_log[audit.entry_index];
                    if entry.repaired_slot as usize >= SWARM_SIZE
                        || entry.parent_slot_a as usize >= SWARM_SIZE
                        || entry.parent_slot_b as usize >= SWARM_SIZE
                        || entry.parent_slot_a == entry.parent_slot_b
                    {
                        return Err(Error::InvalidInput);
                    }
                    let factor_b =
                        bytes_to_scalar(&entry.factor_b).map_err(|_| Error::BadProof)?;
                    if factor_b == Scalar::from(0u64) {
                        return Err(Error::BadProof);
                    }
                    let a_eval =
                        bytes_to_scalar(&audit.parent_a_eval).map_err(|_| Error::BadProof)?;
                    let b_eval =
                        bytes_to_scalar(&audit.parent_b_eval).map_err(|_| Error::BadProof)?;
                    let new_eval =
                        bytes_to_scalar(&audit.repaired_eval).map_err(|_| Error::BadProof)?;

                    // 3a. 부모 A, B가 기존 온체인 루트(old_root)에 속하는지 KZG 검증
                    kzg.verify(
                        &swarm.active_blobs_root,
                        entry.parent_slot_a as usize,
                        a_eval,
                        &audit.parent_a_proof,
                    )
                    .map_err(|_| Error::BadProof)?;
                    kzg.verify(
                        &swarm.active_blobs_root,
                        entry.parent_slot_b as usize,
                        b_eval,
                        &audit.parent_b_proof,
                    )
                    .map_err(|_| Error::BadProof)?;

                    // 3b. 복구 슬롯이 새 루트(new_blobs_root)에 속하는지 KZG 검증
                    kzg.verify(
                        &new_blobs_root,
                        entry.repaired_slot as usize,
                        new_eval,
                        &audit.repaired_proof,
                    )
                    .map_err(|_| Error::BadProof)?;

                    // 3c. F_p 선형 동형성 일치 검증: new_eval == a_eval + factor_b * b_eval
                    //     및 G1 타원곡선 점 덧셈 일치 확인
                    if new_eval != a_eval + factor_b * b_eval {
                        return Err(Error::BadProof);
                    }
                    let c_a = kzg.commit_fingerprint(a_eval);
                    let c_b = kzg.commit_fingerprint(b_eval);
                    let c_expected = kzg
                        .combine_commitments(&c_a, &c_b, factor_b)
                        .map_err(|_| Error::BadProof)?;
                    let c_actual = kzg.commit_fingerprint(new_eval);
                    if c_actual != c_expected {
                        return Err(Error::BadProof);
                    }

                    // 3d. 비-복구 슬롯 무결성 검증: VRF로 지목된 미복구 슬롯이 old/new 루트에서 동일하게 유지되는지 확인
                    if let Some(expected_unchanged) = expected_unchanged_slot_index(
                        epoch_seed,
                        swarm_id,
                        epoch,
                        &repair_log,
                        SWARM_SIZE,
                    ) {
                        if audit.unchanged_slot != expected_unchanged
                            || repair_log
                                .iter()
                                .any(|r| r.repaired_slot == audit.unchanged_slot)
                        {
                            return Err(Error::BadProof);
                        }
                        let unchanged_scalar =
                            bytes_to_scalar(&audit.unchanged_eval).map_err(|_| Error::BadProof)?;
                        kzg.verify(
                            &swarm.active_blobs_root,
                            audit.unchanged_slot as usize,
                            unchanged_scalar,
                            &audit.unchanged_old_proof,
                        )
                        .map_err(|_| Error::BadProof)?;
                        kzg.verify(
                            &new_blobs_root,
                            audit.unchanged_slot as usize,
                            unchanged_scalar,
                            &audit.unchanged_new_proof,
                        )
                        .map_err(|_| Error::BadProof)?;
                    }
                }

                // 4. 모든 검증 통과 -> 보상 정산 + 지연 슬래싱 + 대기 노드 충원 원자적 반영
                let mut staged_db = self.db.clone();
                let staged_swarm = staged_db.swarms.get_mut(&swarm_id).expect("checked");
                let staged_roster = staged_db.swarm_rosters.get_mut(&swarm_id).expect("checked");

                let payout = staged_swarm
                    .storage_bounty_pool
                    .min(self.config.epoch_bounty_payout);
                let online_count = uptime_bitmap.count_ones() as u128;
                let agg_bonus = (payout * 5) / 100;
                let member_pool = payout - agg_bonus;
                let per_node = member_pool / online_count;
                let actual_distributed = per_node * online_count;
                let total_spent = agg_bonus + actual_distributed;
                staged_swarm.storage_bounty_pool -= total_spent;

                // 반장 보너스 지급
                if let Some(agg_acc) = staged_db.nodes.get_mut(&agg_pubkey) {
                    agg_acc.reward_balance += agg_bonus;
                }

                // 100대 비트맵 순회 정산 & 유예 기간 초과 노드 지연 슬래싱 + 대기 노드 교체
                let mut total_slashed = 0u128;
                let mut new_total_bond = staged_swarm.total_bond_balance;
                let mut roster_changed = false;
                for (slot_idx, slot_pk) in staged_roster.iter_mut().enumerate() {
                    let is_online = (uptime_bitmap & (1u128 << slot_idx)) != 0;
                    if is_online {
                        if let Some(acc) = staged_db.nodes.get_mut(slot_pk) {
                            acc.reward_balance += per_node;
                            acc.consecutive_offline_epochs = 0;
                        }
                    } else if let Some(acc) = staged_db.nodes.get_mut(slot_pk) {
                        acc.consecutive_offline_epochs += 1;
                        if acc.consecutive_offline_epochs >= self.config.grace_period_epochs {
                            let penalty = acc.stake.min(self.config.offline_slash_penalty);
                            acc.stake -= penalty;
                            acc.slashed = true;
                            total_slashed += penalty;
                            new_total_bond = new_total_bond.saturating_sub(penalty);

                            // L1 Standby Pool에서 신규 대기 노드가 있으면 정식 슬롯으로 충원
                            if let Some(replacement_pk) = staged_db.standby_pool.first().copied() {
                                staged_db.standby_pool.remove(0);
                                let old_remaining_stake = acc.stake;
                                new_total_bond =
                                    new_total_bond.saturating_sub(old_remaining_stake);
                                *slot_pk = replacement_pk;
                                roster_changed = true;
                                if let Some(rep_acc) = staged_db.nodes.get(&replacement_pk) {
                                    new_total_bond += rep_acc.stake;
                                }
                            }
                        }
                    }
                }

                if roster_changed {
                    staged_swarm.member_verkle_root =
                        compute_member_verkle_root(kzg, staged_roster)?;
                }
                staged_swarm.total_bond_balance = new_total_bond;
                staged_swarm.active_blobs_root = new_blobs_root;
                staged_swarm.last_epoch_settled = epoch;

                self.db = staged_db;
                self.settled_history.insert(
                    (swarm_id, epoch),
                    SettledCheckpointRecord {
                        swarm_id,
                        epoch,
                        aggregator_slot,
                        aggregator_pubkey: agg_pubkey,
                        uptime_bitmap,
                        member_verkle_root: swarm.member_verkle_root,
                        roster_snapshot: roster,
                        fault_penalized_slots: BTreeSet::new(),
                    },
                );

                Ok(ExecutionReceipt {
                    tx_kind: "SubmitSwarmCheckpoint",
                    distributed_reward: actual_distributed,
                    aggregator_bonus: agg_bonus,
                    slashed_amount: total_slashed,
                    active_blobs_root: Some(new_blobs_root),
                })
            }

            NativeTransaction::SubmitHeartbeatFaultProof {
                swarm_id,
                epoch,
                node_slot,
                aggregator_slot,
                signed_pong_receipt,
            } => {
                if node_slot as usize >= SWARM_SIZE {
                    return Err(Error::InvalidInput);
                }
                let swarm = self.db.swarms.get(&swarm_id).ok_or(Error::InvalidInput)?;
                let rec = self
                    .settled_history
                    .get_mut(&(swarm_id, epoch))
                    .ok_or(Error::BadEpoch)?;

                if epoch + self.config.fault_challenge_window < swarm.last_epoch_settled {
                    return Err(Error::BadEpoch);
                }
                if rec.aggregator_slot != aggregator_slot {
                    return Err(Error::InvalidFaultProof);
                }
                // 실제 비트맵에서 결석(0)으로 기록되었을 때만 반박 성립
                if (rec.uptime_bitmap & (1u128 << node_slot)) != 0
                    || rec.fault_penalized_slots.contains(&node_slot)
                {
                    return Err(Error::InvalidFaultProof);
                }

                // 피해 노드와 반장 슬롯이 해당 에포크 member_verkle_root에 속함을 KZG 멤버십 증명으로 검증
                let victim_pk = *rec
                    .roster_snapshot
                    .get(node_slot as usize)
                    .ok_or(Error::InvalidInput)?;
                let agg_pk = rec.aggregator_pubkey;
                let victim_proof =
                    open_member_verkle_proof(kzg, &rec.roster_snapshot, node_slot as usize)?;
                verify_member_verkle_proof(
                    kzg,
                    &rec.member_verkle_root,
                    node_slot as usize,
                    &victim_pk,
                    &victim_proof,
                )?;
                let agg_proof =
                    open_member_verkle_proof(kzg, &rec.roster_snapshot, aggregator_slot as usize)?;
                verify_member_verkle_proof(
                    kzg,
                    &rec.member_verkle_root,
                    aggregator_slot as usize,
                    &agg_pk,
                    &agg_proof,
                )?;

                // 반장의 개인키로 서명된 Heartbeat 생존 확인 영수증 검증
                let agg_vk =
                    VerifyingKey::from_sec1_bytes(&agg_pk).map_err(|_| Error::BadSignature)?;
                let sig =
                    Signature::from_slice(&signed_pong_receipt).map_err(|_| Error::BadSignature)?;
                let msg = heartbeat_signing_bytes(swarm_id, epoch, node_slot);
                agg_vk.verify(&msg, &sig).map_err(|_| Error::BadSignature)?;

                // 조작 입증 완료 -> 반장 담보금 슬래싱 후 피해 노드에 보상 지급
                rec.fault_penalized_slots.insert(node_slot);

                let slashed = if let Some(agg_acc) = self.db.nodes.get_mut(&agg_pk) {
                    let penalty = agg_acc.stake.min(self.config.aggregator_fault_slash);
                    agg_acc.stake -= penalty;
                    agg_acc.slashed = true;
                    if let Some(sw) = self.db.swarms.get_mut(&swarm_id) {
                        sw.total_bond_balance = sw.total_bond_balance.saturating_sub(penalty);
                    }
                    penalty
                } else {
                    0
                };

                if let Some(victim_acc) = self.db.nodes.get_mut(&victim_pk) {
                    victim_acc.reward_balance += slashed;
                }

                Ok(ExecutionReceipt {
                    tx_kind: "SubmitHeartbeatFaultProof",
                    distributed_reward: slashed,
                    aggregator_bonus: 0,
                    slashed_amount: slashed,
                    active_blobs_root: None,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};
    use verkle_fountain::verkle_kzg::scalar_to_bytes;

    fn key_for(seed_num: u64) -> SigningKey {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&(seed_num + 100).to_le_bytes());
        let mut rng = StdRng::from_seed(seed);
        SigningKey::random(&mut rng)
    }

    fn setup_swarm_executor() -> (
        Executor,
        Kzg,
        Vec<SigningKey>,
        Vec<[u8; 33]>,
        Vec<Scalar>,
        KzgRoot,
        [u8; 32],
    ) {
        let mut rng = StdRng::seed_from_u64(42);
        let kzg = Kzg::setup(SWARM_SIZE - 1, &mut rng);
        let mut exec = Executor::new(ExecutorConfig::default());
        let epoch_seed = [0x99u8; 32];

        let mut keys = Vec::with_capacity(SWARM_SIZE);
        let mut roster = Vec::with_capacity(SWARM_SIZE);
        for i in 0..SWARM_SIZE {
            let sk = key_for(i as u64);
            let (pk, sig) = sign_registration(&sk, exec.config.chain_id, i as u16, 1, 2_000);
            exec.execute(
                NativeTransaction::RegisterMobileNode {
                    pubkey_p256: pk,
                    hw_attestation_sig: sig,
                    ip_subnet_hash: i as u16,
                    country_code: 1,
                    stake: 2_000,
                },
                &kzg,
                &epoch_seed,
            )
            .unwrap();
            keys.push(sk);
            roster.push(pk);
        }

        let fps: Vec<Scalar> = (0..SWARM_SIZE)
            .map(|i| Scalar::from((i * i * 7 + 13) as u64))
            .collect();
        let root = kzg.commit(&fps).unwrap();
        let member_root = compute_member_verkle_root(&kzg, &roster).unwrap();
        exec.init_swarm(0, roster.clone(), member_root, root, 10_000)
            .unwrap();

        (exec, kzg, keys, roster, fps, root, epoch_seed)
    }

    fn build_signed_checkpoint(
        swarm_id: u64,
        epoch: u64,
        aggregator_slot: u8,
        agg_key: &SigningKey,
        kzg: &Kzg,
        fps: &[Scalar],
        root: KzgRoot,
        uptime_bitmap: u128,
        epoch_seed: &[u8; 32],
    ) -> NativeTransaction {
        let sample_index = expected_sample_index(epoch_seed, swarm_id, epoch, SWARM_SIZE);
        let sample_eval = scalar_to_bytes(&fps[sample_index as usize]);
        let kzg_sample_proof = kzg.open(fps, sample_index as usize).unwrap();
        let msg = NativeTransaction::checkpoint_signing_bytes(
            swarm_id,
            epoch,
            aggregator_slot,
            &root,
            &[],
            uptime_bitmap,
            sample_index,
            &sample_eval,
        );
        let sig: Signature = agg_key.sign(&msg);
        NativeTransaction::SubmitSwarmCheckpoint {
            swarm_id,
            epoch,
            aggregator_slot,
            new_blobs_root: root,
            repair_log: Vec::new(),
            uptime_bitmap,
            sample_index,
            sample_eval,
            kzg_sample_proof,
            repair_audit: None,
            aggregator_p256_sig: sig.to_bytes().into(),
        }
    }

    #[test]
    fn register_node_rejects_under_min_stake_duplicate_and_bad_signature() {
        let mut rng = StdRng::seed_from_u64(1);
        let kzg = Kzg::setup(4, &mut rng);
        let mut exec = Executor::new(ExecutorConfig::default());
        let seed = [0xAA; 32];

        // (a) 최소 스테이킹 미달 거부
        let sk_low = key_for(1);
        let (pk_low, sig_low) = sign_registration(&sk_low, exec.config.chain_id, 1, 1, 999);
        let err_low = exec
            .execute(
                NativeTransaction::RegisterMobileNode {
                    pubkey_p256: pk_low,
                    hw_attestation_sig: sig_low,
                    ip_subnet_hash: 1,
                    country_code: 1,
                    stake: 999,
                },
                &kzg,
                &seed,
            )
            .unwrap_err();
        assert!(matches!(err_low, Error::InvalidInput));

        // 정상 등록
        let sk = key_for(2);
        let (pk, sig) = sign_registration(&sk, exec.config.chain_id, 2, 1, 1_500);
        exec.execute(
            NativeTransaction::RegisterMobileNode {
                pubkey_p256: pk,
                hw_attestation_sig: sig,
                ip_subnet_hash: 2,
                country_code: 1,
                stake: 1_500,
            },
            &kzg,
            &seed,
        )
        .unwrap();

        // (b) 중복 등록 거부
        let err_dup = exec
            .execute(
                NativeTransaction::RegisterMobileNode {
                    pubkey_p256: pk,
                    hw_attestation_sig: sig,
                    ip_subnet_hash: 2,
                    country_code: 1,
                    stake: 1_500,
                },
                &kzg,
                &seed,
            )
            .unwrap_err();
        assert!(matches!(err_dup, Error::InvalidInput));

        // (c) 서명 후 stake 변조 및 서명 바이트 변조 거부
        let sk3 = key_for(3);
        let (pk3, sig3) = sign_registration(&sk3, exec.config.chain_id, 3, 1, 1_500);
        let err_tampered_stake = exec
            .execute(
                NativeTransaction::RegisterMobileNode {
                    pubkey_p256: pk3,
                    hw_attestation_sig: sig3,
                    ip_subnet_hash: 3,
                    country_code: 1,
                    stake: 2_000,
                },
                &kzg,
                &seed,
            )
            .unwrap_err();
        assert!(matches!(err_tampered_stake, Error::BadSignature));

        let mut bad_sig = sig3;
        bad_sig[0] ^= 0xFF;
        let err_bad_sig = exec
            .execute(
                NativeTransaction::RegisterMobileNode {
                    pubkey_p256: pk3,
                    hw_attestation_sig: bad_sig,
                    ip_subnet_hash: 3,
                    country_code: 1,
                    stake: 1_500,
                },
                &kzg,
                &seed,
            )
            .unwrap_err();
        assert!(matches!(err_bad_sig, Error::BadSignature));
    }

    #[test]
    fn init_swarm_and_deposit_bounty_validate_roster_and_amounts() {
        let mut pre_exec = Executor::new(ExecutorConfig::default());

        // 100개 미만 로스터 거부
        assert!(matches!(
            pre_exec.init_swarm(0, vec![[0x02; 33]; 99], [0; 48], [0; 48], 100),
            Err(Error::InvalidInput)
        ));

        // 미등록 노드가 포함된 100개 로스터 거부
        assert!(matches!(
            pre_exec.init_swarm(0, vec![[0x02; 33]; SWARM_SIZE], [0; 48], [0; 48], 100),
            Err(Error::Unauthorized)
        ));

        let (mut exec, kzg, _keys, _roster, _fps, _root, epoch_seed) = setup_swarm_executor();

        // 0원 입금 거부 & 미존재 스웜 입금 거부
        assert!(matches!(
            exec.execute(
                NativeTransaction::DepositStorageBounty {
                    swarm_id: 0,
                    amount: 0,
                },
                &kzg,
                &epoch_seed,
            ),
            Err(Error::InvalidInput)
        ));
        assert!(matches!(
            exec.execute(
                NativeTransaction::DepositStorageBounty {
                    swarm_id: 99,
                    amount: 500,
                },
                &kzg,
                &epoch_seed,
            ),
            Err(Error::InvalidInput)
        ));

        let before = exec.db.get_swarm(0).unwrap().storage_bounty_pool;
        exec.execute(
            NativeTransaction::DepositStorageBounty {
                swarm_id: 0,
                amount: 500,
            },
            &kzg,
            &epoch_seed,
        )
        .unwrap();
        assert_eq!(exec.db.get_swarm(0).unwrap().storage_bounty_pool, before + 500);
    }

    #[test]
    fn checkpoint_rejects_wrong_epoch_offline_aggregator_and_bad_vrf_sample() {
        let (mut exec, kzg, keys, _roster, fps, root, epoch_seed) = setup_swarm_executor();
        let full_bitmap = (1u128 << SWARM_SIZE) - 1;

        // (a) epoch != last_epoch_settled + 1 -> BadEpoch
        let wrong_epoch_tx =
            build_signed_checkpoint(0, 2, 0, &keys[0], &kzg, &fps, root, full_bitmap, &epoch_seed);
        assert!(matches!(
            exec.execute(wrong_epoch_tx, &kzg, &epoch_seed),
            Err(Error::BadEpoch)
        ));

        // (b) 제출자 슬롯 비트가 0(결석) -> Unauthorized
        let offline_bitmap = full_bitmap & !1u128;
        let offline_agg_tx = build_signed_checkpoint(
            0,
            1,
            0,
            &keys[0],
            &kzg,
            &fps,
            root,
            offline_bitmap,
            &epoch_seed,
        );
        assert!(matches!(
            exec.execute(offline_agg_tx, &kzg, &epoch_seed),
            Err(Error::Unauthorized)
        ));

        // (c) 잘못된 sample_index 및 잘못된 KZG 증명 -> BadProof
        let mut bad_idx_tx =
            build_signed_checkpoint(0, 1, 0, &keys[0], &kzg, &fps, root, full_bitmap, &epoch_seed);
        if let NativeTransaction::SubmitSwarmCheckpoint {
            ref mut sample_index,
            ref mut sample_eval,
            ref mut kzg_sample_proof,
            ref mut aggregator_p256_sig,
            ..
        } = bad_idx_tx
        {
            *sample_index = (*sample_index + 1) % SWARM_SIZE as u8;
            *sample_eval = scalar_to_bytes(&fps[*sample_index as usize]);
            *kzg_sample_proof = kzg.open(&fps, *sample_index as usize).unwrap();
            let msg = NativeTransaction::checkpoint_signing_bytes(
                0,
                1,
                0,
                &root,
                &[],
                full_bitmap,
                *sample_index,
                sample_eval,
            );
            let sig: Signature = keys[0].sign(&msg);
            *aggregator_p256_sig = sig.to_bytes().into();
        }
        assert!(matches!(
            exec.execute(bad_idx_tx, &kzg, &epoch_seed),
            Err(Error::BadProof)
        ));

        let mut bad_proof_tx =
            build_signed_checkpoint(0, 1, 0, &keys[0], &kzg, &fps, root, full_bitmap, &epoch_seed);
        if let NativeTransaction::SubmitSwarmCheckpoint {
            sample_index,
            ref mut kzg_sample_proof,
            ..
        } = bad_proof_tx
        {
            let other_idx = (sample_index as usize + 1) % SWARM_SIZE;
            *kzg_sample_proof = kzg.open(&fps, other_idx).unwrap();
        }
        assert!(matches!(
            exec.execute(bad_proof_tx, &kzg, &epoch_seed),
            Err(Error::BadProof)
        ));
    }

    #[test]
    fn heartbeat_fault_proof_rejects_online_slot_duplicate_claim_and_expired_window() {
        let (mut exec, kzg, keys, _roster, fps, root, epoch_seed) = setup_swarm_executor();
        let full_bitmap = (1u128 << SWARM_SIZE) - 1;
        // 10번, 12번 슬롯 결석(0), 11번 슬롯 출석(1)
        let bitmap = full_bitmap & !(1u128 << 10) & !(1u128 << 12);

        let ckpt =
            build_signed_checkpoint(0, 1, 0, &keys[0], &kzg, &fps, root, bitmap, &epoch_seed);
        exec.execute(ckpt, &kzg, &epoch_seed).unwrap();

        let sign_ack = |slot: u8| -> [u8; 64] {
            let msg = heartbeat_signing_bytes(0, 1, slot);
            let sig: Signature = keys[0].sign(&msg);
            sig.to_bytes().into()
        };

        // (a) 출석(1) 처리된 11번 슬롯 반박 거부
        assert!(matches!(
            exec.execute(
                NativeTransaction::SubmitHeartbeatFaultProof {
                    swarm_id: 0,
                    epoch: 1,
                    node_slot: 11,
                    aggregator_slot: 0,
                    signed_pong_receipt: sign_ack(11),
                },
                &kzg,
                &epoch_seed,
            ),
            Err(Error::InvalidFaultProof)
        ));

        // (b) 결석(0) 처리된 10번 슬롯 정당 반박 성공
        let receipt = exec
            .execute(
                NativeTransaction::SubmitHeartbeatFaultProof {
                    swarm_id: 0,
                    epoch: 1,
                    node_slot: 10,
                    aggregator_slot: 0,
                    signed_pong_receipt: sign_ack(10),
                },
                &kzg,
                &epoch_seed,
            )
            .unwrap();
        assert_eq!(receipt.slashed_amount, exec.config.aggregator_fault_slash);

        // (c) 동일 슬롯 중복 반박 거부
        assert!(matches!(
            exec.execute(
                NativeTransaction::SubmitHeartbeatFaultProof {
                    swarm_id: 0,
                    epoch: 1,
                    node_slot: 10,
                    aggregator_slot: 0,
                    signed_pong_receipt: sign_ack(10),
                },
                &kzg,
                &epoch_seed,
            ),
            Err(Error::InvalidFaultProof)
        ));

        // (d) 챌린지 윈도우(4 에포크) 경과 후 만료 거부
        for epoch in 2..=6 {
            let tx = build_signed_checkpoint(
                0,
                epoch,
                0,
                &keys[0],
                &kzg,
                &fps,
                root,
                full_bitmap,
                &epoch_seed,
            );
            exec.execute(tx, &kzg, &epoch_seed).unwrap();
        }
        assert!(matches!(
            exec.execute(
                NativeTransaction::SubmitHeartbeatFaultProof {
                    swarm_id: 0,
                    epoch: 1,
                    node_slot: 12,
                    aggregator_slot: 0,
                    signed_pong_receipt: sign_ack(12),
                },
                &kzg,
                &epoch_seed,
            ),
            Err(Error::BadEpoch)
        ));
    }

    #[test]
    fn checkpoint_rejects_successor_when_higher_priority_slot_is_online() {
        let (mut exec, kzg, keys, _roster, fps, root, epoch_seed) = setup_swarm_executor();
        let full_bitmap = (1u128 << SWARM_SIZE) - 1;

        // 0번 슬롯이 온라인(1)인데 1번 슬롯이 반장으로 제출 시도 -> Unauthorized
        let tx_slot1_while_0_online =
            build_signed_checkpoint(0, 1, 1, &keys[1], &kzg, &fps, root, full_bitmap, &epoch_seed);
        assert!(matches!(
            exec.execute(tx_slot1_while_0_online, &kzg, &epoch_seed),
            Err(Error::Unauthorized)
        ));

        // 0..4번 중 4번만 온라인(1)이어도 5번 승계자는 Unauthorized
        let bitmap_only_4_online = full_bitmap & !((1u128 << 4) - 1);
        let tx_slot5_while_4_online = build_signed_checkpoint(
            0,
            1,
            5,
            &keys[5],
            &kzg,
            &fps,
            root,
            bitmap_only_4_online,
            &epoch_seed,
        );
        assert!(matches!(
            exec.execute(tx_slot5_while_4_online, &kzg, &epoch_seed),
            Err(Error::Unauthorized)
        ));

        // 0..5번 선순위 슬롯이 모두 오프라인(0)이면 5번 승계자 제출 성공
        let valid_successor_bitmap = full_bitmap & !((1u128 << 5) - 1);
        let tx_valid_successor = build_signed_checkpoint(
            0,
            1,
            5,
            &keys[5],
            &kzg,
            &fps,
            root,
            valid_successor_bitmap,
            &epoch_seed,
        );
        exec.execute(tx_valid_successor, &kzg, &epoch_seed).unwrap();
    }

    #[test]
    fn expected_unchanged_slot_index_skips_repaired_slots_and_handles_full_log() {
        use crate::state_db::RepairEntry;

        let epoch_seed = [0x42u8; 32];
        let first = expected_unchanged_slot_index(&epoch_seed, 0, 1, &[], SWARM_SIZE).unwrap();
        assert!((first as usize) < SWARM_SIZE);

        // VRF가 처음 지목한 슬롯이 repair_log에 포함되면 다음 미복구 슬롯으로 순회
        let log_with_first = vec![RepairEntry {
            repaired_slot: first,
            parent_slot_a: 10,
            parent_slot_b: 20,
            factor_b: [1u8; 32],
        }];
        let second =
            expected_unchanged_slot_index(&epoch_seed, 0, 1, &log_with_first, SWARM_SIZE).unwrap();
        assert_eq!(second, ((first as usize + 1) % SWARM_SIZE) as u8);

        // 모든 슬롯이 repair_log에 있으면 None
        let full_log: Vec<RepairEntry> = (0..SWARM_SIZE)
            .map(|s| RepairEntry {
                repaired_slot: s as u8,
                parent_slot_a: 0,
                parent_slot_b: 1,
                factor_b: [1u8; 32],
            })
            .collect();
        assert!(expected_unchanged_slot_index(&epoch_seed, 0, 1, &full_log, SWARM_SIZE).is_none());
    }

    #[test]
    fn checkpoint_rejects_repair_that_modifies_unchanged_slot() {
        use crate::state_db::{RepairAuditProof, RepairEntry};

        let (mut exec, kzg, keys, _roster, fps, _root, epoch_seed) = setup_swarm_executor();
        let full_bitmap = (1u128 << SWARM_SIZE) - 1;
        let factor_b = Scalar::from(7u64);
        let entry = RepairEntry {
            repaired_slot: 0,
            parent_slot_a: 10,
            parent_slot_b: 20,
            factor_b: scalar_to_bytes(&factor_b),
        };
        let repair_log = vec![entry.clone()];

        let unchanged_slot =
            expected_unchanged_slot_index(&epoch_seed, 0, 1, &repair_log, SWARM_SIZE).unwrap();
        assert_ne!(unchanged_slot, 0);

        let mut tampered_fps = fps.clone();
        tampered_fps[0] = fps[10] + factor_b * fps[20];
        // 비-복구 슬롯의 지문을 고의로 위변조
        tampered_fps[unchanged_slot as usize] += Scalar::from(1u64);
        let tampered_root = kzg.commit(&tampered_fps).unwrap();

        let sample_index = expected_sample_index(&epoch_seed, 0, 1, SWARM_SIZE);
        let sample_eval = scalar_to_bytes(&tampered_fps[sample_index as usize]);
        let kzg_sample_proof = kzg.open(&tampered_fps, sample_index as usize).unwrap();

        let parent_a_proof = kzg.open(&fps, 10).unwrap();
        let parent_b_proof = kzg.open(&fps, 20).unwrap();
        let repaired_proof = kzg.open(&tampered_fps, 0).unwrap();
        let unchanged_old_proof = kzg.open(&fps, unchanged_slot as usize).unwrap();
        let unchanged_new_proof = kzg.open(&tampered_fps, unchanged_slot as usize).unwrap();

        let build_tampered_tx = |unchanged_eval_scalar: Scalar| {
            let msg = NativeTransaction::checkpoint_signing_bytes(
                0,
                1,
                1,
                &tampered_root,
                &repair_log,
                full_bitmap & !1u128,
                sample_index,
                &sample_eval,
            );
            let sig: Signature = keys[1].sign(&msg);
            NativeTransaction::SubmitSwarmCheckpoint {
                swarm_id: 0,
                epoch: 1,
                aggregator_slot: 1,
                new_blobs_root: tampered_root,
                repair_log: repair_log.clone(),
                uptime_bitmap: full_bitmap & !1u128,
                sample_index,
                sample_eval,
                kzg_sample_proof,
                repair_audit: Some(RepairAuditProof {
                    entry_index: 0,
                    parent_a_eval: scalar_to_bytes(&fps[10]),
                    parent_a_proof,
                    parent_b_eval: scalar_to_bytes(&fps[20]),
                    parent_b_proof,
                    repaired_eval: scalar_to_bytes(&tampered_fps[0]),
                    repaired_proof,
                    unchanged_slot,
                    unchanged_eval: scalar_to_bytes(&unchanged_eval_scalar),
                    unchanged_old_proof,
                    unchanged_new_proof,
                }),
                aggregator_p256_sig: sig.to_bytes().into(),
            }
        };

        // old eval 기준 제출 -> new_root 검증 실패 (BadProof)
        assert!(matches!(
            exec.execute(
                build_tampered_tx(fps[unchanged_slot as usize]),
                &kzg,
                &epoch_seed
            ),
            Err(Error::BadProof)
        ));
        // new eval 기준 제출 -> old_root 검증 실패 (BadProof)
        assert!(matches!(
            exec.execute(
                build_tampered_tx(tampered_fps[unchanged_slot as usize]),
                &kzg,
                &epoch_seed
            ),
            Err(Error::BadProof)
        ));
    }

    #[test]
    fn checkpoint_rejects_tampered_member_verkle_root_and_out_of_sync_roster() {
        let (mut exec, kzg, keys, _roster, fps, root, epoch_seed) = setup_swarm_executor();
        let full_bitmap = (1u128 << SWARM_SIZE) - 1;

        // (a) 온체인 member_verkle_root 변조 시 체크포인트 거부
        let mut tampered_exec = exec.clone();
        tampered_exec.db.swarms.get_mut(&0).unwrap().member_verkle_root[0] ^= 0xFF;
        let ckpt_tampered =
            build_signed_checkpoint(0, 1, 0, &keys[0], &kzg, &fps, root, full_bitmap, &epoch_seed);
        assert!(matches!(
            tampered_exec.execute(ckpt_tampered, &kzg, &epoch_seed),
            Err(Error::BadProof)
        ));

        // (b) 오프체인 로스터가 다른 공개키로 변조되어 member_verkle_root와 불일치 시 거부
        let alt_sk = key_for(999);
        let alt_pk: [u8; 33] = alt_sk
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap();
        exec.db.swarm_rosters.get_mut(&0).unwrap()[0] = alt_pk;
        let ckpt_bad_roster =
            build_signed_checkpoint(0, 1, 0, &alt_sk, &kzg, &fps, root, full_bitmap, &epoch_seed);
        assert!(matches!(
            exec.execute(ckpt_bad_roster, &kzg, &epoch_seed),
            Err(Error::BadProof)
        ));
    }

    #[test]
    fn delayed_slashing_replaces_slot_and_updates_member_verkle_root() {
        let (mut exec, kzg, keys, roster, fps, root, epoch_seed) = setup_swarm_executor();
        let initial_member_root = exec.db.get_swarm(0).unwrap().member_verkle_root;

        // 기존 스웜 배정 완료 노드는 대기 풀에서 비운 뒤 신규 예비 노드 1대 등록
        exec.db.standby_pool.clear();
        let standby_sk = key_for(777);
        let (standby_pk, standby_sig) =
            sign_registration(&standby_sk, exec.config.chain_id, 250, 82, 3_000);
        exec.execute(
            NativeTransaction::RegisterMobileNode {
                pubkey_p256: standby_pk,
                hw_attestation_sig: standby_sig,
                ip_subnet_hash: 250,
                country_code: 82,
                stake: 3_000,
            },
            &kzg,
            &epoch_seed,
        )
        .unwrap();
        assert_eq!(exec.db.standby_pool, vec![standby_pk]);

        let full_bitmap = (1u128 << SWARM_SIZE) - 1;
        let bitmap_without_15 = full_bitmap & !(1u128 << 15);
        let evicted_pk = roster[15];

        // 1~3 에포크까지는 유예 기간 -> 슬래싱/교체 없음, member_verkle_root 유지
        for epoch in 1..=3 {
            let tx = build_signed_checkpoint(
                0,
                epoch,
                0,
                &keys[0],
                &kzg,
                &fps,
                root,
                bitmap_without_15,
                &epoch_seed,
            );
            let receipt = exec.execute(tx, &kzg, &epoch_seed).unwrap();
            assert_eq!(receipt.slashed_amount, 0);
            assert_eq!(exec.db.get_swarm(0).unwrap().member_verkle_root, initial_member_root);
        }

        // 4번째 에포크 도달 -> 지연 슬래싱 + 대기 노드 충원 + member_verkle_root 자동 재계산
        let tx4 = build_signed_checkpoint(
            0,
            4,
            0,
            &keys[0],
            &kzg,
            &fps,
            root,
            bitmap_without_15,
            &epoch_seed,
        );
        let receipt4 = exec.execute(tx4, &kzg, &epoch_seed).unwrap();
        assert_eq!(receipt4.slashed_amount, exec.config.offline_slash_penalty);
        assert!(exec.db.standby_pool.is_empty());
        assert_eq!(exec.db.swarm_rosters[&0][15], standby_pk);

        let updated_member_root = exec.db.get_swarm(0).unwrap().member_verkle_root;
        assert_ne!(updated_member_root, initial_member_root);
        assert_eq!(
            updated_member_root,
            compute_member_verkle_root(&kzg, &exec.db.swarm_rosters[&0]).unwrap()
        );

        // 갱신된 member_verkle_root로 새 노드 멤버십 증명 통과, 퇴출 노드 거부
        let new_proof = open_member_verkle_proof(&kzg, &exec.db.swarm_rosters[&0], 15).unwrap();
        verify_member_verkle_proof(&kzg, &updated_member_root, 15, &standby_pk, &new_proof)
            .unwrap();
        assert!(matches!(
            verify_member_verkle_proof(&kzg, &updated_member_root, 15, &evicted_pk, &new_proof),
            Err(Error::BadProof)
        ));

        // 교체 이후 에포크(5) 체크포인트도 새 member_verkle_root 기준으로 정상 정산
        let tx5 = build_signed_checkpoint(
            0,
            5,
            0,
            &keys[0],
            &kzg,
            &fps,
            root,
            full_bitmap,
            &epoch_seed,
        );
        exec.execute(tx5, &kzg, &epoch_seed).unwrap();

        // 에포크 4(교체 직전 로스터/루트 스냅샷)에 대한 Heartbeat Fault Proof도
        // SettledCheckpointRecord.member_verkle_root 기준으로 검증 가능하며,
        // 기록 내 member_verkle_root 변조 시 BadProof로 거부된다.
        let msg = heartbeat_signing_bytes(0, 4, 15);
        let sig: Signature = keys[0].sign(&msg);
        let mut tampered_rec_exec = exec.clone();
        tampered_rec_exec
            .settled_history
            .get_mut(&(0, 4))
            .unwrap()
            .member_verkle_root[0] ^= 0x55;
        assert!(matches!(
            tampered_rec_exec.execute(
                NativeTransaction::SubmitHeartbeatFaultProof {
                    swarm_id: 0,
                    epoch: 4,
                    node_slot: 15,
                    aggregator_slot: 0,
                    signed_pong_receipt: sig.to_bytes().into(),
                },
                &kzg,
                &epoch_seed,
            ),
            Err(Error::BadProof)
        ));

        let fault_receipt = exec
            .execute(
                NativeTransaction::SubmitHeartbeatFaultProof {
                    swarm_id: 0,
                    epoch: 4,
                    node_slot: 15,
                    aggregator_slot: 0,
                    signed_pong_receipt: sig.to_bytes().into(),
                },
                &kzg,
                &epoch_seed,
            )
            .unwrap();
        assert_eq!(fault_receipt.slashed_amount, exec.config.aggregator_fault_slash);
    }
}
