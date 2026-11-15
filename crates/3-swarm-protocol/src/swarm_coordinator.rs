use crate::lazy_repair_fsm::{LazyRepairFsm, NodeState};
use crate::{Error, Result};
use l1_state_engine::executor::{
    expected_repair_audit_index, expected_sample_index, expected_unchanged_slot_index,
    heartbeat_signing_bytes,
};
use l1_state_engine::state_db::{NativeTransaction, RepairAuditProof, RepairEntry, SWARM_SIZE};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use verkle_fountain::verkle_kzg::{scalar_to_bytes, Kzg, KzgProof, Scalar};

/// 0번 슬롯부터 순회하여 현재 온라인 상태인 최우선 노드를 스웜 반장(어그리게이터)으로 선출한다.
/// 0번이 오프라인이면 1번 -> 2번 순으로 자동 승계된다.
pub fn select_active_aggregator(fsm: &LazyRepairFsm) -> Result<u8> {
    fsm.slots
        .iter()
        .enumerate()
        .find_map(|(i, slot)| (slot.state == NodeState::Online).then_some(i as u8))
        .ok_or(Error::CoordinatorFailed)
}

/// 반장 노드가 출석 확인 시 온라인 노드에게 발급해 주는 생존 확인 서명 영수증
/// (추후 반장이 해당 노드를 결석 조작할 경우 SubmitHeartbeatFaultProof 반박 증거로 사용됨)
pub fn issue_heartbeat_ack(
    swarm_id: u64,
    epoch: u64,
    node_slot: u8,
    aggregator_key: &SigningKey,
) -> [u8; 64] {
    let msg = heartbeat_signing_bytes(swarm_id, epoch, node_slot);
    let sig: Signature = aggregator_key.sign(&msg);
    sig.to_bytes().into()
}

/// 에포크 종료 시 100대 출석 비트맵 + KZG 루트 + VRF 샘플 증명 + (복구 시) 복구 계보 감사를 묶어
/// 단일 SubmitSwarmCheckpoint 트랜잭션을 조립하고 서명한다.
#[allow(clippy::too_many_arguments)]
pub fn build_checkpoint(
    swarm_id: u64,
    epoch: u64,
    epoch_seed: &[u8; 32],
    kzg: &Kzg,
    fsm: &LazyRepairFsm,
    old_fingerprints: &[Scalar],
    old_proofs: &[KzgProof],
    repair_log: Vec<RepairEntry>,
    aggregator_slot: u8,
    aggregator_key: &SigningKey,
) -> Result<NativeTransaction> {
    build_checkpoint_with_bitmap(
        swarm_id,
        epoch,
        epoch_seed,
        kzg,
        fsm,
        fsm.uptime_bitmap(),
        old_fingerprints,
        old_proofs,
        repair_log,
        aggregator_slot,
        aggregator_key,
    )
}

/// 테스트/시뮬레이션용(예: 조작된 출석 비트맵 주입 테스트 포함) 체크포인트 빌더
#[allow(clippy::too_many_arguments)]
pub fn build_checkpoint_with_bitmap(
    swarm_id: u64,
    epoch: u64,
    epoch_seed: &[u8; 32],
    kzg: &Kzg,
    fsm: &LazyRepairFsm,
    uptime_bitmap: u128,
    old_fingerprints: &[Scalar],
    old_proofs: &[KzgProof],
    repair_log: Vec<RepairEntry>,
    aggregator_slot: u8,
    aggregator_key: &SigningKey,
) -> Result<NativeTransaction> {
    let agg_idx = aggregator_slot as usize;
    if agg_idx >= SWARM_SIZE || fsm.slots[agg_idx].state != NodeState::Online {
        return Err(Error::CoordinatorFailed);
    }
    if old_fingerprints.len() != SWARM_SIZE {
        return Err(Error::Invalid);
    }

    // 복구되지 않은 죽은 슬롯(shard == None)은 기존 온체인 지문(old_fingerprints)을 유지한다.
    let new_fps: Vec<Scalar> = fsm
        .slots
        .iter()
        .enumerate()
        .map(|(i, s)| {
            s.shard
                .as_ref()
                .map_or(old_fingerprints[i], |sh| sh.fingerprint())
        })
        .collect();
    let new_blobs_root = kzg
        .commit(&new_fps)
        .map_err(|_| Error::CoordinatorFailed)?;

    let sample_index = expected_sample_index(epoch_seed, swarm_id, epoch, SWARM_SIZE);
    let sample_eval = scalar_to_bytes(&new_fps[sample_index as usize]);
    let kzg_sample_proof = kzg
        .open(&new_fps, sample_index as usize)
        .map_err(|_| Error::CoordinatorFailed)?;

    let repair_audit = if repair_log.is_empty() {
        None
    } else {
        if old_proofs.len() != SWARM_SIZE {
            return Err(Error::Invalid);
        }
        let old_blobs_root = kzg
            .commit(old_fingerprints)
            .map_err(|_| Error::CoordinatorFailed)?;
        let entry_index =
            expected_repair_audit_index(epoch_seed, swarm_id, epoch, repair_log.len());
        let entry = &repair_log[entry_index];
        let pa = entry.parent_slot_a as usize;
        let pb = entry.parent_slot_b as usize;
        let pr = entry.repaired_slot as usize;

        let repaired_proof = kzg
            .open(&new_fps, pr)
            .map_err(|_| Error::CoordinatorFailed)?;

        let unchanged_slot =
            expected_unchanged_slot_index(epoch_seed, swarm_id, epoch, &repair_log, SWARM_SIZE)
                .ok_or(Error::CoordinatorFailed)?;
        let unchanged_idx = unchanged_slot as usize;
        let unchanged_new_proof = kzg
            .open(&new_fps, unchanged_idx)
            .map_err(|_| Error::CoordinatorFailed)?;

        Some(RepairAuditProof {
            entry_index,
            old_blobs_root,
            parent_a_eval: scalar_to_bytes(&old_fingerprints[pa]),
            parent_a_proof: old_proofs[pa],
            parent_b_eval: scalar_to_bytes(&old_fingerprints[pb]),
            parent_b_proof: old_proofs[pb],
            repaired_eval: scalar_to_bytes(&new_fps[pr]),
            repaired_proof,
            unchanged_slot,
            unchanged_eval: scalar_to_bytes(&old_fingerprints[unchanged_idx]),
            unchanged_old_proof: old_proofs[unchanged_idx],
            unchanged_new_proof,
        })
    };

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
    let sig: Signature = aggregator_key.sign(&msg);

    Ok(NativeTransaction::SubmitSwarmCheckpoint {
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
        aggregator_p256_sig: sig.to_bytes().into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use verkle_fountain::fountain::encode;

    #[test]
    fn select_active_aggregator_succeeds_in_order_and_fails_when_all_offline() {
        let shards = encode(b"coordinator test payload", 30, SWARM_SIZE, 5).unwrap();
        let mut fsm = LazyRepairFsm::new(shards, 45, 60).unwrap();

        assert_eq!(select_active_aggregator(&fsm).unwrap(), 0);
        for i in 0..3 {
            fsm.drop_node(i, Some(10)).unwrap();
        }
        assert_eq!(select_active_aggregator(&fsm).unwrap(), 3);

        for i in 3..SWARM_SIZE {
            fsm.drop_node(i, None).unwrap();
        }
        assert!(matches!(
            select_active_aggregator(&fsm),
            Err(Error::CoordinatorFailed)
        ));
    }

    #[test]
    fn build_checkpoint_rejects_offline_or_out_of_range_aggregator() {
        let shards = encode(&vec![0x19u8; 4096], 30, SWARM_SIZE, 9).unwrap();
        let mut rng = ChaCha8Rng::seed_from_u64(9);
        let kzg = Kzg::setup(SWARM_SIZE - 1, &mut rng);
        let fps: Vec<Scalar> = shards.iter().map(|s| s.fingerprint()).collect();
        let proofs: Vec<KzgProof> = (0..SWARM_SIZE)
            .map(|i| kzg.open(&fps, i).unwrap())
            .collect();

        let mut fsm = LazyRepairFsm::new(shards, 45, 60).unwrap();
        fsm.drop_node(0, Some(10)).unwrap();
        let key = SigningKey::random(&mut rng);
        let seed = [0xAAu8; 32];

        assert!(matches!(
            build_checkpoint(0, 1, &seed, &kzg, &fsm, &fps, &proofs, Vec::new(), 0, &key),
            Err(Error::CoordinatorFailed)
        ));
        assert!(matches!(
            build_checkpoint(
                0,
                1,
                &seed,
                &kzg,
                &fsm,
                &fps,
                &proofs,
                Vec::new(),
                100,
                &key
            ),
            Err(Error::CoordinatorFailed)
        ));
    }
}
