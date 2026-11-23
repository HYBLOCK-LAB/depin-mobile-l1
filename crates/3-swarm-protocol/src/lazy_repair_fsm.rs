use crate::{Error, Result};
use l1_state_engine::state_db::{RepairEntry, MAX_SWARM_SIZE, MIN_SWARM_SIZE};
use verkle_fountain::fountain::{rank, repair_local_field, Shard};
use verkle_fountain::pollution_guard::{verify_homomorphic_repair, AuthenticatedShard};
use verkle_fountain::verkle_kzg::{scalar_to_bytes, Kzg, KzgProof, KzgRoot, Scalar};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeState {
    Online,
    TransientOffline { return_at: u64 },
    Dead,
}

#[derive(Clone, Debug)]
pub struct Slot {
    pub state: NodeState,
    pub generation: u64,
    pub shard: Option<Shard>,
    /// 지연 복구로 새 조각을 합성했을 때, 같은 에포크 내 임시 보관 책임을 맡은 생존 노드 슬롯 인덱스
    pub custodian_slot: Option<usize>,
}

#[derive(Clone, Debug)]
pub struct LazyRepairFsm {
    pub slots: Vec<Slot>,
    pub k: usize,
    pub trigger: usize,
    pub target: usize,
}

impl LazyRepairFsm {
    pub fn new(shards: Vec<Shard>, trigger: usize, target: usize) -> Result<Self> {
        let first = shards.first().ok_or(Error::Invalid)?;
        let k = first.k;
        let object = first.object_id;
        let len = first.original_len;

        let n = shards.len();
        if !(MIN_SWARM_SIZE..=MAX_SWARM_SIZE).contains(&n)
            || k >= trigger
            || trigger >= target
            || target > n
        {
            return Err(Error::Invalid);
        }

        for s in &shards {
            s.validate().map_err(|_| Error::Invalid)?;
            if s.k != k || s.object_id != object || s.original_len != len {
                return Err(Error::Invalid);
            }
        }

        Ok(Self {
            slots: shards
                .into_iter()
                .map(|shard| Slot {
                    state: NodeState::Online,
                    generation: 0,
                    shard: Some(shard),
                    custodian_slot: None,
                })
                .collect(),
            k,
            trigger,
            target,
        })
    }

    pub fn is_slot_shard_accessible(&self, index: usize) -> bool {
        let Some(slot) = self.slots.get(index) else {
            return false;
        };
        if slot.shard.is_none() {
            return false;
        }
        if slot.state == NodeState::Online {
            return true;
        }
        if let Some(cust) = slot.custodian_slot {
            return self
                .slots
                .get(cust)
                .is_some_and(|c| c.state == NodeState::Online);
        }
        false
    }

    /// 현재 스웜 내 물리적으로 켜져 있는 노드 수
    pub fn online_node_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| s.state == NodeState::Online)
            .count()
    }

    /// 현재 스웜에서 즉시 접근 가능한 활성 조각 수 (온라인 노드 + 임시 보관 생존 노드)
    pub fn active_shard_count(&self) -> usize {
        (0..self.slots.len())
            .filter(|&i| self.is_slot_shard_accessible(i))
            .count()
    }

    /// 100대 노드의 물리적 온라인 가동 여부 비트맵 (SubmitSwarmCheckpoint.uptime_bitmap 직결)
    pub fn uptime_bitmap(&self) -> u128 {
        let mut bitmap = 0u128;
        for (i, slot) in self.slots.iter().enumerate() {
            if slot.state == NodeState::Online {
                bitmap |= 1u128 << i;
            }
        }
        bitmap
    }

    /// F_p 가우스 소거법 기반 현재 접근 가능한 조각들의 선형 독립 랭크
    pub fn online_rank(&self) -> usize {
        let rows: Vec<Vec<Scalar>> = (0..self.slots.len())
            .filter(|&i| self.is_slot_shard_accessible(i))
            .filter_map(|i| self.slots[i].shard.as_ref().map(|s| s.coefficients.clone()))
            .collect();
        rank(&rows, self.k)
    }

    /// 현재 접근 가능한 조각들의 복사본 반환 (다운로드 및 디코딩 검증용)
    pub fn accessible_shards(&self) -> Vec<Shard> {
        (0..self.slots.len())
            .filter(|&i| self.is_slot_shard_accessible(i))
            .filter_map(|i| self.slots[i].shard.clone())
            .collect()
    }

    /// 100개 슬롯 전체의 1단계 선형 지문 벡터 (빈 슬롯은 Scalar::from(0))
    pub fn slot_fingerprints(&self) -> Vec<Scalar> {
        self.slots
            .iter()
            .map(|s| {
                s.shard
                    .as_ref()
                    .map_or(Scalar::from(0u64), |sh| sh.fingerprint())
            })
            .collect()
    }

    pub fn drop_node(&mut self, index: usize, return_at: Option<u64>) -> Result<u64> {
        let slot = self.slots.get_mut(index).ok_or(Error::Invalid)?;
        if slot.state != NodeState::Online {
            return Err(Error::Invalid);
        }
        slot.state = return_at.map_or(NodeState::Dead, |ts| NodeState::TransientOffline {
            return_at: ts,
        });
        if return_at.is_none() {
            slot.shard = None;
            slot.custodian_slot = None;
        }
        Ok(slot.generation)
    }

    /// Generation 가드로 지연 복구 교체 후 뒤늦게 돌아온 옛 노드가 새 조각을 덮어쓰는 것을 방지한다.
    pub fn return_node(&mut self, index: usize, generation: u64, now: u64) -> Result<bool> {
        let slot = self.slots.get_mut(index).ok_or(Error::Invalid)?;
        if generation != slot.generation {
            return Ok(false);
        }
        match slot.state {
            NodeState::TransientOffline { return_at } if return_at <= now => {
                slot.state = NodeState::Online;
                slot.custodian_slot = None;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// 안전버퍼 임계선(A <= T_repair=45) 도달 시 F_p 선형 결합 로컬 복구 + 동형 오염 검증 + 임시 보관 배정을 원자적으로 실행한다.
    pub fn repair(
        &mut self,
        kzg: &Kzg,
        root: &KzgRoot,
        proofs: &[KzgProof],
    ) -> Result<Vec<RepairEntry>> {
        let active = self.active_shard_count();
        if active > self.trigger {
            return Ok(Vec::new());
        }
        if self.online_rank() < self.k {
            return Err(Error::Unavailable);
        }
        if proofs.len() != self.slots.len() {
            return Err(Error::RepairFailed);
        }

        let online_custodians: Vec<usize> = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| (s.state == NodeState::Online).then_some(i))
            .collect();
        if online_custodians.is_empty() {
            return Err(Error::Unavailable);
        }

        let accessible_parents: Vec<(usize, &Shard)> = (0..self.slots.len())
            .filter(|&i| self.is_slot_shard_accessible(i))
            .filter_map(|i| self.slots[i].shard.as_ref().map(|sh| (i, sh)))
            .collect();

        let target_slots: Vec<usize> = (0..self.slots.len())
            .filter(|&i| !self.is_slot_shard_accessible(i))
            .collect();

        let needed = self.target.saturating_sub(active);
        if needed == 0 || target_slots.len() < needed {
            return Err(Error::RepairFailed);
        }

        let mut repairs = Vec::with_capacity(needed);
        let mut candidates: Vec<(usize, usize, Shard, RepairEntry)> = Vec::with_capacity(needed);
        let mut factor_seed = 2u64;

        'outer: for x in 0..accessible_parents.len() {
            for y in (x + 1)..accessible_parents.len() {
                let (ia, a) = accessible_parents[x];
                let (ib, b) = accessible_parents[y];
                if a.coefficients == b.coefficients {
                    continue;
                }
                let factor_b = Scalar::from(factor_seed);
                factor_seed += 1;

                let candidate =
                    repair_local_field(a, b, factor_b).map_err(|_| Error::RepairFailed)?;

                verify_homomorphic_repair(
                    kzg,
                    root,
                    AuthenticatedShard {
                        shard: a,
                        index: ia,
                        proof: &proofs[ia],
                    },
                    AuthenticatedShard {
                        shard: b,
                        index: ib,
                        proof: &proofs[ib],
                    },
                    factor_b,
                    &candidate,
                )
                .map_err(|_| Error::RepairFailed)?;

                let slot_pos = candidates.len();
                let target_slot = target_slots[slot_pos];
                let custodian = online_custodians[slot_pos % online_custodians.len()];
                let entry = RepairEntry {
                    repaired_slot: target_slot as u8,
                    parent_slot_a: ia as u8,
                    parent_slot_b: ib as u8,
                    factor_b: scalar_to_bytes(&factor_b),
                };
                candidates.push((target_slot, custodian, candidate, entry));
                if candidates.len() == needed {
                    break 'outer;
                }
            }
        }

        if candidates.len() != needed {
            return Err(Error::RepairFailed);
        }

        // 모든 후보 검증 완료 후 원자적 상태 반영 (Staging)
        let mut staged = self.clone();
        for (target_slot, custodian, shard, entry) in candidates {
            let slot = &mut staged.slots[target_slot];
            slot.generation = slot.generation.checked_add(1).ok_or(Error::Invalid)?;
            slot.shard = Some(shard);
            slot.custodian_slot = Some(custodian);
            repairs.push(entry);
        }
        *self = staged;
        Ok(repairs)
    }

    /// 에포크 종료 시 L1 Standby Pool에서 정식 교체 편입된 슬롯들의 임시 보관 상태를 해제한다.
    pub fn finalize_standby_replacements(&mut self, replaced_slots: &[usize]) {
        for &idx in replaced_slots {
            if let Some(slot) = self.slots.get_mut(idx) {
                slot.state = NodeState::Online;
                slot.custodian_slot = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use verkle_fountain::fountain::encode;

    const TEST_N: usize = 100;

    fn make_fsm_fixtures(
        seed: u64,
    ) -> (Vec<Shard>, Kzg, [u8; 48], Vec<[u8; 48]>) {
        let data = vec![0x6Au8; 4096];
        let shards = encode(&data, 30, TEST_N, seed).unwrap();
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let kzg = Kzg::setup(MAX_SWARM_SIZE - 1, &mut rng);
        let fps: Vec<Scalar> = shards.iter().map(|s| s.fingerprint()).collect();
        let root = kzg.commit(&fps).unwrap();
        let proofs: Vec<[u8; 48]> = (0..TEST_N).map(|i| kzg.open(&fps, i).unwrap()).collect();
        (shards, kzg, root, proofs)
    }

    #[test]
    fn fsm_rejects_invalid_thresholds_and_tracks_transient_return() {
        let (shards, _, _, _) = make_fsm_fixtures(11);
        assert!(matches!(
            LazyRepairFsm::new(shards.clone(), 30, 60),
            Err(Error::Invalid)
        ));
        assert!(matches!(
            LazyRepairFsm::new(shards.clone(), 60, 60),
            Err(Error::Invalid)
        ));
        assert!(matches!(
            LazyRepairFsm::new(shards.clone(), 45, 101),
            Err(Error::Invalid)
        ));

        assert!(matches!(
            LazyRepairFsm::new(shards[..MIN_SWARM_SIZE - 1].to_vec(), 5, 8),
            Err(Error::Invalid)
        ));

        let mut fsm = LazyRepairFsm::new(shards, 45, 60).unwrap();
        let gen0 = fsm.drop_node(0, Some(10)).unwrap();
        assert_eq!(gen0, 0);
        assert!(!fsm.return_node(0, gen0, 5).unwrap());
        assert!(matches!(
            fsm.slots[0].state,
            NodeState::TransientOffline { return_at: 10 }
        ));
        assert!(fsm.return_node(0, gen0, 10).unwrap());
        assert_eq!(fsm.slots[0].state, NodeState::Online);
    }

    #[test]
    fn fsm_repair_fails_when_online_rank_falls_below_k() {
        let (shards, kzg, root, proofs) = make_fsm_fixtures(22);
        let mut fsm = LazyRepairFsm::new(shards, 45, 60).unwrap();

        for i in 0..71 {
            fsm.drop_node(i, None).unwrap();
        }
        assert_eq!(fsm.active_shard_count(), 29);
        assert!(matches!(
            fsm.repair(&kzg, &root, &proofs),
            Err(Error::Unavailable)
        ));
    }

    #[test]
    fn fsm_custodian_keeps_repaired_shard_accessible_until_standby_finalized() {
        let (shards, kzg, root, proofs) = make_fsm_fixtures(33);
        let mut fsm = LazyRepairFsm::new(shards, 45, 60).unwrap();

        for i in 0..55 {
            fsm.drop_node(i, None).unwrap();
        }
        let repairs = fsm.repair(&kzg, &root, &proofs).unwrap();
        assert_eq!(repairs.len(), 15);
        assert_eq!(fsm.online_node_count(), 45);
        assert_eq!(fsm.active_shard_count(), 60);

        let replaced: Vec<usize> = repairs.iter().map(|r| r.repaired_slot as usize).collect();
        for &idx in &replaced {
            assert_eq!(fsm.slots[idx].state, NodeState::Dead);
            assert!(fsm.slots[idx].custodian_slot.is_some());
            assert!(fsm.is_slot_shard_accessible(idx));
        }

        fsm.finalize_standby_replacements(&replaced);
        for &idx in &replaced {
            assert_eq!(fsm.slots[idx].state, NodeState::Online);
            assert!(fsm.slots[idx].custodian_slot.is_none());
        }
        assert_eq!(fsm.online_node_count(), 60);
    }
}
