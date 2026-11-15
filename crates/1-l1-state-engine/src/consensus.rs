use crate::executor::{ExecutionReceipt, Executor};
use crate::state_db::NativeTransaction;
use crate::{Error, Result};
use p256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use verkle_fountain::verkle_kzg::Kzg;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VotePhase {
    Prevote,
    Precommit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorInfo {
    pub id: u64,
    pub pubkey_p256: [u8; 33],
    pub voting_power: u64,
}

#[derive(Clone, Debug)]
pub struct ValidatorSigner {
    pub id: u64,
    pub voting_power: u64,
    pub signing_key: SigningKey,
}

impl ValidatorSigner {
    pub fn new(id: u64, voting_power: u64, signing_key: SigningKey) -> Self {
        Self {
            id,
            voting_power,
            signing_key,
        }
    }

    pub fn info(&self) -> ValidatorInfo {
        let pk: [u8; 33] = self
            .signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("compressed SEC1 key");
        ValidatorInfo {
            id: self.id,
            pubkey_p256: pk,
            voting_power: self.voting_power,
        }
    }

    pub fn sign_vote(&self, height: u64, block_hash: [u8; 32], phase: VotePhase) -> Vote {
        let msg = vote_signing_bytes(height, &block_hash, phase, self.id);
        let sig: Signature = self.signing_key.sign(&msg);
        Vote {
            height,
            block_hash,
            phase,
            validator_id: self.id,
            signature: sig.to_bytes().into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vote {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub phase: VotePhase,
    pub validator_id: u64,
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    pub height: u64,
    pub prev_hash: [u8; 32],
    pub epoch_seed: [u8; 32],
    pub proposer_id: u64,
    pub tx_count: usize,
    pub state_root: [u8; 32],
}

impl BlockHeader {
    pub fn block_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"depin/block-header/v1");
        h.update(self.height.to_le_bytes());
        h.update(self.prev_hash);
        h.update(self.epoch_seed);
        h.update(self.proposer_id.to_le_bytes());
        h.update((self.tx_count as u64).to_le_bytes());
        h.update(self.state_root);
        h.finalize().into()
    }
}

#[derive(Clone, Debug)]
pub struct FinalizedBlock {
    pub header: BlockHeader,
    pub block_hash: [u8; 32],
    pub receipts: Vec<ExecutionReceipt>,
    pub precommits: Vec<Vote>,
}

pub fn vote_signing_bytes(
    height: u64,
    block_hash: &[u8; 32],
    phase: VotePhase,
    validator_id: u64,
) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"depin/bft-vote/v1");
    h.update(height.to_le_bytes());
    h.update(block_hash);
    h.update([match phase {
        VotePhase::Prevote => 1,
        VotePhase::Precommit => 2,
    }]);
    h.update(validator_id.to_le_bytes());
    h.finalize().to_vec()
}

/// Executor의 결정론적 상태 커밋먼트(State Root) 계산
pub fn compute_state_root(executor: &Executor) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"depin/state-root/v1");
    for (swarm_id, sw) in &executor.db.swarms {
        h.update(swarm_id.to_le_bytes());
        h.update(sw.member_verkle_root);
        h.update(sw.active_blobs_root);
        h.update(sw.total_bond_balance.to_le_bytes());
        h.update(sw.storage_bounty_pool.to_le_bytes());
        h.update(sw.last_epoch_settled.to_le_bytes());
    }
    for (pk, acc) in &executor.db.nodes {
        h.update(pk);
        h.update(acc.stake.to_le_bytes());
        h.update(acc.reward_balance.to_le_bytes());
        h.update(acc.consecutive_offline_epochs.to_le_bytes());
        h.update([u8::from(acc.slashed)]);
    }
    h.finalize().into()
}

/// 상시 가동 검증자 집합의 2/3 초과 BFT 합의를 수행하는 순수 Rust 경량 합의 엔진
#[derive(Clone, Debug)]
pub struct BftEngine {
    pub validators: Vec<ValidatorInfo>,
    pub height: u64,
    pub last_block_hash: [u8; 32],
    pub chain: Vec<FinalizedBlock>,
}

impl BftEngine {
    pub fn new(validators: Vec<ValidatorInfo>) -> Result<Self> {
        if validators.is_empty() {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            validators,
            height: 0,
            last_block_hash: [0u8; 32],
            chain: Vec::new(),
        })
    }

    pub fn total_voting_power(&self) -> u64 {
        self.validators.iter().map(|v| v.voting_power).sum()
    }

    /// 온라인 검증자 서명자들의 Prevote/Precommit 투표를 집계해 >2/3 정족수 달성 시 블록과 상태 전이를 확정한다.
    pub fn propose_and_finalize(
        &mut self,
        executor: &mut Executor,
        kzg: &Kzg,
        proposer_id: u64,
        txs: Vec<NativeTransaction>,
        epoch_seed: [u8; 32],
        online_signers: &[&ValidatorSigner],
    ) -> Result<FinalizedBlock> {
        if !self.validators.iter().any(|v| v.id == proposer_id) {
            return Err(Error::Unauthorized);
        }

        // 1. 실행 엔진 복제본에서 트랜잭션들을 먼저 결정론적으로 실행
        let mut staged_exec = executor.clone();
        let mut receipts = Vec::with_capacity(txs.len());
        for tx in txs {
            receipts.push(staged_exec.execute(tx, kzg, &epoch_seed)?);
        }

        let next_height = self.height + 1;
        let state_root = compute_state_root(&staged_exec);
        let header = BlockHeader {
            height: next_height,
            prev_hash: self.last_block_hash,
            epoch_seed,
            proposer_id,
            tx_count: receipts.len(),
            state_root,
        };
        let block_hash = header.block_hash();

        // 2. Prevote & Precommit 단계 투표 생성 및 >2/3 정족수 서명 검증
        let prevotes: Vec<Vote> = online_signers
            .iter()
            .map(|s| s.sign_vote(next_height, block_hash, VotePhase::Prevote))
            .collect();
        self.verify_quorum(&prevotes, next_height, &block_hash, VotePhase::Prevote)?;

        let precommits: Vec<Vote> = online_signers
            .iter()
            .map(|s| s.sign_vote(next_height, block_hash, VotePhase::Precommit))
            .collect();
        self.verify_quorum(&precommits, next_height, &block_hash, VotePhase::Precommit)?;

        // 3. 정족수 달성 시 원자적 커밋
        *executor = staged_exec;
        self.height = next_height;
        self.last_block_hash = block_hash;
        let finalized = FinalizedBlock {
            header,
            block_hash,
            receipts,
            precommits,
        };
        self.chain.push(finalized.clone());
        Ok(finalized)
    }

    pub fn verify_quorum(
        &self,
        votes: &[Vote],
        height: u64,
        block_hash: &[u8; 32],
        phase: VotePhase,
    ) -> Result<u64> {
        let mut seen = BTreeSet::new();
        let mut power = 0u64;
        for vote in votes {
            if vote.height != height || &vote.block_hash != block_hash || vote.phase != phase {
                continue;
            }
            if !seen.insert(vote.validator_id) {
                continue;
            }
            let Some(val) = self.validators.iter().find(|v| v.id == vote.validator_id) else {
                continue;
            };
            let vk = VerifyingKey::from_sec1_bytes(&val.pubkey_p256)
                .map_err(|_| Error::BadSignature)?;
            let sig = Signature::from_slice(&vote.signature).map_err(|_| Error::BadSignature)?;
            let msg = vote_signing_bytes(height, block_hash, phase, vote.validator_id);
            if vk.verify(&msg, &sig).is_ok() {
                power += val.voting_power;
            }
        }

        let total = self.total_voting_power();
        if power * 3 > total * 2 {
            Ok(power)
        } else {
            Err(Error::ConsensusFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::ExecutorConfig;
    use rand::rngs::OsRng;

    #[test]
    fn bft_requires_more_than_two_thirds_quorum() {
        let signers: Vec<ValidatorSigner> = (0..4)
            .map(|id| ValidatorSigner::new(id, 1, SigningKey::random(&mut OsRng)))
            .collect();
        let infos: Vec<ValidatorInfo> = signers.iter().map(|s| s.info()).collect();
        let mut bft = BftEngine::new(infos).unwrap();
        let mut exec = Executor::new(ExecutorConfig::default());
        let kzg = Kzg::setup(4, &mut OsRng);

        // 4명 중 2명(2/4 <= 2/3)만 온라인이면 합의 실패해야 함
        let err = bft
            .propose_and_finalize(&mut exec, &kzg, 0, vec![], [1u8; 32], &[&signers[0], &signers[1]])
            .unwrap_err();
        assert!(matches!(err, Error::ConsensusFailed));
        assert_eq!(bft.height, 0);

        // 4명 중 3명(3/4 > 2/3)이 서명하면 블록 확정
        let block = bft
            .propose_and_finalize(
                &mut exec,
                &kzg,
                0,
                vec![],
                [1u8; 32],
                &[&signers[0], &signers[1], &signers[2]],
            )
            .unwrap();
        assert_eq!(block.header.height, 1);
        assert_eq!(bft.height, 1);
    }

    #[test]
    fn bft_rejects_empty_validator_set_and_unregistered_proposer() {
        assert!(matches!(BftEngine::new(vec![]), Err(Error::InvalidInput)));

        let signers: Vec<ValidatorSigner> = (0..4)
            .map(|id| ValidatorSigner::new(id, 1, SigningKey::random(&mut OsRng)))
            .collect();
        let infos: Vec<ValidatorInfo> = signers.iter().map(|s| s.info()).collect();
        let mut bft = BftEngine::new(infos).unwrap();
        let mut exec = Executor::new(ExecutorConfig::default());
        let kzg = Kzg::setup(4, &mut OsRng);

        let err = bft
            .propose_and_finalize(
                &mut exec,
                &kzg,
                99,
                vec![],
                [1u8; 32],
                &[&signers[0], &signers[1], &signers[2]],
            )
            .unwrap_err();
        assert!(matches!(err, Error::Unauthorized));
    }

    #[test]
    fn bft_ignores_duplicate_votes_wrong_phase_and_bad_signatures() {
        let signers: Vec<ValidatorSigner> = (0..4)
            .map(|id| ValidatorSigner::new(id, 1, SigningKey::random(&mut OsRng)))
            .collect();
        let infos: Vec<ValidatorInfo> = signers.iter().map(|s| s.info()).collect();
        let bft = BftEngine::new(infos).unwrap();
        let hash = [0x42u8; 32];

        // 1. 동일 검증자 중복 투표 3개는 투표력 1만 인정 -> 정족수(>2/3) 미달
        let dup_votes = vec![
            signers[0].sign_vote(1, hash, VotePhase::Prevote),
            signers[0].sign_vote(1, hash, VotePhase::Prevote),
            signers[0].sign_vote(1, hash, VotePhase::Prevote),
        ];
        assert!(matches!(
            bft.verify_quorum(&dup_votes, 1, &hash, VotePhase::Prevote),
            Err(Error::ConsensusFailed)
        ));

        // 2. 다른 VotePhase(Precommit) 투표는 Prevote 정족수에 합산되지 않음
        let wrong_phase_votes = vec![
            signers[0].sign_vote(1, hash, VotePhase::Precommit),
            signers[1].sign_vote(1, hash, VotePhase::Precommit),
            signers[2].sign_vote(1, hash, VotePhase::Precommit),
        ];
        assert!(matches!(
            bft.verify_quorum(&wrong_phase_votes, 1, &hash, VotePhase::Prevote),
            Err(Error::ConsensusFailed)
        ));

        // 3. 다른 키로 위조 서명된 투표(유효하지 않은 서명자)는 무시되어 정족수 미달
        let mut forged = signers[1].sign_vote(1, hash, VotePhase::Prevote);
        forged.validator_id = 0; // signer[0] 명의 도용
        let votes_with_forgery = vec![
            forged,
            signers[1].sign_vote(1, hash, VotePhase::Prevote),
            signers[2].sign_vote(1, hash, VotePhase::Prevote),
        ];
        assert!(matches!(
            bft.verify_quorum(&votes_with_forgery, 1, &hash, VotePhase::Prevote),
            Err(Error::ConsensusFailed)
        ));

        // 4. 구조 자체가 깨진 서명(영바이트)은 BadSignature 반환
        let malformed = Vote {
            height: 1,
            block_hash: hash,
            phase: VotePhase::Prevote,
            validator_id: 0,
            signature: [0u8; 64],
        };
        assert!(matches!(
            bft.verify_quorum(&[malformed], 1, &hash, VotePhase::Prevote),
            Err(Error::BadSignature)
        ));
    }
}
