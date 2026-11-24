use crate::fountain::Shard;
use crate::verkle_kzg::{Kzg, KzgProof, KzgRoot, Scalar};
use crate::{Error, Result};
use ark_ff::AdditiveGroup;

pub struct AuthenticatedShard<'a> {
    pub shard: &'a Shard,
    pub index: usize,
    pub proof: &'a KzgProof,
}

/// F_p 소수체 동형 오염 공격(Pollution Attack) 탐지기.
/// 1) 부모 조각 A, B가 현재 온체인 KZG 루트(`root`)에 속한 정당한 지문임을 페어링 검증하고,
/// 2) 새로 합성된 `candidate`의 48B 점 커밋먼트가 `Commit(fp(A)) + factor_b * Commit(fp(B))`와 일치하는지
///    원본 파일 데이터 없이 O(1) 타원곡선 점 연산으로 검증한다.
pub fn verify_homomorphic_repair(
    kzg: &Kzg,
    root: &KzgRoot,
    auth_a: AuthenticatedShard<'_>,
    auth_b: AuthenticatedShard<'_>,
    factor_b: Scalar,
    candidate: &Shard,
) -> Result<()> {
    auth_a.shard.validate()?;
    auth_b.shard.validate()?;
    candidate.validate()?;

    if factor_b == Scalar::ZERO
        || auth_a.shard.object_id != auth_b.shard.object_id
        || auth_a.shard.object_id != candidate.object_id
        || auth_a.shard.k != auth_b.shard.k
        || auth_a.shard.k != candidate.k
        || auth_a.shard.original_len != auth_b.shard.original_len
        || auth_a.shard.original_len != candidate.original_len
        || auth_a.shard.symbols.len() != auth_b.shard.symbols.len()
        || auth_a.shard.symbols.len() != candidate.symbols.len()
    {
        return Err(Error::InvalidInput);
    }

    // 1. 부모 조각 A, B의 지문이 현재 KZG 매니페스트 루트에 정당하게 등록되어 있는지 검증
    let fp_a = auth_a.shard.fingerprint();
    let fp_b = auth_b.shard.fingerprint();
    kzg.verify(root, auth_a.index, fp_a, auth_a.proof)?;
    kzg.verify(root, auth_b.index, fp_b, auth_b.proof)?;

    // 2. 타원곡선 점 연산을 통한 O(1) 선형 동형성 검증:
    //    Commit(fp(candidate)) == Commit(fp(A)) + factor_b * Commit(fp(B))
    let c_a = kzg.commit_fingerprint(fp_a);
    let c_b = kzg.commit_fingerprint(fp_b);
    let expected_commit = kzg.combine_commitments(&c_a, &c_b, factor_b)?;
    let fp_cand = candidate.fingerprint();
    let actual_commit = kzg.commit_fingerprint(fp_cand);
    if actual_commit != expected_commit {
        return Err(Error::PollutionDetected);
    }

    // 3. 계수 마스크 선형 결합 일치 확인 (rank 추적 정합성 보장)
    let coeffs_match = auth_a
        .shard
        .coefficients
        .iter()
        .zip(&auth_b.shard.coefficients)
        .zip(&candidate.coefficients)
        .all(|((ca, cb), cc)| *cc == *ca + factor_b * *cb);
    if !coeffs_match {
        return Err(Error::PollutionDetected);
    }

    // 4. 심볼 벡터 전체의 F_p 선형 결합 정합성 대조 (공개 평가점 r에 대한 다항식 지문 충돌 공격 F01 차단)
    let symbols_match = auth_a
        .shard
        .symbols
        .iter()
        .zip(&auth_b.shard.symbols)
        .zip(&candidate.symbols)
        .all(|((sa, sb), sc)| *sc == *sa + factor_b * *sb);
    if !symbols_match {
        return Err(Error::PollutionDetected);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fountain::{encode, repair_local_field};
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn catches_polluted_repair_shard_while_accepting_valid_field_repair() {
        let mut rng = ChaCha8Rng::seed_from_u64(99);
        let kzg = Kzg::setup(99, &mut rng);
        let data = vec![42u8; 4096];
        let shards = encode(&data, 30, 100, 11).unwrap();

        let fps: Vec<Scalar> = shards.iter().map(|s| s.fingerprint()).collect();
        let root = kzg.commit(&fps).unwrap();
        let proof_a = kzg.open(&fps, 2).unwrap();
        let proof_b = kzg.open(&fps, 9).unwrap();

        let beta = Scalar::from(7u64);
        let mut repaired = repair_local_field(&shards[2], &shards[9], beta).unwrap();

        verify_homomorphic_repair(
            &kzg,
            &root,
            AuthenticatedShard {
                shard: &shards[2],
                index: 2,
                proof: &proof_a,
            },
            AuthenticatedShard {
                shard: &shards[9],
                index: 9,
                proof: &proof_b,
            },
            beta,
            &repaired,
        )
        .unwrap();

        // 악성 노드가 심볼 1개에 쓰레기 데이터(+1)를 섞는 오염 공격(Pollution Attack) 시뮬레이션
        repaired.symbols[0] += Scalar::from(1u64);
        let err = verify_homomorphic_repair(
            &kzg,
            &root,
            AuthenticatedShard {
                shard: &shards[2],
                index: 2,
                proof: &proof_a,
            },
            AuthenticatedShard {
                shard: &shards[9],
                index: 9,
                proof: &proof_b,
            },
            beta,
            &repaired,
        )
        .unwrap_err();
        assert!(matches!(err, Error::PollutionDetected));
    }

    #[test]
    fn rejects_mismatched_coefficients_even_if_symbols_untouched() {
        let mut rng = ChaCha8Rng::seed_from_u64(123);
        let kzg = Kzg::setup(99, &mut rng);
        let data = vec![77u8; 4096];
        let shards = encode(&data, 30, 100, 15).unwrap();

        let fps: Vec<Scalar> = shards.iter().map(|s| s.fingerprint()).collect();
        let root = kzg.commit(&fps).unwrap();
        let proof_a = kzg.open(&fps, 1).unwrap();
        let proof_b = kzg.open(&fps, 8).unwrap();

        let beta = Scalar::from(5u64);
        let mut repaired = repair_local_field(&shards[1], &shards[8], beta).unwrap();
        // 심볼은 정상 유지한 채 선형 계수 벡터만 변조 -> PollutionDetected 거부
        repaired.coefficients[0] += Scalar::from(1u64);

        let err = verify_homomorphic_repair(
            &kzg,
            &root,
            AuthenticatedShard {
                shard: &shards[1],
                index: 1,
                proof: &proof_a,
            },
            AuthenticatedShard {
                shard: &shards[8],
                index: 8,
                proof: &proof_b,
            },
            beta,
            &repaired,
        )
        .unwrap_err();
        assert!(matches!(err, Error::PollutionDetected));
    }

    #[test]
    fn rejects_zero_factor_or_forged_parent_kzg_proof() {
        let mut rng = ChaCha8Rng::seed_from_u64(321);
        let kzg = Kzg::setup(99, &mut rng);
        let data = vec![55u8; 4096];
        let shards = encode(&data, 30, 100, 21).unwrap();

        let fps: Vec<Scalar> = shards.iter().map(|s| s.fingerprint()).collect();
        let root = kzg.commit(&fps).unwrap();
        let proof_a = kzg.open(&fps, 2).unwrap();
        let proof_other = kzg.open(&fps, 15).unwrap();
        let beta = Scalar::from(4u64);
        let repaired = repair_local_field(&shards[2], &shards[9], beta).unwrap();

        // factor_b == 0 거부
        let err_zero = verify_homomorphic_repair(
            &kzg,
            &root,
            AuthenticatedShard {
                shard: &shards[2],
                index: 2,
                proof: &proof_a,
            },
            AuthenticatedShard {
                shard: &shards[9],
                index: 9,
                proof: &proof_other,
            },
            Scalar::from(0u64),
            &repaired,
        )
        .unwrap_err();
        assert!(matches!(err_zero, Error::InvalidInput));

        // 다른 슬롯(15)의 KZG 증명을 9번 조각 증명으로 제출 -> CryptoFailure
        let err_proof = verify_homomorphic_repair(
            &kzg,
            &root,
            AuthenticatedShard {
                shard: &shards[2],
                index: 2,
                proof: &proof_a,
            },
            AuthenticatedShard {
                shard: &shards[9],
                index: 9,
                proof: &proof_other,
            },
            beta,
            &repaired,
        )
        .unwrap_err();
        assert!(matches!(err_proof, Error::CryptoFailure));
    }

    #[test]
    fn rejects_fingerprint_collision_payload_tampering() {
        let mut rng = ChaCha8Rng::seed_from_u64(4242);
        let kzg = Kzg::setup(99, &mut rng);
        let data = vec![63u8; 4096];
        let shards = encode(&data, 30, 100, 33).unwrap();

        let fps: Vec<Scalar> = shards.iter().map(|s| s.fingerprint()).collect();
        let root = kzg.commit(&fps).unwrap();
        let proof_a = kzg.open(&fps, 3).unwrap();
        let proof_b = kzg.open(&fps, 11).unwrap();

        let beta = Scalar::from(9u64);
        let mut forged = repair_local_field(&shards[3], &shards[11], beta).unwrap();
        let honest_fp = forged.fingerprint();

        // 공개 평가점 r에 대해 sum(delta_j * r^{j+1}) == 0이 되도록 심볼을 변조해 지문 충돌 유도
        let r = crate::verkle_kzg::evaluation_point(&forged.object_id);
        forged.symbols[0] += r;
        forged.symbols[1] -= Scalar::from(1u64);
        assert_eq!(forged.fingerprint(), honest_fp);

        let err = verify_homomorphic_repair(
            &kzg,
            &root,
            AuthenticatedShard {
                shard: &shards[3],
                index: 3,
                proof: &proof_a,
            },
            AuthenticatedShard {
                shard: &shards[11],
                index: 11,
                proof: &proof_b,
            },
            beta,
            &forged,
        )
        .unwrap_err();
        assert!(matches!(err, Error::PollutionDetected));
    }
}
