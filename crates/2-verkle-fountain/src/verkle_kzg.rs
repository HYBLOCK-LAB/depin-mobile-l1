use crate::{Error, Result};
use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// BLS12-381 스칼라 필드 원소 (F_p, p ≈ 2^255)
pub type Scalar = Fr;
/// 압축된 BLS12-381 G1 커밋먼트 루트 (48 Bytes)
pub type KzgRoot = [u8; 48];
/// 압축된 BLS12-381 G1 오프닝 증명 (48 Bytes)
pub type KzgProof = [u8; 48];

pub fn g1_to_bytes(point: &G1Affine) -> KzgRoot {
    let mut out = [0u8; 48];
    point
        .serialize_compressed(&mut out[..])
        .expect("compressed G1Affine must fit in 48 bytes");
    out
}

pub fn bytes_to_g1(bytes: &KzgRoot) -> Result<G1Affine> {
    G1Affine::deserialize_compressed(&bytes[..]).map_err(|_| Error::CryptoFailure)
}

pub fn scalar_to_bytes(s: &Scalar) -> [u8; 32] {
    let mut out = [0u8; 32];
    let le = s.into_bigint().to_bytes_le();
    out.copy_from_slice(&le[..32]);
    out
}

pub fn bytes_to_scalar(bytes: &[u8; 32]) -> Result<Scalar> {
    Scalar::deserialize_compressed(&bytes[..]).map_err(|_| Error::CryptoFailure)
}

/// 파일 식별자(object_id)로부터 1단계 선형 동형 지문 평가점 r ∈ F_p를 결정론적으로 도출한다.
pub fn evaluation_point(object_id: &[u8; 32]) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(b"depin/fp-eval-point/v1");
    hasher.update(object_id);
    digest_to_scalar(&hasher.finalize())
}

/// 해시 다이제스트를 0이 아닌 F_p 원소로 축약한다.
pub fn digest_to_scalar(digest: &[u8]) -> Scalar {
    let r = Scalar::from_le_bytes_mod_order(digest);
    if r == Scalar::ZERO {
        Scalar::ONE
    } else {
        r
    }
}

/// G1 항등원의 압축 직렬화 (결합 계산의 시작점)
pub fn identity_root() -> KzgRoot {
    g1_to_bytes(&G1Affine::zero())
}

/// 1단계 선형 동형 지문: fp(S) = sum_{j=0}^{m-1} symbols[j] * r^{j+1} mod p.
/// 선형성에 의해 fp(S_A + beta * S_B) == fp(S_A) + beta * fp(S_B)가 항상 성립한다.
pub fn linear_fingerprint(symbols: &[Scalar], r: Scalar) -> Scalar {
    let mut acc = Scalar::ZERO;
    for s in symbols.iter().rev() {
        acc = (acc + *s) * r;
    }
    acc
}

/// 도메인 {0, 1, ..., n-1} 위에서 값 벡터 `values`를 지나는 차수 < n 다항식의 계수(상수항부터)를 보간한다.
pub fn interpolate(values: &[Scalar]) -> Result<Vec<Scalar>> {
    let n = values.len();
    if n == 0 {
        return Err(Error::InvalidInput);
    }
    // 뉴턴 차분상 테이블 계산 (x_i = i 이므로 분모 x_i - x_{i-j} = j)
    let mut dd = values.to_vec();
    for j in 1..n {
        let denom_inv = Scalar::from(j as u64)
            .inverse()
            .ok_or(Error::CryptoFailure)?;
        for i in (j..n).rev() {
            dd[i] = (dd[i] - dd[i - 1]) * denom_inv;
        }
    }

    // 뉴턴 다항식을 단항식 기저(monomial basis) 계수로 전개
    let mut coeffs = Vec::with_capacity(n);
    coeffs.push(dd[n - 1]);
    for k in (0..n - 1).rev() {
        let x_k = Scalar::from(k as u64);
        let prev_len = coeffs.len();
        coeffs.push(Scalar::ZERO);
        for i in (1..=prev_len).rev() {
            coeffs[i] = coeffs[i - 1] - coeffs[i] * x_k;
        }
        coeffs[0] = dd[k] - coeffs[0] * x_k;
    }
    Ok(coeffs)
}

#[derive(Clone, Debug)]
pub struct Kzg {
    pub powers_g1: Vec<G1Affine>,
    pub g2_gen: G2Affine,
    pub g2_tau: G2Affine,
}

impl Kzg {
    /// 테스트/프로토타입용 SRS 생성 (실운영 배포 시 다자 세레머니 공개 SRS로 교체 필요)
    pub fn setup(max_degree: usize, rng: &mut impl RngCore) -> Self {
        let tau = loop {
            let mut buf = [0u8; 32];
            rng.fill_bytes(&mut buf);
            let candidate = Scalar::from_le_bytes_mod_order(&buf);
            if candidate != Scalar::ZERO {
                break candidate;
            }
        };

        let g1 = G1Projective::from(G1Affine::generator());
        let g2 = G2Projective::from(G2Affine::generator());

        let mut powers_proj = Vec::with_capacity(max_degree + 1);
        let mut cur = Scalar::ONE;
        for _ in 0..=max_degree {
            powers_proj.push(g1 * cur);
            cur *= tau;
        }
        let powers_g1 = G1Projective::normalize_batch(&powers_proj);
        let g2_gen = G2Affine::generator();
        let g2_tau = (g2 * tau).into_affine();

        Self {
            powers_g1,
            g2_gen,
            g2_tau,
        }
    }

    /// KZG SRS를 디스크 저장용 압축 바이너리로 직렬화한다.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        (self.powers_g1.len() as u64)
            .serialize_compressed(&mut out)
            .map_err(|_| Error::CryptoFailure)?;
        for p in &self.powers_g1 {
            p.serialize_compressed(&mut out)
                .map_err(|_| Error::CryptoFailure)?;
        }
        self.g2_gen
            .serialize_compressed(&mut out)
            .map_err(|_| Error::CryptoFailure)?;
        self.g2_tau
            .serialize_compressed(&mut out)
            .map_err(|_| Error::CryptoFailure)?;
        Ok(out)
    }

    /// 직렬화된 바이트로부터 KZG SRS를 복원한다.
    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self> {
        let len = u64::deserialize_compressed(&mut bytes).map_err(|_| Error::CryptoFailure)? as usize;
        let mut powers_g1 = Vec::with_capacity(len);
        for _ in 0..len {
            powers_g1.push(
                G1Affine::deserialize_compressed(&mut bytes).map_err(|_| Error::CryptoFailure)?,
            );
        }
        let g2_gen =
            G2Affine::deserialize_compressed(&mut bytes).map_err(|_| Error::CryptoFailure)?;
        let g2_tau =
            G2Affine::deserialize_compressed(&mut bytes).map_err(|_| Error::CryptoFailure)?;
        Ok(Self {
            powers_g1,
            g2_gen,
            g2_tau,
        })
    }

    /// 다항식 계수 벡터 [c_0, c_1, ..., c_d]에 대한 KZG 커밋먼트 [P(tau)]G1 반환
    pub fn commit_coeffs(&self, coeffs: &[Scalar]) -> Result<KzgRoot> {
        if coeffs.is_empty() || coeffs.len() > self.powers_g1.len() {
            return Err(Error::InvalidInput);
        }
        let proj = G1Projective::msm(&self.powers_g1[..coeffs.len()], coeffs)
            .map_err(|_| Error::CryptoFailure)?;
        Ok(g1_to_bytes(&proj.into_affine()))
    }

    /// 100개 슬롯 지문 벡터 `values`에 대한 48B Verkle/KZG 루트 생성
    pub fn commit(&self, values: &[Scalar]) -> Result<KzgRoot> {
        let coeffs = interpolate(values)?;
        self.commit_coeffs(&coeffs)
    }

    /// 특정 슬롯 `index`에 대한 48B KZG 몫 다항식 증명 생성: pi = [(P(tau) - P(index)) / (tau - index)]G1
    pub fn open(&self, values: &[Scalar], index: usize) -> Result<KzgProof> {
        if index >= values.len() || values.len() > self.powers_g1.len() {
            return Err(Error::InvalidInput);
        }
        let mut p = interpolate(values)?;
        let z = Scalar::from(index as u64);
        p[0] -= values[index];

        let n = p.len();
        if n <= 1 {
            return Ok(g1_to_bytes(&G1Affine::zero()));
        }
        let mut q = vec![Scalar::ZERO; n - 1];
        let mut rem = p[n - 1];
        q[n - 2] = rem;
        for i in (1..n - 1).rev() {
            rem = p[i] + rem * z;
            q[i - 1] = rem;
        }
        self.commit_coeffs(&q)
    }

    /// 도메인 {0, 1, ..., values.len()-1} 전체 슬롯에 대한 KZG 몫 다항식 증명을 단일 보간으로 일괄 생성한다.
    pub fn open_all(&self, values: &[Scalar]) -> Result<Vec<KzgProof>> {
        if values.is_empty() || values.len() > self.powers_g1.len() {
            return Err(Error::InvalidInput);
        }
        let p = interpolate(values)?;
        let n = p.len();
        if n <= 1 {
            return Ok(vec![g1_to_bytes(&G1Affine::zero()); values.len()]);
        }
        let mut proofs = Vec::with_capacity(values.len());
        let mut q = vec![Scalar::ZERO; n - 1];
        for index in 0..values.len() {
            let z = Scalar::from(index as u64);
            let mut rem = p[n - 1];
            q[n - 2] = rem;
            for i in (1..n - 1).rev() {
                rem = p[i] + rem * z;
                q[i - 1] = rem;
            }
            proofs.push(self.commit_coeffs(&q)?);
        }
        Ok(proofs)
    }

    /// 페어링 등식 검증: e(C - [value]G1, G2) == e(proof, [tau]G2 - [index]G2)
    pub fn verify(
        &self,
        root: &KzgRoot,
        index: usize,
        value: Scalar,
        proof: &KzgProof,
    ) -> Result<()> {
        if index >= self.powers_g1.len() {
            return Err(Error::InvalidInput);
        }
        let c = bytes_to_g1(root)?;
        let pi = bytes_to_g1(proof)?;
        let z = Scalar::from(index as u64);

        let lhs_g1 = (c.into_group() - (self.powers_g1[0].into_group() * value)).into_affine();
        let rhs_g2 = (self.g2_tau.into_group() - (self.g2_gen.into_group() * z)).into_affine();

        let pairing_out = Bls12_381::multi_pairing([lhs_g1, -pi], [self.g2_gen, rhs_g2]);
        if pairing_out.is_zero() {
            Ok(())
        } else {
            Err(Error::CryptoFailure)
        }
    }

    /// 단일 선형 동형 지문 스칼라에 대한 48B G1 점 커밋먼트 생성: Commit(fp) = [fp]G1
    pub fn commit_fingerprint(&self, fp: Scalar) -> KzgRoot {
        let pt = (self.powers_g1[0].into_group() * fp).into_affine();
        g1_to_bytes(&pt)
    }

    /// 48B 타원곡선 점 수준에서의 동형 선형 결합 계산: C_A + factor_b * C_B
    pub fn combine_commitments(
        &self,
        commit_a: &KzgRoot,
        commit_b: &KzgRoot,
        factor_b: Scalar,
    ) -> Result<KzgRoot> {
        let a = bytes_to_g1(commit_a)?;
        let b = bytes_to_g1(commit_b)?;
        let combined = (a.into_group() + (b.into_group() * factor_b)).into_affine();
        Ok(g1_to_bytes(&combined))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn kzg_commit_open_verify_and_homomorphism() {
        let mut rng = ChaCha8Rng::seed_from_u64(1234);
        let kzg = Kzg::setup(99, &mut rng);

        let values: Vec<Scalar> = (0..100).map(|i| Scalar::from((i * 17 + 5) as u64)).collect();
        let root = kzg.commit(&values).unwrap();

        for idx in [0, 7, 45, 99] {
            let proof = kzg.open(&values, idx).unwrap();
            kzg.verify(&root, idx, values[idx], &proof).unwrap();

            // 잘못된 값이나 인덱스 위조는 실패해야 함
            let wrong = values[idx] + Scalar::ONE;
            assert!(kzg.verify(&root, idx, wrong, &proof).is_err());
        }

        let all_proofs = kzg.open_all(&values).unwrap();
        assert_eq!(all_proofs.len(), values.len());
        for idx in [0, 7, 45, 99] {
            assert_eq!(all_proofs[idx], kzg.open(&values, idx).unwrap());
        }

        // 1단계 동형 지문 + 2단계 점 덧셈 동형성 일치 검증
        let r = evaluation_point(&[7u8; 32]);
        let s_a = vec![Scalar::from(11u64), Scalar::from(22u64), Scalar::from(33u64)];
        let s_b = vec![Scalar::from(44u64), Scalar::from(55u64), Scalar::from(66u64)];
        let beta = Scalar::from(3u64);
        let s_new: Vec<Scalar> = s_a.iter().zip(&s_b).map(|(a, b)| *a + beta * *b).collect();

        let fp_a = linear_fingerprint(&s_a, r);
        let fp_b = linear_fingerprint(&s_b, r);
        let fp_new = linear_fingerprint(&s_new, r);
        assert_eq!(fp_new, fp_a + beta * fp_b);

        let c_a = kzg.commit_fingerprint(fp_a);
        let c_b = kzg.commit_fingerprint(fp_b);
        let c_new = kzg.commit_fingerprint(fp_new);
        let c_expected = kzg.combine_commitments(&c_a, &c_b, beta).unwrap();
        assert_eq!(c_new, c_expected);
    }

    #[test]
    fn kzg_commit_is_linear_over_value_vectors() {
        let mut rng = ChaCha8Rng::seed_from_u64(77);
        let kzg = Kzg::setup(15, &mut rng);
        let v1: Vec<Scalar> = (0..16).map(|i| Scalar::from((i * 13 + 2) as u64)).collect();
        let v2: Vec<Scalar> = (0..16).map(|i| Scalar::from((i * 29 + 9) as u64)).collect();
        let l1 = digest_to_scalar(&[3u8; 32]);
        let l2 = digest_to_scalar(&[5u8; 32]);

        let mixed: Vec<Scalar> = v1.iter().zip(&v2).map(|(a, b)| l1 * *a + l2 * *b).collect();
        let scaled_first = kzg
            .combine_commitments(&identity_root(), &kzg.commit(&v1).unwrap(), l1)
            .unwrap();
        let aggregate = kzg
            .combine_commitments(&scaled_first, &kzg.commit(&v2).unwrap(), l2)
            .unwrap();
        assert_eq!(kzg.commit(&mixed).unwrap(), aggregate);
    }

    #[test]
    fn kzg_srs_serialization_roundtrip_and_corrupted_bytes_error() {
        let mut rng = ChaCha8Rng::seed_from_u64(555);
        let kzg = Kzg::setup(31, &mut rng);
        let bytes = kzg.to_bytes().unwrap();
        let restored = Kzg::from_bytes(&bytes).unwrap();

        let values: Vec<Scalar> = (0..32).map(|i| Scalar::from((i * 11 + 3) as u64)).collect();
        let root_orig = kzg.commit(&values).unwrap();
        let root_restored = restored.commit(&values).unwrap();
        assert_eq!(root_orig, root_restored);

        let proof = restored.open(&values, 17).unwrap();
        kzg.verify(&root_orig, 17, values[17], &proof).unwrap();

        assert!(matches!(
            Kzg::from_bytes(&bytes[..10]),
            Err(Error::CryptoFailure)
        ));
    }

    #[test]
    fn scalar_and_g1_serialization_roundtrip_and_bounds() {
        let s = Scalar::from(987_654_321u64);
        let s_bytes = scalar_to_bytes(&s);
        assert_eq!(bytes_to_scalar(&s_bytes).unwrap(), s);

        let pt = G1Affine::generator();
        let pt_bytes = g1_to_bytes(&pt);
        assert_eq!(bytes_to_g1(&pt_bytes).unwrap(), pt);

        let mut rng = ChaCha8Rng::seed_from_u64(88);
        let kzg = Kzg::setup(7, &mut rng);
        let values: Vec<Scalar> = (0..8).map(Scalar::from).collect();
        let root = kzg.commit(&values).unwrap();
        let proof = kzg.open(&values, 0).unwrap();

        assert!(matches!(
            kzg.open(&values, values.len()),
            Err(Error::InvalidInput)
        ));
        assert!(matches!(
            kzg.verify(&root, kzg.powers_g1.len(), values[0], &proof),
            Err(Error::InvalidInput)
        ));
    }
}
