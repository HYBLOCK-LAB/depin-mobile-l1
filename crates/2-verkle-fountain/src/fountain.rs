use crate::verkle_kzg::{evaluation_point, linear_fingerprint, Scalar};
use crate::{Error, Result};
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use sha2::{Digest, Sha256};

/// BLS12-381 Fr 스칼라(254+ bit)에 오버플로우 없이 무손실 매핑되는 바이트 청크 크기
pub const BYTES_PER_SCALAR: usize = 31;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shard {
    pub object_id: [u8; 32],
    pub k: usize,
    pub original_len: usize,
    /// 원본 k개 소스 블록에 대한 F_p 선형 결합 계수 벡터 (길이 = k)
    pub coefficients: Vec<Scalar>,
    /// F_p 스칼라 원소들의 배열로 표현된 인코딩 데이터 조각
    pub symbols: Vec<Scalar>,
}

impl Shard {
    pub fn validate(&self) -> Result<()> {
        if self.k == 0
            || self.coefficients.len() != self.k
            || self.symbols.is_empty()
            || self.coefficients.iter().all(|c| *c == Scalar::ZERO)
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }

    /// 이 조각의 1단계 선형 동형 지문 (fp(S) ∈ F_p) 계산
    pub fn fingerprint(&self) -> Scalar {
        let r = evaluation_point(&self.object_id);
        linear_fingerprint(&self.symbols, r)
    }

    /// 조각의 바이트 크기 추정치 (인코딩 심볼 수 * 32B)
    pub fn payload_bytes(&self) -> usize {
        self.symbols.len() * 32
    }
}

/// 임의 바이트 슬라이스를 31바이트 단위 Fr 스칼라 벡터로 무손실 변환한다.
fn pack_source_matrix(data: &[u8], k: usize) -> (Vec<Vec<Scalar>>, usize) {
    let total_raw_scalars = data.len().div_ceil(BYTES_PER_SCALAR).max(1);
    let symbols_per_shard = total_raw_scalars.div_ceil(k);
    let total_scalars = symbols_per_shard * k;

    let mut flat = Vec::with_capacity(total_scalars);
    for chunk in data.chunks(BYTES_PER_SCALAR) {
        let mut buf = [0u8; 32];
        buf[..chunk.len()].copy_from_slice(chunk);
        flat.push(Scalar::from_le_bytes_mod_order(&buf));
    }
    flat.resize(total_scalars, Scalar::ZERO);

    let matrix: Vec<Vec<Scalar>> = flat
        .chunks_exact(symbols_per_shard)
        .map(|slice| slice.to_vec())
        .collect();
    (matrix, symbols_per_shard)
}

/// 원본 바이트 데이터를 k개 소스 조각 + (n-k)개 F_p 선형 결합 패리티 조각으로 분할 인코딩한다.
pub fn encode(data: &[u8], k: usize, n: usize, seed: u64) -> Result<Vec<Shard>> {
    if k == 0 || n < k {
        return Err(Error::InvalidInput);
    }
    let object_id: [u8; 32] = Sha256::digest(data).into();
    let (source_rows, sym_len) = pack_source_matrix(data, k);
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut shards = Vec::with_capacity(n);

    for slot in 0..n {
        let mut coefficients = vec![Scalar::ZERO; k];
        let mut symbols = vec![Scalar::ZERO; sym_len];

        if slot < k {
            // Systematic 조각: 앞의 k개는 단위 벡터
            coefficients[slot] = Scalar::ONE;
            symbols.copy_from_slice(&source_rows[slot]);
        } else {
            // 패리티 조각: F_p 위에서 임의의 비영(non-zero) 선형 결합 계수 생성
            for (row_idx, coeff) in coefficients.iter_mut().enumerate() {
                let mut buf = [0u8; 32];
                rng.fill_bytes(&mut buf);
                let mut c = Scalar::from_le_bytes_mod_order(&buf);
                if c == Scalar::ZERO {
                    c = Scalar::ONE;
                }
                *coeff = c;
                for j in 0..sym_len {
                    symbols[j] += c * source_rows[row_idx][j];
                }
            }
        }

        shards.push(Shard {
            object_id,
            k,
            original_len: data.len(),
            coefficients,
            symbols,
        });
    }

    Ok(shards)
}

/// F_p 유한체 위에서 원본 디코딩 없이 두 조각을 선형 결합(S_new = S_A + factor_b * S_B mod p)하여 새 패리티 조각을 생성한다.
/// KZG 스칼라 필드와 대수적으로 일치하므로 Commit(fp(S_new)) == Commit(fp(S_A)) + factor_b * Commit(fp(S_B))가 항상 성립한다.
pub fn repair_local_field(a: &Shard, b: &Shard, factor_b: Scalar) -> Result<Shard> {
    a.validate()?;
    b.validate()?;
    if a.object_id != b.object_id
        || a.k != b.k
        || a.original_len != b.original_len
        || a.symbols.len() != b.symbols.len()
        || factor_b == Scalar::ZERO
    {
        return Err(Error::InvalidInput);
    }

    let coefficients: Vec<Scalar> = a
        .coefficients
        .iter()
        .zip(&b.coefficients)
        .map(|(ca, cb)| *ca + factor_b * *cb)
        .collect();
    if coefficients.iter().all(|c| *c == Scalar::ZERO) {
        return Err(Error::InvalidInput);
    }

    let symbols: Vec<Scalar> = a
        .symbols
        .iter()
        .zip(&b.symbols)
        .map(|(sa, sb)| *sa + factor_b * *sb)
        .collect();

    Ok(Shard {
        object_id: a.object_id,
        k: a.k,
        original_len: a.original_len,
        coefficients,
        symbols,
    })
}

/// 상삼각 기저 배열(`pivots[col]`은 선도 원소가 `col` 열이고 해당 값이 1로 정규화된 행)에
/// 새 계수 행이 선형 독립인지 판별하여 삽입한다.
fn try_insert_pivot(pivots: &mut [Option<Vec<Scalar>>], row: &[Scalar]) -> bool {
    let k = pivots.len();
    if row.len() != k {
        return false;
    }
    let mut cur = row.to_vec();
    for col in 0..k {
        if cur[col] == Scalar::ZERO {
            continue;
        }
        if let Some(pivot_row) = &pivots[col] {
            let factor = cur[col];
            for j in col..k {
                cur[j] -= factor * pivot_row[j];
            }
        } else {
            let inv = cur[col].inverse().expect("non-zero scalar must be invertible");
            for j in col..k {
                cur[j] *= inv;
            }
            pivots[col] = Some(cur);
            return true;
        }
    }
    false
}

/// F_p 유한체 가우스 소거법으로 계수 행렬의 선형 독립 랭크를 계산한다.
pub fn rank(rows: &[Vec<Scalar>], k: usize) -> usize {
    if k == 0 || rows.is_empty() {
        return 0;
    }
    let mut pivots: Vec<Option<Vec<Scalar>>> = vec![None; k];
    let mut count = 0usize;
    for row in rows {
        if try_insert_pivot(&mut pivots, row) {
            count += 1;
            if count == k {
                break;
            }
        }
    }
    count
}

/// 선형 독립인 k개 이상의 F_p 조각으로부터 가우스-조르당 소거법을 통해 원본 바이트를 완벽 복원한다.
pub fn decode(shards: &[Shard]) -> Result<Vec<u8>> {
    let first = shards.first().ok_or(Error::InvalidInput)?;
    first.validate()?;
    let k = first.k;
    let object_id = first.object_id;
    let original_len = first.original_len;
    let sym_len = first.symbols.len();

    for s in shards {
        s.validate()?;
        if s.k != k
            || s.object_id != object_id
            || s.original_len != original_len
            || s.symbols.len() != sym_len
        {
            return Err(Error::InvalidInput);
        }
    }

    // 선형 독립인 k개 행 선별
    let mut selected_coeffs: Vec<Vec<Scalar>> = Vec::with_capacity(k);
    let mut selected_syms: Vec<Vec<Scalar>> = Vec::with_capacity(k);
    let mut pivots: Vec<Option<Vec<Scalar>>> = vec![None; k];

    for s in shards {
        if try_insert_pivot(&mut pivots, &s.coefficients) {
            selected_coeffs.push(s.coefficients.clone());
            selected_syms.push(s.symbols.clone());
            if selected_coeffs.len() == k {
                break;
            }
        }
    }

    if selected_coeffs.len() < k {
        return Err(Error::InsufficientRank);
    }

    // F_p 가우스-조르당 소거법 수행: [A | Y] -> [I | X]
    let mut a = selected_coeffs;
    let mut y = selected_syms;
    for col in 0..k {
        let pivot_idx = (col..k)
            .find(|&r| a[r][col] != Scalar::ZERO)
            .ok_or(Error::InsufficientRank)?;
        if pivot_idx != col {
            a.swap(pivot_idx, col);
            y.swap(pivot_idx, col);
        }
        let inv = a[col][col].inverse().ok_or(Error::InsufficientRank)?;
        for j in col..k {
            a[col][j] *= inv;
        }
        for s_idx in 0..sym_len {
            y[col][s_idx] *= inv;
        }

        for r in 0..k {
            if r == col || a[r][col] == Scalar::ZERO {
                continue;
            }
            let factor = a[r][col];
            for j in col..k {
                let sub = factor * a[col][j];
                a[r][j] -= sub;
            }
            for s_idx in 0..sym_len {
                let sub = factor * y[col][s_idx];
                y[r][s_idx] -= sub;
            }
        }
    }

    // 스칼라 행렬을 원본 바이트 스트림으로 역직렬화
    let mut out = Vec::with_capacity(original_len + BYTES_PER_SCALAR);
    for row in &y {
        for scalar in row {
            if out.len() >= original_len {
                break;
            }
            let le = scalar.into_bigint().to_bytes_le();
            if le[BYTES_PER_SCALAR] != 0 {
                return Err(Error::CryptoFailure);
            }
            out.extend_from_slice(&le[..BYTES_PER_SCALAR]);
        }
        if out.len() >= original_len {
            break;
        }
    }
    out.truncate(original_len);

    let recovered_hash: [u8; 32] = Sha256::digest(&out).into();
    if recovered_hash != object_id {
        return Err(Error::CryptoFailure);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_local_field_repair_and_decode_boundary_lengths() {
        for len in [0usize, 1, 30, 31, 32, 1023, 8192] {
            let data: Vec<u8> = (0..len).map(|i| ((i * 73 + 19) % 251) as u8).collect();
            let shards = encode(&data, 30, 100, 777).unwrap();
            assert_eq!(shards.len(), 100);

            // 패리티 29개 + 로컬 F_p 복구 조각 1개 혼합해서 디코딩 검증
            let repaired =
                repair_local_field(&shards[3], &shards[17], Scalar::from(5u64)).unwrap();
            let mut subset: Vec<Shard> = shards[71..100].to_vec(); // 29개 패리티
            subset.push(repaired); // + 1개 로컬 복구 조각

            let recovered = decode(&subset).unwrap();
            assert_eq!(recovered, data, "failed recovery for len={}", len);
        }
    }

    #[test]
    fn encode_and_shard_validate_reject_invalid_parameters() {
        assert!(matches!(encode(b"hello", 0, 10, 1), Err(Error::InvalidInput)));
        assert!(matches!(encode(b"hello", 10, 9, 1), Err(Error::InvalidInput)));

        let shards = encode(b"valid payload", 4, 8, 2).unwrap();
        let mut zero_coeff = shards[0].clone();
        zero_coeff.coefficients.fill(Scalar::ZERO);
        assert!(matches!(zero_coeff.validate(), Err(Error::InvalidInput)));

        let mut wrong_len_coeff = shards[0].clone();
        wrong_len_coeff.coefficients.pop();
        assert!(matches!(wrong_len_coeff.validate(), Err(Error::InvalidInput)));
    }

    #[test]
    fn decode_fails_with_insufficient_rank_on_linearly_dependent_shards() {
        let data = vec![0xABu8; 4096];
        let shards = encode(&data, 30, 100, 99).unwrap();

        let mut subset: Vec<Shard> = shards[..29].to_vec();
        for factor in 2u64..=6 {
            let dep = repair_local_field(&shards[0], &shards[1], Scalar::from(factor)).unwrap();
            subset.push(dep);
        }
        assert_eq!(subset.len(), 34);
        assert!(matches!(decode(&subset), Err(Error::InsufficientRank)));
    }

    #[test]
    fn decode_detects_corrupted_symbol_via_sha256_object_id() {
        let data = vec![0x3Eu8; 2048];
        let shards = encode(&data, 30, 60, 17).unwrap();
        let mut subset: Vec<Shard> = shards[..30].to_vec();
        subset[0].symbols[0] += Scalar::ONE;

        assert!(matches!(decode(&subset), Err(Error::CryptoFailure)));
    }

    #[test]
    fn repair_local_field_rejects_zero_factor_and_mismatched_metadata() {
        let shards_a = encode(b"object alpha payload", 4, 8, 1).unwrap();
        let shards_b = encode(b"object beta payload!", 4, 8, 2).unwrap();

        assert!(matches!(
            repair_local_field(&shards_a[0], &shards_a[1], Scalar::ZERO),
            Err(Error::InvalidInput)
        ));
        assert!(matches!(
            repair_local_field(&shards_a[0], &shards_b[1], Scalar::from(3u64)),
            Err(Error::InvalidInput)
        ));
        assert!(matches!(
            repair_local_field(&shards_a[0], &shards_a[0], -Scalar::ONE),
            Err(Error::InvalidInput)
        ));
    }
}
