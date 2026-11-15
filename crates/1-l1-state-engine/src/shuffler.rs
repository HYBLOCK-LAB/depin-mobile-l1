use crate::state_db::SWARM_SIZE;
use crate::{Error, Result};
use sha3::{Digest, Keccak256};
use std::collections::BTreeMap;

/// 셔플러 입력용 모바일 노드 등록 정보
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeDescriptor {
    pub pubkey_p256: [u8; 33],
    pub ip_subnet_hash: u16,
    pub country_code: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShuffleConfig {
    pub swarm_size: usize,
    pub max_per_subnet: usize,
    pub max_per_country: usize,
}

impl Default for ShuffleConfig {
    fn default() -> Self {
        Self {
            swarm_size: SWARM_SIZE,
            max_per_subnet: 2,
            max_per_country: 25,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ShuffleOutput {
    pub swarms: Vec<Vec<[u8; 33]>>,
    pub standby_pool: Vec<[u8; 33]>,
}

fn score_node(pubkey: &[u8; 33], epoch_seed: &[u8; 32]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(pubkey);
    h.update(epoch_seed);
    h.finalize().into()
}

/// 에포크 VRF 난수 + IP 서브넷(<=2) + 국가 코드(<=25) 다양성 필터 기반 결정론적 스웜 편성.
/// 미완성 스웜이나 다양성 제약을 넘긴 노드는 standby_pool로 결정론적 이관(Spillover)된다.
pub fn shuffle(
    epoch_seed: &[u8; 32],
    nodes: &[NodeDescriptor],
    cfg: &ShuffleConfig,
) -> Result<ShuffleOutput> {
    if cfg.swarm_size == 0 || cfg.max_per_subnet == 0 || cfg.max_per_country == 0 {
        return Err(Error::InvalidInput);
    }

    let mut ranked: Vec<([u8; 32], &NodeDescriptor)> = nodes
        .iter()
        .map(|n| (score_node(&n.pubkey_p256, epoch_seed), n))
        .collect();
    ranked.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.pubkey_p256.cmp(&b.1.pubkey_p256)));

    let mut pending: Vec<&NodeDescriptor> = ranked.into_iter().map(|(_, n)| n).collect();
    let mut swarms = Vec::new();

    loop {
        if pending.len() < cfg.swarm_size {
            break;
        }
        let mut current = Vec::with_capacity(cfg.swarm_size);
        let mut subnet_counts: BTreeMap<u16, usize> = BTreeMap::new();
        let mut country_counts: BTreeMap<u8, usize> = BTreeMap::new();
        let mut spillover = Vec::new();

        for node in pending.into_iter() {
            let s_cnt = subnet_counts.get(&node.ip_subnet_hash).copied().unwrap_or(0);
            let c_cnt = country_counts.get(&node.country_code).copied().unwrap_or(0);

            if current.len() < cfg.swarm_size
                && s_cnt < cfg.max_per_subnet
                && c_cnt < cfg.max_per_country
            {
                *subnet_counts.entry(node.ip_subnet_hash).or_insert(0) += 1;
                *country_counts.entry(node.country_code).or_insert(0) += 1;
                current.push(node.pubkey_p256);
            } else {
                spillover.push(node);
            }
        }

        if current.len() == cfg.swarm_size {
            swarms.push(current);
            pending = spillover;
        } else {
            // 다양성 제약 하에서 100대 스웜을 더 이상 채울 수 없으므로 남은 노드는 모두 대기 풀로 이동
            let mut leftover: Vec<[u8; 33]> = current;
            leftover.extend(spillover.into_iter().map(|n| n.pubkey_p256));
            return Ok(ShuffleOutput {
                swarms,
                standby_pool: leftover,
            });
        }
    }

    let standby_pool = pending.into_iter().map(|n| n.pubkey_p256).collect();
    Ok(ShuffleOutput {
        swarms,
        standby_pool,
    })
}

/// Zero-Tx 파일 라우팅: 클라이언트가 온체인 트랜잭션 없이 공개된 epoch_seed만으로 담당 Swarm ID를 결정론적 계산한다.
pub fn route_file_to_swarm(
    file_id: &[u8; 32],
    epoch_seed: &[u8; 32],
    swarm_count: usize,
) -> Result<u64> {
    if swarm_count == 0 {
        return Err(Error::InvalidInput);
    }
    let mut h = Keccak256::new();
    h.update(b"depin/route-file/v1");
    h.update(file_id);
    h.update(epoch_seed);
    let digest = h.finalize();
    let idx = u64::from_le_bytes(digest[..8].try_into().expect("8 bytes"));
    Ok(idx % swarm_count as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shuffle_enforces_diversity_and_determinism() {
        let mut nodes = Vec::new();
        for i in 0..240u16 {
            let mut pk = [0u8; 33];
            pk[0] = 0x02;
            pk[1..3].copy_from_slice(&i.to_le_bytes());
            nodes.push(NodeDescriptor {
                pubkey_p256: pk,
                ip_subnet_hash: i / 2,    // 서브넷당 정확히 2대 이하 가능
                country_code: (i % 10) as u8, // 국가당 최대 24대 (<=25대 제한 충족)
            });
        }

        let seed = [0xAA; 32];
        let out1 = shuffle(&seed, &nodes, &ShuffleConfig::default()).unwrap();
        let out2 = shuffle(&seed, &nodes, &ShuffleConfig::default()).unwrap();

        assert_eq!(out1.swarms.len(), 2);
        assert_eq!(out1.swarms[0].len(), 100);
        assert_eq!(out1.swarms[1].len(), 100);
        assert_eq!(out1.standby_pool.len(), 40);
        assert_eq!(out1.swarms, out2.swarms);

        let r = route_file_to_swarm(&[9u8; 32], &seed, out1.swarms.len()).unwrap();
        assert!(r < 2);
    }

    #[test]
    fn shuffle_spills_excess_same_subnet_or_country_to_standby_pool() {
        let mut nodes = Vec::new();
        for i in 0..105u16 {
            let mut pk = [0u8; 33];
            pk[0] = 0x02;
            pk[1..3].copy_from_slice(&i.to_le_bytes());
            nodes.push(NodeDescriptor {
                pubkey_p256: pk,
                ip_subnet_hash: 7, // 전원 동일 서브넷 -> max_per_subnet(2) 초과로 스웜 미완성
                country_code: (i % 10) as u8,
            });
        }

        let out = shuffle(&[0x55; 32], &nodes, &ShuffleConfig::default()).unwrap();
        assert!(out.swarms.is_empty());
        assert_eq!(out.standby_pool.len(), 105);
    }

    #[test]
    fn shuffle_rejects_zero_config_and_route_rejects_zero_swarms() {
        let seed = [0x11; 32];
        for cfg in [
            ShuffleConfig {
                swarm_size: 0,
                max_per_subnet: 2,
                max_per_country: 25,
            },
            ShuffleConfig {
                swarm_size: 100,
                max_per_subnet: 0,
                max_per_country: 25,
            },
            ShuffleConfig {
                swarm_size: 100,
                max_per_subnet: 2,
                max_per_country: 0,
            },
        ] {
            assert!(matches!(
                shuffle(&seed, &[], &cfg),
                Err(Error::InvalidInput)
            ));
        }

        assert!(matches!(
            route_file_to_swarm(&[0u8; 32], &seed, 0),
            Err(Error::InvalidInput)
        ));
    }
}
