use crate::state_db::{DEFAULT_UPTIME_BPS, MAX_SWARM_SIZE, MIN_SWARM_SIZE};
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
    pub max_per_subnet: usize,
    pub max_per_country: usize,
}

impl Default for ShuffleConfig {
    fn default() -> Self {
        Self {
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

pub fn score_node(pubkey: &[u8; 33], epoch_seed: &[u8; 32]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(pubkey);
    h.update(epoch_seed);
    h.finalize().into()
}

fn effective_max_per_subnet(size: usize, base: usize) -> usize {
    (base * size).div_ceil(100).max(base)
}

fn effective_max_per_country(size: usize, base: usize) -> usize {
    (base * size).div_ceil(100).max(2)
}

fn try_fill_swarm<'a>(
    pending: &[&'a NodeDescriptor],
    size: usize,
    max_subnet: usize,
    max_country: usize,
) -> (Vec<&'a NodeDescriptor>, Vec<&'a NodeDescriptor>) {
    let mut current = Vec::with_capacity(size);
    let mut subnet_counts: BTreeMap<u16, usize> = BTreeMap::new();
    let mut country_counts: BTreeMap<u8, usize> = BTreeMap::new();
    let mut spillover = Vec::with_capacity(pending.len());

    for &node in pending {
        let s_cnt = subnet_counts.get(&node.ip_subnet_hash).copied().unwrap_or(0);
        let c_cnt = country_counts.get(&node.country_code).copied().unwrap_or(0);

        if current.len() < size && s_cnt < max_subnet && c_cnt < max_country {
            *subnet_counts.entry(node.ip_subnet_hash).or_insert(0) += 1;
            *country_counts.entry(node.country_code).or_insert(0) += 1;
            current.push(node);
        } else {
            spillover.push(node);
        }
    }
    (current, spillover)
}

/// 가동률 버킷(높은 가동률 우선) + VRF 난수 + 비례 다양성 필터 기반 결정론적 스웜 편성.
pub fn shuffle_with_uptime(
    epoch_seed: &[u8; 32],
    nodes: &[(NodeDescriptor, u16)],
    cfg: &ShuffleConfig,
) -> Result<ShuffleOutput> {
    if cfg.max_per_subnet == 0 || cfg.max_per_country == 0 {
        return Err(Error::InvalidInput);
    }

    let mut ranked: Vec<(std::cmp::Reverse<u16>, [u8; 32], &NodeDescriptor)> = nodes
        .iter()
        .map(|(n, uptime_bps)| {
            (
                std::cmp::Reverse(*uptime_bps / 1_000),
                score_node(&n.pubkey_p256, epoch_seed),
                n,
            )
        })
        .collect();
    ranked.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| a.1.cmp(&b.1))
            .then_with(|| a.2.pubkey_p256.cmp(&b.2.pubkey_p256))
    });

    let mut pending: Vec<&NodeDescriptor> = ranked.into_iter().map(|(_, _, n)| n).collect();
    let mut swarms = Vec::new();

    for size in swarm_sizes(nodes.len()) {
        let max_subnet = effective_max_per_subnet(size, cfg.max_per_subnet);
        let max_country = effective_max_per_country(size, cfg.max_per_country);
        let (mut current, mut spillover) = try_fill_swarm(&pending, size, max_subnet, max_country);
        if current.len() < size && max_country < cfg.max_per_country {
            (current, spillover) =
                try_fill_swarm(&pending, size, max_subnet, cfg.max_per_country);
        }

        if current.len() == size {
            swarms.push(current.into_iter().map(|n| n.pubkey_p256).collect());
            pending = spillover;
        } else {
            // 다양성 제약 하에서 스웜을 더 이상 채울 수 없으므로 남은 노드는 모두 대기 풀로 이동
            let mut leftover: Vec<[u8; 33]> = current.into_iter().map(|n| n.pubkey_p256).collect();
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

/// 에포크 VRF 난수 + IP 서브넷 + 국가 코드 비례 다양성 필터 기반 결정론적 스웜 편성.
/// 미완성 스웜이나 다양성 제약을 넘긴 노드는 standby_pool로 결정론적 이관(Spillover)된다.
pub fn shuffle(
    epoch_seed: &[u8; 32],
    nodes: &[NodeDescriptor],
    cfg: &ShuffleConfig,
) -> Result<ShuffleOutput> {
    let with_default_uptime: Vec<(NodeDescriptor, u16)> = nodes
        .iter()
        .cloned()
        .map(|n| (n, DEFAULT_UPTIME_BPS))
        .collect();
    shuffle_with_uptime(epoch_seed, &with_default_uptime, cfg)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwarmParams {
    pub n: u8,
    pub k: u8,
    pub t_repair: u8,
    pub t_target: u8,
}

pub fn swarm_sizes(m: usize) -> Vec<usize> {
    if m < MIN_SWARM_SIZE {
        return Vec::new();
    }
    let active = if m <= 15 { m } else { m - m.div_ceil(10) };
    let s = active.div_ceil(MAX_SWARM_SIZE).max((active + 50) / 100);
    (0..s)
        .map(|j| active / s + usize::from(j < active % s))
        .collect()
}

pub fn swarm_params(n: usize, avg_uptime_bps: u16) -> Result<SwarmParams> {
    if !(MIN_SWARM_SIZE..=MAX_SWARM_SIZE).contains(&n) {
        return Err(Error::InvalidInput);
    }
    const S: i64 = 10_000;
    let u = i64::from(avg_uptime_bps.clamp(5_000, 9_500));
    let n = n as i64;
    let mu_s = n * u;
    let sigma_s = ((n * u * (S - u)) as u64).isqrt() as i64;
    let tt_raw = (2 * mu_s - 3 * sigma_s).div_euclid(2 * S);
    let t_target = tt_raw.clamp((55 * n + 99) / 100, 80 * n / 100);
    let lo = (35 * n + 99) / 100;
    let hi = t_target - (12 * n / 100).max(2);
    let tr_raw = (mu_s - 3 * sigma_s).div_euclid(S);
    let t_repair = tr_raw.clamp(lo, hi);
    let k = (2 * t_repair / 3).max(2);
    Ok(SwarmParams {
        n: n as u8,
        k: k as u8,
        t_repair: t_repair as u8,
        t_target: t_target as u8,
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

        assert_eq!(swarm_sizes(240), vec![108, 108]);
        assert_eq!(out1.swarms.len(), 2);
        assert_eq!(out1.swarms[0].len(), 108);
        assert_eq!(out1.swarms[1].len(), 108);
        assert_eq!(out1.standby_pool.len(), 24);
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
                max_per_subnet: 0,
                max_per_country: 25,
            },
            ShuffleConfig {
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

    #[test]
    fn swarm_sizes_partition_active_nodes_within_bounds() {
        for m in 0..MIN_SWARM_SIZE {
            assert!(swarm_sizes(m).is_empty());
        }
        assert_eq!(swarm_sizes(10), vec![10]);
        assert_eq!(swarm_sizes(60), vec![54]);
        assert_eq!(swarm_sizes(100), vec![90]);
        assert_eq!(swarm_sizes(160), vec![72, 72]);
        assert_eq!(swarm_sizes(170), vec![77, 76]);

        for m in MIN_SWARM_SIZE..=5000 {
            let sizes = swarm_sizes(m);
            let reserve = if m > 15 { m.div_ceil(10) } else { 0 };
            assert!(sizes
                .iter()
                .all(|s| (MIN_SWARM_SIZE..=MAX_SWARM_SIZE).contains(s)));
            assert_eq!(sizes.iter().sum::<usize>(), m - reserve);
        }
    }

    #[test]
    fn swarm_params_reference_values_and_invariants() {
        assert_eq!(
            swarm_params(100, 7500).unwrap(),
            SwarmParams {
                n: 100,
                k: 37,
                t_repair: 56,
                t_target: 68
            }
        );
        let small = swarm_params(10, 7500).unwrap();
        assert_eq!((small.k, small.t_repair, small.t_target), (2, 4, 6));
        assert_eq!(
            swarm_params(100, 4000).unwrap(),
            swarm_params(100, 5000).unwrap()
        );
        assert!(matches!(
            swarm_params(MIN_SWARM_SIZE - 1, 7500),
            Err(Error::InvalidInput)
        ));
        assert!(matches!(
            swarm_params(MAX_SWARM_SIZE + 1, 7500),
            Err(Error::InvalidInput)
        ));

        for n in MIN_SWARM_SIZE..=MAX_SWARM_SIZE {
            for u in (5000u16..=9500).step_by(50) {
                let p = swarm_params(n, u).unwrap();
                assert_eq!(p.n as usize, n);
                assert!(2 <= p.k && p.k < p.t_repair && p.t_repair < p.t_target);
                assert!(p.t_target as usize <= n);
            }
        }
    }

    #[test]
    fn shuffle_applies_proportional_caps_and_prioritizes_higher_uptime_buckets() {
        let seed = [0x33u8; 32];

        // 1. Proportional cap scaling for size > 100 (M=120 -> size=108, subnet cap=3, country cap=27)
        // Put 3 nodes on subnet 1 so base subnet cap(2) would fail unless scaled to 3, and 26 in country 1.
        let mut big_nodes = Vec::new();
        for i in 0..120u16 {
            let mut pk = [0u8; 33];
            pk[0] = 0x02;
            pk[1..3].copy_from_slice(&i.to_le_bytes());
            let subnet = if i < 3 { 999 } else { i / 2 };
            let country = if i < 26 { 1 } else { 2 + (i % 6) as u8 };
            big_nodes.push(NodeDescriptor {
                pubkey_p256: pk,
                ip_subnet_hash: subnet,
                country_code: country,
            });
        }
        assert_eq!(effective_max_per_subnet(108, 2), 3);
        assert_eq!(effective_max_per_country(108, 25), 27);
        let big_out = shuffle(&seed, &big_nodes, &ShuffleConfig::default()).unwrap();
        assert_eq!(big_out.swarms.len(), 1);
        assert_eq!(big_out.swarms[0].len(), 108);

        // 2. Uptime bucket prioritization: 16 nodes (10 high uptime, 6 low uptime) -> swarm n=14 takes all 10 high nodes
        let mut uptime_nodes = Vec::new();
        let mut high_pks = Vec::new();
        for i in 0..16u16 {
            let mut pk = [0u8; 33];
            pk[0] = 0x03;
            pk[1..3].copy_from_slice(&i.to_le_bytes());
            let uptime = if i < 10 {
                high_pks.push(pk);
                9_000
            } else {
                4_000
            };
            uptime_nodes.push((
                NodeDescriptor {
                    pubkey_p256: pk,
                    ip_subnet_hash: i,
                    country_code: (i % 8) as u8,
                },
                uptime,
            ));
        }
        let up_out = shuffle_with_uptime(&seed, &uptime_nodes, &ShuffleConfig::default()).unwrap();
        assert_eq!(up_out.swarms.len(), 1);
        assert_eq!(up_out.swarms[0].len(), 14);
        assert_eq!(up_out.standby_pool.len(), 2);
        for pk in &high_pks {
            assert!(up_out.swarms[0].contains(pk));
        }

        // 3. Proportional country cap for smaller swarms (n=14 -> cap=4) with soft fallback when needed
        assert_eq!(effective_max_per_country(14, 25), 4);
        let concentrated_nodes: Vec<NodeDescriptor> = (0..16u16)
            .map(|i| {
                let mut pk = [0u8; 33];
                pk[0] = 0x04;
                pk[1..3].copy_from_slice(&i.to_le_bytes());
                NodeDescriptor {
                    pubkey_p256: pk,
                    ip_subnet_hash: i,
                    country_code: (i % 2) as u8, // up to 8 per country (> 4 proportional cap, <= 25 base)
                }
            })
            .collect();
        let fallback_out = shuffle(&seed, &concentrated_nodes, &ShuffleConfig::default()).unwrap();
        assert_eq!(fallback_out.swarms.len(), 1);
        assert_eq!(fallback_out.swarms[0].len(), 14);
    }
}
