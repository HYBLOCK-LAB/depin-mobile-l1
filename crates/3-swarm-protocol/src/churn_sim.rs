//! 시드 기반 이산 사건(Discrete-Event) 모바일 Churn 시뮬레이터.
//! 24시간(10분 단위 144스텝) 동안 F_p 선형 결합 랭크 기반 생존율 및 복구 트래픽을 비교한다.
use crate::{Error, Result};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::Path;
use verkle_fountain::fountain::rank;
use verkle_fountain::verkle_kzg::Scalar;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Replication,
    ReedSolomon,
    WalrusProxy,
    Proposed,
}

impl Method {
    pub const ALL: [Self; 4] = [
        Self::Replication,
        Self::ReedSolomon,
        Self::WalrusProxy,
        Self::Proposed,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Replication => "swarm_replication_proxy",
            Self::ReedSolomon => "storj_rs_proxy",
            Self::WalrusProxy => "walrus_2d_proxy",
            Self::Proposed => "proposed_fp_lazy",
        }
    }
}

#[derive(Clone, Debug)]
pub struct SimConfig {
    pub hourly_churn: f64,
    pub return_probability: f64,
    pub steps: usize,
    pub step_minutes: usize,
    pub k: usize,
    pub n: usize,
    pub trigger: usize,
    pub target: usize,
    pub file_bytes: u64,
    pub seed: u64,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            hourly_churn: 0.25,
            return_probability: 0.90,
            steps: 144,
            step_minutes: 10,
            k: 30,
            n: 100,
            trigger: 45,
            target: 60,
            file_bytes: 100_000_000,
            seed: 42,
        }
    }
}

#[derive(Clone, Copy)]
enum Status {
    Online,
    TransientOffline(usize),
    Dead,
}

#[derive(Clone)]
struct SimNode {
    status: Status,
    coeff: Vec<Scalar>,
    mask_tag: u64,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct StepRecord {
    pub method: String,
    pub hourly_churn: f64,
    pub seed: u64,
    pub step: usize,
    pub active: usize,
    pub online_rank: usize,
    pub stored_rank: usize,
    pub repair_read_bytes: u64,
    pub repair_write_bytes: u64,
    pub onchain_tx: u64,
    pub available: bool,
    pub data_lost: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct SimResult {
    pub method: String,
    pub hourly_churn: f64,
    pub trigger: usize,
    pub seed: u64,
    pub repair_read_bytes: u64,
    pub repair_write_bytes: u64,
    pub onchain_tx: u64,
    pub available_steps: usize,
    pub total_steps: usize,
    pub survived: bool,
    pub final_active: usize,
    pub initial_storage_bytes: u64,
}

pub fn run(config: &SimConfig, method: Method) -> Result<(SimResult, Vec<StepRecord>)> {
    if !config.hourly_churn.is_finite()
        || !(0.0..=1.0).contains(&config.hourly_churn)
        || !config.return_probability.is_finite()
        || !(0.0..=1.0).contains(&config.return_probability)
        || config.steps == 0
        || config.steps > 100_000
        || config.step_minutes == 0
        || config.step_minutes > 60
        || config.n > 100
        || config.k == 0
        || config.k >= config.trigger
        || config.trigger >= config.target
        || config.target > config.n
        || config.file_bytes == 0
        || config.file_bytes > 1_000_000_000_000
    {
        return Err(Error::Invalid);
    }

    let replication = matches!(method, Method::Replication);
    let (k, n) = if replication {
        (1, 3)
    } else {
        (config.k, config.n)
    };
    let width = config.file_bytes.div_ceil(k as u64);

    let mut rng = ChaCha8Rng::seed_from_u64(config.seed);
    let mut nodes: Vec<SimNode> = (0..n)
        .map(|i| {
            let mut coeff = vec![Scalar::from(0u64); k];
            if i < k {
                coeff[i] = Scalar::from(1u64);
            } else {
                for c in &mut coeff {
                    *c = Scalar::from((rng.gen::<u64>() % 1_000_000_000).max(1));
                }
            }
            SimNode {
                status: Status::Online,
                coeff,
                mask_tag: i as u64 + 1,
            }
        })
        .collect();

    // Paired RNG: 모든 비교 모델이 매 스텝 동일한 이탈/복귀 난수를 경험하도록 이벤트 시드를 분리한다.
    let mut events = ChaCha8Rng::seed_from_u64(config.seed ^ 0x6576_656e_7473);
    let drop_prob = 1.0 - (1.0 - config.hourly_churn).powf(config.step_minutes as f64 / 60.0);

    let mut reads = 0u64;
    let mut writes = 0u64;
    let mut tx = 0u64;
    let mut available_steps = 0usize;
    let mut lost = false;
    let mut records = Vec::with_capacity(config.steps);
    let mut next_tag = n as u64 + 100;

    for step in 1..=config.steps {
        let noise: Vec<(f64, f64, usize)> = (0..100)
            .map(|_| (events.gen(), events.gen(), events.gen_range(1..=2)))
            .collect();

        for (i, node) in nodes.iter_mut().enumerate() {
            if let Status::TransientOffline(at) = node.status {
                if at <= step {
                    node.status = Status::Online;
                }
            }
            if matches!(node.status, Status::Online) && noise[i].0 < drop_prob {
                if noise[i].1 < config.return_probability {
                    node.status = Status::TransientOffline(step + noise[i].2);
                } else {
                    node.status = Status::Dead;
                    node.coeff.fill(Scalar::from(0u64));
                    node.mask_tag = 0;
                }
            }
        }

        let stored_rows: Vec<Vec<Scalar>> = nodes
            .iter()
            .filter(|node| !matches!(node.status, Status::Dead))
            .map(|node| node.coeff.clone())
            .collect();
        let stored_rank_pre = rank(&stored_rows, k);
        if stored_rank_pre < k {
            lost = true;
        }

        let online_nodes: Vec<(Vec<Scalar>, u64)> = nodes
            .iter()
            .filter(|node| matches!(node.status, Status::Online))
            .map(|node| (node.coeff.clone(), node.mask_tag))
            .collect();
        let active = online_nodes.len();
        let online_rows: Vec<Vec<Scalar>> = online_nodes.iter().map(|(c, _)| c.clone()).collect();
        let online_rank_pre = rank(&online_rows, k);

        let proposed = matches!(method, Method::Proposed);
        let should_repair = if proposed {
            active <= config.trigger
        } else {
            active < n
        };

        if should_repair && !lost && online_rank_pre >= k {
            let goal = if proposed { config.target } else { n };
            let needed = goal.saturating_sub(active);
            let mut used_tags: BTreeSet<u64> = online_nodes.iter().map(|(_, t)| *t).collect();
            let mut candidates: Vec<(Vec<Scalar>, u64)> = Vec::with_capacity(needed);

            if proposed {
                let m = online_nodes.len();
                for idx in 0..needed {
                    let a = idx % m;
                    let mut b = (idx * 7 + 1 + idx / m) % m;
                    if b == a {
                        b = (a + 1) % m;
                    }
                    let beta = Scalar::from((idx as u64) + 2);
                    let new_coeff: Vec<Scalar> = online_nodes[a]
                        .0
                        .iter()
                        .zip(&online_nodes[b].0)
                        .map(|(ca, cb)| *ca + beta * *cb)
                        .collect();
                    let tag = next_tag;
                    next_tag += 1;
                    if used_tags.insert(tag) {
                        candidates.push((new_coeff, tag));
                    }
                }
            } else {
                for _ in 0..needed {
                    let coeff: Vec<Scalar> = (0..k)
                        .map(|_| Scalar::from((rng.gen::<u64>() % 1_000_000_000).max(1)))
                        .collect();
                    let tag = next_tag;
                    next_tag += 1;
                    candidates.push((coeff, tag));
                }
            }

            let mut target_indices: Vec<usize> = nodes
                .iter()
                .enumerate()
                .filter_map(|(i, n)| matches!(n.status, Status::Dead).then_some(i))
                .collect();
            target_indices.extend(
                nodes
                    .iter()
                    .enumerate()
                    .filter_map(|(i, n)| matches!(n.status, Status::TransientOffline(_)).then_some(i)),
            );

            for (idx, (coeff, tag)) in target_indices.into_iter().zip(candidates) {
                nodes[idx] = SimNode {
                    status: Status::Online,
                    coeff,
                    mask_tag: tag,
                };
                let read_count = match method {
                    Method::Replication => 1,
                    Method::ReedSolomon => k,
                    Method::WalrusProxy => 10,
                    Method::Proposed => 2,
                };
                reads += read_count as u64 * width;
                writes += width;
                if !proposed {
                    tx += 1;
                }
            }
        }

        // 제안 방식: 6시간(360분) 에포크 종료 시 단일 체크포인트 Tx 1회만 발행
        if proposed && (step * config.step_minutes).is_multiple_of(360) {
            tx += 1;
        }

        let online_after: Vec<Vec<Scalar>> = nodes
            .iter()
            .filter(|node| matches!(node.status, Status::Online))
            .map(|node| node.coeff.clone())
            .collect();
        let stored_after: Vec<Vec<Scalar>> = nodes
            .iter()
            .filter(|node| !matches!(node.status, Status::Dead))
            .map(|node| node.coeff.clone())
            .collect();

        let current_rank = rank(&online_after, k);
        let stored_rank = rank(&stored_after, k);
        lost |= stored_rank < k;
        let available = !lost && current_rank >= k;
        if available {
            available_steps += 1;
        }

        records.push(StepRecord {
            method: method.name().into(),
            hourly_churn: config.hourly_churn,
            seed: config.seed,
            step,
            active: online_after.len(),
            online_rank: current_rank,
            stored_rank,
            repair_read_bytes: reads,
            repair_write_bytes: writes,
            onchain_tx: tx,
            available,
            data_lost: lost,
        });
    }

    let final_active = records.last().ok_or(Error::Invalid)?.active;
    Ok((
        SimResult {
            method: method.name().into(),
            hourly_churn: config.hourly_churn,
            trigger: config.trigger,
            seed: config.seed,
            repair_read_bytes: reads,
            repair_write_bytes: writes,
            onchain_tx: tx,
            available_steps,
            total_steps: config.steps,
            survived: !lost,
            final_active,
            initial_storage_bytes: n as u64 * width,
        },
        records,
    ))
}

/// 안전버퍼 발동 임계값 T_repair 변화에 따른 파레토 최적점(트래픽 vs 생존율) 스윕 실험
pub fn sweep_trigger_thresholds(triggers: &[usize], base: &SimConfig) -> Result<Vec<SimResult>> {
    let mut out = Vec::with_capacity(triggers.len());
    for &t in triggers {
        let mut cfg = base.clone();
        cfg.trigger = t;
        if cfg.target <= t {
            cfg.target = (t + 15).min(cfg.n);
        }
        let (res, _) = run(&cfg, Method::Proposed)?;
        out.push(res);
    }
    Ok(out)
}

pub fn write_results_csv(path: &Path, results: &[SimResult]) -> Result<()> {
    let mut wtr = csv::Writer::from_path(path).map_err(|_| Error::Invalid)?;
    for r in results {
        wtr.serialize(r).map_err(|_| Error::Invalid)?;
    }
    wtr.flush().map_err(|_| Error::Invalid)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn churn_sim_paired_rng_determinism_and_epoch_tx_bound() {
        let cfg = SimConfig::default();
        let (res1, rec1) = run(&cfg, Method::Proposed).unwrap();
        let (res2, rec2) = run(&cfg, Method::Proposed).unwrap();
        assert_eq!(res1, res2);
        assert_eq!(rec1, rec2);
        assert_eq!(res1.onchain_tx, 4);
        assert!(res1.survived);

        let (rs_res, _) = run(&cfg, Method::ReedSolomon).unwrap();
        assert!(res1.repair_read_bytes < rs_res.repair_read_bytes);
    }

    #[test]
    fn churn_sim_rejects_invalid_parameters() {
        let bad_churn = SimConfig {
            hourly_churn: 1.5,
            ..SimConfig::default()
        };
        assert!(matches!(
            run(&bad_churn, Method::Proposed),
            Err(Error::Invalid)
        ));

        let bad_steps = SimConfig {
            steps: 0,
            ..SimConfig::default()
        };
        assert!(matches!(
            run(&bad_steps, Method::Proposed),
            Err(Error::Invalid)
        ));

        let bad_trigger = SimConfig {
            k: 45,
            trigger: 45,
            ..SimConfig::default()
        };
        assert!(matches!(
            run(&bad_trigger, Method::Proposed),
            Err(Error::Invalid)
        ));

        let bad_bytes = SimConfig {
            file_bytes: 0,
            ..SimConfig::default()
        };
        assert!(matches!(
            run(&bad_bytes, Method::Proposed),
            Err(Error::Invalid)
        ));
    }

    #[test]
    fn sweep_trigger_thresholds_and_csv_export() {
        let cfg = SimConfig::default();
        let results = sweep_trigger_thresholds(&[35, 45, 55], &cfg).unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(
            results.iter().map(|r| r.trigger).collect::<Vec<_>>(),
            vec![35, 45, 55]
        );

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "depin_churn_test_{}_{}.csv",
            std::process::id(),
            nanos
        ));
        write_results_csv(&path, &results).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("proposed_fp_lazy"));
        let _ = std::fs::remove_file(&path);
    }
}
