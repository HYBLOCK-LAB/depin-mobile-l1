use l1_state_engine::consensus::{BftEngine, ValidatorInfo, ValidatorSigner};
use l1_state_engine::executor::{sign_registration, Executor, ExecutorConfig};
use l1_state_engine::shuffler::{route_file_to_swarm, shuffle, NodeDescriptor, ShuffleConfig};
use l1_state_engine::state_db::{LegacyStateDB, NativeTransaction, VirtualSwarmState, SWARM_SIZE};
use p256::ecdsa::SigningKey;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::time::Instant;
use swarm_protocol::churn_sim::{
    run as run_sim, sweep_trigger_thresholds, write_results_csv, Method, SimConfig,
};
use swarm_protocol::lazy_repair_fsm::LazyRepairFsm;
use swarm_protocol::swarm_coordinator::{build_checkpoint, select_active_aggregator};
use verkle_fountain::fountain::{decode, encode, repair_local_field};
use verkle_fountain::pollution_guard::{verify_homomorphic_repair, AuthenticatedShard};
use verkle_fountain::verkle_kzg::{Kzg, Scalar};

fn deterministic_signing_key(idx: usize) -> SigningKey {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&(idx as u64 + 1000).to_le_bytes());
    let mut rng = ChaCha8Rng::from_seed(seed);
    SigningKey::random(&mut rng)
}

fn main() {
    println!("==================================================================");
    println!("  DePIN Mobile Storage L1 (Pure Rust) - Integrated Benchmark Suite");
    println!("==================================================================\n");

    let mut rng = ChaCha8Rng::seed_from_u64(42);
    let kzg = Kzg::setup(SWARM_SIZE - 1, &mut rng);

    // ------------------------------------------------------------------
    // 1. 코딩 및 암호학 코어 벤치마크 (2-verkle-fountain)
    // ------------------------------------------------------------------
    let sample_data: Vec<u8> = (0..1_000_000)
        .map(|i| ((i * 37 + 13) % 251) as u8)
        .collect();
    let t0 = Instant::now();
    let shards = encode(&sample_data, 30, SWARM_SIZE, 2026).expect("encode");
    let encode_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let t1 = Instant::now();
    let fps: Vec<Scalar> = shards.iter().map(|s| s.fingerprint()).collect();
    let root = kzg.commit(&fps).expect("commit");
    let commit_ms = t1.elapsed().as_secs_f64() * 1000.0;

    let proof_a = kzg.open(&fps, 2).expect("open a");
    let proof_b = kzg.open(&fps, 9).expect("open b");
    let beta = Scalar::from(5u64);

    let t2 = Instant::now();
    let repaired = repair_local_field(&shards[2], &shards[9], beta).expect("local repair");
    let repair_ms = t2.elapsed().as_secs_f64() * 1000.0;

    let t3 = Instant::now();
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
    .expect("homomorphic verify");
    let pollution_check_ms = t3.elapsed().as_secs_f64() * 1000.0;

    let mut decode_subset = shards[71..100].to_vec();
    decode_subset.push(repaired.clone());
    let t4 = Instant::now();
    let recovered = decode(&decode_subset).expect("decode");
    let decode_ms = t4.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(recovered, sample_data);

    println!("## [Area 1] 2-verkle-fountain (F_p Linear Fountain + Lagrange KZG, 1MB Payload)");
    println!("| Metric | Value |");
    println!("| :--- | ---: |");
    println!("| F_p Fountain Encode (k=30, n=100) | {:.3} ms |", encode_ms);
    println!("| 2-Stage Fingerprint + 48B KZG Root | {:.3} ms |", commit_ms);
    println!("| Local F_p Linear Repair (1 shard) | {:.3} ms |", repair_ms);
    println!("| Homomorphic Pollution Verification | {:.3} ms |", pollution_check_ms);
    println!("| Gaussian-Jordan Decode (30 shards) | {:.3} ms |\n", decode_ms);

    // ------------------------------------------------------------------
    // 2. 온체인 상태 압축 & BFT 합의 벤치마크 (1-l1-state-engine + 3-swarm-protocol)
    // ------------------------------------------------------------------
    let mut exec = Executor::new(ExecutorConfig::default());
    let mut node_keys: Vec<SigningKey> = Vec::with_capacity(120);
    let mut descriptors: Vec<NodeDescriptor> = Vec::with_capacity(120);
    let mut reg_txs = Vec::with_capacity(120);

    for i in 0..120 {
        let sk = deterministic_signing_key(i);
        let ip_subnet = (i / 2) as u16;
        let country = (i % 10) as u8;
        let (pk, sig) = sign_registration(&sk, exec.config.chain_id, ip_subnet, country, 2_000);
        descriptors.push(NodeDescriptor {
            pubkey_p256: pk,
            ip_subnet_hash: ip_subnet,
            country_code: country,
        });
        reg_txs.push(NativeTransaction::RegisterMobileNode {
            pubkey_p256: pk,
            hw_attestation_sig: sig,
            ip_subnet_hash: ip_subnet,
            country_code: country,
            stake: 2_000,
        });
        node_keys.push(sk);
    }

    let validators: Vec<ValidatorSigner> = (0..4)
        .map(|id| ValidatorSigner::new(id, 1, deterministic_signing_key(500 + id as usize)))
        .collect();
    let val_infos: Vec<ValidatorInfo> = validators.iter().map(|v| v.info()).collect();
    let mut bft = BftEngine::new(val_infos).expect("bft");

    let epoch_seed = [0x5A; 32];
    bft.propose_and_finalize(
        &mut exec,
        &kzg,
        0,
        reg_txs,
        epoch_seed,
        &[&validators[0], &validators[1], &validators[2], &validators[3]],
    )
    .expect("register block");

    let shuffled = shuffle(&epoch_seed, &descriptors, &ShuffleConfig::default()).expect("shuffle");
    let swarm_roster = shuffled.swarms[0].clone();
    let _target_swarm = route_file_to_swarm(&shards[0].object_id, &epoch_seed, 1).expect("route");

    // 100대 스웜에 대응하는 LegacyStateDB vs EnshrinedSwarmDB 크기 비교
    let mut legacy_db = LegacyStateDB::default();
    legacy_db.insert_blob_slots(0, &swarm_roster);

    exec.init_swarm(0, swarm_roster.clone(), [0x11; 48], root, 10_000)
        .expect("init swarm");
    let mut fsm = LazyRepairFsm::new(shards, 45, 60).expect("fsm");

    // 55대 노드 이탈(T_repair = 45 도달) 후 지연 복구 + 반장 승계 + BFT 체크포인트 블록 확정 측정
    let proofs: Vec<[u8; 48]> = (0..SWARM_SIZE)
        .map(|i| kzg.open(&fps, i).expect("open"))
        .collect();
    for i in 0..55 {
        if i % 3 == 0 {
            let _ = fsm.drop_node(i, None); // 영구 이탈
        } else {
            let _ = fsm.drop_node(i, Some(10)); // 일시 이탈
        }
    }

    let repair_log = fsm.repair(&kzg, &root, &proofs).expect("fsm repair");
    let agg_slot = select_active_aggregator(&fsm).expect("aggregator");
    let agg_pk = swarm_roster[agg_slot as usize];
    let agg_idx_global = descriptors
        .iter()
        .position(|d| d.pubkey_p256 == agg_pk)
        .expect("agg key");

    let ckpt_tx = build_checkpoint(
        0,
        1,
        &epoch_seed,
        &kzg,
        &fsm,
        &fps,
        &proofs,
        repair_log,
        agg_slot,
        &node_keys[agg_idx_global],
    )
    .expect("build checkpoint");

    let t_bft = Instant::now();
    bft.propose_and_finalize(
        &mut exec,
        &kzg,
        1,
        vec![ckpt_tx],
        epoch_seed,
        &[&validators[0], &validators[1], &validators[2]],
    )
    .expect("checkpoint block");
    let bft_ckpt_ms = t_bft.elapsed().as_secs_f64() * 1000.0;

    println!("## [Area 2] 1-l1-state-engine (Virtual Swarm Compression & Pure Rust BFT)");
    println!("| Metric | Legacy Individual Slot DB | Proposed Virtual Swarm L1 |");
    println!("| :--- | ---: | ---: |");
    println!(
        "| On-chain State Size per Swarm (100 nodes) | {} Bytes | {} Bytes ({:.1}% reduction) |",
        legacy_db.total_state_bytes(),
        VirtualSwarmState::encoded_bytes_len(),
        (1.0 - VirtualSwarmState::encoded_bytes_len() as f64 / legacy_db.total_state_bytes() as f64)
            * 100.0
    );
    println!(
        "| Checkpoint + Repair Audit + 3/4 BFT Block Time | N/A | {:.3} ms |\n",
        bft_ckpt_ms
    );

    // ------------------------------------------------------------------
    // 3. 24시간 모바일 Churn 시뮬레이션 및 임계값 스윕 (3-swarm-protocol)
    // ------------------------------------------------------------------
    let mut sim_results = Vec::new();
    println!("## [Area 3] 3-swarm-protocol (24h Churn Simulation, 100MB File, return_prob=90%)");
    println!("| Churn Rate | Method | 24h Onchain Tx | Repair Read (GB) | Repair Write (GB) | Survived |");
    println!("| :---: | :--- | ---: | ---: | ---: | :---: |");

    for churn in [0.05, 0.15, 0.25, 0.35, 0.55] {
        for method in Method::ALL {
            let cfg = SimConfig {
                hourly_churn: churn,
                ..SimConfig::default()
            };
            let (res, _) = run_sim(&cfg, method).expect("sim");
            let read_gb = res.repair_read_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
            let write_gb = res.repair_write_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
            println!(
                "| {:>3.0}% | {:<23} | {:>14} | {:>16.2} | {:>17.2} | {:^8} |",
                churn * 100.0,
                res.method,
                res.onchain_tx,
                read_gb,
                write_gb,
                if res.survived { "YES" } else { "LOST" }
            );
            sim_results.push(res);
        }
    }

    let sweep_cfg = SimConfig {
        hourly_churn: 0.25,
        ..SimConfig::default()
    };
    let sweep_results =
        sweep_trigger_thresholds(&[35, 40, 45, 50, 55], &sweep_cfg).expect("sweep");

    println!("\n## [Area 3-B] T_repair Safety-Buffer Threshold Sweep (Hourly Churn = 25%)");
    println!("| T_repair | Target | Repair Read (GB) | Available Steps | Survived |");
    println!("| :---: | :---: | ---: | ---: | :---: |");
    for res in &sweep_results {
        println!(
            "| {:>8} | {:>6} | {:>16.2} | {:>9} / {:<4} | {:^8} |",
            res.trigger,
            (res.trigger + 15).min(100),
            res.repair_read_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
            res.available_steps,
            res.total_steps,
            if res.survived { "YES" } else { "LOST" }
        );
    }

    let results_dir = Path::new("results");
    fs::create_dir_all(results_dir).expect("create results dir");
    write_results_csv(&results_dir.join("churn_comparison.csv"), &sim_results)
        .expect("write churn csv");
    write_results_csv(&results_dir.join("threshold_sweep.csv"), &sweep_results)
        .expect("write sweep csv");

    let _hash_sanity = Sha256::digest(&sample_data);
    println!("\nCSV artifacts exported to: results/churn_comparison.csv, results/threshold_sweep.csv");
}
