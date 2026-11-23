use l1_state_engine::consensus::{BftEngine, ValidatorInfo, ValidatorSigner};
use l1_state_engine::executor::{
    expected_unchanged_slot_index, sign_registration, Executor, ExecutorConfig,
};
use l1_state_engine::shuffler::{
    route_file_to_swarm, shuffle, swarm_params, swarm_sizes, NodeDescriptor, ShuffleConfig,
};
use l1_state_engine::state_db::{
    compute_member_verkle_root, NativeTransaction, RepairEntry, DEFAULT_UPTIME_BPS,
    MAX_SWARM_SIZE,
};
use l1_state_engine::Error as L1Error;
use p256::ecdsa::SigningKey;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use swarm_protocol::lazy_repair_fsm::{LazyRepairFsm, NodeState};
use swarm_protocol::swarm_coordinator::{
    build_checkpoint, build_checkpoint_with_bitmap, issue_heartbeat_ack, select_active_aggregator,
};
use verkle_fountain::fountain::{decode, encode};
use verkle_fountain::verkle_kzg::{scalar_to_bytes, Kzg, Scalar};

const TEST_N: usize = 100;
const TEST_NODE_COUNT: usize = 112;

fn test_signing_key(seed_num: u64) -> SigningKey {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&(seed_num + 5000).to_le_bytes());
    let mut rng = ChaCha8Rng::from_seed(seed);
    SigningKey::random(&mut rng)
}

fn setup_network_and_swarm() -> (
    Kzg,
    Executor,
    BftEngine,
    Vec<ValidatorSigner>,
    Vec<SigningKey>,
    Vec<NodeDescriptor>,
    Vec<[u8; 33]>,
    [u8; 32],
) {
    let mut rng = ChaCha8Rng::seed_from_u64(77);
    let kzg = Kzg::setup(MAX_SWARM_SIZE - 1, &mut rng);
    let mut exec = Executor::new(ExecutorConfig::default());

    let mut node_keys = Vec::with_capacity(TEST_NODE_COUNT);
    let mut descriptors = Vec::with_capacity(TEST_NODE_COUNT);
    let mut reg_txs = Vec::with_capacity(TEST_NODE_COUNT);

    for i in 0..TEST_NODE_COUNT {
        let sk = test_signing_key(i as u64);
        let subnet = (i / 2) as u16;
        let country = (i % 8) as u8;
        let (pk, sig) = sign_registration(&sk, exec.config.chain_id, subnet, country, 1_500);
        descriptors.push(NodeDescriptor {
            pubkey_p256: pk,
            ip_subnet_hash: subnet,
            country_code: country,
        });
        reg_txs.push(NativeTransaction::RegisterMobileNode {
            pubkey_p256: pk,
            hw_attestation_sig: sig,
            ip_subnet_hash: subnet,
            country_code: country,
            stake: 1_500,
        });
        node_keys.push(sk);
    }

    let validators: Vec<ValidatorSigner> = (0..4)
        .map(|id| ValidatorSigner::new(id, 1, test_signing_key(900 + id)))
        .collect();
    let infos: Vec<ValidatorInfo> = validators.iter().map(|v| v.info()).collect();
    let mut bft = BftEngine::new(infos).unwrap();
    let epoch_seed = [0xAB; 32];

    bft.propose_and_finalize(
        &mut exec,
        &kzg,
        0,
        reg_txs,
        epoch_seed,
        &[&validators[0], &validators[1], &validators[2], &validators[3]],
    )
    .unwrap();

    let shuffled = shuffle(&epoch_seed, &descriptors, &ShuffleConfig::default()).unwrap();
    assert_eq!(shuffled.swarms.len(), 1);
    assert_eq!(shuffled.swarms[0].len(), TEST_N);
    assert_eq!(shuffled.standby_pool.len(), TEST_NODE_COUNT - TEST_N);
    let roster = shuffled.swarms[0].clone();

    (
        kzg,
        exec,
        bft,
        validators,
        node_keys,
        descriptors,
        roster,
        epoch_seed,
    )
}

#[test]
fn e2e_lifecycle_safe_buffer_repair_successor_bft_settlement_and_decode() {
    let (kzg, mut exec, mut bft, validators, node_keys, descriptors, roster, epoch_seed) =
        setup_network_and_swarm();

    let payload: Vec<u8> = (0..12_345).map(|i| ((i * 29 + 7) % 253) as u8).collect();
    let shards = encode(&payload, 30, TEST_N, 901).unwrap();
    let init_fps: Vec<Scalar> = shards.iter().map(|s| s.fingerprint()).collect();
    let init_root = kzg.commit(&init_fps).unwrap();
    let init_proofs: Vec<[u8; 48]> = (0..TEST_N)
        .map(|i| kzg.open(&init_fps, i).unwrap())
        .collect();

    let _routed_swarm = route_file_to_swarm(&shards[0].object_id, &epoch_seed, 1).unwrap();
    let member_root = compute_member_verkle_root(&kzg, &roster).unwrap();
    exec.init_swarm(0, roster.clone(), member_root, init_root, 5_000)
        .unwrap();

    let mut fsm = LazyRepairFsm::new(shards, 45, 60).unwrap();

    // 54개 노드만 이탈 -> 활성 46개 (> trigger 45) -> 안전버퍼가 복구를 억제(0건)
    for i in 0..54 {
        fsm.drop_node(i, Some(5)).unwrap();
    }
    assert_eq!(fsm.active_shard_count(), 46);
    let suppressed = fsm.repair(&kzg, &init_root, &init_proofs).unwrap();
    assert!(suppressed.is_empty());

    // 1대 추가 이탈(총 55대 이탈, 0번 반장 포함) -> 활성 45개 == trigger(45) -> 지연 복구 15건 발동!
    fsm.drop_node(54, None).unwrap();
    assert_eq!(fsm.active_shard_count(), 45);
    let repair_log = fsm.repair(&kzg, &init_root, &init_proofs).unwrap();
    assert_eq!(repair_log.len(), 15);
    assert_eq!(fsm.active_shard_count(), 60);

    // 0번 슬롯 반장이 오프라인이므로 차순위 온라인 슬롯(55번)으로 반장 자동 승계 검증
    let agg_slot = select_active_aggregator(&fsm).unwrap();
    assert_eq!(agg_slot, 55);
    let agg_pk = roster[agg_slot as usize];
    let agg_key_idx = descriptors
        .iter()
        .position(|d| d.pubkey_p256 == agg_pk)
        .unwrap();

    let ckpt_tx = build_checkpoint(
        0,
        1,
        &epoch_seed,
        &kzg,
        &fsm,
        &init_fps,
        &init_proofs,
        repair_log,
        agg_slot,
        &node_keys[agg_key_idx],
    )
    .unwrap();

    let block = bft
        .propose_and_finalize(
            &mut exec,
            &kzg,
            0,
            vec![ckpt_tx],
            epoch_seed,
            &[&validators[0], &validators[1], &validators[2]],
        )
        .unwrap();
    assert_eq!(block.receipts.len(), 1);
    assert_eq!(block.receipts[0].aggregator_bonus, 50); // 1000의 5% = 50
    assert_ne!(
        exec.db.get_swarm(0).unwrap().active_blobs_root,
        init_root
    );

    // 복구된 스웜 조각만으로 원본 파일 완벽 복원 검증
    let recovered = decode(&fsm.accessible_shards()).unwrap();
    assert_eq!(recovered, payload);
}

#[test]
fn zombie_node_generation_guard_prevents_stale_overwrite() {
    let payload = vec![0xCDu8; 4096];
    let shards = encode(&payload, 30, TEST_N, 33).unwrap();
    let mut rng = ChaCha8Rng::seed_from_u64(33);
    let kzg = Kzg::setup(MAX_SWARM_SIZE - 1, &mut rng);
    let fps: Vec<Scalar> = shards.iter().map(|s| s.fingerprint()).collect();
    let root = kzg.commit(&fps).unwrap();
    let proofs: Vec<[u8; 48]> = (0..TEST_N).map(|i| kzg.open(&fps, i).unwrap()).collect();

    let mut fsm = LazyRepairFsm::new(shards, 45, 60).unwrap();

    // 슬롯 0..55 일시 이탈 (0번 슬롯의 generation=0 저장)
    let gen0 = fsm.drop_node(0, Some(10)).unwrap();
    for i in 1..55 {
        fsm.drop_node(i, None).unwrap();
    }

    // 지연 복구 발동 -> 0번 슬롯 교체되며 generation 증가
    let repairs = fsm.repair(&kzg, &root, &proofs).unwrap();
    assert!(repairs.iter().any(|r| r.repaired_slot == 0));
    let shard_before_zombie = fsm.slots[0].shard.clone();

    // 늦게 복귀한 옛날 0번 좀비 노드가 이전 generation(0)으로 복귀 시도 -> 차단되어야 함
    let returned = fsm.return_node(0, gen0, 20).unwrap();
    assert!(!returned);
    assert_eq!(fsm.slots[0].shard, shard_before_zombie);
    assert!(fsm.slots[0].state != NodeState::Online);
}

#[test]
fn rejects_fraudulent_root_swap_and_slashes_dishonest_aggregator_heartbeat() {
    let (kzg, mut exec, _bft, _validators, node_keys, descriptors, roster, epoch_seed) =
        setup_network_and_swarm();

    let payload = vec![0x55u8; 4096];
    let shards = encode(&payload, 30, TEST_N, 55).unwrap();
    let fps: Vec<Scalar> = shards.iter().map(|s| s.fingerprint()).collect();
    let root = kzg.commit(&fps).unwrap();
    let proofs: Vec<[u8; 48]> = (0..TEST_N).map(|i| kzg.open(&fps, i).unwrap()).collect();

    let member_root = compute_member_verkle_root(&kzg, &roster).unwrap();
    exec.init_swarm(0, roster.clone(), member_root, root, 10_000)
        .unwrap();
    let fsm = LazyRepairFsm::new(shards, 45, 60).unwrap();

    let agg_pk = roster[0];
    let agg_idx = descriptors
        .iter()
        .position(|d| d.pubkey_p256 == agg_pk)
        .unwrap();
    let agg_key = &node_keys[agg_idx];

    // 1. 반장이 12번 온라인 노드에게 Heartbeat 생존 서명을 발급한 뒤, 정산 비트맵에서는 고의로 결석(0) 조작
    let pong_receipt = issue_heartbeat_ack(0, 1, 12, agg_key);
    let malicious_bitmap = fsm.uptime_bitmap() & !(1u128 << 12);
    let ckpt_tx = build_checkpoint_with_bitmap(
        0,
        1,
        &epoch_seed,
        &kzg,
        &fsm,
        malicious_bitmap,
        &fps,
        &proofs,
        Vec::new(),
        0,
        agg_key,
    )
    .unwrap();
    exec.execute(ckpt_tx, &kzg, &epoch_seed).unwrap();

    // 피해 노드(12번)가 생존 영수증을 L1에 제출 -> 반장 담보금 슬래싱 & 피해자 보상 지급
    let agg_stake_before = exec.db.nodes[&agg_pk].stake;
    let victim_pk = roster[12];
    let victim_reward_before = exec.db.nodes[&victim_pk].reward_balance;

    exec.execute(
        NativeTransaction::SubmitHeartbeatFaultProof {
            swarm_id: 0,
            epoch: 1,
            node_slot: 12,
            aggregator_slot: 0,
            signed_pong_receipt: pong_receipt,
        },
        &kzg,
        &epoch_seed,
    )
    .unwrap();

    assert!(exec.db.nodes[&agg_pk].stake < agg_stake_before);
    assert!(exec.db.nodes[&agg_pk].slashed);
    assert!(exec.db.nodes[&victim_pk].reward_balance > victim_reward_before);

    // 2. 가짜 복구 계보(동형 등식 불일치)로 루트 교체 시도 시 L1이 거부해야 함
    let mut forged_tx = build_checkpoint(
        0,
        2,
        &epoch_seed,
        &kzg,
        &fsm,
        &fps,
        &proofs,
        vec![RepairEntry {
            repaired_slot: 5,
            parent_slot_a: 1,
            parent_slot_b: 2,
            factor_b: scalar_to_bytes(&Scalar::from(99u64)), // 실제 데이터와 맞지 않는 거짓 계수
        }],
        0,
        agg_key,
    )
    .unwrap();
    if let NativeTransaction::SubmitSwarmCheckpoint {
        ref mut new_blobs_root,
        ..
    } = forged_tx
    {
        // 루트는 그대로인데 잘못된 factor_b 계수 보고 -> 동형성 검증 실패
        *new_blobs_root = root;
    }
    let err = exec.execute(forged_tx, &kzg, &epoch_seed).unwrap_err();
    assert!(matches!(err, L1Error::BadProof));
}

#[test]
fn delayed_slashing_triggers_after_grace_period_and_replaces_from_standby() {
    let (kzg, mut exec, _bft, _validators, node_keys, descriptors, roster, epoch_seed) =
        setup_network_and_swarm();

    let payload = vec![0x77u8; 4096];
    let shards = encode(&payload, 30, TEST_N, 77).unwrap();
    let fps: Vec<Scalar> = shards.iter().map(|s| s.fingerprint()).collect();
    let root = kzg.commit(&fps).unwrap();
    let proofs: Vec<[u8; 48]> = (0..TEST_N).map(|i| kzg.open(&fps, i).unwrap()).collect();

    let initial_member_root = compute_member_verkle_root(&kzg, &roster).unwrap();
    exec.init_swarm(0, roster.clone(), initial_member_root, root, 20_000)
        .unwrap();
    let fsm = LazyRepairFsm::new(shards, 45, 60).unwrap();

    let agg_pk = roster[0];
    let agg_idx = descriptors
        .iter()
        .position(|d| d.pubkey_p256 == agg_pk)
        .unwrap();
    let agg_key = &node_keys[agg_idx];

    let dead_slot_pk = roster[15];
    let initial_standby_len = exec.db.standby_pool.len();
    let bitmap_without_15 = fsm.uptime_bitmap() & !(1u128 << 15);

    // 유예 기간(4 에포크) 중 1~3 에포크까지는 슬래싱 유예됨
    for epoch in 1..=3u64 {
        let tx = build_checkpoint_with_bitmap(
            0,
            epoch,
            &epoch_seed,
            &kzg,
            &fsm,
            bitmap_without_15,
            &fps,
            &proofs,
            Vec::new(),
            0,
            agg_key,
        )
        .unwrap();
        let receipt = exec.execute(tx, &kzg, &epoch_seed).unwrap();
        assert_eq!(receipt.slashed_amount, 0);
        assert!(!exec.db.nodes[&dead_slot_pk].slashed);
    }

    // 4번째 연속 오프라인 에포크 도달 -> 지연 슬래싱 발동 & Standby Pool에서 15번 슬롯 신규 교체!
    let tx4 = build_checkpoint_with_bitmap(
        0,
        4,
        &epoch_seed,
        &kzg,
        &fsm,
        bitmap_without_15,
        &fps,
        &proofs,
        Vec::new(),
        0,
        agg_key,
    )
    .unwrap();
    let receipt4 = exec.execute(tx4, &kzg, &epoch_seed).unwrap();
    assert!(receipt4.slashed_amount > 0);
    assert!(exec.db.nodes[&dead_slot_pk].slashed);
    assert_eq!(exec.db.standby_pool.len(), initial_standby_len - 1);
    assert_ne!(exec.db.swarm_rosters[&0][15], dead_slot_pk);
    let updated_member_root = exec.db.get_swarm(0).unwrap().member_verkle_root;
    assert_ne!(updated_member_root, initial_member_root);
    assert_eq!(
        updated_member_root,
        compute_member_verkle_root(&kzg, &exec.db.swarm_rosters[&0]).unwrap()
    );
}

#[test]
fn rejects_out_of_order_aggregator_and_tampered_unchanged_slot_on_repair() {
    let (kzg, mut exec, _bft, _validators, node_keys, descriptors, roster, epoch_seed) =
        setup_network_and_swarm();

    let payload: Vec<u8> = (0..8_192).map(|i| ((i * 19 + 3) % 251) as u8).collect();
    let shards = encode(&payload, 30, TEST_N, 88).unwrap();
    let init_fps: Vec<Scalar> = shards.iter().map(|s| s.fingerprint()).collect();
    let init_root = kzg.commit(&init_fps).unwrap();
    let init_proofs: Vec<[u8; 48]> = (0..TEST_N)
        .map(|i| kzg.open(&init_fps, i).unwrap())
        .collect();

    let member_root = compute_member_verkle_root(&kzg, &roster).unwrap();
    exec.init_swarm(0, roster.clone(), member_root, init_root, 10_000)
        .unwrap();

    // 1. 0번 슬롯이 온라인인데 2번 슬롯이 반장 권한으로 제출 시도 -> Unauthorized
    let fsm_all_online = LazyRepairFsm::new(shards.clone(), 45, 60).unwrap();
    let slot2_idx = descriptors
        .iter()
        .position(|d| d.pubkey_p256 == roster[2])
        .unwrap();
    let premature_tx = build_checkpoint_with_bitmap(
        0,
        1,
        &epoch_seed,
        &kzg,
        &fsm_all_online,
        fsm_all_online.uptime_bitmap(),
        &init_fps,
        &init_proofs,
        Vec::new(),
        2,
        &node_keys[slot2_idx],
    )
    .unwrap();
    assert!(matches!(
        exec.execute(premature_tx, &kzg, &epoch_seed),
        Err(L1Error::Unauthorized)
    ));

    // 2. 정상 지연 복구 중 비-복구(unchanged) 슬롯의 조각 심볼을 변조한 루트 교체 -> BadProof
    let mut fsm = LazyRepairFsm::new(shards, 45, 60).unwrap();
    for i in 0..55 {
        fsm.drop_node(i, Some(10)).unwrap();
    }
    let repair_log = fsm.repair(&kzg, &init_root, &init_proofs).unwrap();
    assert_eq!(repair_log.len(), 15);

    let agg_slot = select_active_aggregator(&fsm).unwrap();
    let agg_idx = descriptors
        .iter()
        .position(|d| d.pubkey_p256 == roster[agg_slot as usize])
        .unwrap();
    let unchanged_slot =
        expected_unchanged_slot_index(&epoch_seed, 0, 1, &repair_log, TEST_N).unwrap();

    let mut tampered_fsm = fsm.clone();
    tampered_fsm.slots[unchanged_slot as usize]
        .shard
        .as_mut()
        .unwrap()
        .symbols[0] += Scalar::from(1u64);

    let tampered_tx = build_checkpoint(
        0,
        1,
        &epoch_seed,
        &kzg,
        &tampered_fsm,
        &init_fps,
        &init_proofs,
        repair_log.clone(),
        agg_slot,
        &node_keys[agg_idx],
    )
    .unwrap();
    assert!(matches!(
        exec.execute(tampered_tx, &kzg, &epoch_seed),
        Err(L1Error::BadProof)
    ));

    // 변조되지 않은 정상 FSM으로 제출하면 성공
    let valid_tx = build_checkpoint(
        0,
        1,
        &epoch_seed,
        &kzg,
        &fsm,
        &init_fps,
        &init_proofs,
        repair_log,
        agg_slot,
        &node_keys[agg_idx],
    )
    .unwrap();
    exec.execute(valid_tx, &kzg, &epoch_seed).unwrap();
}

#[test]
fn auto_shuffled_adaptive_swarm_aligns_onchain_and_fsm_parameters() {
    const NODE_COUNT: usize = 50;

    let mut rng = ChaCha8Rng::seed_from_u64(505);
    let kzg = Kzg::setup(MAX_SWARM_SIZE - 1, &mut rng);
    let mut exec = Executor::new(ExecutorConfig::default());
    let epoch_seed = [0xCDu8; 32];

    let mut node_keys = Vec::with_capacity(NODE_COUNT);
    let mut node_pks = Vec::with_capacity(NODE_COUNT);
    for i in 0..NODE_COUNT {
        let sk = test_signing_key(700 + i as u64);
        let subnet = i as u16;
        let country = (i % 8) as u8;
        let (pk, sig) = sign_registration(&sk, exec.config.chain_id, subnet, country, 1_500);
        exec.execute(
            NativeTransaction::RegisterMobileNode {
                pubkey_p256: pk,
                hw_attestation_sig: sig,
                ip_subnet_hash: subnet,
                country_code: country,
                stake: 1_500,
            },
            &kzg,
            &epoch_seed,
        )
        .unwrap();
        node_keys.push(sk);
        node_pks.push(pk);
    }

    let formed = exec
        .auto_shuffle_standby_swarms(&kzg, &epoch_seed, 20_000)
        .unwrap();
    assert_eq!(formed, vec![0]);

    let expected_n = swarm_sizes(NODE_COUNT)[0];
    let expected_params = swarm_params(expected_n, DEFAULT_UPTIME_BPS).unwrap();
    let swarm = exec.db.get_swarm(0).unwrap().clone();
    assert_eq!(swarm.swarm_size_n, expected_params.n);
    assert_eq!(swarm.min_threshold_k, expected_params.k);
    assert_eq!(swarm.lazy_repair_trigger, expected_params.t_repair);
    assert_eq!(swarm.lazy_repair_target, expected_params.t_target);
    assert_eq!(exec.db.standby_pool.len(), NODE_COUNT - expected_n);

    let n = swarm.swarm_size_n as usize;
    let k = swarm.min_threshold_k as usize;
    let t_repair = swarm.lazy_repair_trigger as usize;
    let t_target = swarm.lazy_repair_target as usize;
    let roster = exec.db.swarm_rosters[&0].clone();

    let payload: Vec<u8> = (0..4_096).map(|i| ((i * 31 + 5) % 249) as u8).collect();
    let shards = encode(&payload, k, n, 707).unwrap();
    let init_fps: Vec<Scalar> = shards.iter().map(|s| s.fingerprint()).collect();
    let init_root = kzg.commit(&init_fps).unwrap();
    let init_proofs: Vec<[u8; 48]> = (0..n).map(|i| kzg.open(&init_fps, i).unwrap()).collect();

    let mut fsm = LazyRepairFsm::new(shards, t_repair, t_target).unwrap();
    for i in 0..(n - t_repair) {
        fsm.drop_node(i, Some(10)).unwrap();
    }
    assert_eq!(fsm.active_shard_count(), t_repair);

    let repair_log = fsm.repair(&kzg, &init_root, &init_proofs).unwrap();
    assert_eq!(repair_log.len(), t_target - t_repair);

    let agg_slot = select_active_aggregator(&fsm).unwrap();
    assert_eq!(agg_slot as usize, n - t_repair);
    let agg_idx = node_pks
        .iter()
        .position(|pk| *pk == roster[agg_slot as usize])
        .unwrap();

    let ckpt = build_checkpoint(
        0,
        1,
        &epoch_seed,
        &kzg,
        &fsm,
        &init_fps,
        &init_proofs,
        repair_log,
        agg_slot,
        &node_keys[agg_idx],
    )
    .unwrap();
    let receipt = exec.execute(ckpt, &kzg, &epoch_seed).unwrap();
    assert_ne!(receipt.active_blobs_root, Some(init_root));
    assert_eq!(exec.db.get_swarm(0).unwrap().last_epoch_settled, 1);

    let decoded = decode(&fsm.accessible_shards()).unwrap();
    assert_eq!(decoded, payload);
}
