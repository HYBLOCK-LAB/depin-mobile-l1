# DePIN Mobile Storage L1 (`depin-mobile-l1`)

고이탈률(High-Churn) 모바일 유휴 스토리지 환경을 위한 가상 스웜(Virtual Swarm) 기반 L1 블록체인 프로토콜 순수 Rust 구현체입니다.

---

## 1. 아키텍처 구성 (Crates & Binaries)

- **`crates/1-l1-state-engine`**:
  - `VirtualSwarmState` (148B 고정 헤더, 온체인 상태 98.3% 절감)
  - VRF + IP/국가 다양성 셔플러 & Zero-Tx 파일 라우터
  - `RepairEntry` VRF 동형 감사, 5% 반장 보너스, `HeartbeatFaultProof` 슬래싱 실행기
  - 순수 Rust 2단계(Prevote/Precommit) `>2/3` 정족수 BFT 합의 엔진
- **`crates/2-verkle-fountain`**:
  - $\mathbb{F}_p$ (`BLS12-381 Fr`) 소수체 선형 결합 파운틴 코딩 ($k=30, n=100$)
  - 0.02ms 로컬 선형 결합 복구 및 가우스-조르당 소거법 복원/랭크 엔진
  - 2단계 32B 선형 동형 지문 + 라그랑주 KZG 커밋먼트 (48B Verkle 루트)
  - 타원곡선 점 덧셈 기반 $O(1)$ 비잔틴 오염 조각 색출기 (`verify_homomorphic_repair`, 3.6ms)
- **`crates/3-swarm-protocol`**:
  - 안전버퍼($T_{\text{repair}}=45$) 지연 복구 상태 머신 (`generation` 가드 및 생존 노드 임시 보관)
  - 0번 → 1번 → 2번 반장 순번 자동 승계 및 단일 체크포인트 트랜잭션 조립기
  - Paired RNG 기반 24시간 이산 사건 Churn 시뮬레이터 및 임계값 스윕
- **`crates/4-node-network`**:
  - 4바이트 길이 접두어 TCP P2P 프로토콜 (`Ping`, `StoreShard`, `FetchShard`, `BftPropose`, `BftCommit`)
  - 원자적 디스크 영속성 (`l1_snapshot.json`, `blocks.jsonl` WAL, 슬롯별 조각/메타데이터)
  - L1 검증자 데몬 (`l1_daemon.rs`) 및 모바일 스토리지 노드 데몬 (`storage_daemon.rs`)
  - 분산 클러스터 맵 생성 및 병렬 업로드/다운로드 클라이언트 라이브러리 (`client.rs`)
- **`bin/depin-node`**: L1 검증자(`validator`) 및 모바일 스토리지(`storage`) OS 데몬 프로세스
- **`bin/depin-cli`**: 클러스터 초기화·업로드·에포크 사이클 트리거·다운로드 CLI
- **`bin/node-benchmark`**: 3개 코어 영역 마이크로 벤치마크 및 비정상/공격 시나리오 통합 테스트 러너
- **`scripts/live_demo.sh`**: 실제 14개 OS 프로세스(L1 검증자 4대 + 100슬롯 스토리지 노드 10대) 장애 복구 라이브 데모

---

## 2. 검증 및 벤치마크 결과

- **테스트 스위트 (`cargo test --workspace`)**:
  - 단위·통합·네트워크 E2E 총 **41건 전원 통과 (0 failed)**
- **실측 벤치마크 성능**:
  - 1MB 페이로드 파운틴 인코딩: **63.856 ms**
  - 2단계 동형 지문 + 48B Verkle 루트 생성: **6.045 ms**
  - 로컬 $\mathbb{F}_p$ 조각 복구: **0.021 ms**
  - $O(1)$ 타원곡선 점 덧셈 동형 오염 검증: **3.619 ms**
  - 30개 조각 가우스-조르당 디코딩: **24.002 ms**
  - 가상 스웜 상태 크기: **148 Bytes (기존 8,900B 대비 98.3% 압축)**
  - 체크포인트 + 복구 감사 + 3/4 BFT 블록 확정 시간: **9.224 ms**
  - 24시간 모바일 Churn 시뮬레이션: **복구 트래픽 99% 이상 절감 (0.00 ~ 0.11 GB)**, **생존율 100%**

---

## 3. 실행 방법

```bash
# 1. 전체 워크스페이스 단위 및 E2E 테스트 (41건)
cargo test --workspace

# 2. 3개 코어 영역 통합 벤치마크 및 CSV 리포트 생성
cargo run --release --bin node-benchmark

# 3. 14개 실제 프로세스 장애·복구·다운로드 라이브 데모
bash scripts/live_demo.sh
```
