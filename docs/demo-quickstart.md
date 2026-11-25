# 로컬 파일 업로드·장애 복구 데모

이 가이드는 PR #11이 반영된 `main`의 데모 사양을 기준으로 작성했다.
검증자 4개와 스토리지 노드 10개를 로컬에서 실행해, 파일 업로드부터 일부 노드 중지, 조각 복구, 파일 다운로드까지 확인한다.

> **검증 기록:** 실행 환경과 커밋, 데모 결과, 검증자 상태 확인 결과는 8절에 기록했다.
> 단계별 예상 출력은 4절을 참고한다.

## 1. 구성과 역할

| 구성 요소 | 하는 일 |
| --- | --- |
| 검증자 | 스토리지 등록과 복구 체크포인트를 블록에 확정한다. |
| 스토리지 노드 | 파일 조각을 저장하고, 다른 노드와 통신해 복구한다. |
| CLI | 등록·업로드·다운로드·복구 실행·상태 조회를 요청한다. |

이 데모는 한 컴퓨터에서 여러 노드 프로세스를 실행한다.
노드 중지는 일부 프로세스를 종료해 재현한다.

## 2. 준비 사항

### 실행 위치

명령은 **Ubuntu 또는 WSL의 Bash 터미널**에서 실행한다. PowerShell에 그대로 입력하지 않는다.

```bash
cd ~/depin-mobile-l1
pwd
ls
```

`Cargo.toml`, `scripts`, `bin`, `crates`가 보이는 저장소 루트에서 실행한다.
저장소를 다른 경로에 받았다면 그 경로를 사용한다.
새 터미널을 열 때도 같은 저장소로 이동한다.

`~/depin-mobile-l1`과 Windows의 `/mnt/c/Users/user/depin-mobile-l1`은 서로 다른 폴더다.
두 곳에 각각 저장소가 있다면 브랜치와 수정 내용도 다를 수 있으므로 작업 위치를 섞지 않는다.

### 필요한 프로그램

- Git, Bash, Rust/Cargo
- `curl`, `shasum`
- `jq`: 검증자 상태 확인 스크립트와 JSON 확인에 사용
- `tee`, `cp`, `date`, `grep`, `sed`: 실행 기록 저장 및 로그 확인에 사용

```bash
git --version
bash --version
rustc --version
cargo --version
curl --version
shasum --version
jq --version
```

Ubuntu에 도구가 없다면 필요한 패키지를 설치한다.

```bash
sudo apt update
sudo apt install -y git build-essential pkg-config curl jq libdigest-sha-perl
```

Rust/Cargo는 Ubuntu 안에서도 사용할 수 있어야 한다.
Windows에 설치했다는 것만으로 Ubuntu에서 사용할 수 있는 것은 아니다.
`rustc --version`과 `cargo --version`이 실패하면 Rust 환경을 준비한 뒤 진행한다.

### 코드 버전 확인

PR #11이 포함된 최신 `main`을 준비한다.
다음 명령은 확인용이며, 브랜치를 바꾸거나 수정 내용을 지우지 않는다.

```bash
git status --short
git branch --show-current
git rev-parse HEAD
```

최신 `main`을 받아야 한다면 현재 변경 사항을 커밋하거나 별도로 보관한 뒤 아래를 실행한다.

```bash
git fetch origin
git switch main
git pull --ff-only origin main
git rev-parse HEAD
git rev-parse origin/main
```

`origin`이 팀 저장소를 가리킨다는 전제다. 다른 원격 이름을 쓴다면 그 이름으로 바꾼다.
오류 없이 갱신됐고 마지막 두 커밋 값이 같으면 가져온 `origin/main`과 같은 코드다.

## 3. 스크립트 확인과 데모 실행

### 실행 전에 읽을 파일

```bash
sed -n '1,260p' scripts/live_demo.sh
sed -n '1,240p' bin/depin-node/src/main.rs
sed -n '1,240p' bin/depin-cli/src/main.rs
```

각 명령은 지정한 파일의 해당 줄 범위를 보여 준다.
파일이 더 길면 이후 줄도 확인한다.
`live_demo.sh`에서 빌드, 노드 시작, 등록, 2개 파일 업로드, 노드 중지, 자율 에포크 복구 정산, 검증자 WAL 재생 복구, 다운로드 순서를 확인한다. (필요 시 `depin-cli run-cycle`로 수동 에포크 실행도 가능하다.)
노드·CLI 인자의 정확한 이름은 해당 커밋의 `main.rs` 또는 실행 파일의 `--help`를 기준으로 한다.

### 로그를 보존하면서 실행

**데모를 시작하면 `/tmp/depin-live-demo`를 비운다.**
이전 실행의 로그가 필요하면 반드시 실행 전에 다른 경로에 복사한다.

아래 명령은 이번 실행의 기록 폴더를 만들고, 기존 노드 로그가 있으면 먼저 보관한다.

```bash
EVIDENCE_DIR=$(mktemp -d "$HOME/depin-demo-evidence-$(date +%Y%m%d-%H%M%S)-XXXXXX")
printf '기록 폴더: %s\n' "$EVIDENCE_DIR"

git rev-parse HEAD | tee "$EVIDENCE_DIR/commit.txt"

if [ -d /tmp/depin-live-demo/logs ]; then
  cp -a /tmp/depin-live-demo/logs "$EVIDENCE_DIR/previous-node-logs"
fi
```

이어서 **같은 터미널**에서 실행한다.

```bash
set -o pipefail

bash scripts/live_demo.sh 2>&1 | tee "$EVIDENCE_DIR/live-demo.log"
demo_exit=${PIPESTATUS[0]}

printf 'demo exit=%s\n' "$demo_exit" | tee "$EVIDENCE_DIR/exit-code.txt"

if [ -d /tmp/depin-live-demo/logs ]; then
  cp -a /tmp/depin-live-demo/logs "$EVIDENCE_DIR/node-logs"
fi
```

- `tee`는 화면에 보이는 출력을 파일에도 저장한다.
- `2>&1`은 오류 출력도 함께 기록한다.
- `${PIPESTATUS[0]}`은 데모 스크립트의 종료 코드다. 파이프라인 직후에 저장해야 한다.
- `demo exit=0`과 아래 성공 출력을 함께 확인한다. 실패했다면 성공한 실행으로 기록하지 않는다.

기록 폴더 생성에는 일반적인 Ubuntu 환경에서 제공하는 `mktemp`를 사용한다.

## 4. 단계별 출력 읽기

아래 값은 **예상 출력 및 확인 항목**이다. 실제 로그의 줄 전체를 실행 기록에 남긴다.

| 단계 | 내부 동작 | 확인할 출력·값 |
| --- | --- | --- |
| 1–2. 빌드와 검증자 시작 | `depin-node`·`depin-cli` 빌드, 클러스터 맵 생성, 검증자 4개 시작 | `CLUSTER_MAP_WRITTEN`의 `slots=10`, 검증자별 `VALIDATOR_READY` |
| 3. 스토리지 시작·등록 | 스토리지 노드 10개 시작, `register-all`로 슬롯 등록 | `STORAGE_READY`, `REGISTERED_SLOTS count=10` |
| 4. 업로드 | 64 KiB·48 KiB 샘플 파일 2개를 인코딩해 같은 스웜의 10개 슬롯에 TCP 전송 | 다운로드에 사용할 `object_id_hex` (2건) |
| 5–6. 장애·자율 복구 | 검증자 1개와 스토리지 노드 6개 중지, 살아남은 슬롯 6이 반장을 승계해 자율 에포크(`--auto-epoch-secs 2`) 정산 | `EPOCH_SETTLED`, `aggregator_slot: 6`, `online_slots: 4`, 접근 가능한 조각 수 4 → 6 |
| 6. 체크포인트 확정 | 남은 검증자 3개가 복구 체크포인트 확정 | 체크포인트 처리 로그 및 검증자의 블록 높이·해시 |
| 7. 검증자 재시작 | 검증자 0이 이번 실행의 블록 WAL(`blocks.jsonl`)을 재생해 상태 복구 | `status`에서 블록 높이와 해시 확인 |
| 8. 다운로드·대조 | 남은 노드에서 조각을 가져와 파일 복원, 원본과 비교 | `DOWNLOAD_OK`, 원본·복원 파일의 SHA-256 일치, `LIVE DEMO PASSED` |

주요 출력을 모아서 찾으려면 같은 터미널에서 실행한다.

```bash
grep -nE 'CLUSTER_MAP_WRITTEN|VALIDATOR_READY|STORAGE_READY|REGISTERED_SLOTS|object_id_hex|aggregator_slot|online_slots|repaired_slots|DOWNLOAD_OK|SHA|sha|LIVE DEMO PASSED' "$EVIDENCE_DIR/live-demo.log"
```

일부 메시지는 노드별 로그에만 있을 수 있다.

```bash
grep -R -nE 'VALIDATOR_READY|STORAGE_READY|repaired_slots' "$EVIDENCE_DIR/node-logs"
```

검색 결과에 없다는 이유만으로 바로 실패라고 판단하지 않는다.
전체 출력과 노드 로그에서 해당 단계의 결과를 확인한다.

### 노드가 꺼져도 파일을 받을 수 있는 이유

1. **업로드할 때 복원에 사용할 중복 정보를 포함해 인코딩한다.**
   파일을 단순히 잘라서 한 조각이라도 없어지면 복원할 수 없는 형태로만 저장하는 것이 아니다.
   인코딩 방식이 요구하는 충분한 조각을 확보하면 원본을 복원할 수 있다.
2. **일부 스토리지 노드가 중지돼도 다른 노드의 조각은 남아 있다.**
   이 데모의 장애 직후 예상 온라인 슬롯 수는 4개다.
3. **살아남은 노드가 복구를 진행한다.**
   슬롯 6이 반장을 승계해 자율 에포크 정산(또는 수동 `run-cycle`) 이후 접근 가능한 조각 수가 4개에서 6개로 늘어나는지 확인한다.
   여기서 **조각 6개는 온라인 스토리지 노드가 6개라는 뜻이 아니다.**
4. **검증자는 복구 체크포인트를 확정한다.**
   스토리지가 실제 파일 조각을 다루고, 검증자는 등록·복구 상태를 블록에 반영한다.
5. **다운로드 후 해시로 원본과 대조한다.**
   `DOWNLOAD_OK`와 함께 원본·복원 파일의 SHA-256이 일치해야 파일 내용까지 같다고 확인할 수 있다.

이 문서는 현재 구현의 최소 복원 조각 수를 별도로 단정하지 않는다.
위의 4 → 6은 이 데모에서 확인할 값이며, 임의의 장애 수에서도 항상 복구된다는 보장은 아니다.

## 5. 포트와 로그 위치

| 프로세스 | 개수 | P2P 포트 | RPC 포트 |
| --- | --- | --- | --- |
| 검증자 | 4 | `19100–19103` | `19110–19113` |
| 스토리지 노드 | 10 | `19200–19209` | `19300–19309` |

- 노드별 로그: `/tmp/depin-live-demo/logs/`
- 이번 실행의 화면 출력: `$EVIDENCE_DIR/live-demo.log`
- 보관한 노드 로그: `$EVIDENCE_DIR/node-logs/`
- 실행 커밋: `$EVIDENCE_DIR/commit.txt`

노드별 파일명은 실제 목록으로 확인한다.

```bash
ls -lah /tmp/depin-live-demo/logs/
```

**데모 스크립트는 종료할 때 자신이 시작한 노드들을 정리한다.**
따라서 데모가 끝난 뒤 해당 RPC에 접속되지 않는 것은 정상일 수 있다.
로그는 남지만, 다음 데모 실행 때 작업 디렉터리를 비우므로 필요한 기록은 위와 같이 보관한다.

## 6. 검증자 상태 확인

이 절은 저장소에 `scripts/check_validators.sh`가 준비된 뒤 실행한다.
파일이 없다면 상태 확인 스크립트 작성 작업을 먼저 완료한다.

```bash
test -f scripts/check_validators.sh && echo "상태 확인 스크립트 있음"
```

검증자가 켜져 있고 **새 블록이 만들어지지 않는 시점**에 조회한다.

```bash
bash scripts/check_validators.sh \
  http://127.0.0.1:19110 \
  http://127.0.0.1:19111
check_exit=$?
printf 'check exit=%s\n' "$check_exit"
```

스크립트의 확인 기준은 다음과 같다.

| 항목 | 기대 동작 |
| --- | --- |
| 각 URL의 `/health`와 `/status` | 모두 조회한다. |
| 정상 상태 출력 | URL별 `validator_id`, `height`, `last_block_hash_hex`를 한 줄씩 출력한다. |
| 전체 정상 | 모든 주소가 정상 응답하고 높이·해시가 같으면 종료 코드 `0` |
| 비정상 | 연결 실패, HTTP·JSON 오류, 높이 또는 해시 불일치 시 문제 URL과 원인을 출력하고 종료 코드 `1` |
| 대기 시간 | 응답하지 않는 URL도 오래 기다리지 않도록 연결·전체 요청 타임아웃을 둔다. |

검증자 ID는 노드마다 다를 수 있다. 비교 대상은 블록 높이와 마지막 블록 해시다.

### 상태 확인 스크립트 리허설

데모가 끝나면 노드가 종료되므로, 아래 검증은 검증자 두 개를 별도로 실행해 진행한다. Bash, `curl`, `jq`가 필요하다.

높이·해시 비교는 새 블록이 생기지 않는 안정된 시점에 진행한다.

1. 실행 준비

`scripts/live_demo.sh`에서 해당 커밋의 검증자 시작 명령과 필요한 사전 준비를 확인한다.

터미널 A·B·C를 열고, 모두 데모를 실행한 동일한 저장소 루트로 이동한다. 아래 경로는 실제 저장소 위치에 맞게 변경한다.

```bash
cd ~/depin-mobile-l1
```

검증자마다 새 데이터 디렉터리를 사용하고, ID·포트·피어 설정을 구분한다. 데모와 동시에 실행한다면 포트가 겹치지 않도록 변경한다.

2. 검증자 두 개 실행

**터미널 B: 검증자 0 실행**

```bash
./target/release/depin-node validator \
  --id 0 \
  --p2p 127.0.0.1:19100 \
  --rpc 127.0.0.1:19110 \
  --peers 127.0.0.1:19101 \
  --validator-count 2 \
  --data-dir "$(mktemp -d /tmp/depin-check-v0.XXXXXX)"
```

**터미널 C: 검증자 1 실행**

```bash
./target/release/depin-node validator \
  --id 1 \
  --p2p 127.0.0.1:19101 \
  --rpc 127.0.0.1:19111 \
  --peers 127.0.0.1:19100 \
  --validator-count 2 \
  --data-dir "$(mktemp -d /tmp/depin-check-v1.XXXXXX)"
```

터미널 B와 C는 노드가 실행 중인 상태로 유지한다.

3. 정상 응답 확인

두 검증자의 시작이 완료되고 높이·해시가 같은 안정된 시점에, **터미널 A**에서 실행한다.

```bash
bash scripts/check_validators.sh \
  http://127.0.0.1:19110 \
  http://127.0.0.1:19111

echo "exit=$?"
```

기대 결과:

- 각 주소의 `validator_id`, `height`, `last_block_hash_hex`가 출력된다.
- 두 검증자의 높이와 해시가 같다.
- 종료 코드가 `exit=0`이다.

4. 높이·해시 불일치 확인

두 검증자가 모두 실행 중인 상태에서 **터미널 A**에서 실행한다.

아래 코드는 검증자 1의 `/status` 응답을 테스트용으로 가공한다. 실제 노드의 저장 데이터는 변경하지 않는다. 괄호 안에서 정의한 `curl` 함수는 테스트 종료 후 현재 터미널에 남지 않는다.

> 이 테스트는 상태 확인 스크립트가 `curl`을 일반 명령으로 호출하고, URL을 마지막 인자로 전달하는 경우에 적용된다.

```bash
(
  curl() {
    local body
    body=$(command curl "$@") || return $?

    if [[ "${@: -1}" == "http://127.0.0.1:19111/status" ]]; then
      jq "$TEST_FILTER" <<<"$body"
    else
      printf '%s\n' "$body"
    fi
  }
  export -f curl

  # 높이 불일치 검사
  export TEST_FILTER='.height += 1'

  echo "=== Height mismatch test ==="
  bash scripts/check_validators.sh \
    http://127.0.0.1:19110 \
    http://127.0.0.1:19111
  echo "exit=$?"

  # 해시 불일치 검사
  export TEST_FILTER='
    .last_block_hash_hex |=
      ((if .[0:1] == "0" then "1" else "0" end) + .[1:])
  '

  echo "=== Hash mismatch test ==="
  bash scripts/check_validators.sh \
    http://127.0.0.1:19110 \
    http://127.0.0.1:19111
  echo "exit=$?"
)
```

기대 결과:

- 높이 불일치 검사에서 문제가 있는 주소와 원인이 출력되고, `exit=1`을 반환한다.
- 해시 불일치 검사에서도 문제가 있는 주소와 원인이 출력되고, `exit=1`을 반환한다.

5. 검증자 종료 후 응답 실패 확인

**터미널 C에서 `Ctrl+C`**를 눌러 검증자 1만 종료한다. 터미널 B의 검증자 0은 계속 실행한다.

**터미널 A**에서 상태 확인 스크립트를 다시 실행한다.

```bash
bash scripts/check_validators.sh \
  http://127.0.0.1:19110 \
  http://127.0.0.1:19111

echo "exit=$?"
```

기대 결과:

- 종료한 검증자의 주소인 `http://127.0.0.1:19111`과 연결 실패 원인이 출력된다.
- `curl`에 설정한 타임아웃에 따라 오래 대기하지 않고 종료한다.
- 종료 코드가 `exit=1`이다.

6. 결과 기록 및 정리

각 검사의 실제 출력과 종료 코드를 기록한다.

| 검사 항목 | 기대 종료 코드 |
|---|---:|
| 두 검증자 정상 응답, 높이·해시 일치 | `0` |
| 높이 불일치 | `1` |
| 해시 불일치 | `1` |
| 검증자 한 개 종료 | `1` |

검증이 끝나면 **터미널 B에서 `Ctrl+C`**를 눌러 남아 있는 검증자 0도 종료한다.

PR에는 실행 커밋과 함께 상태 확인 스크립트의 성공·실패 출력 및 종료 코드를 남긴다.


## 7. 문제가 생겼을 때

### `/health` 대기에서 타임아웃이 발생한다

먼저 해당 노드 로그를 읽고 포트가 이미 사용 중인지 확인한다.
Ubuntu에서 `ss`를 사용할 수 있다면 다음과 같이 조회한다.

```bash
ss -ltnp | grep -E ':(1910[0-3]|1911[0-3]|1920[0-9]|1930[0-9])[[:space:]]'
```

다른 실행의 노드가 포트를 차지했는지, 빌드·시작 오류가 있었는지 확인한다.
무관한 프로세스를 일괄 종료하지 않고 해당 프로세스를 구분한다.

검증자가 실행 중이라면 RPC를 직접 확인할 수도 있다.

```bash
curl --fail --silent --show-error --connect-timeout 2 --max-time 5 \
  http://127.0.0.1:19110/health
curl --fail --silent --show-error --connect-timeout 2 --max-time 5 \
  http://127.0.0.1:19110/status | jq .
```

### 노드를 수동으로 띄웠는데 블록 WAL 또는 캐시 오류가 발생한다

머지 전 버전에서 만든 블록 WAL(`blocks.jsonl`)과 KZG 캐시를 재사용하지 말고 **새 데이터 디렉터리**로 시작한다.
자동 데모의 검증자 0 재시작은 **이번 실행에서 생성한 블록 WAL(`blocks.jsonl`)**을 재생해 상태를 복구하는 별도 단계다.

### 검증자의 높이 또는 해시가 다르다

등록이나 복구로 블록이 생성되는 중인지 확인한다.
서로 다른 시점에 상태를 읽었을 수 있으므로 블록 생성이 멈춘 뒤 다시 비교한다.
계속 다르면 각 검증자의 로그와 피어 연결 상태를 확인한다.

### SHA-256이 다르거나 `LIVE DEMO PASSED`가 없다

이번 실행은 성공으로 기록하지 않는다.
업로드의 `object_id_hex`, 복구 결과, 다운로드 결과를 순서대로 확인한다.
재실행하기 전에 현재 화면 출력과 노드 로그부터 보관한다.

## 8. 실행 기록 및 PR에 남길 내용

아래는 커밋 `13bf479505f305ce0e67150ba1d70607d1a6933e` 기준 실제 실행 기록이다.

| 항목 | 실제 결과 |
| --- | --- |
| 실행 날짜 | 2026-11-24 |
| 실행 환경 | Windows / WSL / Ubuntu 24.04.2 LTS (x86_64) |
| 도구 버전 | rustc 1.97.0 / Cargo 1.97.0 / Bash 5.2.21 |
| 실행 커밋 SHA | `13bf479505f305ce0e67150ba1d70607d1a6933e` |
| 등록 슬롯 수: 10 | `REGISTERED_SLOTS count=10` 확인 |
| 복구 후 접근 가능한 조각 수 | 6 |
| 원본 파일 SHA-256 | `2c9614632becaf172719a4a036e256c78695dff7bf80e2f82f4069e4b2873e30` |
| 복원 파일 SHA-256 | `2c9614632becaf172719a4a036e256c78695dff7bf80e2f82f4069e4b2873e30` |
| 파일 무결성 | 원본과 복원 파일의 SHA-256 일치 |
| 데모 성공 출력 | `DOWNLOAD_OK`, `LIVE DEMO PASSED` 확인 |
| 데모 종료 코드 | 0 |
| 검증자 둘 다 정상·같은 높이·해시 | 예상 0 / 실제 `exit=0`. 높이 0과 해시 일치, `OK` 출력 확인 |
| 검증자 한쪽 중지 | 예상 1 / 실제 `exit=1`. `http://127.0.0.1:19111/health` 주소와 연결 실패 원인 출력 확인 |
| 높이 불일치 | 예상 1 / 실제 `exit=1`. 두 번째 검증자의 응답 높이를 1로 변경한 뒤 해당 주소와 `MISMATCH` 출력 확인 |
| 해시 불일치 | 예상 1 / 실제 `exit=1`. 두 번째 검증자의 응답 해시 첫 글자를 변경한 뒤 해당 주소와 `MISMATCH` 출력 확인 |
| 이번 실행 기록 보관 위치 | `/home/jdlim/depin-demo-evidence/20261124-170038/` |
| 데모 기본 노드 로그 위치 | `/tmp/depin-live-demo/logs/` |

높이·해시 불일치는 `curl` 래퍼와 `jq`로 두 번째 검증자의 `/status` 응답을 가공하여 재현했다. 실제 검증자의 저장 상태는 변경하지 않았다.

PR에는 실행 커밋, 등록·복구 결과, SHA-256 대조 결과, 상태 확인 스크립트의 성공·실패 출력을 남긴다.
실행하지 않은 검증은 완료로 표시하지 않는다.

README에서 이 문서를 연결할 때는 다음 상대 링크를 사용한다.

```markdown
[로컬 데모 실행 가이드](docs/demo-quickstart.md)
```

