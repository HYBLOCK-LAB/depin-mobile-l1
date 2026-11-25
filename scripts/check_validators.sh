#!/usr/bin/env bash
# 1. /health 각 주소가 응답 가능한 상태인지 확인: 정상 응답
# 2. /status 검증자 ID, 높이, 해시 조회
# 3. 첫 번째 정상 응답을 기준으로 나머지의 status 비교: 전체 일치 여부 확인
# 4. 하나라도 오류/불일치 검출 -> 1 / 이상 없으면 -> 0
set -uo pipefail

if (( $# == 0 )); then
  echo "Usage: bash scripts/check_validators.sh RPC_URL..." >&2
  exit 1
fi

for tool in curl jq; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $tool" >&2
    exit 1
  fi
done

fetch() {
  local url="$1"
  local body

  if body=$(curl -fsS --connect-timeout 2 --max-time 5 "$url" 2>&1); then
    printf '%s\n' "$body"
  else
    printf 'ERROR %s: %s\n' "$url" "$body" >&2
    return 1
  fi
}

failed=0
reference_url=""
reference_height=""
reference_hash=""

for input_url in "$@"; do
  url="${input_url%/}"

  if ! health=$(fetch "$url/health"); then
    failed=1
    continue
  fi

  if ! jq -es '
    length == 1 and
    (.[0] | type == "object" and .ok == true)
  ' <<<"$health" >/dev/null 2>&1; then
    echo "ERROR $url/health: invalid JSON or ok is not true" >&2
    failed=1
    continue
  fi

  if ! status=$(fetch "$url/status"); then
    failed=1
    continue
  fi

  if ! fields=$(jq -ers '
    def uint:
      type == "number" and . >= 0 and . == floor;

    if length == 1 then .[0]
    else error("expected one JSON object")
    end
    |
    if type == "object"
       and (.validator_id | uint)
       and (.height | uint)
       and (.last_block_hash_hex |
         type == "string" and test("^[0-9a-fA-F]{64}$"))
    then
      [.validator_id, .height,
       (.last_block_hash_hex | ascii_downcase)] | @tsv
    else
      error("missing or invalid status fields")
    end
  ' <<<"$status" 2>/dev/null); then
    echo "ERROR $url/status: invalid JSON or missing/invalid status fields" >&2
    failed=1
    continue
  fi

  IFS=$'\t' read -r validator_id height hash <<<"$fields"

  printf '%s validator_id=%s height=%s last_block_hash_hex=%s\n' \
    "$url" "$validator_id" "$height" "$hash"

  if [[ -z "$reference_url" ]]; then
    reference_url="$url"
    reference_height="$height"
    reference_hash="$hash"
  elif [[ "$height" != "$reference_height" ||
          "$hash" != "$reference_hash" ]]; then
    printf 'MISMATCH %s: compared with %s; expected height=%s hash=%s\n' \
      "$url" "$reference_url" "$reference_height" "$reference_hash" >&2
    failed=1
  fi
done

if (( failed == 0 )); then
  echo "OK: all validators have matching height and hash"
fi

exit "$failed"
