#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BOOT_TIMEOUT_SECONDS="${BOOT_TIMEOUT_SECONDS:-900}"
if ! [[ "$BOOT_TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] || \
   (( BOOT_TIMEOUT_SECONDS < 1 || BOOT_TIMEOUT_SECONDS > 3600 )); then
  printf 'BOOT_TIMEOUT_SECONDS must be between 1 and 3600\n' >&2
  exit 1
fi

RUN_LOG_PREFIX="${RUN_LOG_PREFIX:-$ROOT/.tmp/run-seh-terminal-integration-$(date +%Y%m%d-%H%M%S)}"

require_fixed() {
  local log="$1" text="$2" description="$3"
  if ! grep -Fq "$text" "$log"; then
    printf 'native SEH terminal failure: %s\nlog: %s\n' "$description" "$log" >&2
    exit 1
  fi
}

run_case() {
  local kind="$1" status="$2"
  local profile="seh-terminal-$kind"
  local out="$ROOT/.tmp/native-driver-$profile"
  local log="$RUN_LOG_PREFIX-$kind.log"
  local rc

  bash tests/native/driver_seh/build.sh "$out" "$kind"
  NTOS_IMAGE_PROFILE="$profile" ./run.sh --build-only
  : > "$log"
  set +e
  python3 scripts/run_with_timeout.py \
    --seconds "$BOOT_TIMEOUT_SECONDS" \
    --cwd "$ROOT/rust-micro" \
    --failure-file "$log" \
    --failure-text '[seh-terminal-unexpected-return]' \
    --ready-file "$log" \
    --ready-text '[provider-bugcheck] terminal' \
    --post-ready-seconds 2 \
    -- ./scripts/run_specs.sh 2>&1 | tee -a "$log"
  rc=${PIPESTATUS[0]}
  set -e

  # 124 is the runner's deliberate post-ready QEMU stop. An ordinary timeout lacks the marker.
  if { (( rc != 0 && rc != 124 )) || ! grep -Fq '[provider-bugcheck] terminal' "$log"; } || \
      grep -Fq '[seh-terminal-unexpected-return]' "$log" || \
      grep -Fq '[seh-native-proof-complete]' "$log" || \
      grep -Fq '[fsd-seh] unwind capture refused' "$log" || \
      grep -Fq '[pump] WALL' "$log"; then
    printf 'native SEH terminal failure: %s stopped without the expected fatal report (status %s)\nlog: %s\n' \
      "$kind" "$rc" "$log" >&2
    exit 1
  fi

  require_fixed "$log" '[driver-launch] launching boot/system service SehDriverTest path=' \
    'registry-selected native driver was not launched'
  require_fixed "$log" '[driver-launch] loaded reactos\system32\drivers\driver_seh.sys' \
    'native driver image was not loaded'
  if ! perl -0pe 's/\[user #PF:[^\n]*\]\n//g' "$log" | \
      grep -F '[seh-native-proof] status=0x00000000 entered=1 after-raise=0 finally=1 caught=1 caught-code=0xc0000022 returned-before-catch=0' >/dev/null; then
    printf 'native SEH terminal failure: handled prefix did not pass\nlog: %s\n' "$log" >&2
    exit 1
  fi
  if ! perl -0pe 's/\[user #PF:[^\n]*\]\n//g' "$log" | \
      grep -F '[seh-unwind-proof] finally=1 after-call=0 landed=1 bare-after=0 bare-landed=1' >/dev/null; then
    printf 'native SEH terminal failure: target unwind prefix did not pass\nlog: %s\n' "$log" >&2
    exit 1
  fi
  if ! perl -0pe 's/\[user #PF:[^\n]*\]\n//g' "$log" | \
      grep -F '[seh-collision-proof] finally=1 inner-after=0 outer-after=0 landed=1' >/dev/null; then
    printf 'native SEH terminal failure: collided unwind prefix did not pass\nlog: %s\n' "$log" >&2
    exit 1
  fi
  require_fixed "$log" "[seh-terminal-trigger] kind=$kind code=0x$status" \
    'the native driver did not enter its terminal branch'
  require_fixed "$log" "[provider-bugcheck] code=0x0x0000001e parameter=0x0x000000000x$status" \
    'the provider did not report the native exception code'
  require_fixed "$log" '[provider-bugcheck] reporting-tcb-suspend=0' \
    'the reporting provider thread was not suspended'
  require_fixed "$log" '[provider-bugcheck] terminal' \
    'the provider did not enter its terminal state'
  printf 'native SEH terminal %s passed: %s\n' "$kind" "$log"
}

run_case unhandled c0000022
run_case exit c0000027
