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
case "${SEH_FAULT_CASE:-all}" in
  all)
    SEH_FAULT_CASE=ud2 bash "$0"
    SEH_FAULT_CASE=protection bash "$0"
    exit 0
    ;;
  ud2) EXPECTED_CODE=c000001d ;;
  protection) EXPECTED_CODE=c0000005 ;;
  *) printf 'unsupported SEH fault case: %s\n' "$SEH_FAULT_CASE" >&2; exit 1 ;;
esac
RUN_LOG="${RUN_LOG:-$ROOT/.tmp/run-seh-fault-integration-$(date +%Y%m%d-%H%M%S)-$SEH_FAULT_CASE.log}"

# The isolated seh-driver image profile stages this path. Rebuild it for each serial fault case.
bash tests/native/driver_seh/build.sh "$ROOT/.tmp/native-driver-seh" "fault-$SEH_FAULT_CASE"
NTOS_IMAGE_PROFILE=seh-driver ./run.sh --build-only
: > "$RUN_LOG"
set +e
python3 scripts/run_with_timeout.py \
  --seconds "$BOOT_TIMEOUT_SECONDS" \
  --cwd "$ROOT/rust-micro" \
  --failure-file "$RUN_LOG" \
  --failure-text '[seh-fault-failed]' \
  --ready-file "$RUN_LOG" \
  --ready-text '[seh-fault-proof]' \
  --post-ready-seconds 2 \
  -- ./scripts/run_specs.sh 2>&1 | tee -a "$RUN_LOG"
rc=${PIPESTATUS[0]}
set -e

# 124 is the runner's deliberate post-ready stop; a boot timeout has no proof marker.
if { (( rc != 0 && rc != 124 )) || ! grep -Fq '[seh-fault-proof]' "$RUN_LOG"; } || \
    grep -Fq '[seh-fault-failed]' "$RUN_LOG" || \
    grep -Fq '[provider-bugcheck] terminal' "$RUN_LOG" || \
    grep -Fq '[pump] WALL' "$RUN_LOG"; then
  printf 'native SEH fault integration failed (status %s)\nlog: %s\n' "$rc" "$RUN_LOG" >&2
  exit 1
fi

require_fixed() {
  local text="$1" description="$2"
  if ! grep -Fq "$text" "$RUN_LOG"; then
    printf 'native SEH fault integration failed: %s\nlog: %s\n' "$description" "$RUN_LOG" >&2
    exit 1
  fi
}

require_fixed '[driver-launch] launching boot/system service SehDriverTest path=' \
  'registry-selected native driver was not launched'
require_fixed '[driver-launch] loaded reactos\system32\drivers\driver_seh.sys' \
  'native driver image was not loaded'
if ! perl -0pe 's/\[user #PF:[^\n]*\]\n//g' "$RUN_LOG" | \
    grep -F '[seh-native-proof] status=0x00000000 entered=1 after-raise=0 finally=1 caught=1 caught-code=0xc0000022 returned-before-catch=0' >/dev/null; then
  printf 'native SEH fault integration failed: handled prefix did not pass\nlog: %s\n' "$RUN_LOG" >&2
  exit 1
fi
if ! perl -0pe 's/\[user #PF:[^\n]*\]\n//g' "$RUN_LOG" | \
    grep -F '[seh-unwind-proof] finally=1 after-call=0 landed=1 bare-after=0 bare-landed=1' >/dev/null; then
  printf 'native SEH fault integration failed: target unwind prefix did not pass\nlog: %s\n' "$RUN_LOG" >&2
  exit 1
fi
if ! perl -0pe 's/\[user #PF:[^\n]*\]\n//g' "$RUN_LOG" | \
    grep -F '[seh-collision-proof] finally=1 inner-after=0 outer-after=0 landed=1' >/dev/null; then
  printf 'native SEH fault integration failed: collided unwind prefix did not pass\nlog: %s\n' "$RUN_LOG" >&2
  exit 1
fi
require_fixed "[seh-fault-trigger] kind=$SEH_FAULT_CASE" 'native driver did not execute the fault case'
if ! perl -0pe 's/\[user #PF:[^\n]*\]\n//g' "$RUN_LOG" | \
    grep -F "[seh-fault-proof] kind=$SEH_FAULT_CASE entered=1 after=0 caught=1 code=0x$EXPECTED_CODE" >/dev/null; then
  printf 'native SEH fault integration failed: native __except did not catch the hardware fault exactly once\nlog: %s\n' "$RUN_LOG" >&2
  exit 1
fi
printf 'native SEH fault %s passed: %s\n' "$SEH_FAULT_CASE" "$RUN_LOG"
