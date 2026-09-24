#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RUN_LOG="${RUN_LOG:-$ROOT/.tmp/run-seh-driver-integration-$(date +%Y%m%d-%H%M%S).log}"
BOOT_TIMEOUT_SECONDS="${BOOT_TIMEOUT_SECONDS:-900}"
POST_READY_SECONDS="${POST_READY_SECONDS:-2}"
if [[ ! "$POST_READY_SECONDS" =~ ^[0-9]+$ ]] || (( POST_READY_SECONDS < 1 || POST_READY_SECONDS > 3600 )); then
  printf 'POST_READY_SECONDS must be 1..3600\n' >&2
  exit 2
fi
DESKTOP=0
if [[ "${1:-}" == "--desktop" ]]; then
  DESKTOP=1
  shift
fi

bash tests/native/driver_seh/build.sh

if (( DESKTOP )); then
  NTOS_IMAGE_PROFILE=seh-driver \
  RUN_LOG="$RUN_LOG" \
  BOOT_TIMEOUT_SECONDS="$BOOT_TIMEOUT_SECONDS" \
  ./run.sh --desktop "$@"
else
  NTOS_IMAGE_PROFILE=seh-driver ./run.sh --build-only
  : > "$RUN_LOG"
  set +e
  python3 scripts/run_with_timeout.py \
    --seconds "$BOOT_TIMEOUT_SECONDS" \
    --cwd "$ROOT/rust-micro" \
    --failure-file "$RUN_LOG" \
    --failure-text '[provider-bugcheck] terminal' \
    --ready-file "$RUN_LOG" \
    --ready-text '[seh-native-proof-complete]' \
    --post-ready-seconds "$POST_READY_SECONDS" \
    -- ./scripts/run_specs.sh "$@" 2>&1 | tee -a "$RUN_LOG"
  rc=${PIPESTATUS[0]}
  set -e
  # The shared timeout runner uses 124 when it deliberately stops QEMU after the ready marker.
  # Accept that code only with the driver-emitted marker; an ordinary boot timeout has no marker.
  if { (( rc != 0 && rc != 124 )) || ! grep -Fq '[seh-native-proof-complete]' "$RUN_LOG"; } \
      || grep -Fq '[provider-bugcheck] terminal' "$RUN_LOG" \
      || grep -Fq '[pump] WALL' "$RUN_LOG"; then
    printf 'native SEH integration failure: boot stopped before driver proof (status %s)\nlog: %s\n' "$rc" "$RUN_LOG" >&2
    exit 1
  fi
fi

require_fixed() {
  local text="$1"
  local description="$2"
  if ! grep -Fq "$text" "$RUN_LOG"; then
    printf 'native SEH integration failure: %s\nlog: %s\n' "$description" "$RUN_LOG" >&2
    exit 1
  fi
}

require_fixed \
  '[driver-launch] launching boot/system service SehDriverTest path=' \
  'registry-selected native driver was not launched'
require_fixed \
  '[driver-launch] loaded reactos\system32\drivers\driver_seh.sys' \
  'native driver image was not loaded'
require_fixed \
  '[driver-launch] provider singleton published mup.sys' \
  'registry-selected Mup did not complete DriverEntry'
if grep -Fq '[driver-launch] lifecycle unload service=Mup' "$RUN_LOG"; then
  printf 'native SEH integration failure: boot lifecycle unloaded Mup\nlog: %s\n' "$RUN_LOG" >&2
  exit 1
fi
# Demand faults may print between bytes of the component's DbgPrint. Strip only those kernel
# fault diagnostics before matching the driver-emitted evidence; keep every proof byte intact.
if ! perl -0pe 's/\[user #PF:[^\n]*\]\n//g' "$RUN_LOG" | \
    grep -F '[seh-native-proof] status=0x00000000 entered=1 after-raise=0 finally=1 caught=1 caught-code=0xc0000022 returned-before-catch=0' >/dev/null; then
  printf 'native SEH integration failure: native raise/finally/except evidence was not exact\nlog: %s\n' "$RUN_LOG" >&2
  exit 1
fi
if ! perl -0pe 's/\[user #PF:[^\n]*\]\n//g' "$RUN_LOG" | \
    grep -F '[seh-unwind-proof] finally=1 after-call=0 landed=1 bare-after=0 bare-landed=1' >/dev/null; then
  printf 'native SEH integration failure: target unwind evidence was not exact\nlog: %s\n' "$RUN_LOG" >&2
  exit 1
fi
if ! perl -0pe 's/\[user #PF:[^\n]*\]\n//g' "$RUN_LOG" | \
    grep -F '[seh-collision-proof] finally=1 inner-after=0 outer-after=0 landed=1' >/dev/null; then
  printf 'native SEH integration failure: collided unwind evidence was not exact\nlog: %s\n' "$RUN_LOG" >&2
  exit 1
fi
if (( DESKTOP )); then
  require_fixed 'PASS exec_explorer_shell_chrome_painted' 'desktop paint regressed'
  require_fixed '[microtest sentinel matched -- exiting QEMU]' 'QEMU did not exit through the sentinel'
else
  require_fixed '[seh-native-proof-complete]' 'native proof completion was not observed'
fi

printf 'native SEH integration passed: %s\n' "$RUN_LOG"
