#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RUN_LOG="${RUN_LOG:-$ROOT/.tmp/run-seh-driver-integration-$(date +%Y%m%d-%H%M%S).log}"
BOOT_TIMEOUT_SECONDS="${BOOT_TIMEOUT_SECONDS:-900}"

bash tests/native/driver_seh/build.sh

NTOS_IMAGE_PROFILE=seh-driver \
RUN_LOG="$RUN_LOG" \
BOOT_TIMEOUT_SECONDS="$BOOT_TIMEOUT_SECONDS" \
./run.sh "$@"

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
  '[seh-native-proof] status=0x00000000 entered=1 after-raise=0 finally=1 caught=1 caught-code=0xc0000022 returned-before-catch=0' \
  'native raise/finally/except evidence was not exact'
require_fixed 'PASS exec_explorer_shell_chrome_painted' 'desktop paint regressed'
require_fixed '[microtest sentinel matched -- exiting QEMU]' 'QEMU did not exit through the sentinel'

printf 'native SEH integration passed: %s\n' "$RUN_LOG"
