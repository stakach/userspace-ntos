#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RUN_LOG="${RUN_LOG:-$ROOT/.tmp/run-live-device-action-$(date +%Y%m%d-%H%M%S).log}"
BOOT_TIMEOUT_SECONDS="${BOOT_TIMEOUT_SECONDS:-900}"

NTOS_IMAGE_PROFILE=live-device-action \
NTOS_GENERATED_E1000_COUNT=2 \
RUN_LOG="$RUN_LOG" \
BOOT_TIMEOUT_SECONDS="$BOOT_TIMEOUT_SECONDS" \
./run.sh \
  -netdev user,id=ntnet1 \
  -device e1000,netdev=ntnet1

require_fixed() {
  local text="$1"
  local description="$2"
  if ! grep -Fq "$text" "$RUN_LOG"; then
    printf 'live-device-action integration failure: %s\nlog: %s\n' "$description" "$RUN_LOG" >&2
    exit 1
  fi
}

require_log() {
  local pattern="$1"
  local description="$2"
  if ! grep -Eq "$pattern" "$RUN_LOG"; then
    printf 'live-device-action integration failure: %s\nlog: %s\n' "$description" "$RUN_LOG" >&2
    exit 1
  fi
}

instance='PCI\VEN_8086&DEV_100E\3&11583659&0&20'
require_fixed "[pnp-live-action] claimed " 'CM action was not claimed'
require_fixed "[pnp-live-action] delivered " 'user-mode PnP did not receive the action'
require_fixed "[pnp-live-action] retired " 'terminal action was not acknowledged to CM'
require_fixed "[driver-launch] config PnP AddDevice service=E1000 devnode=$instance" \
  'the dynamically reported NIC did not execute real AddDevice'
require_log \
  '\[pnp-live-proof\] generation/sequence/token=[^ ]+ kind=arrival status/reply=0x0*0/0x0*0 empty-after-ack=1 instance=PCI\\VEN_8086&DEV_100E\\3&11583659&0&20' \
  'the exact arrival/result/reply/empty-claim proof row is incomplete'
require_fixed \
  '[pnp-live-proof] summary claims/rows/success/failed=1/1/1/0 empty-after-ack/active/reply-tail=1/0/0' \
  'the live action ledger is not exact and leak-free'
require_fixed 'PASS exec_live_device_actions_exact' 'the generic live-action gate failed'
require_fixed 'PASS exec_explorer_shell_chrome_painted' 'desktop paint regressed'
require_fixed '[microtest sentinel matched -- exiting QEMU]' 'QEMU did not exit through the sentinel'

printf 'live-device-action integration passed: %s\n' "$RUN_LOG"
