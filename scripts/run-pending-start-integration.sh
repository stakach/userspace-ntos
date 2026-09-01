#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RUN_LOG="${RUN_LOG:-$ROOT/.tmp/run-pending-start-integration-$(date +%Y%m%d-%H%M%S).log}"
BOOT_TIMEOUT_SECONDS="${BOOT_TIMEOUT_SECONDS:-900}"

NTOS_IMAGE_PROFILE=pending-start \
RUN_LOG="$RUN_LOG" \
BOOT_TIMEOUT_SECONDS="$BOOT_TIMEOUT_SECONDS" \
./run.sh

require_log() {
  local pattern="$1"
  local description="$2"
  if ! grep -Eq "$pattern" "$RUN_LOG"; then
    printf 'pending-start integration failure: %s\nlog: %s\n' "$description" "$RUN_LOG" >&2
    exit 1
  fi
}

require_fixed() {
  local text="$1"
  local description="$2"
  if ! grep -Fq "$text" "$RUN_LOG"; then
    printf 'pending-start integration failure: %s\nlog: %s\n' "$description" "$RUN_LOG" >&2
    exit 1
  fi
}

require_line_parts() {
  local prefix="$1"
  local suffix="$2"
  local description="$3"
  local line
  while IFS= read -r line; do
    if [[ "$line" == *"$prefix"*"$suffix"* ]]; then
      return 0
    fi
  done < "$RUN_LOG"
  printf 'pending-start integration failure: %s\nlog: %s\n' "$description" "$RUN_LOG" >&2
  exit 1
}

require_log \
  '\[native-driver-load\] NtLoadDriver calls/terminal/replied=1/1/1 .*reply-failures/protocol-errors/pending=0/0/0 .*success/already-loaded/failed=1/0/0' \
  'SCM did not receive one exact successful load-only NtLoadDriver reply'

for instance in 0001 0002; do
  devnode="ROOT\\USERSPACE_NTOS_PENDING_START\\$instance"
  require_fixed \
    "[driver-launch] config PnP StartDevice pending service=PendingStartTest devnode=$devnode" \
    "fixture devnode $instance did not return real STATUS_PENDING"
  require_fixed \
    "[driver-launch] config PnP StartDevice service=PendingStartTest devnode=$devnode status=0x00000000" \
    "fixture devnode $instance did not complete with STATUS_SUCCESS"
  require_line_parts \
    "[driver-launch] config PnP hardware evidence service=PendingStartTest devnode=$devnode group=irq " \
    'dpc=1' \
    "fixture devnode $instance did not complete through its timer/DPC"
done

require_log \
  'final config PnP summary .*terminal/failed/pending/pending-observed/indeterminate=[0-9]+/0/0/2/0' \
  'generic PnP summary did not retire both pending devnodes exactly'
require_log 'PASS exec_explorer_shell_chrome_painted' 'desktop paint regressed'
require_log '\[microtest sentinel matched -- exiting QEMU\]' 'QEMU did not exit through the sentinel'

printf 'pending-start integration passed: %s\n' "$RUN_LOG"
