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

require_log \
  '\[native-driver-load\] NtLoadDriver calls/terminal/replied=1/1/1 .*reply-failures/protocol-errors/pending=0/0/0 .*success/already-loaded/failed=1/0/0' \
  'SCM did not receive one exact successful load-only NtLoadDriver reply'

for instance in 0001 0002; do
  devnode="ROOT\\USERSPACE_NTOS_PENDING_START\\$instance"
  require_fixed \
    "[driver-launch] config PnP AddDevice service=PendingStartTest devnode=$devnode" \
    "fixture devnode $instance was not presented to the generic PnP path"
done

proof_rows=0
while IFS= read -r line; do
  if [[ "$line" == *'[pnp-pending-proof] irp='* \
    && "$line" == *' status=0x00000000 stages=0x0000007f irp-retired=1 observed=1'* ]]; then
    proof_rows=$((proof_rows + 1))
  fi
done < "$RUN_LOG"
if [[ "$proof_rows" -ne 2 ]]; then
  printf 'pending-start integration failure: expected two exact successful generic proof rows, got %s\nlog: %s\n' \
    "$proof_rows" "$RUN_LOG" >&2
  exit 1
fi

require_fixed \
  '[pnp-pending-proof] summary rows/success/failed/incomplete=2/2/0/0 active/retained-irps/violations/duplicates=0/0/0/0' \
  'generic per-devnode pending START ledger was not exact and leak-free'

require_log \
  'final config PnP summary .*terminal/failed/pending/pending-observed/indeterminate=[0-9]+/0/0/2/0' \
  'generic PnP summary did not retire both pending devnodes exactly'
require_log 'PASS exec_explorer_shell_chrome_painted' 'desktop paint regressed'
require_log '\[microtest sentinel matched -- exiting QEMU\]' 'QEMU did not exit through the sentinel'

printf 'pending-start integration passed: %s\n' "$RUN_LOG"
