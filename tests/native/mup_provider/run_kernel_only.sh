#!/usr/bin/env bash
# Exercise the real Mup/provider path without making win32k imports part of this gate.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT"

BOOT_TIMEOUT_SECONDS="${BOOT_TIMEOUT_SECONDS:-600}"
if ! [[ "$BOOT_TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] \
   || [ "$BOOT_TIMEOUT_SECONDS" -lt 1 ] \
   || [ "$BOOT_TIMEOUT_SECONDS" -gt 3600 ]; then
  echo "BOOT_TIMEOUT_SECONDS must be an integer from 1 through 3600" >&2
  exit 2
fi

tests/native/mup_provider/build.sh
NTOS_IMAGE_PROFILE=mup-provider NTOS_MUP_PROVIDER_KERNEL_ONLY=1 \
  ./run.sh --build-only

mkdir -p .tmp
RUN_LOG="${RUN_LOG:-$ROOT/.tmp/mup-provider-kernel-only-$(date +%Y%m%d-%H%M%S).log}"
: > "$RUN_LOG"
echo "Native Mup provider log: $RUN_LOG"
set +e
python3 scripts/run_with_timeout.py \
  --seconds "$BOOT_TIMEOUT_SECONDS" \
  --cwd "$ROOT/rust-micro" \
  --failure-file "$RUN_LOG" \
  --failure-text '[provider-bugcheck] terminal' \
  --completion-file "$RUN_LOG" \
  --completion-text '[mup-provider-close] probe-file' \
  --completion-grace-seconds 2 \
  -- ./scripts/run_specs.sh 2>&1 | tee -a "$RUN_LOG"
rc=${PIPESTATUS[0]}
set -e

if [ "$rc" != 0 ] && [ "$rc" != 3 ]; then
  echo "Mup provider boot did not complete (runner status $rc): $RUN_LOG" >&2
  exit 1
fi
if ! grep -Fq '[mup-provider-gate] kernel-only native service loop' "$RUN_LOG" \
   || grep -Fq '[win32k-import] reject image' "$RUN_LOG" \
   || ! grep -Eq '\[mup-provider-register\] status=0x00000000' "$RUN_LOG" \
   || ! grep -Eq '\[mup-provider-query\] count=[1-9][0-9]* accepted=[1-9][0-9]* .*security=1' "$RUN_LOG" \
   || ! grep -Eq '\[mup-provider-probe\] status=0x00000000 queries=[1-9][0-9]* accepted=[1-9][0-9]* file-created=[1-9][0-9]* cleaned=[1-9][0-9]*' "$RUN_LOG" \
   || ! grep -Eq '\[mup-provider-close\] probe-file closed=[1-9][0-9]*' "$RUN_LOG"; then
  echo "Mup/provider registration, query, and File lifecycle proof incomplete: $RUN_LOG" >&2
  exit 1
fi

echo "Mup/provider registration, query, and File CREATE/CLEANUP/CLOSE verified: $RUN_LOG"
