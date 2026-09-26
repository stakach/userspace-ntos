#!/usr/bin/env bash
# Exercise the real Mup/provider path without making win32k imports part of this gate.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT"

BOOT_TIMEOUT_SECONDS="${BOOT_TIMEOUT_SECONDS:-180}"
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
  --completion-text '[zw-read-file-verified]' \
  --completion-grace-seconds 15 \
  -- ./scripts/run_specs.sh 2>&1 | tee -a "$RUN_LOG"
rc=${PIPESTATUS[0]}
set -e

if [ "$rc" != 0 ] && [ "$rc" != 3 ]; then
  echo "Mup provider boot did not complete (runner status $rc): $RUN_LOG" >&2
  exit 1
fi
# An accepted MUP query requires both completed provider registration and a non-null security
# context. Serial DbgPrint can interleave within a line, so use the final probe's counters rather
# than the individual query trace for that proof.
if ! grep -Fq '[mup-provider-gate] kernel-only native service loop' "$RUN_LOG" \
   || ! grep -Fq 'PASS exec_mounted_volume_external_file_dispatch_font_read' "$RUN_LOG" \
   || grep -Fq '[win32k-import] reject image' "$RUN_LOG" \
   || grep -Fq '!@src/component_scheduler.rs:' "$RUN_LOG" \
   || ! grep -Eq '\[mup-provider-probe\] status=0x00000000 queries=[1-9][0-9]* accepted=[1-9][0-9]* ' "$RUN_LOG" \
   || { ! grep -Eq '\[mup-provider-create\] probe-file created=[1-9][0-9]*' "$RUN_LOG" \
        && ! grep -Eq '\[mup-provider-probe\] status=0x00000000 queries=[1-9][0-9]* accepted=[1-9][0-9]* .*file-created=[1-9][0-9]* cleaned=[1-9][0-9]* closed=[1-9][0-9]*' "$RUN_LOG"; } \
   || ! grep -Eq '\[mup-provider-write-result\] status=0x00000000 info=10' "$RUN_LOG" \
   || ! grep -Eq '\[mup-provider-read\] count=[1-9][0-9]* bytes=10' "$RUN_LOG" \
   || { ! grep -Fq '[read-forward-result] offset=0 call=0x00000000 wait=0x00000000 status=0x00000000 iosb=0x00000000 info=10 bytes-match=1' "$RUN_LOG" \
        && ! grep -Fq '[read-forward-verified-0]' "$RUN_LOG"; } \
   || ! grep -Fq '[mup-provider-read-pending-dispatch] status=0x00000103' "$RUN_LOG" \
   || ! grep -Eq '\[mup-provider-read-pending-complete\] count=[1-9][0-9]* bytes=20' "$RUN_LOG" \
   || ! grep -Fq '[read-forward-verified-1]' "$RUN_LOG" \
   || [ "$(grep -Fc '[mup-provider-read-pending-complete]' "$RUN_LOG")" -ne 1 ] \
   || ! grep -Fq '[mup-provider-flush] count=1' "$RUN_LOG" \
   || ! grep -Fq '[flush-forward-verified-0]' "$RUN_LOG" \
   || ! grep -Fq '[mup-provider-flush-pending-dispatch] status=0x00000103' "$RUN_LOG" \
   || ! grep -Fq '[mup-provider-flush-pending-complete] count=2' "$RUN_LOG" \
   || ! grep -Fq '[flush-forward-verified-1]' "$RUN_LOG" \
   || [ "$(grep -Fc '[mup-provider-flush-pending-complete]' "$RUN_LOG")" -ne 1 ] \
   || ! grep -Fq '[mup-provider-query-file] count=1 class=5 bytes=24' "$RUN_LOG" \
   || ! grep -Fq '[query-forward-verified-0]' "$RUN_LOG" \
   || ! grep -Fq '[mup-provider-query-file-pending-dispatch] status=0x00000103' "$RUN_LOG" \
   || ! grep -Fq '[mup-provider-query-file-pending-complete] count=2 bytes=24' "$RUN_LOG" \
   || ! grep -Fq '[query-forward-verified-1]' "$RUN_LOG" \
   || [ "$(grep -Fc '[mup-provider-query-file-pending-complete]' "$RUN_LOG")" -ne 1 ] \
   || ! grep -Fq '[mup-provider-query-file] count=3 class=5 bytes=24' "$RUN_LOG" \
   || ! grep -Fq '[zw-query-file-verified]' "$RUN_LOG" \
   || ! grep -Fq '[zw-read-file-verified]' "$RUN_LOG" \
   || { ! grep -Eq '\[mup-provider-probe\] status=0x00000000 queries=[1-9][0-9]* accepted=[1-9][0-9]* .*file-created=[1-9][0-9]* cleaned=[1-9][0-9]* closed=[1-9][0-9]*' "$RUN_LOG" \
        && { ! grep -Eq '\[mup-provider-cleanup\] probe-file cleaned=[1-9][0-9]*' "$RUN_LOG" \
             || ! grep -Eq 'probe-file closed=[1-9][0-9]*' "$RUN_LOG"; }; }; then
  echo "Mup/provider registration, query, immediate/pending IRPs, Zw READ/QUERY, WRITE, and File lifecycle proof incomplete: $RUN_LOG" >&2
  exit 1
fi

echo "Mup/provider registration, query, File WRITE, immediate/pending cross-domain READ, FLUSH and QUERY_INFORMATION, Zw READ/QUERY, and CREATE/CLEANUP/CLOSE verified: $RUN_LOG"
