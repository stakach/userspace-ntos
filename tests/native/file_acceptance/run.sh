#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
cd "$ROOT"
if [[ ${1:-} == --verify-log ]]; then
    [[ $# == 2 ]] || { printf 'usage: %s --verify-log LOG\n' "$0" >&2; exit 2; }
    exec python3 "$ROOT/tests/native/file_acceptance/verify_log.py" "$2"
fi
for arg in "$@"; do
    if [[ $arg == --build-only ]]; then
        NTOS_IMAGE_PROFILE=file-acceptance ./run.sh "$@"
        exit $?
    fi
done
export RUN_LOG=${RUN_LOG:-"$ROOT/.tmp/run-file-acceptance-$(date +%Y%m%d-%H%M%S).log"}
# Preserve the separate whole-OS verdict; neither it nor the fixture marker substitutes for the other.
set +e
NTOS_IMAGE_PROFILE=file-acceptance ./run.sh "$@"
rc=$?
python3 "$ROOT/tests/native/file_acceptance/verify_log.py" "$RUN_LOG"
fixture_rc=$?
set -e
printf 'File fixture verdict=%s; separate whole-OS verdict=%s; log=%s\n' "$fixture_rc" "$rc" "$RUN_LOG"
if (( rc != 0 )); then exit "$rc"; fi
exit "$fixture_rc"
