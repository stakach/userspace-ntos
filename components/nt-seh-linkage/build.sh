#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
OUT=${1:-"$ROOT/.tmp/nt-seh-linkage"}
CLANG=${CLANG:-clang}
if [[ -z ${RUST_LLD:-} ]]; then
    SYSROOT=$(rustc +nightly --print sysroot)
    HOST=$(rustc +nightly -vV | sed -n 's/^host: //p')
    RUST_LLD="$SYSROOT/lib/rustlib/$HOST/bin/rust-lld"
fi
mkdir -p "$OUT"

"$CLANG" --target=x86_64-pc-windows-msvc -c "$HERE/seh_linkage.S" \
    -o "$OUT/seh_linkage.obj"
"$RUST_LLD" -flavor link /machine:x64 /dll /noentry /nodefaultlib \
    /dynamicbase /nxcompat /timestamp:0 \
    /export:SehCallFilter /export:SehCallFinally \
    /export:SehExecuteHandlerForException /export:SehExecuteHandlerForUnwind \
    /export:SehRaiseStatus /export:SehUnwindEx /export:SehResumeContext \
    /export:SehRaiseDispatch,DATA /export:SehUnwindDispatch,DATA \
    "/out:$OUT/nt-seh-linkage.dll" "$OUT/seh_linkage.obj"
cargo run --manifest-path "$ROOT/Cargo.toml" -p seh-linkage-verify -- \
    "$OUT/nt-seh-linkage.dll"
printf 'Verified SEH linkage metadata: %s/nt-seh-linkage.dll (not executed)\n' "$OUT"
