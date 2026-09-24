#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
OUT=${1:-"$ROOT/.tmp/native-driver-seh"}
VARIANT=${2:-success}
case "$VARIANT" in
    success) VARIANT_CFLAG=() ;;
    unhandled) VARIANT_CFLAG=(-DSEH_TERMINAL_UNHANDLED) ;;
    exit) VARIANT_CFLAG=(-DSEH_TERMINAL_EXIT) ;;
    fault-ud2) VARIANT_CFLAG=(-DSEH_FAULT_UD2) ;;
    *) echo "error: unsupported native SEH fixture variant: $VARIANT" >&2; exit 1 ;;
esac
CLANG=${CLANG:-clang}
if [[ -z ${RUST_LLD:-} ]]; then
    SYSROOT=$(rustc +nightly --print sysroot)
    HOST=$(rustc +nightly -vV | sed -n 's/^host: //p')
    RUST_LLD="$SYSROOT/lib/rustlib/$HOST/bin/rust-lld"
fi
mkdir -p "$OUT"

if command -v "${LLVM_DLLTOOL:-llvm-dlltool}" >/dev/null 2>&1; then
    "${LLVM_DLLTOOL:-llvm-dlltool}" -m i386:x86-64 -d "$HERE/imports.def" \
        -l "$OUT/ntoskrnl.lib"
else
    # This trap DLL exists only to create an import library. It is never installed into the OS.
    "$CLANG" --target=x86_64-pc-windows-msvc -c "$HERE/import_anchor.S" \
        -o "$OUT/import_anchor.obj"
    "$RUST_LLD" -flavor link /machine:x64 /dll /noentry /nodefaultlib \
        /timestamp:0 "/def:$HERE/imports.def" "/implib:$OUT/ntoskrnl.lib" \
        "/out:$OUT/import-only-ntoskrnl.exe" "$OUT/import_anchor.obj"
fi

"$CLANG" --target=x86_64-pc-windows-msvc -fms-extensions -ffreestanding \
    -fno-builtin -fno-stack-protector -mno-stack-arg-probe -fno-ident \
    -Wall -Wextra -Werror -O2 "${VARIANT_CFLAG[@]}" -c "$HERE/driver_seh.c" -o "$OUT/driver_seh.obj"
"$CLANG" --target=x86_64-pc-windows-msvc -c "$HERE/bare_unwind.S" \
    -o "$OUT/bare_unwind.obj"
"$RUST_LLD" -flavor link /machine:x64 /driver /dll /entry:DriverEntry \
    /subsystem:native,5.2 /osversion:5.2 /nodefaultlib /dynamicbase /nxcompat /timestamp:0 \
    /export:SehFixtureEvidence,DATA "/out:$OUT/driver_seh.sys" \
    "$OUT/driver_seh.obj" "$OUT/bare_unwind.obj" "$OUT/ntoskrnl.lib"
VERIFY_ARGS=()
if [[ "$VARIANT" == fault-ud2 ]]; then
    VERIFY_ARGS=(--fault-ud2)
fi
cargo run --manifest-path "$ROOT/Cargo.toml" -p seh-linkage-verify \
    --bin seh-driver-fixture-verify -- "$OUT/driver_seh.sys" "$OUT/driver_seh.obj" "${VERIFY_ARGS[@]}"
printf 'Verified native SEH fixture (%s): %s/driver_seh.sys (not staged or executed)\n' "$VARIANT" "$OUT"
