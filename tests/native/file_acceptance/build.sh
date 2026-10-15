#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
OUT=${1:-"$ROOT/.tmp/native-file-acceptance"}
NTDLL=${NTDLL:-"$ROOT/.tmp/nt-ntdll.dll"}
find_tool() {
    if [[ -x "/opt/homebrew/opt/llvm/bin/$1" ]]; then
        printf '%s\n' "/opt/homebrew/opt/llvm/bin/$1"
    else command -v "$1"; fi
}
CLANG=${CLANG:-$(find_tool clang)}
if [[ -z ${LLVM_DLLTOOL:-} ]] && [[ -x /opt/homebrew/opt/llvm/bin/llvm-dlltool ]]; then
    LLVM_DLLTOOL=/opt/homebrew/opt/llvm/bin/llvm-dlltool
fi
if [[ -z ${RUST_LLD:-} ]]; then
    SYSROOT=$(rustc +nightly --print sysroot)
    HOST=$(rustc +nightly -vV | sed -n 's/^host: //p')
    RUST_LLD="$SYSROOT/lib/rustlib/$HOST/bin/rust-lld"
fi
[[ -f "$NTDLL" ]] || { printf 'Missing built ntdll: %s\n' "$NTDLL" >&2; exit 1; }
mkdir -p "$OUT"
"$CLANG" --target=x86_64-pc-windows-msvc -ffreestanding -fno-builtin \
    -fno-stack-protector -mno-stack-arg-probe -fno-ident -std=c11 \
    -Wall -Wextra -Werror -O2 -c "$HERE/file_acceptance.c" -o "$OUT/file_acceptance.obj"
if command -v "${LLVM_DLLTOOL:-llvm-dlltool}" >/dev/null 2>&1; then
    "${LLVM_DLLTOOL:-llvm-dlltool}" -m i386:x86-64 -d "$HERE/imports.def" -l "$OUT/ntdll.lib"
else
    "$CLANG" --target=x86_64-pc-windows-msvc -c "$HERE/import_anchor.S" -o "$OUT/import_anchor.obj"
    "$RUST_LLD" -flavor link /machine:x64 /dll /noentry /nodefaultlib /timestamp:0 \
        "/def:$HERE/imports.def" "/implib:$OUT/ntdll.lib" \
        "/out:$OUT/import-only-ntdll.dll" "$OUT/import_anchor.obj"
fi
"$RUST_LLD" -flavor link /machine:x64 /subsystem:native,5.2 /osversion:5.2 /entry:NtProcessStartup \
    /nodefaultlib /dynamicbase /nxcompat /timestamp:0 /fixed:no \
    "/out:$OUT/file_acceptance.exe" "$OUT/file_acceptance.obj" "$OUT/ntdll.lib"
cargo run --manifest-path "$ROOT/Cargo.toml" -p ntdll-dll-verify \
    --bin nt-native-test-verify -- "$OUT/file_acceptance.exe" "$NTDLL" file-acceptance
printf 'Prepared native file fixture (not executed): %s\n' "$OUT/file_acceptance.exe"
