#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
OUT=${1:-"$ROOT/.tmp/native-font-cleanup"}
NTDLL=${NTDLL:-"$ROOT/.tmp/nt-ntdll.dll"}
REACTOS_SYSTEM32=${REACTOS_SYSTEM32:-"$ROOT/rust-micro/.tmp/reactos/reactos/system32"}
find_tool() {
    if [[ -x "/opt/homebrew/opt/llvm/bin/$1" ]]; then printf '%s\n' "/opt/homebrew/opt/llvm/bin/$1";
    else command -v "$1"; fi
}
CLANG=${CLANG:-$(find_tool clang)}
if [[ -z ${RUST_LLD:-} ]]; then
    SYSROOT=$(rustc +nightly --print sysroot)
    HOST=$(rustc +nightly -vV | sed -n 's/^host: //p')
    RUST_LLD="$SYSROOT/lib/rustlib/$HOST/bin/rust-lld"
fi
for path in "$NTDLL" "$REACTOS_SYSTEM32/kernel32.dll" "$REACTOS_SYSTEM32/gdi32.dll"; do
    [[ -f "$path" ]] || { printf 'Missing actual import dependency: %s\n' "$path" >&2; exit 1; }
done
mkdir -p "$OUT"
"$CLANG" --target=x86_64-pc-windows-msvc -c "$HERE/import_anchor.S" -o "$OUT/import_anchor.obj"
for library in ntdll kernel32 gdi32; do
    "$RUST_LLD" -flavor link /machine:x64 /dll /noentry /nodefaultlib /timestamp:0 \
        "/def:$HERE/$library.def" "/implib:$OUT/$library.lib" \
        "/out:$OUT/import-only-$library.dll" "$OUT/import_anchor.obj"
done
for fixture in font_run_setup font_acceptance; do
    "$CLANG" --target=x86_64-pc-windows-msvc -ffreestanding -fno-builtin \
        -fno-stack-protector -mno-stack-arg-probe -fno-ident -std=c11 \
        -Wall -Wextra -Werror -O2 -c "$HERE/$fixture.c" -o "$OUT/$fixture.obj"
done
"$RUST_LLD" -flavor link /machine:x64 /subsystem:native,5.2 /osversion:5.2 \
    /entry:NtProcessStartup /nodefaultlib /dynamicbase /nxcompat /timestamp:0 /fixed:no \
    "/out:$OUT/font_run_setup.exe" "$OUT/font_run_setup.obj" "$OUT/ntdll.lib"
"$RUST_LLD" -flavor link /machine:x64 /subsystem:windows,5.2 /osversion:5.2 \
    /entry:WinMainCRTStartup /nodefaultlib /dynamicbase /nxcompat /timestamp:0 /fixed:no \
    "/out:$OUT/font_acceptance.exe" "$OUT/font_acceptance.obj" \
    "$OUT/ntdll.lib" "$OUT/kernel32.lib" "$OUT/gdi32.lib"
cargo run --manifest-path "$ROOT/Cargo.toml" -p ntdll-dll-verify --bin nt-font-test-verify -- \
    setup "$OUT/font_run_setup.exe" "$NTDLL"
cargo run --manifest-path "$ROOT/Cargo.toml" -p ntdll-dll-verify --bin nt-font-test-verify -- \
    font "$OUT/font_acceptance.exe" "$NTDLL" "$REACTOS_SYSTEM32/kernel32.dll" "$REACTOS_SYSTEM32/gdi32.dll"
printf 'Prepared font cleanup fixtures (not executed): %s\n' "$OUT"
