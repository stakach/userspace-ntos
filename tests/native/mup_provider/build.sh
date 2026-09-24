#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
OUT=${1:-"$ROOT/.tmp/native-mup-provider"}
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
    "$CLANG" --target=x86_64-pc-windows-msvc -c "$HERE/import_anchor.S" \
        -o "$OUT/import_anchor.obj"
    "$RUST_LLD" -flavor link /machine:x64 /dll /noentry /nodefaultlib \
        /timestamp:0 "/def:$HERE/imports.def" "/implib:$OUT/ntoskrnl.lib" \
        "/out:$OUT/import-only-ntoskrnl.exe" "$OUT/import_anchor.obj"
fi

"$CLANG" --target=x86_64-pc-windows-msvc -fms-extensions -ffreestanding \
    -fno-builtin -fno-stack-protector -mno-stack-arg-probe -fno-ident \
    -Wall -Wextra -Werror -O2 -c "$HERE/mup_provider.c" -o "$OUT/mup_provider.obj"
"$RUST_LLD" -flavor link /machine:x64 /driver /dll /entry:DriverEntry \
    /subsystem:native,5.2 /osversion:5.2 /nodefaultlib /dynamicbase /nxcompat /timestamp:0 \
    /export:MupProviderEvidence,DATA "/out:$OUT/mup_provider.sys" \
    "$OUT/mup_provider.obj" "$OUT/ntoskrnl.lib"
printf 'Prepared native Mup provider fixture: %s/mup_provider.sys (not staged or executed)\n' "$OUT"
