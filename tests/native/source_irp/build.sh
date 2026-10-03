#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
OUT=${1:-"$ROOT/.tmp/native-source-irp"}
CLANG=${CLANG:-clang}
if [[ -z ${RUST_LLD:-} ]]; then
    SYSROOT=$(rustc +nightly --print sysroot)
    HOST=$(rustc +nightly -vV | sed -n 's/^host: //p')
    RUST_LLD="$SYSROOT/lib/rustlib/$HOST/bin/rust-lld"
fi
mkdir -p "$OUT"
if command -v "${LLVM_DLLTOOL:-llvm-dlltool}" >/dev/null 2>&1; then
    "${LLVM_DLLTOOL:-llvm-dlltool}" -m i386:x86-64 -d "$HERE/imports.def" -l "$OUT/ntoskrnl.lib"
else
    "$CLANG" --target=x86_64-pc-windows-msvc -c "$HERE/import_anchor.S" -o "$OUT/import_anchor.obj"
    "$RUST_LLD" -flavor link /machine:x64 /dll /noentry /nodefaultlib /timestamp:0 \
        "/def:$HERE/imports.def" "/implib:$OUT/ntoskrnl.lib" \
        "/out:$OUT/import-only-ntoskrnl.exe" "$OUT/import_anchor.obj"
fi
for name in target source; do
    "$CLANG" --target=x86_64-pc-windows-msvc -fms-extensions -ffreestanding \
        -fno-builtin -fno-stack-protector -mno-stack-arg-probe -fno-ident \
        -Wall -Wextra -Werror -O2 -c "$HERE/$name.c" -o "$OUT/$name.obj"
done
"$RUST_LLD" -flavor link /machine:x64 /driver /dll /entry:DriverEntry \
    /subsystem:native,5.2 /osversion:5.2 /nodefaultlib /dynamicbase /nxcompat /timestamp:0 \
    "/out:$OUT/source_irp_target.sys" "$OUT/target.obj" "$OUT/ntoskrnl.lib"
"$RUST_LLD" -flavor link /machine:x64 /driver /dll /noentry \
    /subsystem:native,5.2 /osversion:5.2 /nodefaultlib /dynamicbase /nxcompat /timestamp:0 \
    "/out:$OUT/source_irp_probe.sys" "$OUT/source.obj" "$OUT/ntoskrnl.lib"
printf 'Prepared native source IRP target and caller (not staged or executed): %s\n' "$OUT"
