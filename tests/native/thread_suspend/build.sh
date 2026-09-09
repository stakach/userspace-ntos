#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
OUT=${1:-"$ROOT/.tmp/native-thread-suspend"}
NTDLL=${NTDLL:-"$ROOT/.tmp/nt-ntdll.dll"}

find_tool() {
    local name=$1
    if [[ -x "/opt/homebrew/opt/llvm/bin/$name" ]]; then
        printf '%s\n' "/opt/homebrew/opt/llvm/bin/$name"
    else
        command -v "$name"
    fi
}

CLANG=${CLANG:-$(find_tool clang)}
LLVM_DLLTOOL=${LLVM_DLLTOOL:-$(find_tool llvm-dlltool)}
if [[ -z ${RUST_LLD:-} ]]; then
    SYSROOT=$(rustc +nightly --print sysroot)
    HOST=$(rustc +nightly -vV | sed -n 's/^host: //p')
    RUST_LLD="$SYSROOT/lib/rustlib/$HOST/bin/rust-lld"
fi
[[ -f "$NTDLL" ]] || { printf 'Build our ntdll first: missing %s\n' "$NTDLL" >&2; exit 1; }
mkdir -p "$OUT"

"$CLANG" --target=x86_64-pc-windows-msvc -ffreestanding -fno-builtin \
    -fno-stack-protector -mno-stack-arg-probe -fno-ident \
    -Wall -Wextra -Werror -O2 -c "$HERE/thread_suspend.c" -o "$OUT/thread_suspend.obj"
"$LLVM_DLLTOOL" -m i386:x86-64 -d "$HERE/imports.def" -l "$OUT/ntdll.lib"
"$RUST_LLD" -flavor link /machine:x64 /subsystem:native,5.2 /osversion:5.2 /entry:NtProcessStartup \
    /nodefaultlib /dynamicbase /nxcompat /timestamp:0 /fixed:no \
    "/out:$OUT/thread_suspend.exe" "$OUT/thread_suspend.obj" "$OUT/ntdll.lib"
cargo run --manifest-path "$ROOT/Cargo.toml" -p ntdll-dll-verify \
    --bin nt-native-test-verify -- "$OUT/thread_suspend.exe" "$NTDLL"
printf 'Prepared native fixture: %s/thread_suspend.exe (not executed)\n' "$OUT"
