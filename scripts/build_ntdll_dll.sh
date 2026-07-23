#!/usr/bin/env bash
#
# build_ntdll_dll.sh — emit our Rust ntdll as a loadable PE32+ DLL (ntdll_plan.md Step 4.0).
#
# Produces `.tmp/nt-ntdll.dll`: a PE32+ DLL whose export directory lists the complete `Nt*` ABI
# (under their real Windows names) + `LdrpInitialize`, with a `.reloc` directory, no CRT startup,
# no_std. Built from the host-tested `nt-ntdll` rlib via the thin `nt-ntdll-dll` cdylib wrapper.
#
# This is a BUILD + VERIFY step ONLY — it does NOT wire the DLL into the boot (that is Step 4.A+).
#
# Toolchain (all bundled with the Rust nightly — no mingw / external linker needed on macOS):
#   * target : a custom no-CRT spec derived from `x86_64-pc-windows-gnullvm` (mingw import libs +
#              CRT startup objects stripped; linker = the bundled `rust-lld`, flavor `gnu-lld`).
#   * -Zbuild-std (core/alloc/panic_abort) with `-Cpanic=immediate-abort` (no_std, no unwinder) and
#              `compiler-builtins-mem` (supplies memcpy/memcmp/… since we drop msvcrt).
#   * --no-gc-sections : keep the `.reloc` fixups (gc-sections collects the base-reloc chunks).
#
# Requires: a Rust nightly with `rust-src` + the `x86_64-pc-windows-gnullvm` std component:
#   rustup toolchain install nightly
#   rustup component add rust-src
#   rustup target add x86_64-pc-windows-gnullvm
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DLL_CRATE="$ROOT/crates/nt-ntdll-dll"
# nt-ntdll-dll is its OWN workspace (excluded from the main one — it never builds for the host), so
# the build runs from inside the crate dir. Target spec + output are relative to that dir.
TARGET_JSON="x86_64-pc-windows-gnullvm-nostd.json"
TARGET_DIRNAME="x86_64-pc-windows-gnullvm-nostd"
OUT_DIR="$ROOT/.tmp"
OUT_DLL="$OUT_DIR/nt-ntdll.dll"
FEATURE_ARGS=()
if [ -n "${NTDLL_FEATURES:-}" ]; then
  FEATURE_ARGS=(--features "$NTDLL_FEATURES")
fi

echo "==> building nt-ntdll-dll (PE32+ ntdll.dll) for $TARGET_DIRNAME"

( cd "$DLL_CRATE" && \
  RUSTFLAGS="-Zunstable-options -Cpanic=immediate-abort -Clink-arg=--no-gc-sections" \
    cargo +nightly build \
      --release \
      --target "$TARGET_JSON" \
      "${FEATURE_ARGS[@]}" \
      -Z build-std=core,alloc,panic_abort \
      -Z build-std-features=compiler-builtins-mem \
      -Z json-target-spec )

BUILT="$DLL_CRATE/target/$TARGET_DIRNAME/release/nt_ntdll_dll.dll"
if [ ! -f "$BUILT" ]; then
  echo "!! build produced no DLL at $BUILT" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
cp "$BUILT" "$OUT_DLL"
echo "==> staged: $OUT_DLL"

# ---- Informational objdump dump (cosmetic; the hard gate is the nt-pe-loader verify below) ------
# objdump output format varies (llvm-objdump vs GNU binutils on Linux CI); this section is best-
# effort and never fails the build. The authoritative export/reloc gate is `ntdll-dll-verify`.
OBJDUMP="${OBJDUMP:-}"
if [ -z "$OBJDUMP" ]; then
  for cand in llvm-objdump /opt/homebrew/opt/llvm/bin/llvm-objdump /usr/local/opt/llvm/bin/llvm-objdump objdump; do
    if command -v "$cand" >/dev/null 2>&1 || [ -x "$cand" ]; then OBJDUMP="$cand"; break; fi
  done
fi
if [ -n "$OBJDUMP" ]; then
  echo "==> objdump ($OBJDUMP) — informational:"
  file "$OUT_DLL" || true
  "$OBJDUMP" -p "$OUT_DLL" 2>&1 | grep -iE "Magic|^\s*DLL\b|AddressOfEntryPoint|DllCharacteristics" | sed 's/^/   /' || true
  "$OBJDUMP" -h "$OUT_DLL" 2>&1 | awk '$2 ~ /^\./ {printf " %s", $2} END {print ""}' | sed 's/^/   sections:/' || true
fi

# ---- Compatibility proof (THE HARD GATE): parse it with the EXECUTIVE'S OWN loader --------------
# ntdll-dll-verify asserts PE32+/IMAGE_FILE_DLL, the complete Nt* ABI + LdrpInitialize exported
# (reporting the RVA), and a non-empty base-relocation directory. If our own nt-pe-loader can read
# it, the executive can load it (Step 4.B). Non-zero exit fails the build.
echo "==> compatibility check (hard gate): parsing with the executive's own nt-pe-loader"
cargo run -q -p ntdll-dll-verify -- "$OUT_DLL"

echo "==> OK: PE32+ ntdll.dll (complete Nt* ABI + LdrpInitialize + .reloc), nt-pe-loader-parsed, staged at $OUT_DLL"
