#!/usr/bin/env bash
# Build the isolated-components Object Manager service and stage it as the
# kernel's rootserver ELF. Needs `alloc` (the NT crates) and compiler-builtins-mem
# (surt-core's init_ring + alloc/memcpy). Large code model (surt-core + NT crates).
set -euo pipefail

cd "$(dirname "$0")"

mkdir -p ../../rust-micro/.tmp
SEH_LINKAGE_STAGE=../../rust-micro/.tmp/nt-seh-linkage.dll
rm -f "$SEH_LINKAGE_STAGE" ../../rust-micro/.tmp/rootserver.elf

# Extra args are forwarded to cargo — e.g. `./build.sh --features debug-trace` to enable
# the grind-era verbose trace diagnostics. The DEFAULT build (no args) is feature-off = ships.
cargo +nightly build \
  -Z build-std=core,alloc \
  -Z build-std-features=compiler-builtins-mem \
  -Z unstable-options \
  -Z json-target-spec \
  --target triplet.json \
  --release \
  "$@"

bash ../nt-seh-linkage/build.sh
cp ../../.tmp/nt-seh-linkage/nt-seh-linkage.dll "$SEH_LINKAGE_STAGE"
echo "SEH linkage staged: rust-micro/.tmp/nt-seh-linkage.dll"

cp target/triplet/release/ntos-executive ../../rust-micro/.tmp/rootserver.elf
echo "ntos-executive staged: rust-micro/.tmp/rootserver.elf"

# P2: generate a real registry hive (nt-hive-core image) + stage it for the disk image, so
# the Config Manager can read it off the FS. Host tool (std); the nt-hive-core lib stays
# no_std, and it lives in the main workspace (not this component's), so run it from there.
HIVE_OUT="$(cd ../../rust-micro/.tmp && pwd)/hive.dat"
IMAGE_PROFILE="${NTOS_IMAGE_PROFILE:-production}"
( cd ../../crates/nt-hive-core && NTOS_IMAGE_PROFILE="$IMAGE_PROFILE" cargo run -q --release --bin gen_hive -- "$HIVE_OUT" )
printf '%s\n' "$IMAGE_PROFILE" > ../../rust-micro/.tmp/image-profile
echo "registry hive staged: rust-micro/.tmp/hive.dat"
