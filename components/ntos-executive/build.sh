#!/usr/bin/env bash
# Build the isolated-components Object Manager service and stage it as the
# kernel's rootserver ELF. Needs `alloc` (the NT crates) and compiler-builtins-mem
# (surt-core's init_ring + alloc/memcpy). Large code model (surt-core + NT crates).
set -euo pipefail

cd "$(dirname "$0")"

cargo +nightly build \
  -Z build-std=core,alloc \
  -Z build-std-features=compiler-builtins-mem \
  -Z unstable-options \
  -Z json-target-spec \
  --target triplet.json \
  --release

mkdir -p ../../rust-micro/.tmp
cp target/triplet/release/ntos-executive ../../rust-micro/.tmp/rootserver.elf
echo "ntos-executive staged: rust-micro/.tmp/rootserver.elf"

# P2: generate a real registry hive (nt-hive-core image) + stage it for the disk image, so
# the Config Manager can read it off the FS. Host tool (std); the nt-hive-core lib stays
# no_std, and it lives in the main workspace (not this component's), so run it from there.
HIVE_OUT="$(cd ../../rust-micro/.tmp && pwd)/hive.dat"
( cd ../../crates/nt-hive-core && cargo run -q --release --bin gen_hive -- "$HIVE_OUT" )
echo "registry hive staged: rust-micro/.tmp/hive.dat"
