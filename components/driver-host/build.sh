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
cp target/triplet/release/ntos-driver-host ../../rust-micro/.tmp/rootserver.elf
echo "ntos-driver-host staged: rust-micro/.tmp/rootserver.elf"
