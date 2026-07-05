#!/usr/bin/env bash
# Build the NT Device-Interface-Registry Driver Host component and stage it as the kernel's rootserver
# ELF (rust-micro/.tmp/rootserver.elf). Needs `alloc` (the NT crates), so
# build-std includes alloc; compiler-builtins-mem provides memcpy/memset.
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
cp target/triplet/release/ntos-driver-host-loadercompat ../../rust-micro/.tmp/rootserver.elf
echo "ntos-driver-host-loadercompat staged: rust-micro/.tmp/rootserver.elf"
