#!/usr/bin/env bash
# Build the UMDF v2 Driver Host + stage it as the kernel's rootserver ELF.
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
cp target/triplet/release/ntos-driver-host-umdf ../../rust-micro/.tmp/rootserver.elf
echo "ntos-driver-host-umdf staged: rust-micro/.tmp/rootserver.elf"
