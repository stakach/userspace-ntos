#!/usr/bin/env bash
# Build the NT PnP Driver Host component and stage it as the kernel's rootserver
# ELF (rust-micro/.tmp/rootserver.elf). First builds the SEPARATE isolated driver
# binary (driver-host-um) and stages its ELF as um-driver.elf, which this crate
# embeds via include_bytes! and loads into a private VSpace at runtime.
set -euo pipefail

cd "$(dirname "$0")"

# 1. Build the isolated user-mode driver (its own ELF) + stage it for embedding.
../driver-host-um/build.sh
cp ../driver-host-um/target/triplet/release/ntos-driver-host-um um-driver.elf

# 2. Build the driver-host (embeds um-driver.elf).
cargo +nightly build \
  -Z build-std=core,alloc \
  -Z build-std-features=compiler-builtins-mem \
  -Z unstable-options \
  -Z json-target-spec \
  --target triplet.json \
  --release

mkdir -p ../../rust-micro/.tmp
cp target/triplet/release/ntos-driver-host-pnp ../../rust-micro/.tmp/rootserver.elf
echo "ntos-driver-host-pnp staged: rust-micro/.tmp/rootserver.elf"
