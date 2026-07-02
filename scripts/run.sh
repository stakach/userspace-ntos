#!/usr/bin/env bash
# run.sh — build the NTOS root task, stage it as the kernel's rootserver, build
# the kernel (via the rust-micro submodule), and boot it in QEMU.
#
#   ./scripts/run.sh
#
# Requires the nightly toolchain + rust-src (for -Z build-std), plus the
# submodule checked out (`git submodule update --init`).
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ ! -e rust-micro/scripts/build_kernel.sh ]]; then
  echo "error: rust-micro submodule not checked out. Run:" >&2
  echo "  git submodule update --init --recursive" >&2
  exit 1
fi

# 1. Build the NTOS root-task ELF for the kernel's bare-metal target.
#    compiler-builtins-mem provides memcpy/memset for future NT code.
( cd crates/ntos-root && cargo +nightly build \
    -Z build-std=core \
    -Z build-std-features=compiler-builtins-mem \
    -Z unstable-options \
    -Z json-target-spec \
    --target triplet.json \
    --release )

# 2. Stage it as the kernel's rootserver, then build the kernel + image using the
#    submodule's pipeline in "bring your own rootserver" mode.
mkdir -p rust-micro/.tmp
cp crates/ntos-root/target/triplet/release/ntos-root rust-micro/.tmp/rootserver.elf
( cd rust-micro && ./scripts/build_kernel.sh extern-rootserver )

# 3. Boot in QEMU (serial to stdout; the kernel qemu_exits on the sentinel).
( cd rust-micro && ./scripts/run_specs.sh )
