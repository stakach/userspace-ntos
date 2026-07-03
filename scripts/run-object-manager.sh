#!/usr/bin/env bash
# Build the NT Object Manager component + the kernel (via the rust-micro
# submodule) and boot it in QEMU. The component runs the whole NT object stack
# bare-metal and prints PASS/FAIL per step.
#
#   ./scripts/run-object-manager.sh
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ ! -e rust-micro/scripts/build_kernel.sh ]]; then
  echo "error: rust-micro submodule not checked out. Run:" >&2
  echo "  git submodule update --init --recursive" >&2
  exit 1
fi

# 1. Build + stage the component ELF as the kernel's rootserver.
./components/object-manager/build.sh

# 2. Build the kernel + image using the caller-staged rootserver.
( cd rust-micro && ./scripts/build_kernel.sh extern-rootserver )

# 3. Boot in QEMU.
( cd rust-micro && ./scripts/run_specs.sh )
