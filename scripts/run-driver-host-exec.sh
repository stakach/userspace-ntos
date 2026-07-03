#!/usr/bin/env bash
# Build the Driver Host executor component — which maps the real SurtTest.sys WDM
# driver executable in its own VSpace and runs its DriverEntry under the Microsoft
# x64 ABI — and boot it in QEMU.
#
#   ./scripts/run-driver-host-exec.sh
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ ! -e rust-micro/scripts/build_kernel.sh ]]; then
  echo "error: rust-micro submodule not checked out. Run:" >&2
  echo "  git submodule update --init --recursive" >&2
  exit 1
fi

./components/driver-host-exec/build.sh
( cd rust-micro && ./scripts/build_kernel.sh extern-rootserver )
( cd rust-micro && ./scripts/run_specs.sh )
