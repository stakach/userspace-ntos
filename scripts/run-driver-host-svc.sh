#!/usr/bin/env bash
# Build the isolated Driver Host component — a broker rootserver that spawns a
# fault-contained child which maps the real SurtTest.sys executable and runs its
# DriverEntry + IRP dispatch — and boot it in QEMU.
#
#   ./scripts/run-driver-host-svc.sh
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ ! -e rust-micro/scripts/build_kernel.sh ]]; then
  echo "error: rust-micro submodule not checked out. Run:" >&2
  echo "  git submodule update --init --recursive" >&2
  exit 1
fi

./components/driver-host-svc/build.sh
( cd rust-micro && ./scripts/build_kernel.sh extern-rootserver )
( cd rust-micro && ./scripts/run_specs.sh )
