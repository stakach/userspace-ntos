#!/usr/bin/env bash
# Build the driver-host demo — the I/O Manager (over an embedded Object Manager)
# dispatching IRPs to a SEPARATE isolated driver-peer component over SURT — and
# boot it in QEMU.
#
#   ./scripts/run-driver-host.sh
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ ! -e rust-micro/scripts/build_kernel.sh ]]; then
  echo "error: rust-micro submodule not checked out. Run:" >&2
  echo "  git submodule update --init --recursive" >&2
  exit 1
fi

./components/driver-host/build.sh
( cd rust-micro && ./scripts/build_kernel.sh extern-rootserver )
( cd rust-micro && ./scripts/run_specs.sh )
