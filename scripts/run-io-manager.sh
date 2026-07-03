#!/usr/bin/env bash
# Build the isolated-components I/O Manager service (client + server as two
# separate seL4 components talking over SURT, the server embedding an in-process
# Object Manager) + the kernel, and boot it in QEMU.
#
#   ./scripts/run-io-manager.sh
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ ! -e rust-micro/scripts/build_kernel.sh ]]; then
  echo "error: rust-micro submodule not checked out. Run:" >&2
  echo "  git submodule update --init --recursive" >&2
  exit 1
fi

./components/io-manager/build.sh
( cd rust-micro && ./scripts/build_kernel.sh extern-rootserver )
( cd rust-micro && ./scripts/run_specs.sh )
