#!/usr/bin/env bash
# Build the MMIO+interrupt Driver Host, stage as rootserver, boot in QEMU —
# real MmioInterruptTest.sys over simulated MMIO + injected interrupts.
set -euo pipefail
cd "$(dirname "$0")/.."
./build.sh
cd ../../rust-micro
./scripts/build_kernel.sh extern-rootserver
./scripts/run_specs.sh
