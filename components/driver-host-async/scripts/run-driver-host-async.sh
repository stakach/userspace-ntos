#!/usr/bin/env bash
# Build the async Driver Host component, stage it as the kernel rootserver, and
# boot it in QEMU — real AsyncTest.sys over DPC/timer/work-item completion.
set -euo pipefail
cd "$(dirname "$0")/.."
./build.sh
cd ../../rust-micro
./scripts/build_kernel.sh extern-rootserver
./scripts/run_specs.sh
