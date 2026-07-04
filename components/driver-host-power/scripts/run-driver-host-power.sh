#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
./build.sh
cd ../../rust-micro
./scripts/build_kernel.sh extern-rootserver
./scripts/run_specs.sh
