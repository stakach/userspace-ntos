#!/usr/bin/env bash
# Build the ntos-executive core (spawns the Object Manager as an isolated service
# and drives it over SURT) + kernel, and boot QEMU with serial output.
set -euo pipefail
cd "$(dirname "$0")/.."
components/ntos-executive/build.sh
cd rust-micro
./scripts/build_kernel.sh extern-rootserver
./scripts/run_specs.sh
