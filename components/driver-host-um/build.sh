#!/usr/bin/env bash
# Build the isolated user-mode driver component to its OWN ELF. driver-host-pnp's
# build.sh runs this first, then embeds the resulting ELF via include_bytes!.
set -euo pipefail
cd "$(dirname "$0")"
cargo +nightly build \
  -Z build-std=core,alloc \
  -Z build-std-features=compiler-builtins-mem \
  -Z unstable-options \
  -Z json-target-spec \
  --target triplet.json \
  --release
echo "ntos-driver-host-um built: $(pwd)/target/triplet/release/ntos-driver-host-um"
