#!/usr/bin/env bash
# Build the ntdll syscall-trap component, stage it as the kernel's rootserver, and boot it in
# QEMU. Demonstrates the REAL seL4 syscall trap: a real Windows 7 ntdll syscall stub executes,
# its `syscall` instruction traps into the kernel (UnknownSyscall fault), and the NT native
# syscall dispatcher services it. Requires references/ntdll.dll (gitignored).
set -euo pipefail
cd "$(dirname "$0")/.."
if [ ! -f references/ntdll.dll ]; then
  echo "references/ntdll.dll not found (gitignored); place a Windows 7 x64 ntdll there." >&2
  exit 1
fi
./components/driver-host-ntdll/build.sh
( cd rust-micro && ./scripts/build_kernel.sh extern-rootserver && ./scripts/run_specs.sh )
