#!/usr/bin/env bash
# run.sh — one-command launcher for the rust-micro kernel hosting the REAL
# ReactOS user-space stack: BOOTBOOT -> rust-micro (seL4-style microkernel) ->
# smss -> csrss -> winlogon -> win32k -> a PAINTED Windows desktop.
#
#   ./run.sh              # headless serial gate; prints SUCCESS on "[microtest done]"
#   ./run.sh --desktop    # boot with a QEMU window so you SEE the painted desktop
#   ./run.sh --debug      # forward QEMU int/cpu_reset tracing (triple-fault hunts)
#
# What it does (idempotent + re-runnable):
#   [1/5] preflight — verify every required tool + the Rust nightly toolchain
#   [2/5] submodule — check out rust-micro if missing
#   [3/5] fetch     — download the GPL ReactOS livecd binaries (first run only)
#   [4/5] build     — build the ntos-executive + kernel + pack the disk image
#   [5/5] run       — boot QEMU (headless gate, or a display window with --desktop)
set -euo pipefail

cd "$(dirname "$0")"
ROOT="$(pwd)"
RM="$ROOT/rust-micro"

# ---- flags --------------------------------------------------------------
GRAPHICS=0
PASSTHRU=()
for arg in "$@"; do
  case "$arg" in
    --desktop|--display|--graphics) GRAPHICS=1 ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//' | sed '/^!/d'
      exit 0
      ;;
    *) PASSTHRU+=("$arg") ;;
  esac
done

say() { printf '\033[1;36m%s\033[0m\n' "$*"; }
err() { printf '\033[1;31m%s\033[0m\n' "$*" >&2; }

# ---- [1/5] preflight dependency check -----------------------------------
say "[1/5] checking dependencies..."

# macOS: dosfstools' mkfs.vfat installs under sbin, not always on PATH.
if [ "$(uname)" = "Darwin" ]; then
  for d in /opt/homebrew/sbin /usr/local/sbin; do
    case ":$PATH:" in *":$d:"*) ;; *) [ -d "$d" ] && PATH="$d:$PATH" ;; esac
  done
fi

IS_MAC=0; [ "$(uname)" = "Darwin" ] && IS_MAC=1

# tool -> "macOS remedy | Debian/Ubuntu remedy"  (assign empty so set -u is happy)
MISSING_TOOL=(); MISSING_MAC=(); MISSING_APT=()
check_tool() {
  local tool="$1" mac="$2" apt="$3"
  if ! command -v "$tool" >/dev/null 2>&1; then
    MISSING_TOOL+=("$tool"); MISSING_MAC+=("$mac"); MISSING_APT+=("$apt")
  fi
}
check_tool qemu-system-x86_64 "brew install qemu"       "apt install qemu-system-x86"
check_tool mkfs.vfat          "brew install dosfstools" "apt install dosfstools"
check_tool mmd                "brew install mtools"     "apt install mtools"
check_tool mcopy              "brew install mtools"     "apt install mtools"
check_tool dd                 "(base system)"           "(coreutils)"
check_tool curl               "brew install curl"       "apt install curl"
check_tool bsdtar             "brew install libarchive" "apt install libarchive-tools"
check_tool python3            "brew install python"     "apt install python3"
check_tool cargo              "install rustup: https://rustup.rs" "install rustup: https://rustup.rs"
check_tool rustup             "install rustup: https://rustup.rs" "install rustup: https://rustup.rs"

# Rust nightly toolchain + rust-src component (needed for -Z build-std).
if command -v rustup >/dev/null 2>&1; then
  if ! rustup toolchain list 2>/dev/null | grep -q '^nightly'; then
    MISSING_TOOL+=("rust nightly toolchain")
    MISSING_MAC+=("rustup toolchain install nightly")
    MISSING_APT+=("rustup toolchain install nightly")
  elif ! rustup component list --toolchain nightly 2>/dev/null | grep -q 'rust-src.*(installed)'; then
    MISSING_TOOL+=("rust-src (nightly)")
    MISSING_MAC+=("rustup component add rust-src --toolchain nightly")
    MISSING_APT+=("rustup component add rust-src --toolchain nightly")
  fi
fi

# UEFI firmware (OVMF / edk2). Same search order run_specs.sh uses.
OVMF_FOUND=""
if [ -n "${OVMF:-}" ] && [ -f "${OVMF:-}" ]; then
  OVMF_FOUND="$OVMF"
else
  for c in \
      "$(brew --prefix qemu 2>/dev/null)/share/qemu/edk2-x86_64-code.fd" \
      /opt/homebrew/share/qemu/edk2-x86_64-code.fd \
      /usr/local/share/qemu/edk2-x86_64-code.fd \
      /usr/share/OVMF/OVMF_CODE.fd \
      /usr/share/edk2-ovmf/OVMF_CODE.fd \
      /usr/share/qemu/OVMF.fd; do
    [ -n "$c" ] && [ -f "$c" ] && { OVMF_FOUND="$c"; break; }
  done
fi
if [ -z "$OVMF_FOUND" ]; then
  MISSING_TOOL+=("OVMF/edk2 UEFI firmware")
  MISSING_MAC+=("bundled with 'brew install qemu'")
  MISSING_APT+=("apt install ovmf")
fi

if [ "${#MISSING_TOOL[@]}" -gt 0 ]; then
  err ""
  err "Missing prerequisites:"
  err ""
  if [ "$IS_MAC" = 1 ]; then col="macOS"; else col="Debian/Ubuntu"; fi
  printf '  %-28s %s\n' "MISSING" "INSTALL ($col)" >&2
  printf '  %-28s %s\n' "-------" "--------------" >&2
  for i in "${!MISSING_TOOL[@]}"; do
    if [ "$IS_MAC" = 1 ]; then remedy="${MISSING_MAC[$i]}"; else remedy="${MISSING_APT[$i]}"; fi
    printf '  %-28s %s\n' "${MISSING_TOOL[$i]}" "$remedy" >&2
  done
  err ""
  err "Install the above and re-run ./run.sh"
  exit 1
fi
say "      all dependencies present (OVMF: $OVMF_FOUND)"

# ---- [2/5] submodule ----------------------------------------------------
say "[2/5] checking rust-micro submodule..."
if [ ! -e "$RM/scripts/build_kernel.sh" ]; then
  say "      submodule missing — running git submodule update --init --recursive"
  git submodule update --init --recursive
fi

# ---- [3/5] fetch the ReactOS binaries (first run only) ------------------
say "[3/5] checking ReactOS binaries..."
REACTOS_KEY="$RM/.tmp/reactos/ros-csrss.exe"
if [ ! -f "$REACTOS_KEY" ] || [ ! -f "$RM/.tmp/reactos/ros-win32k.sys" ] \
   || [ ! -f "$RM/.tmp/reactos/ros-winlogon.exe" ]; then
  say "      fetching GPL ReactOS x64 livecd (~30 MiB download, first run only, cached)"
  "$RM/scripts/fetch_reactos.sh"
else
  say "      ReactOS binaries already staged (cached)"
fi

# ---- [4/5] build the executive + kernel + disk image --------------------
say "[4/5] building ntos-executive + kernel + disk image..."
"$ROOT/scripts/build_ntdll_dll.sh"
"$ROOT/components/ntos-executive/build.sh"
( cd "$RM" && ./scripts/build_kernel.sh extern-rootserver )

# ---- [5/5] run ----------------------------------------------------------
if [ "$GRAPHICS" = 1 ]; then
  say "[5/5] booting QEMU with a DISPLAY window (--desktop)..."
  say "      Watch for the ReactOS desktop background (a blue-grey field, 0x003a6ea5)."
  say "      Serial log streams here; close the QEMU window to quit."
  # In graphics mode run_specs drops isa-debug-exit, so QEMU stays alive with the
  # painted desktop until the user closes the window (exit status is the window's).
  ( cd "$RM" && GRAPHICS=1 ./scripts/run_specs.sh "${PASSTHRU[@]}" )
  exit 0
fi

say "[5/5] booting QEMU (headless serial gate)..."
say "      Success = the executive prints '[microtest done]' with no FAIL lines."
say "      Tip: ./run.sh --desktop to SEE the painted ReactOS desktop in a window."
# run_specs execs QEMU; the kernel signals the result through isa-debug-exit:
#   host exit 3 = kernel qemu_exit(0) = PASS ((0<<1|1)<<1|1),  255 = panic.
set +e
( cd "$RM" && ./scripts/run_specs.sh "${PASSTHRU[@]}" )
rc=$?
set -e
echo
if [ "$rc" = 3 ] || [ "$rc" = 0 ]; then
  say "SUCCESS — the ReactOS stack booted and the win32k desktop painted (0x003a6ea5)."
  say "         See 'PASS exec_win32k_desktop_painted' above; run ./run.sh --desktop to view it."
  exit 0
fi
err "FAILED — QEMU exited $rc (255 = kernel panic). Scroll up for the last PASS/FAIL line."
exit 1
