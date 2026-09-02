#!/usr/bin/env bash
# run.sh — one-command launcher for the rust-micro kernel hosting the REAL
# ReactOS user-space stack: Simpleboot -> rust-micro (seL4-style microkernel) ->
# smss -> csrss -> winlogon -> win32k -> a PAINTED Windows desktop.
#
#   ./run.sh              # headless serial gate; requires the complete Explorer shell proof
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
BOOT_TIMEOUT_SECONDS="${BOOT_TIMEOUT_SECONDS:-3600}"

if ! [[ "$BOOT_TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] \
   || [ "$BOOT_TIMEOUT_SECONDS" -lt 1 ] \
   || [ "$BOOT_TIMEOUT_SECONDS" -gt 3600 ]; then
  printf 'BOOT_TIMEOUT_SECONDS must be an integer from 1 through 3600\n' >&2
  exit 2
fi

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

run_boot_lane() {
  python3 "$ROOT/scripts/run_with_timeout.py" \
    --seconds "$BOOT_TIMEOUT_SECONDS" \
    --cwd "$RM" \
    --completion-file "$RUN_LOG" \
    --completion-text '[microtest sentinel matched -- exiting QEMU]' \
    -- "$@"
}

run_desktop_boot_lane() {
  python3 "$ROOT/scripts/run_with_timeout.py" \
    --seconds "$BOOT_TIMEOUT_SECONDS" \
    --cwd "$RM" \
    --ready-file "$RUN_LOG" \
    --ready-text 'PASS exec_explorer_shell_chrome_painted' \
    --post-ready-seconds 60 \
    --completion-file "$RUN_LOG" \
    --completion-text '[microtest sentinel matched -- exiting QEMU]' \
    -- "$@"
}

complete_boot_verdict() {
  local log="$1" rc="$2" summary passed total
  summary="$(sed -n \
    's/.*\[ntos-exec summary: \([0-9][0-9]*\)\/\([0-9][0-9]*\) executive->isolated-service checks passed\].*/\1 \2/p' \
    "$log" | tail -n 1)"
  passed=""
  total=""
  read -r passed total <<< "$summary"
  if grep -q 'PASS exec_explorer_shell_chrome_painted' "$log" \
     && ! grep -q 'FAIL exec_explorer_shell_chrome_painted' "$log" \
     && ! grep -q '^  FAIL ' "$log" \
     && grep -q '\[microtest sentinel matched -- exiting QEMU\]' "$log" \
     && [ -n "$passed" ] \
     && [ "$passed" = "$total" ] \
     && { [ "$rc" = 1 ] || [ "$rc" = 3 ] || [ "$rc" = 0 ]; }; then
    printf '%s %s\n' "$passed" "$total"
    return 0
  fi
  return 1
}

BOOT_IMAGE="$RM/.tmp/disk.img"

ensure_no_qemu_lane_running() {
  local holders=""
  holders="$(ps -axo pid=,command= 2>/dev/null | awk '
    /[q]emu-system-x86_64/ || /[r]un_specs[.]sh/ { print }
  ' || true)"
  [ -z "$holders" ] && return 0

  err ""
  err "A QEMU/run_specs boot lane is already running:"
  printf '%s\n' "$holders" >&2
  err ""
  err "Stop the existing desktop/headless run before starting another boot."
  exit 1
}

ensure_boot_image_available() {
  local image="$1"
  [ -e "$image" ] || return 0

  local holders=""
  if command -v lsof >/dev/null 2>&1; then
    holders="$(lsof "$image" 2>/dev/null || true)"
    [ -z "$holders" ] && return 0
    err ""
    err "Boot image is already open: $image"
    printf '%s\n' "$holders" >&2
    err ""
    err "Stop the existing QEMU/run.sh lane before starting another boot."
    exit 1
  fi

  if command -v fuser >/dev/null 2>&1 && fuser "$image" >/dev/null 2>&1; then
    err ""
    err "Boot image is already open: $image"
    fuser -v "$image" >&2 || true
    err ""
    err "Stop the existing QEMU/run.sh lane before starting another boot."
    exit 1
  fi
}

# ---- [1/5] preflight dependency check -----------------------------------
say "[1/5] checking dependencies..."

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
check_tool cc                 "xcode-select --install"  "apt install build-essential"
check_tool dd                 "(base system)"           "(coreutils)"
check_tool tar                "(base system)"           "apt install tar"
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
"$RM/scripts/verify_reactos_acpi_provider.sh"

# ---- [4/5] build the executive + kernel + disk image --------------------
say "[4/5] building ntos-executive + kernel + disk image..."
ensure_no_qemu_lane_running
ensure_boot_image_available "$BOOT_IMAGE"
"$ROOT/scripts/build_ntdll_dll.sh"
"$ROOT/components/ntos-executive/build.sh"
( cd "$RM" && ./scripts/build_kernel.sh extern-rootserver )

# ---- [5/5] run ----------------------------------------------------------
ensure_no_qemu_lane_running
ensure_boot_image_available "$BOOT_IMAGE"
if [ "$GRAPHICS" = 1 ]; then
  say "[5/5] booting QEMU with a DISPLAY window (--desktop)..."
  say "      Watch for the ReactOS desktop background (a blue-grey field, 0x003a6ea5)."
  mkdir -p "$ROOT/.tmp"
  RUN_LOG="${RUN_LOG:-$ROOT/.tmp/run-desktop-$(date +%Y%m%d-%H%M%S).log}"
  : > "$RUN_LOG"
  say "      Serial log streams here and to: $RUN_LOG"
  say "      Boot readiness timeout: ${BOOT_TIMEOUT_SECONDS}s (60s final-verdict grace after paint)."
  say "      QEMU exits after the guest's complete validation verdict."
  set +e
  if [ "${#PASSTHRU[@]}" -gt 0 ]; then
    run_desktop_boot_lane env GRAPHICS=1 ./scripts/run_specs.sh "${PASSTHRU[@]}" 2>&1 | tee -a "$RUN_LOG"
  else
    run_desktop_boot_lane env GRAPHICS=1 ./scripts/run_specs.sh 2>&1 | tee -a "$RUN_LOG"
  fi
  rc=${PIPESTATUS[0]}
  set -e
  echo
  if [ "$rc" = 124 ]; then
    err "FAILED — desktop boot readiness exceeded ${BOOT_TIMEOUT_SECONDS}s; QEMU was terminated."
    err "         Log: $RUN_LOG"
    exit 124
  fi
  if verdict="$(complete_boot_verdict "$RUN_LOG" "$rc")"; then
    read -r passed total <<< "$verdict"
    say "SUCCESS — the visible ReactOS desktop completed its full gate ($passed/$total checks)."
    say "         Log: $RUN_LOG"
    exit 0
  fi
  err "FAILED — desktop QEMU exited $rc without the complete Explorer shell proof."
  err "         Log: $RUN_LOG"
  exit 1
fi

say "[5/5] booting QEMU (headless serial gate)..."
say "      Success = every executive check passes and Explorer shell chrome reaches the framebuffer."
say "      Tip: ./run.sh --desktop to SEE the painted ReactOS desktop in a window."
say "      Boot validation timeout: ${BOOT_TIMEOUT_SECONDS}s (hard maximum: 3600s)."
# run_specs execs QEMU; the kernel signals the result through isa-debug-exit:
#   host exit 3 = kernel qemu_exit(0) = PASS ((0<<1|1)<<1|1),  255 = panic.
mkdir -p "$ROOT/.tmp"
RUN_LOG="${RUN_LOG:-$ROOT/.tmp/run-headless-$(date +%Y%m%d-%H%M%S).log}"
: > "$RUN_LOG"
set +e
if [ "${#PASSTHRU[@]}" -gt 0 ]; then
  run_boot_lane ./scripts/run_specs.sh "${PASSTHRU[@]}" 2>&1 | tee -a "$RUN_LOG"
else
  run_boot_lane ./scripts/run_specs.sh 2>&1 | tee -a "$RUN_LOG"
fi
rc=${PIPESTATUS[0]}
set -e
echo
if [ "$rc" = 124 ]; then
  err "FAILED — boot validation exceeded ${BOOT_TIMEOUT_SECONDS}s; QEMU was terminated."
  err "         Log: $RUN_LOG"
  exit 124
fi
if verdict="$(complete_boot_verdict "$RUN_LOG" "$rc")"; then
  read -r passed total <<< "$verdict"
  say "SUCCESS — the ReactOS stack booted and Explorer painted the complete shell ($passed/$total checks)."
  say "         Log: $RUN_LOG"
  say "         Run ./run.sh --desktop to view it."
  exit 0
fi
err "FAILED — QEMU exited $rc without the complete Explorer shell proof (255 = kernel panic)."
err "         Log: $RUN_LOG"
exit 1
