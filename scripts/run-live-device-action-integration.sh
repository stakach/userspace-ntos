#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RUN_LOG="${RUN_LOG:-$ROOT/.tmp/run-live-device-action-$(date +%Y%m%d-%H%M%S).log}"
BOOT_TIMEOUT_SECONDS="${BOOT_TIMEOUT_SECONDS:-900}"

NTOS_IMAGE_PROFILE=live-device-action \
NTOS_GENERATED_E1000_COUNT=2 \
RUN_LOG="$RUN_LOG" \
BOOT_TIMEOUT_SECONDS="$BOOT_TIMEOUT_SECONDS" \
./run.sh \
  -netdev user,id=ntnet1 \
  -device e1000,netdev=ntnet1

require_fixed() {
  local text="$1"
  local description="$2"
  if ! grep -Fq "$text" "$RUN_LOG"; then
    printf 'live-device-action integration failure: %s\nlog: %s\n' "$description" "$RUN_LOG" >&2
    exit 1
  fi
}

instance='PCI\VEN_8086&DEV_100E\3&11583659&0&20'
require_fixed "[pnp-live-action] claimed " 'CM action was not claimed'
require_fixed "[pnp-live-action] delivered " 'user-mode PnP did not receive the action'
require_fixed "[pnp-live-action] retired " 'responded notification was not acknowledged to CM'
require_fixed "[driver-launch] demand AddDevice service=E1000 devnode=$instance" \
  'the dynamically reported NIC did not execute real AddDevice'
require_fixed "[driver-launch] demand StartDevice service=E1000 devnode=$instance status=0x00000000" \
  'the dynamically reported NIC did not complete its real START IRP'
require_fixed '[ntos-exec] DEMAND-LOAD umpnpmgr ' \
  'SCM did not activate the real PlugPlay service DLL'

python3 - "$RUN_LOG" "$instance" <<'PY'
import re
import sys

log_path, target_instance = sys.argv[1:]
lines = open(log_path, encoding="utf-8", errors="replace").read().splitlines()

identity = r"(?P<generation>[0-9]+)/(?P<sequence>[0-9]+)/(?P<token>[0-9]+)"
claim_re = re.compile(
    rf"^\[pnp-live-action\] (?P<phase>claimed|delivered) "
    rf"generation/sequence/token={identity} instance=(?P<instance>.+)$"
)
retired_re = re.compile(
    rf"^\[pnp-live-action\] retired generation/sequence/token={identity} "
    rf"response/reply=(?P<response>0x[0-9a-fA-F]+)/(?P<reply>0x[0-9a-fA-F]+) "
    rf"instance=(?P<instance>.+)$"
)
proof_re = re.compile(
    rf"^\[pnp-live-proof\] generation/sequence/token={identity} "
    rf"kind=(?P<kind>arrival|change|removal) "
    rf"response/reply=(?P<response>0x[0-9a-fA-F]+)/(?P<reply>0x[0-9a-fA-F]+) "
    rf"empty-after-ack=(?P<empty>[01]) instance=(?P<instance>.+)$"
)
summary_re = re.compile(
    r"^\[pnp-live-proof\] summary claims/rows/responded/failed="
    r"(?P<claims>[0-9]+)/(?P<rows>[0-9]+)/(?P<responded>[0-9]+)/(?P<failed>[0-9]+) "
    r"empty-after-ack/active/response-tail/cm-pending="
    r"(?P<empty>[0-9]+)/(?P<active>[0-9]+)/(?P<response_tail>[0-9]+)/(?P<pending>[0-9]+)$"
)

phases = {"claimed": [], "delivered": [], "retired": []}
positions = {}
proofs = []
summaries = []

def row_key(match):
    return (
        int(match["generation"]),
        int(match["sequence"]),
        int(match["token"]),
        match["instance"],
    )

for line_number, line in enumerate(lines):
    if match := claim_re.match(line):
        key = row_key(match)
        phases[match["phase"]].append(key)
        positions.setdefault(key, []).append((match["phase"], line_number))
    elif match := retired_re.match(line):
        if int(match["response"], 16) != 0 or int(match["reply"], 16) != 0:
            raise SystemExit(f"live-device-action integration failure: non-success retirement: {line}")
        key = row_key(match)
        phases["retired"].append(key)
        positions.setdefault(key, []).append(("retired", line_number))
    elif match := proof_re.match(line):
        proofs.append((row_key(match), match["kind"], int(match["empty"])))
        if int(match["response"], 16) != 0 or int(match["reply"], 16) != 0:
            raise SystemExit(f"live-device-action integration failure: non-success proof row: {line}")
    elif match := summary_re.match(line):
        summaries.append({name: int(value) for name, value in match.groupdict().items()})

if not summaries:
    raise SystemExit("live-device-action integration failure: missing final live-action summary")
summary = summaries[-1]
count = len(proofs)
if count == 0:
    raise SystemExit("live-device-action integration failure: no live CM action reached a terminal proof")
if phases["claimed"] != phases["delivered"] or phases["claimed"] != phases["retired"]:
    raise SystemExit("live-device-action integration failure: claim/delivery/retirement identities differ")
if phases["claimed"] != [row[0] for row in proofs]:
    raise SystemExit("live-device-action integration failure: action and terminal-proof order differs")
if len(set(phases["claimed"])) != count:
    raise SystemExit("live-device-action integration failure: duplicate action identity")
for key in phases["claimed"]:
    observed = [phase for phase, _ in sorted(positions.get(key, []), key=lambda item: item[1])]
    if observed != ["claimed", "delivered", "retired"]:
        raise SystemExit(f"live-device-action integration failure: invalid lifecycle for {key}: {observed}")
if any(key[0] == 0 or key[1] == 0 or key[2] == 0 for key in phases["claimed"]):
    raise SystemExit("live-device-action integration failure: zero action identity component")
for previous, current in zip(phases["claimed"], phases["claimed"][1:]):
    if current[0] < previous[0] or (current[0] == previous[0] and current[1] <= previous[1]):
        raise SystemExit("live-device-action integration failure: action journal order regressed")
if [row[2] for row in proofs] != [0] * (count - 1) + [1]:
    raise SystemExit("live-device-action integration failure: only the final exact ACK may drain the queue")
target_rows = [row for row in proofs if row[0][3] == target_instance]
if len(target_rows) != 1 or target_rows[0][1] != "arrival":
    raise SystemExit("live-device-action integration failure: target NIC arrival proof is not exact")
add_prefix = f"[driver-launch] demand AddDevice service=E1000 devnode={target_instance} device_id="
start_line = (
    f"[driver-launch] demand StartDevice service=E1000 devnode={target_instance} "
    "status=0x00000000"
)
add_positions = [index for index, line in enumerate(lines) if line.startswith(add_prefix)]
start_positions = [index for index, line in enumerate(lines) if line == start_line]
if len(add_positions) != 1:
    raise SystemExit("live-device-action integration failure: target NIC AddDevice count is not exact")
if len(start_positions) != 1:
    raise SystemExit("live-device-action integration failure: target NIC START count is not exact")
if add_positions[0] >= start_positions[0]:
    raise SystemExit("live-device-action integration failure: target NIC START preceded AddDevice")
if not (
    summary["claims"] == summary["rows"] == summary["responded"] == count
    and summary["failed"] == 0
    and summary["empty"] == 1
    and summary["active"] == 0
    and summary["response_tail"] == 0
    and summary["pending"] == 0
):
    raise SystemExit(f"live-device-action integration failure: incoherent final summary: {summary}")
PY

require_fixed 'PASS exec_live_device_actions_exact' 'the generic live-action gate failed'
require_fixed 'PASS exec_explorer_shell_chrome_painted' 'desktop paint regressed'
require_fixed '[microtest sentinel matched -- exiting QEMU]' 'QEMU did not exit through the sentinel'

printf 'live-device-action integration passed: %s\n' "$RUN_LOG"
