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
require_fixed '[setup-state] ReactOS installed-boot values committed setup/service=' \
  'fresh-media installed-state transition did not commit'
require_fixed '[scm-select] PlugPlay auto/demand=1/0 from installed SYSTEM generation' \
  'SCM did not classify PlugPlay from the installed SYSTEM generation'
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

setup_index = next(
    (index for index, line in enumerate(lines)
     if line.startswith("[setup-state] ReactOS installed-boot values committed setup/service=")),
    None,
)
scm_index = next(
    (index for index, line in enumerate(lines)
     if line == "[scm-select] PlugPlay auto/demand=1/0 from installed SYSTEM generation"),
    None,
)
if setup_index is None or scm_index is None or setup_index >= scm_index:
    raise SystemExit(
        "live-device-action integration failure: installed-state commit must precede SCM selection"
    )

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
start_proof_re = re.compile(
    r"^\[pnp-start-proof\] call=(?P<call>[0-9]+) instance=(?P<instance>.+?) "
    r"path=(?P<path>synchronous|pending) "
    r"completion=(?P<completion>no-start-irp|lifecycle-terminal|ownership-lost) "
    r"dispatched=(?P<dispatched>[01]) irp=(?P<irp>[0-9]+) "
    r"devnode/gen/dispatch=(?P<devnode>[0-9]+)/(?P<generation>[0-9]+)/(?P<dispatch>[0-9]+) "
    r"pdo/fdo=(?P<pdo>[0-9]+)/(?P<fdo>[0-9]+) "
    r"origin/completion-driver/device=(?P<origin>[0-9]+)/(?P<completion_driver>[0-9]+)/(?P<completion_device>[0-9]+) "
    r"driver-pending=(?P<driver_pending>[01]) "
    r"start-status=(?P<start_status>0x[0-9a-fA-F]+) "
    r"terminal/reply=(?P<terminal>0x[0-9a-fA-F]+)/(?P<reply>0x[0-9a-fA-F]+) "
    r"reply-outcome=(?P<reply_outcome>delivered|failed|abandoned)$"
)
start_summary_re = re.compile(
    r"^\[pnp-start-proof\] summary calls/rows/replied="
    r"(?P<calls>[0-9]+)/(?P<rows>[0-9]+)/(?P<replied>[0-9]+) "
    r"sync/pending/no-start/lifecycle/lost="
    r"(?P<sync>[0-9]+)/(?P<parked>[0-9]+)/(?P<no_start>[0-9]+)/(?P<lifecycle>[0-9]+)/(?P<lost>[0-9]+) "
    r"failed/abandoned/pending-status/active/protocol="
    r"(?P<failed>[0-9]+)/(?P<abandoned>[0-9]+)/(?P<pending_status>[0-9]+)/(?P<active>[0-9]+)/(?P<protocol>[0-9]+) "
    r"tail/transfer/retained/barriers="
    r"(?P<tail>[0-9]+)/(?P<transfer>[0-9]+)/(?P<retained>[0-9]+)/(?P<barriers>[0-9]+) "
    r"pending-linked/missing=(?P<linked>[0-9]+)/(?P<missing>[0-9]+)$"
)
pending_proof_re = re.compile(
    r"^\[pnp-pending-proof\] irp=(?P<irp>[0-9]+) "
    r"devnode/gen/dispatch=(?P<devnode>[0-9]+)/(?P<generation>[0-9]+)/(?P<dispatch>[0-9]+) "
    r"pdo/fdo=(?P<pdo>[0-9]+)/(?P<fdo>[0-9]+) "
    r"origin/completion-driver/device=(?P<origin>[0-9]+)/(?P<completion_driver>[0-9]+)/(?P<completion_device>[0-9]+) "
    r"status=(?P<status>0x[0-9a-fA-F]+) stages=(?P<stages>0x[0-9a-fA-F]+) "
    r"irp-retired=(?P<retired>[01]) observed=(?P<observed>[01])$"
)

phases = {"claimed": [], "delivered": [], "retired": []}
positions = {}
proofs = []
summaries = []
start_proofs = []
start_summaries = []
pending_proofs = []

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
    elif match := start_proof_re.match(line):
        start_proofs.append(match.groupdict())
    elif match := start_summary_re.match(line):
        start_summaries.append({name: int(value) for name, value in match.groupdict().items()})
    elif match := pending_proof_re.match(line):
        pending_proofs.append(match.groupdict())

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
start_call_ids = [int(row["call"]) for row in start_proofs]
if any(call_id == 0 for call_id in start_call_ids) or len(set(start_call_ids)) != len(start_call_ids):
    raise SystemExit("live-device-action integration failure: StartDevice call IDs are zero or reused")
for row in start_proofs:
    if row["reply_outcome"] == "delivered" and row["terminal"] != row["reply"]:
        raise SystemExit(
            f"live-device-action integration failure: delivered StartDevice status mismatch: {row}"
        )
dispatched_rows = [row for row in start_proofs if row["dispatched"] == "1"]
dispatched_irps = [int(row["irp"]) for row in dispatched_rows]
if any(irp == 0 for irp in dispatched_irps) or len(set(dispatched_irps)) != len(dispatched_irps):
    raise SystemExit("live-device-action integration failure: canonical START IRP was reused")
receipt_rows = [row for row in start_proofs if int(row["devnode"]) != 0]
receipt_dispatches = [
    (int(row["devnode"]), int(row["generation"]), int(row["dispatch"]))
    for row in receipt_rows
]
if (
    any(any(part == 0 for part in identity) for identity in receipt_dispatches)
    or len(set(receipt_dispatches)) != len(receipt_dispatches)
):
    raise SystemExit("live-device-action integration failure: lifecycle dispatch identity was reused")
target_start_rows = [row for row in start_proofs if row["instance"] == target_instance]
if len(target_start_rows) != 1:
    raise SystemExit("live-device-action integration failure: target StartDevice reply row is not exact")
start_row = target_start_rows[0]
numeric_identity = [
    "irp", "devnode", "generation", "dispatch", "pdo", "fdo", "origin",
    "completion_driver", "completion_device",
]
if (
    start_row["completion"] != "lifecycle-terminal"
    or start_row["dispatched"] != "1"
    or start_row["reply_outcome"] != "delivered"
    or any(int(start_row[name]) == 0 for name in numeric_identity)
    or int(start_row["start_status"], 16) != 0
    or int(start_row["terminal"], 16) != 0
    or int(start_row["reply"], 16) != 0
):
    raise SystemExit(f"live-device-action integration failure: invalid target StartDevice row: {start_row}")
add_device_id = int(lines[add_positions[0]].removeprefix(add_prefix))
if int(start_row["fdo"]) != add_device_id:
    raise SystemExit("live-device-action integration failure: StartDevice FDO differs from AddDevice")
same_irp_pending = [row for row in pending_proofs if row["irp"] == start_row["irp"]]
if start_row["driver_pending"] == "1":
    if len(same_irp_pending) != 1:
        raise SystemExit("live-device-action integration failure: pending START has no exact proof row")
    pending_row = same_irp_pending[0]
    for outer_name, pending_name in [
        ("irp", "irp"), ("devnode", "devnode"), ("generation", "generation"),
        ("dispatch", "dispatch"), ("pdo", "pdo"), ("fdo", "fdo"),
        ("origin", "origin"), ("completion_driver", "completion_driver"),
        ("completion_device", "completion_device"),
    ]:
        if start_row[outer_name] != pending_row[pending_name]:
            raise SystemExit("live-device-action integration failure: pending START identity join failed")
    if (
        int(pending_row["status"], 16) != int(start_row["start_status"], 16)
        or int(pending_row["stages"], 16) != 0x7F
        or pending_row["retired"] != "1"
        or pending_row["observed"] != "1"
    ):
        raise SystemExit("live-device-action integration failure: pending START proof is incomplete")
elif same_irp_pending:
    raise SystemExit("live-device-action integration failure: synchronous START has a pending proof row")
if not start_summaries:
    raise SystemExit("live-device-action integration failure: missing StartDevice summary")
start_summary = start_summaries[-1]
if not (
    start_summary["calls"] == start_summary["rows"] == start_summary["replied"] == len(start_proofs)
    and start_summary["lifecycle"] >= 1
    and start_summary["lost"] == 0
    and start_summary["failed"] == 0
    and start_summary["abandoned"] == 0
    and start_summary["pending_status"] == 0
    and start_summary["active"] == 0
    and start_summary["protocol"] == 0
    and start_summary["tail"] == 0
    and start_summary["transfer"] == 0
    and start_summary["retained"] == 0
    and start_summary["barriers"] == 0
    and start_summary["missing"] == 0
):
    raise SystemExit(f"live-device-action integration failure: incoherent StartDevice summary: {start_summary}")
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
require_fixed 'PASS exec_start_device_calls_exact' 'the exact StartDevice reply gate failed'
require_fixed 'PASS exec_explorer_shell_chrome_painted' 'desktop paint regressed'
require_fixed '[microtest sentinel matched -- exiting QEMU]' 'QEMU did not exit through the sentinel'

printf 'live-device-action integration passed: %s\n' "$RUN_LOG"
