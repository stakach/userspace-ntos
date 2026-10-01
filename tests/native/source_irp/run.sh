#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
cd "$ROOT"
RUN_LOG=${RUN_LOG:-"$ROOT/.tmp/run-source-irp-$(date +%Y%m%d-%H%M%S).log"}
bash tests/native/source_irp/build.sh
NTOS_IMAGE_PROFILE=source-irp-integration RUN_LOG="$RUN_LOG" ./run.sh "$@"
python3 - "$RUN_LOG" <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(errors="replace")
text = re.sub(r"\[user #PF:[^\n]*\]\n", "", text)
for mode in range(2):
    call = "00000103" if mode else "00000000"
    for operation in range(6):
        expected = (f"[source-irp-proof] mode={mode} op={operation} call=0x{call} "
                    "wait=0x00000000 iosb=0x00000000 info=16 bytes=1")
        if expected not in text:
            sys.exit(f"Missing exact source IRP evidence: {expected}")
    if f"[source-irp-proof-complete] mode={mode} operations=6" not in text:
        sys.exit(f"Source IRP mode {mode} did not complete")
reports = re.findall(r"\[source-native\][^\n]*", text)
if not reports:
    sys.exit("No native source milestone report")
report = reports[-1]
for kind in ("ioctl", "pnp", "read", "write"):
    counts = re.search(rf" {kind}=(\d+)/(\d+)/(\d+)/(\d+)", report)
    if not counts or not all(int(value) > 0 for value in counts.groups()):
        sys.exit(f"Incomplete native {kind} terminal/commit/retirement evidence")
methods = re.search(r"ioctl-method-terminals\(buffered/in/out/neither\)=(\d+)/(\d+)/(\d+)/(\d+)", report)
if not methods or not all(int(value) >= 2 for value in methods.groups()):
    sys.exit("Not all IOCTL methods reached both native terminal modes")
if "PASS exec_source_native_milestone_coverage" not in text:
    sys.exit("Missing native source milestone gate")
if "PASS exec_explorer_shell_chrome_painted" not in text or "FAIL exec_explorer_shell_chrome_painted" in text:
    sys.exit("Missing genuine Explorer chrome paint gate")
if "[microtest sentinel matched -- exiting QEMU]" not in text:
    sys.exit("Missing complete boot sentinel")
print(f"Native source IRP integration passed: {sys.argv[1]}")
PY
