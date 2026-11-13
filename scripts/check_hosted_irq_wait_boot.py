#!/usr/bin/env python3
"""Reject a retained driver wait that indefinitely blocks its own IRQ delivery."""

import argparse
import re
from pathlib import Path


WAIT = re.compile(
    r"\[hosted-driver-wait\] instance=(\d+).*? reply=(\d+) route=(\d+)"
)
ACTIVE_IRP = re.compile(
    r"\[pump-active-irp\] slot/sequence/domain/cookie/route/tcb/shared/reply/"
    r"source-irp/control-id/major/minor=([0-9/]+)"
)
BUSY_IRQ = re.compile(r"\[hosted-irq\] deferred busy arena event=(\d+)")
SERVED_IRQ = re.compile(r"\[hosted-irq\] serviced event=(\d+)")


def check(log: str) -> tuple[bool, str]:
    waits = list(WAIT.finditer(log))
    active = list(ACTIVE_IRP.finditer(log))
    busy = list(BUSY_IRQ.finditer(log))
    if not waits or not active or not busy:
        return False, "boot lacks the driver wait, active IRP, or deferred IRQ evidence"
    held = [int(value) for value in active[-1].group(1).split("/")]
    if len(held) != 12:
        return False, "active IRP census has an incomplete owner record"
    wait = next(
        (row for row in reversed(waits)
         if int(row.group(2)) == held[7] and int(row.group(3)) == held[4]),
        None,
    )
    if wait is None:
        return True, "active IRP has no matching retained driver wait"
    last_busy = busy[-1]
    served_later = any(
        row.group(1) == last_busy.group(1) and row.start() > last_busy.start()
        for row in SERVED_IRQ.finditer(log)
    )
    if served_later:
        return True, "deferred IRQ later reached its driver ISR"
    return False, (
        f"driver instance {wait.group(1)} retains IRP reply {wait.group(2)} "
        f"while IRQ event {last_busy.group(1)} remains deferred"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("serial_log", type=Path)
    args = parser.parse_args()
    passed, message = check(args.serial_log.read_text(errors="replace"))
    print(message)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
