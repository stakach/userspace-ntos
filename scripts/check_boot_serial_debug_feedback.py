#!/usr/bin/env python3
"""Reject COM1 debug-output feedback after the released serial driver starts.

The first three periodic census records after serial StartDevice bound the sample
to early boot, before a user program could intentionally transmit serial data.
"""

import argparse
from pathlib import Path


def check(log: str) -> tuple[int, int]:
    started = False
    census = 0
    empty_interrupts = 0
    for line in log.splitlines():
        if not started:
            if "config PnP StartDevice service=serial" in line and "status=0x00000000" in line:
                started = True
            continue
        if "SR_IIR_THR_EMPTY" in line:
            empty_interrupts += 1
        if "[census] periodic" in line:
            census += 1
            if census == 3:
                break
    if not started or census != 3:
        raise ValueError("serial StartDevice and three subsequent census records are required")
    return empty_interrupts, census


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    args = parser.parse_args()
    empty_interrupts, census = check(args.log.read_text(errors="replace"))
    print(f"serial THR-empty interrupts across {census} early census intervals: {empty_interrupts}")
    if empty_interrupts > 10:
        print("FAIL: debug output is feeding back through guest COM1")
        return 1
    print("PASS: no sustained COM1 debug-output feedback")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
