#!/usr/bin/env python3
"""Check that a real i8042 CONNECT completion reaches its retained class owner."""

import argparse
import re
from pathlib import Path


SOURCE = re.compile(r"\[hosted-connect-live\] stage=0 irp=(0x[0-9a-f]+)")
PENDING = re.compile(
    r"\[hosted-connect-live\] stage=8 irp=(0x[0-9a-f]+) "
    r"first=0x0000000000000001 second=(0x[0-9a-f]+)"
)
RAW_CLAIM = re.compile(
    r"\[post-hook-connect-completion\] stage/raw/canonical/detail=2/"
    r"(0x[0-9a-f]+)/(0x[0-9a-f]+)/0x0000000000000001"
)
RAW_TERMINAL = re.compile(
    r"\[post-hook-connect-completion\] stage/raw/canonical/detail=4/"
    r"(0x[0-9a-f]+)/0x[0-9a-f]+/0x0000000000000000"
)
OBSERVED = re.compile(
    r"\[hosted-connect-live\] stage=9 irp=(0x[0-9a-f]+) "
    r"first=0x0000000000000000 second=0x0000000000000001"
)


def check(log: str) -> tuple[bool, str]:
    source = SOURCE.search(log)
    if source is None:
        return False, "no retained keyboard CONNECT source was captured"
    pending = next((match for match in PENDING.finditer(log)
                    if match.group(1) == source.group(1)), None)
    if pending is None:
        return False, "retained keyboard CONNECT did not publish its pending port IRP"
    raw = next((match for match in RAW_CLAIM.finditer(log)
                if match.group(2) == pending.group(2) and match.start() > pending.end()), None)
    terminal = next((match for match in RAW_TERMINAL.finditer(log)
                     if raw is not None and match.group(1) == raw.group(1)
                     and match.start() > raw.end()), None)
    if terminal is None:
        return False, "i8042 did not complete a materialized CONNECT IRP"
    observed = next(
        (match for match in OBSERVED.finditer(log)
         if match.group(1) == source.group(1) and match.start() > terminal.end()),
        None,
    )
    if observed is None:
        return False, "native CONNECT completed, but the retained class owner did not observe it"
    return True, "retained class owner observed the completed keyboard CONNECT"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("serial_log", type=Path)
    args = parser.parse_args()
    passed, message = check(args.serial_log.read_text(errors="replace"))
    print(message)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
