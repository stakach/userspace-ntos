#!/usr/bin/env python3
"""Check that a real i8042 CONNECT completion reaches its retained class owner."""

import argparse
import re
from pathlib import Path


SOURCE = re.compile(r"\[hosted-connect-live\] stage=0 irp=(0x[0-9a-f]+)")
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
    raw = RAW_TERMINAL.search(log)
    if raw is None:
        return False, "i8042 did not complete a materialized CONNECT IRP"
    observed = next(
        (match for match in OBSERVED.finditer(log)
         if match.group(1) == source.group(1) and match.start() > raw.end()),
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
