#!/usr/bin/env python3
"""Run one command in its own process group with a boot-readiness deadline."""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path


POLL_INTERVAL_SECONDS = 0.1


class ForwardedSignal(Exception):
    def __init__(self, signum: int) -> None:
        super().__init__(signum)
        self.signum = signum


def terminate_group(process: subprocess.Popen[bytes], signum: signal.Signals) -> None:
    try:
        os.killpg(process.pid, signum)
    except ProcessLookupError:
        pass


def terminate_and_wait(process: subprocess.Popen[bytes], signum: signal.Signals) -> None:
    if process.poll() is not None:
        return
    terminate_group(process, signum)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        terminate_group(process, signal.SIGKILL)
        process.wait()


def ready_marker_observed(
    path: Path, marker: bytes, offset: int, tail: bytes
) -> tuple[bool, int, bytes]:
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return False, 0, b""

    if size < offset:
        offset = 0
        tail = b""
    if size == offset:
        return False, offset, tail

    with path.open("rb") as ready_file:
        ready_file.seek(offset)
        payload = ready_file.read()
    candidate = tail + payload
    retained = candidate[-(len(marker) - 1) :] if len(marker) > 1 else b""
    return marker in candidate, size, retained


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=int, required=True)
    parser.add_argument("--cwd", required=True)
    parser.add_argument("--ready-file")
    parser.add_argument("--ready-text")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if args.seconds <= 0 or not command:
        parser.error("a positive timeout and command are required")
    if bool(args.ready_file) != bool(args.ready_text):
        parser.error("--ready-file and --ready-text must be specified together")

    ready_path = Path(args.ready_file) if args.ready_file else None
    ready_marker = args.ready_text.encode() if args.ready_text else None
    try:
        ready_offset = ready_path.stat().st_size if ready_path else 0
    except FileNotFoundError:
        ready_offset = 0
    ready_tail = b""

    def forward_signal(signum: int, _frame: object) -> None:
        raise ForwardedSignal(signum)

    forwarded_signals = [signal.SIGINT, signal.SIGTERM]
    for signal_name in ("SIGHUP", "SIGQUIT"):
        forwarded_signals.append(getattr(signal, signal_name))
    previous_handlers = {
        signum: signal.signal(signum, forward_signal) for signum in forwarded_signals
    }

    process = subprocess.Popen(command, cwd=args.cwd, start_new_session=True)
    deadline = time.monotonic() + args.seconds
    try:
        while True:
            result = process.poll()
            if result is not None:
                return result

            if ready_path is not None and ready_marker is not None:
                ready, ready_offset, ready_tail = ready_marker_observed(
                    ready_path, ready_marker, ready_offset, ready_tail
                )
                if ready:
                    print(
                        "boot readiness marker observed; deadline disarmed",
                        file=sys.stderr,
                        flush=True,
                    )
                    return process.wait()

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                print(
                    f"boot validation exceeded {args.seconds}s; terminating process group",
                    file=sys.stderr,
                    flush=True,
                )
                terminate_and_wait(process, signal.SIGTERM)
                return 124
            time.sleep(min(POLL_INTERVAL_SECONDS, remaining))
    except ForwardedSignal as forwarded:
        terminate_and_wait(process, signal.Signals(forwarded.signum))
        return 128 + forwarded.signum
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    raise SystemExit(main())
