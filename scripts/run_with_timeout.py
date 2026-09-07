#!/usr/bin/env python3
"""Run one command with independent boot-readiness and completion policies."""

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
    parser.add_argument("--post-ready-seconds", type=float)
    parser.add_argument("--completion-file")
    parser.add_argument("--completion-text")
    parser.add_argument("--completion-grace-seconds", type=float, default=5.0)
    parser.add_argument("--failure-file")
    parser.add_argument("--failure-text")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if args.seconds <= 0 or not command:
        parser.error("a positive timeout and command are required")
    if bool(args.ready_file) != bool(args.ready_text):
        parser.error("--ready-file and --ready-text must be specified together")
    if args.post_ready_seconds is not None and args.post_ready_seconds <= 0:
        parser.error("--post-ready-seconds must be positive")
    if args.post_ready_seconds is not None and not args.ready_file:
        parser.error("--post-ready-seconds requires --ready-file and --ready-text")
    if bool(args.completion_file) != bool(args.completion_text):
        parser.error("--completion-file and --completion-text must be specified together")
    if args.completion_grace_seconds < 0:
        parser.error("--completion-grace-seconds cannot be negative")
    if bool(args.failure_file) != bool(args.failure_text):
        parser.error("--failure-file and --failure-text must be specified together")

    ready_path = Path(args.ready_file) if args.ready_file else None
    ready_marker = args.ready_text.encode() if args.ready_text else None
    try:
        ready_offset = ready_path.stat().st_size if ready_path else 0
    except FileNotFoundError:
        ready_offset = 0
    ready_tail = b""
    completion_path = Path(args.completion_file) if args.completion_file else None
    completion_marker = args.completion_text.encode() if args.completion_text else None
    try:
        completion_offset = completion_path.stat().st_size if completion_path else 0
    except FileNotFoundError:
        completion_offset = 0
    completion_tail = b""
    failure_path = Path(args.failure_file) if args.failure_file else None
    failure_marker = args.failure_text.encode() if args.failure_text else None
    try:
        failure_offset = failure_path.stat().st_size if failure_path else 0
    except FileNotFoundError:
        failure_offset = 0
    failure_tail = b""
    status_messages: list[str] = []

    def failure_observed() -> bool:
        nonlocal failure_offset, failure_tail
        if failure_path is None or failure_marker is None:
            return False
        failed, failure_offset, failure_tail = ready_marker_observed(
            failure_path, failure_marker, failure_offset, failure_tail
        )
        return failed

    def flush_status_messages() -> None:
        for message in status_messages:
            print(message, file=sys.stderr, flush=True)
        status_messages.clear()

    def forward_signal(signum: int, _frame: object) -> None:
        raise ForwardedSignal(signum)

    forwarded_signals = [signal.SIGINT, signal.SIGTERM]
    for signal_name in ("SIGHUP", "SIGQUIT"):
        forwarded_signals.append(getattr(signal, signal_name))
    previous_handlers = {
        signum: signal.signal(signum, forward_signal) for signum in forwarded_signals
    }

    process = subprocess.Popen(command, cwd=args.cwd, start_new_session=True)
    deadline: float | None = time.monotonic() + args.seconds
    completion_deadline: float | None = None
    try:
        while True:
            if failure_observed():
                status_messages.append(
                    "terminal failure marker observed; terminating process group"
                )
                terminate_and_wait(process, signal.SIGTERM)
                flush_status_messages()
                return 125
            result = process.poll()
            if result is not None:
                # Drain bytes written between the first log read and process exit.
                if failure_observed():
                    status_messages.append("terminal failure marker observed at process exit")
                    flush_status_messages()
                    return 125
                flush_status_messages()
                return result

            if completion_path is not None and completion_marker is not None:
                completed, completion_offset, completion_tail = ready_marker_observed(
                    completion_path,
                    completion_marker,
                    completion_offset,
                    completion_tail,
                )
                if completed:
                    status_messages.append(
                        "completion marker observed; awaiting process exit"
                    )
                    completion_deadline = time.monotonic() + args.completion_grace_seconds
                    completion_path = None
                    completion_marker = None
                    deadline = None
                    ready_path = None
                    ready_marker = None

            if completion_deadline is not None and time.monotonic() >= completion_deadline:
                status_messages.append(
                    "completion exit grace expired; terminating process group",
                )
                terminate_and_wait(process, signal.SIGTERM)
                if failure_observed():
                    status_messages.append("terminal failure marker observed during shutdown")
                    flush_status_messages()
                    return 125
                flush_status_messages()
                return 0

            if ready_path is not None and ready_marker is not None:
                ready, ready_offset, ready_tail = ready_marker_observed(
                    ready_path, ready_marker, ready_offset, ready_tail
                )
                if ready:
                    if args.post_ready_seconds is None:
                        status_messages.append(
                            "boot readiness marker observed; deadline disarmed"
                        )
                        deadline = None
                    else:
                        status_messages.append(
                            "boot readiness marker observed; completion deadline armed"
                        )
                        deadline = time.monotonic() + args.post_ready_seconds
                    ready_path = None
                    ready_marker = None

            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    status_messages.append(
                        "boot validation deadline exceeded; terminating process group",
                    )
                    terminate_and_wait(process, signal.SIGTERM)
                    if failure_observed():
                        status_messages.append("terminal failure marker observed during shutdown")
                        flush_status_messages()
                        return 125
                    flush_status_messages()
                    return 124
                time.sleep(min(POLL_INTERVAL_SECONDS, remaining))
            else:
                time.sleep(POLL_INTERVAL_SECONDS)
    except ForwardedSignal as forwarded:
        terminate_and_wait(process, signal.Signals(forwarded.signum))
        flush_status_messages()
        return 128 + forwarded.signum
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    raise SystemExit(main())
