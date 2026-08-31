#!/usr/bin/env python3
"""Run one command in its own process group with a hard wall-clock limit."""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys


def terminate_group(process: subprocess.Popen[bytes], signum: signal.Signals) -> None:
    try:
        os.killpg(process.pid, signum)
    except ProcessLookupError:
        pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=int, required=True)
    parser.add_argument("--cwd", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if args.seconds <= 0 or not command:
        parser.error("a positive timeout and command are required")

    process = subprocess.Popen(command, cwd=args.cwd, start_new_session=True)
    try:
        return process.wait(timeout=args.seconds)
    except subprocess.TimeoutExpired:
        print(
            f"boot validation exceeded {args.seconds}s; terminating process group",
            file=sys.stderr,
            flush=True,
        )
        terminate_group(process, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            terminate_group(process, signal.SIGKILL)
            process.wait()
        return 124
    except KeyboardInterrupt:
        terminate_group(process, signal.SIGINT)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            terminate_group(process, signal.SIGKILL)
            process.wait()
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
