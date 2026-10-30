#!/usr/bin/env python3
"""Bounded CI startup probe with a framebuffer capture; not desktop acceptance."""

import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time


ROOT = Path(__file__).resolve().parent.parent
MICRO = ROOT / "rust-micro"
LOG = ROOT / "native-kvm-smoke.log"
SCREENSHOT = ROOT / "native-kvm-smoke.ppm"
QMP_SOCKET = ROOT / "native-kvm-smoke-qmp.sock"


def qmp_reply(stream, command_id):
    while True:
        line = stream.readline()
        if not line:
            raise RuntimeError("QMP disconnected")
        reply = json.loads(line)
        if reply.get("id") != command_id:
            continue
        if "error" in reply:
            raise RuntimeError(f"QMP {command_id}: {reply['error']}")
        return reply


def capture_framebuffer():
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(10)
        connection.connect(str(QMP_SOCKET))
        with connection.makefile("rwb", buffering=0) as stream:
            greeting = json.loads(stream.readline())
            if "QMP" not in greeting:
                raise RuntimeError("QMP greeting missing")
            stream.write(b'{"execute":"qmp_capabilities","id":"capabilities"}\n')
            qmp_reply(stream, "capabilities")
            command = {
                "execute": "screendump",
                "arguments": {"filename": str(SCREENSHOT), "format": "ppm"},
                "id": "screendump",
            }
            stream.write((json.dumps(command) + "\n").encode())
            qmp_reply(stream, "screendump")
    if not SCREENSHOT.is_file() or SCREENSHOT.stat().st_size == 0:
        raise RuntimeError("QMP did not write a framebuffer image")


def stop_process_group(process):
    if process.poll() is not None:
        return
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, default=180)
    args = parser.parse_args()
    if not 1 <= args.seconds <= 3600:
        parser.error("--seconds must be between 1 and 3600")
    QMP_SOCKET.unlink(missing_ok=True)
    SCREENSHOT.unlink(missing_ok=True)
    command = [
        "./scripts/run_specs.sh",
        "-qmp",
        f"unix:{QMP_SOCKET},server=on,wait=off",
    ]
    with LOG.open("wb") as log:
        process = subprocess.Popen(
            command,
            cwd=MICRO,
            env=os.environ.copy(),
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        started = time.monotonic()
        next_capture = started + 10
        captured = False
        try:
            while time.monotonic() - started < args.seconds:
                if process.poll() is not None:
                    break
                if time.monotonic() >= next_capture and QMP_SOCKET.exists():
                    try:
                        capture_framebuffer()
                        captured = True
                        print(f"QMP framebuffer captured: {SCREENSHOT.name}", flush=True)
                    except (OSError, RuntimeError, ValueError) as error:
                        print(f"QMP framebuffer capture pending: {error}", flush=True)
                    next_capture = time.monotonic() + 30
                time.sleep(1)
        finally:
            stop_process_group(process)
            QMP_SOCKET.unlink(missing_ok=True)

    output = LOG.read_text(errors="replace")
    if "boot: reading Simpleboot memory map" not in output:
        raise SystemExit("guest startup marker absent; inspect native-kvm-smoke.log")
    if not captured:
        raise SystemExit("no QMP framebuffer captured; inspect native-kvm-smoke.log")
    print("KVM smoke passed: guest started and QMP framebuffer was captured")
    print("This probe does not establish Explorer desktop acceptance")


if __name__ == "__main__":
    main()
