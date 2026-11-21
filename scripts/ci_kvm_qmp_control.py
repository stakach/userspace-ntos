"""QMP run-state control for the bounded KVM boot.

QEMU runs with `-no-reboot -action shutdown=pause`, so a guest triple fault (a reset
request) stops the VM in the `shutdown` run state instead of exiting. Its vCPU registers
then still describe the fault, which `-d int` cannot record under KVM.
"""

import json
import socket

# A guest reset or power-off leaves the VM paused here rather than exiting QEMU.
QEMU_SHUTDOWN_ACTION = ["-action", "shutdown=pause"]


def qmp_execute(socket_path, execute, timeout=3):
    """Run one argument-free QMP command and return its `return` value."""
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(timeout)
        connection.connect(str(socket_path))
        with connection.makefile("rwb", buffering=0) as stream:
            greeting = json.loads(stream.readline())
            if "QMP" not in greeting:
                raise RuntimeError("QMP greeting missing")
            for command_id, command in (("capabilities", "qmp_capabilities"),
                                        ("command", execute)):
                stream.write((json.dumps({"execute": command, "id": command_id}) + "\n").encode())
                while True:
                    line = stream.readline()
                    if not line:
                        if command == "quit":
                            return None
                        raise RuntimeError("QMP disconnected")
                    reply = json.loads(line)
                    if reply.get("id") != command_id:
                        continue
                    if "error" in reply:
                        raise RuntimeError(f"QMP {command}: {reply['error']}")
                    break
            return reply.get("return")


def guest_shutdown_paused(status):
    """True when `query-status` reports the VM stopped by a guest reset or power-off."""
    return isinstance(status, dict) and status.get("status") == "shutdown"


def read_run_state(socket_path):
    """The VM run state, or None when QMP cannot answer."""
    try:
        return qmp_execute(socket_path, "query-status")
    except (OSError, RuntimeError, ValueError):
        return None


def request_quit(socket_path):
    """Ask QEMU to exit cleanly (flushing its disk); False when QMP is unavailable."""
    try:
        qmp_execute(socket_path, "quit")
        return True
    except (OSError, RuntimeError, ValueError):
        return False
