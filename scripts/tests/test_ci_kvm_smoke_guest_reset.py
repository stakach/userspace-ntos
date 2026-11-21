"""A guest triple fault must pause QEMU with its registers, and stopping must still exit."""

import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts import ci_kvm_qmp_control, ci_kvm_smoke
from scripts.ci_kvm_qmp_control import (guest_shutdown_paused, read_run_state,
                                        request_quit)


class FakeStream:
    def __init__(self, replies):
        self.replies = replies
        self.pending = [json.dumps({"QMP": {}}).encode() + b"\n"]
        self.commands = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def readline(self):
        return self.pending.pop(0) if self.pending else b""

    def write(self, data):
        command = json.loads(data)
        self.commands.append(command["execute"])
        reply = self.replies.get(command["execute"], {"return": {}})
        if reply is not None:
            # An asynchronous event first: the reader must match its own command id.
            self.pending.append(json.dumps({"event": "STOP"}).encode() + b"\n")
            self.pending.append(json.dumps({"id": command["id"], **reply}).encode() + b"\n")


class FakeSocket:
    def __init__(self, stream):
        self.stream = stream

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def settimeout(self, _seconds):
        pass

    def connect(self, _path):
        pass

    def makefile(self, *_args, **_kwargs):
        return self.stream


def fake_qmp(replies):
    stream = FakeStream(replies)
    return stream, patch.object(ci_kvm_qmp_control.socket, "socket",
                                lambda *_args: FakeSocket(stream))


class GuestResetTests(unittest.TestCase):
    def test_only_the_shutdown_run_state_is_a_guest_reset(self):
        self.assertTrue(guest_shutdown_paused({"status": "shutdown", "running": False}))
        for status in ({"status": "running", "running": True},
                       {"status": "paused", "running": False}, None, []):
            self.assertFalse(guest_shutdown_paused(status))

    def test_run_state_is_read_through_query_status(self):
        stream, qmp = fake_qmp({"query-status": {"return": {"status": "shutdown"}}})
        with qmp:
            self.assertTrue(guest_shutdown_paused(read_run_state("qmp.sock")))
        self.assertEqual(stream.commands, ["qmp_capabilities", "query-status"])

    def test_unanswered_run_state_is_not_a_reset(self):
        with patch.object(ci_kvm_qmp_control.socket, "socket", side_effect=OSError):
            self.assertIsNone(read_run_state("qmp.sock"))

    def test_quit_succeeds_when_qemu_disconnects(self):
        stream, qmp = fake_qmp({"quit": None})
        with qmp:
            self.assertTrue(request_quit("qmp.sock"))
        self.assertEqual(stream.commands, ["qmp_capabilities", "quit"])

    def test_quit_reports_unavailable_qmp(self):
        with patch.object(ci_kvm_qmp_control.socket, "socket", side_effect=OSError):
            self.assertFalse(request_quit("qmp.sock"))

    def test_runner_requests_the_pausing_shutdown_action(self):
        self.assertEqual(ci_kvm_qmp_control.QEMU_SHUTDOWN_ACTION, ["-action", "shutdown=pause"])
        source = Path(ci_kvm_smoke.__file__).read_text()
        self.assertIn("*QEMU_SHUTDOWN_ACTION", source)

    def test_stop_quits_a_paused_qemu_through_qmp_first(self):
        child = subprocess.Popen(["sleep", "30"], start_new_session=True)
        quits = []

        def quit_paused(_path):
            quits.append(True)
            os.killpg(child.pid, signal.SIGKILL)
            return True

        try:
            with tempfile.NamedTemporaryFile() as sock, \
                    patch.object(ci_kvm_smoke, "QMP_SOCKET", Path(sock.name)), \
                    patch.object(ci_kvm_smoke, "request_quit", quit_paused), \
                    patch.object(ci_kvm_smoke.os, "killpg", wraps=os.killpg) as killpg:
                ci_kvm_smoke.stop_process_group(child)
                self.assertEqual(quits, [True])
                self.assertEqual([c for c in killpg.call_args_list
                                  if c.args[1] == signal.SIGTERM], [],
                                 "a clean QMP quit needs no signal")
            self.assertIsNotNone(child.poll())
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
