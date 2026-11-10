"""Retain read-only interrupt-controller evidence when a boot becomes idle."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.ci_kvm_smoke import (capture_stall_state, read_interrupt_state,
                                  retain_halted_interrupt_state, stationary_boot_pair)


class FakeQmpStream:
    def __init__(self, bad_cpu_reply=False):
        self.pending = [json.dumps({"QMP": {}}).encode() + b"\n"]
        self.commands = []
        self.bad_cpu_reply = bad_cpu_reply

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def readline(self):
        return self.pending.pop(0) if self.pending else b""

    def write(self, data):
        command = json.loads(data)
        self.commands.append(command)
        command_id = command["id"]
        if command_id == "cpus":
            cpus = None if self.bad_cpu_reply else [{"cpu-index": 0}, {"cpu-index": 2}]
            reply = {"id": command_id, "return": cpus}
        elif command_id == "lapic-2":
            reply = {"id": command_id, "error": {"class": "GenericError", "desc": "unavailable"}}
        else:
            reply = {"id": command_id, "return": command_id + "-snapshot"}
        self.pending.append(json.dumps(reply).encode() + b"\n")


class FakeQmpSocket:
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


class InterruptStateTests(unittest.TestCase):
    def test_each_all_halted_sample_retains_comparable_interrupt_state(self):
        calls = []
        def capture():
            calls.append(len(calls))
            return {"irq": f"at-{len(calls)}"}

        before = {"elapsed_seconds": 20, "boot_marker": True, "desktop_ready": False,
                  "serial_bytes": 42, "state": {"cpus": [{"cpu-index": 0}],
                  "registers": {"0": "CPU#0 HLT=1"}}}
        after = {"elapsed_seconds": 60, "boot_marker": True, "desktop_ready": False,
                 "serial_bytes": 42, "state": {"cpus": [{"cpu-index": 0}],
                 "registers": {"0": "CPU#0 HLT=1"}}}
        retain_halted_interrupt_state(before, capture)
        retain_halted_interrupt_state(after, capture)
        self.assertTrue(stationary_boot_pair(before, after))
        self.assertEqual(before["interrupts"], {"irq": "at-1"})
        self.assertEqual(after["interrupts"], {"irq": "at-2"})

    def test_running_sample_skips_interrupt_capture(self):
        sample = {"state": {"cpus": [{"cpu-index": 0}],
                            "registers": {"0": "CPU#0 HLT=0"}}}
        def forbidden():
            self.fail("running guest must not acquire extra QMP samples")
        retain_halted_interrupt_state(sample, forbidden)
        self.assertNotIn("interrupts", sample)

    def test_reads_pic_irq_and_each_lapic_without_losing_partial_failure(self):
        stream = FakeQmpStream()
        with patch("scripts.ci_kvm_smoke.socket.socket", return_value=FakeQmpSocket(stream)):
            state = read_interrupt_state()
        self.assertEqual(state["pic"], "pic-snapshot")
        self.assertEqual(state["irq"], "irq-snapshot")
        self.assertEqual(state["lapic"]["0"], "lapic-0-snapshot")
        self.assertIn("unavailable", state["lapic_errors"]["2"])
        self.assertEqual([command["id"] for command in stream.commands],
                         ["capabilities", "cpus", "pic", "irq", "lapic-0", "lapic-2"])
        self.assertEqual([command["arguments"]["command-line"]
                          for command in stream.commands[2:]],
                         ["info pic", "info irq", "info lapic", "info lapic"])
        self.assertEqual(stream.commands[4]["arguments"]["cpu-index"], 0)
        self.assertEqual(stream.commands[5]["arguments"]["cpu-index"], 2)

    def test_pic_and_irq_survive_unavailable_cpu_list(self):
        stream = FakeQmpStream(bad_cpu_reply=True)
        with patch("scripts.ci_kvm_smoke.socket.socket", return_value=FakeQmpSocket(stream)):
            state = read_interrupt_state()
        self.assertIn("CPU list missing", state["cpu_error"])
        self.assertEqual(state["pic"], "pic-snapshot")
        self.assertEqual(state["irq"], "irq-snapshot")
        self.assertEqual(state["lapic"], {})

    def test_stall_artifact_includes_interrupt_state(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            serial = Path(directory) / "serial.log"
            serial.write_bytes(b"")
            with (patch("scripts.ci_kvm_smoke.read_cpu_state", return_value={"cpus": []}),
                  patch("scripts.ci_kvm_smoke.read_interrupt_state",
                        return_value={"pic": "PIC", "irq": "IRQ", "lapic": {}}),
                  patch("scripts.ci_kvm_smoke.LOG", serial)):
                capture_stall_state(path)
            artifact = json.loads(path.read_text())
            self.assertEqual(artifact["interrupts"],
                             {"pic": "PIC", "irq": "IRQ", "lapic": {}})


if __name__ == "__main__":
    unittest.main()
