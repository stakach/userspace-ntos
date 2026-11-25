"""A stationary user CPU retains bounded, live code and thread evidence."""

import json
import unittest
from unittest.mock import patch

from scripts import ci_kvm_smoke


REGISTERS = ("CPU#0\r\nRSP=000001001101f7c0\r\n"
             "RIP=0000010000879d7e RFL=00000202 CPL=3 HLT=0\r\n"
             "GS =0000 0000010011042000 ffffffff 00800000\r\n"
             "CR3=000000007e17d000\r\n")


class FakeStream:
    def __init__(self, registers_after=REGISTERS, unreadable=None):
        self.pending = [json.dumps({"QMP": {}}).encode() + b"\n"]
        self.commands = []
        self.registers_after = registers_after
        self.unreadable = unreadable

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def readline(self):
        return self.pending.pop(0) if self.pending else b""

    def write(self, data):
        command = json.loads(data)
        self.commands.append(command)
        result = (self.registers_after if command["id"] == "registers-after"
                  else command["id"])
        reply = ({"id": command["id"], "error": {"desc": "unmapped"}}
                 if command["id"] == self.unreadable else
                 {"id": command["id"], "return": result})
        self.pending.append(json.dumps(reply).encode() + b"\n")


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


class UserStallTests(unittest.TestCase):
    def test_running_user_cpu_captures_code_stack_teb_and_coherence(self):
        stream = FakeStream()
        with patch.object(ci_kvm_smoke.socket, "socket", return_value=FakeSocket(stream)):
            result = ci_kvm_smoke.read_user_execution_context(REGISTERS)
        self.assertEqual(result["code_bytes"], "code-bytes")
        self.assertEqual(result["stack"], "stack")
        self.assertEqual(result["teb_client_id"], "teb-client-id")
        self.assertTrue(result["coherent"])
        self.assertEqual([command["arguments"]["command-line"]
                          for command in stream.commands[1:]],
                         ["x /64bx 0x10000879d5e", "x /16i 0x10000879d7e",
                          "x /32gx 0x1001101f7c0", "x /2gx 0x10011042040",
                          "info registers"])
        self.assertTrue(all(command["arguments"]["cpu-index"] == 0
                            for command in stream.commands[1:]))

    def test_halted_or_kernel_cpu_skips_user_memory(self):
        self.assertIsNone(ci_kvm_smoke.read_user_execution_context(
            REGISTERS.replace("HLT=0", "HLT=1")))
        self.assertIsNone(ci_kvm_smoke.read_user_execution_context(
            REGISTERS.replace("CPL=3", "CPL=0")))

    def test_changed_address_space_marks_memory_incoherent_without_hiding_reads(self):
        stream = FakeStream(registers_after=REGISTERS.replace("7e17d000", "7e17e000"),
                            unreadable="teb-client-id")
        with patch.object(ci_kvm_smoke.socket, "socket", return_value=FakeSocket(stream)):
            result = ci_kvm_smoke.read_user_execution_context(REGISTERS)
        self.assertFalse(result["coherent"])
        self.assertEqual(result["code_bytes"], "code-bytes")
        self.assertIn("unmapped", result["errors"]["teb_client_id"])


if __name__ == "__main__":
    unittest.main()
