"""A parked executive panic must end a bounded boot without losing serial evidence."""

from pathlib import Path
import tempfile
import unittest

import scripts.ci_kvm_smoke as smoke
from scripts.ci_kvm_smoke import SerialPanicDetector


def terminal_detector(log):
    # Before the terminal detector exists, exercise the live serial scanner and fail on its
    # missing outcome instead of failing test collection at import time.
    detector = getattr(smoke, "SerialTerminalDetector", SerialPanicDetector)
    return detector(log)


class SerialPanicDetectorTests(unittest.TestCase):
    def test_detects_executive_panic_across_fragmented_serial_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "serial.log"
            log.write_bytes(b"[receive-child] phase=parked\n!@src/win32k_")
            detector = SerialPanicDetector(log)
            self.assertIsNone(detector.poll())

            with log.open("ab") as stream:
                stream.write(b"pending_dispatch.rs:1")
            self.assertIsNone(detector.poll())

            with log.open("ab") as stream:
                stream.write(b"66\n")
            self.assertEqual(detector.poll(), "src/win32k_pending_dispatch.rs:166")

    def test_ignores_bare_and_quoted_or_malformed_markers(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "serial.log"
            log.write_bytes(
                b"!\n"
                b"guest mentioned !@src/foo.rs:23 in a status message\n"
                b"!@src/foo.rs:0\n"
                b"!@src/foo.rs:abc\n"
                b"!@src/foo.c:23\n"
            )
            detector = SerialPanicDetector(log)
            self.assertIsNone(detector.poll())

            with log.open("ab") as stream:
                stream.write(b"!@src/foo.rs:23\n")
            self.assertEqual(detector.poll(), "src/foo.rs:23")

    def test_reads_only_new_serial_bytes_after_a_large_progress_log(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "serial.log"
            log.write_bytes(b"progress\n" * 131072)
            detector = SerialPanicDetector(log)
            self.assertIsNone(detector.poll())

            with log.open("ab") as stream:
                stream.write(b"!@src/win32k_receive.rs:477\n")
            self.assertEqual(detector.poll(), "src/win32k_receive.rs:477")


class SerialTerminalDetectorTests(unittest.TestCase):
    def test_quiesce_gate_is_terminal_across_split_serial_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "serial.log"
            log.write_bytes(b"[quiesce] every live process parked/waiting (no sig")
            detector = terminal_detector(log)
            self.assertIsNone(detector.poll())

            with log.open("ab") as stream:
                stream.write(b"naler left) -> run gate\r")
            self.assertIsNone(detector.poll())

            with log.open("ab") as stream:
                stream.write(b"\n")
            self.assertEqual(detector.poll(), "quiesce")
            self.assertIsNone(detector.poll())

    def test_durability_refusal_is_terminal_across_split_serial_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "serial.log"
            log.write_bytes(b"[cm-flush] shutdown hive durability ref")
            detector = terminal_detector(log)
            self.assertIsNone(detector.poll())

            with log.open("ab") as stream:
                stream.write(b"used status=0xc00000a3\n")
            self.assertEqual(detector.poll(), "durability-refused")
            self.assertIsNone(detector.poll())

    def test_partial_or_quoted_quiesce_is_not_terminal(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "serial.log"
            log.write_bytes(
                b"trace: [quiesce] every live process parked/waiting (no signaler left) -> run gate\n"
                b"[quiesce] every live process parked/waiting (no signaler left) -> run gate?\n"
                b"[cm-flush] shutdown hive durability refused status=unknown\n"
            )
            self.assertIsNone(terminal_detector(log).poll())


if __name__ == "__main__":
    unittest.main()
