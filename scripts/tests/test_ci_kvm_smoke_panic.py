"""A parked executive panic must end a bounded boot without losing serial evidence."""

from pathlib import Path
import tempfile
import unittest

from scripts.ci_kvm_smoke import SerialPanicDetector


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


if __name__ == "__main__":
    unittest.main()
