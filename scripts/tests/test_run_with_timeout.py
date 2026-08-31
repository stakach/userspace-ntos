from __future__ import annotations

import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "run_with_timeout.py"


class RunWithTimeoutTests(unittest.TestCase):
    def run_helper(
        self, seconds: int, command: list[str], ready_file: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        args = [
            sys.executable,
            str(SCRIPT),
            "--seconds",
            str(seconds),
            "--cwd",
            str(SCRIPT.parent),
        ]
        if ready_file is not None:
            args.extend(
                ["--ready-file", str(ready_file), "--ready-text", "DESKTOP_READY"]
            )
        args.extend(["--", *command])
        return subprocess.run(args, capture_output=True, text=True, timeout=8)

    def test_timeout_returns_124(self) -> None:
        started = time.monotonic()
        result = self.run_helper(
            1, [sys.executable, "-c", "import time; time.sleep(30)"]
        )
        self.assertEqual(result.returncode, 124)
        self.assertIn("terminating process group", result.stderr)
        self.assertLess(time.monotonic() - started, 7)

    def test_fresh_readiness_marker_disarms_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            ready_file = Path(temporary_directory) / "serial.log"
            ready_file.touch()
            program = (
                "import pathlib,time; "
                "time.sleep(.2); "
                f"pathlib.Path({str(ready_file)!r}).write_text('DESKTOP_READY'); "
                "time.sleep(1.2)"
            )
            result = self.run_helper(1, [sys.executable, "-c", program], ready_file)
        self.assertEqual(result.returncode, 0)
        self.assertIn("deadline disarmed", result.stderr)

    def test_split_readiness_marker_disarms_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            ready_file = Path(temporary_directory) / "serial.log"
            ready_file.touch()
            program = (
                "import pathlib,time; "
                f"p=pathlib.Path({str(ready_file)!r}); "
                "time.sleep(.2); p.write_text('DESKTOP_'); "
                "time.sleep(.2); p.open('a').write('READY'); "
                "time.sleep(1.2)"
            )
            result = self.run_helper(1, [sys.executable, "-c", program], ready_file)
        self.assertEqual(result.returncode, 0)
        self.assertIn("deadline disarmed", result.stderr)

    def test_stale_readiness_marker_does_not_disarm_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            ready_file = Path(temporary_directory) / "serial.log"
            ready_file.write_text("DESKTOP_READY")
            result = self.run_helper(
                1,
                [sys.executable, "-c", "import time; time.sleep(30)"],
                ready_file,
            )
        self.assertEqual(result.returncode, 124)
        self.assertNotIn("deadline disarmed", result.stderr)


if __name__ == "__main__":
    unittest.main()
