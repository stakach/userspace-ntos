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
        self,
        seconds: int,
        command: list[str],
        ready_file: Path | None = None,
        completion_file: Path | None = None,
        completion_grace_seconds: float = 5.0,
        merge_output: bool = False,
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
        if completion_file is not None:
            args.extend(
                [
                    "--completion-file",
                    str(completion_file),
                    "--completion-text",
                    "BOOT_COMPLETE",
                    "--completion-grace-seconds",
                    str(completion_grace_seconds),
                ]
            )
        args.extend(["--", *command])
        if merge_output:
            return subprocess.run(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=8,
            )
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

    def test_readiness_status_cannot_split_merged_child_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            ready_file = Path(temporary_directory) / "serial.log"
            ready_file.touch()
            program = (
                "import pathlib,time; "
                "print('GUEST_BEGIN', flush=True); "
                f"pathlib.Path({str(ready_file)!r}).write_text('DESKTOP_READY'); "
                "time.sleep(.3); print('GUEST_END', flush=True)"
            )
            result = self.run_helper(
                1,
                [sys.executable, "-c", program],
                ready_file,
                merge_output=True,
            )
        self.assertEqual(result.returncode, 0)
        self.assertIsNone(result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            [
                "GUEST_BEGIN",
                "GUEST_END",
                "boot readiness marker observed; deadline disarmed",
            ],
        )

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

    def test_completion_marker_ends_a_ready_but_running_process(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            marker_file = Path(temporary_directory) / "serial.log"
            marker_file.touch()
            program = (
                "import pathlib,time; "
                f"p=pathlib.Path({str(marker_file)!r}); "
                "time.sleep(.2); p.write_text('DESKTOP_READY'); "
                "time.sleep(.2); p.open('a').write('BOOT_COMPLETE'); "
                "time.sleep(30)"
            )
            started = time.monotonic()
            result = self.run_helper(
                1,
                [sys.executable, "-c", program],
                marker_file,
                marker_file,
                0.1,
            )
        self.assertEqual(result.returncode, 0)
        self.assertIn("deadline disarmed", result.stderr)
        self.assertIn("completion marker observed", result.stderr)
        self.assertIn("grace expired", result.stderr)
        self.assertLess(time.monotonic() - started, 3)

    def test_completion_marker_preserves_a_prompt_child_exit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            completion_file = Path(temporary_directory) / "serial.log"
            completion_file.touch()
            program = (
                "import pathlib,sys,time; "
                f"pathlib.Path({str(completion_file)!r}).write_text('BOOT_COMPLETE'); "
                "time.sleep(.2); sys.exit(3)"
            )
            result = self.run_helper(
                1,
                [sys.executable, "-c", program],
                completion_file=completion_file,
            )
        self.assertEqual(result.returncode, 3)
        self.assertIn("completion marker observed", result.stderr)

    def test_stale_completion_marker_does_not_end_the_process(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            completion_file = Path(temporary_directory) / "serial.log"
            completion_file.write_text("BOOT_COMPLETE")
            result = self.run_helper(
                1,
                [sys.executable, "-c", "import time; time.sleep(30)"],
                completion_file=completion_file,
            )
        self.assertEqual(result.returncode, 124)
        self.assertNotIn("completion marker observed", result.stderr)


if __name__ == "__main__":
    unittest.main()
