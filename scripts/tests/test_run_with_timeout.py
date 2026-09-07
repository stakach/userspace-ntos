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
        post_ready_seconds: float | None = None,
        merge_output: bool = False,
        failure_file: Path | None = None,
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
            if post_ready_seconds is not None:
                args.extend(["--post-ready-seconds", str(post_ready_seconds)])
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
        if failure_file is not None:
            args.extend(
                ["--failure-file", str(failure_file), "--failure-text", "BOOT_FAILED"]
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

    def test_post_ready_deadline_bounds_missing_completion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            ready_file = Path(temporary_directory) / "serial.log"
            ready_file.touch()
            program = (
                "import pathlib,time; "
                "time.sleep(.2); "
                f"pathlib.Path({str(ready_file)!r}).write_text('DESKTOP_READY'); "
                "time.sleep(30)"
            )
            started = time.monotonic()
            result = self.run_helper(
                3,
                [sys.executable, "-c", program],
                ready_file,
                post_ready_seconds=0.3,
            )
        self.assertEqual(result.returncode, 124)
        self.assertIn("completion deadline armed", result.stderr)
        self.assertLess(time.monotonic() - started, 3)

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

    def test_terminal_failure_stops_running_process(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "serial.log"
            program = (
                "import pathlib,time; "
                f"pathlib.Path({str(log)!r}).write_text('BOOT_FAILED'); "
                "time.sleep(30)"
            )
            started = time.monotonic()
            result = self.run_helper(
                6, [sys.executable, "-c", program], failure_file=log
            )
        self.assertEqual(result.returncode, 125)
        self.assertIn("terminal failure marker observed", result.stderr)
        self.assertLess(time.monotonic() - started, 3)

    def test_split_failure_after_readiness_still_stops_process(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "serial.log"
            program = (
                "import pathlib,time; "
                f"p=pathlib.Path({str(log)!r}); p.write_text('DESKTOP_READY'); "
                "time.sleep(.2); p.open('a').write('BOOT_'); "
                "time.sleep(.2); p.open('a').write('FAILED'); time.sleep(30)"
            )
            result = self.run_helper(
                1, [sys.executable, "-c", program], ready_file=log, failure_file=log
            )
        self.assertEqual(result.returncode, 125)
        self.assertIn("deadline disarmed", result.stderr)
        self.assertIn("terminal failure marker observed", result.stderr)

    def test_failure_during_completion_grace_overrides_completion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "serial.log"
            program = (
                "import pathlib,time; "
                f"p=pathlib.Path({str(log)!r}); p.write_text('BOOT_COMPLETE'); "
                "time.sleep(.3); p.open('a').write('BOOT_FAILED'); time.sleep(30)"
            )
            started = time.monotonic()
            result = self.run_helper(
                1, [sys.executable, "-c", program], completion_file=log,
                completion_grace_seconds=5, failure_file=log,
            )
        self.assertEqual(result.returncode, 125)
        self.assertIn("completion marker observed", result.stderr)
        self.assertIn("terminal failure marker observed", result.stderr)
        self.assertLess(time.monotonic() - started, 3)

    def test_failure_and_successful_exit_in_one_poll_is_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "serial.log"
            program = (
                "import pathlib; "
                f"pathlib.Path({str(log)!r}).write_text('BOOT_COMPLETE BOOT_FAILED')"
            )
            result = self.run_helper(
                1, [sys.executable, "-c", program], completion_file=log, failure_file=log
            )
        self.assertEqual(result.returncode, 125)

    def test_stale_failure_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "serial.log"
            log.write_text("BOOT_FAILED")
            result = self.run_helper(
                1, [sys.executable, "-c", "import time; time.sleep(.2)"], failure_file=log
            )
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("terminal failure", result.stderr)

    def test_failure_during_timeout_shutdown_remains_terminal_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "serial.log"
            program = (
                "import pathlib,signal,sys,time\n"
                "def stopped(signum, frame):\n"
                f"    pathlib.Path({str(log)!r}).write_text('BOOT_FAILED')\n"
                "    sys.exit(0)\n"
                "signal.signal(signal.SIGTERM, stopped)\n"
                "time.sleep(30)\n"
            )
            result = self.run_helper(
                1, [sys.executable, "-c", program], failure_file=log
            )
        self.assertEqual(result.returncode, 125)
        self.assertIn("terminal failure marker observed during shutdown", result.stderr)

    def test_failure_options_require_pair(self) -> None:
        for option in ["--failure-file", "--failure-text"]:
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--seconds", "1", "--cwd", ".",
                 option, "value", "--", sys.executable, "-c", "pass"],
                capture_output=True, text=True, timeout=3,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("must be specified together", result.stderr)


if __name__ == "__main__":
    unittest.main()
