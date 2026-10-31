"""The bounded boot must not leave QEMU's child process holding the disk."""

import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest

from scripts.ci_kvm_smoke import stop_process_group


def is_live(pid):
    result = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)],
                            capture_output=True, text=True, check=False)
    return result.returncode == 0 and not result.stdout.strip().startswith("Z")


class ProcessGroupStopTests(unittest.TestCase):
    def test_reaps_a_child_after_the_launcher_exits(self):
        with tempfile.TemporaryDirectory() as directory:
            child_pid_file = Path(directory) / "child.pid"
            launcher = subprocess.Popen(
                [sys.executable, "-c",
                 "import pathlib, subprocess, sys; "
                 "child = subprocess.Popen(['sleep', '30']); "
                 "pathlib.Path(sys.argv[1]).write_text(str(child.pid))",
                 str(child_pid_file)],
                start_new_session=True,
            )
            child_pid = None
            try:
                launcher.wait(timeout=5)
                child_pid = int(child_pid_file.read_text())
                self.assertTrue(is_live(child_pid))
                stop_process_group(launcher)
                self.assertFalse(is_live(child_pid))
            finally:
                if child_pid is None or is_live(child_pid):
                    try:
                        os.killpg(launcher.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                if launcher.poll() is None:
                    launcher.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
