"""Linux process stat parsing must keep CPU evidence aligned with QEMU's group."""

import os
import unittest
from unittest.mock import patch

from scripts.ci_kvm_smoke import parse_proc_stat, read_host_state


class ProcStatCpuTests(unittest.TestCase):
    @staticmethod
    def stat(group):
        fields = ["S"] + ["0"] * 21
        fields[2] = str(group)
        fields[11] = "250"
        fields[12] = "75"
        fields[21] = "4096"
        return "42 (qemu (boot) worker) " + " ".join(fields)

    def test_parenthesized_process_name_does_not_shift_cpu_fields(self):
        # Fields after comm start with state (#3); utime/stime are #14/#15, RSS #24.
        self.assertEqual(parse_proc_stat(self.stat(17)), (17, 325, 4096))

    def test_incomplete_record_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_proc_stat("42 (qemu) S 0")

    @patch("scripts.ci_kvm_smoke.subprocess.check_output")
    @patch("scripts.ci_kvm_smoke.Path.read_text", autospec=True)
    def test_reused_pid_does_not_join_the_exact_group(self, read_text, check_output):
        check_output.return_value = "42 17 S\n43 17 S\n"
        def content(path):
            if str(path) == "/proc/42/stat":
                return self.stat(17)
            if str(path) == "/proc/43/stat":
                return self.stat(99)
            return "some avg10=0.00 total=0\nfull avg10=0.00 total=0\n"
        read_text.side_effect = content
        state = read_host_state(17)
        self.assertEqual(state["group_members"], 1)
        self.assertEqual(state["group_cpu_seconds"], round(325 / os.sysconf("SC_CLK_TCK"), 3))
        self.assertIn("full avg10", state["cpu_pressure"])


if __name__ == "__main__":
    unittest.main()
