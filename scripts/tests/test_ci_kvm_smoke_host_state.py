"""Linux process stat parsing must keep CPU evidence aligned with QEMU's group."""

import os
import unittest
from unittest.mock import patch

from scripts.ci_kvm_smoke import cpu_sample_delay, parse_proc_stat, read_host_state, stationary_boot_pair


class StationaryBootTests(unittest.TestCase):
    @staticmethod
    def sample(elapsed, serial, halted=(True, True), boot_marker=True):
        cpus = [{"cpu-index": index} for index in range(len(halted))]
        registers = {str(index): f"RIP=deadbeef HLT={int(value)}" for index, value in enumerate(halted)}
        return {"elapsed_seconds": elapsed, "serial_bytes": serial,
                "boot_marker": boot_marker, "state": {"cpus": cpus, "registers": registers}}

    def test_two_stationary_halted_samples_are_a_stall(self):
        self.assertTrue(stationary_boot_pair(self.sample(48, 200000), self.sample(91, 200000)))

    def test_new_serial_progress_clears_stall(self):
        self.assertFalse(stationary_boot_pair(self.sample(48, 200000), self.sample(91, 200001)))

    def test_running_cpu_or_short_interval_is_not_a_stall(self):
        self.assertFalse(stationary_boot_pair(self.sample(48, 200000),
                                              self.sample(91, 200000, (True, False))))
        self.assertFalse(stationary_boot_pair(self.sample(48, 200000), self.sample(70, 200000)))

    def test_missing_or_preboot_samples_cannot_stop_guest(self):
        self.assertFalse(stationary_boot_pair(None, self.sample(91, 200000)))
        self.assertFalse(stationary_boot_pair(self.sample(48, 200000, boot_marker=False),
                                              self.sample(91, 200000)))
        incomplete = self.sample(91, 200000)
        incomplete["state"]["registers"].pop("1")
        self.assertFalse(stationary_boot_pair(self.sample(48, 200000), incomplete))

    def test_interactive_desktop_may_be_quiet_without_being_stalled(self):
        desktop = self.sample(91, 200000)
        desktop["desktop_ready"] = True
        self.assertFalse(stationary_boot_pair(self.sample(48, 200000), desktop))


class ProcStatCpuTests(unittest.TestCase):
    def test_cpu_samples_move_across_periodic_guest_phases(self):
        delays = [cpu_sample_delay(index) for index in range(8)]
        self.assertEqual(delays[:4], delays[4:])
        self.assertEqual(len(set(delays[:4])), 4)
        self.assertTrue(all(0 < delay < 60 for delay in delays))

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
