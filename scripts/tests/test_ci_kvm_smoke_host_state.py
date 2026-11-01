"""Linux process stat parsing must keep CPU evidence aligned with QEMU's group."""

import os
import unittest
from unittest.mock import patch

import scripts.ci_kvm_smoke as smoke
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


class PsCreateFoldStallTests(unittest.TestCase):
    @staticmethod
    def samples(extra=b"", elapsed=150, second_rip="00000100004c0033"):
        first = (b"boot: reading Simpleboot memory map\n"
                 b"[ps-create-event] #1048576 stage=fold-enter route=1152921504606847011 reply=0 label=0\n")
        fold = (b"[ps-create-after-autonomous] #524288 stage=loop tcb=238686 route=1152921504606847011\n"
                b"[ps-create-event] #2097152 stage=fold-service-return route=1152921504606847011 reply=0 label=0\n"
                b"[ps-create-after-autonomous] #1048576 stage=loop tcb=238686 route=1152921504606847011\n")
        serial = first + fold + extra
        def sample(seconds, size, rip, cpu):
            return {"elapsed_seconds": seconds, "serial_bytes": size, "boot_marker": True,
                    "desktop_ready": False, "host": {"group_cpu_seconds": cpu},
                    "state": {"cpus": [{"cpu-index": i} for i in range(4)],
                              "registers": {str(i): (f"RIP={rip} CR3=000000007d4ff000 HLT=0" if i == 0
                                                     else "RIP=fffffffffe02dce2 CR3=000000007dd72000 HLT=1")
                                            for i in range(4)}}}
        return (sample(91, len(first), "00000100004c0033", 67.73),
                sample(elapsed, len(serial), second_rip, 126.86), serial)

    @staticmethod
    def classify(previous, current, serial):
        # The old classifier is the behavioral RED: serial fold diagnostics grow while CPU0 spins.
        detector = getattr(smoke, "ps_create_fold_stall_pair", None)
        return detector(previous, current, serial) if detector else stationary_boot_pair(previous, current)

    def test_repeated_same_route_fold_with_one_spinning_cpu_is_stationary(self):
        previous, current, serial = self.samples()
        self.assertTrue(self.classify(previous, current, serial))

    def test_real_installation_progress_never_counts_as_fold_only(self):
        previous, current, serial = self.samples(b"[writable-fs-snapshot] committed generation=4 bytes=2048\n")
        self.assertFalse(self.classify(previous, current, serial))

    def test_changed_cpu_or_route_does_not_stop_guest(self):
        previous, current, serial = self.samples(second_rip="00000100004c0044")
        self.assertFalse(self.classify(previous, current, serial))
        previous, current, serial = self.samples()
        changed = serial.replace(b"stage=loop tcb=238686 route=1152921504606847011",
                                 b"stage=loop tcb=238686 route=1152921504606847012")
        self.assertFalse(self.classify(previous, current, changed))

    def test_short_interval_or_desktop_does_not_stop_guest(self):
        previous, current, serial = self.samples(elapsed=110)
        self.assertFalse(self.classify(previous, current, serial))
        previous, current, serial = self.samples()
        current["desktop_ready"] = True
        self.assertFalse(self.classify(previous, current, serial))


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
