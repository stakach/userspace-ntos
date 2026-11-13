"""Attribute host CPU time only to QMP's exact QEMU vCPU threads."""

import os
from pathlib import Path
import tempfile
import unittest

from scripts.ci_kvm_smoke import read_vcpu_host_state


def proc_stat(pid, group, utime=250, stime=75, starttime=900):
    fields = ["S"] + ["0"] * 21
    fields[2] = str(group)
    fields[11] = str(utime)
    fields[12] = str(stime)
    fields[19] = str(starttime)
    return f"{pid} (qemu (boot) worker) " + " ".join(fields)


class VcpuHostCpuTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.proc = Path(self.directory.name)
        (self.proc / "510" / "task" / "512").mkdir(parents=True)
        (self.proc / "512").mkdir()
        (self.proc / "512" / "status").write_text("Name:\tCPU 0/KVM\nTgid:\t510\n")
        (self.proc / "510" / "stat").write_text(proc_stat(510, 42, starttime=800))
        (self.proc / "510" / "task" / "512" / "stat").write_text(
            proc_stat(512, 42, starttime=900)
        )
        (self.proc / "510" / "exe").symlink_to("/usr/bin/qemu-system-x86_64")

    def sample(self):
        return read_vcpu_host_state(42, [{"cpu-index": 0, "thread-id": 512}], self.proc)["0"]

    def test_exact_qemu_thread_records_identity_and_cpu_time(self):
        sample = self.sample()
        self.assertEqual(sample["tid"], 512)
        self.assertEqual(sample["tgid"], 510)
        self.assertEqual(sample["process_starttime_ticks"], 800)
        self.assertEqual(sample["thread_starttime_ticks"], 900)
        self.assertEqual(sample["cpu_seconds"], round(325 / os.sysconf("SC_CLK_TCK"), 3))
        self.assertNotIn("error", sample)

    def test_reused_thread_id_changes_generation(self):
        before = self.sample()
        (self.proc / "510" / "task" / "512" / "stat").write_text(
            proc_stat(512, 42, utime=1, stime=0, starttime=901)
        )
        after = self.sample()
        self.assertNotEqual(before["thread_starttime_ticks"], after["thread_starttime_ticks"])
        self.assertLess(after["cpu_seconds"], before["cpu_seconds"])

    def test_unrelated_process_in_same_group_is_not_qemu(self):
        (self.proc / "510" / "exe").unlink()
        (self.proc / "510" / "exe").symlink_to("/usr/bin/bash")
        self.assertIn("error", self.sample())
        self.assertNotIn("cpu_seconds", self.sample())

    def test_wrong_group_or_thread_identity_is_unavailable(self):
        (self.proc / "510" / "stat").write_text(proc_stat(510, 99))
        self.assertIn("error", self.sample())
        (self.proc / "510" / "stat").write_text(proc_stat(510, 42))
        (self.proc / "510" / "task" / "512" / "stat").write_text(proc_stat(513, 42))
        self.assertIn("error", self.sample())

    def test_missing_task_or_tgid_is_unavailable(self):
        (self.proc / "510" / "task" / "512" / "stat").unlink()
        self.assertIn("error", self.sample())
        (self.proc / "512" / "status").write_text("Name:\tCPU 0/KVM\n")
        self.assertIn("error", self.sample())

    def test_missing_qmp_thread_id_is_unavailable(self):
        sample = read_vcpu_host_state(42, [{"cpu-index": 0}], self.proc)["0"]
        self.assertIn("error", sample)
        self.assertNotIn("cpu_seconds", sample)


if __name__ == "__main__":
    unittest.main()
