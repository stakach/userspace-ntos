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
    def test_provider_bugcheck_is_terminal_across_split_serial_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "serial.log"
            log.write_bytes(b"[provider-bugcheck] code=0x0000001e\n[provider-bugcheck] term")
            detector = terminal_detector(log)
            self.assertIsNone(detector.poll())

            with log.open("ab") as stream:
                stream.write(b"inal\n")
            self.assertEqual(detector.poll(), "provider-bugcheck")
            self.assertIsNone(detector.poll())

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

    def test_no_boot_milestone_run_gate_is_terminal(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "serial.log"
            log.write_bytes(b"[quiesce] no boot milestone for ~180s wall-clock -> run gate\n")
            self.assertEqual(terminal_detector(log).poll(), "quiesce")

    def test_double_prefixed_durability_refusal_is_terminal(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "serial.log"
            log.write_bytes(
                b"[cm-flush] quiesce boot hive checkpoint failed status=0x0x80000011\n"
                b"[cm-flush] shutdown hive durability refused status=0x0x80000011\n"
            )
            self.assertEqual(terminal_detector(log).poll(), "durability-refused")

    def test_winlogon_gina_initialization_failure_is_terminal(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "serial.log"
            log.write_bytes(
                b"[dbg] err:(base\\system\\winlogon\\winlogon.c:538) "
                b"WL: Failed to initialize Gina\n"
            )
            self.assertEqual(terminal_detector(log).poll(), "gina-load-failed")

    def test_partial_or_quoted_quiesce_is_not_terminal(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "serial.log"
            log.write_bytes(
                b"trace: [quiesce] every live process parked/waiting (no signaler left) -> run gate\n"
                b"[quiesce] every live process parked/waiting (no signaler left) -> run gate?\n"
                b"[cm-flush] shutdown hive durability refused status=unknown\n"
            )
            self.assertIsNone(terminal_detector(log).poll())


class BootProgressWatchdogTests(unittest.TestCase):
    """Only finite boot milestones and bounded completed disk I/O buy more time."""

    @staticmethod
    def watchdog():
        watchdog = smoke.BootProgressWatchdog(
            started=0, idle_seconds=180, max_disk_extensions=2
        )
        watchdog.observe_serial(b"boot: reading Simpleboot memory map\n", 0)
        return watchdog

    @staticmethod
    def blockstats(read_bytes, written_bytes, *, device="bootdisk"):
        return {"return": [{
            "device": device,
            "stats": {"rd_bytes": read_bytes, "wr_bytes": written_bytes},
        }]}

    def test_duplicate_milestone_and_serial_chatter_do_not_reset_idle_clock(self):
        watchdog = self.watchdog()
        self.assertEqual(
            watchdog.observe_serial(b"[setup-provision] phase=network-end detail=0\n", 10),
            ["setup-provision:network-end"],
        )
        for at in (40, 100, 179, 189):
            self.assertEqual(
                watchdog.observe_serial(
                    b"[setup-provision] phase=network-end detail=0\n"
                    b"[hosted-irq] serviced event=3 claimed=1\n"
                    b"[registry-interface-retry] id=28 count=4 phase=durable\n",
                    at,
                ),
                [],
            )
        self.assertIsNone(watchdog.idle_reason(189))
        self.assertIsNotNone(watchdog.idle_reason(190))

    def test_distinct_completed_milestone_resets_180_second_window(self):
        watchdog = self.watchdog()
        self.assertEqual(
            watchdog.observe_serial(b"[setup-provision] phase=network-end detail=0\n", 20),
            ["setup-provision:network-end"],
        )
        self.assertEqual(
            watchdog.observe_serial(b"[setup-provision] phase=print-end detail=0\n", 170),
            ["setup-provision:print-end"],
        )
        self.assertIsNone(watchdog.idle_reason(349))
        self.assertIsNotNone(watchdog.idle_reason(350))

    def test_completed_bootdisk_bytes_allow_only_two_bounded_extensions(self):
        watchdog = self.watchdog()
        self.assertFalse(watchdog.observe_blockstats(self.blockstats(0, 0), 0))
        self.assertFalse(watchdog.observe_blockstats(self.blockstats(0, 0), 170))
        self.assertTrue(watchdog.observe_blockstats(self.blockstats(4096, 0), 180))
        self.assertIsNone(watchdog.idle_reason(359))
        self.assertFalse(watchdog.observe_blockstats(self.blockstats(4096, 0), 350))
        self.assertTrue(watchdog.observe_blockstats(self.blockstats(8192, 0), 360))
        self.assertIsNone(watchdog.idle_reason(539))
        self.assertFalse(watchdog.observe_blockstats(self.blockstats(8192, 0), 530))
        self.assertFalse(watchdog.observe_blockstats(self.blockstats(12288, 0), 540))
        self.assertIsNotNone(watchdog.idle_reason(540))

    def test_old_disk_bytes_cannot_extend_a_stationary_boot(self):
        # KVM 41608161520: a 36 s driver milestone was followed by a final write
        # near 40 s. The 210 s sample was flat, yet the old watchdog credited
        # those stale bytes at the 216 s idle boundary.
        watchdog = self.watchdog()
        watchdog.observe_blockstats(self.blockstats(0, 0), 30)
        watchdog.observe_serial(b"[setup-provision] phase=network-end detail=0\n", 36)
        watchdog.observe_blockstats(self.blockstats(4096, 0), 40)
        watchdog.observe_blockstats(self.blockstats(4096, 0), 210)
        reason = smoke.refresh_idle_progress(
            watchdog, 216, lambda: self.blockstats(4096, 0),
        )
        self.assertIsNotNone(reason, "completed bytes from 176 seconds ago are not live progress")
        self.assertEqual(watchdog.last_progress, 36)
        self.assertEqual(watchdog.disk_extensions, 0)

    def test_long_qmp_gap_cannot_date_accumulated_disk_bytes(self):
        watchdog = self.watchdog()
        watchdog.observe_blockstats(self.blockstats(0, 0), 0)
        reason = smoke.refresh_idle_progress(
            watchdog, 180, lambda: self.blockstats(4096, 0),
        )
        self.assertIsNotNone(reason, "an unsampled 180-second interval is not fresh disk proof")
        self.assertEqual(watchdog.disk_extensions, 0)

    def test_recent_disk_change_survives_one_flat_threshold_sample(self):
        watchdog = self.watchdog()
        watchdog.observe_blockstats(self.blockstats(0, 0), 0)
        watchdog.observe_blockstats(self.blockstats(0, 0), 170)
        watchdog.observe_blockstats(self.blockstats(4096, 0), 175)
        reason = smoke.refresh_idle_progress(
            watchdog, 180, lambda: self.blockstats(4096, 0),
        )
        self.assertIsNone(reason)
        self.assertEqual(watchdog.disk_extensions, 1)

    def test_frequent_early_disk_polls_do_not_spend_grace_before_idle_window(self):
        watchdog = self.watchdog()
        self.assertFalse(watchdog.observe_blockstats(self.blockstats(0, 0), 0))
        for at in range(10, 180, 10):
            self.assertFalse(
                watchdog.observe_blockstats(self.blockstats(at * 4096, 0), at),
                f"bootdisk bytes at {at}s are real but the milestone is not yet idle",
            )
        self.assertIsNone(watchdog.idle_reason(179))
        self.assertTrue(watchdog.observe_blockstats(self.blockstats(180 * 4096, 0), 180))
        for at in range(190, 360, 10):
            self.assertFalse(watchdog.observe_blockstats(self.blockstats(at * 4096, 0), at))
        self.assertTrue(watchdog.observe_blockstats(self.blockstats(360 * 4096, 0), 360))
        for at in range(370, 540, 10):
            self.assertFalse(watchdog.observe_blockstats(self.blockstats(at * 4096, 0), at))
        self.assertFalse(watchdog.observe_blockstats(self.blockstats(540 * 4096, 0), 540))
        self.assertIsNotNone(watchdog.idle_reason(540))

    def test_missing_or_ambiguous_bootdisk_statistics_are_not_progress(self):
        watchdog = self.watchdog()
        self.assertFalse(watchdog.observe_blockstats(self.blockstats(4096, 0, device="pflash0"), 90))
        self.assertFalse(watchdog.observe_blockstats({"return": []}, 100))
        self.assertFalse(watchdog.observe_blockstats({"error": "QMP disconnected"}, 110))
        ambiguous = {"return": [
            self.blockstats(4096, 0)["return"][0],
            self.blockstats(8192, 0)["return"][0],
        ]}
        self.assertFalse(watchdog.observe_blockstats(ambiguous, 120))
        self.assertIsNotNone(watchdog.idle_reason(180))

    def test_split_serial_milestone_is_counted_once_when_line_completes(self):
        watchdog = self.watchdog()
        self.assertEqual(watchdog.observe_serial(b"[setup-provision] phase=profile-shell-", 100), [])
        self.assertEqual(watchdog.observe_serial(b"end detail=0\r", 110), [])
        self.assertEqual(
            watchdog.observe_serial(b"\n", 120),
            ["setup-provision:profile-shell-end"],
        )
        self.assertEqual(
            watchdog.observe_serial(b"[setup-provision] phase=profile-shell-end detail=0\n", 130),
            [],
        )
        self.assertIsNone(watchdog.idle_reason(299))
        self.assertIsNotNone(watchdog.idle_reason(300))

    def test_no_progress_for_180_seconds_is_a_stop_even_with_serial_output(self):
        watchdog = self.watchdog()
        for at in (30, 60, 90, 120, 150):
            watchdog.observe_serial(b"[hosted-irq] serviced event=3 claimed=1\n", at)
        self.assertIsNone(watchdog.idle_reason(179))
        self.assertIsNotNone(watchdog.idle_reason(180))

    def test_real_indented_pass_records_are_unique_milestones(self):
        watchdog = self.watchdog()
        self.assertEqual(watchdog.observe_serial(b"  PASS exec_ob_ping\n", 30), ["PASS exec_ob_ping"])
        self.assertEqual(watchdog.observe_serial(b"  PASS exec_ob_ping\n", 60), [])
        self.assertEqual(
            watchdog.observe_serial(b"  PASS exec_ob_create_directory\n", 170),
            ["PASS exec_ob_create_directory"],
        )
        self.assertIsNone(watchdog.idle_reason(349))
        self.assertIsNotNone(watchdog.idle_reason(350))

    def test_directory_publication_counts_only_successful_reply_for_new_token(self):
        watchdog = self.watchdog()
        self.assertEqual(
            watchdog.observe_serial(b"[directory-publish] token=1 stage=poll status=0x0000000000000000\n", 10),
            [],
        )
        self.assertEqual(
            watchdog.observe_serial(b"[directory-publish] token=1 stage=reply status=0x0000000000000000\n", 20),
            ["directory-publish:1"],
        )
        self.assertEqual(
            watchdog.observe_serial(b"[directory-publish] token=1 stage=reply status=0x0000000000000000\n", 60),
            [],
        )
        self.assertEqual(
            watchdog.observe_serial(b"[directory-publish] token=2 stage=reply status=0xc000000d\n", 90),
            [],
        )
        self.assertEqual(
            watchdog.observe_serial(b"[directory-publish] token=2 stage=reply status=0x0000000000000000\n", 170),
            ["directory-publish:2"],
        )

    def test_new_hosted_process_is_progress_but_repeated_census_is_not(self):
        watchdog = self.watchdog()
        allocation = (
            b"[pm-dynamic] allocated hosted process pi=18 pid=388 parent=100 "
            b"image=diagdata.exe token=22 inherited\n"
        )
        self.assertEqual(watchdog.observe_serial(allocation, 170), ["process:388:diagdata.exe"])
        self.assertEqual(watchdog.observe_serial(allocation, 200), [])
        self.assertIsNone(watchdog.idle_reason(349))
        self.assertIsNotNone(watchdog.idle_reason(350))

    def test_successful_win32k_desktop_switch_is_one_shot_milestone(self):
        watchdog = self.watchdog()
        switch = (
            b"[win32k-desktop-switch] pi/ret/target/active/info/wnd/hwnd/style/resolved="
            b"/0x000000000x00000008/0x000000000x00000001/0x000001000x0a09b370"
            b"/0x000001000x0a09b370/0x000001000x07802730/0x000001000x078028b0"
            b"/0x000000000x00020026/0x000000000x96000000/0x000001000x078028b0\n"
        )
        self.assertEqual(
            watchdog.observe_serial(switch, 90), ["win32k-desktop-switch"]
        )
        self.assertEqual(watchdog.observe_serial(switch, 170), [])
        self.assertIsNone(watchdog.idle_reason(269))
        self.assertIsNotNone(watchdog.idle_reason(270))


if __name__ == "__main__":
    unittest.main()
