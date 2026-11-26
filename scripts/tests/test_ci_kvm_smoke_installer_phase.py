"""Installer phase receipts must never infer ownership from serial adjacency."""

import unittest

from scripts.ci_kvm_installer_phase import parse_installer_phases


def birth(pid, generation, tick):
    return (f"[pm-dynamic] allocated hosted process pi=17 pid={pid} parent=248 "
            f"image=rundll32.exe token=1 inherited pgen={generation} at_100ns={tick}")


def loader_pair(pid, start, end):
    return (f"[dbg] nt-ntdll: snap resolved=400 missing=0 spot=0x1 pid=0x{pid:x} "
            f"tsc=0x1 qpc-start=0x{start:x} qpc-end=0x{end:x}")


def assignment(pid, generation, tick):
    return (f"[pnp-install-batch] child-pid/gen/file/ordinal/total={pid}/{generation}/0x1/1/1 "
            f"server-file=0x2 device=\"ACPI\\PNP0C0F\\1\" owner-pid/gen=248/9 "
            f"at_100ns={tick}")


def attach(pid, generation, tick):
    return ("[pnp-install-child] child-pid/gen/owner-pid/gen/client-file/server-file="
            f"{pid}/{generation}/248/9/1/2 at_100ns={tick}")


def enum_open(pid, generation, tick):
    return (f"[pnp-install-enum-open] child-pid/gen/server-file/ordinal/status="
            f"{pid}/{generation}/0x2/1/0x0x00000000 at_100ns={tick}")


def terminal(pid, generation, tick):
    return (f"[pnp-install-batch] child-terminal pid/gen/server-file/client-file/status="
            f"{pid}/{generation}/0x2/0x1/0x0x00000000 at_100ns={tick}")


class InstallerPhaseTests(unittest.TestCase):
    def test_pid_reuse_keeps_loader_receipts_with_the_exact_generation(self):
        lines = [
            birth(356, 12, 100_000), attach(356, 12, 115_000),
            assignment(356, 12, 120_000),
            loader_pair(356, 110_000, 130_000),
            enum_open(356, 12, 140_000), terminal(356, 12, 200_000),
            birth(356, 13, 300_000), assignment(356, 13, 320_000),
            loader_pair(356, 310_000, 350_000),
            enum_open(356, 13, 360_000), terminal(356, 13, 400_000),
        ]
        rows = parse_installer_phases(lines)["rows"]
        self.assertEqual([(row["pid"], row["generation"]) for row in rows],
                         [(356, 12), (356, 13)])
        self.assertEqual([row["loader_start_100ns"] for row in rows], [110_000, 310_000])
        self.assertEqual([row["loader_end_100ns"] for row in rows], [130_000, 350_000])
        self.assertEqual([row["enum_open_100ns"] for row in rows], [140_000, 360_000])
        self.assertEqual([row["attach_100ns"] for row in rows], [115_000, None])
        self.assertEqual([row["terminal_100ns"] for row in rows], [200_000, 400_000])
        self.assertEqual([(row["owner_pid"], row["owner_generation"]) for row in rows],
                         [(248, 9), (248, 9)])

    def test_nonmonotonic_phase_is_unknown_instead_of_negative_duration(self):
        lines = [birth(356, 12, 100_000), loader_pair(356, 140_000, 130_000),
                 enum_open(356, 12, 150_000),
                 terminal(356, 12, 200_000)]
        row = parse_installer_phases(lines)["rows"][0]
        self.assertIsNone(row["loader_end_100ns"])
        self.assertIn("nonmonotonic-loader", row["invalid"])
        self.assertIsNone(row["loader_ms"])

    def test_overlapping_pid_lifetimes_do_not_claim_a_loader_marker(self):
        lines = [birth(356, 12, 100_000), birth(356, 13, 110_000),
                 loader_pair(356, 120_000, 130_000), terminal(356, 12, 200_000),
                 terminal(356, 13, 210_000)]
        rows = parse_installer_phases(lines)["rows"]
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row["loader_start_100ns"] is None for row in rows))

    def test_loader_pair_must_be_wholly_inside_one_lifetime(self):
        row = parse_installer_phases([
            birth(356, 12, 100_000), loader_pair(356, 210_000, 190_000),
            terminal(356, 12, 200_000),
        ])["rows"][0]
        self.assertIsNone(row["loader_start_100ns"])
        self.assertIsNone(row["loader_end_100ns"])

    def test_third_loader_pair_cannot_clear_duplicate_ambiguity(self):
        row = parse_installer_phases([
            birth(356, 12, 100_000), loader_pair(356, 110_000, 120_000),
            loader_pair(356, 130_000, 140_000), loader_pair(356, 150_000, 160_000),
            terminal(356, 12, 200_000),
        ])["rows"][0]
        self.assertIsNone(row["loader_start_100ns"])
        self.assertIn("duplicate-loader", row["invalid"])

    def test_root_phase_timestamps_outside_lifetime_are_unknown(self):
        row = parse_installer_phases([
            birth(356, 12, 100_000), attach(356, 12, 90_000),
            assignment(356, 12, 210_000), terminal(356, 12, 200_000),
        ])["rows"][0]
        self.assertIsNone(row["attach_100ns"])
        self.assertIsNone(row["assignment_100ns"])

    def test_receipt_is_bounded(self):
        result = parse_installer_phases([birth(356, 12, 1), birth(480, 17, 2)], max_rows=1)
        self.assertEqual(len(result["rows"]), 1)
        self.assertEqual(result["overflow"], 1)

    def test_overflow_cannot_leave_a_false_exact_loader_duration(self):
        row = parse_installer_phases([
            birth(356, 12, 100_000), loader_pair(356, 110_000, 120_000),
            birth(356, 13, 105_000),
        ], max_rows=1)["rows"][0]
        self.assertIsNone(row["loader_start_100ns"])
        self.assertIsNone(row["loader_ms"])
        self.assertIn("truncated", row["invalid"])

    def test_conflicting_exact_parent_identity_is_not_accepted(self):
        other_owner = assignment(356, 12, 130_000).replace(
            "owner-pid/gen=248/9", "owner-pid/gen=249/10")
        row = parse_installer_phases([
            birth(356, 12, 100_000), attach(356, 12, 110_000),
            other_owner, terminal(356, 12, 200_000),
        ])["rows"][0]
        self.assertIsNone(row["owner_pid"])
        self.assertIn("owner-conflict", row["invalid"])

    def test_invalid_installer_event_still_marks_the_child_as_observed(self):
        row = parse_installer_phases([
            birth(356, 12, 100_000), attach(356, 12, 90_000),
            terminal(356, 12, 200_000),
        ])["rows"][0]
        self.assertTrue(row["installer_observed"])
        self.assertIsNone(row["attach_100ns"])

    def test_uncertain_lifetime_never_claims_pid_only_loader_time(self):
        cases = (
            [birth(356, 12, 100_000), loader_pair(356, 110_000, 120_000)],
            [birth(356, 12, 100_000), birth(356, 12, 100_000),
             loader_pair(356, 110_000, 120_000), terminal(356, 12, 200_000)],
            [birth(356, 12, 100_000), loader_pair(356, 110_000, 120_000),
             terminal(356, 12, 90_000)],
            [birth(356, 12, 100_000), loader_pair(356, 110_000, 120_000),
             terminal(356, 12, 200_000), terminal(356, 12, 210_000)],
        )
        for lines in cases:
            with self.subTest(lines=lines):
                row = parse_installer_phases(lines)["rows"][0]
                self.assertIsNone(row["loader_start_100ns"])
                self.assertIsNone(row["loader_end_100ns"])
                self.assertIsNone(row["loader_ms"])


if __name__ == "__main__":
    unittest.main()
