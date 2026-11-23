"""A KVM boot passes the desktop gate exactly when its desktop, interaction and log are clean."""

import unittest

from scripts.ci_kvm_verdict import InteractionOutcome, boot_verdict

SEALED = (b"[quiesce] Explorer runtime paint milestones complete; "
          b"boot-progress epoch sealed\r\n")
BOOT = b"boot: reading Simpleboot memory map\r\n[pm-dynamic] allocated hosted process\r\n"
COMPLETE = InteractionOutcome(requested=True, armed=True, completed=5, total=5, errors=0)


class DesktopGateTests(unittest.TestCase):
    def test_a_sealed_desktop_with_a_complete_interaction_and_a_clean_log_passes(self):
        verdict = boot_verdict(BOOT + SEALED + b"[user-callback] B completed\r\n", COMPLETE)
        self.assertTrue(verdict.passed, verdict.reasons)
        self.assertTrue(verdict.sealed)
        self.assertEqual(verdict.faults, [])

    def test_a_boot_that_never_seals_fails_even_when_it_ran_its_whole_bound(self):
        verdict = boot_verdict(BOOT, InteractionOutcome(requested=True, total=5))
        self.assertFalse(verdict.passed)
        self.assertIn("Explorer desktop never sealed", verdict.reasons)

    def test_seal_is_retained_when_the_bound_expires_before_idle_arms_interaction(self):
        verdict = boot_verdict(BOOT + SEALED, InteractionOutcome(requested=True, total=5))
        self.assertTrue(verdict.sealed)
        self.assertFalse(verdict.passed)
        self.assertEqual(verdict.reasons, ["scripted interaction never armed"])
        self.assertFalse(verdict.to_json()["interaction"]["armed"])

    def test_the_interaction_must_run_every_step_without_an_input_error(self):
        for outcome in (
            InteractionOutcome(requested=False),
            InteractionOutcome(requested=True, armed=True, completed=4, total=5),
            InteractionOutcome(requested=True, armed=True, completed=5, total=5, errors=1),
            InteractionOutcome(requested=True, armed=True, completed=0, total=0),
        ):
            with self.subTest(outcome=outcome):
                verdict = boot_verdict(BOOT + SEALED, outcome)
                self.assertFalse(verdict.passed)
                self.assertIn(outcome.describe(), verdict.reasons)

    def test_every_guest_fault_fails_a_sealed_desktop(self):
        faults = {
            "executive panic": b"!@src/win32k_subsystem.rs:3938\r\n",
            "provider bugcheck": b"[provider-bugcheck] code=0x0x000000c4 parameter=0x785\r\n",
            "service-loop exit": b"[service-loop-exit] reason=add-device-parent-retained site=483\r\n",
            "kernel panic": b"PANIC: src/arch/x86_64/exceptions.rs:412 boom\r\n",
            # KVM run 44981790454 boot 1: the kernel halted on a user #DE after the seal.
            "kernel halt": (b"EXCEPTION: Divide by zero error\r\nException number: 0x14001E108\r\n"
                            b"System halted due to unrecoverable error\r\n"),
        }
        for kind, record in faults.items():
            with self.subTest(kind=kind):
                verdict = boot_verdict(BOOT + SEALED + record, COMPLETE)
                self.assertFalse(verdict.passed)
                self.assertEqual(len(verdict.faults), 1)
                self.assertTrue(verdict.faults[0].startswith(kind + ": "), verdict.faults)

    def test_a_fault_before_the_seal_is_reported_with_the_missing_desktop(self):
        verdict = boot_verdict(BOOT + b"[provider-bugcheck] terminal\r\n", COMPLETE)
        self.assertFalse(verdict.passed)
        self.assertEqual(verdict.reasons, ["provider bugcheck: [provider-bugcheck] terminal",
                                           "Explorer desktop never sealed"])

    def test_quoted_or_malformed_panic_markers_are_not_faults(self):
        noise = (b"guest mentioned !@src/foo.rs:0\r\n[dbg] service loop exit pending\r\n"
                 b"[provider-bugcheck-diag]\r\n")
        self.assertTrue(boot_verdict(BOOT + SEALED + noise, COMPLETE).passed)

    def test_runner_stops_fail_the_boot(self):
        verdict = boot_verdict(BOOT + SEALED, COMPLETE,
                               ["guest terminal reset (triple fault or reset request)"])
        self.assertFalse(verdict.passed)
        self.assertEqual(verdict.reasons, ["guest terminal reset (triple fault or reset request)"])

    def test_the_verdict_record_names_its_interaction(self):
        document = boot_verdict(BOOT + SEALED, COMPLETE).to_json()
        self.assertEqual(document["interaction"]["summary"],
                         "scripted interaction 5/5 steps, 0 input/capture errors")
        self.assertTrue(document["passed"])


if __name__ == "__main__":
    unittest.main()
