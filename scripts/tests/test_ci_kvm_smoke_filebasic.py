"""A guest FileBasic probe must prove a real before/after attribute change."""

import json
from pathlib import Path
import unittest

from scripts.ci_kvm_interaction import DEFAULT_SCRIPT, load_script, parse_script
from scripts import ci_kvm_visual_proof
from scripts.ci_kvm_verdict import InteractionOutcome, boot_verdict
from scripts.ci_kvm_visual_proof import VisualProof


FILEBASIC_SCRIPT = Path(__file__).resolve().parents[1] / "kvm_filebasic_interaction_steps.json"
SEALED = b"[quiesce] Explorer runtime paint milestones complete; boot-progress epoch sealed\n"


def native_set(irp, attrs, handle):
    return b"".join(
        (f"[file-set-owner] stage={stage} table=2 slot=3 generation={irp} "
         f"irp={irp} pi=4 tid=5 status=0 file={handle}"
         + (f" stable=100 attrs={attrs}" if stage == "basic-terminal" else "")
         + "\n").encode()
        for stage in ("basic-terminal", "reply", "file-released", "retired")
    )


class FileBasicInteractionTests(unittest.TestCase):
    def test_profile_keeps_desktop_proof_then_clears_and_sets_one_scratch_directory(self):
        desktop = load_script(DEFAULT_SCRIPT)
        profile = parse_script(json.loads(FILEBASIC_SCRIPT.read_text()))

        self.assertEqual((profile.screen, profile.arm, profile.settle_seconds),
                         (desktop.screen, desktop.arm, desktop.settle_seconds))
        self.assertEqual(profile.steps[:len(desktop.steps)], desktop.steps)
        self.assertEqual([step.name for step in profile.steps[len(desktop.steps):]],
                         ["basicproof-create", "basicproof-clear-readonly",
                          "basicproof-baseline-readback", "basicproof-set-readonly",
                          "basicproof-readback"])
        self.assertEqual([step.actions for step in profile.steps[len(desktop.steps):]], [
            (("type", "if not exist basicproof md basicproof\n"),),
            (("type", "attrib -R basicproof\n"),),
            (("type", "attrib basicproof\n"),),
            (("type", "attrib +R basicproof\n"),),
            (("type", "attrib basicproof\n"),),
        ])
        self.assertTrue(all(0 < step.wait_seconds <= 120
                            for step in profile.steps[len(desktop.steps):]))

    def test_readback_requires_exact_current_directory_path_and_attribute_state(self):
        command = "D:\\Scratch\\Work>attrib basicproof\n"
        result = "     R     D:\\Scratch\\Work\\basicproof\n"
        clear = "           D:\\Scratch\\Work\\basicproof\n"
        contains = ci_kvm_visual_proof.contains_readonly_attribute

        self.assertTrue(contains(command + result, "basicproof", readonly=True))
        self.assertTrue(contains(command + clear, "basicproof", readonly=False))
        self.assertTrue(contains(command + clear + command + result,
                                 "basicproof", readonly=True))
        self.assertFalse(contains(command + clear + command + result,
                                  "basicproof", readonly=False))
        self.assertTrue(contains(command + "A    R     D:\\Scratch\\Work\\BASICPROOF\n",
                                 "basicproof", readonly=True))
        for transcript in (
            "D:\\Scratch\\Work>attrib +R basicproof\n",  # setter is not a readback
            command,  # no result
            command + clear,  # R absent
            command + "     R     D:\\Scratch\\Work\\other\n",  # another File
            command + "     R     D:\\Other\\basicproof\n",  # another directory
            command + "     R     D:\\Scratch\\Work\\basicproof2\n",  # basename prefix
            result + command,  # stale output before the readback command
        ):
            with self.subTest(transcript=transcript):
                self.assertFalse(contains(transcript, "basicproof", readonly=True))
        self.assertFalse(contains(command + result, "basicproof", readonly=False))
        self.assertFalse(contains(command + "     R     D:\\Scratch\\Work\\other\n",
                                  "basicproof", readonly=False))

    def test_verdict_requires_both_visual_readbacks_for_filebasic_profile(self):
        required = ("basicproof-baseline-readback", "basicproof-readback")
        outcome = dict(requested=True, armed=True, completed=11, total=11,
                       visual_proof=VisualProof(True), required_checkpoints=required)
        self.assertFalse(boot_verdict(SEALED,
                                      InteractionOutcome(**outcome)).passed)
        outcome["checkpoints"] = {required[0]: VisualProof(True),
                                  required[1]: VisualProof(False, error="R absent")}
        self.assertFalse(boot_verdict(SEALED,
                                      InteractionOutcome(**outcome)).passed)
        outcome["checkpoints"][required[1]] = VisualProof(True)
        self.assertFalse(boot_verdict(SEALED,
                                      InteractionOutcome(**outcome)).passed)
        serial = SEALED + native_set(101, 16, 81) + native_set(102, 17, 82)
        verdict = boot_verdict(serial, InteractionOutcome(**outcome))
        self.assertTrue(verdict.passed, verdict.reasons)
        self.assertTrue(verdict.to_json()["filebasic_receipts"]["passed"])


if __name__ == "__main__":
    unittest.main()
