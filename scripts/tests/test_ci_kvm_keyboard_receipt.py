"""The input runner waits for guest class ownership, not QMP acceptance."""

from pathlib import Path
import tempfile
import unittest

from scripts.ci_kvm_interaction import action_batches, load_script
from scripts.ci_kvm_keyboard_receipt import KeyboardClassReceipt, SCAN_CODES


class KeyboardClassReceiptTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.serial = Path(self.directory.name) / "serial.log"
        self.serial.write_bytes(b"boot noise\n")
        self.receipt = KeyboardClassReceipt(self.serial)

    def tearDown(self):
        self.directory.cleanup()

    def append(self, sequence, code, flags, *, index=0, batch=1, consumed=1):
        with self.serial.open("ab") as serial:
            serial.write((f"[kbd-class-record] sequence={sequence} code=0x0x{code:08x} "
                          f"flags=0x0x{flags:08x} index={index} batch={batch} "
                          f"consumed={consumed}\n").encode())

    def test_reads_exact_make_and_break_after_starting_offset(self):
        make = {"type": "key", "data": {"down": True,
                "key": {"type": "qcode", "data": "m"}}}
        release = {"type": "key", "data": {"down": False,
                   "key": {"type": "qcode", "data": "m"}}}
        self.append(25, 0x32, 0)
        self.assertEqual(self.receipt.wait_for(make, 0.01), 25)
        self.append(26, 0x32, 1)
        self.assertEqual(self.receipt.wait_for(release, 0.01), 26)

    def test_wrong_scan_code_fails_instead_of_acking_next_key(self):
        event = {"type": "key", "data": {"down": False,
                 "key": {"type": "qcode", "data": "r"}}}
        self.append(43, 0x13, 0, index=15, batch=16, consumed=16)
        with self.assertRaisesRegex(RuntimeError, "r break.*class receipt mismatch"):
            self.receipt.wait_for(event, 0.01)

    def test_unconsumed_class_record_does_not_ack_input(self):
        event = {"type": "key", "data": {"down": True,
                 "key": {"type": "qcode", "data": "m"}}}
        self.append(1, 0x32, 0, index=1, batch=2, consumed=1)
        with self.assertRaisesRegex(RuntimeError, "class receipt invalid"):
            self.receipt.wait_for(event, 0.01)

    def test_both_desktop_scripts_use_mapped_keyboard_qcodes(self):
        for name in ("kvm_interaction_steps.json", "kvm_filebasic_interaction_steps.json"):
            script = load_script(Path(__file__).parents[1] / name)
            qcodes = [event["data"]["key"]["data"]
                      for step in script.steps for action in step.actions
                      if action[0] != "verified_click"
                      for events, _pause in action_batches(action, script.screen)
                      for event in events if event["type"] == "key"]
            self.assertTrue(set(qcodes) <= SCAN_CODES.keys())
            if name == "kvm_filebasic_interaction_steps.json":
                self.assertEqual(len(qcodes), 540)


if __name__ == "__main__":
    unittest.main()
