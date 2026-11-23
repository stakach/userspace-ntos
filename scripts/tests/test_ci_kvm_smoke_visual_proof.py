"""A successful QMP send is not evidence that its intended guest window received input."""

from pathlib import Path
import hashlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.ci_kvm_visual_proof import (contains_ready_prompt, contains_ver_result,
                                         prove_ready_prompt, prove_ver_result)


BOOT1_OCR = ("C:\\Windows\\svstem32\\cmd.exe\n"
             "LiberNT [Version 0.4.17-amd64-dev 26261013-8e478a2]\n"
             "C:\\Users\\User>ver\n"
             "Microsoft Windows [Version 10.0.26100.1]\n"
             "C:\\Users\\User>\n")
BOOT2_OCR = ("C:\\Windows\\svstem32\\cmd.exe\n"
             "ReactOS Applications Manager\n"
             "Name Version Description\n"
             "Welcome to ReactOS Applications Manager!\n")
READY_PROMPT_OCR = ("CAWindows\\svstem32\\emd.exe\n"
                    "‘Command Prompt\n"
                    "LiberNT [Version 0.4.17-amd64-dev 20261013-8e478a2]\n"
                    "C:\\Users\\User>\n"
                    "Command\nPrompt\n")
# Run 45220839653 boot 1, original step-6 PPM SHA
# bd680e8be300fbd1b6c7eebc541b3899676fbdc3bc5bda3f99dda43a48121d21.
RECORDED_READY_COMMA_OCR = ("CAWindows\\svstem32\\emd.exe\n"
                            "‘Command Prompt\n"
                            "LiberNT [Version 0.4.17-amd64-dev 20261013-8e478a2]\n"
                            "(C) Copyright 2026 LiberNT Team.\n"
                            "(C) Copyright 1996-2026 ReactOS Team.\n"
                            "C:\\Users\\User>,\n")
OLD_APPLAUNCH_OCR = ("C:\\Windows\\system32\\cmd.exe\n"
                     "APPLAUNCH_NO_DISK\nAPPLAUNCH_DONE\n"
                     "Command\nPrompt\n")
RECORDED_SPILLOVER_OCR = (Path(__file__).with_name("fixtures") /
                          "ready_prompt_45248027167.txt").read_text()


class VisualProofTests(unittest.TestCase):
    def test_recorded_ready_prompt_ignores_separate_punctuation_spillover(self):
        # Original full step-6 PPM SHA-256 from mainline run 45248027167:
        # 2cb84c651432283ecf1e3e4bcae3209a2326a5ddb285712b6ff8d54df7e835dc.
        # PSM 11 joins an unrelated desktop glyph into the prompt's OCR line.
        self.assertTrue(contains_ready_prompt(RECORDED_SPILLOVER_OCR))
        self.assertFalse(contains_ready_prompt(OLD_APPLAUNCH_OCR))
        self.assertFalse(contains_ready_prompt("Command Prompt\nabc C:\\Users\\User>,\n"))
        self.assertFalse(contains_ready_prompt("Command Prompt\n(;} C:\\Users\\User>,ver\n"))
        self.assertFalse(contains_ready_prompt("Command Prompt\n!!!! C:\\Users\\User>,\n"))

    def test_recorded_ready_prompt_ocr_comma_caret_is_not_a_typed_command(self):
        self.assertTrue(contains_ready_prompt(RECORDED_READY_COMMA_OCR))
        self.assertFalse(contains_ready_prompt("Command Prompt\nC:\\Users\\User>,ver\n"))
        self.assertFalse(contains_ready_prompt(OLD_APPLAUNCH_OCR))

    def test_ready_prompt_distinguishes_recorded_foreground_from_old_window(self):
        self.assertTrue(contains_ready_prompt(READY_PROMPT_OCR))
        self.assertFalse(contains_ready_prompt(OLD_APPLAUNCH_OCR))
        self.assertFalse(contains_ready_prompt("Command Prompt\nC:\\Users\\User>ver\n"))
        self.assertFalse(contains_ready_prompt("C:\\Users\\User>\nCommand Prompt\n"))

    def test_ready_prompt_proof_retains_original_ppm_hash_and_ocr(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "native-kvm-interact-05-command-prompt.ppm"
            image.write_bytes(b"P6\n1 1\n255\n\0\0\0")
            with patch("scripts.ci_kvm_visual_proof.subprocess.run") as ocr:
                ocr.return_value = subprocess.CompletedProcess([], 0, READY_PROMPT_OCR, "")
                proof = prove_ready_prompt(image)
            self.assertTrue(proof.passed)
            self.assertEqual(proof.image_sha256, hashlib.sha256(image.read_bytes()).hexdigest())
            self.assertIn("C:\\Users\\User>", proof.ocr_text)
            with patch("scripts.ci_kvm_visual_proof.subprocess.run") as ocr:
                ocr.return_value = subprocess.CompletedProcess([], 0, OLD_APPLAUNCH_OCR, "")
                rejected = prove_ready_prompt(image)
            self.assertFalse(rejected.passed)
            self.assertEqual(rejected.image_sha256, proof.image_sha256)

    def test_recorded_boot_one_result_is_visible_but_obscured_boot_two_is_not(self):
        self.assertTrue(contains_ver_result(BOOT1_OCR))
        self.assertFalse(contains_ver_result(BOOT2_OCR))
        self.assertFalse(contains_ver_result(
            "Microsoft Windows [Version 10.0.26100.1]\nC:\\Users\\User>ver\n"))
        self.assertFalse(contains_ver_result("C:\\Users\\User>ver\n"))
        self.assertFalse(contains_ver_result(
            "C:\\Users\\User>\nver\nMicrosoft Windows [Version 10.0.26100.1]\n"))

    def test_original_ppm_is_inspected_and_ocr_text_is_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "native-kvm-interact-05-ver.ppm"
            image.write_bytes(b"P6\n1 1\n255\n\0\0\0")
            with patch("scripts.ci_kvm_visual_proof.subprocess.run") as ocr:
                ocr.return_value = subprocess.CompletedProcess([], 0, BOOT1_OCR, "")
                proof = prove_ver_result(image)
            self.assertTrue(proof.passed)
            self.assertIn("Microsoft Windows", proof.ocr_text)
            self.assertEqual(proof.image_name, image.name)
            self.assertEqual(proof.image_sha256, hashlib.sha256(image.read_bytes()).hexdigest())
            self.assertEqual(ocr.call_args.args[0][:3],
                             ["tesseract", str(image), "stdout"])

    def test_missing_result_or_ocr_failure_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "ver.ppm"
            self.assertFalse(prove_ver_result(image).passed)
            image.write_bytes(b"P6\n1 1\n255\n\0\0\0")
            with patch("scripts.ci_kvm_visual_proof.subprocess.run") as ocr:
                ocr.return_value = subprocess.CompletedProcess([], 0, BOOT2_OCR, "")
                proof = prove_ver_result(image)
                self.assertFalse(proof.passed)
                self.assertEqual(proof.error, "typed ver and response not both visible")
                self.assertIn("Applications Manager", proof.ocr_text)
                ocr.side_effect = FileNotFoundError("tesseract")
                self.assertIn("OCR unavailable", prove_ver_result(image).error)
                ocr.side_effect = subprocess.TimeoutExpired("tesseract", 20)
                self.assertIn("OCR unavailable", prove_ver_result(image).error)


if __name__ == "__main__":
    unittest.main()
