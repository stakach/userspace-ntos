"""A successful QMP send is not evidence that its intended guest window received input."""

from pathlib import Path
import hashlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.ci_kvm_visual_proof import contains_ver_result, prove_ver_result


BOOT1_OCR = ("C:\\Windows\\svstem32\\cmd.exe\n"
             "LiberNT [Version 0.4.17-amd64-dev 26261013-8e478a2]\n"
             "C:\\Users\\User>ver\n"
             "Microsoft Windows [Version 10.0.26100.1]\n"
             "C:\\Users\\User>\n")
BOOT2_OCR = ("C:\\Windows\\svstem32\\cmd.exe\n"
             "ReactOS Applications Manager\n"
             "Name Version Description\n"
             "Welcome to ReactOS Applications Manager!\n")


class VisualProofTests(unittest.TestCase):
    def test_recorded_boot_one_result_is_visible_but_obscured_boot_two_is_not(self):
        self.assertTrue(contains_ver_result(BOOT1_OCR))
        self.assertFalse(contains_ver_result(BOOT2_OCR))
        self.assertFalse(contains_ver_result(
            "Microsoft Windows [Version 10.0.26100.1]\nC:\\Users\\User>ver\n"))
        self.assertFalse(contains_ver_result("C:\\Users\\User>ver\n"))

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
