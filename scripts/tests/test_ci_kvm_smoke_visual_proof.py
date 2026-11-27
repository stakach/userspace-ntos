"""A successful QMP send is not evidence that its intended guest window received input."""

from pathlib import Path
import gzip
import hashlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts import ci_kvm_visual_proof
from scripts.ci_kvm_ppm import crop_ppm
from scripts.ci_kvm_visual_proof import (contains_command_prompt_search_result,
                                         contains_basicproof_directory,
                                         contains_ready_prompt, contains_start_menu_search_box,
                                         contains_ver_result, prove_basicproof_directory,
                                         prove_child_stdout_completion,
                                         prove_command_prompt_search_result,
                                         prove_readonly_attribute, prove_ready_prompt,
                                         prove_start_menu_search_box,
                                         prove_ver_result)


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
RECORDED_BOOT2_VER_OCR = (Path(__file__).with_name("fixtures") /
                          "ver_boot2_45256201173.txt").read_text()


class VisualProofTests(unittest.TestCase):
    def test_saved_child_stdout_crop_follows_console_position(self):
        # KVM 46059546967 probe 5 visibly shows child output and a returned
        # prompt at y=484. The old prompt crop at y=558 missed the console.
        fixture = Path(__file__).parent / "fixtures"
        complete = gzip.decompress((fixture / "child_stdout_complete_46059546967.ppm.gz").read_bytes())
        pending = gzip.decompress((fixture / "child_stdout_pending_46059546967.ppm.gz").read_bytes())
        image = Path("native-kvm-interact-12-basicproof-child-stdout-probe-05.ppm")
        sparse = ("C:\\Users\\User>cmd /c echo CHILD_STDOUT_OK\n"
                  "CHILD_STDOUT_OK\nCommand,\n___ C:\\Users\\User>\n")
        original_sha = "77db5143a7a122e90a5eae4660b87a2af1a2fbcb8a599dcc3934bf8c0fe8d8b1"
        with patch("scripts.ci_kvm_visual_proof._prove_image",
                   return_value=ci_kvm_visual_proof.VisualProof(
                       False, sparse, "child stdout marker and returned prompt not visible",
                       image.name, original_sha)), \
             patch("scripts.ci_kvm_visual_proof.crop_ppm", return_value=complete) as crop:
            proof = prove_child_stdout_completion(image)
        self.assertTrue(proof.passed, proof.error)
        self.assertEqual(proof.image_sha256, original_sha)
        self.assertIn("CHILD_STDOUT_OK\nC:\\Users\\User>", proof.ocr_text)
        crop.assert_called_with(image, 68, 420, 500, 500)
        with patch("scripts.ci_kvm_visual_proof._prove_image",
                   return_value=ci_kvm_visual_proof.VisualProof(
                       False, "C:\\Users\\User>cmd /c echo CHILD_STDOUT_OK\n",
                       "child stdout marker and returned prompt not visible",
                       image.name, "pending-sha")), \
             patch("scripts.ci_kvm_visual_proof.crop_ppm", return_value=pending):
            self.assertFalse(prove_child_stdout_completion(image).passed)

    def test_saved_attrib_readback_uses_exact_console_pixels_and_returned_prompt(self):
        # KVM 46055607414 probe 3: the mounted clear completed and this original
        # frame rendered `A C:\\Users\\User\\basicproof.txt`, but sparse full-frame
        # OCR inserted a space after the dot in the basename.
        sparse = ("C:\\Users\\User>attrib basicproof.txt\n"
                  "A\nC:\\Users\\User\\basicproof. txt\n"
                  "C:\\Users\\User>\n")
        self.assertFalse(ci_kvm_visual_proof.contains_readonly_attribute(
            sparse, "basicproof.txt", readonly=False))
        fixture = Path(__file__).parent / "fixtures"
        complete = gzip.decompress((fixture / "attrib_readback_46055607414.ppm.gz").read_bytes())
        pending = gzip.decompress((fixture / "attrib_pending_46055607414.ppm.gz").read_bytes())
        image = Path("native-kvm-interact-15-basicproof-baseline-readback-probe-03.ppm")
        original_sha = "8c1646207e3958d0ba7bf5dafb5599cc304d12cffcb3a18fc888a0e948f6b558"
        with patch("scripts.ci_kvm_visual_proof._prove_image",
                   return_value=ci_kvm_visual_proof.VisualProof(
                       False, sparse, "exact readback not visible", image.name, original_sha)), \
             patch("scripts.ci_kvm_visual_proof.crop_ppm", return_value=complete) as crop:
            proof = prove_readonly_attribute(image, "basicproof.txt", readonly=False)
            self.assertFalse(prove_readonly_attribute(image, "basicproof.txt", readonly=True).passed)
        self.assertTrue(proof.passed, proof.error)
        self.assertEqual(proof.image_sha256, original_sha)
        self.assertIn("A C:\\Users\\User\\basicproof.txt", proof.ocr_text)
        crop.assert_called_with(image, 68, 426, 520, 510, scale=2)
        with patch("scripts.ci_kvm_visual_proof._prove_image",
                   return_value=ci_kvm_visual_proof.VisualProof(
                       False, sparse, "exact readback not visible", image.name, "pending-sha")), \
             patch("scripts.ci_kvm_visual_proof.crop_ppm", return_value=pending):
            self.assertFalse(prove_readonly_attribute(image, "basicproof.txt", readonly=False).passed)

    def test_saved_create_input_is_verified_before_return_from_its_own_frame(self):
        # Run 46025217921 step 7: the exact command is visible with a block
        # cursor; the subsequent Return never reached the guest.
        original = ("‘Command Prompt\nC:\\Users\\User>ver\n"
                    "Microsoft Windows [Version 10.0.26100.1]\n"
                    "C:\\Users\\User>md basicproof,,\n")
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "native-kvm-interact-07-basicproof-create-input.ppm"
            image.write_bytes(b"P6\n1 1\n255\n\0\0\0")
            sha = hashlib.sha256(image.read_bytes()).hexdigest()
            with patch("scripts.ci_kvm_visual_proof.crop_ppm", return_value=b"P6\n1 1\n255\n\0\0\0") as crop, \
                    patch("scripts.ci_kvm_visual_proof.subprocess.run") as ocr:
                ocr.side_effect = [subprocess.CompletedProcess([], 0, original, ""),
                                   subprocess.CompletedProcess([], 0,
                                       b"C:\\Users\\User>md basicproof,\n", b"")]
                proof = ci_kvm_visual_proof.prove_basicproof_create_input(image)
                self.assertTrue(proof.passed)
                self.assertEqual(proof.image_sha256, sha)
                self.assertIn("create input crop: C:\\Users\\User>md basicproof,",
                              proof.ocr_text)
                crop.assert_called_once()
                self.assertEqual(ocr.call_args.kwargs["input"], b"P6\n1 1\n255\n\0\0\0")
                ocr.side_effect = [subprocess.CompletedProcess([], 0, original, ""),
                                   subprocess.CompletedProcess([], 0,
                                       b"C:\\Users\\User>md basicproo,\n", b"")]
                self.assertFalse(ci_kvm_visual_proof.prove_basicproof_create_input(image).passed)
                ocr.side_effect = [subprocess.CompletedProcess([], 0,
                                       original.replace("‘Command Prompt\n", ""), "")]
                self.assertFalse(ci_kvm_visual_proof.prove_basicproof_create_input(image).passed)
                ocr.side_effect = [subprocess.CompletedProcess([], 0,
                                       original.replace("basicproof,,", "basicproof")
                                       + "C:\\Users\\User>\n", "")]
                self.assertFalse(ci_kvm_visual_proof.prove_basicproof_create_input(image).passed)

    def test_saved_missing_return_cannot_prove_create_completion(self):
        prompt = "C:\\Users\\User>"
        complete = prompt + "md basicproof\n_ | " + prompt + "\n"
        pending = prompt + "md basicproof,,\n"
        combined = prompt + "md basicproofdir basicproof\n" + prompt + "\n"
        contains = ci_kvm_visual_proof.contains_basicproof_create_completion
        self.assertTrue(contains(prompt + "md basicproof\n" + prompt))
        self.assertTrue(contains(prompt + "md basicproof,,\n" + prompt))
        self.assertFalse(contains(pending))
        self.assertFalse(contains(combined))
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "native-kvm-interact-08-basicproof-create.ppm"
            image.write_bytes(b"P6\n1 1\n255\n\0\0\0")
            sha = hashlib.sha256(image.read_bytes()).hexdigest()
            with patch("scripts.ci_kvm_visual_proof.crop_ppm", return_value=b"P6\n1 1\n255\n\0\0\0") as crop, \
                    patch("scripts.ci_kvm_visual_proof.subprocess.run") as ocr:
                ocr.side_effect = [subprocess.CompletedProcess([], 0, complete, ""),
                                   subprocess.CompletedProcess([], 0, (prompt + "\n").encode(), b"")]
                proof = ci_kvm_visual_proof.prove_basicproof_create_completion(image)
                self.assertTrue(proof.passed)
                self.assertEqual(proof.image_sha256, sha)
                self.assertIn("create prompt crop: " + prompt, proof.ocr_text)
                crop.assert_called_once()
                ocr.side_effect = [subprocess.CompletedProcess([], 0, pending, ""),
                                   subprocess.CompletedProcess([], 0,
                                       (prompt + "md basicproof,,\n").encode(), b"")]
                self.assertFalse(ci_kvm_visual_proof.prove_basicproof_create_completion(image).passed)
                ocr.side_effect = [subprocess.CompletedProcess([], 0, combined, "")]
                self.assertFalse(ci_kvm_visual_proof.prove_basicproof_create_completion(image).passed)
                ocr.side_effect = [subprocess.CompletedProcess([], 0,
                                       prompt + "md basicproof\n" + prompt + "\n", ""),
                                   subprocess.CompletedProcess([], 0,
                                       (prompt + "dir basicproof\n").encode(), b"")]
                stale = ci_kvm_visual_proof.prove_basicproof_create_completion(image)
                self.assertFalse(stale.passed)
                self.assertEqual(stale.image_sha256, sha)
                self.assertIn("create prompt crop: " + prompt + "dir basicproof",
                              stale.ocr_text)
                ocr.side_effect = [subprocess.CompletedProcess([], 0,
                                       prompt + "md basicproof\n" + prompt +
                                       "\nA subdirectory or file basicproof already exists.\n", "")]
                self.assertFalse(ci_kvm_visual_proof.prove_basicproof_create_completion(image).passed)

    def test_recorded_child_stdout_requires_marker_and_cropped_empty_prompt(self):
        # Run 46018329889 probe 05: the original frame visibly has both lines,
        # but sparse full-frame OCR joins desktop glyphs to the prompt.
        recorded = ("C:\\Users\\User>cmd /c echo CHILD_STDOUT_OK\n"
                    "CHILD_STDOUT_OK\n_ | C:\\Users\\User>\n")
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "child.ppm"
            image.write_bytes(b"P6\n1 1\n255\n\0\0\0")
            expected_sha = hashlib.sha256(image.read_bytes()).hexdigest()
            with patch("scripts.ci_kvm_visual_proof.crop_ppm", return_value=b"P6\n1 1\n255\n\0\0\0") as crop, \
                    patch("scripts.ci_kvm_visual_proof.subprocess.run") as ocr:
                ocr.side_effect = [subprocess.CompletedProcess([], 0, recorded, ""),
                                   subprocess.CompletedProcess([], 0,
                                       b"C:\\Users\\User>cmd /c echo CHILD_STDOUT_OK\n"
                                       b"CHILD_STDOUT_OK\nC:\\Users\\User>\n", b"")]
                proof = prove_child_stdout_completion(image)
                self.assertTrue(proof.passed)
                self.assertEqual(proof.image_sha256, expected_sha)
                self.assertIn("child completion crop: C:\\Users\\User>cmd /c echo CHILD_STDOUT_OK",
                              proof.ocr_text)
                crop.assert_called_once()
                self.assertEqual(ocr.call_args.kwargs["input"], b"P6\n1 1\n255\n\0\0\0")
                ocr.side_effect = [subprocess.CompletedProcess([], 0, recorded, ""),
                                   subprocess.CompletedProcess([], 0,
                                       b"C:\\Users\\User>cmd /c echo CHILD_STDOUT_OK\n"
                                       b"CHILD_STDOUT_OK\nC:\\Users\\User>attrib /?\n", b"")]
                self.assertFalse(prove_child_stdout_completion(image).passed)
                ocr.side_effect = [subprocess.CompletedProcess([], 0, recorded.replace(
                    "\nCHILD_STDOUT_OK\n", "\n"), ""),
                                   subprocess.CompletedProcess([], 0,
                                       b"C:\\Users\\User>cmd /c echo CHILD_STDOUT_OK\n"
                                       b"C:\\Users\\User>\n", b"")]
                self.assertFalse(prove_child_stdout_completion(image).passed)

    def test_directory_gate_rejects_recorded_dropped_input_and_missing_directory(self):
        prompt = "C:\\Users\\User>"
        good = (prompt + "dir basicproof\n"
                "Directory of C:\\Users\\User\\basicproof\n"
                "0 File(s) 0 bytes\n" + prompt)
        self.assertTrue(contains_basicproof_directory(good))
        self.assertFalse(contains_basicproof_directory(
            prompt + "if not existproof md basicproof\nSyntax error - md\n"
            + prompt + "dir basicproof\nDirectory of C:\\Users\\User\nFile not found\n"
            + prompt))
        self.assertFalse(contains_basicproof_directory(good.replace(
            "Directory of C:\\Users\\User\\basicproof",
            "Directory of C:\\Users\\User")))
        self.assertFalse(contains_basicproof_directory(good.replace(
            "0 File(s) 0 bytes", "File not found")))
        self.assertFalse(contains_basicproof_directory(
            prompt + "dir basicproof\n0 File(s) 0 bytes\n"
            "Directory of C:\\Users\\User\\basicproof\n" + prompt))
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "directory.ppm"
            image.write_bytes(b"P6\n1 1\n255\n\0\0\0")
            with patch("scripts.ci_kvm_visual_proof.subprocess.run") as ocr:
                ocr.return_value = subprocess.CompletedProcess([], 0, good, "")
                self.assertTrue(prove_basicproof_directory(image).passed)

    def test_directory_gate_recovers_saved_zero_count_ocr_with_exact_crop(self):
        # KVM 46044370404 visibly returned from an empty listing. Sparse whole-frame
        # OCR read its actual zero as "@ File(s)" and rejected the real directory.
        prompt = "C:\\Users\\User>"
        sparse = (prompt + "dir basicproof\n"
                  "Directory of C:\\Users\\User\\basicproof\n"
                  "@ File(s)\n0 bytes\n2 Dir(s)\n" + prompt)
        self.assertFalse(contains_basicproof_directory(sparse))
        saved = (Path(__file__).parent / "fixtures" /
                 "directory_46044370404.ppm").read_bytes()
        original = Path("native-kvm-interact-09-basicproof-directory-list-probe-03.ppm")
        with patch("scripts.ci_kvm_visual_proof._prove_image",
                   return_value=ci_kvm_visual_proof.VisualProof(
                       False, sparse, "basicproof directory listing not visible",
                       original.name, "a3e4b5022121c89edb8ac836fd1f978ae52c7bff905f795fe5e633c58e9926d6")), \
             patch("scripts.ci_kvm_visual_proof.crop_ppm", return_value=saved):
            proof = prove_basicproof_directory(original)
        self.assertTrue(proof.passed, proof.error)
        self.assertIn("0 File(s)", proof.ocr_text)
        pending = (Path(__file__).parent / "fixtures" /
                   "directory_pending_46044370404.ppm").read_bytes()
        with patch("scripts.ci_kvm_visual_proof._prove_image",
                   return_value=ci_kvm_visual_proof.VisualProof(
                       False, sparse, "basicproof directory listing not visible",
                       original.name, "pending-sha")), \
             patch("scripts.ci_kvm_visual_proof.crop_ppm", return_value=pending):
            self.assertFalse(prove_basicproof_directory(original).passed)

    def test_start_menu_and_search_result_require_visible_shell_evidence(self):
        # Pinned LiberNT startmnu2.cpp filters Start Menu shortcut names. Its
        # shortcuts.inf names the cmd.exe Accessories link "Command Prompt".
        menu = "All Programs\nSearch programs and files\nShut down\n"
        recorded_menu = "\u00bb All Programs\n\u00bb\nSearch programs and files\n\u2018Shut down\n"
        caret_menu = "All Programs\nIsearch programs and files\nShut down\n"
        # LiberNT paints result rows directly, above the edit at the bottom;
        # it does not paint a standalone "Programs" heading in search mode.
        results = "Command Prompt\ncommand\nShut down\n"
        recorded_search = "2) Command Prompt\nUser\n\u00bb\n\u2018command\nShut down\n"
        self.assertTrue(contains_start_menu_search_box(menu))
        # Tesseract on the actual 45425894277 Start screenshot includes
        # Explorer's chevron as a prefix to the All Programs line.
        self.assertTrue(contains_start_menu_search_box(recorded_menu))
        # Actual 45443331583 OCR joined the focused edit's insertion caret
        # to the placeholder even though the full menu was visible.
        self.assertTrue(contains_start_menu_search_box(caret_menu))
        self.assertFalse(contains_start_menu_search_box("Command Prompt\nC:\\Users\\User>\n"))
        self.assertTrue(contains_command_prompt_search_result(results))
        # Actual 45439719217 OCR read the shortcut icon as "2)" and the edit
        # caret as a leading quote, though both are plainly visible.
        self.assertTrue(contains_command_prompt_search_result(recorded_search))
        self.assertFalse(contains_command_prompt_search_result(menu))
        self.assertFalse(contains_command_prompt_search_result(
            "command\nNo items match your search.\n"))
        self.assertTrue(contains_command_prompt_search_result(
            "2) Command Prompt\nUser\nShut down\n"))

    def test_ppm_crop_preserves_exact_original_pixels_at_double_size(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "frame.ppm"
            image.write_bytes(b"P6\n4 2\n255\n" + bytes(range(24)))
            crop = crop_ppm(image, 1, 0, 3, 2, scale=2)
            header = b"P6\n4 4\n255\n"
            self.assertEqual(crop[:len(header)], header)
            self.assertEqual(crop[len(header):],
                             bytes([3, 4, 5] * 2 + [6, 7, 8] * 2) * 2 +
                             bytes([15, 16, 17] * 2 + [18, 19, 20] * 2) * 2)
            with self.assertRaises(ValueError):
                crop_ppm(image, 1, 0, 5, 2, scale=2)

    def test_shell_search_proofs_retain_original_frame_and_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "native-kvm-interact-03-command-prompt-search.ppm"
            image.write_bytes(b"P6\n1 1\n255\n\0\0\0")
            expected_sha = hashlib.sha256(image.read_bytes()).hexdigest()
            with patch("scripts.ci_kvm_visual_proof.crop_ppm", return_value=b"P6\n1 1\n255\n\0\0\0") as crop, \
                    patch("scripts.ci_kvm_visual_proof.subprocess.run") as ocr:
                ocr.return_value = subprocess.CompletedProcess(
                    [], 0, "All Programs\nSearch programs and files\n", "")
                menu = prove_start_menu_search_box(image)
                self.assertTrue(menu.passed)
                self.assertEqual(menu.image_sha256, expected_sha)
                ocr.side_effect = [
                    # Full-frame OCR from run 45446936802 mangled the tiny
                    # edit text, while the same frame's crop reads command.
                    subprocess.CompletedProcess([], 0, "2) Command Prompt\nUser\neanncst|\nShut down\n", ""),
                    subprocess.CompletedProcess([], 0, b"command\n", b""),
                ]
                result = prove_command_prompt_search_result(image)
                self.assertTrue(result.passed)
                self.assertEqual(result.image_sha256, expected_sha)
                self.assertIn("search query crop: command", result.ocr_text)
                crop.assert_called_once_with(image, 17, 683, 210, 702, scale=2)
                self.assertEqual(ocr.call_args.args[:2], (["tesseract", "stdin", "stdout", "-l", "eng", "--psm", "7"],))
                self.assertEqual(ocr.call_args.kwargs["input"], b"P6\n1 1\n255\n\0\0\0")
                ocr.side_effect = [
                    subprocess.CompletedProcess([], 0, "2) Command Prompt\nUser\nShut down\n", ""),
                    subprocess.CompletedProcess([], 0, b"Search programs and files\n", b""),
                ]
                missing = prove_command_prompt_search_result(image)
                self.assertFalse(missing.passed)
                self.assertIn("Search programs and files", missing.ocr_text)
                self.assertEqual(missing.image_sha256, expected_sha)

    def test_recorded_boot2_ver_ignores_separate_punctuation_spillover(self):
        # Original boot-2 step-7 PPM SHA-256 from mainline run 45256201173:
        # 5d81ceacaabece252cef893f1435a9cf28f1a3ecb39a04767caef4611abf29a2.
        # Both the command and version are visible; PSM 11 joined an unrelated glyph.
        self.assertTrue(contains_ver_result(RECORDED_BOOT2_VER_OCR))
        self.assertFalse(contains_ver_result(RECORDED_BOOT2_VER_OCR.replace(
            "C:\\Users\\User>ver", "C:\\Users\\User>dir")))
        self.assertFalse(contains_ver_result(RECORDED_BOOT2_VER_OCR.replace(
            "Microsoft Windows [Version 10.0.26100.1]", "Version unavailable")))
        self.assertFalse(contains_ver_result("Command Prompt\nabc C:\\Users\\User>ver\n"
                                             "Microsoft Windows [Version 10.0.26100.1]\n"))
        self.assertFalse(contains_ver_result("Command Prompt\n!!!! C:\\Users\\User>ver\n"
                                             "Microsoft Windows [Version 10.0.26100.1]\n"))

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
                             ["tesseract", "stdin", "stdout"])
            self.assertEqual(ocr.call_args.kwargs["input"], image.read_bytes())

    def test_missing_result_or_ocr_failure_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "ver.ppm"
            self.assertTrue(prove_ver_result(image).fatal)
            image.write_bytes(b"P6\n1 1\n255\n\0\0\0")
            with patch("scripts.ci_kvm_visual_proof.subprocess.run") as ocr:
                ocr.return_value = subprocess.CompletedProcess([], 0, BOOT2_OCR, "")
                proof = prove_ver_result(image)
                self.assertFalse(proof.passed)
                self.assertFalse(proof.fatal)
                self.assertEqual(proof.error, "typed ver and response not both visible")
                self.assertIn("Applications Manager", proof.ocr_text)
                ocr.side_effect = FileNotFoundError("tesseract")
                unavailable = prove_ver_result(image)
                self.assertIn("OCR unavailable", unavailable.error)
                self.assertTrue(unavailable.fatal)
                ocr.side_effect = subprocess.TimeoutExpired("tesseract", 20)
                timeout = prove_ver_result(image)
                self.assertIn("OCR unavailable", timeout.error)
                self.assertTrue(timeout.fatal)


if __name__ == "__main__":
    unittest.main()
