import unittest

from verify_log import REQUIRED, REPEATED, verify


def record(case, field, actual, expected=None):
    if expected is None:
        expected = actual
    return f"[file-acceptance] case={case} field={field} actual=0x{actual:016x} expected=0x{expected:016x}"


def accepted_log():
    lines = [record("BEGIN", "version", 1), record("identity", "pid", 413)]
    for (case, field), value in REQUIRED.items():
        if case not in {"BEGIN", "PASS", "EXIT-REQUEST"}:
            lines.append(record(case, field, value))
    receipts = {
        ("parent-open", "status"): 0,
        ("write", "status"): 0,
        ("write", "information"): 16,
        ("relative-read", "status"): 0,
        ("file-all", "status"): 0,
        ("file-all", "name-bytes"): 60,
        ("file-all", "information"): 160,
    }
    for (case, field), value in receipts.items():
        if (case, field) not in REQUIRED:
            lines.append(record(case, field, value))
    for (case, field), (count, value) in REPEATED.items():
        lines.extend(record(case, field, value) for _ in range(count))
    lines += [record("PASS", "cases", 19), record("EXIT-REQUEST", "status", 0),
              "[process-terminal-committed] pi=23 pid=413 generation=7 exit-status=0x00000000 signaled=1",
              "[process-delete] retired pi=23 pid=413 generation=7 threads=2"]
    return "\n".join(lines)


class AcceptanceParserTests(unittest.TestCase):
    def test_exact_dynamic_identity_and_retirement(self):
        self.assertEqual(verify(accepted_log()), (413, 7))

    def test_actual_display_transport_prefix_and_empty_final_thread_inventory(self):
        text = accepted_log().replace("[file-acceptance]", "[smss] [file-acceptance]")
        self.assertEqual(verify(text.replace("threads=2", "threads=0")), (413, 7))
        for malformed in [text.replace("[smss] [file-acceptance]", "junk [file-acceptance]", 1),
                          text.replace("expected=0x0000000000000013", "expected=0x0000000000000013.")]:
            with self.subTest(log=malformed), self.assertRaises(ValueError):
                verify(malformed)

    def test_desktop_alone_is_not_fixture_proof(self):
        with self.assertRaises(ValueError):
            verify("PASS exec_explorer_shell_chrome_painted\n[microtest sentinel matched -- exiting QEMU]")

    def test_status_store_must_preserve_amd64_padding(self):
        for text in [accepted_log().replace(record("file-all", "iosb-padding", 0xABABABAB), ""),
                     accepted_log().replace(record("file-all", "iosb-padding", 0xABABABAB),
                                            record("file-all", "iosb-padding", 0, 0xABABABAB))]:
            with self.subTest(log=text), self.assertRaises(ValueError):
                verify(text)

    def test_missing_worker_and_actual_mismatch_fail(self):
        for log in [accepted_log().replace(record("registry-worker-wait", "completed", 1), ""),
                    accepted_log().replace(record("relative-read", "bytes", 1), record("relative-read", "bytes", 0, 1)),
                    accepted_log() + "\n" + record("FAIL-EXIT-RETURNED", "status", 0)]:
            with self.subTest(log=log), self.assertRaises(ValueError):
                verify(log)

    def test_mode_full_span_failures_and_no_mutation_are_required(self):
        for case, refusal in (("mode-noaccess-span", 0xC0000005),
                              ("mode-guard-span", 0x80000001)):
            for text in [accepted_log().replace(record(case, "status", refusal), ""),
                         accepted_log().replace(record(case, "status", refusal),
                                                record(case, "status", 0, refusal)),
                         accepted_log().replace(record(case, "mode", 0x1020), ""),
                         accepted_log().replace(record(case, "iosb-information", 0xABABABABABABABAB), "")]:
                with self.subTest(case=case, log=text), self.assertRaises(ValueError):
                    verify(text)

    def test_successful_file_operation_receipts_cannot_be_omitted(self):
        for case, field, value in [
            ("parent-open", "status", 0),
            ("write", "status", 0),
            ("write", "information", 16),
            ("relative-read", "status", 0),
            ("file-all", "status", 0),
            ("file-all", "information", 160),
        ]:
            with self.subTest(case=case, field=field), self.assertRaises(ValueError):
                verify(accepted_log().replace(record(case, field, value), ""))

    def test_file_all_extent_requires_nonempty_utf16_within_actual_buffer(self):
        # All altered records are internally equal actual/expected. Only the independent
        # FileAll extent contract can reject them, not the generic mismatch guard.
        for name_bytes, information in [
            (0, 100),
            (1, 101),
            (60, 159),
            (60, 161),
            (390, 490),
            (0xFFFFFFA4, 8),
        ]:
            malformed = accepted_log().replace(
                record("file-all", "name-bytes", 60),
                record("file-all", "name-bytes", name_bytes),
            ).replace(
                record("file-all", "information", 160),
                record("file-all", "information", information),
            )
            with self.subTest(name_bytes=name_bytes, information=information), self.assertRaises(ValueError):
                verify(malformed)
        with self.assertRaises(ValueError):
            verify(accepted_log().replace(record("file-all", "name-bytes", 60), ""))

    def test_actual_file_name_suffix_proof_is_required(self):
        for text in [accepted_log().replace(record("file-all", "name-suffix", 1), ""),
                     accepted_log().replace(record("file-all", "name-suffix", 1),
                                            record("file-all", "name-suffix", 0))]:
            with self.subTest(log=text), self.assertRaises(ValueError):
                verify(text)

    def test_exit_status_generation_order_and_resource_retirement_fail(self):
        for old, new in [("exit-status=0x00000000", "exit-status=0xc0000001"),
                         ("retired pi=23 pid=413 generation=7", "retired pi=23 pid=413 generation=8"),
                         ("retired pi=23", "retired pi=24"),
                         ("pid=413 generation=7 exit-status", "pid=414 generation=7 exit-status")]:
            with self.subTest(new=new), self.assertRaises(ValueError):
                verify(accepted_log().replace(old, new))
        lines = accepted_log().splitlines()
        lines[-1], lines[-2] = lines[-2], lines[-1]
        with self.assertRaises(ValueError):
            verify("\n".join(lines))

    def test_replayed_or_truncated_receipts_fail(self):
        text = accepted_log()
        for log in [text + "\n" + text.splitlines()[-1],
                    text + "\n" + record("PASS", "cases", 19),
                    text.replace("signaled=1", "signaled=0"),
                    text.replace(" expected=0x0000000000000013", "")]:
            with self.subTest(log=log), self.assertRaises(ValueError):
                verify(log)


if __name__ == "__main__":
    unittest.main()
