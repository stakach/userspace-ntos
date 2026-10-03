import unittest

from verify_log import verify


SOURCE = "file=0x0000010003000100 generation=0x0000000000000007"
PROVIDER = "file=0x0000010007000200 generation=0x0000000000000007"


def accepted_lines():
    lines = [
        f"[mup-terminal-failure-identity] {PROVIDER} status=0x00000000 info=8",
        f"[terminal-failure-identity] {SOURCE} call=0x00000000 wait=0x00000000 iosb=0x00000000 info=8",
    ]
    for operation in range(3):
        lines += [
            f"[mup-terminal-failure-pending] operation={operation} {PROVIDER} status=0x00000103",
            f"[terminal-failure-retained] operation={operation} {SOURCE} event=0x00000102 iosb-and-output-unchanged=1",
            f"[mup-terminal-failure-release] operation={operation} {PROVIDER}",
            f"[mup-terminal-failure-terminal-intent] operation={operation} {PROVIDER} status=0xc0000185 info=0 ownership-unchanged=1",
            f"[terminal-failure-result] operation={operation} {SOURCE} call=0x00000103 release=0x00000000 wait=0x00000000 iosb=0xc0000185 info=0 output-unchanged=1",
            f"[terminal-failure-verified] operation={operation} {SOURCE}",
        ]
    lines += [
        f"[terminal-failure-handle-close-begin] {SOURCE}",
        f"[mup-terminal-failure-cleanup] {PROVIDER} count=1",
        f"[terminal-failure-handle-close-return] {SOURCE} status=0x00000000",
        f"[terminal-failure-pointer-release-begin] {SOURCE}",
        f"[mup-terminal-failure-close] {PROVIDER} count=1",
        f"[terminal-failure-pointer-release-return] {SOURCE}",
    ]
    return lines


class MupFailureLogTests(unittest.TestCase):
    def test_cross_domain_addresses_are_distinct_but_actual_generation_matches(self):
        self.assertEqual(verify("\n".join(accepted_lines())), (0x10003000100, 0x10007000200, 7))

    def test_every_receipt_is_required_and_duplicates_are_rejected(self):
        lines = accepted_lines()
        for index in range(len(lines)):
            with self.subTest(missing=index), self.assertRaises(ValueError):
                verify("\n".join(lines[:index] + lines[index + 1:]))
            with self.subTest(duplicate=index), self.assertRaises(ValueError):
                verify("\n".join(lines + [lines[index]]))

    def test_wrong_identity_generation_or_terminal_effect_is_rejected(self):
        text = "\n".join(accepted_lines())
        for before, after in [
            ("generation=0x0000000000000007", "generation=0x0000000000000008"),
            ("file=0x0000010003000100", "file=0x0000010003000200"),
            ("file=0x0000010007000200", "file=0x0000010007000300"),
            ("event=0x00000102", "event=0x00000000"),
            ("iosb-and-output-unchanged=1", "iosb-and-output-unchanged=0"),
            ("ownership-unchanged=1", "ownership-unchanged=0"),
            ("output-unchanged=1", "output-unchanged=0"),
            ("iosb=0xc0000185", "iosb=0x00000000"),
            ("release=0x00000000", "release=0xc000000d"),
            ("info=0", "info=10"),
        ]:
            with self.subTest(after=after), self.assertRaises(ValueError):
                verify(text.replace(before, after, 1))

    def test_pending_completion_and_lifecycle_order_is_enforced(self):
        lines = accepted_lines()
        for first, second in [(2, 3), (3, 4), (4, 5), (5, 6), (6, 7), (20, 19), (23, 22)]:
            changed = lines.copy()
            changed[first], changed[second] = changed[second], changed[first]
            with self.subTest(swapped=(first, second)), self.assertRaises(ValueError):
                verify("\n".join(changed))

    def test_async_cleanup_or_close_after_call_return_is_allowed(self):
        lines = accepted_lines()
        lines = lines[:20] + [lines[20], lines[22], lines[23], lines[25], lines[21], lines[24]]
        self.assertEqual(verify("\n".join(lines)), (0x10003000100, 0x10007000200, 7))

    def test_malformed_or_unframed_failure_records_are_not_evidence(self):
        text = "\n".join(accepted_lines())
        for altered in [text.replace("[terminal-failure-result]", "junk [terminal-failure-result]", 1),
                        text.replace("status=0xc0000185", "status=0x0xc0000185", 1),
                        text + "\n[read-forward-fail] status=0xc0000001"]:
            with self.subTest(text=altered), self.assertRaises(ValueError):
                verify(altered)


if __name__ == "__main__":
    unittest.main()
