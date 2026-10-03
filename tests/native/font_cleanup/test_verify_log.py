import unittest

from verify_log import verify


def successful_log():
    setup = "\n".join(
        ["[font-setup] PID-QUERY actual=0x00000000 expected=0x00000000", "[font-setup] BEGIN pid=40"] +
        [f"[font-setup] {stage} actual=0x00000000 expected=0x00000000"
         for stage in ("CREATE-RUN", "SET-RUN", "READBACK-RUN", "CLOSE-RUN")] +
        ["[font-setup] PASS RUN-REGISTERED", "[font-setup] EXIT-REQUEST status=0x00000000",
         "[process-terminal-committed] pi=20 pid=40 generation=2 exit-status=0x00000000 signaled=1",
         "[process-delete] retired pi=20 pid=40 generation=2 threads=1"])
    identity = ("pointer=0x0000010000300000 native-generation=7 view-generation=8 "
                "provider-domain=4 provider-generation=3 base=0x0000010004000000")
    font = "\n".join([
        "[font-acceptance] PID-QUERY actual=0x00000000 expected=0x00000000",
        "[font-acceptance] BEGIN pid=80",
        f"[kernel-section-map] {identity} bytes=8000 pages=2",
        "[font-acceptance] ADDED fonts=1 flags=0x00000010",
        "[font-acceptance] PASS PRIVATE-FONT-LOADED",
        "[font-acceptance] EXIT-REQUEST status=0x00000000",
        "[process-terminal-committed] pi=25 pid=80 generation=5 exit-status=0x00000000 signaled=1",
        f"[kernel-section-unmap-retired] {identity} remaining-refs=0",
        "[kernel-section-cleanup-result] op=unmap target=0x0000010004000000 "
        "provider-domain=4 provider-generation=3 caller=kernel pid=80 tid=90 "
        "thread-generation=6 canonical-current=1 process-signaled=1 status=0x00000000 return-value=0",
        "[process-delete] retired pi=25 pid=80 generation=5 threads=1"])
    return setup + "\n" + font


class FontCleanupLogTests(unittest.TestCase):
    def test_complete_exact_receipts(self):
        self.assertEqual(verify(successful_log()), (80, 5, 1))

    def test_missing_or_duplicate_required_lines(self):
        lines = successful_log().splitlines()
        for index in range(len(lines)):
            with self.subTest(index=index), self.assertRaises(ValueError):
                verify("\n".join(lines[:index] + lines[index + 1:]))
        for line in lines:
            with self.subTest(duplicate=line), self.assertRaises(ValueError):
                verify(successful_log() + "\n" + line)

    def test_wrong_or_unconfirmed_cleanup_owner(self):
        for before, after in [("caller=kernel pid=80", "caller=kernel pid=81"),
                              ("canonical-current=1", "canonical-current=0"),
                              ("process-signaled=1", "process-signaled=unknown"),
                              ("status=0x00000000 return-value=0", "status=0xc0000008"),
                              ("remaining-refs=0", "remaining-refs=1")]:
            with self.subTest(after=after), self.assertRaises(ValueError):
                verify(successful_log().replace(before, after))

    def test_stale_view_or_provider_generation(self):
        text = successful_log()
        for before, after in [("view-generation=8", "view-generation=9"),
                              ("native-generation=7", "native-generation=9"),
                              ("provider-generation=3", "provider-generation=9")]:
            with self.subTest(after=after), self.assertRaises(ValueError):
                verify(text.replace(before, after, 1))

    def test_retirement_before_termination_is_not_late_cleanup(self):
        lines = successful_log().splitlines()
        receipt = next(line for line in lines if "[kernel-section-unmap-retired]" in line)
        lines.remove(receipt)
        index = next(i for i, line in enumerate(lines) if "pi=25 pid=80" in line)
        lines.insert(index, receipt)
        with self.assertRaises(ValueError):
            verify("\n".join(lines))

    def test_execution_without_native_retirement_cannot_pass(self):
        text = "\n".join(line for line in successful_log().splitlines() if "kernel-section" not in line)
        with self.assertRaises(ValueError):
            verify(text)


if __name__ == "__main__":
    unittest.main()
