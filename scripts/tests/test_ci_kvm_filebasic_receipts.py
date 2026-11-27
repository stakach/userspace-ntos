"""FileBasic proof needs exact native settlement, not just visible attrib output."""

import unittest

from scripts.ci_kvm_filebasic_receipts import prove_filebasic_receipts


def event(stage, *, file=81, stable=100, slot=3, generation=7, irp=101,
          attrs=None, status=0):
    line = (f"[file-set-owner] stage={stage} table=2 slot={slot} "
            f"generation={generation} irp={irp} pi=4 tid=5 "
            f"status={status} file={file}")
    if attrs is not None:
        line += f" stable={stable} attrs={attrs}"
    return (line + "\n").encode()


def sequence(*, attrs, irp, file=81, stable=100, status=0):
    return b"".join(event(stage, file=file, stable=stable, irp=irp,
                          attrs=attrs if stage == "basic-terminal" else None,
                          status=status)
                    for stage in ("basic-terminal", "reply", "file-released", "retired"))


class FileBasicReceiptTests(unittest.TestCase):
    def test_accepts_clear_then_set_of_same_file_with_exact_owner_stages(self):
        serial = sequence(attrs=16, irp=101, file=81) + sequence(attrs=17, irp=102, file=82)
        self.assertTrue(prove_filebasic_receipts(serial).passed)

    def test_rejects_missing_or_crossed_owner_stages(self):
        clear = sequence(attrs=16, irp=101)
        set_prefix = event("basic-terminal", irp=102, attrs=17)
        for tail in (
            b"",
            event("reply", irp=102) + event("retired", irp=102),
            event("reply", irp=103) + event("file-released", irp=102)
            + event("retired", irp=102),
            event("reply", irp=102, generation=8)
            + event("file-released", irp=102) + event("retired", irp=102),
            event("reply", irp=102, status=5)
            + event("file-released", irp=102) + event("retired", irp=102),
        ):
            with self.subTest(tail=tail):
                self.assertFalse(prove_filebasic_receipts(clear + set_prefix + tail).passed)

    def test_rejects_different_files_reversed_order_or_no_attribute_change(self):
        for serial in (
            sequence(attrs=16, irp=101, stable=100)
            + sequence(attrs=17, irp=102, stable=101),
            sequence(attrs=17, irp=101) + sequence(attrs=16, irp=102),
            sequence(attrs=0, irp=101) + sequence(attrs=17, irp=102),
            sequence(attrs=17, irp=101) + sequence(attrs=17, irp=102),
            sequence(attrs=16, irp=101, status=5) + sequence(attrs=17, irp=102),
        ):
            with self.subTest(serial=serial):
                self.assertFalse(prove_filebasic_receipts(serial).passed)

    def test_ignores_unrelated_set_receipts_but_needs_basic_terminal(self):
        unrelated = event("reply", irp=8) + event("file-released", irp=8)
        serial = unrelated + sequence(attrs=16, irp=101) + sequence(attrs=17, irp=102)
        self.assertTrue(prove_filebasic_receipts(serial).passed)


if __name__ == "__main__":
    unittest.main()
