import unittest

from scripts.ci_kvm_smoke import published_storahci_abars


class AhciProbeTest(unittest.TestCase):
    def test_keeps_both_published_controllers_and_deduplicates_repeat_publication(self):
        serial = (
            b"[driver-launch] assigned PCI resources service=storahci devnode=first "
            b"mmio=0x0x810a1000 len=4096\n"
            b"[driver-launch] assigned PCI resources service=storahci devnode=second "
            b"mmio=0x0x810a0000 len=4096\n"
            b"[driver-launch] assigned PCI resources service=storahci devnode=first "
            b"mmio=0x0x810a1000 len=4096\n"
        )
        self.assertEqual(published_storahci_abars(serial), [0x810A1000, 0x810A0000])


if __name__ == "__main__":
    unittest.main()
