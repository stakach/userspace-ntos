"""Icon focus from the original mainline KVM run 45196431411 frame crops.

The 57x67 fixtures cover x=15..71, y=455..521. Original desktop, aim and
selected PPM SHA-256 values are 2b71e649d19e0b29b49bd39786b3e7689dd5de46053e55c4196a1eb0159a6213,
d58039c946a93fcb6eaf194863d4fbf276c1a39da8f4397c3da8c2213b72d373,
and 4f0df57fb71ae5d7a3e40c3d2011f72542a6be65a207555dcd6f86482357505b.
"""

from pathlib import Path
import unittest

from scripts.ci_kvm_cursor import prove_selected_icon


FIXTURES = Path(__file__).with_name("fixtures") / "icon_selection_45196431411"
TARGET = (37, 470)
ORIGIN = (15, 455)


class IconSelectionProofTests(unittest.TestCase):
    def test_recorded_aim_is_not_selection_but_click_selects_icon(self):
        before = prove_selected_icon(FIXTURES / "desktop.ppm", FIXTURES / "aim.ppm",
                                     TARGET, origin=ORIGIN)
        self.assertFalse(before.passed)
        selected = prove_selected_icon(FIXTURES / "aim.ppm", FIXTURES / "selected.ppm",
                                       TARGET, origin=ORIGIN)
        self.assertTrue(selected.passed)
        self.assertEqual(selected.image_name, "selected.ppm")
        self.assertEqual(len(selected.image_sha256), 64)


if __name__ == "__main__":
    unittest.main()
