"""Recorded KVM pointer drift from mainline run 45184256752."""

import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ci_kvm_cursor import measure_cursor_hotspot, cursor_is_at_target


FIXTURES = Path(__file__).with_name("fixtures") / "cursor_45184256752"
TARGET = (37, 470)
ORIGIN = (32, 430)


class CursorProofTests(unittest.TestCase):
    def test_recorded_boot1_click_was_on_target(self):
        position = measure_cursor_hotspot(FIXTURES / "boot1-before.ppm",
                                          FIXTURES / "boot1-after.ppm", ORIGIN)
        self.assertEqual(position, TARGET)
        self.assertTrue(cursor_is_at_target(position, TARGET))

    def test_recorded_boot2_click_missed_icon(self):
        position = measure_cursor_hotspot(FIXTURES / "boot2-before.ppm",
                                          FIXTURES / "boot2-after.ppm", ORIGIN)
        self.assertEqual(position, (37, 446))
        self.assertFalse(cursor_is_at_target(position, TARGET))


if __name__ == "__main__":
    unittest.main()
