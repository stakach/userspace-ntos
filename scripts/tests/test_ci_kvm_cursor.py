"""Recorded KVM pointer drift from mainline run 45184256752.

Fixtures are x=32..43, y=430..509 crops of the original step-4/step-5 PPMs.
Original boot-1 hashes: c38c1a6fc1226a65d4a8faeef2b33aeb8ca7f3b463cedcf1db2012ac4167873f
and ba1e252025781f2aecdb67d2330541b5a4192958bd05ece806d342b3e0a22a98.
Original boot-2 hashes: 4fc5e271ea947425b90789330b00e3ccbe62132834e04ac2acabf95dda0067ee
and b77ffca21cbb03e0eb00bdb9d05116a60e5e3a6b5fd2a0b980aaa4871ee34489.
The uncut PPMs stay with the KVM run evidence.
"""

import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ci_kvm_cursor import measure_cursor_hotspot, cursor_is_at_target, prove_cursor_position


FIXTURES = Path(__file__).with_name("fixtures") / "cursor_45184256752"
OUTSIDE_RADIUS = Path(__file__).with_name("fixtures") / "cursor_45233851099"
ACCELERATED_OVERSHOOT = Path(__file__).with_name("fixtures") / "cursor_46031955425"
ICON_SELECTION = Path(__file__).with_name("fixtures") / "icon_selection_45196431411"
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

    def test_recorded_cursor_beyond_initial_neighborhood_can_be_corrected(self):
        # Mainline run 45233851099: original desktop-clear PPM SHA-256
        # 089bd7607fb57a88412b9bdfad265c7881eb8d1054c0f5f2bf06db9a3195d15b;
        # original step-5 aim PPM SHA-256
        # d5f47a24f77cd8d57c3ced7010879dcdc470909dac1c0dc6c09fc60278012786.
        # The crop spans x=0..79, y=430..534, so hotspot (33,76) is (33,506)
        # on the original screen; the intended click is (37,470).
        proof = prove_cursor_position(OUTSIDE_RADIUS / "before.ppm",
                                      OUTSIDE_RADIUS / "aim.ppm", (37, 40))
        self.assertEqual(proof.position, (33, 76))
        self.assertFalse(cursor_is_at_target(proof.position, (37, 40)))

    def test_icon_selection_change_is_not_a_cursor(self):
        self.assertIsNone(measure_cursor_hotspot(ICON_SELECTION / "aim.ppm",
                                                ICON_SELECTION / "selected.ppm"))

    def test_recorded_acceleration_overshoot_is_measured_from_original_frames(self):
        # Run 46031955425: original baseline SHA-256 8af63714114e876af4646a261dd3e05b
        # a9b8fdd9b75e0a00498dcd4a49e259dc, aim1 ee2536786af21629ee69c5227a59dfa0
        # 53e10a679fc6cb42a0113d86fb26511b, aim2 dc4c6d17c402e56087d1b3e717e0c0c
        # 76109766179c569418079ea5c24440e1d. Crops x=850..1024, y=0..180 retain the
        # original pixels and exclude the old cursor and desktop clock. Target (925,100) is
        # (75,100) here; after requested (+36,-26), aim2 hotspot (1001,46) is (151,46).
        first = prove_cursor_position(ACCELERATED_OVERSHOOT / "baseline.ppm",
                                      ACCELERATED_OVERSHOOT / "aim1.ppm", (75, 100))
        self.assertEqual(first.position, (39, 126))
        proof = prove_cursor_position(ACCELERATED_OVERSHOOT / "baseline.ppm",
                                      ACCELERATED_OVERSHOOT / "aim2.ppm", (75, 100))
        self.assertEqual(proof.position, (151, 46))
        self.assertFalse(cursor_is_at_target(proof.position, (75, 100)))


if __name__ == "__main__":
    unittest.main()
