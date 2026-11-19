"""Scripted desktop interaction: strict step parsing, exact PS/2 event paths, safe pacing."""

import copy
import json
from pathlib import Path
import tempfile
import unittest

from scripts.ci_kvm_interaction import (
    DEFAULT_SCRIPT, InteractionRunner, action_batches, chord_batches, load_script,
    parse_script, pointer_batches, relative_deltas, screenshot_name, text_chords,
)
from scripts.ci_kvm_smoke import DESKTOP_EPOCH_SEALED_RECORD, SerialPanicDetector

DOCUMENT = {
    "screen": [1024, 768],
    "settle_seconds": 20,
    "steps": [
        {"name": "baseline", "actions": [], "wait_seconds": 0},
        {"name": "start-menu", "actions": [{"click": [28, 743]}], "wait_seconds": 5},
        {"name": "ver", "actions": [{"type": "ver\n"}, {"key": ["ctrl", "esc"]}],
         "wait_seconds": 8},
    ],
}


def rel_sum(batches):
    x = y = 0
    for events, _pause in batches:
        for event in events:
            if event["type"] == "rel":
                if event["data"]["axis"] == "x":
                    x += event["data"]["value"]
                else:
                    y += event["data"]["value"]
    return x, y


def keys(batches):
    return [(event["data"]["key"]["data"], event["data"]["down"])
            for events, _pause in batches for event in events]


class ParseScriptTests(unittest.TestCase):
    def test_default_script_parses(self):
        script = load_script(DEFAULT_SCRIPT)
        self.assertEqual(script.screen, (1024, 768))
        self.assertEqual(script.steps[0].name, "baseline")
        self.assertEqual(script.steps[1].actions, (("click", (28, 743)),))

    def test_document_parses_to_ordered_steps(self):
        script = parse_script(DOCUMENT)
        self.assertEqual([step.name for step in script.steps], ["baseline", "start-menu", "ver"])
        self.assertEqual(script.steps[2].actions, (("type", "ver\n"), ("key", ("ctrl", "esc"))))
        self.assertEqual(script.steps[2].wait_seconds, 8.0)
        self.assertEqual(script.settle_seconds, 20.0)

    def test_invalid_documents_fail_before_boot(self):
        def mutate(change):
            document = copy.deepcopy(DOCUMENT)
            change(document)
            return document

        cases = {
            "off-screen click": lambda d: d["steps"][1].update(actions=[{"click": [1024, 10]}]),
            "unknown action": lambda d: d["steps"][1].update(actions=[{"wiggle": [1, 1]}]),
            "two actions in one object": lambda d: d["steps"][1].update(
                actions=[{"click": [1, 1], "key": ["esc"]}]),
            "duplicate name": lambda d: d["steps"][2].update(name="baseline"),
            "unsafe name": lambda d: d["steps"][2].update(name="../x"),
            "unmapped text": lambda d: d["steps"][2].update(actions=[{"type": "veré"}]),
            "empty chord": lambda d: d["steps"][2].update(actions=[{"key": []}]),
            "boolean wait": lambda d: d["steps"][0].update(wait_seconds=True),
            "unbounded wait": lambda d: d["steps"][0].update(wait_seconds=601),
            "unknown field": lambda d: d.update(extra=1),
            "no steps": lambda d: d.update(steps=[]),
        }
        for label, change in cases.items():
            with self.subTest(label), self.assertRaises(ValueError):
                parse_script(mutate(change))


class EventGenerationTests(unittest.TestCase):
    def test_relative_deltas_are_small_and_exact(self):
        for dx, dy in ((28, -24), (37, -297), (0, 0), (-3, 1), (1023, -767)):
            with self.subTest(dx=dx, dy=dy):
                deltas = relative_deltas(dx, dy, 4)
                self.assertEqual((sum(d[0] for d in deltas), sum(d[1] for d in deltas)), (dx, dy))
                self.assertTrue(all(abs(x) <= 4 and abs(y) <= 4 and (x or y) for x, y in deltas))

    def test_pointer_pins_bottom_left_then_aims_relative(self):
        batches = pointer_batches((28, 743), (1024, 768))
        pin = [batch for batch in batches if any(
            abs(event["data"]["value"]) > 4 for event in batch[0])]
        # Pinning overshoots both edges so the clamped cursor sits at exactly (0, 767).
        self.assertEqual(rel_sum(pin), (-2048, 1536))
        self.assertEqual(rel_sum(batches[len(pin):]), (28, 743 - 767))
        self.assertEqual(batches[:len(pin)], pin)

    def test_double_click_is_two_left_clicks_without_movement(self):
        batches = action_batches(("double_click", (37, 470)), (1024, 768))
        buttons = [batch for batch in batches if batch[0][0]["type"] == "btn"]
        self.assertEqual([batch[0][0]["data"]["down"] for batch in buttons],
                         [True, False, True, False])
        self.assertEqual(batches[-4:], buttons)
        self.assertLess(sum(pause for _events, pause in buttons), 0.5)

    def test_chords_release_in_reverse(self):
        self.assertEqual(keys(chord_batches(("ctrl", "esc"))),
                         [("ctrl", True), ("esc", True), ("esc", False), ("ctrl", False)])

    def test_text_maps_to_us_layout_qcodes(self):
        self.assertEqual(text_chords("ver\n"), (("v",), ("e",), ("r",), ("ret",)))
        self.assertEqual(text_chords("C:"), (("shift", "c"), ("shift", "semicolon")))
        self.assertEqual(keys(action_batches(("type", "v\n"), (1024, 768))),
                         [("v", True), ("v", False), ("ret", True), ("ret", False)])


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class InteractionRunnerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.log = Path(self.directory.name) / "interact.jsonl"
        self.clock = FakeClock()
        self.performed, self.captured = [], []

    def tearDown(self):
        self.directory.cleanup()

    def runner(self, perform=None, capture=None):
        return InteractionRunner(parse_script(DOCUMENT), perform or self.performed.append,
                                 capture or self.captured.append, self.log, self.clock)

    def test_runs_steps_after_settle_and_waits_between_actions_and_screenshots(self):
        runner = self.runner()
        self.assertFalse(runner.in_progress)
        self.assertEqual(runner.advance(100), [])  # never acts before the desktop seal
        runner.arm(0)
        self.assertTrue(runner.in_progress)
        self.assertEqual(runner.advance(19), [])
        self.clock.now = 20
        self.assertEqual(runner.advance(20), [screenshot_name(1, parse_script(DOCUMENT).steps[0])])
        self.assertEqual(len(self.performed), 1)  # start-menu click sent, waiting 5 s
        self.clock.now = 24
        self.assertEqual(runner.advance(24), [])
        self.clock.now = 25
        self.assertEqual(runner.advance(25), ["native-kvm-interact-02-start-menu.ppm"])
        self.assertEqual(len(self.performed), 3)  # both ver actions sent
        self.assertTrue(runner.in_progress)
        self.clock.now = 33
        self.assertEqual(runner.advance(33), ["native-kvm-interact-03-ver.ppm"])
        self.assertTrue(runner.finished)
        self.assertFalse(runner.in_progress)
        self.assertEqual(self.captured, ["native-kvm-interact-01-baseline.ppm",
                                         "native-kvm-interact-02-start-menu.ppm",
                                         "native-kvm-interact-03-ver.ppm"])
        self.assertEqual(runner.failures, 0)

    def test_input_and_capture_errors_are_recorded_not_raised(self):
        def refuse(_batches):
            raise RuntimeError("QMP input-send-event: refused")

        def broken(_name):
            raise OSError("socket closed")

        runner = self.runner(refuse, broken)
        runner.arm(0)
        for now in (20, 25, 33):
            self.clock.now = now
            runner.advance(now)
        self.assertTrue(runner.finished)
        self.assertEqual(runner.failures, 6)  # three actions and three screenshots
        entries = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual([entry["event"] for entry in entries].count("error"), 6)
        self.assertIn("refused", entries[2]["error"])

    def test_seal_detector_finds_the_desktop_record(self):
        path = Path(self.directory.name) / "serial.log"
        path.write_bytes(b"[quiesce] Explorer runtime paint milestones complete; boot-progress "
                         b"epoch sealed\r\n")
        self.assertIsNotNone(SerialPanicDetector(path, DESKTOP_EPOCH_SEALED_RECORD).poll())


if __name__ == "__main__":
    unittest.main()
