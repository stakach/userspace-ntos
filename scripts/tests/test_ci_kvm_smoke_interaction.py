"""Scripted desktop interaction: strict step parsing, exact PS/2 event paths, safe pacing."""

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts.ci_kvm_interaction import (
    DEFAULT_SCRIPT, InteractionRunner, action_batches, chord_batches, load_script,
    parse_script, pointer_batches, relative_deltas, screenshot_name, text_chords,
)
from scripts.ci_kvm_smoke import (DESKTOP_EPOCH_SEALED_RECORD, SerialPanicDetector,
                                  send_input_batches)
from scripts.ci_kvm_cursor import CursorProof, cursor_is_at_target
from scripts.ci_kvm_visual_proof import VisualProof

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
        # Prove cursor aim and a real click on neutral wallpaper. LiberNT's
        # Start menu focuses its edit on open, so typing needs no second click.
        self.assertEqual(script.steps[1].actions,
                         (("verified_click", (925, 100)),))
        self.assertEqual(script.steps[2].actions, (("click", (28, 743)),))
        # Run 45436226805 captured the shell after 10 s while its menu was
        # still absent; 45425894277 had a visible menu after a 60 s settle.
        self.assertEqual(script.steps[2].wait_seconds, 60.0)
        self.assertEqual([step.readiness_poll_seconds for step in script.steps],
                         [None, None, 2.0, 2.0, 4.0, None])
        # The Start menu searches shortcut names, so "command" can find
        # Command Prompt; the result must be visible before Enter launches it.
        self.assertEqual([step.name for step in script.steps],
                         ["baseline", "desktop-pointer", "start-menu", "command-prompt-search",
                          "command-prompt", "ver"])
        self.assertEqual(script.steps[3].actions, (("type", "command"),))
        self.assertEqual(script.steps[4].actions, (("key", ("ret",)),))
        self.assertEqual(script.steps[5].actions, (("type", "ver\n"),))

    def test_document_parses_to_ordered_steps(self):
        script = parse_script(DOCUMENT)
        self.assertEqual([step.name for step in script.steps], ["baseline", "start-menu", "ver"])
        self.assertEqual(script.steps[2].actions, (("type", "ver\n"), ("key", ("ctrl", "esc"))))
        self.assertEqual(script.steps[2].wait_seconds, 8.0)
        self.assertEqual(script.settle_seconds, 20.0)
        self.assertEqual(script.arm, "seal")

    def test_arm_mode_selects_seal_or_sealed_idle(self):
        self.assertEqual(parse_script({**DOCUMENT, "arm": "idle"}).arm, "idle")
        self.assertEqual(load_script(DEFAULT_SCRIPT).arm, "idle")
        for bad in ("later", "", 1, None):
            with self.subTest(bad), self.assertRaises(ValueError):
                parse_script({**DOCUMENT, "arm": bad})

    def test_production_script_waits_for_sealed_desktop_idle(self):
        script = load_script(DEFAULT_SCRIPT)
        # LiberNT's Run\AppLauncher opens a /c console after Explorer paints.
        # Starting the search at seal let that console steal Enter before the
        # interactive Command Prompt shortcut could launch (KVM 45468676396).
        self.assertEqual(script.arm, "idle")
        self.assertEqual(script.settle_seconds, 10)
        with tempfile.TemporaryDirectory() as directory:
            serial = Path(directory) / "serial.log"
            serial.write_bytes(
                b"[quiesce] Explorer runtime paint milestones complete; boot-progress "
                b"epoch sealed\n[hosted-process] another background child started\n"
            )
            self.assertIsNotNone(SerialPanicDetector(
                serial, DESKTOP_EPOCH_SEALED_RECORD).poll())
            screenshots = []
            now = [100.0]
            interaction = InteractionRunner(
                script, lambda _batches: None, screenshots.append,
                Path(directory) / "interaction.jsonl", clock=lambda: now[0])
            interaction.arm(now[0])
            now[0] = 110.0
            interaction.advance(now[0])
            self.assertEqual(screenshots, ["native-kvm-interact-01-baseline.ppm"])

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
            "zero readiness poll": lambda d: d["steps"][1].update(
                readiness_poll_seconds=0),
            "subsecond readiness poll": lambda d: d["steps"][1].update(
                readiness_poll_seconds=0.5),
            "poll beyond deadline": lambda d: d["steps"][1].update(
                readiness_poll_seconds=6),
            "boolean readiness poll": lambda d: d["steps"][1].update(
                readiness_poll_seconds=True),
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

    def test_a_click_waits_for_motion_to_drain_and_holds_the_press(self):
        # Boot 44559273509 lost a press sent 10 ms behind undrained motion packets.
        batches = action_batches(("click", (28, 743)), (1024, 768))
        last_move, press, release = batches[-3], batches[-2], batches[-1]
        self.assertEqual(last_move[0][0]["type"], "rel")
        self.assertGreaterEqual(last_move[1], 0.3)
        self.assertTrue(press[0][0]["data"]["down"])
        self.assertGreaterEqual(press[1], 0.15)
        self.assertFalse(release[0][0]["data"]["down"])

    def test_chords_release_in_reverse(self):
        self.assertEqual(keys(chord_batches(("ctrl", "esc"))),
                         [("ctrl", True), ("esc", True), ("esc", False), ("ctrl", False)])

    def test_text_maps_to_us_layout_qcodes(self):
        self.assertEqual(text_chords("ver\n"), (("v",), ("e",), ("r",), ("ret",)))
        self.assertEqual(text_chords("C:"), (("shift", "c"), ("shift", "semicolon")))
        self.assertEqual(text_chords("echo x>proof.txt\n")[6], ("shift", "dot"))
        self.assertEqual(keys(action_batches(("type", "v\n"), (1024, 768))),
                         [("v", True), ("v", False), ("ret", True), ("ret", False)])

    def test_qmp_ack_without_class_receipt_holds_the_next_key(self):
        class QmpStream:
            def __init__(self):
                self.commands = []
                self.pending = [b'{"QMP":{}}\n']

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                pass

            def write(self, data):
                command = json.loads(data)
                self.commands.append(command)
                self.pending.append((json.dumps({"id": command["id"], "return": {}})
                                     + "\n").encode())

            def readline(self):
                return self.pending.pop(0)

        class QmpSocket:
            def __init__(self, stream):
                self.stream = stream

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                pass

            def settimeout(self, _seconds):
                pass

            def connect(self, _path):
                pass

            def makefile(self, *_args, **_kwargs):
                return self.stream

        with tempfile.TemporaryDirectory() as directory:
            serial = Path(directory) / "serial.log"
            serial.write_bytes(b"")
            stream = QmpStream()
            with (mock.patch("scripts.ci_kvm_smoke.LOG", serial),
                  mock.patch("scripts.ci_kvm_smoke.QMP_SOCKET", Path(directory) / "qmp"),
                  mock.patch("scripts.ci_kvm_smoke.socket.socket",
                             return_value=QmpSocket(stream)),
                  mock.patch("scripts.ci_kvm_smoke.KEYBOARD_RECEIPT_TIMEOUT", 0.02,
                             create=True)):
                with self.assertRaisesRegex(RuntimeError, "keyboard.*class receipt"):
                    send_input_batches(chord_batches(("m",)))
            sent = [entry for entry in stream.commands
                    if entry["execute"] == "input-send-event"]
            self.assertEqual(len(sent), 1)


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

    def test_serial_offsets_bracket_input_and_screenshot(self):
        script = parse_script({"screen": [1024, 768], "settle_seconds": 0,
                               "steps": [{"name": "type", "actions": [{"type": "m"}],
                                          "wait_seconds": 1}]})
        serial = Path(self.directory.name) / "serial.log"
        serial.write_bytes(b"boot\n")

        def perform(_batches):
            with serial.open("ab") as output:
                output.write(b"class-record\n")

        def capture(_name):
            with serial.open("ab") as output:
                output.write(b"read-terminal\n")

        runner = InteractionRunner(script, perform, capture, self.log, self.clock,
                                   serial_offset=lambda: serial.stat().st_size)
        runner.arm(0)
        runner.advance(0)
        self.clock.now = 1
        runner.advance(1)
        events = [json.loads(line) for line in self.log.read_text().splitlines()]
        action = next(event for event in events if event["event"] == "action")
        screenshot = next(event for event in events if event["event"] == "screenshot")
        self.assertEqual(serial.read_bytes()[:action["serial_bytes"]],
                         b"boot\nclass-record\n")
        self.assertEqual(serial.read_bytes()[:screenshot["serial_bytes"]],
                         b"boot\nclass-record\nread-terminal\n")

    def test_start_menu_visual_readiness_advances_before_wait_ceiling(self):
        script = parse_script({"screen": [1024, 768], "settle_seconds": 0,
                               "steps": [
                                   {"name": "start-menu", "actions": [{"click": [28, 743]}],
                                    "wait_seconds": 60, "readiness_poll_seconds": 2},
                                   {"name": "ver", "actions": [{"type": "ver\n"}],
                                    "wait_seconds": 0}]})
        proof = lambda name: VisualProof(True, "Start menu search visible", "", name,
                                         "start-sha")
        runner = InteractionRunner(script, self.performed.append, self.captured.append,
                                   self.log, self.clock,
                                   checks={"start-menu": proof})
        runner.arm(0)
        runner.advance(0)
        self.assertEqual(len(self.performed), 1)
        self.clock.now = 2
        runner.advance(2)
        self.assertEqual(runner.checkpoints["start-menu"].image_name, self.captured[0])
        self.assertIn("-probe-", self.captured[0])
        self.assertEqual(self.captured[-1], "native-kvm-interact-02-ver.ppm")
        self.assertEqual(len(self.performed), 2, "visible Start must permit the next action at 2 s")
        receipt = next(entry for entry in map(json.loads, self.log.read_text().splitlines())
                       if entry["event"] == "checkpoint" and entry["name"] == "start-menu")
        self.assertEqual((receipt["attempt"], receipt["ready_after_seconds"]), (1, 2))
        self.assertEqual(receipt["image_sha256"], "start-sha")

    def test_ready_command_prompt_advances_before_wait_ceiling(self):
        script = parse_script({"screen": [1024, 768], "settle_seconds": 0,
                               "steps": [
                                   {"name": "command-prompt", "actions": [{"key": ["ret"]}],
                                    "wait_seconds": 120, "readiness_poll_seconds": 4},
                                   {"name": "ver", "actions": [{"type": "ver\n"}],
                                    "wait_seconds": 0}]})
        proof = lambda name: VisualProof(True, "C:\\Users\\User>", "", name,
                                         "prompt-sha")
        runner = InteractionRunner(script, self.performed.append, self.captured.append,
                                   self.log, self.clock,
                                   checks={"command-prompt": proof})
        runner.arm(0)
        runner.advance(0)
        self.clock.now = 4
        runner.advance(4)
        self.assertEqual(runner.checkpoints["command-prompt"].image_name, self.captured[0])
        self.assertEqual(self.captured[-1], "native-kvm-interact-02-ver.ppm")
        self.assertEqual(len(self.performed), 2, "ready prompt must permit ver at 4 s")

    def test_failed_visual_probes_retry_then_halt_at_wait_ceiling(self):
        script = parse_script({"screen": [1024, 768], "settle_seconds": 0,
                               "steps": [
                                   {"name": "start-menu", "actions": [{"click": [28, 743]}],
                                    "wait_seconds": 6, "readiness_poll_seconds": 2},
                                   {"name": "ver", "actions": [{"type": "ver\n"}],
                                    "wait_seconds": 0}]})
        proof = lambda name: VisualProof(False, "", "Start menu absent", name,
                                         "failed-sha")
        runner = InteractionRunner(script, self.performed.append, self.captured.append,
                                   self.log, self.clock,
                                   checks={"start-menu": proof})
        runner.arm(0)
        runner.advance(0)
        self.clock.now = 2
        runner.advance(2)
        self.assertGreaterEqual(len(self.captured), 1, "must probe before the 6 s ceiling")
        self.assertFalse(runner.finished, "a failed early probe may retry")
        self.clock.now = 6
        runner.advance(6)
        self.assertTrue(runner.finished)
        self.assertEqual(runner.failures, 1)
        self.assertGreaterEqual(len(self.captured), 2)
        self.assertEqual(len(self.captured), len(set(self.captured)),
                         "each failed probe must retain a distinct screenshot")
        self.assertTrue(all("-probe-" in name for name in self.captured))
        self.assertEqual(len(self.performed), 1, "never type ver without Start proof")

    def test_final_visual_probe_survives_one_boot_loop_tick_of_scheduling_slack(self):
        script = parse_script({"screen": [1024, 768], "settle_seconds": 0,
                               "steps": [
                                   {"name": "start-menu", "actions": [{"click": [28, 743]}],
                                    "wait_seconds": 4, "readiness_poll_seconds": 2},
                                   {"name": "ver", "actions": [{"type": "ver\n"}],
                                    "wait_seconds": 0}]})
        proofs = iter((False, True))
        def prove(name):
            return VisualProof(next(proofs), "Start menu search visible",
                               image_name=name, image_sha256="frame-sha")
        runner = InteractionRunner(script, self.performed.append, self.captured.append,
                                   self.log, self.clock, checks={"start-menu": prove})
        runner.arm(0)
        runner.advance(0)
        self.clock.now = 2
        runner.advance(2)
        self.clock.now = 4.1  # the bounded boot loop woke just after the scheduled deadline
        runner.advance(4.1)
        self.assertEqual(len(self.captured), 3)
        self.assertEqual(len(self.performed), 2, "the final exact frame must permit the next step")
        self.assertEqual(runner.failures, 0)

    def test_visual_probe_retries_without_repeating_guest_input(self):
        script = parse_script({"screen": [1024, 768], "settle_seconds": 0,
                               "steps": [
                                   {"name": "start-menu", "actions": [{"click": [28, 743]}],
                                    "wait_seconds": 60, "readiness_poll_seconds": 2},
                                   {"name": "ver", "actions": [{"type": "ver\n"}],
                                    "wait_seconds": 0}]})
        proofs = iter(((False, "not ready", "sha1"), (True, "", "sha2")))
        def prove(name):
            ready, error, digest = next(proofs)
            return VisualProof(ready, "search box" if ready else "", error, name, digest)
        runner = InteractionRunner(script, self.performed.append, self.captured.append,
                                   self.log, self.clock,
                                   checks={"start-menu": prove})
        runner.arm(0)
        runner.advance(0)
        self.clock.now = 2
        runner.advance(2)
        self.assertEqual(len(self.performed), 1, "no next action before visual proof")
        runner.advance(2)
        self.assertEqual(len(self.captured), 1, "a same-time tick must not repeat OCR")
        self.clock.now = 4
        runner.advance(4)
        self.assertEqual(len(self.performed), 2, "successful retry permits next action")
        self.assertEqual(runner.failures, 0)
        self.assertEqual(len(self.captured), len(set(self.captured)))
        self.assertTrue(all("-probe-" in name for name in self.captured[:-1]))
        self.assertEqual(self.captured[-1], "native-kvm-interact-02-ver.ppm")

    def test_early_probe_capture_error_fails_closed(self):
        script = parse_script({"screen": [1024, 768], "settle_seconds": 0,
                               "steps": [
                                   {"name": "start-menu", "actions": [{"click": [28, 743]}],
                                    "wait_seconds": 60, "readiness_poll_seconds": 2},
                                   {"name": "ver", "actions": [{"type": "ver\n"}],
                                    "wait_seconds": 0}]})
        def broken(_name):
            raise OSError("framebuffer unavailable")
        runner = InteractionRunner(script, self.performed.append, broken, self.log, self.clock,
                                   checks={"start-menu": lambda _name: None})
        runner.arm(0)
        runner.advance(0)
        self.clock.now = 2
        runner.advance(2)
        self.assertTrue(runner.finished)
        self.assertEqual(runner.failures, 1)
        self.assertEqual(len(self.performed), 1, "never type ver after capture failure")

    def test_checked_step_without_poll_opt_in_keeps_legacy_wait(self):
        script = parse_script({"screen": [1024, 768], "settle_seconds": 0,
                               "steps": [{"name": "start-menu", "actions": [],
                                          "wait_seconds": 60}]})
        runner = InteractionRunner(script, self.performed.append, self.captured.append,
                                   self.log, self.clock,
                                   checks={"start-menu": lambda name: VisualProof(
                                       True, image_name=name, image_sha256="sha")})
        runner.arm(0)
        runner.advance(0)
        self.clock.now = 2
        self.assertEqual(runner.advance(2), [])
        self.assertEqual(self.captured, [])
        self.clock.now = 60
        self.assertEqual(runner.advance(60), ["native-kvm-interact-01-start-menu.ppm"])
        self.assertTrue(runner.finished)

    def test_frame_capture_after_one_tick_slack_cannot_accept_late_proof(self):
        script = parse_script({"screen": [1024, 768], "settle_seconds": 0,
                               "steps": [
                                   {"name": "start-menu", "actions": [{"click": [28, 743]}],
                                    "wait_seconds": 6, "readiness_poll_seconds": 2},
                                   {"name": "ver", "actions": [{"type": "ver\n"}],
                                    "wait_seconds": 0}]})
        def slow_capture(name):
            self.captured.append(name)
            self.clock.now = 7.1
        def proof(name):
            return VisualProof(True, "Start menu search visible", image_name=name,
                               image_sha256="sha")
        runner = InteractionRunner(script, self.performed.append, slow_capture,
                                   self.log, self.clock, checks={"start-menu": proof})
        runner.arm(0)
        runner.advance(0)
        self.clock.now = 2
        runner.advance(2)
        self.assertTrue(runner.finished)
        self.assertEqual(runner.failures, 1)
        self.assertEqual(len(self.performed), 1)

    def test_slow_ocr_of_an_on_time_frame_keeps_its_capture_time(self):
        script = parse_script({"screen": [1024, 768], "settle_seconds": 0,
                               "steps": [{"name": "start-menu", "actions": [],
                                          "wait_seconds": 6, "readiness_poll_seconds": 2}]})
        def slow_proof(name):
            self.clock.now = 7
            return VisualProof(True, "Start menu search visible", image_name=name,
                               image_sha256="sha")
        runner = InteractionRunner(script, self.performed.append, self.captured.append,
                                   self.log, self.clock, checks={"start-menu": slow_proof})
        runner.arm(0)
        runner.advance(0)
        self.clock.now = 2
        runner.advance(2)
        self.assertTrue(runner.finished)
        self.assertEqual(runner.failures, 0)
        receipt = next(entry for entry in map(json.loads, self.log.read_text().splitlines())
                       if entry["event"] == "checkpoint")
        self.assertEqual(receipt["ready_after_seconds"], 2)

    def test_input_error_does_not_advance_on_visual_proof(self):
        script = parse_script({"screen": [1024, 768], "settle_seconds": 0,
                               "steps": [
                                   {"name": "start-menu", "actions": [{"click": [28, 743]}],
                                    "wait_seconds": 60, "readiness_poll_seconds": 2},
                                   {"name": "ver", "actions": [{"type": "ver\n"}],
                                    "wait_seconds": 0}]})
        def refuse(_batches):
            raise RuntimeError("QMP input-send-event: refused")
        runner = InteractionRunner(script, refuse, self.captured.append,
                                   self.log, self.clock,
                                   checks={"start-menu": lambda name: VisualProof(
                                       True, image_name=name, image_sha256="sha")})
        runner.arm(0)
        runner.advance(0)
        self.assertTrue(runner.finished)
        self.assertEqual(runner.failures, 1)
        self.assertEqual(self.captured, [])

    def test_uncertain_input_on_unchecked_step_stops_before_next_action(self):
        script = parse_script({"screen": [1024, 768], "settle_seconds": 0,
                               "steps": [{"name": "text", "actions": [
                                   {"type": "a"}, {"type": "b"}],
                                   "wait_seconds": 0}]})
        calls = []
        def uncertain(batches):
            calls.append(batches)
            raise RuntimeError("keyboard a make missing class receipt")
        runner = InteractionRunner(script, uncertain, self.captured.append,
                                   self.log, self.clock)
        runner.arm(0)
        runner.advance(0)
        self.assertTrue(runner.finished)
        self.assertEqual(runner.failures, 1)
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.captured, [])

    def test_visual_infrastructure_failure_halts_without_retry(self):
        script = parse_script({"screen": [1024, 768], "settle_seconds": 0,
                               "steps": [
                                   {"name": "start-menu", "actions": [],
                                    "wait_seconds": 60, "readiness_poll_seconds": 2},
                                   {"name": "ver", "actions": [{"type": "ver\n"}],
                                    "wait_seconds": 0}]})
        runner = InteractionRunner(script, self.performed.append, self.captured.append,
                                   self.log, self.clock,
                                   checks={"start-menu": lambda name: VisualProof(
                                       False, error="OCR unavailable: executable missing",
                                       image_name=name, image_sha256="sha", fatal=True)})
        runner.arm(0)
        runner.advance(0)
        self.clock.now = 2
        runner.advance(2)
        self.assertTrue(runner.finished)
        self.assertEqual(runner.failures, 1)
        self.assertEqual(len(self.captured), 1)
        self.assertEqual(self.performed, [])

    def test_polled_success_requires_current_hashed_capture(self):
        script = parse_script({"screen": [1024, 768], "settle_seconds": 0,
                               "steps": [
                                   {"name": "start-menu", "actions": [{"click": [28, 743]}],
                                    "wait_seconds": 60, "readiness_poll_seconds": 2},
                                   {"name": "ver", "actions": [{"type": "ver\n"}],
                                    "wait_seconds": 0}]})
        for label, image_name, digest in (("stale frame", "prior-frame.ppm", "sha"),
                                          ("missing hash", None, "")):
            with self.subTest(label):
                performed, captured = [], []
                runner = InteractionRunner(
                    script, performed.append, captured.append, self.log, self.clock,
                    checks={"start-menu": lambda name: VisualProof(
                        True, "search visible", image_name=image_name or name,
                        image_sha256=digest)})
                self.clock.now = 0
                runner.arm(0)
                runner.advance(0)
                self.clock.now = 2
                runner.advance(2)
                self.assertTrue(runner.finished)
                self.assertEqual(runner.failures, 1)
                self.assertEqual(len(performed), 1, "unbound proof must not type ver")
                self.assertEqual(len(captured), 1)
                self.assertFalse(runner.checkpoints["start-menu"].passed)

    def test_readiness_backoff_never_exceeds_eight_seconds(self):
        script = parse_script({"screen": [1024, 768], "settle_seconds": 0,
                               "steps": [{"name": "start-menu", "actions": [],
                                          "wait_seconds": 60,
                                          "readiness_poll_seconds": 2}]})
        runner = InteractionRunner(
            script, self.performed.append, self.captured.append, self.log, self.clock,
            checks={"start-menu": lambda name: VisualProof(
                False, error="not visible", image_name=name, image_sha256="sha")})
        runner.arm(0)
        runner.advance(0)
        for second in (2, 4, 8, 16, 24):
            self.clock.now = second
            runner.advance(second)
        self.assertEqual(len(self.captured), 5)

    def test_polled_step_without_visual_check_never_sends_input(self):
        script = parse_script({"screen": [1024, 768], "settle_seconds": 0,
                               "steps": [{"name": "start-menu",
                                          "actions": [{"click": [28, 743]}],
                                          "wait_seconds": 60,
                                          "readiness_poll_seconds": 2}]})
        runner = InteractionRunner(script, self.performed.append, self.captured.append,
                                   self.log, self.clock)
        runner.arm(0)
        runner.advance(0)
        self.assertTrue(runner.finished)
        self.assertEqual(runner.failures, 1)
        self.assertEqual(self.performed, [])
        self.assertEqual(self.captured, [])

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

    def test_input_and_capture_errors_are_recorded_without_more_input(self):
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
        self.assertEqual(runner.failures, 2)  # baseline screenshot, then first input
        entries = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual([entry["event"] for entry in entries].count("error"), 2)
        self.assertIn("refused", entries[-1]["error"])

    def test_missing_ready_prompt_halts_before_typing_ver_and_retains_proof(self):
        script = parse_script({"screen": [1024, 768], "settle_seconds": 0,
                               "steps": [
                                   {"name": "command-prompt", "actions": [{"type": "cmd\n"}],
                                    "wait_seconds": 0},
                                   {"name": "ver", "actions": [{"type": "ver\n"}],
                                    "wait_seconds": 0}]})
        proof = VisualProof(False, "APPLAUNCH_DONE\n", "ready Command Prompt not visible",
                            "native-kvm-interact-01-command-prompt.ppm", "recorded-image-sha")
        runner = InteractionRunner(script, self.performed.append, self.captured.append,
                                   self.log, self.clock,
                                   checks={"command-prompt": lambda _name: proof})
        runner.arm(0)
        runner.advance(0)
        self.assertTrue(runner.finished)
        self.assertEqual(runner.index, 0, "a failed visual step is not completed")
        self.assertEqual(len(self.performed), 1)
        self.assertEqual(runner.failures, 1)
        self.assertEqual(runner.checkpoints["command-prompt"], proof)
        entries = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual(entries[-1]["image_sha256"], "recorded-image-sha")
        self.assertEqual(entries[-1]["event"], "checkpoint")

    def test_verified_click_corrects_recorded_boot2_drift_before_press(self):
        script = parse_script({"screen": [1024, 768], "settle_seconds": 0,
                               "steps": [
                                   {"name": "baseline", "actions": [], "wait_seconds": 0},
                                   {"name": "command-prompt", "actions": [
                                       {"verified_click": [37, 470]}],
                                    "wait_seconds": 0}]})
        positions = iter(((37, 446), (37, 458), (37, 470)))
        def probe(_before, after, _target):
            return CursorProof(next(positions), after, "recorded-image-sha")
        runner = InteractionRunner(script, self.performed.append, self.captured.append,
                                   self.log, self.clock, cursor_probe=probe)
        runner.arm(0)
        runner.advance(0)
        self.assertTrue(runner.finished)
        self.assertEqual(runner.failures, 0)
        self.assertEqual(len(self.performed), 4)  # aim, two measured corrections, then click
        self.assertEqual([rel_sum(batches) for batches in self.performed[1:3]],
                         [(0, 12), (0, 12)])
        self.assertEqual([events[0]["data"]["down"]
                          for events, _pause in self.performed[3]],
                         [True, False])
        self.assertGreaterEqual(self.performed[3][0][1], 0.15)
        self.assertEqual([receipt["position"] for receipt in runner.cursor_receipts],
                         [[37, 446], [37, 458], [37, 470]])

    def test_verified_click_retries_one_pixel_opposite_drift_without_early_press(self):
        # KVM run 46141984183: the first correction from (957,78) toward
        # (925,100) left x unchanged and measured y one pixel higher. A single
        # noisy frame must not abort the bounded proof or authorize a click.
        target = (925, 100)
        measured = [(957, 78), (957, 77), (945, 85),
                    (933, 94), target]
        positions = iter(measured)
        script = parse_script({"screen": [1024, 768], "settle_seconds": 0,
                               "steps": [
                                   {"name": "baseline", "actions": [], "wait_seconds": 0},
                                   {"name": "desktop-pointer", "actions": [
                                       {"verified_click": list(target)}], "wait_seconds": 0}]})
        runner = InteractionRunner(
            script, self.performed.append, self.captured.append, self.log,
            self.clock,
            cursor_probe=lambda _before, after, _target:
                CursorProof(next(positions), after, "recorded-image-sha"))
        runner.arm(0)
        runner.advance(0)
        self.assertEqual(runner.failures, 0)
        self.assertEqual([receipt["position"] for receipt in runner.cursor_receipts],
                         [list(position) for position in measured])
        self.assertEqual(len(self.performed), len(measured) + 1)
        self.assertTrue(all(not any(event["type"] == "btn"
                                    for events, _pause in batches for event in events)
                            for batches in self.performed[:-1]))
        self.assertEqual([events[0]["data"]["down"]
                          for events, _pause in self.performed[-1]], [True, False])

    def test_verified_click_rejects_material_opposite_motion_without_press(self):
        target = (925, 100)
        positions = iter(((957, 78), (961, 74)))
        script = parse_script({"screen": [1024, 768], "settle_seconds": 0,
                               "steps": [
                                   {"name": "baseline", "actions": [], "wait_seconds": 0},
                                   {"name": "desktop-pointer", "actions": [
                                       {"verified_click": list(target)}], "wait_seconds": 0}]})
        runner = InteractionRunner(
            script, self.performed.append, self.captured.append, self.log,
            self.clock,
            cursor_probe=lambda _before, after, _target:
                CursorProof(next(positions), after, "recorded-image-sha"))
        runner.arm(0)
        runner.advance(0)
        self.assertEqual(runner.failures, 1)
        self.assertEqual(len(runner.cursor_receipts), 2)
        self.assertEqual(len(self.performed), 2)
        self.assertIn("opposite the correction", self.log.read_text())

    def test_verified_click_converges_with_measured_threefold_guest_acceleration(self):
        # Run 46031955425: a measured (889,126) hotspot moved to (1001,46)
        # when the runner requested (+36,-26). Every correction must be small
        # and based on a new measurement before a button event can be sent.
        target = (925, 100)
        script = parse_script({"screen": [1024, 768], "settle_seconds": 0,
                               "steps": [
                                   {"name": "baseline", "actions": [], "wait_seconds": 0},
                                   {"name": "desktop-pointer", "actions": [
                                       {"verified_click": list(target)}], "wait_seconds": 0}]})
        position = [889, 126]
        calls = []

        def perform(batches):
            calls.append(batches)
            if len(calls) == 1:  # initial corner pin and target aim
                return
            dx, dy = rel_sum(batches)
            if (dx, dy) != (0, 0):
                position[0] += 3 * dx
                position[1] += 3 * dy

        def probe(_before, after, _target):
            return CursorProof(tuple(position), after, "captured-frame-sha")

        runner = InteractionRunner(script, perform, self.captured.append, self.log,
                                   self.clock, cursor_probe=probe)
        runner.arm(0)
        runner.advance(0)
        self.assertEqual(runner.failures, 0)
        self.assertLessEqual(len(runner.cursor_receipts), 6)
        self.assertTrue(cursor_is_at_target(tuple(position), target))
        corrections = calls[1:-1]
        self.assertGreaterEqual(len(corrections), 1)
        self.assertTrue(all(max(map(abs, rel_sum(batches))) <= 12
                            for batches in corrections))
        self.assertEqual([events[0]["data"]["down"]
                          for events, _pause in calls[-1]], [True, False])
        self.assertTrue(all(not any(event["type"] == "btn"
                                    for events, _pause in batches for event in events)
                            for batches in calls[:-1]))
        self.assertTrue(cursor_is_at_target(tuple(runner.cursor_receipts[-1]["position"]),
                                            target))

    def test_verified_click_waits_for_seventh_measured_frame_after_initial_overshoot(self):
        # A live FileBasic boot measured these six hotspots while aiming at neutral wallpaper.
        # The sixth remains outside the strict three-pixel margin, but a final bounded
        # correction can reach the target. No button may precede that seventh receipt.
        target = (925, 100)
        measured = [(881, 132), (973, 65), (967, 70),
                    (955, 79), (943, 87), (931, 96), target]
        positions = iter(measured)
        script = parse_script({"screen": [1024, 768], "settle_seconds": 0,
                               "steps": [
                                   {"name": "baseline", "actions": [], "wait_seconds": 0},
                                   {"name": "desktop-pointer", "actions": [
                                       {"verified_click": list(target)}], "wait_seconds": 0}]})

        def probe(_before, after, _target):
            return CursorProof(next(positions), after, "recorded-image-sha")

        runner = InteractionRunner(script, self.performed.append, self.captured.append,
                                   self.log, self.clock, cursor_probe=probe)
        runner.arm(0)
        runner.advance(0)
        self.assertEqual(runner.failures, 0)
        self.assertEqual([receipt["position"] for receipt in runner.cursor_receipts],
                         [list(position) for position in measured])
        self.assertEqual(len(self.performed), 8)  # aim, six corrections, proven click
        self.assertEqual(rel_sum(self.performed[-2]), (-6, 4))
        self.assertTrue(all(not any(event["type"] == "btn"
                                    for events, _pause in batches for event in events)
                            for batches in self.performed[:-1]))
        self.assertEqual([events[0]["data"]["down"]
                          for events, _pause in self.performed[-1]],
                         [True, False])

    def test_unmeasured_cursor_halts_without_click(self):
        script = parse_script({"screen": [1024, 768], "settle_seconds": 0,
                               "steps": [
                                   {"name": "baseline", "actions": [], "wait_seconds": 0},
                                   {"name": "command-prompt", "actions": [
                                       {"verified_click": [37, 470]}],
                                    "wait_seconds": 0}]})
        runner = InteractionRunner(
            script, self.performed.append, self.captured.append, self.log, self.clock,
            cursor_probe=lambda _before, after, _target: CursorProof(None, after, "sha"))
        runner.arm(0)
        runner.advance(0)
        self.assertTrue(runner.finished)
        self.assertEqual(runner.failures, 1)
        self.assertEqual(len(self.performed), 1)  # aim only; no button packet

    def test_bounded_correction_never_clicks_when_cursor_stays_off_target(self):
        script = parse_script({"screen": [1024, 768], "settle_seconds": 0,
                               "steps": [
                                   {"name": "baseline", "actions": [], "wait_seconds": 0},
                                   {"name": "command-prompt", "actions": [
                                       {"verified_click": [37, 470]}],
                                    "wait_seconds": 0}]})
        runner = InteractionRunner(
            script, self.performed.append, self.captured.append, self.log, self.clock,
            cursor_probe=lambda _before, after, _target: CursorProof((37, 446), after, "sha"))
        runner.arm(0)
        runner.advance(0)
        self.assertTrue(runner.finished)
        self.assertEqual(runner.failures, 1)
        self.assertEqual(len(runner.cursor_receipts), 7)
        self.assertEqual(len(self.performed), 7)  # initial aim and six corrections, no click

    def test_missing_search_result_halts_before_enter(self):
        script = parse_script({"screen": [1024, 768], "settle_seconds": 0,
                               "steps": [
                                   {"name": "baseline", "actions": [], "wait_seconds": 0},
                                   {"name": "command-prompt-search", "actions": [
                                       {"type": "command"}], "wait_seconds": 0},
                                   {"name": "command-prompt", "actions": [
                                       {"key": ["ret"]}], "wait_seconds": 0}]})
        proof = VisualProof(False, error="Command Prompt search result not visible",
                            image_name="search.ppm", image_sha256="recorded-sha")
        runner = InteractionRunner(
            script, self.performed.append, self.captured.append, self.log, self.clock,
            checks={"command-prompt-search": lambda _name: proof})
        runner.arm(0)
        runner.advance(0)
        self.assertTrue(runner.finished)
        self.assertEqual(runner.failures, 1)
        self.assertEqual(len(self.performed), 1)  # query, never Enter
        self.assertFalse(any(event["type"] == "key"
                             and event["data"]["key"]["data"] == "ret"
                             and event["data"]["down"]
                             for batch in self.performed for events, _pause in batch
                             for event in events))
        self.assertEqual(runner.checkpoints["command-prompt-search"], proof)

    def test_visible_search_result_sends_enter_before_ready_prompt_checkpoint(self):
        script = parse_script({"screen": [1024, 768], "settle_seconds": 0,
                               "steps": [
                                   {"name": "baseline", "actions": [], "wait_seconds": 0},
                                   {"name": "command-prompt-search", "actions": [
                                       {"type": "command"}], "wait_seconds": 0},
                                   {"name": "command-prompt", "actions": [
                                       {"key": ["ret"]}], "wait_seconds": 0}]})
        selected = VisualProof(True, image_name="search.ppm", image_sha256="search-sha")
        ready = VisualProof(True, image_name="prompt.ppm", image_sha256="prompt-sha")
        runner = InteractionRunner(
            script, self.performed.append, self.captured.append, self.log, self.clock,
            checks={"command-prompt-search": lambda _name: selected,
                    "command-prompt": lambda _name: ready})
        runner.arm(0)
        runner.advance(0)
        self.assertTrue(runner.finished)
        self.assertEqual(runner.failures, 0)
        self.assertEqual(keys(self.performed[1]), [("ret", True), ("ret", False)])
        entries = [json.loads(line) for line in self.log.read_text().splitlines()]
        selected_index = next(i for i, entry in enumerate(entries)
                              if entry["event"] == "checkpoint"
                              and entry["name"] == "command-prompt-search")
        enter_index = next(i for i, entry in enumerate(entries)
                           if entry["event"] == "action"
                           and entry["name"] == "command-prompt")
        ready_index = next(i for i, entry in enumerate(entries)
                           if entry["event"] == "checkpoint"
                           and entry["name"] == "command-prompt")
        self.assertLess(selected_index, enter_index)
        self.assertLess(enter_index, ready_index)
        self.assertEqual(list(runner.checkpoints), ["command-prompt-search", "command-prompt"])

    def test_seal_detector_finds_the_desktop_record(self):
        path = Path(self.directory.name) / "serial.log"
        path.write_bytes(b"[quiesce] Explorer runtime paint milestones complete; boot-progress "
                         b"epoch sealed\r\n")
        self.assertIsNotNone(SerialPanicDetector(path, DESKTOP_EPOCH_SEALED_RECORD).poll())


if __name__ == "__main__":
    unittest.main()
