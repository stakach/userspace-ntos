"""Scripted guest input for the KVM runner: parse a step list and drive it through QMP.

The q35 machine exposes only the i8042 PS/2 keyboard and mouse, which the guest drives
through i8042prt + kbdclass/mouclass. A PS/2 mouse is relative-only, so a pointer target
is reached by first pinning the cursor against the bottom-left corner of the screen and
then moving by small relative deltas from that known position. win32k adds relative
deltas 1:1, but small paced packets keep the path exact even if a guest layer
accelerates or coalesces larger ones.

Interaction is evidence, never a verdict: failures are recorded, not raised.
"""

from dataclasses import dataclass, replace
import json
from pathlib import Path
import re
import time

try:
    from .ci_kvm_cursor import cursor_is_at_target
except ImportError:
    from ci_kvm_cursor import cursor_is_at_target


DEFAULT_SCRIPT = Path(__file__).with_name("kvm_interaction_steps.json")
STEP_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,39}")
QCODE = re.compile(r"[a-z0-9_]{1,20}")
POINTER_STEP = 4  # pixels per relative packet while aiming
PIN_STEP = 64  # pixels per relative packet while pinning; overshoot clamps at the edge
MOVE_PAUSE = 0.04  # slow enough that the guest never merges packets into accelerated moves
BUTTON_PAUSE = 0.06  # four of these stay well inside the 500 ms double-click time
POINTER_SETTLE = 0.3  # let the guest drain queued motion before a button changes state
CLICK_HOLD = 0.15  # a lone click holds long enough for the guest to read the press
KEY_PAUSE = 0.05
POINTER_ACTIONS = ("move", "click", "double_click")
VERIFIED_POINTER_ACTION = "verified_click"
MAX_CURSOR_AIMS = 3
CHAR_QCODES = {" ": "spc", "\n": "ret", "\t": "tab", ".": "dot", ",": "comma",
               "-": "minus", "=": "equal", "/": "slash", "\\": "backslash",
               ";": "semicolon", "'": "apostrophe"}
SHIFTED_CHAR_QCODES = {":": "semicolon", "_": "minus", "+": "equal", "?": "slash",
                       ">": "dot",
                       '"': "apostrophe", "|": "backslash"}


@dataclass(frozen=True)
class Step:
    name: str
    actions: tuple
    wait_seconds: float
    readiness_poll_seconds: float | None = None


@dataclass(frozen=True)
class Script:
    screen: tuple
    settle_seconds: float
    steps: tuple
    # "seal" starts on the desktop seal; "idle" waits until the sealed guest first goes idle,
    # which is after Explorer's RunOnce work and its desktop window exist.
    arm: str = "seal"


ARM_MODES = ("seal", "idle")


def _seconds(value, field):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 600:
        raise ValueError(f"{field} must be a number of seconds from 0 to 600")
    return float(value)


def _point(value, screen, field):
    if (not isinstance(value, list) or len(value) != 2
            or any(isinstance(axis, bool) or not isinstance(axis, int) for axis in value)
            or not (0 <= value[0] < screen[0] and 0 <= value[1] < screen[1])):
        raise ValueError(f"{field} must be an on-screen [x, y] pixel")
    return tuple(value)


def text_chords(text):
    """Translate text to the qcode chords a US keyboard layout types it with."""
    chords = []
    for char in text:
        if "a" <= char <= "z" or "0" <= char <= "9":
            chords.append((char,))
        elif "A" <= char <= "Z":
            chords.append(("shift", char.lower()))
        elif char in CHAR_QCODES:
            chords.append((CHAR_QCODES[char],))
        elif char in SHIFTED_CHAR_QCODES:
            chords.append(("shift", SHIFTED_CHAR_QCODES[char]))
        else:
            raise ValueError(f"no key mapping for character {char!r}")
    return tuple(chords)


def _action(value, screen, field):
    if not isinstance(value, dict) or len(value) != 1:
        raise ValueError(f"{field} must be an object with exactly one action")
    (kind, argument), = value.items()
    if kind in (*POINTER_ACTIONS, VERIFIED_POINTER_ACTION):
        return kind, _point(argument, screen, f"{field}.{kind}")
    if kind == "key":
        if (not isinstance(argument, list) or not argument
                or not all(isinstance(code, str) and QCODE.fullmatch(code) for code in argument)):
            raise ValueError(f"{field}.key must be a non-empty list of QEMU qcodes")
        return kind, tuple(argument)
    if kind == "type":
        if not isinstance(argument, str) or not argument:
            raise ValueError(f"{field}.type must be non-empty text")
        text_chords(argument)
        return kind, argument
    raise ValueError(f"{field} has unknown action {kind!r}")


def parse_script(document):
    """Validate a step document completely before the guest boots."""
    if (not isinstance(document, dict)
            or set(document) - {"screen", "settle_seconds", "steps", "arm"}):
        raise ValueError("script must be an object with screen, settle_seconds, steps and arm")
    arm = document.get("arm", "seal")
    if arm not in ARM_MODES:
        raise ValueError(f"arm must be one of {', '.join(ARM_MODES)}")
    screen = document.get("screen")
    if (not isinstance(screen, list) or len(screen) != 2
            or any(isinstance(axis, bool) or not isinstance(axis, int) or not 1 <= axis <= 8192
                   for axis in screen)):
        raise ValueError("screen must be [width, height] in pixels")
    screen = tuple(screen)
    settle = _seconds(document.get("settle_seconds"), "settle_seconds")
    raw_steps = document.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        raise ValueError("steps must be a non-empty list")
    steps, names = [], set()
    for index, raw in enumerate(raw_steps, 1):
        field = f"steps[{index}]"
        if not isinstance(raw, dict) or set(raw) - {"name", "actions", "wait_seconds",
                                                    "readiness_poll_seconds"}:
            raise ValueError(f"{field} must be an object with name, actions and wait_seconds")
        name = raw.get("name")
        if not isinstance(name, str) or not STEP_NAME.fullmatch(name) or name in names:
            raise ValueError(f"{field}.name must be a unique lowercase-hyphenated name")
        names.add(name)
        actions = raw.get("actions")
        if not isinstance(actions, list):
            raise ValueError(f"{field}.actions must be a list")
        parsed_actions = tuple(_action(action, screen, f"{field}.actions[{number}]")
                               for number, action in enumerate(actions, 1))
        wait = _seconds(raw.get("wait_seconds"), f"{field}.wait_seconds")
        poll = None
        if "readiness_poll_seconds" in raw:
            poll = _seconds(raw["readiness_poll_seconds"],
                            f"{field}.readiness_poll_seconds")
            if not 1 <= poll <= wait:
                raise ValueError(f"{field}.readiness_poll_seconds must be >= 1 and <= wait_seconds")
        steps.append(Step(name, parsed_actions, wait, poll))
    return Script(screen, settle, tuple(steps), arm)


def load_script(path):
    return parse_script(json.loads(Path(path).read_text()))


def relative_deltas(dx, dy, max_step):
    """Split a move into packets no larger than max_step on either axis, summing exactly."""
    count = max(1, -(-max(abs(dx), abs(dy)) // max_step))
    deltas, sent_x, sent_y = [], 0, 0
    for index in range(1, count + 1):
        x, y = round(dx * index / count), round(dy * index / count)
        if x != sent_x or y != sent_y:
            deltas.append((x - sent_x, y - sent_y))
        sent_x, sent_y = x, y
    return deltas


def _rel(dx, dy):
    events = [{"type": "rel", "data": {"axis": "x", "value": dx}}] if dx else []
    if dy:
        events.append({"type": "rel", "data": {"axis": "y", "value": dy}})
    return events


def _button(down):
    return [{"type": "btn", "data": {"down": down, "button": "left"}}]


def _key(code, down):
    return {"type": "key", "data": {"down": down, "key": {"type": "qcode", "data": code}}}


def pointer_batches(point, screen):
    """Pin the cursor at (0, height-1), then aim at point with small relative packets."""
    width, height = screen
    batches = [(_rel(dx, dy), MOVE_PAUSE)
               for dx, dy in relative_deltas(-2 * width, 2 * height, PIN_STEP)]
    batches += [(_rel(dx, dy), MOVE_PAUSE)
                for dx, dy in relative_deltas(point[0], point[1] - (height - 1), POINTER_STEP)]
    return batches


def chord_batches(codes):
    """Press a chord in order and release it in reverse."""
    return ([([_key(code, True)], KEY_PAUSE) for code in codes]
            + [([_key(code, False)], KEY_PAUSE) for code in reversed(codes)])


def action_batches(action, screen):
    """Expand one parsed action into (QMP input events, pause seconds) batches."""
    kind, argument = action
    if kind == VERIFIED_POINTER_ACTION:
        raise ValueError("verified click needs a framebuffer checkpoint")
    if kind in POINTER_ACTIONS:
        batches = pointer_batches(argument, screen)
        clicks = {"move": 0, "click": 1, "double_click": 2}[kind]
        if clicks and batches:
            # QEMU's PS/2 mouse merges unread packets, keeping only the latest button
            # state, so a press sent behind undrained motion can be lost.
            events, _pause = batches[-1]
            batches[-1] = (events, POINTER_SETTLE)
        hold = CLICK_HOLD if clicks == 1 else BUTTON_PAUSE
        for _ in range(clicks):
            batches += [(_button(True), hold), (_button(False), BUTTON_PAUSE)]
        return batches
    if kind == "key":
        return chord_batches(argument)
    return [batch for chord in text_chords(argument) for batch in chord_batches(chord)]


def relative_pointer_batches(dx, dy):
    """Correct a measured guest cursor without resetting it to an assumed origin."""
    batches = [(_rel(x, y), MOVE_PAUSE)
               for x, y in relative_deltas(dx, dy, POINTER_STEP)]
    if batches:
        events, _pause = batches[-1]
        batches[-1] = events, POINTER_SETTLE
    return batches


def held_click_batches():
    return [(_button(True), CLICK_HOLD), (_button(False), BUTTON_PAUSE)]


def screenshot_name(index, step):
    return f"native-kvm-interact-{index:02d}-{step.name}.ppm"


class InteractionRunner:
    """Advance a script from the boot loop without blocking it across step waits.

    perform(batches) sends input over QMP; capture(name) writes a framebuffer file.
    While the runner is in progress the boot loop holds its idle stop, so a guest that
    is quiet between steps is not classified stationary before the script finishes.
    """

    def __init__(self, script, perform, capture, log_path, clock=time.monotonic,
                 checks=None, cursor_probe=None):
        self.script = script
        self.perform = perform
        self.capture = capture
        self.log_path = Path(log_path)
        self.clock = clock
        self.armed_at = None
        self.index = 0
        self.acted = False
        self.next_at = None
        self.step_started_at = None
        self.step_deadline = None
        self.poll_attempt = 0
        self.failures = 0
        self.checks = checks or {}
        self.checkpoints = {}
        self.cursor_probe = cursor_probe
        self.cursor_receipts = []
        self.last_capture = None
        self.halted = False

    @property
    def armed(self):
        return self.armed_at is not None

    @property
    def finished(self):
        return self.halted or self.index >= len(self.script.steps)

    @property
    def in_progress(self):
        return self.armed and not self.finished

    def arm(self, now):
        if not self.armed:
            self.armed_at = now
            self.next_at = now + self.script.settle_seconds
            self._record({"event": "armed", "settle_seconds": self.script.settle_seconds})

    def advance(self, now):
        """Run every phase that is due; return the names of screenshots attempted."""
        shots = []
        while self.in_progress and now >= self.next_at:
            step = self.script.steps[self.index]
            if not self.acted:
                if (step.readiness_poll_seconds is not None
                        and step.name not in self.checks):
                    self._fail(step, "readiness", RuntimeError("polled step has no visual check"))
                    self.halted = True
                    break
                prior_failures = self.failures
                self._act(step)
                if self.halted or (step.readiness_poll_seconds is not None
                                   and self.failures != prior_failures):
                    self.halted = True
                    break
                self.acted = True
                self.step_started_at = self.clock()
                self.step_deadline = self.step_started_at + step.wait_seconds
                self.poll_attempt = 0
                self.next_at = (self.step_started_at + step.readiness_poll_seconds
                                if step.readiness_poll_seconds is not None
                                else self.step_deadline)
                now = self.clock()
                continue
            polling = step.readiness_poll_seconds is not None
            if polling and self.clock() > self.step_deadline:
                self._fail(step, "readiness", RuntimeError("visual readiness deadline expired"))
                self.halted = True
                break
            if polling:
                self.poll_attempt += 1
            name = screenshot_name(self.index + 1, step)
            if polling:
                name = name.removesuffix(".ppm") + f"-probe-{self.poll_attempt:02d}.ppm"
            shots.append(name)
            captured = False
            try:
                self.capture(name)
                captured = True
                self.last_capture = name
                self._record({"event": "screenshot", "step": self.index + 1,
                              "name": step.name, "file": name})
            except (OSError, RuntimeError, ValueError, KeyError) as error:
                self.last_capture = None
                self._fail(step, "screenshot", error)
            if step.name in self.checks:
                if not captured:
                    self.halted = True
                else:
                    try:
                        proof = self.checks[step.name](name)
                        completed_at = self.clock()
                        if (polling and proof.passed
                                and (proof.image_name != name or not proof.image_sha256.strip())):
                            proof = replace(proof, passed=False, fatal=True,
                                            error="visual readiness proof does not identify the captured frame")
                        if polling and completed_at > self.step_deadline:
                            proof = replace(proof, passed=False,
                                            error="visual readiness proof completed after deadline")
                        self.checkpoints[step.name] = proof
                        receipt = {"event": "checkpoint", "step": self.index + 1,
                                   "name": step.name, "passed": proof.passed,
                                   "error": proof.error, "ocr_text": proof.ocr_text,
                                   "image_sha256": proof.image_sha256}
                        if polling:
                            receipt.update(attempt=self.poll_attempt,
                                           ready_after_seconds=round(
                                               completed_at - self.step_started_at, 2),
                                           file=name)
                        self._record(receipt)
                        if not proof.passed:
                            if (not polling or proof.fatal
                                    or completed_at >= self.step_deadline):
                                self.failures += 1
                                self.halted = True
                            else:
                                interval = min(8, step.readiness_poll_seconds
                                               * 2 ** (self.poll_attempt - 1))
                                self.next_at = min(self.step_deadline, completed_at + interval)
                                now = completed_at
                                continue
                    except (OSError, RuntimeError, ValueError, KeyError) as error:
                        self._fail(step, "checkpoint", error)
                        self.halted = True
            self.index += 1
            self.acted = False
            now = self.clock()
            self.next_at = now
        return shots

    def _act(self, step):
        for number, action in enumerate(step.actions, 1):
            try:
                if action[0] == VERIFIED_POINTER_ACTION:
                    self._verified_click(step, action[1])
                    if self.halted:
                        return
                    self._record({"event": "action", "step": self.index + 1,
                                  "name": step.name, "action": number,
                                  "kind": action[0], "argument": list(action[1])})
                    continue
                self.perform(action_batches(action, self.script.screen))
                self._record({"event": "action", "step": self.index + 1, "name": step.name,
                              "action": number, "kind": action[0],
                              "argument": list(action[1]) if action[0] != "type" else action[1]})
            except (OSError, RuntimeError, ValueError, KeyError) as error:
                self._fail(step, f"action {number} {action[0]}", error)
                if (action[0] == VERIFIED_POINTER_ACTION
                        or step.readiness_poll_seconds is not None):
                    self.halted = True
                    return

    def _verified_click(self, step, target):
        if self.last_capture is None or self.cursor_probe is None:
            raise RuntimeError("verified click requires a prior framebuffer and cursor probe")
        self.perform(pointer_batches(target, self.script.screen))
        for attempt in range(1, MAX_CURSOR_AIMS + 1):
            name = screenshot_name(self.index + 1, step).removesuffix(".ppm")
            name += f"-aim-{attempt}.ppm"
            self.capture(name)
            proof = self.cursor_probe(self.last_capture, name, target)
            receipt = {"event": "cursor-aim", "step": self.index + 1,
                       "attempt": attempt, "target": list(target),
                       "position": list(proof.position) if proof.position else None,
                       "file": proof.image_name, "image_sha256": proof.image_sha256}
            self.cursor_receipts.append(receipt)
            self._record(receipt)
            if cursor_is_at_target(proof.position, target):
                self.perform(held_click_batches())
                return
            if proof.position is None:
                raise RuntimeError("guest cursor not measurable near target")
            if attempt < MAX_CURSOR_AIMS:
                self.perform(relative_pointer_batches(target[0] - proof.position[0],
                                                     target[1] - proof.position[1]))
        raise RuntimeError("guest cursor missed target after bounded correction")

    def _fail(self, step, what, error):
        self.failures += 1
        self._record({"event": "error", "step": self.index + 1, "name": step.name,
                      "what": what, "error": str(error)})

    def summary(self):
        return (f"{self.index}/{len(self.script.steps)} interaction steps completed, "
                f"{self.failures} input/capture/checkpoint errors")

    def _record(self, entry):
        entry = {"elapsed_seconds": round(self.clock() - (self.armed_at or 0), 2), **entry}
        try:
            with self.log_path.open("a") as log:
                log.write(json.dumps(entry) + "\n")
        except OSError:
            pass
