"""Scripted guest input for the KVM runner: parse a step list and drive it through QMP.

The q35 machine exposes only the i8042 PS/2 keyboard and mouse, which the guest drives
through i8042prt + kbdclass/mouclass. A PS/2 mouse is relative-only, so a pointer target
is reached by first pinning the cursor against the bottom-left corner of the screen and
then moving by small relative deltas from that known position. win32k adds relative
deltas 1:1, but small paced packets keep the path exact even if a guest layer
accelerates or coalesces larger ones.

Interaction is evidence, never a verdict: failures are recorded, not raised.
"""

from dataclasses import dataclass
import json
from pathlib import Path
import re
import time


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
CHAR_QCODES = {" ": "spc", "\n": "ret", "\t": "tab", ".": "dot", ",": "comma",
               "-": "minus", "=": "equal", "/": "slash", "\\": "backslash",
               ";": "semicolon", "'": "apostrophe"}
SHIFTED_CHAR_QCODES = {":": "semicolon", "_": "minus", "+": "equal", "?": "slash",
                       '"': "apostrophe", "|": "backslash"}


@dataclass(frozen=True)
class Step:
    name: str
    actions: tuple
    wait_seconds: float


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
    if kind in POINTER_ACTIONS:
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
        if not isinstance(raw, dict) or set(raw) - {"name", "actions", "wait_seconds"}:
            raise ValueError(f"{field} must be an object with name, actions and wait_seconds")
        name = raw.get("name")
        if not isinstance(name, str) or not STEP_NAME.fullmatch(name) or name in names:
            raise ValueError(f"{field}.name must be a unique lowercase-hyphenated name")
        names.add(name)
        actions = raw.get("actions")
        if not isinstance(actions, list):
            raise ValueError(f"{field}.actions must be a list")
        steps.append(Step(name, tuple(_action(action, screen, f"{field}.actions[{number}]")
                                      for number, action in enumerate(actions, 1)),
                          _seconds(raw.get("wait_seconds"), f"{field}.wait_seconds")))
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


def screenshot_name(index, step):
    return f"native-kvm-interact-{index:02d}-{step.name}.ppm"


class InteractionRunner:
    """Advance a script from the boot loop without blocking it across step waits.

    perform(batches) sends input over QMP; capture(name) writes a framebuffer file.
    While the runner is in progress the boot loop holds its idle stop, so a guest that
    is quiet between steps is not classified stationary before the script finishes.
    """

    def __init__(self, script, perform, capture, log_path, clock=time.monotonic):
        self.script = script
        self.perform = perform
        self.capture = capture
        self.log_path = Path(log_path)
        self.clock = clock
        self.armed_at = None
        self.index = 0
        self.acted = False
        self.next_at = None
        self.failures = 0

    @property
    def armed(self):
        return self.armed_at is not None

    @property
    def finished(self):
        return self.index >= len(self.script.steps)

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
                self._act(step)
                self.acted = True
                self.next_at = self.clock() + step.wait_seconds
                now = self.clock()
                continue
            name = screenshot_name(self.index + 1, step)
            shots.append(name)
            try:
                self.capture(name)
                self._record({"event": "screenshot", "step": self.index + 1,
                              "name": step.name, "file": name})
            except (OSError, RuntimeError, ValueError, KeyError) as error:
                self._fail(step, "screenshot", error)
            self.index += 1
            self.acted = False
            now = self.clock()
            self.next_at = now
        return shots

    def _act(self, step):
        for number, action in enumerate(step.actions, 1):
            try:
                self.perform(action_batches(action, self.script.screen))
                self._record({"event": "action", "step": self.index + 1, "name": step.name,
                              "action": number, "kind": action[0],
                              "argument": list(action[1]) if action[0] != "type" else action[1]})
            except (OSError, RuntimeError, ValueError, KeyError) as error:
                self._fail(step, f"action {number} {action[0]}", error)

    def _fail(self, step, what, error):
        self.failures += 1
        self._record({"event": "error", "step": self.index + 1, "name": step.name,
                      "what": what, "error": str(error)})

    def summary(self):
        return (f"{self.index}/{len(self.script.steps)} interaction steps completed, "
                f"{self.failures} input/capture errors")

    def _record(self, entry):
        entry = {"elapsed_seconds": round(self.clock() - (self.armed_at or 0), 2), **entry}
        try:
            with self.log_path.open("a") as log:
                log.write(json.dumps(entry) + "\n")
        except OSError:
            pass
