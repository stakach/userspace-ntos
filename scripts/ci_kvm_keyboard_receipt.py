"""Bounded guest confirmation for QMP PS/2 keyboard events.

QMP acknowledges queueing an event, not delivery to the guest. The hosted IRQ
broker's class record is the first authenticated receipt for each scan code.
Do not send another key until that receipt arrives, and never retry an event
whose effect is uncertain.
"""

from pathlib import Path
import re
import time


# Set 1 make codes reported in KEYBOARD_INPUT_DATA by ReactOS i8042prt.
# Only qcodes emitted by the maintained desktop scripts are admitted.
SCAN_CODES = {
    "a": 0x1e, "b": 0x30, "c": 0x2e, "d": 0x20, "e": 0x12,
    "f": 0x21, "h": 0x23, "i": 0x17, "k": 0x25, "l": 0x26,
    "m": 0x32, "n": 0x31, "o": 0x18, "p": 0x19, "r": 0x13,
    "s": 0x1f, "t": 0x14, "u": 0x16, "v": 0x2f, "x": 0x2d,
    "dot": 0x34, "equal": 0x0d, "minus": 0x0c, "slash": 0x35,
    "spc": 0x39, "ret": 0x1c, "shift": 0x2a,
}
CLASS_RECORD = re.compile(
    rb"\[kbd-class-record\] sequence=(\d+) code=(?:0x)+([0-9a-fA-F]+) "
    rb"flags=(?:0x)+([0-9a-fA-F]+) index=(\d+) batch=(\d+) consumed=(\d+)"
)


class KeyboardClassReceipt:
    """Follow the serial tail from before the first QMP event in one action."""

    def __init__(self, path, clock=time.monotonic, sleep=time.sleep):
        self.path = Path(path)
        self.offset = self.path.stat().st_size
        self.clock = clock
        self.sleep = sleep
        self.partial = b""
        self.last_sequence = None

    @staticmethod
    def expected(event):
        data = event["data"]
        qcode = data["key"]["data"]
        code = SCAN_CODES.get(qcode)
        if code is None:
            raise RuntimeError(f"keyboard qcode {qcode!r} has no class receipt mapping")
        flags = 0 if data["down"] else 1
        label = f"{qcode} {'make' if data['down'] else 'break'} (0x{code:02x}/{flags})"
        return code, flags, label

    def wait_for(self, event, timeout):
        code, flags, expected = self.expected(event)
        deadline = self.clock() + timeout
        while True:
            with self.path.open("rb") as serial:
                serial.seek(self.offset)
                chunk = serial.read(65536)
            self.offset += len(chunk)
            self.partial += chunk
            while b"\n" in self.partial:
                line, self.partial = self.partial.split(b"\n", 1)
                match = CLASS_RECORD.search(line)
                if match is None:
                    continue
                sequence, actual_code, actual_flags, index, batch, consumed = (
                    int(match.group(1)), int(match.group(2), 16),
                    int(match.group(3), 16), int(match.group(4)),
                    int(match.group(5)), int(match.group(6)))
                if (self.last_sequence is not None and sequence <= self.last_sequence) or (
                        index >= batch or index >= consumed):
                    raise RuntimeError(
                        f"keyboard class receipt invalid: sequence={sequence} "
                        f"index={index} batch={batch} consumed={consumed}")
                self.last_sequence = sequence
                if (actual_code, actual_flags) != (code, flags):
                    raise RuntimeError(
                        f"keyboard {expected} class receipt mismatch: sequence={sequence} "
                        f"code=0x{actual_code:02x} flags={actual_flags}")
                return sequence
            if self.clock() >= deadline:
                raise RuntimeError(
                    f"keyboard {expected} missing class receipt within {timeout:g}s "
                    f"after sequence={self.last_sequence}")
            self.sleep(max(0, min(0.02, deadline - self.clock())))
