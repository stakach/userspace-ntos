"""The desktop gate one bounded KVM boot must pass (#31).

A boot passes exactly when:

* Explorer sealed the desktop's boot-progress epoch;
* the scripted interaction ran every step with no input or capture error;
* the serial log holds no executive panic, provider bugcheck, service-loop exit, kernel
  panic or kernel halt;
* the runner saw no other terminal stop (a guest reset, a refused hive durability verdict,
  a fatal guest gate, a missing startup marker or framebuffer).

The rule is pure so that it can be tested against recorded serial output.
"""

from dataclasses import asdict, dataclass, field
import re

DESKTOP_SEALED = re.compile(
    rb"\[quiesce\] Explorer runtime paint milestones complete; boot-progress epoch sealed"
)
EXECUTIVE_PANIC = re.compile(rb"!@(src/[A-Za-z0-9_./-]+\.rs:[1-9][0-9]*)\r?\n")
# Each record names one way the guest failed, whatever the runner did afterwards.
FAULT_RECORDS = (
    ("executive panic", EXECUTIVE_PANIC),
    ("provider bugcheck", re.compile(rb"\[provider-bugcheck\] [^\r\n]*")),
    ("service-loop exit", re.compile(rb"\[service-loop-exit\] reason=[^\r\n]*")),
    ("kernel panic", re.compile(rb"PANIC: [^\r\n]*\.rs:[0-9]+")),
    ("kernel halt", re.compile(rb"System halted due to unrecoverable error")),
)


@dataclass(frozen=True)
class InteractionOutcome:
    """What the scripted interaction did; `requested` is false when it never ran."""

    requested: bool
    completed: int = 0
    total: int = 0
    errors: int = 0

    def passed(self):
        return self.requested and self.total > 0 and self.completed == self.total \
            and self.errors == 0

    def describe(self):
        if not self.requested:
            return "scripted interaction was not requested"
        return (f"scripted interaction {self.completed}/{self.total} steps, "
                f"{self.errors} input/capture errors")


@dataclass
class BootVerdict:
    passed: bool
    sealed: bool
    interaction: InteractionOutcome
    faults: list = field(default_factory=list)
    reasons: list = field(default_factory=list)

    def to_json(self):
        document = asdict(self)
        document["interaction"]["summary"] = self.interaction.describe()
        return document


def serial_faults(serial):
    """The fault kinds the serial log records, each with its first record."""
    faults = []
    for kind, pattern in FAULT_RECORDS:
        match = pattern.search(serial)
        if match:
            record = match.group(0).decode("utf-8", "replace").strip()
            faults.append(f"{kind}: {record}")
    return faults


def boot_verdict(serial, interaction, runner_failures=()):
    """Decide one boot from its serial log, its interaction and the runner's own stops."""
    sealed = DESKTOP_SEALED.search(serial) is not None
    faults = serial_faults(serial)
    reasons = list(runner_failures) + faults
    if not sealed:
        reasons.append("Explorer desktop never sealed")
    if not interaction.passed():
        reasons.append(interaction.describe())
    return BootVerdict(passed=not reasons, sealed=sealed, interaction=interaction,
                       faults=faults, reasons=reasons)
