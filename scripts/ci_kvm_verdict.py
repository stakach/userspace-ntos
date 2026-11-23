"""The desktop gate one bounded KVM boot must pass (#31).

A boot passes exactly when:

* Explorer sealed the desktop's boot-progress epoch;
* the scripted interaction ran every step with no input or capture error and the
  final framebuffer visibly contains the typed command and its result;
* the serial log holds no executive panic, provider bugcheck, service-loop exit, kernel
  panic or kernel halt;
* the runner saw no other terminal stop (a guest reset, a refused hive durability verdict,
  a fatal guest gate, a missing startup marker or framebuffer).

The rule is pure so that it can be tested against recorded serial output.
"""

from dataclasses import asdict, dataclass, field
import re

try:
    from .ci_kvm_visual_proof import VisualProof
except ImportError:
    from ci_kvm_visual_proof import VisualProof

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
    """Distinguish an omitted script, a script awaiting its trigger and an attempted script."""

    requested: bool
    armed: bool = False
    completed: int = 0
    total: int = 0
    errors: int = 0
    checkpoints: dict = field(default_factory=dict)
    visual_proof: VisualProof | None = None

    def receipts_passed(self):
        return self.requested and self.armed and self.total > 0 \
            and self.completed == self.total and self.errors == 0

    def passed(self):
        return self.receipts_passed() and self.visual_proof is not None \
            and self.visual_proof.passed

    def describe(self):
        if not self.requested:
            return "scripted interaction was not requested"
        if not self.armed:
            return "scripted interaction never armed"
        summary = (f"scripted interaction {self.completed}/{self.total} steps, "
                   f"{self.errors} input/capture/checkpoint errors")
        for name, proof in self.checkpoints.items():
            if not proof.passed:
                return f"{summary}; {name}: {proof.error}"
        return summary


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
    if not interaction.receipts_passed():
        reasons.append(interaction.describe())
    elif interaction.visual_proof is None or not interaction.visual_proof.passed:
        reason = "visible command result missing"
        if interaction.visual_proof is not None and interaction.visual_proof.error:
            reason += f": {interaction.visual_proof.error}"
        reasons.append(reason)
    return BootVerdict(passed=not reasons, sealed=sealed, interaction=interaction,
                       faults=faults, reasons=reasons)
