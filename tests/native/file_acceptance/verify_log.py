#!/usr/bin/env python3
"""Verify fixture observations plus canonical exit/retirement, not desktop acceptance."""
import argparse
import re
from pathlib import Path

RECORD = re.compile(
    r"^(?:\[smss\] )?\[file-acceptance\] case=([A-Za-z0-9-]+) field=([A-Za-z0-9-]+) "
    r"actual=0x([0-9a-f]{16}) expected=0x([0-9a-f]{16})$"
)
RETIRED = re.compile(
    r"^\[process-delete\] retired pi=(\d+) pid=(\d+) generation=(\d+) threads=(\d+)$"
)
TERMINAL = re.compile(
    r"^\[process-terminal-committed\] pi=(\d+) pid=(\d+) generation=(\d+) "
    r"exit-status=0x([0-9a-f]{8}) signaled=1$"
)

# Each required check must originate from the executable, not be inferred from desktop paint.
REQUIRED = {
    ("BEGIN", "version"): 1,
    ("identity", "status"): 0,
    ("identity", "bytes"): 48,
    ("parent-open", "status"): 0,
    ("open-missing-child", "status"): 0xC0000034,
    ("open-missing-child", "handle-unchanged"): 0xABABABABABABABAB,
    ("open-missing-child", "iosb-status"): 0xABABABABABABABAB,
    ("open-missing-child", "iosb-information"): 0xABABABABABABABAB,
    ("relative-create", "status"): 0,
    ("relative-create", "information"): 2,
    ("direct-create-open", "status"): 0,
    ("create-options-before-handle", "status"): 0xC000000D,
    ("create-options-before-handle", "old-protection"): 0x104,
    ("create-options-before-handle", "handle-unchanged"): 0xABABABABABABABAB,
    ("create-options-before-handle", "protected-output-unchanged"): 0xABABABABABABABAB,
    ("create-allocation-before-attributes", "status"): 0x80000001,
    ("create-allocation-before-attributes", "old-protection"): 4,
    ("create-allocation-before-attributes", "handle-unchanged"): 0xABABABABABABABAB,
    ("create-allocation-before-attributes", "iosb-status"): 0xABABABABABABABAB,
    ("create-allocation-before-attributes", "iosb-information"): 0xABABABABABABABAB,
    ("create-allocation-before-attributes", "input-unchanged"): 0xABABABABABABABAB,
    ("create-ea-before-attributes", "status"): 0x80000001,
    ("create-ea-before-attributes", "old-protection"): 4,
    ("create-ea-before-attributes", "handle-unchanged"): 0xABABABABABABABAB,
    ("create-ea-before-attributes", "iosb-status"): 0xABABABABABABABAB,
    ("create-ea-before-attributes", "iosb-information"): 0xABABABABABABABAB,
    ("create-ea-before-attributes", "input-unchanged"): 0xABABABABABABABAB,
    ("direct-create-open", "handle-published"): 1,
    ("direct-create-open", "iosb-status"): 0,
    ("direct-create-open", "information"): 1,
    ("direct-create-open", "iosb-padding"): 0xABABABAB,
    ("direct-create-close", "status"): 0,
    ("direct-create-collision", "status"): 0xC0000035,
    ("direct-create-collision", "handle-unchanged"): 0xABABABABABABABAB,
    ("direct-create-collision", "iosb-status"): 0xABABABABABABABAB,
    ("direct-create-collision", "iosb-information"): 0xABABABABABABABAB,
    ("create-handle-before-iosb", "status"): 0x80000001,
    ("create-iosb-before-attributes", "status"): 0x80000001,
    ("create-handle-before-iosb", "old-protection"): 4,
    ("create-iosb-before-attributes", "old-protection"): 4,
    ("create-handle-before-iosb", "handle-unchanged"): 0xABABABABABABABAB,
    ("create-iosb-before-attributes", "handle-unchanged"): 0xABABABABABABABAB,
    ("create-handle-before-iosb", "protected-output-unchanged"): 0xABABABABABABABAB,
    ("create-iosb-before-attributes", "protected-output-unchanged"): 0xABABABABABABABAB,
    ("relative-reopen", "status"): 0,
    ("write", "status"): 0,
    ("write", "information"): 16,
    ("relative-read", "status"): 0,
    ("relative-read", "bytes"): 1,
    ("write-readonly-handle", "status"): 0xC0000022,
    ("write-access-before-probe", "status"): 0xC0000022,
    ("nondirectory-root", "status"): 0xC0000103,
    ("file-all", "boundary-canaries"): 1,
    ("file-all", "status"): 0,
    ("file-all", "iosb-status"): 0,
    ("file-all", "iosb-padding"): 0xABABABAB,
    ("file-all", "eof"): 16,
    ("file-all", "position"): 16,
    ("file-all", "name-even"): 0,
    ("file-all", "name-suffix"): 1,
    ("file-all", "mode"): 0x1020,
    ("short-standard", "status"): 0xC0000004,
    ("short-standard", "iosb-status"): 0xABABABABABABABAB,
    ("query-class-before-probe", "status"): 0xC0000003,
    ("query-length-before-probe", "status"): 0xC0000004,
    ("query-probe-before-handle", "status"): 0xC0000005,
    ("read-handle-before-probe", "status"): 0xC0000008,
    ("write-handle-before-probe", "status"): 0xC0000008,
    ("open-handle-before-iosb", "status"): 0x80000001,
    ("open-iosb-before-attributes", "status"): 0x80000001,
    ("open-handle-before-iosb", "old-protection"): 4,
    ("open-iosb-before-attributes", "old-protection"): 4,
    ("open-handle-before-iosb", "handle-unchanged"): 0xABABABABABABABAB,
    ("open-iosb-before-attributes", "handle-unchanged"): 0xABABABABABABABAB,
    ("open-handle-before-iosb", "protected-output-unchanged"): 0xABABABABABABABAB,
    ("open-iosb-before-attributes", "protected-output-unchanged"): 0xABABABABABABABAB,
    ("open-attributes-after-outputs", "status"): 0xC0000005,
    ("open-attributes-after-outputs", "handle-unchanged"): 0xABABABABABABABAB,
    ("open-attributes-after-outputs", "iosb-status"): 0xABABABABABABABAB,
    ("open-attributes-after-outputs", "iosb-information"): 0xABABABABABABABAB,
    ("open-attributes-after-outputs", "old-protection"): 1,
    ("noaccess-query-output", "status"): 0xC0000005,
    ("guard-query-output", "status"): 0x80000001,
    ("noaccess-query-output", "old-protection"): 1,
    ("guard-query-output", "old-protection"): 4,
    ("noaccess-query-output", "output-unchanged"): 1,
    ("guard-query-output", "output-unchanged"): 1,
    ("read-output-crossing", "status"): 0xC0000005,
    ("read-output-fault-file-wait", "status"): 0,
    ("write-input-crossing", "status"): 0xC0000005,
    ("write-fault-event-create", "status"): 0,
    ("write-input-fault-file-wait", "status"): 0x102,
    ("write-fault-event-close", "status"): 0,
    ("read-iosb-crossing", "status"): 0xC0000005,
    ("content-after-faults", "unchanged"): 1,
    ("content-after-faults", "status"): 0,
    ("content-after-faults", "information"): 16,
    ("registry-worker-create", "status"): 0,
    ("registry-worker-open", "status"): 0,
    ("registry-worker-size", "status"): 0xC0000023,
    ("registry-worker-size", "required"): 72,
    ("registry-worker-name", "status"): 0,
    ("registry-worker-name", "required"): 72,
    ("registry-worker-name", "name-length"): 68,
    ("registry-worker-name", "name-and-canaries"): 1,
    ("registry-worker-wait", "status"): 0,
    ("registry-worker-wait", "completed"): 1,
    ("mode-duplicate", "status"): 0,
    ("mode-set", "status"): 0,
    ("mode-set", "information"): 0,
    ("mode-set", "padding"): 0xABABABAB,
    ("mode-query-duplicate", "status"): 0,
    ("mode-query-duplicate", "mode"): 0x1016,
    ("mode-all-duplicate", "status"): 0,
    ("mode-all-duplicate", "mode"): 0x1016,
    ("mode-all-duplicate", "position"): 16,
    ("mode-reject", "status"): 0xC000000D,
    ("mode-reject-query", "status"): 0,
    ("mode-reject-query", "mode"): 0x1016,
    ("mode-restore", "status"): 0,
    ("mode-restore-query", "status"): 0,
    ("mode-restore-query", "mode"): 0x1020,
    ("PASS", "cases"): 19,
    ("EXIT-REQUEST", "status"): 0,
}
for case in ("noaccess-query-output", "guard-query-output", "read-output-crossing", "write-input-crossing"):
    for field in ("iosb-status", "iosb-information"):
        REQUIRED[(case, field)] = 0xABABABABABABABAB
for case, refusal, old_protection, prefix in (
    ("write-input-guard", 0x80000001, 4, "write-guard"),
    ("write-offset-noaccess", 0xC0000005, 1, "write-offset"),
    ("write-key-guard", 0x80000001, 4, "write-key"),
):
    REQUIRED[(case, "status")] = refusal
    REQUIRED[(case, "iosb-status")] = 0xABABABABABABABAB
    REQUIRED[(case, "iosb-information")] = 0xABABABABABABABAB
    REQUIRED[(case, "old-protection")] = old_protection
    REQUIRED[(case, "position")] = 16
    REQUIRED[(prefix + "-event-create", "status")] = 0
    REQUIRED[(prefix + "-event-close", "status")] = 0
    REQUIRED[((case if case == "write-input-guard" else prefix) + "-position", "status")] = 0
    REQUIRED[((case if case == "write-input-guard" else prefix) + "-file-wait", "status")] = (
        0x102 if case == "write-input-guard" else 0
    )
    REQUIRED[((case if case == "write-input-guard" else prefix) + "-event-wait", "status")] = (
        0x102 if case == "write-input-guard" else 0
    )
REQUIRED[("read-iosb-crossing", "status-word")] = 0xABABABABABABABAB
for case, refusal in (("mode-noaccess-span", 0xC0000005), ("mode-guard-span", 0x80000001)):
    REQUIRED[(case, "status")] = refusal
    REQUIRED[(case + "-query", "status")] = 0
    REQUIRED[(case, "iosb-status")] = 0xABABABABABABABAB
    REQUIRED[(case, "iosb-information")] = 0xABABABABABABABAB
    REQUIRED[(case, "input-scalar")] = 0x10
    REQUIRED[(case, "mode")] = 0x1020

REPEATED = {
    ("event", "status"): (5, 0x102),
    ("position", "status"): (8, 0),
    ("position", "information"): (8, 8),
    ("position", "offset"): (8, 16),
    ("close", "status"): (7, 0),
}


def verify(text):
    observations = {}
    terminals, retirements = [], []
    lines = text.splitlines()
    for number, line in enumerate(lines):
        if "[provider-bugcheck] terminal" in line or "[pump] WALL" in line:
            raise ValueError("terminal native failure")
        if "[file-acceptance]" in line:
            match = RECORD.fullmatch(line)
            if not match:
                raise ValueError(f"malformed fixture observation at line {number + 1}")
            case, field, actual, expected = match.groups()
            if case.startswith("FAIL") or int(actual, 16) != int(expected, 16):
                raise ValueError(f"failed fixture observation {case}/{field}")
            observations.setdefault((case, field), []).append((number, int(actual, 16)))
        if match := TERMINAL.fullmatch(line):
            pi, pid, generation, status = match.groups()
            terminals.append((number, int(pi), int(pid), int(generation), int(status, 16)))
        if match := RETIRED.fullmatch(line):
            pi, pid, generation, threads = map(int, match.groups())
            retirements.append((number, pi, pid, generation, threads))
    for key, expected in REQUIRED.items():
        values = observations.get(key, [])
        if len(values) != 1 or values[0][1] != expected:
            raise ValueError(f"missing, duplicate or incorrect observation {key}")
    for key, (count, expected) in REPEATED.items():
        values = observations.get(key, [])
        if len(values) != count or any(value != expected for _, value in values):
            raise ValueError(f"incomplete repeated native observations {key}")
    name_values = observations.get(("file-all", "name-bytes"), [])
    information_values = observations.get(("file-all", "information"), [])
    if len(name_values) != 1 or len(information_values) != 1:
        raise ValueError("missing or duplicate FileAll name extent")
    name_bytes = name_values[0][1]
    information = information_values[0][1]
    if name_bytes == 0 or name_bytes & 1 or information != 100 + name_bytes or information > 488:
        raise ValueError("invalid FileAll UTF-16 name extent")
    pids = observations.get(("identity", "pid"), [])
    if len(pids) != 1 or pids[0][1] == 0:
        raise ValueError("missing unique dynamic process identity")
    pid = pids[0][1]
    begin = observations[("BEGIN", "version")][0][0]
    passed = observations[("PASS", "cases")][0][0]
    exit_request = observations[("EXIT-REQUEST", "status")][0][0]
    if not begin < pids[0][0] < passed < exit_request:
        raise ValueError("fixture milestones out of order")
    for key in REQUIRED:
        if key not in {("BEGIN", "version"), ("EXIT-REQUEST", "status")}:
            if not begin < observations[key][0][0] <= passed:
                raise ValueError("acceptance observation outside actual fixture execution")
    for key in REPEATED:
        if any(not begin < line < passed for line, _ in observations[key]):
            raise ValueError("repeated acceptance observation outside fixture execution")
    if any(not begin < line < passed for line, _ in name_values + information_values):
        raise ValueError("FileAll extent outside actual fixture execution")
    exits = [row for row in terminals if row[2] == pid and row[0] > exit_request]
    if len(exits) != 1 or exits[0][3] == 0 or exits[0][4] != 0:
        raise ValueError("missing unique zero-status canonical process exit")
    terminal_line, pi, _, generation, _ = exits[0]
    retired = [row for row in retirements if row[1:4] == (pi, pid, generation)]
    if len(retired) != 1 or retired[0][0] <= terminal_line:
        raise ValueError("missing exact-generation process/thread resource retirement")
    return pid, generation


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    args = parser.parse_args()
    try:
        pid, generation = verify(args.log.read_text())
    except (OSError, UnicodeError, ValueError) as error:
        parser.exit(1, f"FAIL native file acceptance: {error}\n")
    print(f"PASS native file acceptance: pid={pid} generation={generation}; desktop not verified by this parser")


if __name__ == "__main__":
    main()
