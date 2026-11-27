"""Correlate FileBasic native ownership receipts from a bounded KVM boot."""

from dataclasses import dataclass
import re


OWNER = re.compile(
    rb"\[file-set-owner\] stage=(?P<stage>basic-terminal|reply|file-released|retired) "
    rb"table=(?P<table>\d+) slot=(?P<slot>\d+) generation=(?P<generation>\d+) "
    rb"irp=(?P<irp>\d+) pi=(?P<pi>\d+) tid=(?P<tid>\d+) "
    rb"status=(?P<status>\d+) file=(?P<file>\d+)"
    rb"(?: stable=(?P<stable>\d+) attrs=(?P<attrs>\d+))?"
)
MOUNTED = re.compile(
    rb"\[mounted-basic-owner\] stage=(?P<stage>terminal|ack) "
    rb"irp=(?P<irp>\d+) file=(?P<file>\d+) context=(?P<context>\d+) "
    rb"mount=(?P<mount>\d+) overlay_mount=(?P<overlay_mount>\d+) "
    rb"overlay_file=(?P<overlay_file>\d+) status=(?P<status>\d+) "
    rb"stable=(?P<stable>\d+) attrs=(?P<attrs>\d+)"
)
STAGES = (b"basic-terminal", b"reply", b"file-released", b"retired")


@dataclass(frozen=True)
class FileBasicProof:
    passed: bool
    error: str = ""


def prove_filebasic_receipts(serial: bytes) -> FileBasicProof:
    """Find successful clear then set operations on one exact Overlay File.

    Each operation must progress through the same pending table, slot, generation,
    IRP, process, thread and open handle. The two operations must refer to the
    same stable filesystem File ID, even when they opened separate handles.
    """
    active = {}
    seen = set()
    complete = []
    mounted = {}
    mounted_seen = set()
    for line in serial.splitlines():
        provider = MOUNTED.fullmatch(line.strip())
        if provider is not None:
            fields = provider.groupdict()
            key = (int(fields["irp"]), int(fields["file"]))
            owner = tuple(int(fields[name]) for name in
                          ("context", "mount", "overlay_mount", "overlay_file",
                           "stable", "attrs"))
            if fields["stage"] == b"terminal":
                if key in mounted_seen:
                    mounted.pop(key, None)
                    continue
                mounted_seen.add(key)
                if int(fields["status"]) == 0 and owner[4] != 0:
                    mounted[key] = (1, owner, None)
            elif int(fields["status"]) == 0:
                stage = mounted.get(key)
                if stage is not None and stage[0] == 2 and stage[1] == owner:
                    mounted[key] = (3, owner, stage[2])
                else:
                    mounted.pop(key, None)
            continue
        match = OWNER.fullmatch(line.strip())
        if match is None:
            continue
        fields = match.groupdict()
        key = tuple(int(fields[name]) for name in
                    ("table", "slot", "generation", "irp", "pi", "tid", "file"))
        stage = fields["stage"]
        status = int(fields["status"])
        mounted_key = (int(fields["irp"]), int(fields["file"]))
        mounted_stage = mounted.get(mounted_key)
        if mounted_stage is not None:
            if stage == b"reply" and mounted_stage[0] == 1 and status == 0:
                mounted[mounted_key] = (2, mounted_stage[1], key)
            elif stage == b"retired" and mounted_stage[0] == 3 and status == 0:
                if mounted_stage[2] == key:
                    complete.append((mounted_stage[1][4], mounted_stage[1][5]))
                mounted.pop(mounted_key, None)
            else:
                mounted.pop(mounted_key, None)
        if stage == STAGES[0]:
            if key in seen:
                active.pop(key, None)
                continue
            seen.add(key)
            attrs, stable = fields["attrs"], fields["stable"]
            if status == 0 and attrs is not None and stable is not None and int(stable) != 0:
                active[key] = (1, int(stable), int(attrs))
            continue
        state = active.get(key)
        if state is None:
            continue
        next_stage, stable, attrs = state
        if status != 0 or stage != STAGES[next_stage]:
            active.pop(key)
            continue
        if next_stage == len(STAGES) - 1:
            complete.append((stable, attrs))
            active.pop(key)
        else:
            active[key] = (next_stage + 1, stable, attrs)

    cleared = set()
    for file, attrs in complete:
        if attrs != 0 and not attrs & 1:
            cleared.add(file)
        elif attrs & 1 and file in cleared:
            return FileBasicProof(True)
    return FileBasicProof(False, "no successful exact FileBasic clear/set ownership pair on one Overlay File")
