#!/usr/bin/env python3
"""Bounded CI KVM boot, gated on Explorer and a visible command result (#31, #440)."""

import argparse
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import threading
import time

if __package__:
    from .ci_kvm_cursor import prove_cursor_position, prove_selected_icon
    from .ci_kvm_interaction import DEFAULT_SCRIPT, InteractionRunner, load_script, screenshot_name
    from .ci_kvm_qmp_control import (QEMU_SHUTDOWN_ACTION, guest_shutdown_paused,
                                     read_run_state, request_quit)
    from .ci_kvm_verdict import DESKTOP_SEALED, EXECUTIVE_PANIC, InteractionOutcome, boot_verdict
    from .ci_kvm_visual_proof import VisualProof, prove_ready_prompt, prove_ver_result
else:
    from ci_kvm_cursor import prove_cursor_position, prove_selected_icon
    from ci_kvm_interaction import DEFAULT_SCRIPT, InteractionRunner, load_script, screenshot_name
    from ci_kvm_qmp_control import (QEMU_SHUTDOWN_ACTION, guest_shutdown_paused,
                                    read_run_state, request_quit)
    from ci_kvm_verdict import DESKTOP_SEALED, EXECUTIVE_PANIC, InteractionOutcome, boot_verdict
    from ci_kvm_visual_proof import VisualProof, prove_ready_prompt, prove_ver_result


ROOT = Path(__file__).resolve().parent.parent
MICRO = ROOT / "rust-micro"
LOG = ROOT / "native-kvm-smoke.log"
SCREENSHOT = ROOT / "native-kvm-smoke.ppm"
QMP_SOCKET = ROOT / "native-kvm-smoke-qmp.sock"
INTERRUPT_TRACE = MICRO / "native-kvm-qemu-int.log"
INTERRUPT_TRACE_TAIL = ROOT / "native-kvm-qemu-int-tail.log"
STALL_STATE = ROOT / "native-kvm-stall-state.json"
GUEST_RESET_STATE = ROOT / "native-kvm-guest-reset-state.json"
VOLUME_DISPATCH_STATE = ROOT / "native-kvm-volume-dispatch-state.json"
CPU_SAMPLES = ROOT / "native-kvm-cpu-samples.jsonl"
BLOCKSTATS = ROOT / "native-kvm-blockstats.jsonl"
STOPPED_MARKER = ROOT / "native-kvm-qemu-stopped"
STATIONARY_MARKER = ROOT / "native-kvm-stationary.txt"
POST_SETUP_IDLE_MARKER = ROOT / "native-kvm-post-setup-idle.txt"
INTERACTION_LOG = ROOT / "native-kvm-interact.jsonl"
VERDICT = ROOT / "native-kvm-verdict.json"
# The boot ran its whole bound without a fault or a desktop: a setup disk worth continuing.
BOUND_REACHED_MARKER = ROOT / "native-kvm-bound-reached.txt"

# Fixed 60-second QMP samples repeatedly hit the same clock-publication RIP,
# while the guest's own cycle counter showed that path used only a few seconds.
# Vary the phase so a periodic guest path cannot masquerade as a CPU hotspot.
CPU_SAMPLE_DELAYS = (17, 31, 43, 59)
TERMINAL_BOOT_STOP = re.compile(
    rb"(?:^|[\r\n])("
    rb"\[quiesce\] every live process parked/waiting \(no signaler left\) -> run gate"
    rb"|\[quiesce\] no boot milestone for ~[0-9]+s wall-clock -> run gate"
    rb"|\[cm-flush\] shutdown hive durability refused status=(?:0x){1,2}[0-9a-fA-F]{8}"
    rb"|\[provider-bugcheck\] terminal"
    rb"|\[dbg\] err:\(base\\system\\winlogon\\winlogon\.c:[0-9]+\) WL: Failed to initialize Gina"
    rb"|\[user #PF: tcb=1 cr2=0x[0-9a-fA-F]{16} err=0x[0-9a-fA-F]{16} "
    rb"rip=0x[0-9a-fA-F]{16}\]\r?\n"
    rb"\[no fault handler \xe2\x80\x94 suspending thread\]"
    rb")\r?\n"
)
# The quiesce gate line precedes the executive's post-loop hive durability fence (#422). The
# guest may be stopped only once that fence reports, or the wait reaches its bound.
QUIESCE_DURABILITY_VERDICT = re.compile(
    rb"(?:^|[\r\n])\[cm-flush\] shutdown hive durability "
    rb"(proven|refused status=(?:0x){1,2}[0-9a-fA-F]{8})\r?\n"
)
QUIESCE_DURABILITY_GRACE_SECONDS = 60
PS_CREATE_FOLD_EVENT = re.compile(
    rb"\[ps-create-event\] #[0-9]+ stage=fold-(?:enter|service-return|restore-return) "
    rb"route=([0-9]+) reply=0 label=0"
)
PS_CREATE_FOLD_LOOP = re.compile(
    rb"\[ps-create-after-autonomous\] #[0-9]+ stage=loop tcb=([0-9]+) route=([0-9]+)"
)
SETUP_PHASE_COMPLETE = re.compile(
    rb"\[setup-provision\] phase=([a-z0-9-]+-end) detail=[0-9]+"
)
DRIVER_START_COMPLETE = re.compile(
    rb"\[driver-launch\] demand StartDevice service=([^ ]+) devnode=(.+) status=0x0*0\s*$"
)
SETUP_PROCESS_START = re.compile(
    rb"\[pm-dynamic\] allocated hosted process pi=([0-9]+) pid=([0-9]+) parent=[0-9]+ "
    rb"image=setup\.exe "
)
PROCESS_EXIT = re.compile(
    rb"\[process-terminal-committed\] pi=([0-9]+) pid=([0-9]+) generation=[0-9]+ "
    rb"exit-status=0x([0-9a-fA-F]{8}) "
)
USER_HIVE_LOADED = re.compile(
    rb"\[cm-load\] NtLoadKey MOUNTED \\Registry\\User\\(S-1-5-21-[0-9-]+) "
)
DESKTOP_EPOCH_SEALED = DESKTOP_SEALED
# The same record as a capture group, so a serial detector can wait for the sealed desktop.
DESKTOP_EPOCH_SEALED_RECORD = re.compile(b"(" + DESKTOP_EPOCH_SEALED.pattern + b")")
SPEC_PASS = re.compile(rb" {0,2}PASS ([A-Za-z0-9_]+)")
DIRECTORY_PUBLISH_REPLY = re.compile(
    rb"\[directory-publish\] token=([0-9]+) stage=reply status=(?:0x){1,2}0+"
)
HOSTED_PROCESS_ALLOCATED = re.compile(
    rb"\[pm-dynamic\] allocated hosted process pi=[0-9]+ pid=([0-9]+) "
    rb"parent=[0-9]+ image=([^ ]+) token=[0-9]+ inherited"
)
FILE_BACKED_SECTION_MAP = re.compile(
    rb"\[kernel-section-map\] .* section-index=[0-9]+ section-generation=[0-9]+ "
    rb"backing-kind=4 file-present=1 file-mount=[0-9]+ file-id=([0-9]+) "
    rb".* bytes=[1-9][0-9]* pages=[1-9][0-9]*"
)
FONT_BROKER_RETURN = re.compile(
    rb"\[font-next-broker-return\] ordinal=[0-9]+ "
    rb"reply-info=(?:0x){1,2}[0-9a-fA-F]+ status=(?:0x){1,2}([0-9a-fA-F]+)"
    rb"(?: start-tsc=[0-9]+ end-tsc=[0-9]+)?"
)
DESKTOP_SWITCH_PREFIX = b"[win32k-desktop-switch] pi/ret/"
INSTALL_PIPE_OPEN = re.compile(
    rb'\[pnp-install-pipe\] stage=provider-result pi=([1-9][0-9]*) '
    rb'generation=([1-9][0-9]*) status=0x0x00000000 '
    rb'name="\\\?\?\\pipe\\PNP_Device_Install_Pipe_0\.\{'
    rb'([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-'
    rb'[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}"'
)
# QMP block statistics are sampled every ten seconds. A change observed after
# more than two missed samples cannot prove when its disk work actually ran.
RECENT_DISK_SAMPLE_SECONDS = 30
SUSTAINED_DISK_PROGRESS_BYTES = 1024 * 1024


class BootProgressWatchdog:
    """Bound a boot by finite milestones, small disk graces, and fresh sustained I/O."""

    def __init__(self, started, idle_seconds=180, max_disk_extensions=2):
        self.idle_seconds = idle_seconds
        self.max_disk_extensions = max_disk_extensions
        self.last_progress = started
        self.last_milestone = "startup"
        self.armed = False
        self.disk_extensions = 0
        self.disk_bytes = None
        self.disk_checkpoint = None
        self.disk_sampled_at = None
        self.disk_changed_at = None
        self.seen = set()
        self.pending_font_file_id = None
        self.pending = b""

    def observe_serial(self, chunk, now):
        """Consume completed serial lines; repeated log messages are never progress."""
        if not isinstance(chunk, bytes):
            return []
        records = self.pending + chunk
        lines = records.split(b"\n")
        self.pending = lines.pop()[-4096:]
        milestones = []
        for line in lines:
            line = line.rstrip(b"\r")
            if b"boot: reading Simpleboot memory map" in line and not self.armed:
                self.armed = True
                self.last_progress = now
                self.last_milestone = "guest-started"
                milestones.append("guest-started")
            if not self.armed:
                continue
            key = None
            if match := FILE_BACKED_SECTION_MAP.fullmatch(line):
                # A map alone does not prove a font was accepted. Pair this
                # file-backed result with the font broker's real completion.
                self.pending_font_file_id = match.group(1).decode("ascii")
            elif match := FONT_BROKER_RETURN.fullmatch(line):
                if int(match.group(1), 16) == 0 and self.pending_font_file_id is not None:
                    key = "font-section-map:" + self.pending_font_file_id
                self.pending_font_file_id = None
            elif match := SETUP_PHASE_COMPLETE.fullmatch(line):
                key = "setup-provision:" + match.group(1).decode("ascii")
            elif match := DRIVER_START_COMPLETE.fullmatch(line):
                key = ("driver-start:" + match.group(1).decode("ascii") + ":"
                       + match.group(2).decode("ascii", "replace"))
            elif match := SPEC_PASS.fullmatch(line):
                key = "PASS " + match.group(1).decode("ascii")
            elif match := DIRECTORY_PUBLISH_REPLY.fullmatch(line):
                key = "directory-publish:" + match.group(1).decode("ascii")
            elif match := HOSTED_PROCESS_ALLOCATED.fullmatch(line):
                key = ("process:" + match.group(1).decode("ascii") + ":"
                       + match.group(2).decode("ascii", "replace"))
            elif match := INSTALL_PIPE_OPEN.fullmatch(line):
                # One successful open per exact child/generation/pipe is real install progress.
                # It does not imply payload transfer or device installation completed.
                key = ("install-pipe-open:" + match.group(1).decode("ascii") + ":"
                       + match.group(2).decode("ascii") + ":"
                       + match.group(3).decode("ascii"))
            elif line.startswith(DESKTOP_SWITCH_PREFIX):
                fields = line.partition(b"=")[2].split(b"/")
                if len(fields) >= 3:
                    returned = fields[2]
                    if returned.startswith(b"0x"):
                        final_hex = returned.rpartition(b"0x")[2]
                        if final_hex and all(byte in b"0123456789abcdefABCDEF" for byte in final_hex):
                            if int(final_hex, 16) == 1:
                                key = "win32k-desktop-switch"
            if key is not None and key not in self.seen:
                self.seen.add(key)
                self.last_progress = now
                self.last_milestone = key
                self.disk_extensions = 0
                self.disk_checkpoint = self.disk_bytes
                milestones.append(key)
        return milestones

    def observe_blockstats(self, reply, now):
        """Count completed bytes from the single named boot disk, with finite grace."""
        if not self.armed or not isinstance(reply, dict):
            return False
        records = reply.get("return")
        if not isinstance(records, list):
            return False
        boot_disks = [record for record in records if isinstance(record, dict)
                      and record.get("device") == "bootdisk"]
        if len(boot_disks) != 1:
            return False
        stats = boot_disks[0].get("stats")
        if not isinstance(stats, dict):
            return False
        read_bytes, written_bytes = stats.get("rd_bytes"), stats.get("wr_bytes")
        if (not isinstance(read_bytes, int) or isinstance(read_bytes, bool) or read_bytes < 0
                or not isinstance(written_bytes, int) or isinstance(written_bytes, bool)
                or written_bytes < 0):
            return False
        total = read_bytes + written_bytes
        previous = self.disk_bytes
        if previous is not None and total < previous:
            return False
        previous_sample = self.disk_sampled_at
        self.disk_bytes = total
        self.disk_sampled_at = now
        if previous is not None and total > previous:
            # A long observation gap cannot date the completed I/O. Require a
            # later fresh change before granting another boot interval.
            self.disk_changed_at = (now if previous_sample is not None
                                    and now - previous_sample <= RECENT_DISK_SAMPLE_SECONDS
                                    else None)
        if previous is None or self.disk_checkpoint is None:
            self.disk_checkpoint = total
            return False
        if not self._disk_progress_is_fresh(total, now):
            return False
        self.disk_extensions += 1
        self.disk_checkpoint = total
        self.last_progress = now
        self.last_milestone = f"bootdisk completed bytes={total}"
        return True

    def _disk_progress_is_fresh(self, total, now):
        if (now - self.last_progress < self.idle_seconds
                or total <= self.disk_checkpoint
                or self.disk_changed_at is None
                or now - self.disk_changed_at > RECENT_DISK_SAMPLE_SECONDS):
            return False
        # Tiny repeated I/O earns only finite grace. Substantial freshly sampled work is
        # active progress, still bounded by the runner's absolute boot deadline.
        return (self.disk_extensions < self.max_disk_extensions
                or total - self.disk_checkpoint >= SUSTAINED_DISK_PROGRESS_BYTES)

    def idle_reason(self, now):
        if not self.armed or now - self.last_progress < self.idle_seconds:
            return None
        return (f"no boot milestone or bounded disk work for {now - self.last_progress:.0f}s; "
                f"last={self.last_milestone}, bootdisk_bytes={self.disk_bytes}")


def post_setup_idle_evidence(serial):
    """Describe proof that setup finished and a user logged on, or return None.

    setup.exe exits 0 on its failure path too, so its exit alone proves nothing. Winlogon
    only logs a user on once setup is no longer in progress; a user hive loaded after the
    last setup.exe exited 0 is the evidence that the disk holds a completed installation.

    A continuation boot of such a disk never runs setup.exe. Its evidence is a user logon
    followed by Explorer completing its runtime paint milestones (the executive seals its
    boot-progress epoch), so a later idle stop keeps the painted-desktop disk.
    """
    starts = list(SETUP_PROCESS_START.finditer(serial))
    if not starts:
        hive = USER_HIVE_LOADED.search(serial)
        if hive is None or DESKTOP_EPOCH_SEALED.search(serial, hive.end()) is None:
            return None
        return (f"user hive {hive.group(1).decode()} loaded; "
                f"Explorer desktop paint milestones sealed afterwards")
    start = starts[-1]
    exited = None
    for match in PROCESS_EXIT.finditer(serial, start.end()):
        if match.group(1, 2) == start.group(1, 2):
            exited = match
            break
    if exited is None or int(exited.group(3), 16) != 0:
        return None
    hive = USER_HIVE_LOADED.search(serial, exited.end())
    if hive is None:
        return None
    return (f"setup.exe pid={start.group(2).decode()} exited 0; "
            f"user hive {hive.group(1).decode()} loaded afterwards")


def refresh_idle_progress(watchdog, now, read_blockstats):
    """Observe completed disk work at the idle boundary before classifying a stall."""
    reason = watchdog.idle_reason(now)
    if reason is None:
        return None
    try:
        reply = read_blockstats()
    except (OSError, RuntimeError, ValueError, KeyError):
        return reason
    watchdog.observe_blockstats(reply, now)
    return watchdog.idle_reason(now)


class SerialPanicDetector:
    """Read only new serial output, retaining split panic records across polls."""

    def __init__(self, path, pattern=EXECUTIVE_PANIC):
        self.path = path
        self.pattern = pattern
        self.offset = 0
        self.tail = b""

    def poll(self):
        with self.path.open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            size = stream.tell()
            if size < self.offset:
                self.offset = 0
                self.tail = b""
            stream.seek(self.offset)
            while chunk := stream.read(65536):
                self.offset += len(chunk)
                candidate = self.tail + chunk
                match = self.pattern.search(candidate)
                self.tail = candidate[-4096:]
                if match:
                    return match.group(1).decode("utf-8")
        return None


class SerialTerminalDetector(SerialPanicDetector):
    """Detect fatal guest gates, including a hosted provider bugcheck."""

    def __init__(self, path):
        super().__init__(path, TERMINAL_BOOT_STOP)

    def poll(self):
        record = super().poll()
        if record is None:
            return None
        if record.startswith("[quiesce]"):
            return "quiesce"
        if record.startswith("[provider-bugcheck]"):
            return "provider-bugcheck"
        if record.startswith("[user #PF: tcb=1"):
            return "rootserver-page-fault"
        if "WL: Failed to initialize Gina" in record:
            return "gina-load-failed"
        return "durability-refused"


class QuiesceDurabilityFence:
    """Wait for the hive durability verdict that follows a quiesce gate.

    The gate's evidence is captured when the gate line arrives. The guest keeps running
    until the executive's post-loop fence has published every dirty hive, so a stop never
    discards a write that the fence was about to make durable.
    """

    def __init__(self, path, gated_at, grace_seconds=QUIESCE_DURABILITY_GRACE_SECONDS):
        self.detector = SerialPanicDetector(path, QUIESCE_DURABILITY_VERDICT)
        self.deadline = gated_at + grace_seconds

    def poll(self, now):
        """Return None while waiting, else "proven", "refused" or "unproven"."""
        verdict = self.detector.poll()
        if verdict is not None:
            return "proven" if verdict == "proven" else "refused"
        return "unproven" if now >= self.deadline else None


QUIESCE_VERDICT_REASONS = {
    "proven": "quiesce",
    "refused": "durability-refused",
    "unproven": "quiesce-durability-unproven",
}


def cpu_sample_delay(sample_index):
    return CPU_SAMPLE_DELAYS[sample_index % len(CPU_SAMPLE_DELAYS)]


def halted_cpu_indices(sample):
    """Return the exact reported CPU set only when every vCPU is halted."""
    state = sample.get("state")
    if not isinstance(state, dict) or state.get("error") or state.get("register_errors"):
        return None
    cpus, registers = state.get("cpus"), state.get("registers")
    if not isinstance(cpus, list) or not cpus or not isinstance(registers, dict):
        return None
    indices = [cpu.get("cpu-index") for cpu in cpus if isinstance(cpu, dict)]
    if len(indices) != len(cpus) or len(set(indices)) != len(cpus):
        return None
    if not all(isinstance(registers.get(str(index)), str)
               and re.search(r"\bHLT=1\b", registers[str(index)]) for index in indices):
        return None
    return set(indices)


def stationary_boot_pair(previous, current):
    """Classify two QMP/serial samples without altering the guest."""
    if not previous or not current:
        return False
    if (not previous.get("boot_marker") or not current.get("boot_marker")
            or previous.get("desktop_ready") or current.get("desktop_ready")):
        return False
    serial = current.get("serial_bytes")
    if not isinstance(serial, int) or serial <= 0 or serial != previous.get("serial_bytes"):
        return False
    before, after = previous.get("elapsed_seconds"), current.get("elapsed_seconds")
    if not isinstance(before, (int, float)) or not isinstance(after, (int, float)) \
            or after - before < 30:
        return False

    before_cpus = halted_cpu_indices(previous)
    return before_cpus is not None and before_cpus == halted_cpu_indices(current)


def ps_create_fold_stall_pair(previous, current, serial):
    """Recognize the proven single-CPU PsCreate fold spin, not general serial activity."""
    if not previous or not current or not isinstance(serial, bytes):
        return False
    if (not previous.get("boot_marker") or not current.get("boot_marker")
            or previous.get("desktop_ready") or current.get("desktop_ready")):
        return False
    before, after = previous.get("elapsed_seconds"), current.get("elapsed_seconds")
    start, end = previous.get("serial_bytes"), current.get("serial_bytes")
    if (not isinstance(before, (int, float)) or not isinstance(after, (int, float))
            or after - before < 30 or not isinstance(start, int) or not isinstance(end, int)
            or start <= 0 or end <= start or end > len(serial) or end - start > 65536
            or serial[start - 1] != 10 or serial[end - 1] != 10):
        return False
    previous_cpu = previous.get("host", {}).get("group_cpu_seconds")
    current_cpu = current.get("host", {}).get("group_cpu_seconds")
    if (not isinstance(previous_cpu, (int, float)) or not isinstance(current_cpu, (int, float))
            or current_cpu - previous_cpu < (after - before) * 0.5):
        return False

    def cpu_locations(sample):
        state = sample.get("state")
        if not isinstance(state, dict) or state.get("error") or state.get("register_errors"):
            return None
        cpus, registers = state.get("cpus"), state.get("registers")
        if not isinstance(cpus, list) or len(cpus) < 2 or not isinstance(registers, dict):
            return None
        indices = [cpu.get("cpu-index") for cpu in cpus if isinstance(cpu, dict)]
        if len(indices) != len(cpus) or len(set(indices)) != len(cpus):
            return None
        active = []
        for index in indices:
            record = registers.get(str(index))
            if not isinstance(record, str):
                return None
            halted = re.search(r"\bHLT=([01])\b", record)
            rip = re.search(r"\bRIP=([0-9a-fA-F]+)\b", record)
            cr3 = re.search(r"\bCR3=([0-9a-fA-F]+)\b", record)
            if not halted or not rip or not cr3:
                return None
            if halted.group(1) == "0":
                active.append((index, rip.group(1).lower(), cr3.group(1).lower()))
        return active if len(active) == 1 else None

    if cpu_locations(previous) is None or cpu_locations(previous) != cpu_locations(current):
        return False

    routes, threads = set(), set()
    saw_fold = saw_loop = False
    for line in serial[start:end].splitlines():
        if match := PS_CREATE_FOLD_EVENT.fullmatch(line):
            routes.add(match.group(1))
            saw_fold = True
        elif match := PS_CREATE_FOLD_LOOP.fullmatch(line):
            threads.add(match.group(1))
            routes.add(match.group(2))
            saw_loop = True
        else:
            return False
    return saw_fold and saw_loop and len(routes) == 1 and len(threads) == 1


def qmp_reply(stream, command_id):
    while True:
        line = stream.readline()
        if not line:
            raise RuntimeError("QMP disconnected")
        reply = json.loads(line)
        if reply.get("id") != command_id:
            continue
        if "error" in reply:
            raise RuntimeError(f"QMP {command_id}: {reply['error']}")
        return reply


def capture_framebuffer(path=SCREENSHOT):
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(10)
        connection.connect(str(QMP_SOCKET))
        with connection.makefile("rwb", buffering=0) as stream:
            greeting = json.loads(stream.readline())
            if "QMP" not in greeting:
                raise RuntimeError("QMP greeting missing")
            stream.write(b'{"execute":"qmp_capabilities","id":"capabilities"}\n')
            qmp_reply(stream, "capabilities")
            command = {
                "execute": "screendump",
                "arguments": {"filename": str(path), "format": "ppm"},
                "id": "screendump",
            }
            stream.write((json.dumps(command) + "\n").encode())
            qmp_reply(stream, "screendump")
    if not path.is_file() or path.stat().st_size == 0:
        raise RuntimeError("QMP did not write a framebuffer image")


def send_input_batches(batches):
    """Inject guest input over one QMP session, pausing after each batch's sync."""
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(10)
        connection.connect(str(QMP_SOCKET))
        with connection.makefile("rwb", buffering=0) as stream:
            greeting = json.loads(stream.readline())
            if "QMP" not in greeting:
                raise RuntimeError("QMP greeting missing")
            stream.write(b'{"execute":"qmp_capabilities","id":"capabilities"}\n')
            qmp_reply(stream, "capabilities")
            for number, (events, pause) in enumerate(batches):
                command_id = f"input-{number}"
                stream.write((json.dumps({"execute": "input-send-event",
                                          "arguments": {"events": events},
                                          "id": command_id}) + "\n").encode())
                qmp_reply(stream, command_id)
                time.sleep(pause)


def read_cpu_state():
    """Read each vCPU's current registers without changing guest state."""
    state = {"cpus": []}
    try:
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(3)
            connection.connect(str(QMP_SOCKET))
            with connection.makefile("rwb", buffering=0) as stream:
                greeting = json.loads(stream.readline())
                if "QMP" not in greeting:
                    raise RuntimeError("QMP greeting missing")
                stream.write(b'{"execute":"qmp_capabilities","id":"capabilities"}\n')
                qmp_reply(stream, "capabilities")
                stream.write(b'{"execute":"query-cpus-fast","id":"cpus"}\n')
                cpus = qmp_reply(stream, "cpus")["return"]
                state["cpus"] = cpus
                for cpu in cpus:
                    index = cpu["cpu-index"]
                    command_id = f"registers-{index}"
                    command = {
                        "execute": "human-monitor-command",
                        "arguments": {"command-line": "info registers", "cpu-index": index},
                        "id": command_id,
                    }
                    stream.write((json.dumps(command) + "\n").encode())
                    try:
                        state.setdefault("registers", {})[str(index)] = qmp_reply(
                            stream, command_id
                        )["return"]
                    except (OSError, RuntimeError, ValueError, KeyError) as error:
                        state.setdefault("register_errors", {})[str(index)] = str(error)
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        state["error"] = str(error)
    return state


def read_interrupt_state():
    """Read PIC, IRQ and per-vCPU LAPIC state without changing guest execution."""
    state = {"lapic": {}}
    try:
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(3)
            connection.connect(str(QMP_SOCKET))
            with connection.makefile("rwb", buffering=0) as stream:
                greeting = json.loads(stream.readline())
                if "QMP" not in greeting:
                    raise RuntimeError("QMP greeting missing")
                stream.write(b'{"execute":"qmp_capabilities","id":"capabilities"}\n')
                qmp_reply(stream, "capabilities")
                stream.write(b'{"execute":"query-cpus-fast","id":"cpus"}\n')
                try:
                    cpus = qmp_reply(stream, "cpus")["return"]
                    if not isinstance(cpus, list):
                        raise ValueError("QMP CPU list missing")
                except (OSError, RuntimeError, ValueError, KeyError) as error:
                    cpus = []
                    state["cpu_error"] = str(error)
                commands = [("pic", "info pic", None), ("irq", "info irq", None)]
                commands.extend((f"lapic-{cpu['cpu-index']}", "info lapic", cpu["cpu-index"])
                                for cpu in cpus if isinstance(cpu, dict)
                                and isinstance(cpu.get("cpu-index"), int)
                                and not isinstance(cpu["cpu-index"], bool))
                for command_id, line, cpu_index in commands:
                    arguments = {"command-line": line}
                    if cpu_index is not None:
                        arguments["cpu-index"] = cpu_index
                    stream.write((json.dumps({"execute": "human-monitor-command",
                                              "arguments": arguments, "id": command_id}) + "\n").encode())
                    try:
                        result = qmp_reply(stream, command_id)["return"]
                        if cpu_index is None:
                            state[command_id] = result
                        else:
                            state["lapic"][str(cpu_index)] = result
                    except (OSError, RuntimeError, ValueError, KeyError) as error:
                        if cpu_index is None:
                            state[f"{command_id}_error"] = str(error)
                        else:
                            state.setdefault("lapic_errors", {})[str(cpu_index)] = str(error)
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        state["error"] = str(error)
    return state


def retain_halted_interrupt_state(sample, read_state):
    """Retain a bounded read-only controller snapshot for each all-HLT CPU sample."""
    if halted_cpu_indices(sample) is not None:
        sample["interrupts"] = read_state()
    return sample


def read_bootdisk_blockstats():
    """Read completed I/O counters without changing guest execution."""
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(3)
        connection.connect(str(QMP_SOCKET))
        with connection.makefile("rwb", buffering=0) as stream:
            greeting = json.loads(stream.readline())
            if "QMP" not in greeting:
                raise RuntimeError("QMP greeting missing")
            stream.write(b'{"execute":"qmp_capabilities","id":"capabilities"}\n')
            qmp_reply(stream, "capabilities")
            stream.write(b'{"execute":"query-blockstats","id":"blockstats"}\n')
            return qmp_reply(stream, "blockstats")


def record_bootdisk_blockstats(reply, elapsed_seconds):
    """Retain only the named boot disk's completed I/O and time counters."""
    if not isinstance(reply, dict) or not isinstance(reply.get("return"), list):
        return
    disks = [record for record in reply["return"] if isinstance(record, dict)
             and record.get("device") == "bootdisk"]
    if len(disks) != 1 or not isinstance(disks[0].get("stats"), dict):
        return
    fields = ("rd_operations", "rd_bytes", "rd_total_time_ns", "wr_operations", "wr_bytes",
              "wr_total_time_ns", "flush_operations", "flush_total_time_ns")
    stats = disks[0]["stats"]
    sample = {field: stats[field] for field in fields
              if isinstance(stats.get(field), int) and not isinstance(stats[field], bool)
              and stats[field] >= 0}
    if sample:
        with BLOCKSTATS.open("a") as output:
            output.write(json.dumps({"elapsed_seconds": round(elapsed_seconds, 2),
                                     "device": "bootdisk", "stats": sample}) + "\n")


def proc_stat_fields(stat):
    """Split Linux stat after the final parenthesized comm, even if comm contains ')'."""
    # comm is parenthesized and may itself contain spaces or closing parentheses.
    head, separator, tail = stat.rpartition(") ")
    if not separator:
        raise ValueError("missing process stat command")
    pid_text, prefix, _comm = head.partition(" (")
    if not prefix:
        raise ValueError("missing process stat pid")
    fields = tail.split()
    if len(fields) < 22:
        raise ValueError("incomplete process stat")
    return int(pid_text), fields


def parse_proc_stat(stat):
    """Return process-group identity, CPU ticks, and RSS pages from /proc/PID/stat."""
    _pid, fields = proc_stat_fields(stat)
    return int(fields[2]), int(fields[11]) + int(fields[12]), int(fields[21])


def parse_proc_task_cpu(stat, expected_pid):
    """Return exact task group, CPU ticks, and start generation from Linux stat."""
    pid, fields = proc_stat_fields(stat)
    if pid != expected_pid:
        raise ValueError("process stat pid changed")
    return int(fields[2]), int(fields[11]) + int(fields[12]), int(fields[19])


def read_vcpu_host_state(process_group, cpus, proc_root=Path("/proc")):
    """Sample QMP vCPU threads after validating their QEMU process and generation."""
    samples = {}
    if not isinstance(cpus, list):
        return samples
    for cpu in cpus:
        if not isinstance(cpu, dict):
            continue
        index = cpu.get("cpu-index")
        if not isinstance(index, int) or isinstance(index, bool) or index < 0:
            continue
        key = str(index)
        tid = cpu.get("thread-id")
        if not isinstance(tid, int) or isinstance(tid, bool) or tid <= 0:
            samples[key] = {"error": "QMP vCPU thread-id unavailable"}
            continue
        try:
            status = (proc_root / str(tid) / "status").read_text()
            tgid = next((int(match.group(1)) for line in status.splitlines()
                         if (match := re.fullmatch(r"Tgid:\s*([0-9]+)", line))), None)
            if tgid is None or tgid <= 0:
                raise ValueError("vCPU Tgid unavailable")
            owner = proc_root / str(tgid)
            owner_group, _owner_ticks, owner_start = parse_proc_task_cpu(
                (owner / "stat").read_text(), tgid)
            if owner_group != process_group:
                raise ValueError("vCPU process group changed")
            if Path(os.readlink(owner / "exe")).name != "qemu-system-x86_64":
                raise ValueError("vCPU thread does not belong to QEMU")
            task_group, ticks, task_start = parse_proc_task_cpu(
                (owner / "task" / str(tid) / "stat").read_text(), tid)
            if task_group != process_group:
                raise ValueError("vCPU task process group changed")
            owner_group_after, _owner_ticks, owner_start_after = parse_proc_task_cpu(
                (owner / "stat").read_text(), tgid)
            if owner_group_after != process_group or owner_start_after != owner_start:
                raise ValueError("QEMU process generation changed")
            samples[key] = {
                "tid": tid, "tgid": tgid,
                "process_starttime_ticks": owner_start,
                "thread_starttime_ticks": task_start,
                "cpu_seconds": round(ticks / os.sysconf("SC_CLK_TCK"), 3),
            }
        except (OSError, ValueError) as error:
            samples[key] = {"tid": tid, "error": str(error)}
    return samples


def read_host_state(process_group):
    """Sample runner pressure and CPU consumed by the private QEMU process group."""
    state = {"load_average": os.getloadavg()}
    for resource in ("cpu", "io", "memory"):
        try:
            state[f"{resource}_pressure"] = (Path("/proc/pressure") / resource).read_text().strip()
        except OSError:
            state[f"{resource}_pressure"] = "unavailable"
    for name, path in (
        ("cgroup_cpu_stat", Path("/sys/fs/cgroup/cpu.stat")),
        ("cgroup_memory_current", Path("/sys/fs/cgroup/memory.current")),
        ("cgroup_swap_current", Path("/sys/fs/cgroup/memory.swap.current")),
    ):
        try:
            state[name] = path.read_text().strip()
        except OSError:
            state[name] = "unavailable"
    cpu_ticks = 0
    rss_pages = 0
    members = 0
    try:
        processes = subprocess.check_output(["ps", "-eo", "pid=,pgid=,stat="], text=True)
        for line in processes.splitlines():
            fields = line.split()
            if len(fields) < 3 or int(fields[1]) != process_group or fields[2].startswith("Z"):
                continue
            try:
                exact_group, ticks, pages = parse_proc_stat(Path(f"/proc/{fields[0]}/stat").read_text())
            except (OSError, ValueError):
                continue  # The process may exit between ps and /proc.
            if exact_group != process_group:
                continue  # A reused PID is not authority for the earlier ps snapshot.
            members += 1
            cpu_ticks += ticks
            rss_pages += pages
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        state["process_error"] = str(error)
    state["group_members"] = members
    state["group_cpu_seconds"] = round(cpu_ticks / os.sysconf("SC_CLK_TCK"), 3)
    state["group_rss_mib"] = round(rss_pages * os.sysconf("SC_PAGE_SIZE") / (1024 * 1024), 1)
    return state


def published_storahci_abars(serial):
    """Return each published controller BAR once, in discovery order."""
    matches = re.finditer(
        rb"assigned PCI resources service=storahci[^\r\n]*mmio=0x(?:0x)?([0-9a-fA-F]+)",
        serial,
    )
    return list(dict.fromkeys(int(match.group(1), 16) for match in matches))


def capture_stall_state(path=STALL_STATE):
    """Keep CPU, interrupt-controller and AHCI evidence at a proof frontier or stall."""
    state = read_cpu_state()
    state["interrupts"] = read_interrupt_state()
    # Every published AHCI BAR is evidence: a boot may enumerate multiple controllers,
    # and the last one in the serial log need not own the mounted volume.
    # Read controller registers through QMP without changing the guest or its disk.
    try:
        serial = LOG.read_bytes()
        bars = published_storahci_abars(serial)
        if bars:
            with socket.socket(socket.AF_UNIX) as connection:
                connection.settimeout(3)
                connection.connect(str(QMP_SOCKET))
                with connection.makefile("rwb", buffering=0) as stream:
                    greeting = json.loads(stream.readline())
                    if "QMP" not in greeting:
                        raise RuntimeError("QMP greeting missing")
                    stream.write(b'{"execute":"qmp_capabilities","id":"capabilities"}\n')
                    qmp_reply(stream, "capabilities")
                    state["ahci"] = {"controllers": []}
                    for abar in bars:
                        controller = {"abar": abar, "registers": {}}
                        state["ahci"]["controllers"].append(controller)
                        registers = {
                            "hba": (abar, 4),  # CAP, GHC, IS, PI
                            "port0_status": (abar + 0x110, 3),  # PxIS, PxIE, PxCMD
                            "port0_task": (abar + 0x120, 1),  # PxTFD
                            "port0_error": (abar + 0x130, 3),  # PxSERR, PxSACT, PxCI
                        }
                        for name, (address, count) in registers.items():
                            command_id = f"ahci-{abar:x}-{name}"
                            command = {"execute": "human-monitor-command", "arguments": {
                                "command-line": f"xp /{count}wx 0x{address:x}"
                            }, "id": command_id}
                            stream.write((json.dumps(command) + "\n").encode())
                            controller["registers"][name] = qmp_reply(stream, command_id)["return"]
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        state["ahci_error"] = str(error)
    path.write_text(json.dumps(state, indent=2) + "\n")


def stop_process_group(process, deadline=None):
    if deadline is None:
        deadline = time.monotonic() + 10
    def live_members():
        # The launcher shell can exit before QEMU. A second boot or disk hash must wait for
        # every non-zombie member of this private process group, not only the shell PID.
        output = subprocess.check_output(["ps", "-eo", "pgid=,stat="], text=True)
        return any(
            int(fields[0]) == process.pid and not fields[1].startswith("Z")
            for line in output.splitlines()
            if len(fields := line.split()) >= 2
        )

    if live_members():
        if time.monotonic() < deadline:
            # A guest reset leaves QEMU paused; quit through QMP before signalling.
            if QMP_SOCKET.exists() and request_quit(QMP_SOCKET):
                quit_deadline = min(time.monotonic() + 10, deadline)
                while live_members() and time.monotonic() < quit_deadline:
                    time.sleep(0.1)
        if live_members() and time.monotonic() < deadline:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            term_deadline = min(time.monotonic() + 10, deadline)
            while live_members() and time.monotonic() < term_deadline:
                time.sleep(0.1)
        if live_members():
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 10
            while live_members() and time.monotonic() < deadline:
                time.sleep(0.1)
        if live_members():
            raise RuntimeError("QEMU process group still owns the boot disk")
    process.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, default=180)
    parser.add_argument("--trace-interrupts", action="store_true")
    parser.add_argument("--interact", nargs="?", const=DEFAULT_SCRIPT, type=Path,
                            metavar="STEPS_JSON",
                        help="after the sealed Explorer desktop, drive guest input from a step "
                             "list and capture a screenshot after each step; the gate requires "
                             "every step to complete")
    args = parser.parse_args()
    if not 1 <= args.seconds <= 3600:
        parser.error("--seconds must be between 1 and 3600")
    interaction_script = None
    if args.interact is not None:
        try:
            interaction_script = load_script(args.interact)
        except (OSError, ValueError) as error:
            parser.error(f"--interact {args.interact}: {error}")
    QMP_SOCKET.unlink(missing_ok=True)
    SCREENSHOT.unlink(missing_ok=True)
    INTERRUPT_TRACE.unlink(missing_ok=True)
    INTERRUPT_TRACE_TAIL.unlink(missing_ok=True)
    STALL_STATE.unlink(missing_ok=True)
    GUEST_RESET_STATE.unlink(missing_ok=True)
    VOLUME_DISPATCH_STATE.unlink(missing_ok=True)
    CPU_SAMPLES.unlink(missing_ok=True)
    BLOCKSTATS.unlink(missing_ok=True)
    STOPPED_MARKER.unlink(missing_ok=True)
    STATIONARY_MARKER.unlink(missing_ok=True)
    POST_SETUP_IDLE_MARKER.unlink(missing_ok=True)
    INTERACTION_LOG.unlink(missing_ok=True)
    VERDICT.unlink(missing_ok=True)
    BOUND_REACHED_MARKER.unlink(missing_ok=True)
    for stale in ROOT.glob("native-kvm-interact-*.ppm"):
        stale.unlink()
    command = [
        "./scripts/run_specs.sh",
        "-qmp",
        f"unix:{QMP_SOCKET},server=on,wait=off",
        # run_specs.sh passes -no-reboot; a triple fault now pauses with its registers intact.
        *QEMU_SHUTDOWN_ACTION,
    ]
    # The workflow names the CPU model. `-cpu host` alone never exposes invariant TSC:
    # QEMU treats the bit as unmigratable, so the workflow requests `invtsc=on`. KVM
    # grants it only when the runner CPU has it, and the guest's guarded clock still
    # decides whether the calibrated fast path is safe to admit.
    if cpu_model := os.environ.get("QEMU_CPU_MODEL"):
        command += ["-cpu", cpu_model]
    if args.trace_interrupts:
        command += ["-d", "int,cpu_reset", "-D", str(INTERRUPT_TRACE)]
    with LOG.open("wb") as log:
        process = subprocess.Popen(
            command,
            cwd=MICRO,
            env=os.environ.copy(),
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        started = time.monotonic()
        deadline = started + args.seconds
        next_capture = started + 10
        next_blockstats = started + 10
        progress_offset = 0
        cpu_sample_index = 0
        next_cpu_sample = started + cpu_sample_delay(cpu_sample_index)
        captured = False
        stall_captured = False
        volume_dispatch_captured = False
        panic_detector = SerialPanicDetector(LOG)
        terminal_detector = SerialTerminalDetector(LOG)
        progress_watchdog = BootProgressWatchdog(started)
        panic_site = None
        terminal_reason = None
        quiesce_fence = None
        stationary_reason = None
        previous_sample = None
        interaction = seal_detector = None
        desktop_sealed = False
        if interaction_script is not None:
            checks = {"command-prompt": lambda name: prove_ready_prompt(ROOT / name)}
            selected_step = next((step for step in interaction_script.steps
                                  if step.name == "command-prompt-selected"), None)
            if selected_step is not None:
                target = selected_step.actions[0][1]
                checks["command-prompt-selected"] = lambda name: prove_selected_icon(
                    ROOT / interaction.cursor_receipts[-1]["file"], ROOT / name, target)
            interaction = InteractionRunner(
                interaction_script, send_input_batches,
                lambda name: capture_framebuffer(ROOT / name), INTERACTION_LOG,
                checks=checks,
                cursor_probe=lambda before, after, target: prove_cursor_position(
                    ROOT / before, ROOT / after, target))
            seal_detector = SerialPanicDetector(LOG, DESKTOP_EPOCH_SEALED_RECORD)
        def capture_terminal_evidence(reason):
            nonlocal captured, stall_captured
            if not QMP_SOCKET.exists():
                return
            try:
                capture_stall_state()
                stall_captured = True
            except OSError as error:
                print(f"QMP {reason} state capture failed: {error}", flush=True)
            try:
                capture_framebuffer()
                captured = True
                print(f"QMP {reason} framebuffer captured: {SCREENSHOT.name}", flush=True)
            except (OSError, RuntimeError, ValueError) as error:
                print(f"QMP {reason} framebuffer capture failed: {error}", flush=True)
        bound_stop = threading.Event()
        def signal_guest(sig):
            bound_stop.set()
            # A paused guest reset may ignore SIGTERM; QMP quit still exits and flushes.
            if sig == signal.SIGTERM and QMP_SOCKET.exists():
                request_quit(QMP_SOCKET)
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                pass
        soft_stop = threading.Timer(max(1, args.seconds - 15), signal_guest,
                                    args=(signal.SIGTERM,))
        # A separate hard stop bounds guest execution even if QMP or the main loop stalls.
        hard_stop = threading.Timer(args.seconds, signal_guest,
                                    args=(signal.SIGKILL,))
        soft_stop.start()
        hard_stop.start()
        try:
            while time.monotonic() < deadline:
                if not volume_dispatch_captured and QMP_SOCKET.exists() and LOG.exists():
                    if b"step=volume-sector" in LOG.read_bytes():
                        capture_stall_state(VOLUME_DISPATCH_STATE)
                        volume_dispatch_captured = True
                panic_site = panic_detector.poll()
                if panic_site:
                    print(f"Executive panic at {panic_site}; stopping bounded boot", flush=True)
                    capture_terminal_evidence("panic")
                    break
                if quiesce_fence is not None:
                    verdict = quiesce_fence.poll(time.monotonic())
                    if verdict is None:
                        if process.poll() is not None:
                            break
                        time.sleep(min(1, max(0, deadline - time.monotonic())))
                        continue
                    terminal_reason = QUIESCE_VERDICT_REASONS[verdict]
                    print(f"Quiesce hive durability {verdict}; stopping bounded boot", flush=True)
                    break
                terminal_reason = terminal_detector.poll()
                if terminal_reason == "quiesce":
                    # Capture the gate's state now; stop only after the durability fence.
                    print("Guest terminal quiesce; waiting for its hive durability verdict",
                          flush=True)
                    capture_terminal_evidence(terminal_reason)
                    quiesce_fence = QuiesceDurabilityFence(LOG, time.monotonic())
                    terminal_reason = None
                    continue
                if terminal_reason:
                    print(f"Guest terminal {terminal_reason}; stopping bounded boot", flush=True)
                    capture_terminal_evidence(terminal_reason)
                    break
                if process.poll() is not None:
                    break
                if QMP_SOCKET.exists() and guest_shutdown_paused(read_run_state(QMP_SOCKET)):
                    terminal_reason = "reset (triple fault or reset request)"
                    print(f"Guest {terminal_reason}; registers retained in "
                          f"{GUEST_RESET_STATE.name}", flush=True)
                    capture_stall_state(GUEST_RESET_STATE)
                    break
                with LOG.open("rb") as serial_stream:
                    serial_stream.seek(progress_offset)
                    while chunk := serial_stream.read(65536):
                        progress_offset += len(chunk)
                        for milestone in progress_watchdog.observe_serial(chunk, time.monotonic()):
                            print(f"Boot progress {time.monotonic() - started:.0f}s: {milestone}",
                                  flush=True)
                if (interaction is not None and not desktop_sealed
                        and seal_detector.poll() is not None):
                    desktop_sealed = True
                    if interaction_script.arm == "seal":
                        interaction.arm(time.monotonic())
                        print(f"Interaction armed {time.monotonic() - started:.0f}s: desktop "
                              f"sealed; first step after {interaction_script.settle_seconds:.0f}s",
                              flush=True)
                    else:
                        print(f"Desktop sealed {time.monotonic() - started:.0f}s; interaction "
                              "waits for the guest to go idle", flush=True)
                if interaction is not None and interaction.in_progress and QMP_SOCKET.exists():
                    for name in interaction.advance(time.monotonic()):
                        print(f"Interaction {time.monotonic() - started:.0f}s: {name}", flush=True)
                    if interaction.finished:
                        print(f"Interaction finished: {interaction.summary()}", flush=True)
                    if interaction.halted:
                        terminal_reason = "interaction checkpoint failed"
                        print("Guest interaction checkpoint failed; stopping bounded boot",
                              flush=True)
                        capture_terminal_evidence(terminal_reason)
                        break
                if time.monotonic() >= next_blockstats and QMP_SOCKET.exists():
                    try:
                        blockstats = read_bootdisk_blockstats()
                    except (OSError, RuntimeError, ValueError, KeyError):
                        blockstats = None
                    record_bootdisk_blockstats(blockstats, time.monotonic() - started)
                    if progress_watchdog.observe_blockstats(blockstats, time.monotonic()):
                        print(f"Boot progress {time.monotonic() - started:.0f}s: "
                              f"{progress_watchdog.last_milestone}", flush=True)
                    next_blockstats = time.monotonic() + 10
                # A scripted interaction holds the idle stop until its last screenshot; the
                # guest is expected to be quiet between steps. The script is finite, so the
                # ordinary idle rule (and its post-setup disk evidence) applies afterwards.
                idle_reason = (None if interaction is not None and interaction.in_progress
                               else progress_watchdog.idle_reason(time.monotonic()))
                if idle_reason and QMP_SOCKET.exists():
                    # A scheduled sample can fall just before the idle boundary while disk
                    # traffic is still advancing. Take one fresh sample before stopping QEMU.
                    sample_time = time.monotonic()
                    def threshold_blockstats():
                        reply = read_bootdisk_blockstats()
                        record_bootdisk_blockstats(reply, sample_time - started)
                        return reply
                    idle_reason = refresh_idle_progress(
                        progress_watchdog, sample_time, threshold_blockstats)
                    if idle_reason is None:
                        print(f"Boot progress {sample_time - started:.0f}s: "
                              f"{progress_watchdog.last_milestone}", flush=True)
                    next_blockstats = sample_time + 10
                if (idle_reason and interaction is not None and not interaction.armed
                        and desktop_sealed and interaction_script.arm == "idle"):
                    # The sealed guest's first idle is when its startup work is done; that is
                    # when the scripted input starts, not when the boot stops.
                    interaction.arm(time.monotonic())
                    print(f"Interaction armed {time.monotonic() - started:.0f}s: sealed desktop "
                          f"idle ({idle_reason}); first step after "
                          f"{interaction_script.settle_seconds:.0f}s", flush=True)
                    idle_reason = None
                if idle_reason:
                    stationary_reason = idle_reason
                    STATIONARY_MARKER.write_text(stationary_reason + "\n")
                    print(f"Guest stationary: {stationary_reason}; stopping bounded boot", flush=True)
                    capture_terminal_evidence("stationary")
                    break
                if (not stall_captured and time.monotonic() >= deadline - 45
                        and QMP_SOCKET.exists()):
                    capture_stall_state()
                    stall_captured = True
                if time.monotonic() >= next_capture and QMP_SOCKET.exists():
                    try:
                        capture_framebuffer()
                        captured = True
                        print(f"QMP framebuffer captured: {SCREENSHOT.name}", flush=True)
                    except (OSError, RuntimeError, ValueError) as error:
                        print(f"QMP framebuffer capture pending: {error}", flush=True)
                    next_capture = time.monotonic() + 30
                if time.monotonic() >= next_cpu_sample and QMP_SOCKET.exists():
                    try:
                        host = read_host_state(process.pid)
                    except (OSError, ValueError) as error:
                        host = {"error": str(error)}
                    try:
                        serial_bytes = LOG.stat().st_size
                    except OSError:
                        serial_bytes = None
                    serial = LOG.read_bytes()
                    cpu_state = read_cpu_state()
                    sample = {"elapsed_seconds": round(time.monotonic() - started, 3),
                              "state": cpu_state,
                              "vcpu_host": read_vcpu_host_state(process.pid, cpu_state.get("cpus")),
                              "host": host, "serial_bytes": serial_bytes,
                              "boot_marker": b"boot: reading Simpleboot memory map" in serial,
                              "desktop_ready": b"PASS exec_explorer_shell_chrome_painted" in serial}
                    retain_halted_interrupt_state(sample, read_interrupt_state)
                    with CPU_SAMPLES.open("a") as samples:
                        samples.write(json.dumps(sample) + "\n")
                    if stationary_boot_pair(previous_sample, sample):
                        stationary_reason = (f"serial unchanged and all vCPUs halted from "
                                             f"{previous_sample['elapsed_seconds']}s to "
                                             f"{sample['elapsed_seconds']}s")
                        STATIONARY_MARKER.write_text(stationary_reason + "\n")
                        print(f"Guest stationary: {stationary_reason}; stopping bounded boot", flush=True)
                        capture_terminal_evidence("stationary")
                        break
                    if ps_create_fold_stall_pair(previous_sample, sample, serial):
                        stationary_reason = (f"PsCreate fold loop with one unchanged running vCPU from "
                                             f"{previous_sample['elapsed_seconds']}s to "
                                             f"{sample['elapsed_seconds']}s")
                        STATIONARY_MARKER.write_text(stationary_reason + "\n")
                        print(f"Guest stationary: {stationary_reason}; stopping bounded boot", flush=True)
                        capture_terminal_evidence("stationary")
                        break
                    previous_sample = sample
                    cpu_sample_index += 1
                    next_cpu_sample = time.monotonic() + cpu_sample_delay(cpu_sample_index)
                time.sleep(min(1, max(0, deadline - time.monotonic())))
        finally:
            try:
                soft_stop.cancel()
                hard_stop.cancel()
                soft_stop.join()
                hard_stop.join()
                stop_process_group(process, deadline)
                STOPPED_MARKER.write_text("QEMU process group stopped and reaped\n")
            finally:
                QMP_SOCKET.unlink(missing_ok=True)
            if args.trace_interrupts and INTERRUPT_TRACE.is_file():
                with INTERRUPT_TRACE.open("rb") as trace:
                    trace.seek(0, os.SEEK_END)
                    trace.seek(max(0, trace.tell() - 131072))
                    INTERRUPT_TRACE_TAIL.write_bytes(trace.read())
                INTERRUPT_TRACE.unlink()

    serial = LOG.read_bytes()
    panic_site = panic_site or panic_detector.poll()
    if quiesce_fence is not None and terminal_reason is None:
        terminal_reason = QUIESCE_VERDICT_REASONS["unproven"]
    terminal_reason = terminal_reason or terminal_detector.poll()
    runner_failures = []
    if terminal_reason:
        runner_failures.append(f"guest terminal {terminal_reason}")
    if b"boot: reading Simpleboot memory map" not in serial:
        runner_failures.append("guest startup marker absent")
    if not captured:
        runner_failures.append("no QMP framebuffer captured")
    if stationary_reason:
        # The marker lets the workflow keep a stopped disk whose setup completed, so later
        # boots need not replay setup; it is not a pass on its own.
        evidence = post_setup_idle_evidence(serial)
        if evidence:
            POST_SETUP_IDLE_MARKER.write_text(evidence + "\n")
            print(f"Post-setup idle stop: {evidence}", flush=True)
    elif (bound_stop.is_set() and not panic_site and not terminal_reason
            and not runner_failures):
        BOUND_REACHED_MARKER.write_text(f"ran the whole {args.seconds}s bound\n")
    visual_proof = None
    if interaction is not None:
        ver_step = next(((number, step) for number, step in
                         enumerate(interaction_script.steps, 1) if step.name == "ver"), None)
        if ver_step is None:
            visual_proof = VisualProof(False, error="script has no ver step")
        else:
            visual_proof = prove_ver_result(ROOT / screenshot_name(*ver_step))
        print("Visible command result: "
              + ("verified" if visual_proof.passed else visual_proof.error), flush=True)
    outcome = (InteractionOutcome(requested=False) if interaction is None else
               InteractionOutcome(requested=True, armed=interaction.armed,
                                  completed=interaction.index,
                                  total=len(interaction_script.steps),
                                  errors=interaction.failures,
                                  checkpoints=interaction.checkpoints,
                                  cursor_receipts=interaction.cursor_receipts,
                                  visual_proof=visual_proof))
    verdict = boot_verdict(serial, outcome, runner_failures)
    if interaction is not None:
        seal = "Explorer desktop sealed" if verdict.sealed else "Explorer desktop never sealed"
        print(f"Interaction outcome: {seal}; {outcome.describe()}", flush=True)
    VERDICT.write_text(json.dumps({**verdict.to_json(), "stationary": stationary_reason,
                                   "panic_site": panic_site}, indent=2) + "\n")
    if not verdict.passed:
        raise SystemExit("KVM desktop gate failed: " + "; ".join(verdict.reasons)
                         + "; inspect native-kvm-smoke.log and native-kvm-verdict.json")
    print("KVM desktop gate passed: Explorer sealed the desktop, the scripted interaction "
          f"completed ({outcome.describe()}), the command result was visible and the log "
          "records no fault")

if __name__ == "__main__":
    main()
