#!/usr/bin/env python3
"""Bounded CI startup probe with a framebuffer capture; not desktop acceptance."""

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


ROOT = Path(__file__).resolve().parent.parent
MICRO = ROOT / "rust-micro"
LOG = ROOT / "native-kvm-smoke.log"
SCREENSHOT = ROOT / "native-kvm-smoke.ppm"
QMP_SOCKET = ROOT / "native-kvm-smoke-qmp.sock"
INTERRUPT_TRACE = MICRO / "native-kvm-qemu-int.log"
INTERRUPT_TRACE_TAIL = ROOT / "native-kvm-qemu-int-tail.log"
STALL_STATE = ROOT / "native-kvm-stall-state.json"
VOLUME_DISPATCH_STATE = ROOT / "native-kvm-volume-dispatch-state.json"
CPU_SAMPLES = ROOT / "native-kvm-cpu-samples.jsonl"
STOPPED_MARKER = ROOT / "native-kvm-qemu-stopped"
STATIONARY_MARKER = ROOT / "native-kvm-stationary.txt"

# Fixed 60-second QMP samples repeatedly hit the same clock-publication RIP,
# while the guest's own cycle counter showed that path used only a few seconds.
# Vary the phase so a periodic guest path cannot masquerade as a CPU hotspot.
CPU_SAMPLE_DELAYS = (17, 31, 43, 59)
EXECUTIVE_PANIC = re.compile(rb"!@(src/[A-Za-z0-9_./-]+\.rs:[1-9][0-9]*)\r?\n")
TERMINAL_BOOT_STOP = re.compile(
    rb"(?:^|[\r\n])("
    rb"\[quiesce\] every live process parked/waiting \(no signaler left\) -> run gate"
    rb"|\[quiesce\] no boot milestone for ~[0-9]+s wall-clock -> run gate"
    rb"|\[cm-flush\] shutdown hive durability refused status=(?:0x){1,2}[0-9a-fA-F]{8}"
    rb"|\[provider-bugcheck\] terminal"
    rb"|\[dbg\] err:\(base\\system\\winlogon\\winlogon\.c:[0-9]+\) WL: Failed to initialize Gina"
    rb")\r?\n"
)
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
SPEC_PASS = re.compile(rb" {0,2}PASS ([A-Za-z0-9_]+)")
DIRECTORY_PUBLISH_REPLY = re.compile(
    rb"\[directory-publish\] token=([0-9]+) stage=reply status=(?:0x){1,2}0+"
)
HOSTED_PROCESS_ALLOCATED = re.compile(
    rb"\[pm-dynamic\] allocated hosted process pi=[0-9]+ pid=([0-9]+) "
    rb"parent=[0-9]+ image=([^ ]+) token=[0-9]+ inherited"
)
DESKTOP_SWITCH_PREFIX = b"[win32k-desktop-switch] pi/ret/"


class BootProgressWatchdog:
    """Bound a boot by finite milestones and two real disk-I/O graces per epoch."""

    def __init__(self, started, idle_seconds=180, max_disk_extensions=2):
        self.idle_seconds = idle_seconds
        self.max_disk_extensions = max_disk_extensions
        self.last_progress = started
        self.last_milestone = "startup"
        self.armed = False
        self.disk_extensions = 0
        self.disk_bytes = None
        self.disk_checkpoint = None
        self.seen = set()
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
            if match := SETUP_PHASE_COMPLETE.fullmatch(line):
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
        self.disk_bytes = total
        if previous is None or self.disk_checkpoint is None:
            self.disk_checkpoint = total
            return False
        if (now - self.last_progress < self.idle_seconds
                or total <= self.disk_checkpoint
                or self.disk_extensions >= self.max_disk_extensions):
            return False
        self.disk_extensions += 1
        self.disk_checkpoint = total
        self.last_progress = now
        self.last_milestone = f"bootdisk completed bytes={total}"
        return True

    def idle_reason(self, now):
        if not self.armed or now - self.last_progress < self.idle_seconds:
            return None
        return (f"no boot milestone or bounded disk work for {now - self.last_progress:.0f}s; "
                f"last={self.last_milestone}, bootdisk_bytes={self.disk_bytes}")


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
                    return match.group(1).decode("ascii")
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
        if "WL: Failed to initialize Gina" in record:
            return "gina-load-failed"
        return "durability-refused"


def cpu_sample_delay(sample_index):
    return CPU_SAMPLE_DELAYS[sample_index % len(CPU_SAMPLE_DELAYS)]


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

    def halted(sample):
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

    before_cpus = halted(previous)
    return before_cpus is not None and before_cpus == halted(current)


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


def capture_framebuffer():
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
                "arguments": {"filename": str(SCREENSHOT), "format": "ppm"},
                "id": "screendump",
            }
            stream.write((json.dumps(command) + "\n").encode())
            qmp_reply(stream, "screendump")
    if not SCREENSHOT.is_file() or SCREENSHOT.stat().st_size == 0:
        raise RuntimeError("QMP did not write a framebuffer image")


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


def parse_proc_stat(stat):
    """Return process-group identity, CPU ticks, and RSS pages from /proc/PID/stat."""
    # comm is parenthesized and may itself contain spaces or closing parentheses.
    fields = stat.rpartition(") ")[2].split()
    if len(fields) < 22:
        raise ValueError("incomplete process stat")
    return int(fields[2]), int(fields[11]) + int(fields[12]), int(fields[21])


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
    """Keep per-CPU and AHCI register evidence at a proof frontier or stall."""
    state = read_cpu_state()
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
    args = parser.parse_args()
    if not 1 <= args.seconds <= 3600:
        parser.error("--seconds must be between 1 and 3600")
    QMP_SOCKET.unlink(missing_ok=True)
    SCREENSHOT.unlink(missing_ok=True)
    INTERRUPT_TRACE.unlink(missing_ok=True)
    INTERRUPT_TRACE_TAIL.unlink(missing_ok=True)
    STALL_STATE.unlink(missing_ok=True)
    VOLUME_DISPATCH_STATE.unlink(missing_ok=True)
    CPU_SAMPLES.unlink(missing_ok=True)
    STOPPED_MARKER.unlink(missing_ok=True)
    STATIONARY_MARKER.unlink(missing_ok=True)
    command = [
        "./scripts/run_specs.sh",
        "-qmp",
        f"unix:{QMP_SOCKET},server=on,wait=off",
    ]
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
        stationary_reason = None
        previous_sample = None
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
        def signal_guest(sig):
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
                terminal_reason = terminal_detector.poll()
                if terminal_reason:
                    print(f"Guest terminal {terminal_reason}; stopping bounded boot", flush=True)
                    capture_terminal_evidence(terminal_reason)
                    break
                if process.poll() is not None:
                    break
                with LOG.open("rb") as serial_stream:
                    serial_stream.seek(progress_offset)
                    while chunk := serial_stream.read(65536):
                        progress_offset += len(chunk)
                        for milestone in progress_watchdog.observe_serial(chunk, time.monotonic()):
                            print(f"Boot progress {time.monotonic() - started:.0f}s: {milestone}",
                                  flush=True)
                if time.monotonic() >= next_blockstats and QMP_SOCKET.exists():
                    try:
                        blockstats = read_bootdisk_blockstats()
                    except (OSError, RuntimeError, ValueError, KeyError):
                        blockstats = None
                    if progress_watchdog.observe_blockstats(blockstats, time.monotonic()):
                        print(f"Boot progress {time.monotonic() - started:.0f}s: "
                              f"{progress_watchdog.last_milestone}", flush=True)
                    next_blockstats = time.monotonic() + 10
                idle_reason = progress_watchdog.idle_reason(time.monotonic())
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
                    sample = {"elapsed_seconds": round(time.monotonic() - started, 3),
                              "state": read_cpu_state(),
                              "host": host, "serial_bytes": serial_bytes,
                              "boot_marker": b"boot: reading Simpleboot memory map" in serial,
                              "desktop_ready": b"PASS exec_explorer_shell_chrome_painted" in serial}
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

    output = LOG.read_text(errors="replace")
    panic_site = panic_site or panic_detector.poll()
    terminal_reason = terminal_reason or terminal_detector.poll()
    if panic_site:
        raise SystemExit(f"executive panic at {panic_site}; inspect native-kvm-smoke.log")
    if terminal_reason:
        raise SystemExit(f"guest terminal {terminal_reason}; inspect native-kvm-smoke.log")
    if stationary_reason:
        raise SystemExit(f"guest stationary: {stationary_reason}; inspect native-kvm-stationary.txt")
    if "boot: reading Simpleboot memory map" not in output:
        raise SystemExit("guest startup marker absent; inspect native-kvm-smoke.log")
    if not captured:
        raise SystemExit("no QMP framebuffer captured; inspect native-kvm-smoke.log")
    print("KVM smoke passed: guest started and QMP framebuffer was captured")
    print("This probe does not establish Explorer desktop acceptance")


if __name__ == "__main__":
    main()
