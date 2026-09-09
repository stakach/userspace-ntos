#!/usr/bin/env python3
"""Execute unmodified ntdll PE exports against a destructive transport test double.

Install ntdll_native_stubs.requirements.txt into an isolated virtual environment, then:
    python tools/tests/ntdll_native_stubs.py .tmp/nt-ntdll.dll \
        --negative-dll .tmp/nt-ntdll-pre-producer-consolidation.dll

Only SYSCALL is intercepted. DLL instructions, entry points, and code bytes are unchanged;
DllMain and imported libraries are not executed. This proves producer machine-code behavior,
not microkernel Call/Reply, scheduling, or native thread-context acceptance.

API references:
https://www.unicorn-engine.org/docs/tutorial.html
https://pefile.readthedocs.io/en/latest/modules/pefile.html
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct
import sys
import time
from dataclasses import dataclass

import pefile
import unicorn
from unicorn import x86_const as x86


PAGE = 0x1000
MASK64 = (1 << 64) - 1
MAX_IMAGE_BYTES = 256 * 1024 * 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_INSTRUCTIONS = 20_000
EMU_TIMEOUT_US = 1_000_000
MAX_SUITE_SECONDS = 60

# Deliberately independent expectations from crates/nt-syscall-abi/src/lib.rs. Keeping these
# literal checks makes an incompatible generated producer fail rather than redefine its oracle.
NATIVE_LABEL = 0x4E54
RETRY_REPLY = 0x4E54_5254_5259_0001
FAULT_ENDPOINT = 6
MAIN_IPC = 0x0000_0100_105F_B000
SEC_IMAGE_TEB = 0x0000_0100_1600_0000
PE_MAIN_TEB = 0x0000_0100_0057_0000
WORKER_TEB = 0x0000_0100_2100_0000
WORKER_IPC_DELTA = 0x10000
STACK_BASE = 0x0000_0040_0000_0000
STACK_BYTES = 0x4000
ENTRY_RSP = STACK_BASE + 0x2008
RETURN_ADDRESS = STACK_BASE + 0x100000
STATUS = 0xC000_0001


@dataclass(frozen=True)
class Service:
    name: str
    ssn: int
    argc: int


SERVICES = (
    Service("NtTestAlert", 268, 0),
    Service("NtClose", 27, 1),
    Service("NtSetEvent", 228, 2),
    Service("NtWaitForSingleObject", 281, 3),
    Service("NtCreateDebugObject", 35, 4),
    Service("NtAllocateVirtualMemory", 18, 6),
    Service("NtMapViewOfSection", 113, 10),
    Service("NtCreateNamedPipeFile", 46, 14),
)
TEBS = (
    ("sec-image-main", SEC_IMAGE_TEB, MAIN_IPC),
    ("pe-main", PE_MAIN_TEB, MAIN_IPC),
    ("worker", WORKER_TEB, WORKER_TEB - WORKER_IPC_DELTA),
)


class OracleFailure(Exception):
    def __init__(self, category: str, message: str):
        self.category = category
        super().__init__(f"{category}: {message}")


def require(condition: bool, category: str, message: str) -> None:
    if not condition:
        raise OracleFailure(category, message)


def words(values: tuple[int, ...] | list[int]) -> bytes:
    return struct.pack(f"<{len(values)}Q", *values)


@dataclass(frozen=True)
class Artifact:
    path: Path
    digest: str
    base: int
    size: int
    image: bytes
    exports: dict[str, int]

    @classmethod
    def load(cls, path: Path) -> Artifact:
        require(0 < path.stat().st_size <= MAX_FILE_BYTES, "artifact", "bounded DLL file size")
        raw = path.read_bytes()
        pe = pefile.PE(data=raw, fast_load=True)
        try:
            require(pe.FILE_HEADER.Machine == 0x8664, "artifact", "DLL must be AMD64")
            require(pe.OPTIONAL_HEADER.Magic == 0x20B, "artifact", "DLL must be PE32+")
            base = pe.OPTIONAL_HEADER.ImageBase
            size = pe.OPTIONAL_HEADER.SizeOfImage
            require(0 < size <= MAX_IMAGE_BYTES, "artifact", "bounded mapped DLL size")
            require(base % PAGE == 0 and size % PAGE == 0, "artifact", "page-aligned PE image")
            require(0 < base < base + size < (1 << 47), "artifact", "canonical user PE mapping")
            for section in pe.sections:
                va = section.VirtualAddress
                raw_size = section.SizeOfRawData
                raw_offset = section.PointerToRawData
                span = max(section.Misc_VirtualSize, raw_size)
                require(0 <= va <= size and span <= size - va, "artifact", "section image span")
                require(
                    0 <= raw_offset <= len(raw) and raw_size <= len(raw) - raw_offset,
                    "artifact", "section file span",
                )
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
            )
            require(hasattr(pe, "DIRECTORY_ENTRY_EXPORT"), "artifact", "export table missing")
            exports = {}
            for service in SERVICES:
                matches = [
                    symbol for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols
                    if symbol.name == service.name.encode("ascii")
                ]
                require(len(matches) == 1, "artifact", f"exact export {service.name}")
                symbol = matches[0]
                require(symbol.forwarder is None, "artifact", f"{service.name} is forwarded")
                rva = symbol.address
                section = pe.get_section_by_rva(rva)
                require(
                    section is not None
                    and section.Characteristics & 0x20000000 != 0
                    and section.VirtualAddress <= rva < section.VirtualAddress + section.SizeOfRawData,
                    "artifact", f"{service.name} lacks actual executable file bytes",
                )
                exports[service.name] = base + rva
            image = pe.get_memory_mapped_image()
            require(len(image) <= size, "artifact", "mapped PE exceeds SizeOfImage")
            image += bytes(size - len(image))
            return cls(path.resolve(), hashlib.sha256(raw).hexdigest(), base, size, image, exports)
        finally:
            pe.close()


@dataclass(frozen=True)
class Reply:
    info: int
    status: int


class Probe:
    def __init__(
        self,
        artifact: Artifact,
        service: Service,
        teb_name: str,
        teb: int,
        ipc: int,
        replies: tuple[Reply, ...],
        *,
        check_composed_destinations: bool = True,
    ):
        self.artifact = artifact
        self.service = service
        self.name = f"{service.name}/{teb_name}"
        self.teb = teb
        self.ipc = ipc
        self.replies = replies
        self.check_composed_destinations = check_composed_destinations
        self.calls = 0
        self.instructions = 0
        self.first_message: tuple[int, ...] | None = None
        self.first_call_rsp: int | None = None
        self.failure: OracleFailure | None = None
        self.arguments = tuple(
            (0xA170_0000_0000_0000 | service.ssn << 32 | index * 0x10101 | 0x80)
            for index in range(service.argc)
        )
        self.mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        self.mu.mem_map(artifact.base, artifact.size)
        self.mu.mem_write(artifact.base, artifact.image)
        self.mu.mem_protect(artifact.base, artifact.size, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
        self.mu.mem_map(STACK_BASE, STACK_BYTES, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
        self.mu.mem_write(STACK_BASE, bytes((i * 37 + 0xA9) & 0xFF for i in range(STACK_BYTES)))
        self.mu.mem_map(RETURN_ADDRESS, PAGE, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
        self.mu.mem_map(teb, PAGE)
        self.mu.mem_write(teb, bytes([0x6C]) * PAGE)
        self.mu.mem_write(teb + 0x30, words((teb,)))
        self.mu.mem_protect(teb, PAGE, unicorn.UC_PROT_READ)
        self.mu.mem_map(ipc, PAGE, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
        self.poison_ipc(0)

        for index, name in enumerate((
            "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "R8", "R9", "R10",
            "R11", "R12", "R13", "R14", "R15",
        )):
            self.write_reg(name, 0x1122_3344_5566_7700 + index)
        self.write_reg("RSP", ENTRY_RSP)
        self.write_reg("EFLAGS", 0x202)
        self.write_reg("GS_BASE", teb)
        for index in range(16):
            self.write_reg(f"XMM{index}", (0xAABB_CC00_0000_0000 + index) << 64 | 0x1234_5678_0000_0000 + index)
        self.write_reg("MXCSR", 0x1F80)
        for name, arg in zip(("RCX", "RDX", "R8", "R9"), self.arguments):
            self.write_reg(name, arg)
        self.mu.mem_write(ENTRY_RSP, words((RETURN_ADDRESS,)))
        if service.argc > 4:
            self.mu.mem_write(ENTRY_RSP + 40, words(self.arguments[4:]))
        self.preserved = {
            name: self.read_reg(name)
            for name in ("RBX", "RBP", "RDI", "RSI", "R12", "R13", "R14", "R15")
        }
        self.preserved_xmm = {f"XMM{i}": self.read_reg(f"XMM{i}") for i in range(6, 16)}
        self.canaries = {
            (STACK_BASE, 0x800): bytes(self.mu.mem_read(STACK_BASE, 0x800)),
            (ENTRY_RSP, 0x800): bytes(self.mu.mem_read(ENTRY_RSP, 0x800)),
            (STACK_BASE + STACK_BYTES - 0x800, 0x800): bytes(
                self.mu.mem_read(STACK_BASE + STACK_BYTES - 0x800, 0x800)
            ),
        }
        self.mu.hook_add(unicorn.UC_HOOK_CODE, self.on_code)
        self.mu.hook_add(unicorn.UC_HOOK_INSN, self.on_syscall, None, 1, 0, x86.UC_X86_INS_SYSCALL)

    def read_reg(self, name: str) -> int:
        return self.mu.reg_read(getattr(x86, f"UC_X86_REG_{name}"))

    def write_reg(self, name: str, value: int) -> None:
        self.mu.reg_write(getattr(x86, f"UC_X86_REG_{name}"), value)

    def poison_ipc(self, round_number: int) -> None:
        self.mu.mem_write(self.ipc, words(tuple(
            0xD3AD_0000_0000_0000 | round_number << 32 | index
            for index in range(PAGE // 8)
        )))

    def verify_canaries(self) -> None:
        for (address, length), expected in self.canaries.items():
            actual = bytes(self.mu.mem_read(address, length))
            require(actual == expected, "caller-stack", f"{self.name}: canary/args changed at {address:#x}")

    def on_code(self, _mu: unicorn.Uc, address: int, _size: int, _user_data: object) -> None:
        self.instructions += 1
        if not self.artifact.base <= address < self.artifact.base + self.artifact.size:
            self.failure = OracleFailure("execution", f"{self.name}: escaped DLL at {address:#x}")
            self.mu.emu_stop()

    def on_syscall(self, _mu: unicorn.Uc, _user_data: object) -> None:
        try:
            self.transport_call()
        except OracleFailure as error:
            self.failure = error
            self.mu.emu_stop()

    def transport_call(self) -> None:
        require(self.calls < len(self.replies), "unexpected-call", f"{self.name}: surplus/replayed syscall")
        if self.check_composed_destinations:
            for name in ("R12", "R13"):
                require(
                    self.read_reg(name) == 0, "composed-reply-destination",
                    f"{self.name}: {name}={self.read_reg(name):#x} on call {self.calls + 1}",
                )
        expected_info = NATIVE_LABEL << 12 | self.service.argc + 2
        require(
            self.read_reg("RSI") == expected_info
            and self.read_reg("RDI") == FAULT_ENDPOINT
            and self.read_reg("RDX") == MASK64,
            "request-envelope",
            f"{self.name}: call {self.calls + 1} info={self.read_reg('RSI'):#x}, "
            f"endpoint={self.read_reg('RDI'):#x}, operation={self.read_reg('RDX'):#x}",
        )
        message = tuple(self.read_reg(name) for name in ("R10", "R8", "R9", "R15"))
        message = message[:self.service.argc + 2]
        if self.service.argc > 2:
            message += struct.unpack(
                f"<{self.service.argc - 2}Q", self.mu.mem_read(self.ipc + 0x28, (self.service.argc - 2) * 8)
            )
        expected = (self.service.ssn, ENTRY_RSP) + self.arguments
        require(
            message == expected,
            "retry-vector" if self.calls else "initial-vector",
            f"{self.name}: call {self.calls + 1} message "
            f"{tuple(hex(word) for word in message)} != {tuple(hex(word) for word in expected)}",
        )
        if self.first_message is None:
            self.first_message = message
            self.first_call_rsp = self.read_reg("RSP")
        require(message == self.first_message, "retry-vector", f"{self.name}: changed original vector")
        require(
            self.read_reg("RSP") == self.first_call_rsp
            and STACK_BASE + 0x800 <= self.read_reg("RSP") < ENTRY_RSP,
            "producer-stack", f"{self.name}: unstable or out-of-bounds stub frame",
        )
        self.verify_canaries()
        reply = self.replies[self.calls]
        self.calls += 1

        # The transport is intentionally destructive: no retry may obtain an argument, stack
        # coordinate, endpoint, IPC pointer, or composed destination from a previous reply.
        self.poison_ipc(self.calls)
        for index, name in enumerate((
            "RAX", "RCX", "RDX", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13", "R15",
        )):
            self.write_reg(name, 0xBAD0_0000_0000_0000 | self.calls << 32 | index)
        for index in range(6):
            self.write_reg(f"XMM{index}", (0xDEAD_0000_0000_0000 | self.calls) << 64 | index)
        self.write_reg("EFLAGS", 0x246)  # The Win64 ABI requires DF clear, not preserved arithmetic flags.
        self.write_reg("RSI", reply.info)
        self.write_reg("R10", reply.status)

    def run(self, *, invalid_reply: bool = False) -> int:
        error = None
        started = time.monotonic()
        try:
            self.mu.emu_start(
                self.artifact.exports[self.service.name], RETURN_ADDRESS,
                timeout=EMU_TIMEOUT_US, count=MAX_INSTRUCTIONS,
            )
        except unicorn.UcError as caught:
            error = caught
        if self.failure is not None:
            raise self.failure
        elapsed = time.monotonic() - started
        require(elapsed < 3, "execution-limit", f"{self.name}: emulation exceeded wall limit")
        require(self.instructions < MAX_INSTRUCTIONS, "execution-limit", f"{self.name}: instruction limit")
        self.verify_canaries()
        require(self.calls == len(self.replies), "call-count", f"{self.name}: got {self.calls} transport calls")
        if invalid_reply:
            require(
                error is not None and error.errno == unicorn.UC_ERR_INSN_INVALID,
                "reply-rejection", f"{self.name}: malformed envelope did not fault at UD2: {error}",
            )
            require(
                bytes(self.mu.mem_read(self.read_reg("RIP"), 2)) == b"\x0f\x0b",
                "reply-rejection", f"{self.name}: malformed reply failed somewhere other than UD2",
            )
            return self.instructions
        require(error is None, "execution", f"{self.name}: {error}")
        require(self.read_reg("RIP") == RETURN_ADDRESS, "execution-limit", f"{self.name}: did not return")
        require(self.read_reg("RSP") == ENTRY_RSP + 8, "caller-stack", f"{self.name}: wrong post-RET RSP")
        require(self.read_reg("RAX") == self.replies[-1].status, "return-value", f"{self.name}: terminal status")
        for name, expected in self.preserved.items():
            require(self.read_reg(name) == expected, "win64-register", f"{self.name}: {name} not preserved")
        for name, expected in self.preserved_xmm.items():
            require(self.read_reg(name) == expected, "win64-xmm", f"{self.name}: {name} not preserved")
        require(self.read_reg("MXCSR") == 0x1F80, "win64-fp", f"{self.name}: MXCSR changed")
        require(
            bytes(self.mu.mem_read(self.teb + 0x30, 8)) == words((self.teb,)),
            "thread-identity", f"{self.name}: TEB self pointer changed",
        )
        return self.instructions


def positive_suite(artifact: Artifact, deadline: float) -> int:
    cases = 0
    for service in SERVICES:
        for name, teb, ipc in TEBS:
            require(time.monotonic() < deadline, "suite-limit", "suite deadline")
            probe = Probe(
                artifact, service, name, teb, ipc,
                (Reply(6, RETRY_REPLY), Reply(6, RETRY_REPLY), Reply(1, STATUS)),
            )
            instructions = probe.run()
            print(f"PASS {probe.name}: 3 identical calls, destructive retries, Win64 preserved ({instructions} instructions)")
            cases += 1
    service = SERVICES[-1]
    name, teb, ipc = TEBS[-1]
    probe = Probe(artifact, service, name, teb, ipc, (Reply(1, RETRY_REPLY),))
    probe.run()
    print("PASS one-word retry sentinel returned as ordinary status")
    cases += 1
    malformed = (
        ("zero-length", Reply(0, STATUS)),
        ("wrong-label", Reply(1 << 12 | 1, STATUS)),
        ("extra-cap", Reply(1 << 9 | 1, STATUS)),
        ("unwrapped-cap", Reply(1 << 7 | 1, STATUS)),
        ("wrong-retry-status", Reply(6, STATUS)),
        ("two-word-status", Reply(2, STATUS)),
        ("short-retry", Reply(5, RETRY_REPLY)),
    )
    for label, reply in malformed:
        require(time.monotonic() < deadline, "suite-limit", "suite deadline")
        probe = Probe(artifact, service, name, teb, ipc, (reply,))
        instructions = probe.run(invalid_reply=True)
        print(f"PASS malformed {label}: UD2 without replay ({instructions} instructions)")
        cases += 1
    return cases


def negative_control(artifact: Artifact) -> None:
    name, teb, ipc = TEBS[-1]
    service = next(service for service in SERVICES if service.name == "NtMapViewOfSection")
    for check_composed, category, completed_calls in (
        (True, "composed-reply-destination", 0),
        (False, "retry-vector", 1),
    ):
        # Isolate the two defects in the same unchanged artifact. Only the second negative probe
        # suppresses the composed-destination assertion; all poisoning and vector checks remain.
        # Every positive case retains the assertion through the constructor's default.
        probe = Probe(
            artifact, service, name, teb, ipc,
            (Reply(6, RETRY_REPLY), Reply(6, RETRY_REPLY), Reply(1, STATUS)),
            check_composed_destinations=check_composed,
        )
        try:
            probe.run()
        except OracleFailure as error:
            require(
                error.category == category and probe.calls == completed_calls,
                "negative-control",
                f"expected {category} after {completed_calls} valid calls; "
                f"got {probe.calls} calls and {error}",
            )
            print(f"PASS negative control {category} sha256={artifact.digest}: {error}")
            continue
        raise OracleFailure("negative-control", f"old artifact unexpectedly passed {category} checks")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("dll", type=Path)
    parser.add_argument("--negative-dll", type=Path, help="old unmodified native producer DLL which must fail")
    args = parser.parse_args()
    deadline = time.monotonic() + MAX_SUITE_SECONDS
    try:
        artifact = Artifact.load(args.dll)
        print(f"Artifact: {artifact.path} sha256={artifact.digest}")
        print(f"Emulator: unicorn {unicorn.__version__}; parser: pefile {pefile.__version__}")
        cases = positive_suite(artifact, deadline)
        if args.negative_dll is not None:
            require(time.monotonic() < deadline, "suite-limit", "suite deadline")
            old = Artifact.load(args.negative_dll)
            require(old.digest != artifact.digest, "negative-control", "old and new DLL are identical")
            negative_control(old)
        print(f"PASS {cases} actual-PE producer cases; emulated transport only, no kernel acceptance claimed")
        return 0
    except (OracleFailure, OSError, pefile.PEFormatError, unicorn.UcError) as error:
        print(f"FAIL {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
