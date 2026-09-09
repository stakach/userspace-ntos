#!/usr/bin/env python3
"""Execute the DLL's own RtlVirtualUnwind over interrupted native-stub states.

Uses ntdll_native_stubs.requirements.txt and the unchanged PE image at its preferred base:
    python tools/tests/ntdll_native_unwind.py .tmp/nt-ntdll.dll \
        --negative-dll .tmp/nt-ntdll-pre-native-unwind.dll

The producer runs against the existing destructive transport oracle. Its actual instruction
boundaries and stack bytes become inputs to the actual exported RtlVirtualUnwind machine code.
No Python unwind implementation or substituted exception runtime is used. Any syscall made by
the unwinder itself is a dependency failure, not a request the harness emulates.

Each boundary is exercised with NULL and non-NULL ContextPointers. Only pointer slots for
registers actually restored by this five-push frame may change. Neither hardware fault delivery
nor exception propagation across compiled extern ABI frames is proved.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import struct
import sys
import time

import pefile
import unicorn

from ntdll_native_stubs import (
    Artifact, ENTRY_RSP, MASK64, OracleFailure, PAGE, Probe, Reply, RETRY_REPLY,
    RETURN_ADDRESS, SERVICES, STACK_BASE, STACK_BYTES, STATUS, TEBS, require, words,
)


CONTEXT_BYTES = 0x4D0
CONTEXT_GPRS = (
    "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI", "R8", "R9", "R10",
    "R11", "R12", "R13", "R14", "R15",
)
CONTEXT_GPR_OFFSETS = {name: 0x78 + index * 8 for index, name in enumerate(CONTEXT_GPRS)}
UNWIND_STACK = STACK_BASE + 0x200000
UNWIND_STACK_BYTES = 0x10000
UNWIND_RSP = UNWIND_STACK + 0xF008
UNWIND_RETURN = STACK_BASE + 0x300000
OUTPUT_BASE = STACK_BASE + 0x400000
CONTEXT_ADDRESS = OUTPUT_BASE + 0x100
HANDLER_DATA = OUTPUT_BASE + 0x700
ESTABLISHER = OUTPUT_BASE + 0x740
CONTEXT_POINTERS = OUTPUT_BASE + 0x800
CONTEXT_POINTER_WORDS = tuple(0xFACE_0000_0000_0000 + index * 0x101 for index in range(32))
MAX_UNWIND_INSTRUCTIONS = 100_000
MAX_SNAPSHOTS = 1024
MAX_SUITE_SECONDS = 120
PROLOGUE_BOUNDARIES = frozenset((0, 1, 2, 4, 6, 8, 15))
EPILOGUE_BOUNDARIES = frozenset((223, 230, 232, 234, 236, 237, 238))


def expected_context_pointers(control_offset: int) -> tuple[int, ...]:
    expected = list(CONTEXT_POINTER_WORDS)
    # Golden addresses for the already-verified fixed producer prologue. At a prologue PC only
    # completed pushes exist; at an epilogue PC only pops not yet executed restore a register.
    for register, push_end, stack_offset, pop_pc in (
        (7, 1, 8, 237), (6, 2, 16, 236), (15, 4, 24, 234),
        (12, 6, 32, 232), (13, 8, 40, 230),
    ):
        restored = control_offset <= pop_pc if control_offset >= 223 else control_offset >= push_end
        if restored:
            expected[16 + register] = ENTRY_RSP - stack_offset
    return tuple(expected)


@dataclass(frozen=True)
class FunctionMetadata:
    begin: int
    end: int
    row: int
    unwind_rva: int
    prologue_bytes: int


def load_metadata(artifact: Artifact) -> tuple[int, dict[str, FunctionMetadata]]:
    pe = pefile.PE(str(artifact.path), fast_load=True)
    try:
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"],
        ])
        unwind_exports = [
            symbol for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols
            if symbol.name == b"RtlVirtualUnwind"
        ]
        require(len(unwind_exports) == 1, "artifact", "one RtlVirtualUnwind export required")
        export = unwind_exports[0]
        section = pe.get_section_by_rva(export.address)
        require(
            export.forwarder is None and section is not None
            and section.Characteristics & 0x20000000 != 0
            and section.VirtualAddress <= export.address < section.VirtualAddress + section.SizeOfRawData,
            "artifact", "RtlVirtualUnwind requires actual executable DLL bytes",
        )
        entries = getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", ())
        metadata = {}
        for service in SERVICES:
            rva = artifact.exports[service.name] - artifact.base
            matches = [
                entry for entry in entries
                if entry.struct.BeginAddress <= rva < entry.struct.EndAddress
            ]
            require(len(matches) == 1, "missing-native-metadata", f"{service.name}: exact covering pdata row")
            entry = matches[0]
            info = entry.unwindinfo
            require(
                entry.struct.BeginAddress == rva and entry.struct.EndAddress == rva + 239,
                "native-metadata", f"{service.name}: runtime row must cover the exact direct stub body",
            )
            require(
                info is not None and info.Version == 1 and info.Flags == 0
                and info.SizeOfProlog == 15 and info.CountOfCodes == 6
                and info.FrameRegister == 0 and info.FrameOffset == 0,
                "native-metadata", f"{service.name}: unexpected native UNWIND_INFO header",
            )
            codes = info.UnwindCodes
            require(len(codes) == 6, "native-metadata", f"{service.name}: six unwind operations")
            require(
                codes[0].struct.CodeOffset == 15 and codes[0].struct.UnwindOp == 2
                and codes[0].get_alloc_size() == 128,
                "native-metadata", f"{service.name}: final prologue allocation must be 128 bytes",
            )
            for code, (offset, register) in zip(codes[1:], ((8, 13), (6, 12), (4, 15), (2, 6), (1, 7))):
                require(
                    code.struct.CodeOffset == offset and code.struct.UnwindOp == 0
                    and code.struct.Reg == register,
                    "native-metadata", f"{service.name}: exact saved register/offset metadata",
                )
            row_rva = pe.get_rva_from_offset(entry.struct.get_file_offset())
            require(
                artifact.image[row_rva:row_rva + 12] == entry.struct.__pack__(),
                "native-metadata", f"{service.name}: pass the actual mapped pdata row, not a copy",
            )
            metadata[service.name] = FunctionMetadata(
                artifact.base + entry.struct.BeginAddress,
                artifact.base + entry.struct.EndAddress,
                artifact.base + row_rva,
                entry.struct.UnwindData,
                info.SizeOfProlog,
            )
        return artifact.base + export.address, metadata
    finally:
        pe.close()


@dataclass(frozen=True)
class Snapshot:
    pc: int
    completed_calls: int
    context: bytes
    stack: bytes


class UnwindProbe(Probe):
    def __init__(self, artifact: Artifact, service_name: str):
        self.capturing = True
        self.snapshots: dict[tuple[int, int], Snapshot] = {}
        self.unwind_instructions = 0
        service = next(service for service in SERVICES if service.name == service_name)
        name, teb, ipc = TEBS[-1]
        super().__init__(
            artifact, service, name, teb, ipc,
            (Reply(6, RETRY_REPLY), Reply(6, RETRY_REPLY), Reply(1, STATUS)),
        )

    def raw_context(self, pc: int) -> bytes:
        context = bytearray([0xCD]) * CONTEXT_BYTES
        struct.pack_into("<I", context, 0x30, 0x10000B)
        struct.pack_into("<I", context, 0x34, self.read_reg("MXCSR"))
        struct.pack_into("<I", context, 0x44, self.read_reg("EFLAGS"))
        for name, offset in CONTEXT_GPR_OFFSETS.items():
            struct.pack_into("<Q", context, offset, self.read_reg(name))
        struct.pack_into("<Q", context, 0xF8, pc)
        for index in range(16):
            value = self.read_reg(f"XMM{index}")
            struct.pack_into("<QQ", context, 0x1A0 + index * 16, value & MASK64, value >> 64)
        return bytes(context)

    def on_code(self, mu: unicorn.Uc, address: int, size: int, user_data: object) -> None:
        if not self.capturing:
            self.unwind_instructions += 1
            if not self.artifact.base <= address < self.artifact.base + self.artifact.size:
                self.failure = OracleFailure("unwinder-dependency", f"escaped DLL at {address:#x}")
                self.mu.emu_stop()
            return
        super().on_code(mu, address, size, user_data)
        if self.failure is not None:
            return
        key = (address, self.calls)
        if key not in self.snapshots:
            if len(self.snapshots) >= MAX_SNAPSHOTS:
                self.failure = OracleFailure("execution-limit", "too many producer instruction boundaries")
                self.mu.emu_stop()
                return
            self.snapshots[key] = Snapshot(
                address, self.calls, self.raw_context(address),
                bytes(self.mu.mem_read(STACK_BASE, STACK_BYTES)),
            )

    def on_syscall(self, mu: unicorn.Uc, user_data: object) -> None:
        if self.capturing:
            super().on_syscall(mu, user_data)
        else:
            self.failure = OracleFailure(
                "unwinder-dependency", f"RtlVirtualUnwind called SYSCALL at {self.read_reg('RIP'):#x}"
            )
            self.mu.emu_stop()

    def prepare_unwinder(self) -> None:
        self.capturing = False
        self.mu.mem_map(UNWIND_STACK, UNWIND_STACK_BYTES, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
        self.mu.mem_map(UNWIND_RETURN, PAGE, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
        self.mu.mem_map(OUTPUT_BASE, PAGE, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)

    def unwind_snapshot(
        self, entry: int, metadata: FunctionMetadata, snapshot: Snapshot, *, with_pointers: bool = False,
    ) -> int:
        self.failure = None
        self.unwind_instructions = 0
        self.mu.mem_write(STACK_BASE, snapshot.stack)
        self.mu.mem_write(UNWIND_STACK, bytes([0xA7]) * UNWIND_STACK_BYTES)
        self.mu.mem_write(OUTPUT_BASE, bytes([0xBC]) * PAGE)
        self.mu.mem_write(CONTEXT_ADDRESS, snapshot.context)
        self.mu.mem_write(CONTEXT_POINTERS, words(CONTEXT_POINTER_WORDS))
        self.mu.mem_write(UNWIND_RSP, words((UNWIND_RETURN,)))
        self.mu.mem_write(UNWIND_RSP + 40, words((
            CONTEXT_ADDRESS, HANDLER_DATA, ESTABLISHER, CONTEXT_POINTERS if with_pointers else 0,
        )))
        for index, name in enumerate(CONTEXT_GPRS):
            self.write_reg(name, 0x2233_4455_6677_8800 + index)
        self.write_reg("RSP", UNWIND_RSP)
        self.write_reg("RCX", 0)  # UNW_FLAG_NHANDLER
        self.write_reg("RDX", self.artifact.base)
        self.write_reg("R8", snapshot.pc)
        self.write_reg("R9", metadata.row)
        self.write_reg("EFLAGS", 0x202)
        native_saved = {name: self.read_reg(name) for name in self.preserved}
        native_xmm = {name: self.read_reg(name) for name in self.preserved_xmm}
        native_mxcsr = self.read_reg("MXCSR")
        output_before = bytes(self.mu.mem_read(OUTPUT_BASE, PAGE))
        # The callee may use its shadow area and incoming by-value argument slots. Guard the
        # caller memory beyond those eight declared arguments, not the callee-owned slots.
        frame_tail_before = bytes(self.mu.mem_read(UNWIND_RSP + 72, 0x100))
        error = None
        started = time.monotonic()
        try:
            self.mu.emu_start(entry, UNWIND_RETURN, timeout=1_000_000, count=MAX_UNWIND_INSTRUCTIONS)
        except unicorn.UcError as caught:
            error = caught
        if self.failure is not None:
            raise self.failure
        require(error is None, "unwinder-execution", f"{self.name} PC+{snapshot.pc - metadata.begin:#x}: {error}")
        require(
            time.monotonic() - started < 3 and self.unwind_instructions < MAX_UNWIND_INSTRUCTIONS
            and self.read_reg("RIP") == UNWIND_RETURN,
            "execution-limit", f"{self.name}: RtlVirtualUnwind did not return within limits",
        )
        require(self.read_reg("RAX") == 0, "unwind-handler", "native stub must have no exception handler")
        require(self.read_reg("RSP") == UNWIND_RSP + 8, "unwinder-abi", "wrong RtlVirtualUnwind return RSP")
        for name, value in native_saved.items():
            require(self.read_reg(name) == value, "unwinder-abi", f"RtlVirtualUnwind clobbered {name}")
        for name, value in native_xmm.items():
            require(self.read_reg(name) == value, "unwinder-abi", f"RtlVirtualUnwind clobbered {name}")
        require(self.read_reg("MXCSR") == native_mxcsr, "unwinder-abi", "RtlVirtualUnwind changed MXCSR")
        actual = bytes(self.mu.mem_read(CONTEXT_ADDRESS, CONTEXT_BYTES))
        for name, expected in self.preserved.items():
            value = struct.unpack_from("<Q", actual, CONTEXT_GPR_OFFSETS[name])[0]
            require(
                value == expected, "unwind-register",
                f"{self.name} PC+{snapshot.pc - metadata.begin:#x}/after-call-{snapshot.completed_calls}: "
                f"{name}={value:#x}, caller={expected:#x}",
            )
        for name, offset in CONTEXT_GPR_OFFSETS.items():
            if name != "RSP" and name not in self.preserved:
                require(
                    actual[offset:offset + 8] == snapshot.context[offset:offset + 8],
                    "unwind-register", f"unwind codes must not modify volatile {name}",
                )
        # NT5 RtlVirtualUnwind: without a frame register, the establisher is the input RSP.
        require(
            bytes(self.mu.mem_read(ESTABLISHER, 8)) == snapshot.context[0x98:0xA0],
            "unwind-establisher", "frameless producer must report its interrupted RSP",
        )
        require(
            struct.unpack_from("<Q", actual, 0x98)[0] == ENTRY_RSP + 8
            and struct.unpack_from("<Q", actual, 0xF8)[0] == RETURN_ADDRESS,
            "unwind-control",
            f"{self.name} PC+{snapshot.pc - metadata.begin:#x}/after-call-{snapshot.completed_calls}: "
            f"RSP={struct.unpack_from('<Q', actual, 0x98)[0]:#x} "
            f"RIP={struct.unpack_from('<Q', actual, 0xF8)[0]:#x}",
        )
        # This prologue saves no FP state. The real unwinder must leave FP/debug/control flags,
        # context extensions, and home slots unchanged rather than synthesize defaults.
        for start, end in ((0, 0x78), (0x100, CONTEXT_BYTES)):
            require(actual[start:end] == snapshot.context[start:end], "unwind-context", f"context bytes {start:#x}..{end:#x} changed")
        output_after = bytes(self.mu.mem_read(OUTPUT_BASE, PAGE))
        mutable = ((0x100, 0x100 + CONTEXT_BYTES), (0x700, 0x708), (0x740, 0x748))
        if with_pointers:
            mutable += ((0x800, 0x900),)
        for offset, (before, after) in enumerate(zip(output_before, output_after)):
            if not any(start <= offset < end for start, end in mutable):
                require(before == after, "unwind-canary", f"output canary changed at +{offset:#x}")
        require(
            bytes(self.mu.mem_read(STACK_BASE, STACK_BYTES)) == snapshot.stack,
            "unwind-canary", "unwinder changed the interrupted producer stack",
        )
        require(
            bytes(self.mu.mem_read(UNWIND_STACK, 0x1000)) == bytes([0xA7]) * 0x1000
            and bytes(self.mu.mem_read(UNWIND_RSP, 8)) == words((UNWIND_RETURN,))
            and bytes(self.mu.mem_read(UNWIND_RSP + 72, 0x100)) == frame_tail_before,
            "unwind-canary", "unwinder crossed its own stack/argument canaries",
        )
        if with_pointers:
            pointers = struct.unpack("<32Q", self.mu.mem_read(CONTEXT_POINTERS, 256))
            expected = expected_context_pointers(snapshot.pc - metadata.begin)
            for index, (value, target) in enumerate(zip(pointers, expected)):
                require(
                    value == target, "unwind-context-pointers",
                    f"{self.name} PC+{snapshot.pc - metadata.begin:#x}/after-call-{snapshot.completed_calls}: "
                    f"{'floating' if index < 16 else 'integer'}[{index % 16}]={value:#x}, expected={target:#x}",
                )
        return self.unwind_instructions


def sweep(artifact: Artifact, entry: int, metadata: FunctionMetadata, name: str, deadline: float) -> int:
    probe = UnwindProbe(artifact, name)
    probe.run()
    offsets = {snapshot.pc - metadata.begin for snapshot in probe.snapshots.values()}
    require(PROLOGUE_BOUNDARIES <= offsets, "boundary-coverage", f"{name}: missing prologue boundaries")
    require(EPILOGUE_BOUNDARIES <= offsets, "boundary-coverage", f"{name}: missing epilogue boundaries")
    require(
        {snapshot.completed_calls for snapshot in probe.snapshots.values()} == {0, 1, 2, 3},
        "boundary-coverage", f"{name}: initial, both retries, and terminal reply required",
    )
    require(all(metadata.begin <= snapshot.pc < metadata.end for snapshot in probe.snapshots.values()), "boundary-coverage", f"{name}: producer escaped runtime-function range")
    probe.prepare_unwinder()
    total_instructions = 0
    for snapshot in probe.snapshots.values():
        for with_pointers in (False, True):
            require(time.monotonic() < deadline, "suite-limit", "unwind sweep deadline")
            total_instructions += probe.unwind_snapshot(entry, metadata, snapshot, with_pointers=with_pointers)
    print(
        f"PASS {name}/worker: actual RtlVirtualUnwind restored {len(probe.snapshots)} interrupted states "
        f"(NULL and non-NULL ContextPointers; all prologue/body/retry/epilogue boundaries; "
        f"{total_instructions} unwinder instructions)"
    )
    return len(probe.snapshots) * 2


def negative_control(path: Path) -> None:
    old = Artifact.load(path)
    try:
        load_metadata(old)
    except OracleFailure as error:
        require(error.category == "missing-native-metadata", "negative-control", f"unrelated old artifact failure: {error}")
        print(f"PASS missing-metadata negative control sha256={old.digest}: {error}")
        return
    raise OracleFailure("negative-control", "old DLL unexpectedly has complete native-stub unwind metadata")


def negative_pointers_control(path: Path, current_digest: str) -> None:
    old = Artifact.load(path)
    require(old.digest != current_digest, "negative-control", "old pointer DLL must differ from current DLL")
    entry, metadata = load_metadata(old)
    name = "NtMapViewOfSection"
    function = metadata[name]
    probe = UnwindProbe(old, name)
    probe.run()
    snapshot = probe.snapshots.get((function.begin + function.prologue_bytes, 0))
    require(snapshot is not None, "negative-control", "old artifact full-prologue body boundary missing")
    probe.prepare_unwinder()
    # The old artifact must have valid metadata and perform the actual unwind correctly first.
    probe.unwind_snapshot(entry, function, snapshot)
    try:
        probe.unwind_snapshot(entry, function, snapshot, with_pointers=True)
    except OracleFailure as error:
        require(
            error.category == "unwind-context-pointers"
            and bytes(probe.mu.mem_read(CONTEXT_POINTERS, 256)) == words(CONTEXT_POINTER_WORDS),
            "negative-control", f"expected ignored ContextPointers only, got: {error}",
        )
        print(f"PASS missing-ContextPointers negative control sha256={old.digest}: {error}")
        return
    raise OracleFailure("negative-control", "old DLL unexpectedly populated ContextPointers")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("dll", type=Path)
    parser.add_argument("--negative-dll", type=Path)
    parser.add_argument("--negative-pointers-dll", type=Path, help="valid unwind metadata but old ignored ContextPointers implementation")
    parser.add_argument("--all-services", action="store_true", help="execute boundary sweeps for all eight producer fixtures")
    args = parser.parse_args()
    deadline = time.monotonic() + MAX_SUITE_SECONDS
    try:
        artifact = Artifact.load(args.dll)
        entry, metadata = load_metadata(artifact)
        print(f"Artifact: {artifact.path} sha256={artifact.digest}")
        print(f"PASS exact actual pdata/xdata metadata for {len(metadata)} exported native-stub fixtures")
        names = [service.name for service in SERVICES] if args.all_services else ["NtMapViewOfSection"]
        count = sum(sweep(artifact, entry, metadata[name], name, deadline) for name in names)
        if args.negative_dll is not None:
            require(time.monotonic() < deadline, "suite-limit", "negative-control deadline")
            negative_control(args.negative_dll)
        if args.negative_pointers_dll is not None:
            require(time.monotonic() < deadline, "suite-limit", "pointer-negative-control deadline")
            negative_pointers_control(args.negative_pointers_dll, artifact.digest)
        print(f"PASS {count} real RtlVirtualUnwind calls including exact ContextPointers; foreign-ABI SEH and hardware fault delivery remain unproved")
        return 0
    except (OracleFailure, OSError, pefile.PEFormatError, unicorn.UcError) as error:
        print(f"FAIL {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
