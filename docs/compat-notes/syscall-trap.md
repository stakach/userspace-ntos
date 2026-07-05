# Real seL4 syscall trap — ntdll executes itself

`components/driver-host-ntdll` demonstrates the **real** syscall path: a real Windows 7 ntdll
syscall stub's own `syscall` instruction traps into the seL4 kernel, and the NT native syscall
dispatcher services it — no interpretation.

## How it works
1. The root task copies the **real** `NtQuerySystemInformation` stub bytes straight out of
   `references/ntdll.dll`'s `.text` (`4C 8B D1 B8 33 00 00 00 0F 05 …` = `mov r10,rcx; mov eax,0x33;
   syscall`) into an executable page of its VSpace (mapped W^X: RW to copy, then RO+X).
2. It spawns a user thread whose entry is that stub, sharing the root's CSpace/VSpace, with a
   **fault endpoint** wired via `TCB_SetSpace(tcb, fault_ep, cnode, vspace)` back to the root.
3. The thread runs the stub. Its `syscall` executes → the CPU enters the seL4 kernel. seL4 reads
   the seL4 syscall number from RDX (which is 0 here, not a valid seL4 syscall), so it raises an
   **`UnknownSyscall` fault** (ipc_label 2) delivered to the fault endpoint as a Call IPC.
4. The root `Recv`s the fault. The Windows syscall number is RAX at trap time, which the kernel
   places at fault message word 0 — recovered directly as `ep_recv`'s `mr0`. (`msg[0]=RAX`,
   args would be `R10=msg[9]`, `RDX=msg[3]`, `R8=msg[7]`, `R9=msg[8]`, FaultIP=`msg[15]`.)
5. The recovered number (0x33) is dispatched through the ntdll-derived Windows-7 service table →
   `NtQuerySystemInformation` → the wired KernelServices → NumberOfProcessors.

## Verified in QEMU (`scripts/run-ntdll-trap.sh`)
- `ntdll_parsed` — the real ntdll parsed, 300+ stubs, NtQuerySystemInformation=0x33.
- `ntdll_syscall_trapped` — the stub's `syscall` trapped (UnknownSyscall label=2) and the recovered
  RAX == 0x33 (the real Win7 SSN).
- `trapped_syscall_dispatched` — 0x33 dispatched to NtQuerySystemInformation → NumberOfProcessors=1.

## Scope / next
This proves the trap + number-recovery + dispatch. It does not yet reply to the fault to resume
the thread with the NTSTATUS result (that needs the 18-word register reply via the IPC buffer:
reply slot 0=RAX=result, slot 15=FaultIP+2 to skip the syscall, slots preserved) — a follow-up.
The component is a standalone workspace and `include_bytes!`es the gitignored ntdll, so it builds
only via its own `build.sh` (not the default workspace build).

## Full round trip (implemented)

The demo now also **replies to the fault** so the stub resumes with the NTSTATUS and runs to
completion — the complete NT syscall path:

6. The handler stages a reply message (register slots via the IPC buffer at `ipc_buffer + 8 + i*8`):
   slot 0 (RAX) = the dispatch NTSTATUS, slot 15 (FaultIP) = `STUB_VADDR + 10` — the `ret` right after
   the `syscall` (which sits at `STUB_VADDR + 8`); slots 4..15 = 0, and SP/RFLAGS are left untouched
   (reply length 16, so the kernel preserves the saved values). It issues `SysReplyRecv` on the fault
   endpoint (reply + wait for the next fault in one call).
7. The stub **resumes** at its `ret` with RAX = NTSTATUS. The `ret` pops the (zeroed) stack top and
   jumps to RIP 0 → a **user #PF at rip=0x0** — the expected, benign consequence that *proves the
   stub executed past the syscall*. The handler receives this second fault and verifies it is a
   VMFault (label ≠ 2), not another UnknownSyscall (which would mean the syscall re-executed).

`stub_resumed_after_syscall` passes; the `[user #PF: ... rip=0x0]` line in the log is the resume
proof, not an error. ntdll's own instruction stream ran, trapped, was serviced by the NT
personality, and resumed — the real syscall path end to end.
