# Real seL4 syscall trap — ntdll executes itself

`components/driver-host-ntdll` demonstrates the **real** syscall path: the full real Windows 7
ntdll image is mapped executable in place, a user thread `call`s a real ntdll export, and that
export's own `syscall` instruction traps into the seL4 kernel where the NT native syscall
dispatcher services it — no interpretation, no copied stub.

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

## Clean round trip via a reporter trampoline (implemented)

The trap thread's entry is now a small **trampoline** (hand-assembled machine code in the same
executable page, ahead of the copied ntdll stub), so the stub returns cleanly with no page fault:

```
trampoline:
    call stub          ; pushes a return address, then runs the real ntdll stub
    mov  r10, rax      ; report the returned NTSTATUS as message register 0
    mov  esi, 1        ; MessageInfo: length 1
    mov  edx, -5       ; SYS_SEND  (a VALID seL4 syscall — does not trap)
    syscall            ; SysSend(rdi = done_ep, mr0 = rax) — report the result
    jmp  $
stub:  <real ntdll NtQuerySystemInformation bytes: mov r10,rcx; mov eax,0x33; syscall; ret>
```

Flow:
1. The thread starts at the trampoline. `call stub` pushes a return address and enters the real
   ntdll stub.
2. The stub's `syscall` traps → UnknownSyscall fault → the handler recovers the SSN (RAX, `msg[0]`)
   and dispatches it through the Windows-7 service table → NtQuerySystemInformation → subsystems.
3. The handler **replies** (`SysReplyRecv`, length 16): slot 0 (RAX) = the result, slot 15 (FaultIP)
   = the stub's `ret` (`STUB_VADDR + STUB_OFF + 10`), slot 5 (RDI) = `done_ep` (preserved for the
   trampoline's Send); SP/RFLAGS are left untouched, so the `call`'s pushed return address is intact.
4. The stub's `ret` returns to the trampoline (clean — the stack holds the pushed return address).
5. The trampoline issues a **real seL4 `SysSend`** to `done_ep` reporting RAX. This is a valid seL4
   syscall (number in RDX = -5), so it does *not* trap.
6. The root receives the report on `done_ep` (the same `SysReplyRecv` that resumed the thread), and
   confirms the value round-tripped.

QEMU: `ntdll_parsed` + `ntdll_syscall_trapped` + `trapped_syscall_dispatched` +
`stub_resumed_clean_and_reported` — **no page fault**. ntdll's real code runs, its syscall traps and
is serviced, it resumes and returns, and reports its result — a clean NT syscall round trip on seL4.

## Full ntdll `.text` mapped, jump to a real export (implemented)

The demo now maps the **entire real ntdll image** and calls a real export in place, rather than
copying an 11-byte stub:

1. `map_region` maps `size_of_image` (426 pages, ~1.7 MiB) fresh RW frames at ntdll's **preferred
   base** `0x78e50000` — the whole image fits one 2 MiB slice, so one PT — creating the PDPT/PD/PT.
   Because it's the preferred base, **no relocations** are needed.
2. The headers + every section are copied section-by-section straight from the `include_bytes!`
   `.rodata` into the mapped VSpace (no 1.7 MiB `pe.map()` allocation — it wouldn't fit the heap).
3. `apply_wx` re-maps each page by `PeFile::protection_at`: `.text` → read-only + executable,
   everything else → NX. No page is both writable and executable.
4. The trap thread's trampoline is `mov rax, <ntdll_base + export_rva>; call rax; <report>`. The
   `call rax` jumps into the **real `NtQuerySystemInformation` in mapped ntdll `.text`**, at its
   linked address. Its `syscall` (found by scanning the stub for `0F 05`) traps; the resume IP is
   that `syscall` + 2 (the export's own `ret`).
5. Everything else is as before: trap → dispatch → reply (RAX = result, FaultIP = the export's
   `ret`, RDI = done_ep) → the export returns into the trampoline → `SysSend` reports the result.

QEMU: `ntdll_parsed` + `ntdll_text_mapped_executable` + `ntdll_syscall_trapped` +
`trapped_syscall_dispatched` + `export_resumed_clean_and_reported` — no page fault. ntdll's actual
code, at its actual linked addresses, executes in place and traps through the real seL4 fault path.
