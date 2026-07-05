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

## TEB via %gs — ntdll self-references resolve (implemented)

The trap thread now carries a real Windows **TEB** at its `%gs` base, so ntdll's self-references
(`%gs:[0x30]` = TEB self, `%gs:[0x60]` = PEB) resolve — the last missing piece for running ntdll
code that touches thread-local state.

Kernel change (rust-micro): a per-thread user `%gs` base. `CpuContext` gains `gs_base`;
`TCBSetTLSBase` gains a segment selector (`a3 != 0` → `%gs`, applied via `IA32_KERNEL_GS_BASE` so
the return-to-user `swapgs` makes it the active `%gs` while the kernel keeps its per-CPU `%gs`); the
gs base is restored alongside `fs_base` on **both** dispatch paths (the scheduler context switch and
the syscall-tail next-thread dispatch), so it survives a fault-resume. `sel4-rt` gains
`tcb_set_gs_base`.

Component: builds a `nt_user_host::build_teb` TEB, maps it, and `tcb_set_gs_base(tcb, TEB_VADDR)`.
The trampoline reads `%gs:[0x30]` **after** the export's syscall trap + resume and reports it.

QEMU: `ntdll_teb_via_gs_resolves` passes — the reported `%gs:[0x30]` equals the TEB VA, proving
`%gs` resolves to the thread's TEB and survives the full trap → service → resume cycle. Real ntdll
code, in place, with a real TEB, trapping through the real seL4 fault path.

## Running the loader: LdrpInitialize prologue → first syscall (implemented)

With the TEB/PEB wired up, the component now runs the real ntdll loader entry. A second thread's
trampoline `call`s the real `LdrInitializeThunk` (which calls the internal `LdrpInitialize`) in
mapped ntdll `.text`. The minimal loader environment:
- a `PEB_LDR_DATA` (Length, Initialized=1, three empty **circular** LIST_ENTRYs) referenced by
  `PEB->Ldr`;
- a PEB (BeingDebugged=0, ImageBaseAddress, Ldr);
- the full TEB (0x1800 bytes, both pages) at `%gs`;
- `KUSER_SHARED_DATA` mapped at the Windows-fixed `0x7FFE0000`;
- ntdll's `.data` (the loader lock) mapped RW from the loaded image.

The handler catches the thread's first fault to see how far the real loader code executed.

QEMU: `ldrpinitialize_prologue_ran_to_first_syscall` passes — the first fault is an `UnknownSyscall`
(label 2), i.e. LdrpInitialize's real code ran its whole prologue (TEB, BeingDebugged, the loader
lock's `lock cmpxchg`, `PEB->Ldr`, KUSER_SHARED_DATA, TEB TLS fields) and reached its first `Nt*`
syscall (ssn=0x16). Iteratively mapping what it faulted on (KUSER_SHARED_DATA at 0x7FFE0000, then the
TEB's second page) walked the loader forward to that point. Servicing the loader's syscalls to run
it to completion (which needs faithful out-params + full register preservation across the trap) is
future work.

## Running a real Windows exe + servicing loader syscalls (implemented)

Two capabilities landed together, on top of full fault-message delivery to the handler (the kernel
now fans an UnknownSyscall's saved registers 4..length into the handler's IPC buffer on *both* recv
paths, so a handler can preserve a faulter's callee-saved registers across a serviced syscall).

**A real, unmodified Windows exe runs.** `references/ntdll_only_version_test.exe` (2.5 KiB, imports
only `RtlGetVersion` + `NtTerminateProcess` from ntdll) is mapped at its image base; we do the
loader's import-snap manually (patch its IAT to the mapped ntdll export addresses) and jump to its
entry. It runs: `RtlGetVersion` (real ntdll code, pure PEB/KUSER reads) fills OSVERSIONINFOW, then
`NtTerminateProcess(-1, exitcode)` traps — `exitcode = (((Major<<8)|Minor)<<16)|Build`. QEMU:
`exe_ran_and_reported_win7_version` — the trap is `NtTerminateProcess` (SSN 0x29) with exit code
`0x06011DB1` = **6.1.7601**, so the exe read the real Win7 SP1 version and terminated with it.

**LdrpInitialize's syscalls are serviced in a register-preserving loop.** For each UnknownSyscall
the loop snapshots the saved registers (msg[4..14] from the IPC buffer), dispatches, then replies
echoing the callee-saved set + a result + the resume IP (RCX = saved next-RIP), so the faulter's
registers survive the trap. QEMU: `ldrpinitialize_syscall_serviced_and_resumed` — the loop serviced
the loader's first syscall (0x16) and **resumed it into more ntdll `.text`** (@0x78e8e110), which the
pre-full-message single-shot could not do. Running the loader to completion needs faithful syscall
out-params for its whole sequence (its next fault is a NULL deref from the STATUS_SUCCESS-only pass)
— future work.

## Running LdrpInitialize deep + booting the exe via real NtContinue (implemented)

Two phases, both driving real ntdll through the register-preserving service loop
(`service_loop`), which for each `UnknownSyscall` snapshots the saved registers, services the
syscall, and replies echoing the callee-saved set + result + resume IP.

**Phase A — the real loader runs deep.** The trap thread's trampoline `call`s the real
`LdrInitializeThunk(CONTEXT*)`. The service loop gives its syscalls faithful results:
`NtAllocateVirtualMemory` returns real 64 KiB-aligned mapped memory (a demand-mapped 16 MiB arena);
`NtQuerySystemInformation(SystemBasicInformation)` fills PageSize/AllocationGranularity/CPU count;
`NtQueryInformationProcess` fills PebBaseAddress/ProcessCookie; `NtOpenKey`/`NtOpenFile` return
`STATUS_OBJECT_NAME_NOT_FOUND`. The environment needed to get this far: NLS tables (real
`c_856.nls` + `l_intl.nls`) wired into PEB->Ansi/Oem/UnicodeCaseTableData; a `RTL_USER_PROCESS_PARAMETERS`
(Flags=NORMALIZED, ImagePathName/CommandLine/CurrentDirectory) at PEB->ProcessParameters. QEMU:
`ldrpinitialize_ran_deep` — the real `LdrpInitialize` executes ~20 syscalls (NLS init, process-heap
creation, registry + system-info queries) before it needs real file/section I/O + a full module list
to continue (a filesystem subsystem — future work).

**Phase B — boot the exe via the real NtContinue.** `LdrInitializeThunk` finishes by calling
`NtContinue(CONTEXT)` to jump to the process entry. We prove that boot path directly: a thread `call`s
the real `NtContinue` with a CONTEXT whose `Rip` = the exe entry, `Rsp` = a fresh stack. Servicing that
`NtContinue` loads the thread's registers from the CONTEXT (x64 CONTEXT offsets: Rip@0xF8, Rsp@0x98,
Rax@0x78…R15@0xF0), booting the thread into the exe. The exe then runs (`RtlGetVersion` +
`NtTerminateProcess`). QEMU: `ntcontinue_booted_exe_win7_version` — `booted=1`, exit code `0x06011DB1`
= 6.1.7601: the real `NtContinue` booted a real Windows exe into its entry, and it terminated with the
real Win7 version.

## File/section + object-namespace syscalls; the loader runs deeper (partial merge)

To push toward a single unbroken LdrpInitialize -> NtContinue -> entry, service_loop now services the
loader's file, section, and object-namespace syscalls, backed by the in-memory image bytes:
- **File**: NtOpenFile/NtCreateFile (open the exe/ntdll by path suffix -> handle + IoStatusBlock),
  NtReadFile (copy bytes), NtQueryInformationFile (FileStandardInformation size),
  NtQueryAttributesFile/NtQueryFullAttributesFile, NtClose (a small handle table).
- **Section**: NtCreateSection (section handle backed by the file bytes), NtMapViewOfSection (returns
  the already-mapped image base so the loader's view matches what we loaded).
- **Object namespace**: NtOpenDirectoryObject/NtOpenSymbolicLinkObject (\KnownDlls + KnownDllPath ->
  handles), NtQuerySymbolicLinkObject (returns C:\Windows\system32). Plus ProcessParameters gained
  DllPath, which cleared the earlier STATUS_APP_INIT_FAILURE (0xC0000145 wrapping 0xC000000D).

With these, the real LdrpInitializeProcess runs ~19-20 syscalls deep — through NLS init, process-heap
creation, registry, system-info, and the full **object-namespace path resolution + KnownDlls** setup
(no more hard error). It then faults building the in-memory **module list** (a NULL local where an
LDR_DATA_TABLE_ENTRY/image structure should be) — the remaining piece is the rest of the NT-executive
process-creation contract (module list + LdrpMapDll bookkeeping), which the file/section handlers are
ready to serve once reached. The boot path itself (its terminating NtContinue) stays proven by phase B:
`ntcontinue_booted_exe_win7_version` — the real NtContinue boots the exe, exit 0x06011DB1 = 6.1.7601.

## In-memory module list built (merge still blocked on loader-internal state)

The component now builds real `LDR_DATA_TABLE_ENTRY`s for the exe + ntdll — DllBase, EntryPoint,
SizeOfImage, FullDllName/BaseDllName, Flags (LDRP_IMAGE_DLL|ENTRY_PROCESSED|PROCESS_ATTACH_CALLED),
static LoadCount — and links them into `PEB_LDR_DATA`'s three lists (InLoadOrder + InMemoryOrder =
[exe, ntdll]; InInitializationOrder = [ntdll]).

This is the correct structure and is needed for later import resolution, but it did **not** move the
loader past its current fault (`0x78e8ed33`: it allocates a 0xE0-byte LDR entry, then reads
`FullDllName.Buffer` (+0x50) of a *different*, NULL entry held in a stack local). The reason: at this
stage `LdrpInitializeProcess` manages its module data through its **own** internal state — the loader
hash table (`LdrpHashTable`) and the `LdrpImageEntry`/`LdrpNtDllDataTableEntry` globals it populates
as it creates the entries — not a list injected from outside. The NULL local is loader-internal state
that an earlier step leaves unset in this from-scratch environment; isolating which step needs
instruction-level debugging (a gdb stub on the loader thread), not serial print-tracing. The merge
therefore remains at: phase A runs the real loader deep (through NLS/heap/registry/sysinfo/object-
namespace/KnownDlls), phase B boots the exe via the real NtContinue.

## SystemDllBase (RDX) fix + gdb stub; loader gets past LDR-entry creation

Two things moved the merge forward materially:

**The RDX fix (the big one).** Reading the real NT5 source (`references/nt5/base/ntdll/ldrinit.c`,
much closer to Win7 than ReactOS) showed `LdrpInitializeProcess(Context, SystemDllBase=SystemArgument1,
...)` and that `SystemArgument1` is the **2nd argument (RDX)** the kernel passes to `LdrInitializeThunk`
= ntdll's own base. My trampoline set RCX (Context) but not RDX, so `SystemDllBase`=0 →
`LdrpAllocateDataTableEntry(0)` → `RtlImageNtHeader(0)`=NULL → Win7 reads `NtHeaders->OptionalHeader.
SizeOfImage` (`NtHeaders+0x50`) → the `[NULL+0x50]` fault (cr2=0x50) that blocked us for many
iterations. Fix: `mov rdx, ntdll_base` in the loader trampoline (+ set `PEB->ImageBaseAddress` to the
exe base so `LdrpImageEntry` is built from the exe). The loader now creates both LDR entries and runs
past that point; also added a faithful `NtQueryVirtualMemory` (MEMORY_BASIC_INFORMATION).

**A gdb stub (`scripts/run-gdb.sh`).** Boots the image with QEMU `-s -S` (gdb stub, halted) and drives
`lldb --batch` to break at a VA and dump registers/stack/disasm — the durable tool for this depth of
debugging. With it, the current fault resolves to: `0x78e8c966 mov (%rax),%r8d` with `rax=0`, where
`rax` is the NULL return of an internal chain `fault_fn -> 0x27d30 -> 0x27c20`, and `0x27c20` reads a
**lazily-initialised ntdll global table** (count in `.data`, init guard in `.rdata`, RtlRunOnce init
`0x23a80`) that's empty in this from-scratch environment. That's an ntdll-internal init dependency —
the next layer to chase with gdb. Merge status: loader runs deeper still; boot path stays proven by
phase B (real NtContinue → exe, exit 0x06011DB1).

## gdb: the empty table is RtlpInvertedFunctionTable; pre-populated; fault advances

Stepping into `0x27c20` with the gdb stub showed it's `RtlpLookupFunctionEntry` — a binary search over
`RtlpInvertedFunctionTable` (the exception-unwind image table, 24-byte entries `{FunctionTable, ImageBase,
SizeOfImage, SizeOfTable}`), and `CurrentSize`=**0**. The loader (fault fn `0x3c900`, called with
`rcx`=&`LdrpInvertedFunctionTable`) does an early **stack walk** (`RtlLookupFunctionEntry` loop) *before*
it registers ntdll in the table, so every lookup returns NULL and the walk NULL-derefs (`rbp` held
`RtlRaiseException` — it was building an error/stack capture).

Fix (in ntdll `.data`, RW after load): pre-populate ntdll's entry — `CurrentSize`=1 + `{.pdata VA,
ntdll_base, SizeOfImage, .pdata size}` at gdb-resolved offsets (table @ +0x12F000, guard @ +0x12D089).
gdb confirms it took: `CurrentSize` is now **3** (my ntdll entry at [0]; the loader appended two more
itself — so the format is right and its own registration now runs). The fault **advanced**: it's now a
lookup of **PC=0** — the loader's stack walk unwinds past our injected trampoline (which has no unwind
info) into a zeroed stack slot. Next step: give the loader thread a proper unwind terminator (start it
so the frame chain ends cleanly at a ntdll thread-start frame, rather than a raw `call` trampoline), or
set RCX/RDX via a full TCB_WriteRegisters and start directly at `LdrInitializeThunk`.
