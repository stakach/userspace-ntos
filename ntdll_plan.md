# nt-ntdll — a Rust ntdll.dll (our userspace kernel-ABI half)

**Status:** PLANNING · Step 1 (measure the import surface) DONE (2026-07-16) · Step 2 next
**Owner:** rust-micro / userspace-ntos
**Decision (2026-07-16, user):** build our OWN ntdll.dll in Rust, exporting the same
surface as ReactOS ntdll (source: `references/reactos/dll/ntdll` + `sdk/lib/rtl`), so we
own the kernel-ABI seam and can serve BOTH the classic LPC and the ALPC surface to
different Windows versions simultaneously.

---

## Why (the case)

**ntdll is not an application we host — it is the userspace half of OUR kernel ABI.**
Our kernel (rust-micro + the NT executive) is ours; the syscall boundary is ours. ntdll is
the thing that turns NT/Win32 API calls into *our* syscalls. Every other DLL (kernel32,
user32, gdi32, win32k, explorer) is a *client* of ntdll; ntdll is a client of the kernel.
We own the kernel → owning ntdll is the architecturally consistent choice. Hosting a
foreign ntdll = hosting a foreign syscall table on top of our kernel (the recurring friction).

Four concrete wins:

1. **Dissolves the SSN-collision problem** (the #1 documented Win7-pivot blocker — see
   `[[project_alpc]]`). Win7 `NtAlpcConnectPort=113` collides with ReactOS
   `NtMapViewOfSection=113` ONLY because each version's ntdll bakes in its own SSN table.
   With ONE ntdll and import-by-NAME (which is how it works — `NtCreateFile` resolves
   through ntdll's export; the SSN is internal), the SSN becomes OUR free choice. We define
   the SSN table ONCE in a shared header (ntdll ↔ executive). The "route by which-ntdll-a-
   process-runs" machinery becomes unnecessary.

2. **★ Simpler, faster syscall transport (user insight, 2026-07-16).** Our ntdll's `Nt*`
   stubs do NOT have to emulate the x86 `syscall`/`int 0x2e` trap that faults as
   UnknownSyscall and round-trips through the fault EP. Because WE author the stub, it can
   speak **native seL4 IPC (a `Call` to a service endpoint) or SURT ring submission**
   directly — the proper capability-based microkernel path, no fault-trap emulation. This is
   both cleaner (a real IPC channel, not a trap-and-service hack) and faster (no
   fault-delivery round-trip). Design the `Nt*` stub transport as a swappable backend:
   (a) legacy x86-syscall-trap [compat, for any raw-syscall code], (b) seL4 `Call` to the
   executive/service endpoint, (c) SURT ring for the batchable/async surface. Pick per-call
   or per-surface. **This is a primary reason to own ntdll, not a side effect.**

3. **The natural home for the unified LPC + ALPC surface.** Our ntdll exports BOTH dialects
   — classic LPC (`NtCreatePort`/`NtRequestWaitReplyPort`) AND ALPC
   (`NtAlpcCreatePort`/`NtAlpcConnectPort`) — both resolving to our impls over the
   **`nt-port-core`** we already built with the LPC↔ALPC bridge (`[[project_alpc]]`). A
   ReactOS binary links the LPC names, a Win7 binary links the ALPC names, both work against
   one unified core. "Host Win7 and ReactOS side by side" realized at the seam.

4. **Converts a recurring reverse-engineering tax into one-time authorship.** The dominant
   cost lately has been reverse-engineering ntdll internals via lldb hardware breakpoints:
   TEB offsets, `StaticUnicodeString`, NLS tables, `LdrpInitialize` flow, the `_vista`
   forwarder gap, SxS/apphelp, and the current frontier (`RtlpWaitForCriticalSection`
   deadlock — literally ntdll code). Every one is the cost of NOT owning ntdll — and the
   knowledge already bought IS the spec for writing ours. Plus: Rust, memory-safe, north-star.

## Scope boundary

**ONLY ntdll becomes ours.** Everything above it stays REAL ReactOS/Win7 (kernel32, user32,
gdi32, advapi32, rpcrt4, csrss, winlogon, services, lsass, win32k, explorer, …). ntdll is
uniquely the right thing to own because it is the kernel ABI's userspace half.

## Non-negotiable constraints

- **PEB / TEB / LDR_DATA_TABLE_ENTRY layouts must match byte-for-byte** what hosted binaries
  read directly (they poke `TEB+0x1728`, walk `PEB->Ldr`, etc.). This is the real precision
  work — bounded, and many offsets already mapped this session (`[[project_smss_sec_image]]`).
- **Incremental, never big-bang.** Keep the real-ntdll path working while ours reaches parity
  ONE process at a time (smss first). Boot stays green throughout; delete real-ntdll only at
  proven parity.
- **Rust, no external crates** (kernel policy). Build the DLL via GitHub CI if the local
  toolchain can't emit a PE32+ DLL (`x86_64-pc-windows-*` target or a custom link step) —
  but the SOURCE stays Rust.

---

## Scale (ReactOS `references/reactos/dll/ntdll/def/ntdll.spec` = 1927 exports)

| prefix | count | nature | our cost |
|---|---|---|---|
| `Nt*` (+`Zw*` aliases) | ~398 (+391) | syscall stubs (`mov eax,SSN; syscall` → our transport) | mechanical; we own both ends |
| `Rtl*` (+`Rtlp/Rtlx`) | ~684 | RTL library (heap, strings, AVL, bitmap, time, SD) | subset only; much already in `nt-kernel-exec`/`nt-compat-exports` |
| `Ldr*`/`Ldrp*` | ~59 | the loader | the real work; `nt-pe-loader` + executive demand-load do most |
| `Etw*`/`Dbg*` | ~79 | tracing/debug | no-op stubs initially |
| `Csr*` | 16 | CSR client (LPC-based) | over `nt-port-core` |
| `Ki*` | 7 | user dispatchers (APC/exception/callback) | small, precise |
| ALPC | 23 | the Win7 compat target | over `nt-port-core` |

**We need the IMPORTED SUBSET, not all 1927.** Step 1 measures it.

---

## Phased plan (each phase = a green, testable checkpoint)

### ☑ Step 1 — MEASURE the real import surface (DONE 2026-07-16 — see "Step 1 Results")
Enumerate the actual `ntdll.dll` exports imported across every hosted binary
(smss/csrss/winlogon/services/lsass + kernel32/user32/gdi32/advapi32/rpcrt4/csrsrv/basesrv/
winsrv/msvcrt/lsasrv/samsrv/msv1_0 + win32k.sys). Reuse `nt-pe-loader::parse_imports`. Output:
the deduplicated required export list, grouped by prefix, with per-binary attribution. This
turns "1927" into "the N we actually need" → grounds the estimate + defines the build target.
**Results:** DONE — **545 distinct ntdll exports** imported across the hosted set (see "Step 1 Results" below).

### ◪ Step 2 — `crates/nt-ntdll` skeleton + the shared SSN header  (**2a DONE 2026-07-16**; 2b/2c follow-on)
- A shared `nt-syscall-abi` SSN table (ntdll ↔ executive — the single source of truth).
- The `Nt*` stub generator with the **swappable transport backend** (x86-trap | seL4 Call |
  SURT). Start with the existing trap backend for drop-in compat, then add seL4 Call.
- The `Rtl*` subset (reuse `nt-kernel-exec`), no-op `Etw*/Dbg*`, `Ki*` dispatchers.
- Host-test everything testable (Rtl logic, SSN table round-trip).

**Step 2a landed (see "Step 2a Results" below):** three new host-tested workspace crates —
`nt-syscall-abi` (the shared SSN table), `nt-ntdll-layout` (static-asserted PEB/TEB/LDR), and
`nt-ntdll` (transport seam + stub table + proof slice). 24 tests green; executive still builds
byte-for-byte (separate `[workspace]`). **2b/2c = the bulk port** (244 Rtl bodies / 188 stub
bodies / Csr/Dbg/Ki / the 65 CRT re-exports). **Step 3 = the loader.**

### ☐ Step 3 — the loader + PEB/TEB/LDR layout
Our `LdrpInitialize`: PEB/TEB setup (exact offsets), process-param normalization, build the
`PEB->Ldr` module list, recursive import snap (incl. **forwarders** — kills the `_vista` pins
+ the SxS/apphelp gaps), TLS callbacks, `DLL_PROCESS_ATTACH` ordering. Reuse `nt-pe-loader`.

### ☐ Step 4 — PROVE parity on ONE process (smss), real-ntdll fallback kept
Boot smss on OUR ntdll; every other process stays on real ntdll. Green gate + paint intact.

### ☐ Step 5 — expand outward to parity, then cut over
csrss → winlogon → services → lsass, one at a time, green between. When all pass on our
ntdll, delete the real-ntdll path + the SSN-collision routing machinery.

### ☐ Step 6 — flip the syscall transport to native seL4/SURT
Once parity holds, switch the `Nt*` transport from x86-trap to seL4 `Call`/SURT for the
executive-serviced surface — the performance + cleanliness win. Measure the round-trip
delta.

---

## Risks / mitigations
- **Struct-layout drift** → derive offsets from `references/reactos` + verify against the
  live TEB/PEB reads already mapped; a layout unit-test crate.
- **Loader completeness** (forwarders/TLS/SxS) → reuse `nt-pe-loader` + executive logic;
  forwarders are a *feature we gain* (fixes existing gaps), not new debt.
- **Transition** → strictly incremental with real-ntdll fallback; boot green each step.
- **DLL emit toolchain** → GitHub CI PE32+ build if local can't; source stays Rust.

## Related
`[[project_alpc]]` (nt-port-core + the SSN-collision insight this solves) ·
`[[project_reactos_kernel_replacement]]` (the Win7 pivot) ·
`[[project_smss_sec_image]]` (the ntdll internals already mapped = our spec) ·
`[[feedback_implement_kernel_api_for_real]]` (real impls in nt-* crates) ·
`plans/P8-win7-pivot.md`.

---

## Step 1 Results (measured 2026-07-16)

**Method:** `llvm-objdump -p` PE import-table parse of the real ReactOS **x64** binaries in
`rust-micro/.tmp/reactos/reactos/system32/`, filtered to import descriptors named `ntdll.dll`,
symbol names deduplicated across binaries. (Chose llvm-objdump over `nt-pe-loader::parse_imports`
for a zero-perturbation host measurement — parses PE32+ imports cleanly on macOS.)
Sanity-checked against ntdll's own export table + the 1927-entry `ntdll.spec`.

### The number that matters
**Our Rust ntdll must implement ~545 exports to satisfy the CURRENT hosted ReactOS set** — vs
ntdll.dll's 1372 shipped x64 exports, vs the 1927-entry authorable spec surface. Split:

| bucket | count | our cost |
|---|---|---|
| **Nt\*** (syscall stubs) | **188** | mechanical — this IS our required SSN table (list below) |
| **Zw\*** (aliases) | 7 | aliases of the Nt\* stubs (ZwCreateKey/EnumerateKey/EnumerateValueKey/QueryValueKey/SetValueKey/CallbackReturn/YieldExecution) |
| **Rtl\*** | 244 | subset only; much already in `nt-kernel-exec`/`nt-compat-exports` |
| **Ldr\*** | 21 | the real loader work; `nt-pe-loader` + executive demand-load cover most |
| **Csr\*** | 8 | CSR client over `nt-port-core` (AllocateCaptureBuffer, ClientCallServer, ClientConnectToServer, …) |
| **Dbg\*** | 12 | DbgPrint/DbgPrintEx/DbgPrompt + DbgUi\* (debugger client); mostly serial-forward + no-op |
| **other / CRT** | 65 | C-runtime ntdll re-exports (mem\*/str\*/wcs\*/sprintf/qsort/math) + 3 data exports (`NlsMbCodePageTag`, `NlsMbOemCodePageTag`, `vDbgPrintExWithPrefix`) |
| **Ki\*** / **Etw\*** / **NtAlpc\*** | **0** | none imported by the current set |

Rough authorship estimate: **~188 syscall stubs + ~21 loader + ~244 Rtl + ~65 CRT/other + ~28 (Zw/Csr/Dbg)**.
The 188 Nt\* + 244 Rtl\* are the bulk; Nt\* is mechanical (one-end-per-stub, we own both ends),
Rtl\* is the real library work but heavily pre-existing in `nt-kernel-exec`/`nt-compat-exports`.

### Key findings
- **ALPC not imported by anything.** ZERO `NtAlpc*`/`Alpc*` imports across the entire set —
  **confirms ALPC is the Win7-only future surface.** ReactOS uses classic LPC exclusively
  (`NtCreatePort`/`NtConnectPort`/`NtRequestWaitReplyPort`/`NtReplyWaitReceivePort`/
  `NtAcceptConnectPort`/`NtCompleteConnectPort`/`NtListenPort`/`NtReplyPort` ARE imported). Our
  ntdll exports both dialects; only LPC is exercised today, ALPC lights up when Win7 binaries arrive.
- **win32k.sys imports ntoskrnl.exe / hal.dll / ftfd.dll — NOT ntdll** (0 ntdll imports). It's
  kernel-mode; its kernel-API surface is a SEPARATE measurement (ntoskrnl exports), not merged here.
- **All ntdll imports in this set are by NAME, none by ordinal** — so an import-by-name ntdll
  (which dissolves the SSN-collision) is fully sufficient; no ordinal-export table needed for the
  current set.
- **No `_vista` ALPC/new-surface** — the `*_vista` shims (ntdll_vista/kernel32_vista/advapi32_vista)
  import only ordinary Nt\*/Rtl\* (e.g. ntdll_vista pulls 17 Nt\* + 14 Rtl\*), no exotic surface.
- **`kernelbase.dll` and `sechost.dll` are ABSENT** from the ReactOS set (Win7+ split-outs) — expected.

### Required Nt* syscall list (188) — OUR SSN TABLE
Full list saved to **`/tmp/ntdll_required_surface.txt`** (grouped by prefix: Nt/Zw/Rtl/Ldr/Csr/Dbg/other).
The Nt\* set spans: process/thread (Create/Open/Terminate/Resume/Suspend/SetContext/GetContext +
Query/SetInformationProcess/Thread), memory (Allocate/Free/Protect/Query/Lock/Flush VirtualMemory,
Map/UnmapViewOfSection, Create/OpenSection, physical-page/write-watch), objects (Duplicate/Close/
QueryObject, Directory/SymbolicLink, Make{Permanent,Temporary}Object), files+IO (Create/Open/Read/
Write/Lock/DeviceIoControl/FsControl/QueryInformation/QueryDirectory/NotifyChange + IoCompletion +
mailslot/named-pipe), registry (Create/Open/Delete/Enumerate/Query/Set Key+ValueKey, Save/Restore/
Load/Replace/Flush/NotifyChange), sync (Event/Mutant/Semaphore/Timer/KeyedEvent + WaitFor\* +
SignalAndWait), LPC (the 8 port calls above), security/token (AccessCheck\* + \*Token + \*AuditAlarm +
Privilege\* + Se-ish), atoms, jobs, power, hard-error/display, system-info/time/locale, APC/registry-init.

### Per-binary attribution (ntdll imports; win32k=0)
| binary | TOT | Nt | Zw | Rtl | Ldr | Csr | Dbg | other |
|---|---|---|---|---|---|---|---|---|
| kernel32.dll | 370 | 131 | 0 | 156 | 19 | 8 | 12 | 44 |
| advapi32.dll | 157 | 47 | 0 | 84 | 0 | 0 | 1 | 25 |
| smss.exe | 103 | 42 | 0 | 44 | 2 | 0 | 2 | 13 |
| user32.dll | 83 | 7 | 2 | 28 | 0 | 4 | 1 | 41 |
| lsasrv.dll | 79 | 27 | 2 | 45 | 3 | 0 | 1 | 1 |
| csrsrv.dll | 76 | 36 | 0 | 26 | 4 | 0 | 2 | 8 |
| basesrv.dll | 68 | 25 | 0 | 27 | 3 | 0 | 1 | 12 |
| winsrv.dll | 57 | 19 | 0 | 36 | 0 | 0 | 1 | 1 |
| samsrv.dll | 45 | 6 | 5 | 32 | 0 | 0 | 1 | 1 |
| services.exe | 43 | 7 | 0 | 35 | 0 | 0 | 1 | 0 |
| msv1_0.dll | 43 | 2 | 0 | 23 | 0 | 0 | 1 | 17 |
| kernel32_vista.dll | 43 | 14 | 0 | 21 | 0 | 0 | 1 | 7 |
| gdi32.dll | 41 | 0 | 0 | 16 | 0 | 0 | 1 | 24 |
| ntdll_vista.dll | 39 | 17 | 0 | 14 | 3 | 0 | 1 | 4 |
| advapi32_vista.dll | 32 | 6 | 0 | 12 | 0 | 0 | 0 | 14 |
| userenv.dll | 16 | 1 | 0 | 14 | 0 | 0 | 1 | 0 |
| winlogon.exe | 13 | 5 | 0 | 7 | 0 | 0 | 0 | 1 |
| msvcrt.dll | 11 | 2 | 0 | 5 | 1 | 0 | 1 | 2 |
| rpcrt4.dll | 10 | 4 | 0 | 4 | 0 | 0 | 1 | 1 |
| csrss.exe | 10 | 3 | 0 | 5 | 0 | 0 | 2 | 0 |
| ws2help.dll | 4 | 1 | 0 | 3 | 0 | 0 | 0 | 0 |
| lsass.exe | 3 | 1 | 0 | 1 | 0 | 0 | 1 | 0 |
| mpr.dll | 2 | 0 | 0 | 0 | 0 | 0 | 1 | 1 |
| ws2_32.dll | 1 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| win32k.sys | 0 | — | — | — | — | — | — | — (imports ntoskrnl.exe/hal.dll/ftfd.dll) |

**Top importers:** kernel32 (370, the thin Nt\*/Rtl\* wrapper — imports ONLY ntdll) ≫ advapi32
(157) > smss (103) > user32 (83). kernel32 alone covers 131 of the 188 required Nt\* — implement
kernel32's ntdll dependencies first and most of the syscall surface is exercised.

_Full deduped surface (grouped by prefix): `/tmp/ntdll_required_surface.txt`._

---

## Step 2a Results (landed 2026-07-16)

Three new **host-tested** members of the main `crates/` workspace (ZERO boot risk — new crates
only; nothing wired into the boot, executive runtime logic + `rust-micro/src` untouched). Committed
green on `main`. **24 tests** total (`cargo test -p nt-syscall-abi -p nt-ntdll-layout -p nt-ntdll`),
clippy clean, full workspace builds, and the **executive still builds + stages byte-identically**
(it's a separate `[workspace]`, so adding main-workspace members can't perturb it — verified via
`components/ntos-executive/build.sh`).

### `crates/nt-syscall-abi` — the shared SSN ABI (single source of truth)
Data-driven `name ↔ SSN` table: **188 `Nt*` + 7 `Zw*` aliases**, the exact set the current hosted
ReactOS x64 binaries import (Step 1). **SSN-REUSE DECISION (confirmed):** the numbering is the
**ReactOS `ntoskrnl/sysfuncs.lst`-derived 0-based line index** — *the same numbering the executive
already dispatches on* (`SSN_NT_*` consts). We did NOT invent fresh numbers → owning ntdll is
**zero-churn on the executive**. Tests assert no-dup-SSN, name→ssn→name round-trip, Zw→underlying-Nt
SSN, and **~19 anchors** cross-checked against BOTH `sysfuncs.lst` AND the executive consts
(`NtClose=27`, `NtCreateFile=39`, `NtOpenFile=122`, `NtProtectVirtualMemory=143`,
`NtAllocateVirtualMemory=18`, `NtQuerySystemInformation=181`, `NtSetValueKey=256`,
`NtTerminateProcess=266`, `NtWaitForSingleObject=281`, …). ⚠ NOTE: the surface imports
`NtCreateProcessEx`(50), while the executive currently dispatches `NtCreateProcess`(49) — both are
in `sysfuncs.lst`; the table carries the *imported* name. The **ALPC seam** is documented +
reserved (`ALPC_SSN_BASE = 0x1000`, well clear of the real `0..=292` range) but **NOT assigned** —
ReactOS exports no `NtAlpc*`; ALPC is the Win7-only future where renumber-freedom is legal.

### `crates/nt-ntdll-layout` — byte-exact x64 PEB/TEB/LDR (static-asserted)
`#[repr(C)]` types: `Peb`, `Teb`, `PebLdrData`, `LdrDataTableEntry`, `RtlUserProcessParameters`,
`UnicodeString`, `ListEntry`, `ClientId`, `NtTib`. **Every hosted-read field is placed at its exact
x64 offset via `_rsvd*` padding + proven by `const _: () = assert!(offset_of!(...))`** (compile-time
fail on drift). Sources cited per offset: the **ReactOS NDK `peb_teb.h` `_STRUCT64` C_ASSERT block**
(TEB.NtTib=0x000, EnvironmentPointer=0x038, ExceptionCode=0x2C0, LastStatusValue=0x1250, Vdm=0x1690,
HardErrorMode=0x16B0, GdiBatchCount=0x1740, WaitingOnLoaderLock=0x1760, TlsExpansionSlots=0x1780,
ActiveFrame=0x17C0; PEB.Mutant=0x08, Ldr=0x18, FastPebLock=0x38, NtGlobalFlag=0xBC, SessionId=0x2C0),
`ldrtypes.h`/`rtltypes.h`/`umtypes.h`/`ketypes.h` for the sub-structs, **plus the live-RE offsets**
from `project_smss_sec_image`: `TEB.StaticUnicodeString@0x1258`,
`TEB.ActivationContextStackPointer@0x2C8`, and the PEB NLS ptrs `AnsiCodePageData@0xA0` /
`OemCodePageData@0xA8` / `UnicodeCaseTableData@0xB0`. Also `RTL_USER_PROC_PARAMS_NORMALIZED=0x1`.

### `crates/nt-ntdll` — the ntdll skeleton (transport seam + stub table + proof slice)
`no_std`+`alloc`. **`transport`**: a `Backend` enum with **three declared backends** —
`X86Trap` (**implemented** target-side as the `cfg(target_arch="x86_64")` naked-asm
`mov eax,ssn; syscall` for drop-in compat; host builds return `STATUS_NOT_IMPLEMENTED`), `Sel4Call`
+ `SurtRing` (**declared seams**, real send = Step 6). The **selection policy** `Backend::for_ssn`
(one-place flip point) + SSN plumbing are host-tested; the asm is target-only (expected). Default
policy = `X86Trap` for every SSN → behaviour-identical to real ntdll against today's executive.
**`stubs`**: `StubTable` projects the shared ABI table into 188 `Stub{name, ssn, backend}` (tested:
all 188 present, right SSNs, by-name + by-SSN lookup, unknown→`STATUS_INVALID_SYSTEM_SERVICE`
never-silent-success). **Proof-of-pattern slice**: 5 fully-wired stubs (`NtClose`,
`NtDelayExecution`, `NtCreateFile`, `NtProtectVirtualMemory`, `NtWaitForSingleObject`) + 6 reused
`Rtl*` (`RtlInitUnicodeString`, `RtlCreateUnicodeString`, `RtlCompareMemory`,
`RtlCompareUnicodeString`, `RtlEqualUnicodeString`, `RtlUpcaseUnicodeChar` — re-exported from
`nt-compat-exports::rtl`, proving the "re-export, don't reimplement" pattern).

### Follow-on split (tracked, NOT done here)
- **Step 2b** — the bulk **244 `Rtl*` bodies** (reuse `nt-kernel-exec`/`nt-compat-exports` where
  they exist; author the rest) + the **65 CRT/`other` re-exports** (`mem*`/`str*`/`wcs*`/`sprintf`/
  math + the 3 data exports `NlsMbCodePageTag`/`NlsMbOemCodePageTag`/`vDbgPrintExWithPrefix`).
- **Step 2c** — **`Csr*`** (8, over `nt-port-core`), **`Dbg*`** (12, serial-forward/no-op),
  **`Ki*`** user dispatchers (APC/exception/callback), the full 188 stub *bodies* with the >4-arg
  stack thunk.
- **Step 3** — the loader (`LdrpInitialize` over the `nt-ntdll-layout` structs + `nt-pe-loader`):
  PEB/TEB setup, process-param normalization, `PEB->Ldr` build, recursive import snap incl.
  forwarders, TLS callbacks, `DLL_PROCESS_ATTACH` ordering.
