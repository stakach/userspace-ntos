# nt-ntdll — a Rust ntdll.dll (our userspace kernel-ABI half)

**Status:** PLANNING · Steps 1/2a/2b/2c/3 DONE · Step 4.0/4.0b/4.A/4.B DONE · Step 6.A native transport DONE · real-ntdll fallback RETIRED (our DLL IS `ntdll.dll`) · **SYSTEMATIC PORT: BATCH 1 (smss spawns csrss) DONE · BATCH 2 (recursive dependent-DLL loader → csrss cascades the FULL Win32 client stack on OUR ntdll; 23 new csrsrv+basesrv exports) DONE 2026-07-16** · next wall = executive-side page-rights (`map=8`), then BATCH 3 (winsrv/Win32-stack surface)
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

### ◪ Step 2 — `crates/nt-ntdll` skeleton + the shared SSN header  (**2a + 2b DONE 2026-07-16**; 2c follow-on)
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

### ◪ Step 3 — the loader + PEB/TEB/LDR layout  (**engine DONE, host-tested 2026-07-16 — see "Step 3 Results"**)
Our `LdrpInitialize`: PEB/TEB setup (exact offsets), process-param normalization, build the
`PEB->Ldr` module list, recursive import snap (incl. **forwarders** — kills the `_vista` pins
+ the SxS/apphelp gaps), TLS callbacks, `DLL_PROCESS_ATTACH` ordering. Reuse `nt-pe-loader`.
**Engine landed host-tested (18 new tests, `nt-ntdll` 127→145); the live map/call/gs paths are
honest `LoaderHost` seams (Step 4 wires them).**

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
- ☑ **Step 2b** — the bulk `Rtl*` bodies + the CRT re-exports + the heap + the sync primitives.
  **DONE 2026-07-16 — see "Step 2b Results" below.**
- ☑ **Step 2c** — **`Csr*`** / **`Dbg*`** / **`Ki*`** + the full 188 stub *bodies* + the marshalling
  + the `Rtl*` stragglers. **DONE 2026-07-16 — see "Step 2c Results" below.**
- **Step 3** — the loader (`LdrpInitialize` over the `nt-ntdll-layout` structs + `nt-pe-loader`):
  PEB/TEB setup, process-param normalization, `PEB->Ldr` build, recursive import snap incl.
  forwarders, TLS callbacks, `DLL_PROCESS_ATTACH` ordering.

---

## Step 2b Results (landed 2026-07-16)

Ported the bulk of ntdll's library surface into `crates/nt-ntdll`, host-tested with real vectors.
**ZERO boot risk** — new modules only; nothing wired into the boot, executive runtime + `rust-micro/src`
untouched. Three green commits on `main`. **68 tests** total (`cargo test -p nt-ntdll`, up from 24),
clippy clean (nt-ntdll), full workspace builds, and the **executive still builds + stages
byte-identically** (`components/ntos-executive/build.sh`).

### Category A — pure/mechanical Rtl* (`src/rtl/*`) — DONE, host-tested
`strings` (Init/Create/Copy/Append/Compare/Equal/Prefix/Upcase/Downcase/Duplicate/Erase/Validate
UnicodeString + AnsiString + DOS-8.3), `convert` (NLS-table-driven unicode↔ansi↔oem over a
`CodePage` abstraction — `LATIN1` default exact for ASCII; real 1252/437 PEB tables are a Step-3
wire-up — + the `*Size`/`Rtlx*Size` variants), `integer` (IntegerToChar/CharToInteger/
Int64ToUnicodeString + LARGE_INTEGER helpers), `time` (TimeToTimeFields/TimeFieldsToTime/
*SecondsSince1970, proleptic Gregorian, known-datetime + leap tests), `guid` (GuidToString/
GUIDFromString roundtrip), `path` (DetermineDosPathNameType_U/DosPathNameToNtPathName_U/
IsDosDeviceName_U — pure parse), `status` (NtStatusToDosError + TEB-backed Get/SetLast{NtStatus,
Win32Error} + GetVersion/version-compare), `random` (RtlUniform/RtlRandom LCG + RtlComputeCrc32,
known-vector), `bitmap` (owned `BitMap` wrapper). **Reuse:** the counted-string core + compare/
upcase + integer parse/format come from **`nt-compat-exports::rtl`**; the bitmap primitives are
re-exported from **`nt-kernel-exec::rtl_bitmap`** — not reimplemented. The rest is newly authored
Category-A logic.

### Category A' — CRT / data re-exports (`src/crt.rs`) — DONE, host-tested
`mem*` (memcmp/memchr), `str*` (strlen/cmp/stricmp/ncmp/chr/rchr/str), `wcs*` (wcslen/cmp/icmp/chr/
str), narrow parse (atoi/strtoul), a `_snprintf`-core formatter (`%d %u %x %X %s %c %%`), safe
generic `qsort`/`bsearch`, `abs`/`labs`, and the data-export tags `NlsMbCodePageTag`/
`NlsMbOemCodePageTag` (both `false` for the 1252/437 single-byte defaults). Slice-based cores; the
pointer↔slice marshalling is the loader/CRT layer.

### Category B — the REAL heap (`src/heap.rs`) — DONE, host-tested
`RtlCreateHeap`/`AllocateHeap`/`FreeHeap`/`ReAllocateHeap`/`SizeHeap`/`DestroyHeap` implemented as a
**first-fit free-list allocator with boundary tags + forward/backward coalescing** — not a stub
(it's load-bearing: the loader + every DLL allocates through it). **Design:** each block carries an
in-band `BlockHeader { size, prev_size, free }` (header padded to the 16-byte
`MEMORY_ALLOCATION_ALIGNMENT` so payloads land aligned); allocate = first-fit walk + split;
free = mark + coalesce with physically-adjacent free neighbours via `prev_size` boundary tags;
reallocate = in-place shrink (split tail) / in-place grow (merge free successor) / allocate-copy-free
fallback (original preserved on OOM, the Windows contract). The backing region is abstracted behind
an `unsafe trait Backing` — real process = `NtAllocateVirtualMemory` pages; **host tests = `Vec<u8>`**
→ fully host-tested (10 tests: alloc/size/free/double-free-reject/no-overlap/coalesce-reuse/
exhaustion+recover/realloc-grow-in-place+relocate/shrink/create-reject-tiny/destroy). Pointer-
consuming methods are `unsafe` (they trust the caller's pointer exactly as `RtlFreeHeap`/`RtlSizeHeap`
do).

### Category C — sync primitives (`src/sync.rs`) — fast-path DONE, blocking-path HONEST SEAM
`RTL_CRITICAL_SECTION` / `RTL_SRWLOCK` / `RTL_RUN_ONCE` **layouts** (byte-offset-matching what hosted
binaries read) + the **uncontended fast paths**, host-tested:
- **CriticalSection** — the interlocked `LockCount` model: free (`-1`→`0`) = `Acquired`, owner
  re-entry = `Recursed` (bumps `RecursionCount`), another owner = **`Contended`** (registers the
  waiter, does NOT block/fake); `leave` reports whether a queued waiter must be woken; spin-count
  flag-bit masking. Tests: uncontended acquire/leave, recursive re-entry, contention classification,
  non-owner-leave rejection.
- **SrwLock** — exclusive/shared fast paths (exclusive excludes shared + vice-versa, shared count
  stacks, underflow rejected).
- **RunOnce** — Begin/Complete state machine (Run / Pending / AlreadyComplete).

★ **The contended-blocking path is an honest documented seam, NOT faked** — this is the root fix for
the current `RtlpWaitForCriticalSection` boot deadlock. `WaitSeam::wait_for_ownership` /
`wake_one` name the exact keyed-event operations (`NtWaitForKeyedEvent` / `NtReleaseKeyedEvent`,
SSN-resolved via the shared `nt-syscall-abi` table) and route them through the swappable
`transport`. On the unwired host transport they return `STATUS_NOT_IMPLEMENTED` — **never a
fabricated acquisition** — so a contended caller can't silently proceed as if it holds the lock. The
real keyed-event send lands when the wait plane is wired (Step 6 / loader integration). A test
asserts the seam is *invoked on contention* and does not fake success. **Our CS is correct by
construction: a real uncontended fast path + an honest blocking seam.**

### Coverage (of the 244 imported Rtl*) + what remains
The Category-A pure surface + the heap (B) + the sync structures/fast-paths (C) cover the
**functional bulk** that the early boot / loader / smss path exercises (per `project_smss_sec_image`:
RtlInitUnicodeString, RtlUnicodeToMultiByteN [NLS], RtlAllocateHeap, process-param normalization,
the critical-section fast path). **Remaining for Step 2c** (deferred with reason — they need process
state or subsystem coupling, not "more pure functions"): the **security-descriptor / ACL / SID /
token** family (`RtlCreateSecurityDescriptor`, `Rtl*Ace`, `RtlAllocateAndInitializeSid`,
`RtlAdjustPrivilege`, … — belongs over `nt-security`), the **activation-context / SxS** family
(`RtlActivateActivationContext`, `RtlFindActivationContextSection*` — apphelp/SxS), the
**environment / current-directory / full-path** family (`RtlCreateEnvironment`,
`RtlExpandEnvironmentStrings_U`, `RtlGetFullPathName_U`, `RtlDosSearchPath_U`,
`RtlSetCurrentDirectory_U` — need the PEB process-params + CWD from Step 3), the **registry-shim**
`Rtlp*` (`RtlpNtOpenKey`/`RtlpNtQueryValueKey`/`RtlpNtSetValueKey` — thin `Nt*Key` wrappers,
land with the stub bodies), the **timer-queue / thread-pool / work-item** family
(`RtlCreateTimerQueue`, `RtlQueueWorkItem`, `RtlRegisterWait` — need the thread-pool plane), the
**handle-table** (`RtlInitializeHandleTable`/`RtlAllocateHandle`), the **resource** RW-lock
(`RtlInitializeResource` — a heavier cousin of SRW), **atom tables** (`RtlCreateAtomTable` etc. —
reuse `nt-kernel-exec::rtl_atom`), **pointer encode/decode** (`RtlEncodePointer`/`RtlDecodePointer`
— need the process cookie), **image helpers** (`RtlImageNtHeader`/`RtlImageDirectoryEntryToData`/
`RtlPcToFileHeader` — reuse `nt-pe-loader`), and the **exception raisers** (`RtlRaiseException`/
`RtlRaiseStatus` — target-only, pair with `Ki*`).

---

## Step 2c Results (landed 2026-07-16)

Completed the ntdll **export surface** — the full 188 `Nt*` stub bodies + arg marshalling,
`Csr*`/`Dbg*`/`Ki*`, and the state-coupled `Rtl*` stragglers — host-tested, **ZERO boot risk**
(new modules only; nothing wired into the boot, executive runtime + `rust-micro/src` untouched;
`nt-ntdll` is a separate `[workspace]` from the executive so it cannot perturb the staged binary —
verified: `components/ntos-executive/build.sh` stages green after the change). **nt-ntdll: 127
tests** (up from 68); **nt-syscall-abi: 12** (added the arity table). Clippy-clean (nt-ntdll);
builds on both the host and the `x86_64-unknown-none` target (the naked trap stubs + all target asm).

### 1. The full 188 `Nt*` trap-stub bodies + arg marshalling
- **`src/trap_stubs.rs`** — a `generate_trap_stubs!` macro emits all **188** naked x86_64 stubs, each
  the canonical `mov r10,rcx; mov eax,<ssn>; syscall; ret` (`#[unsafe(naked)]` + `naked_asm!`,
  `#[cfg(target_arch="x86_64")]`; host builds get only the metadata table). ★ Per the ABI, args >4
  **stay on the caller's stack** for the trap path — the kernel reads them there, so there is NO
  stack thunk; the naked `syscall; ret` forwards register + stack args untouched. Host-tested that
  the generation covers all 188 with the exact SSN + arity, no dup name/SSN, and matches the shared
  `nt-syscall-abi` table (`generated_ssns_match_the_shared_abi_exactly`).
- **`src/marshal.rs`** — the arity-driven gatherer for the **non-trap** transports (seL4 `Call` /
  SURT ring), which — unlike the trap — must GATHER every arg incl. the stack tail into a
  self-contained IPC message. An `ArgSource` trait (register window + stack window; host mock =
  `SliceArgSource`/`FlatArgSource`) + `marshal(ssn, argc, src)` → `Marshalled { ssn, args }`.
  Arity comes from the new **`nt-syscall-abi::NT_ARGC` / `argc_of`** table (every one of the 188 has
  an exact arity; unknown → conservative `MAX_STUB_ARGS`=14). Host-tested incl. the **>4-arg case**
  (NtCreateFile = 11 args: 4 reg + 7 stack) and the widest (NtCreateNamedPipeFile = 14). The
  transport's `Sel4Call`/`SurtRing` arms now **marshal-then-seam** (build the message, then return
  `STATUS_NOT_IMPLEMENTED` at the honest send seam — never a fabricated result; real send = Step 6).

### 2. `Csr*` (8) — `src/csr.rs`
CSR client over `nt-port-core`: the `CSR_API_MESSAGE` construction (`CsrApiNumber` =
`CSR_MAKE_API_NUMBER(dll,api)`, fixed-arg block, `PORT_MESSAGE`-framed length) + the
**`CSR_CAPTURE_BUFFER`** marshalling (`CsrAllocateCaptureBuffer`/`CsrCaptureMessageBuffer`/
`CsrFreeCaptureBuffer` — 8-byte-aligned packing + server-relocatable `CapturedPointer` descriptors +
capacity/pointer-count rejection) + `CsrClientConnectToServer`/`CsrClientCallServer`/
`CsrGetProcessId`. The actual port SEND is the **LPC seam** (`NtRequestWaitReplyPort` over
`nt-port-core`, wired later): `call_server` builds the message + returns `STATUS_NOT_IMPLEMENTED`
(connected) / `STATUS_INVALID_PARAMETER` (unconnected) — the round-trip is NOT faked. Host-tested.

### 3. `Dbg*` (12) — `src/dbg.rs`
The debug-print family: `render`/`render_with_prefix` reuse the 2b `_snprintf`-core; `DbgPrintEx`
**component/level filtering** (`ComponentFilter::should_print` — ERROR always, bit-index + masked-
raw levels, host-tested); `DbgPrompt` request shape (the response goes in **R8** on our kernel — the
`project_smss_sec_image` fix — modelled, not faked); the `int 0x2d` DebugService `emit` +
`DbgBreakPoint`/`DbgUserBreakPoint` (`int3`) are `#[cfg(target_arch="x86_64")]`. Host-tests cover
formatting + level filtering + the prompt shape.

### 4. `Ki*` dispatchers — `src/ki.rs` (+ the SEH machinery in `src/rtl/exception.rs`)
The four user dispatchers the **kernel jumps to** (0 imported — but load-bearing: APC/SEH/callback
delivery): `KiUserApcDispatcher` (unpack `(routine,args,CONTEXT)` → call + `NtContinue`),
`KiUserExceptionDispatcher` (run `RtlDispatchException` → Continue/LastChance/Noncontinuable),
`KiUserCallbackDispatcher` (the win32k `KeUserModeCallback` bridge — resolve
`PEB->KernelCallbackTable[ApiIndex]` → call → `NtCallbackReturn`), `KiRaiseUserExceptionDispatcher`.
The **dispatch LOGIC** is host-tested; the machine-context save + `NtContinue`/`NtCallbackReturn` are
honest target seams (return `STATUS_NOT_IMPLEMENTED` on the host — no fabricated resume). Paired with
**`src/rtl/exception.rs`** — the x64 table-based SEH machinery: `RtlDispatchException` (frame walk),
`RtlUnwind` (2nd pass / `__finally`), `RtlAddFunctionTable`/`RtlLookupFunctionEntry` (`.pdata`
`RUNTIME_FUNCTION` registry with binary-search lookup). **This is the machinery Step 3's loader
needs** (SEH + function-table registration during `DLL_PROCESS_ATTACH`).

### 5. `Rtl*` stragglers — delegate/reuse, honest seams
- **`src/rtl/security.rs`** — SID/ACL/SD family (`RtlLengthSid`/`RtlCreateAcl`/`RtlAddAce`/
  `RtlCreateSecurityDescriptor`/`RtlSetDaclSecurityDescriptor`/`RtlMapGenericMask`/…) **delegated to
  `nt-security`** (re-exports its `Sid`/`Acl`/`Ace`/`SecurityDescriptor` — ONE SID model, no copy).
- **`src/rtl/atom.rs`** — atom tables **reuse `nt-kernel-exec::rtl_atom`** (`OwnedAtomTable`).
- **`src/rtl/environment.rs`** — env / CWD / full-path (`RtlCreateEnvironment`/
  `RtlQueryEnvironmentVariable_U`/`RtlSetEnvironmentVariable`/`RtlExpandEnvironmentStrings_U`/
  `RtlGetCurrentDirectory_U`/`RtlSetCurrentDirectory_U`/`RtlGetFullPathName_U` +
  `RtlNormalizeProcessParams` over `nt-ntdll-layout`'s `RTL_USER_PROC_PARAMS_NORMALIZED`). Pure logic
  over an in-Rust env/cwd model; the live-PEB pointer is the documented Step-3 seam.
- **`src/rtl/encode.rs`** — `RtlEncodePointer`/`RtlDecodePointer` (+ system variants): the exact
  `rotr64(ptr ^ cookie, cookie&0x3F)` bijection; the process-cookie source is the Step-3 seam.
- **`src/rtl/image.rs`** — `RtlImageNtHeader`/`RtlImageDirectoryEntryToData`/`RtlImageRvaToVa`/
  `RtlImageRvaToSection`/`RtlPcToFileHeader` **reuse `nt-pe-loader::PeFile`**.

### ★ SSN reconciliation finding + recommendation (NtCreateProcessEx 50 vs NtCreateProcess 49)
The imported surface (measured Step 1) contains **`NtCreateProcessEx` (SSN 50)** — the ntdll export
ReactOS binaries actually link — while the **executive currently dispatches `NtCreateProcess`
(SSN 49)**. Both are real `sysfuncs.lst` entries (49 = NtCreateProcess, 50 = NtCreateProcessEx). The
shared `nt-syscall-abi` table honestly carries the **imported** name+SSN (`NtCreateProcessEx`, 50).
**Recommendation for Step 4 (do NOT change the executive now):** teach the **executive** to dispatch
**SSN 50 = NtCreateProcessEx** (the arg-superset: `NtCreateProcessEx` adds a `JobMemberLevel` param
and drops the debug/exception-port pair into flags) and route SSN 49 as a thin shim onto the same
handler (49's args are a prefix of 50's). Do NOT alias 49→50 in ntdll — our ntdll should emit the
**real** stub the binary imports (50), and the executive is the one place that already owns the
create policy, so it's the natural place to learn 50. This keeps ntdll import-by-name faithful and
localizes the change to the create-dispatch site (which `project_process_convergence` already owns).
Net: **one executive dispatch arm added at cutover, zero ntdll aliasing.**

### What remains for Step 3 (the loader)
`LdrpInitialize` over the `nt-ntdll-layout` PEB/TEB/LDR structs + `nt-pe-loader`: PEB/TEB setup at
the exact offsets, process-param normalization (uses `rtl::environment`), the `PEB->Ldr` module-list
build, recursive import snap **incl. forwarders** (kills the `_vista`/SxS gaps), TLS callbacks, and
`DLL_PROCESS_ATTACH` ordering — plus wiring the SEH function-table registration (`rtl::exception`)
and the process cookie (`rtl::encode`) / live-PEB pointers (`rtl::environment`) that this step's
stragglers left as documented seams. The syscall/port/context SENDs (Sel4Call/SurtRing/LPC/
NtContinue) remain the Step-6 transport flip.

---

## Step 3 Results (landed 2026-07-16 — the loader ENGINE, host-tested, forwarders PROVEN)

The host-testable **graph engine** at the heart of `LdrpInitialize` — import resolution incl.
**forwarders**, `DLL_PROCESS_ATTACH` ordering, `PEB->Ldr` construction, and the orchestration —
lands in a new `crates/nt-ntdll/src/loader/` module set, **host-tested over mock modules**, with the
live map/call/gs paths honest `LoaderHost` seams (Step 4). **ZERO boot risk** — new modules only;
nothing wired into the boot, executive runtime + `rust-micro/src` untouched (nt-ntdll is a separate
`[workspace]` from the executive, verified: `components/ntos-executive/build.sh` stages green). **18
new tests (`nt-ntdll` 127 → 145)**; clippy-clean (nt-ntdll); builds on host + `x86_64-unknown-none`.

### 1. The module graph + import resolution incl. FORWARDERS — `loader/module.rs` + `loader/resolve.rs`
- **`module.rs`** — `LoadedModule` (base VA + parsed export/import tables) + `LoaderState` (the
  module set, keyed **case-insensitively** with an implied `.dll` suffix — the real Ldr's
  `LdrpFindLoadedDllByName` behavior). `LoadedModule::from_pe` builds it from an `nt-pe-loader`
  `PeFile` (reusing `parse_exports`/`parse_imports`) and **detects forwarders**: an export whose RVA
  falls inside the export-directory range is a `"TARGETDLL.func"` / `"TARGETDLL.#ordinal"` string
  (parsed by `parse_forwarder`, splitting on the LAST `.` so api-set DLL names with dots work).
  `LoadedModule::mock` builds a synthetic module for the host graph tests.
- **`resolve.rs`** — `LdrpSnapThunk`-equivalent: `snap_module`/`snap_all` resolve every import against
  the loaded set (name or ordinal → concrete address), and **★ recursive forwarder resolution**
  follows chains `A→B→C` with **cycle detection** (an on-chain repeat or a >16-hop depth → a
  structured `ResolveError::ForwarderCycle`, never a spin). **★ THE MARQUEE PROOF** (`forwarder_
  resolves_vista_pattern`): a mock `foo.dll` exporting `Bar` as a forwarder to `foo_vista.dll!Bar`
  resolves to `foo_vista`'s concrete `Bar` **WITHOUT any pinning hack** — the 3 documented `_vista`
  pins are obsolete + this generalizes (chain, by-ordinal, cycle all tested). Missing module/export
  = `ResolveError::ModuleNotFound` / `ExportNotFound` (real STATUS, not the demand-load spin).

### 2. Dependency ordering for `DLL_PROCESS_ATTACH` — `loader/order.rs`
`initialization_order` = a **post-order DFS** over the import graph → dependencies-before-dependents
(the `InInitializationOrderModuleList` order). **Cycle-tolerant**: an on-stack back-edge is broken
(init in load order within a cycle — the real Ldr rule), so the traversal always terminates with a
total order. Host-tested: a **diamond** (`app→{b,c}→d`: d before b/c before app) + a **cycle**
(`b↔c` terminates, all modules present). NOTE: a forwarder target is loaded + initialized but is not
an import edge, so it is not ordered by the import graph (matches the real Ldr).

### 3. `PEB->Ldr` construction + list threading — `loader/peb.rs`
`build_ldr` materializes one `LDR_DATA_TABLE_ENTRY` per module (over `nt-ntdll-layout`'s byte-exact
structs) and **threads all three `LIST_ENTRY` lists** — `InLoadOrder`/`InMemoryOrder` (@ entry
+0x00/+0x10) + `InInitializationOrder` (@ +0x20) — circularly through the `PEB_LDR_DATA` head (@
+0x10/+0x20/+0x30), by **absolute VA** (model VAs host-side; a scratch alloc live). Host-tested by
**walking** the built `InLoadOrder`/`InInitializationOrder` lists (follow flinks from the head) and
recovering the modules in the right order — the exact traversal a hosted binary / debugger does.
Entry fields (dll_base/entry_point/size_of_image/base_dll_name length) asserted. (Added `Default`
derives to the four layout structs so the entries can be constructed from outside the layout crate
without touching the private `_pad` fields — no layout change.)

### 4. `LdrpInitialize` orchestration + the `LoaderHost` seam — `loader/init.rs` + `loader/host.rs`
`ldrp_initialize(state, params, host)` ties it together in the real Ldr order: (1) normalize params
(`rtl::environment::normalize_flags` → NORMALIZED bit), (2) compute the process cookie
(`compute_process_cookie`, deterministic-from-seed host-side, non-zero), (3) map every module, (4)
resolve ALL imports incl. forwarders + write each IAT slot, (5) compute the ATTACH order, (6) build
`PEB->Ldr` + commit PEB/TEB, (7) run TLS callbacks + `DLL_PROCESS_ATTACH` in dependency order (the
EXE gets no DllMain — its entry is the transfer target), (8) transfer to the entry. A `DllMain`
returning FALSE → `STATUS_DLL_INIT_FAILED`; a missing dep → `STATUS_DLL_NOT_FOUND`. **All host-tested
over a mock set + a recording `MockHost`** (asserts exactly what the loader drove: mapped 4,
NtClose IAT write = the forwarded ntdll_vista address, DllMain order deps-first, PEB/TEB committed,
transferred to app's entry).

**★ The `LoaderHost` seam** (`host.rs`) — the honest boundary between the host-testable engine and
the four live-process ops: `map_image` (NtAllocateVirtualMemory + copy/relocate + NtProtect),
`write_iat_slot`, `call_dll_main` / `run_tls_callbacks` (transfer into target code),
`commit_peb_teb` (gs-relative writes), `transfer_to_entry` (NtContinue-style). **`MockHost`** records
the drive (host tests); **`NullHost`** returns `STATUS_NOT_IMPLEMENTED` for every op — the invariant
proof (`null_host_never_fakes_a_live_operation`) that the engine **NEVER fabricates a live result**.
The real on-target host is Step 4.

**★ apphelp — the correct behavior** (`ShimPolicy`): the loader loads the shim engine (`apphelp.dll`)
**only if a shim database matched** (`ShimPolicy::LoadShimEngine`); the default `NoShims` does NOT
load apphelp — the *correct* Windows behavior, replacing the executive's ad-hoc apphelp denylist
hack (`project_full_fs.md`). Owning the loader makes this a policy decision, host-tested both ways.

### What Step 4 must wire (the live path)
- **The real `LoaderHost` impl** (on-target): `map_image` = the demand-load / NtAllocateVirtualMemory
  path (reuse `nt-pe-loader::MappedImage` + `relocations`); `write_iat_slot` = a raw write into the
  live image; `call_dll_main` / `run_tls_callbacks` = a control transfer with the `CONTEXT`;
  `commit_peb_teb` = the gs-relative PEB/TEB writes (the byte-exact offsets are in `nt-ntdll-layout`);
  `transfer_to_entry` = the `NtContinue`/trampoline hand-off. The `LdrDataTableEntry` name-buffer VAs
  + the `RTL_USER_PROCESS_PARAMETERS` UNICODE_STRING pointer-rebase (denormalize→normalize) also
  land here (the model leaves `buffer` = 0).
- **The executive-side SSN-50 arm** (`NtCreateProcessEx` — see the Step 2c reconciliation): teach the
  executive to dispatch SSN 50 (49 as a prefix shim) so our ntdll's real imported stub routes.
- **The transport flip** (Step 6): the syscall/port/context SENDs (Sel4Call/SurtRing/LPC/NtContinue)
  from x86-trap to native seL4 Call/SURT once parity holds.
- Wire the SEH function-table registration (`rtl::exception::FunctionTable::add`) during ATTACH + the
  process cookie into `rtl::encode`'s `RtlEncodePointer`.

## Step 4 Plan (from recon, 2026-07-16)
The executive currently acts as an EXTERNAL loader for the real ntdll. Key recon findings:
- **The executive does NOT snap imports** — the real ntdll's `LdrpSnapThunk` does it IN-PROCESS. So OUR ntdll's loader owns import snapping (our `loader/resolve.rs` already does). The executive only demand-maps pages (`fill_image_page` img_spawn.rs:239-266) + registers modules in `nt-dll-registry`.
- **The executive PRE-STAGES TEB/PEB/params/NLS/KUSER at spawn** (img_spawn.rs:346-532) → `commit_peb_teb` is largely already done; our loader mainly builds `PEB->Ldr` + snaps imports. gs-base set to `SMSS_TEB_VA` at TCB creation (img_spawn.rs:592).
- **smss statically imports ONLY ntdll** → snapping smss's imports resolves against OUR OWN export table (no other DLLs to load) = the cleanest first target.
- **The trampoline** (img_spawn.rs:542-574) calls `LdrpInitialize @ NTDLL_BASE+0x8e70` (REAL ntdll's RVA — Step 4 must use OUR LdrpInitialize's RVA), then chains to smss entry with RCX=PEB.
- **Substitution point**: `spawn_sec_image(pi, pe, ..., ntdll_base, ...)` (img_spawn.rs:271) — for pi 0 pass OUR ntdll PE; keep real ntdll for pi>=1 (fallback). Call site service_sec_image.rs:96-142.
- **LoaderHost→executive map**: `map_image`→fill_image_page/apply_relocations_to_buf(img_spawn.rs:835-871); `write_iat_slot`→smss_copyout(img_spawn.rs:652-661)/stack-mirror; `commit_peb_teb`→already pre-staged; `transfer_to_entry`→the trampoline's `call entry` (img_spawn.rs:568). Our loader OWNS snap; executive provides memory+registration.
- **SSN-50 reconciliation**: add `NtCreateProcessEx`(50) to nt-syscall enum + `SSN_NT_CREATE_PROCESS_EX=50` (main.rs) + dispatch arm (exec_handler.rs ~4781; 49's args are a prefix of 50's).

### ☑ Step 4.0 — EMIT nt-ntdll as a loadable PE32+ DLL (DONE 2026-07-16, LOCAL emit, host-verified)
Make `nt-ntdll` build to a PE32+ DLL with a correct EXPORT directory + relocations + no_std + no CRT.
**LANDED (local emit on macOS — no mingw, no CI needed):** a **verified PE32+ ntdll.dll** is produced
by a reproducible script + parsed by the executive's OWN loader. **ZERO boot risk** — no boot wiring;
executive still builds byte-identically (`rootserver.elf` MD5 `14c6615f…` unchanged); `nt-ntdll`
host tests still **145/145** green.

**Design fork resolved → the CLEAN way (wrapper crate, NOT crate-type on the rlib):** a NEW thin
`crates/nt-ntdll-dll` **cdylib** wraps the host-tested `nt-ntdll` **rlib** — so the rlib keeps its
145 `cargo test` host tests (a cdylib crate-type would have conflicted). It is its **OWN `[workspace]`**
+ **excluded** from the main workspace (a no_std PE cdylib can't build for the host, so
`cargo build --workspace` must not try — same convention as the bare-metal crates).

**The working build invocation** (`scripts/build_ntdll_dll.sh`, fully reproducible):
- **Target:** a **custom JSON target** `crates/nt-ntdll-dll/x86_64-pc-windows-gnullvm-nostd.json`
  derived from `x86_64-pc-windows-gnullvm` with the **mingw import libs stripped**
  (`late-link-args` dropped: no `-lmingw32/-lmingwex/-lmsvcrt/-lkernel32/-luser32`) and the **CRT
  startup objects removed** (`*-link-objects*` dropped) → no mingw toolchain needed on macOS.
- **Linker = the BUNDLED `rust-lld`** (`linker="rust-lld"`, `linker-flavor="gnu-lld"`,
  `link-self-contained.components=["linker"]`). (`x86_64-pc-windows-gnullvm` FIRST-choice would have
  used `x86_64-w64-mingw32-clang` which isn't on macOS; the custom spec + rust-lld avoids it.)
- **Flags:** `-Z build-std=core,alloc,panic_abort` + `-Z build-std-features=compiler-builtins-mem`
  (supplies `memcpy/memcmp/…` since we drop msvcrt) + `-Z json-target-spec`; `RUSTFLAGS` =
  `-Zunstable-options -Cpanic=immediate-abort` (no_std, no unwinder — this nightly's panic strategy
  is `immediate-abort`, NOT the old `panic_immediate_abort` build-std feature) +
  `-Clink-arg=--no-gc-sections` (**load-bearing**: `--gc-sections` collected the base-reloc chunks →
  empty `.reloc`; `--no-gc-sections` keeps a real `.reloc`). `--release` (742→734 KB; debug is ~6 MB
  of DWARF).
- **The cdylib provides the no-CRT runtime bits** (`src/lib.rs`): a `#[panic_handler]`, a placeholder
  `#[global_allocator]` (the rlib links `alloc`; Step 4.B swaps in the real `heap`-backed one),
  `DllMain`/`DllMainCRTStartup` (the entry, so no CRT `_DllMainCRTStartup` dep), `fma`/`fmaf` stubs
  (libm float-traits pull them; never on a live path), and a `#[used]` `KEEP_TRAP_STUBS` anchoring
  the rlib's new `#[used] TRAP_STUB_ADDRS` fn-ptr table so the linker RETAINS all 188 stubs.
- **Export mechanism:** changed the `generate_trap_stubs!` macro's `#[no_mangle]` → **`#[export_name = $name]`** so the PE export directory lists the REAL Windows names (`NtClose`, not `nt_close`).
  Host tests unaffected (they test the metadata table, not the symbol names).

**The export directory (verified):** **193 total exports = 188 `Nt*` + `LdrpInitialize` + `DllMain` +
`DllMainCRTStartup` + `fma` + `fmaf`**. `objdump` + our own loader confirm **all 188 `Nt*` present, 0
missing**; spot-checks `NtClose/NtCreateFile/NtOpenFile/NtDelayExecution/NtWaitForSingleObject/
NtProtectVirtualMemory` all present. **`LdrpInitialize` RVA = `0x1010`** (release build; NOT
stable across builds — Step 4.B/4.A must derive it from the export table, never hardcode it).

**objdump proof:** `file` → `PE32+ executable (DLL) (GUI) x86-64, for MS Windows`; Magic `0x020b`
(PE32+); Characteristics `0x2022` (**IMAGE_FILE_DLL**); DllCharacteristics `0x160`
(DYNAMIC_BASE+NX+HIGH_ENTROPY); sections **`.text .rdata .data .pdata .reloc`** (+ `.edata` export
dir); image_base `0x180000000`; subsystem 2 (GUI).

**★ Real compatibility proof — the executive's OWN loader parses it:** new host tool
`tools/ntdll-dll-verify` runs `nt-pe-loader::PeFile::parse` over the DLL and asserts PE32+ +
IMAGE_FILE_DLL + all 188 Nt* + LdrpInitialize exported + a non-empty base-reloc dir → **PASS
(2040 reloc fixups parse cleanly)**. If our loader can read it, the executive can load it (Step 4.B).
Wired into the build script as the hard gate.

**Staged DLL path (for Step 4.A to substitute): `.tmp/nt-ntdll.dll`** (gitignored build artifact;
regenerate with `./scripts/build_ntdll_dll.sh`). CI fallback also added
(`.github/workflows/ci.yml` job `ntdll-dll` builds + verifies + uploads the artifact on Linux).

**⚠ KNOWN GAP (tracked for Step 4.B, NOT part of the 4.0 gate):** the DLL exports the **Nt\* + Ldrp**
surface but **NOT yet the `Rtl*` smss imports** (smss imports ~44 Rtl\*; per Step 1). The Rtl bodies
EXIST in the rlib but as Rust-ABI fns, not `extern "C"` PE exports — exporting them is mechanical
`#[export_name]` C-ABI wrappers over the existing `rtl::*` (the PE-emit machinery proven here
generalizes trivially). **smss won't fully resolve against our ntdll until these land** — do it as the
first task of Step 4.B (or a 4.0b increment) alongside the real `LoaderHost`. **→ RESOLVED by Step 4.0b below.**

### ☑ Step 4.0b — COMPLETE the export table for smss (DONE 2026-07-16, host-proven 0-missing)
Closed the Step-4.0 known gap: the DLL now exports smss.exe's **FULL** ntdll import set — the last
piece before the Step 4.A live substitution. **ZERO boot risk** (only the `nt-ntdll-dll` cdylib + the
verify tool + the plan touched; executive still builds byte-identically, `rootserver.elf` MD5
`14c6615f…` UNCHANGED; `nt-ntdll` rlib untouched → **145/145** host tests green).

**The measured target (authoritative worklist):** smss.exe imports **103 symbols** from ntdll —
**42 `Nt*`** (already exported by 4.0) + **61 non-`Nt*`**: ~44 `Rtl*`, 2 `Ldr*`
(`LdrQueryImageFileExecutionOptions`, `LdrVerifyImageMatchesChecksum`), 2 `Dbg*` (`DbgPrint`,
`DbgBreakPoint`), and ~13 CRT/other (`memcpy`/`memset`/`wcslen`/`wcscpy`/`wcsstr`/`_wcsicmp`/`_wcsupr`/
`_stricmp`/`sprintf`/`swprintf`/`_vsnprintf`/`_vsnwprintf`/`__C_specific_handler`). Measured by
extending `tools/ntdll-dll-verify` to parse smss's ntdll import descriptor with `nt-pe-loader` (no
llvm-objdump dependency — that binary isn't on the dev shell).

**Export mechanism** (`crates/nt-ntdll-dll/src/exports.rs`, a new module in the cdylib): each symbol
is a `#[export_name = "RtlXxx"] pub unsafe extern "system" fn` (or `extern "C"` for the CRT) C-ABI
wrapper with the **real ntdll x64 signature** (cross-checked against `references/reactos/sdk/lib/rtl`:
`RtlInitUnicodeString` sets `Length=size`/`MaximumLength=size+sizeof(NUL)`; `RtlAdjustPrivilege(ULONG,
BOOLEAN,BOOLEAN,PBOOLEAN)`; etc.). Bodies operate on raw pointers via the byte-exact
`nt-ntdll-layout::UnicodeString` and call the host-tested `nt_ntdll::rtl::*`/`crt` logic where a body
exists. **Retention:** a `#[used]` anchor fn (`exports::export_anchor`, address-of's all 61) is
referenced by a `#[used] KEEP_EXPORTS` in `lib.rs` — the same anti-DCE mechanism as the `Nt*`
`TRAP_STUB_ADDRS`, adapted because the 61 heterogeneous signatures can't be `as`-cast to one
fn-pointer type in a `const` (address-of at runtime in the anchor body sidesteps that).

**Signature/link subtleties handled:** (1) `memcpy`/`memset` are also emitted (weak, hidden) by the
`compiler-builtins-mem` build-std feature → defined ours `#[linkage="weak"]` (`#![feature(linkage)]`)
to avoid a duplicate-strong-symbol link error while still landing them in the PE export directory.
(2) The C-variadic exports (`DbgPrint`/`sprintf`/`swprintf`) declare only the fixed args — the Win64
ABI leaves the variadic tail in caller regs/stack (which we never read) — so no `c_variadic` nightly
feature is needed; ABI-safe no-op bodies.

**Honesty discipline (project rule):** self-contained symbols (string init/compare/append, integer
parse, CRT mem/str/wcs, critical-section fast paths, SID length, ACL/SD header init) are **fully
implemented — correct on a live path**. Symbols needing the live process plane not yet wired at 4.0b
(process heap for `RtlAllocateHeap`/`RtlFreeHeap`/`RtlCreate*`; live PEB for env/CWD/paths;
boot-status device; `RtlCreateUserProcess/Thread`; SEH `__C_specific_handler`; live token/registry)
export at the correct ABI but return an **honest failure** (real `NTSTATUS`/null/FALSE) — NEVER a
fabricated success. Step 4.A/4.B wires the live plane, at which point these bodies light up.

**PROOF (the deliverable — makes 4.A safe):** `tools/ntdll-dll-verify` now cross-checks smss's parsed
ntdll imports against our export table and asserts **0 missing**. Result on the rebuilt DLL:
**254 total exports** (188 `Nt*` + `LdrpInitialize`/`DllMain`/… + the 61 new), **smss's 103-symbol
ntdll import set 100% covered (0 missing)**, 188 `Nt*` still present (0 missing), `.reloc` intact
(2042 fixups), nt-pe-loader parses it PE32+/DLL. `LdrpInitialize` RVA drifted `0x1010`→`0x1050`
(as expected; Step 4.A/4.B derives it from the export table, never hardcodes). **The DLL is now a
complete drop-in for smss — READY FOR 4.A substitution.**

### ☑ Step 4.A — first control: our ntdll substituted for smss (pi 0), OUR Rust PROVEN running in-process + a live trap serviced (DONE 2026-07-16)
**The milestone: our Rust ntdll's `LdrpInitialize` executed in smss's isolated VSpace and issued an
`int 0x2d` DebugService trap the kernel serviced — the observable line
`[dbg] nt-ntdll: our Rust LdrpInitialize running in smss (Step 4.A)` appears in the boot log with the
flag ON.** Committed with the flag OFF → the gate stays green via the real-ntdll fallback. **sel4test
byte-identical (NO `rust-micro/src` change — only `scripts/make_image.sh`).**

**The staging + substitution mechanism (all executive-side + scripts):**
- **Staging (scripts-only):** `make_image.sh` (rust-micro) stages `../.tmp/nt-ntdll.dll` (built by
  `scripts/build_ntdll_dll.sh`) BY PATH at **`\reactos\system32\nt-ntdll.dll`** — a DISTINCT leaf, so
  the real ReactOS `ntdll.dll` is untouched (the pi>=1 fallback). Absent DLL → the note prints, boot
  stays on real ntdll (never fails the image build).
- **The revert flag:** `SMSS_USE_OUR_NTDLL: bool` (main.rs, next to `NTDLL_BASE`). **`false` = the
  committed-green boot** (real ntdll everywhere). `true` = OUR ntdll for smss/pi 0 only. A `const`, so
  OFF dead-code-eliminates the substitution branch.
- **The substitution (main.rs, the live smss spawn ~6700):** with the flag ON, `load_dll_from_fs(
  OUR_NTDLL_FS_PATH, …)` reads our DLL into the FS pool (a `'static` slice), relocates it to
  `NTDLL_BASE` (`apply_relocations_to_buf`), and passes OUR `PeFile` as the ntdll arg to BOTH
  `spawn_sec_image` (so the demand-fault router fills ntdll pages from OUR bytes) and
  `service_sec_image`. Any failure (load/parse/no-LdrpInitialize) → falls back to real ntdll (a
  logged miss = still green).
- **The trampoline LdrpInitialize-RVA derivation (NEVER hardcoded):** `spawn_sec_image` gained an
  `ldrpinit_rva: u64` param (0 = the real ntdll's fixed `0x8e70`). At smss spawn we call
  `our_pe.exports()` (nt-pe-loader) → find `"LdrpInitialize"` → its RVA (`0x1050` this build, drifts),
  and pass it. The trampoline emits `movabs rax, NTDLL_BASE + <that rva>; call rax`. All pi>=1 call
  sites pass `0` (real ntdll) → byte-identical fallback.

**The observable proof (the deliverable):** the cdylib's `LdrpInitialize` (`crates/nt-ntdll-dll/
src/lib.rs`), as its FIRST action, emits the 60-byte marker via `int 0x2d; int3` with `eax=1`
(BREAKPOINT_PRINT), `rcx=msg`, `rdx=len` — the DebugService ABI the kernel already forwards to serial
(exceptions.rs `error_code==0x16a`). **★ The marker bytes are built on the STACK, NOT a `.rdata`
static** — the kernel's PRINT handler reads `rcx` DIRECTLY from kernel mode, so the buffer must be on
an already-mapped page; a fresh `.rdata` page is NOT demand-faulted yet → the first attempt (a
`.rdata` static) caused a KERNEL #PF at the marker VA (`cr2=NTDLL_BASE+0x5a0d0`). Stack buffer = fixed
(the stack is mapped at spawn). Boot-log flow with ON: `#PF 0x801050` (instr-fetch = smss enters OUR
LdrpInitialize, page faults RX in) → the marker prints → LdrpInitialize returns to the trampoline →
smss chains to its entry `0x572ee0` → calls its IAT `0x848f00` → stops safely at a null-ish deref
(`[vmf-out]`, `exec_reactos_smss_live_paged`/`_calls_into_ntdll` PASS). The IAT mismatch (smss's IAT
is resolved against REAL-ntdll export RVAs from `imports.bin`, but OUR export RVAs differ) is EXPECTED
— 4.B's real loader snaps imports in-process.

**The committed state (default OFF) + gate:** `SMSS_USE_OUR_NTDLL=false` → **All specs passed**, gate
**174/98**, paint **768/768 @ 0x003a6ea5** (verified). Flag ON boot: All specs passed, marker printed,
gate drops to **142/98** + paint FAILs (smss stops after the marker → doesn't launch csrss/winlogon →
no desktop paint) — the EXPECTED 4.A behavior (control proven, not the full boot). `nt-ntdll` host
tests 145/145.

**What 4.B wires next (the real LoaderHost):** replace the cdylib `LdrpInitialize` marker-then-return
with the live drive of `nt_ntdll::loader::ldrp_initialize` over a real on-target `LoaderHost`:
`map_image` (demand-load / NtAllocateVirtualMemory + relocate), `write_iat_slot` (snap smss's
ntdll-only imports IN-PROCESS against OUR export table — fixes the IAT-RVA mismatch that stops 4.A),
`commit_peb_teb` (the executive already pre-stages these), `transfer_to_entry` (NtContinue/trampoline
to smss's `NtProcessStartup`). Plus wire the real process heap allocator (swap the cdylib's
`AbortAllocator` for the `heap`-backed one) so `RtlAllocateHeap`/`RtlCreate*` light up. Goal: smss
reaches `NtProcessStartup` under OUR ntdll.
### ☑ Step 4.B — the in-process LoaderHost: real heap + import snap against OUR export table + transfer → smss reaches NtProcessStartup under OUR ntdll (DONE 2026-07-16)
**The milestone: our Rust ntdll's `LdrpInitialize` ran IN smss's VSpace, created a real process heap
(`NtAllocateVirtualMemory` → serviced), SNAPPED all 103 of smss's ntdll imports against OUR export
table (direct in-process IAT writes), then returned to the trampoline which chained to smss's real
entry — `smss reached NtProcessStartup and called back into OUR ntdll via the snapped IAT`.**
Committed with the flag OFF → the gate stays green via the real-ntdll fallback. **sel4test
byte-identical.**

**★ IN-PROCESS architecture (the recon's external-loader lean was wrong — this matches real ntdll):**
our `LdrpInitialize` runs in smss's own VSpace (4.A proved a trap from here is serviced), so the
LoaderHost does its work IN-PROCESS: (a) DIRECT memory reads/writes to already-mapped pages (smss's
IAT, our export dir), and (b) our own `Nt*` syscall stubs for kernel ops (the heap via
`NtAllocateVirtualMemory`). It does NOT touch executive-side primitives (`smss_copyout` etc.) — those
are for an executive-driven loader, which is NOT how ntdll works. smss imports ONLY ntdll, and BOTH
smss + ntdll are already mapped by the executive → `map_image` is a no-op; the only real work is the
heap + the import snap + the transfer.

**What landed (all cdylib + one executive trampoline line; NO `rust-micro/src` change):**
- **`crates/nt-ntdll-dll/src/on_target.rs`** — the in-process drive:
  - **`nt_allocate_virtual_memory(size)`** — an inline `Nt*` trap caller (`mov r10,rcx; mov eax,18;
    syscall`) for `NtAllocateVirtualMemory`. ★ `*BaseAddress`(RDX)/`*RegionSize`(R9) are STACK locals
    — the executive reads/writes them through its stack mirror (matches its NtAllocateVirtualMemory
    handler exactly). The two extra args (Type/Protect) sit at `[rsp+0x28]`/`[rsp+0x30]`.
  - **process heap** — `nt_ntdll::heap::Heap` (the host-tested first-fit free-list allocator) over a
    1 MiB `NtAllocateVirtualMemory` region, installed as the cdylib's `#[global_allocator]` (replaced
    the 4.0 `AbortAllocator`). So the loader's `alloc` works in-process, as real ntdll creates the
    process heap early. A pre-install alloc returns null (honest failure, never a bogus pointer).
  - **a minimal MAPPED-IMAGE PE walker (by RVA)** — in-process every image is already MAPPED, so
    RVA == offset-from-base (unlike `nt-pe-loader::PeFile`, which parses a FLAT FILE using section
    *file* offsets — wrong for a mapped image). `export_rva_by_name` walks OUR export directory
    (`AddressOfNames`/`AddressOfNameOrdinals`/`AddressOfFunctions`); `snap_smss_imports` walks smss's
    import descriptor array, and for the ntdll descriptor resolves each name→our-export-RVA and writes
    `NTDLL_BASE + rva` into the IAT slot (`*(iat) = addr`, a direct in-process write — the slot page is
    `.rdata` RW_NX + demand-faulted).
- **`crates/nt-ntdll-dll/src/lib.rs`** — `LdrpInitialize(Context, NtDllBase, smss_base)` now DRIVES:
  marker → `on_target::ldrp_drive(smss_base, ntdll_base)` (heap + snap) → a second marker reporting
  the snap result → return to the trampoline. The `#[global_allocator]` is the real process heap.
- **`components/ntos-executive/src/img_spawn.rs`** (the ONE executive change, flag-gated so flag-OFF
  is byte-identical) — the spawn trampoline passes **smss's image base in R8** (the LdrpInitialize C-ABI
  3rd arg) when calling OUR LdrpInitialize (`ldrpinit_rva != 0`); the real ntdll path still emits
  `xor r8d,r8d` (byte-identical). Our loader needs smss's base to find its import dir (real ntdll gets
  it from the PEB, which our minimal in-process path doesn't walk yet).

**The IMPORT-SNAP proof (the deliverable):** flag-ON boot log —
`[dbg] nt-ntdll: Step 4.B in-process loader drive (LdrpInit)` then
`[dbg] nt-ntdll: snap resolved=103 missing=0 spot=0x0000010000803060`. **All 103 of smss's ntdll
imports resolved (0 missing) against OUR export table**, and the spot IAT slot now holds
`0x1_0080_3060` = `NTDLL_BASE(0x1_0080_0000) + 0x3060` — a value that POINTS INTO OUR ntdll's exports
(fixing the 4.A IAT-RVA mismatch, where the executive had pre-snapped against REAL-ntdll RVAs).

**How far smss runs under OUR ntdll (the parity signal):** immediately after the snap the boot log
shows `#PF rip=0x…572ee0` (instr-fetch) = **smss's real entry `NtProcessStartup`** (PE_LOAD_BASE
`0x…560000` + entry RVA `0x12ee0`) executing under OUR ntdll, then `rip=0x…561150`/`…572ffb` (smss
`.text` running) and `rip=0x…808260` = **smss CALLING BACK INTO OUR ntdll** (`NTDLL_BASE + 0x8260`)
through the freshly-snapped IAT — cross-module control into our loader/RTL. **smss reached its entry
and drives our ntdll's exported surface.** (vs real-ntdll smss, which runs the full LdrpInitialize
process bring-up → SmpInit → spawns csrss; ours reaches the entry + the first exported-ntdll calls =
the point where 4.C's parity work — the `Rtl*`/`Nt*` bodies smss's `NtProcessStartup` exercises —
picks up.)

**The committed state (default OFF) + gate:** `SMSS_USE_OUR_NTDLL=false` → the real-ntdll fallback →
gate **174/98**, paint **768/768 @ 0x003a6ea5** (verified). **sel4test byte-identical** (the only
executive change is inside the `ldrpinit_rva != 0` branch, dead on flag-OFF; no `rust-micro/src`
change). `nt-ntdll` host tests **145/145**. Flag ON reproduces the snap + entry proof above.

**What 4.C wires next (parity → spawn csrss):** smss's `NtProcessStartup` now runs under OUR ntdll +
calls our exported surface; 4.C brings the exercised `Rtl*`/`Nt*`/`Ldr*` BODIES to real-ntdll parity
(the 4.0b honest seams — `RtlAllocateHeap` now HAS a live process heap to route to; process-param
normalization; the loader-module list `PEB->Ldr` a real binary walks) so smss progresses as far under
our ntdll as under real (SmpInit → SmpExecuteImage → `NtCreateProcessEx` for csrss). Add the executive
**SSN-50 arm** (`NtCreateProcessEx` — 49's args are a prefix of 50's; see the Step 2c reconciliation).
Keep the fallback + the gate green (174/98, paint 768/768) throughout.
### ◪ Step 4.C — parity: smss progresses as far under our ntdll as under real (spawns csrss); add the SSN-50 arm; keep fallback; gate green (174/98, paint 768/768) throughout. (4.B reached NtProcessStartup + snapped IAT; 4.C = the exercised Rtl*/Nt* body parity now that the process heap is live + the SSN-50 create arm.)

**IN PROGRESS 2026-07-16 — checkpoint 1 (4 real bodies, oracle-diff-driven; smss now runs DEEP into SmpInit under OUR ntdll):**

**The oracle.** The flag-OFF committed boot runs the SAME smss.exe on the REAL ReactOS ntdll (full LdrpInitialize → SmpInit → spawns csrss = `[sec-stop] csrss (badge 2) spawned`, 137 faults / 111 in ntdll). Flag-ON boots on OUR ntdll; the divergence point in smss's SSN ring / #PF trail is the wall — a Rtl/Nt body ours seams-out that real ntdll implements. Fix, re-emit the DLL, re-boot, repeat.

**The walls made real (each let smss run further — all in `crates/nt-ntdll-dll`, NO rust-micro/src change, sel4test byte-identical):**
1. **`RtlAllocateHeap` / `RtlFreeHeap`** (`exports.rs` → new `crate::process_heap_{alloc,free}` in `lib.rs`) — route to the 4.B in-process `nt_ntdll::heap` process heap (the `HeapHandle` is ignored: smss's process has one heap). Honors `HEAP_ZERO_MEMORY`. **Wall was:** smss's `NtProcessStartup` called `RtlAllocateHeap(Peb->ProcessHeap, 0, 0x1000)`; the 4.0b seam returned NULL → smss took its null branch → `NtTerminateProcess`. **After:** smss reaches its heap-alloc SUCCESS branch (`#PF rva 0x130b1`).
2. **`RtlUnicodeStringToAnsiString` / `RtlAnsiStringToUnicodeString`** (`exports.rs`, real) — narrow/widen via `nt_ntdll::rtl::convert` (LATIN1/ASCII-exact code page), destination buffer from the process heap when `AllocateDestinationString`, NUL-terminated, `STATUS_BUFFER_TOO_SMALL` on a too-small caller buffer. The pure convert logic is host-tested in nt-ntdll.
3. **`RtlAdjustPrivilege`** (`exports.rs` → new `on_target::rtl_adjust_privilege`) — the LIVE token dance via our own trap stubs (`syscall4`/`syscall6` helpers): `NtOpenProcessToken(129)` → build a one-entry `TOKEN_PRIVILEGES` → `NtAdjustPrivilegesToken(12)` → `NtClose(27)` → report `*WasEnabled`. The executive services the token plane (success no-ops), so this reports SUCCESS. **Wall was:** the seam returned STATUS_NOT_IMPLEMENTED inside smss's fatal-error reporter (which enables SeShutdownPrivilege before `NtRaiseHardError`).
4. **`RtlSetProcessIsCritical` / `RtlSetThreadIsCritical`** (`exports.rs` → new `on_target::rtl_set_{process,thread}_is_critical`) — LIVE `NtSetInformationProcess(ProcessBreakOnTermination=0x1D, 237)` / `NtSetInformationThread(ThreadBreakOnTermination=0x12, 238)` via trap stubs. **Wall was:** smss's `NtProcessStartup` tail calls `SmpInit` (smss rva 0x125f0) which does `RtlSetProcessIsCritical`+`RtlSetThreadIsCritical` FIRST; the seams returned STATUS_NOT_IMPLEMENTED → SmpInit bailed → `NtTerminateProcess`.

**How far smss runs under OUR ntdll now (the parity signal):** the flag-ON SSN ring (badge 0) is `18(our-LdrpInit heap), 237(SetProcCritical), 238(SetThreadCritical), 237(NtSetInformationProcess@SmpInit), 237, 129/12/27(RtlAdjustPrivilege), 190(NtRaiseHardError)`. smss's real entry `NtProcessStartup` runs → asserts Peb/ProcessParameters non-null → `RtlAllocateHeap` (success) → `RtlUnicodeStringToAnsiString` ×2 → calls **`SmpInit`** (smss rva 0x7f80) which runs `RtlCreateTagHeap`, `NtSetInformationProcess`, `RtlInitializeCriticalSection` ×2, then `SmpCreateSecurityDescriptors` (rva 0x5fc0: `RtlCreateSecurityDescriptor`+`RtlSetDaclSecurityDescriptor` — already real). It is now **deep inside SmpInit** (vs 4.B which stopped at the entry's first exported-ntdll call). Gate flag-ON: 143/98 (smss doesn't yet spawn csrss → no desktop paint) — the EXPECTED in-progress behavior.

**Remaining walls to the csrss-spawn (the 4.C milestone):** smss still stops at `NtRaiseHardError(190)` — a deeper SmpInit function (smss rva 0x5fc0's caller / the `NtCreatePort(\SmApiPort)` + `RtlCreateUserThread` SM-API path at rva ~0x8148/0x81fc, or an object-namespace / registry body) returns a status smss treats as fatal. Continue the oracle-diff grind: find the next divergent body, make it real, repeat, until smss reaches `SmpExecuteImage → NtOpenFile(csrss) → NtCreateSection(SEC_IMAGE) → NtCreateProcess[Ex]`. **The SSN-50 arm** (`NtCreateProcessEx`) is NOT yet needed (smss hasn't reached the create-process call under our ntdll) — add it when smss emits SSN 50 there.

**checkpoint 1 committed** (`ec07ac9`): gate 174/98, paint 768/768, flag OFF.

**IN PROGRESS 2026-07-16 — checkpoint 2 (SID/ACL builders + RtlCreateUserThread → smss SPAWNS its real SM API loop thread under OUR ntdll):**

Continuing the grind past checkpoint 1's SmpInit-early stop. The next walls, all in smss's
**`SmpInit`** (`SmpCreateSecurityDescriptors` + the SM-port/worker-thread setup):

5. **`RtlAllocateAndInitializeSid`** (`exports.rs`, real) — allocates `8 + 4*count` bytes from the
   process heap and writes a well-formed SID (Revision=1, SubAuthorityCount, 6-byte IdentifierAuthority,
   the sub-authorities). Rejects `count > 8` (STATUS_INVALID_SID).
6. **`RtlAddAccessAllowedAce`** (`exports.rs`, real) — appends a well-formed `ACCESS_ALLOWED_ACE`
   (Type=0, Flags=0, Size, Mask, Sid) after the ACL's existing ACEs, bumps AceCount, with an honest
   `AclSize` capacity check (STATUS_ALLOTTED_SPACE_EXCEEDED). (`RtlCreateSecurityDescriptor`/
   `RtlSetDaclSecurityDescriptor`/`RtlLengthSid`/`RtlCreateAcl`/`RtlGetAce` were ALREADY real.)
   **After 5+6:** smss passes `SmpCreateSecurityDescriptors` → **creates `\SmApiPort`** (`NtCreatePort`,
   SSN 48 now in the ring) + `NtCreateEvent`.
7. **`RtlCreateUserThread`** (`exports.rs` → new `on_target::rtl_create_user_thread` + a `syscall8`
   trap helper) — the LIVE `NtCreateThread(55)` path: allocates a thread stack
   (`NtAllocateVirtualMemory`), builds the amd64 **CONTEXT** (`Rip@0xF8=StartAddress`, `Rcx@0x80=Parameter`,
   `Rsp@0x98=stack top`) + an INITIAL_TEB, then issues `NtCreateThread(&ThreadHandle, THREAD_ALL_ACCESS,
   NULL, ProcessHandle, &ClientId, &Context, &InitialTeb, CreateSuspended)`. The executive's smss (pi 0)
   NtCreateThread handler reads that exact CONTEXT and **spawns the REAL SmpApiLoop thread** in smss's
   VSpace (`spawn_sm_loop_thread`). **★ PROVEN in the boot log:**
   `[sm-loop] spawning REAL SmpApiLoop thread: ctx=0x…105c36f0 entry=0x…56c5d0 port=0x…e` +
   `[sm-loop] spawned tcb=0x9f2a` — smss's SM API worker thread ACTUALLY spawns under OUR ntdll (the
   CONTEXT we built was read correctly). Ring now `18,237,238,237,237,48,18,55,18,55,37,129,12,27,190`
   (two `18,55` = RtlCreateUserThread's stack-alloc + NtCreateThread, ×2 threads). Gate flag-ON 145/98.

**How far smss runs now:** its real `NtProcessStartup → SmpInit` runs the FULL core-SM bring-up under
OUR ntdll — process-critical, security descriptors, **`\SmApiPort` creation, and the SM API loop thread
spawn** (the heart of the Session Manager). Still stops at a deeper `NtRaiseHardError(190)` — the next
wall is past the SM-loop spawn (SmpInit's subsystem-load / KnownDLLs / the SmpApiLoop that ultimately
does `SmpExecuteImage → NtCreateSection(SEC_IMAGE) → NtCreateProcess[Ex]` for csrss = the 4.C milestone).

**checkpoint 2 committed** (`ffa1e4c`): gate 174/98, paint 768/768, flag OFF.

**IN PROGRESS 2026-07-16 — checkpoint 3 (RtlCreateEnvironment → smss reads its registry environment under OUR ntdll):**

8. **`RtlCreateEnvironment`** (`exports.rs`, real) — allocates an environment block on the process
   heap. When `Inherit`, copies the current `PEB->ProcessParameters->Environment` (read via
   `NtCurrentPeb() = gs:[0x60]` → `+0x20` → `+0x80`, measured to the double-wide-NUL); else a minimal
   empty block. Writes the block to `*Environment`. **After:** smss passes `SmpCreateEnvironmentBlock`'s
   env creation → does the REAL registry environment reads: `NtOpenKey(125) ×2`, `NtDeleteValueKey(68)`,
   `NtClose(27)` (new in the ring). smss is now reading its environment from the registry under our ntdll.

**How far smss runs now:** ring `18,237,238,237,237,48,18,55,18,55,37,125,125,68,27,129,12,27,190`.
smss's `SmpInit → SmpCreateEnvironmentBlock` runs the SM-port + SM-loop-thread spawn AND the
registry-environment setup (NtOpenKey/NtDeleteValueKey) under OUR ntdll. **Next wall:
`RtlQueryRegistryValues`** (smss rva 0x9a1f, still a seam) — the table-driven registry reader
`SmpCreateEnvironmentBlock` uses to read the environment values. It's a large body (the
`RTL_QUERY_REGISTRY_TABLE` walk + direct/callback dispatch over NtOpenKey/NtQueryValueKey) — its own
focused increment. Then SmpInit proceeds toward the SmpApiLoop that does
`SmpExecuteImage → NtCreateSection(SEC_IMAGE) → NtCreateProcess[Ex]` for csrss (the 4.C milestone; add
the SSN-50 arm when smss emits SSN 50 there).

**checkpoint 3 committed** (`abae6b0`): gate 174/98, paint 768/768, flag OFF.

**IN PROGRESS 2026-07-16 — checkpoint 4 (RtlQueryRegistryValues → smss runs the object-namespace + subsystem setup under OUR ntdll):**

9. **`RtlQueryRegistryValues`** (`exports.rs`, real default-path) — walks the `RTL_QUERY_REGISTRY_TABLE`
   array (x64 entry 0x38 bytes: QueryRoutine@0x00, Flags@0x08, Name@0x10, EntryContext@0x18,
   DefaultType@0x20, DefaultData@0x28, DefaultLength@0x30; NULL/NULL terminator). Since our minimal
   registry holds none of these values, each entry falls to its DEFAULT (the documented absent-value
   behavior): `RTL_QUERY_REGISTRY_DIRECT` copies `DefaultData`→`EntryContext`; a callback entry with a
   non-`REG_NONE` `DefaultType` invokes `QueryRoutine(Name, DefaultType, DefaultData, DefaultLength,
   Context, EntryContext)`. Returns the first callback error, else SUCCESS. smss builds its environment
   from its compiled-in defaults + proceeds — exactly real ntdll's absent-value behavior.

**How far smss runs now (a BIG jump):** ring grew to 72 service-iters / 39 faults (19 in ntdll):
`…125,125,68,27,36,27,36,27,119,36,129,12,27,129,12,27,36,27,129,12,27,190`. New SSNs
`36=NtCreateDirectoryObject`, `119=NtOpenDirectoryObject` + repeated `129,12,27` (RtlAdjustPrivilege).
smss's `SmpInit` now runs the **object-manager namespace setup** (creates/opens `\Sessions`/`\??`-style
directories) + the subsystem-load privilege dance under OUR ntdll — matching the
`project_smss_sec_image` spec's SmpInit ordering. The SM-loop thread + `\SmApiPort` are up; smss is now
in the deeper subsystem-load phase. Still stops at a deeper `NtRaiseHardError(190)` (next oracle-diff
wall) on the path toward `SmpLoadSubSystemsForMuSession → SmpExecuteImage → NtCreateSection(SEC_IMAGE)
→ NtCreateProcess[Ex]` for csrss (the 4.C milestone; add the SSN-50 arm when smss emits SSN 50 there).

**The committed state (default OFF) + gate:** `SMSS_USE_OUR_NTDLL=false` → gate **174/98**, paint
**768/768 @ 0x003a6ea5** (verified). **sel4test byte-identical** (ONLY `crates/nt-ntdll-dll` changed;
NO rust-micro/src, NO executive change; rust-micro submodule clean). `nt-ntdll` host tests **145/145**.

**IN PROGRESS 2026-07-16 — checkpoint 5 (real registry reader + path/env bodies → smss runs the KnownDlls + DOS-devices + registry-environment + DYNAMIC environment variables under OUR ntdll, DEEP into SmpLoadSubSystemsForMuSession):**

The oracle-diff wall at ckpt 4 was **`RtlDosPathNameToNtPathName_U`** (sminit.c:1465, in `SmpInitializeKnownDllsInternal`) returning FALSE → `STATUS_OBJECT_NAME_INVALID` → `SmpTerminate` → `NtRaiseHardError`. Confirmed by trace: the pure `RtlpDosPathNameToRelativeNtPathName_U` issues NO syscall (invisible in the ring) — the "invisible seam". The ROOT was two coupled seams: (a) `RtlDosPathNameToNtPathName_U` was stubbed, AND (b) `SmpKnownDllPath` was NEVER populated because our `RtlQueryRegistryValues` was defaults-only (the `KnownDlls` config-table entry has `DefaultType=REG_NONE` → its callback `SmpConfigureKnownDlls` never ran; the real hive holds `Session Manager\KnownDlls\DllDirectory=%SystemRoot%\system32`).

**The walls made real (all in `crates/nt-ntdll-dll`, NO rust-micro/src change, sel4test byte-identical):**
10. **`RtlDosPathNameToNtPathName_U`** (`exports.rs`, real) — the fully-qualified-path NT prefix over
    the host-tested `rtl::path::dos_path_name_to_nt_path_name` (`C:\...`→`\??\C:\...`, UNC→`\??\UNC\...`,
    `\\?\X:`→`\??\X:`), allocating the output `UNICODE_STRING.Buffer` (NUL-terminated) from the process
    heap + computing `PartName`. Relative/drive-relative (needs the CWD) → honest FALSE.
11. **`RtlQueryRegistryValues`** (`on_target::rtl_query_registry_values`, real LIVE registry reader) —
    opens the base key (`RTL_REGISTRY_CONTROL`+Path → `\Registry\Machine\System\CurrentControlSet\
    Control\Session Manager`) via our own `NtOpenKey(125)` trap stub, walks the `RTL_QUERY_REGISTRY_
    TABLE`, and for **SUBKEY+QueryRoutine** entries opens the named subkey + **enumerates every value**
    (`NtEnumerateValueKey(77)`, KeyValueFullInformation) → dispatches the caller's `QueryRoutine` with
    the real hive data, and for **named-value** entries queries (`NtQueryValueKey(185)`) → routine /
    default. **REG_EXPAND_SZ expansion** (`%SystemRoot%\system32`→`C:\Windows\system32`) via the live
    PEB environment block + the host-tested `rtl::environment::Environment::{from_block,expand}`. Absent
    keys/values fall to the caller's defaults — real-ntdll behavior, never fabricated. **This is the
    executive's `resolve_key`/`NtEnumerateValueKey`/`NtQueryValueKey` (::ROSSYS.HIV) driven from
    in-process, the real-ntdll model.** After 10+11: smss's `RtlQueryRegistryValues` populates
    `SmpKnownDllPath` → `RtlDosPathNameToNtPathName_U` succeeds → **NtOpenFile(\??\C:\Windows\system32,
    SSN 122)** fires (the KnownDlls dir) — the first proof the conversion worked.
12. **`RtlSetEnvironmentVariable`** (`on_target::rtl_set_environment_variable`, real) — reads the target
    env block (`*Environment` or the PEB process-env), sets/deletes the variable via the host-tested
    `Environment` model, serializes a fresh block on the process heap, and writes the pointer back
    (updating the PEB env slot for the NULL-env case). **Wall was:** the KnownDlls read led into the
    `Session Manager\Environment` subkey enumeration (the hive holds Path/TEMP/TMP/ComSpec/windir) →
    `SmpConfigureEnvironment` (sminit.c:503) calls `RtlSetEnvironmentVariable`, which our 4.0b seam
    returned STATUS_NOT_IMPLEMENTED for → the callback failed → `RtlQueryRegistryValues` failed → fatal.

**How far smss runs now (a BIG jump — 116→225 service-iters):** ring
`…122(NtOpenFile KnownDlls),27,27,96(NtInitializeRegistry),181,181(NtQuerySystemInformation),125,
256,256,256(NtSetValueKey OS/PROC_ARCH),125,185,185(CPU Identifier read),27,256,256,256(PROC_IDENTIFIER/
REVISION/NUMBER_OF_PROCESSORS),125,27,125,185,27,129,12,249,249(NtSetSystemInformation SessionCreate +
win32k ExtendServiceTable),12,27,129,12,27,190`. smss's `SmpInit → SmpLoadDataFromRegistry` now runs
the FULL registry-driven bring-up under OUR ntdll: **KnownDlls path resolution + DOS-devices + the
registry-environment reads + `SmpCreateDynamicEnvironmentVariables`** (writes OS / PROCESSOR_ARCHITECTURE
/ PROCESSOR_IDENTIFIER / PROCESSOR_REVISION / NUMBER_OF_PROCESSORS to the registry, reading the CPU
Identifier/VendorIdentifier from the synth HARDWARE key) — and is now **inside `SmpLoadSubSystemsForMu
Session`** (smsubsys.c:510): `SmpTranslateSystemPartitionInformation` + the SubSystemList `Kmode`/win32k
entry (`NtSetSystemInformation` SessionCreate + ExtendServiceTable = the `249,249`). Gate flag-ON 143/98
(smss doesn't yet spawn csrss → no paint).

**Remaining wall to the csrss-spawn (the 4.C milestone):** smss still stops at `NtRaiseHardError(190)`
past the `249,249` (win32k session/service-table load) — the next divergent body is in `SmpLoadSubSystems
ForMuSession`'s required-subsystem path (`SmpExecuteCommand → SmpLoadSubSystem → SmpExecuteImage →
NtCreateSection(SEC_IMAGE) → NtCreateProcess[Ex]` for csrss) or the `NtSetSystemInformation` win32k-load
return. Continue the oracle-diff grind. **The SSN-50 arm** (`NtCreateProcessEx`) is NOT yet needed (smss
hasn't reached the create-process call under our ntdll) — add it when smss emits SSN 50 there.

**checkpoint 5 committed** (`5d069dd`): gate 174/98, paint 768/768, flag OFF; ONLY `crates/nt-ntdll-dll`
changed; NO rust-micro/src, NO executive change; sel4test byte-identical; `nt-ntdll` host tests 145/145.

**IN PROGRESS 2026-07-16 — checkpoint 6 (env-block off-by-one fix + search-path/env-query bodies → smss REACHES the csrss create-process chain `SmpExecuteImage` under OUR ntdll):**

The ckpt-5 wall was `RtlDosPathNameToNtPathName_U(SmpKnownDllPath)` (fixed). smss then ran deep into
`SmpLoadSubSystemsForMuSession` (win32k `Kmode` NtSetSystemInformation ×2) and stopped at the
required-subsystem `SmpExecuteCommand(csrss) → SmpParseCommandLine`, which resolves csrss's image path
purely in RTL (`RtlQueryEnvironmentVariable_U(Path)` + `RtlDosSearchPath_U`) — both 4.0b seams.
**Diagnosed via a temporary int-0x2d marker (`[qenv:Path=MISS nvars=02]`): `SmpDefaultEnvironment` held
only 2 vars, missing `Path`.** Root cause = an **off-by-one in `on_target::read_env_block`**: it
measured to the double-NUL but EXCLUDED the first terminating NUL, so `Environment::from_block` (which
emits a var only on a NUL) silently DROPPED the last variable of every block → each
`RtlSetEnvironmentVariable` reserialization lost a var → the env never grew past 2-3. (This body/logic
class translated from `references/reactos/sdk/lib/rtl/{env.c,registry.c,path.c}`.)

**The walls made real (all in `crates/nt-ntdll-dll` + one pure host helper/test in `crates/nt-ntdll`,
NO rust-micro/src change, sel4test byte-identical):**
13. **`read_env_block` off-by-one fix** — include the first NUL of the double-NUL so `from_block` emits
    the last variable. Host-regression-test `from_block_keeps_last_var_when_slice_includes_terminating_
    nul` in `nt-ntdll` (146 tests). After the fix the env grows correctly (`[setenv]` 04→05→…→10) and
    `RtlQueryEnvironmentVariable_U(Path)` → **HIT**.
14. **`RtlQueryEnvironmentVariable_U`** (`on_target`, real) — looks up `Name` in the env block
    (`Environment` arg or the PEB process-env), copies the value into `Value->Buffer` (up to
    `Value->MaximumLength`), sets `Value->Length`, returns STATUS_BUFFER_TOO_SMALL / VARIABLE_NOT_FOUND.
    (translated from `env.c:659`.) smss's `SmpParseCommandLine` reads `Path` from `SmpDefaultEnvironment`.
15. **`RtlDosSearchPath_U`** (`on_target`, real) — searches each `;`-separated dir in `Path` for
    `FileName`(+`Extension` if no dot), probing existence via `NtQueryAttributesFile(145)` (the executive
    resolves csrss.exe against the real `\reactos` FS); writes the DOS hit into `Buffer` + `*PartName`.
    smss finds `csrss.exe` on the `Path`.

**How far smss runs now (the parity signal — REACHED the create-process chain):** ring
`…249,249,12,27,145(NtQueryAttributesFile=RtlDosSearchPath csrss probe),37(NtCreateEvent=SmpLoadSubSystem
subsystem event),228(NtWaitForSingleObject),129,12,27,190`. smss's `SmpLoadSubSystemsForMuSession →
SmpExecuteCommand(csrss) → SmpParseCommandLine` now **RESOLVES csrss.exe** (RtlDosSearchPath HIT via
NtQueryAttributesFile) → enters **`SmpLoadSubSystem`** (creates the subsystem NtCreateEvent) → calls
**`SmpExecuteImage`** (smss.c:30) — the csrss create-process chain. Gate flag-ON 145/98.

**Remaining wall = the create-process chain BODIES (the 4.C milestone, next increment):** `SmpExecuteImage`
calls **`RtlCreateProcessParameters`** (smss.c:47) then **`RtlCreateUserProcess`** (smss.c:92) — BOTH
still 4.0b seams. `RtlCreateProcessParameters` is a pure heap/struct-builder (a BODY wall — write it).
`RtlCreateUserProcess` is the body that ISSUES `NtCreateSection(SEC_IMAGE)` + `NtCreateProcess[Ex]` +
`NtCreateThread` — if its LOGIC is the gap it's a BODY wall (write + translate from
`references/reactos/sdk/lib/rtl/process.c`); if the create-process SYSCALL out-param/marshalling breaks,
that's a TRANSPORT wall → flag for Step 6 (the seL4 `Call`/SURT flip; marshalling already host-tested in
`marshal.rs`). **Add the executive SSN-50 (`NtCreateProcessEx`) arm when smss emits SSN 50 there.**

## ★ PIVOT (user, 2026-07-16) — retire the oracle-diff GRIND; go SYSTEMATIC + flip the transport
Two directives: (1) **switch to Step 6 regardless** (flip the syscall transport off x86-trap) — the trap-path grind hit/approached syscall-marshalling friction (out-param write-back via the executive stack-mirror, wide-arg, servicing), which a proper transport eliminates; (2) **focus entirely on PORTING ReactOS ntdll → our Rust ntdll, TEST-DRIVEN**: for each function, port ReactOS's apitests if they exist (`references/reactos/modules/rostests/apitests/ntdll/`) OR write input/output validation tests, THEN port the function body from ReactOS source (`references/reactos/sdk/lib/rtl` for Rtl*, `references/reactos/dll/ntdll` for Ldr*/loader). Retire the reactive oracle-diff grind (Step 4.C paused at ckpt 6 `bb7fd4a`; smss ran deep into SmpInit under our ntdll — 10 real bodies; flag OFF committed green). The systematic port SUBSUMES the grind: instead of discovering walls one boot at a time, port the surface methodically + host-test it, so smss (then all 5 processes) runs on a COMPLETE, tested ntdll.
### ☑ Step 6 — flip the transport → NATIVE seL4 Call (DONE — see "Step 6.A" below). NO kernel change: the crux (TCBSetHostedSyscalls faults every `syscall`) is dissolved by simply NOT setting that per-thread flag for our-ntdll smss (our ntdll owns every syscall, so it never issues a raw Windows `syscall`). smss's syscalls now flow over a real native seL4 `Call(CT_FAULT)`, serviced by the executive's new NT_NATIVE_SYSCALL recv arm, reaching the SAME deep-SmpInit depth (stop_ssn=190) as the trap transport. Out-params kept on the existing stack mirror (MR1=rsp) for a zero-handler-churn cut; value-return layers on later. `marshal.rs`/SURT stay available for a future batched/async surface.
### ☐ Systematic Rtl/Ldr body port (test-driven) — port the ReactOS ntdll surface methodically into `crates/nt-ntdll`, batched by module (string/path/env/time/security/heap/loader), each function: (apitest OR new I/O test) + ported body. On the clean transport (after Step 6). This is the bulk; highly parallelizable (independent functions).

## ★ DECISION (user, 2026-07-16) — NATIVE transport (option A), do it right; spec-break PERMITTED
Chosen: **Step 6.A native seL4 Call transport** (win #2's architectural purity — NO fault-trap emulation), NOT the pragmatic 6.C. **"Don't worry about the spec for now"** — the sel4test byte-identity + the 174/98 boot gate constraint is LIFTED: we may make kernel changes + break the boot/specs while switching the transport and re-implementing, then RECONVERGE the specs. Sequence (user): **(1) switch the transport over → (2) re-implement the ENTIRE ntdll (test-driven port) → (3) get the specs running again → (4) finish the DLL → THEN grind (bring processes up on the complete ntdll).**
### Native transport design (6.A) — investigate the no-kernel-change path FIRST
The crux is TCBSetHostedSyscalls (makes every `syscall` fault). ★ HYPOTHESIS to validate first: for OUR-ntdll processes, simply DON'T set TCBSetHostedSyscalls + grant a service-endpoint cap → the ntdll stub's `seL4_Call` works NATIVELY (our ntdll owns every syscall, so the process never does a raw Windows syscall) → possibly NO kernel change. If a kernel change IS needed, make it (spec-break permitted; extern-rootserver-gate cleanly if feasible). Build: spawn grants SERVICE_EP cap into the process CSpace; ntdll `transport.rs` Sel4Call arm does real seL4_Call (marshal SSN+args via the host-tested `marshal.rs` into the IPC message); executive service loop Recv's the IPC message (decode SSN+args from msg regs, NOT a fault frame), services via ExecNtHandler, Reply with status + out-param VALUES in msg regs; ntdll writes out-params to caller pointers IN-PROCESS (no stack-mirror). Prove smss's syscalls flow over seL4 Call (no fault), out-params clean, smss runs >= as far as on the trap transport. Host tests green; commit recoverable increments; the flag still gates our-ntdll vs real-ntdll (fallback kept).
### Then: full test-driven ntdll port (all Rtl/Ldr bodies) → reconverge specs → finish DLL.

## Step 6.A — NATIVE seL4 Call transport (IN PROGRESS 2026-07-16)

### ★ KERNEL-CHANGE DECISION: NO KERNEL CHANGE NEEDED (hypothesis VALIDATED)
Recon of `rust-micro/src/arch/x86_64/syscall_entry.rs::rust_syscall_dispatch`:
- Lines 598-604: `force_unknown = current_tcb.hosted_syscalls`. The `TCBSetHostedSyscalls` flag
  (label 66) is a **per-thread** opt-in. When it is NOT set, `Syscall::from_i32(rdx)` dispatches the
  syscall NATIVELY — including `SysCall = -1` (the seL4 `Call`). Only when the flag IS set does EVERY
  syscall fault as `UnknownSyscall`.
- The generated `Syscall` enum (`codegen/syscall.xml` → `SysCall = -1`): a native seL4 `Call` puts
  `rdx = -1` (SysCall), `rdi = ep_cap_slot`, `rsi = msginfo`, `r10/r8/r9/r15 = MR0..3`. `handle_syscall`
  routes `SysCall` → `handle_send(blocking, call=true)` → resolves the cap in `rdi`, finds the
  Endpoint, `send_ipc` do_call → the executive's `Recv` on that endpoint wakes with the message.
So: for OUR-ntdll smss, if we (a) do NOT call `TCBSetHostedSyscalls`, and (b) grant a cap to the
service endpoint into smss's CSpace, then our ntdll's `Nt*` stubs issue a **real native seL4 `Call`**
— NOT a Windows-`syscall` UnknownSyscall fault. Our ntdll owns EVERY syscall (each stub is our code),
so smss never issues a raw Windows `syscall` that would need the fault path. **No kernel change.**
The fallback (real-ntdll / pi>=1) keeps `TCBSetHostedSyscalls` + the trap path, byte-identical.

### The service endpoint = the fault EP (reuse, don't add)
The executive's `service_sec_image` loop already `Recv`s on `si_fault` (smss's fault EP), and smss's
CSpace already holds a cap to it at slot `CT_FAULT` (=6) (granted by `spawn_sec_image` via
`CNODE_COPY`, used as the TCB's fault handler). Our ntdll `seL4_Call`s that SAME endpoint at
`CT_FAULT`. The executive's recv loop then receives EITHER a fault message (real-ntdll path / pi>=1:
`mi>>12 ∈ {2,3,6}`) OR our native-syscall message (`mi>>12 == NT_NATIVE_SYSCALL_LABEL`). The badge
still selects the process. No second endpoint, no extra cap-grant plumbing — the existing fault EP +
its CT_FAULT cap IS the service channel.

### The REQUEST / REPLY message layout (`NT_NATIVE_SYSCALL_LABEL = 0x4E54` = "NT")
REQUEST (ntdll → executive), msginfo label = `NT_NATIVE_SYSCALL_LABEL`, length 6:
- MR0 = SSN (the Windows service number)
- MR1 = caller RSP (so the executive reads stack args 5+ AND writes stack out-params via its EXISTING
  stack mirror — a native `Call` does NOT transfer rsp/stack, unlike the UnknownSyscall fault frame)
- MR2 = arg1 (RCX→R10 in the native ABI)
- MR3 = arg2 (RDX)
- MR4 = arg3 (R8)
- MR5 = arg4 (R9)
REPLY (executive → ntdll), length 1:
- MR0 = NTSTATUS
Wire mapping (matches the executive's `recv_full_r12`/`reply_recv` register plumbing): rsi=msginfo,
r10=MR0, r8=MR1, r9=MR2, r15=MR3, IPC-buffer[4]=MR4, [5]=MR5. Reply: r10=MR0=NTSTATUS.

### Out-params: kept on the EXISTING stack/heap/image MIRROR (minimal, provable native cut)
The plan's ideal friction-killer is out-params-as-VALUES written in-process by ntdll. But the
executive has ~100+ SSN handlers that all write out-params through the stack/heap/image MIRROR
(`smss_copyout`/`smss_stack_write`). Rewriting all of them to value-return is the systematic port's
job (next). For THIS transport cut, ntdll passes the SAME pointer args (into smss's mapped memory) in
the message, and the executive services with the SAME handlers writing through the SAME mirror — the
out-params still land in smss's memory, but now over a native `Call` instead of a fault. The mirror
works because MR1 carries RSP. This proves the native transport end-to-end with zero handler churn;
the pure value-return layers on top later, handler-by-handler, during the systematic port.

### The build (flag-gated on our-ntdll; fallback + real-ntdll trap path kept)
1. **Spawn setup** (`img_spawn.rs`): a new `hosted_native: bool` param to `spawn_sec_image` — when
   set (our-ntdll smss), SKIP the `TCBSetHostedSyscalls` invocation (so native `Call` works) and
   ensure CT_FAULT holds a SEND-capable cap (it already does). Flag-OFF / pi>=1: unchanged (byte-id).
2. **ntdll transport** (`nt-ntdll-dll/src/on_target.rs`): the THREE syscall helpers (`syscall4`/
   `syscall6`/`syscall8`) + `nt_allocate_virtual_memory` + the naked trap stubs (`trap_stubs.rs` via
   `exports.rs`) switch from `mov eax,ssn; syscall` to a native `seL4_Call(CT_FAULT)` building the
   REQUEST message, reading MR0 (NTSTATUS) from the reply. A `cfg`/const `NATIVE_TRANSPORT` picks
   native vs trap so the fallback stays.
3. **Executive recv** (`service_sec_image.rs`): the recv loop gains a `mi>>12 == NT_NATIVE_SYSCALL_LABEL`
   arm ALONGSIDE the fault arms — decode SSN=MR0, rsp=MR1, args from MR2..5 + stack, dispatch via the
   SAME `nt_dispatcher`/`ExecNtHandler`, reply MR0 = NTSTATUS. The `(mi>>12)==2` UnknownSyscall arm
   stays for the real-ntdll / pi>=1 fallback.
4. **PROVE**: flag-ON boot log shows smss's syscalls arriving as `NT_NATIVE_SYSCALL_LABEL` messages
   (NOT `[unknown syscall]` faults), serviced + replied, smss ≥ its trap-transport depth
   (deep into SmpInit).

### ✅ DONE — the native transport is LIVE (proven end-to-end, 2026-07-16)
**MILESTONE: smss's syscalls flow over a real native seL4 `Call` — NO fault-trap emulation — and it
runs AT LEAST as deep as on the trap transport (identical SmpInit depth, `stop_ssn=190`).**

**What landed (3 recoverable, host-tested commits on `main`):**
- **ckpt 1** — the kernel-change investigation (NO change needed, validated) + this design.
- **ckpt 2** — the ntdll stub side: `crates/nt-ntdll/src/native_call.rs` (the wire layout, host-tested),
  the 188 naked `Nt*` stubs' native-Call variant (`trap_stubs.rs`, `feature = native_transport`), and
  `nt-ntdll-dll/on_target.rs`'s `syscall4/6/8` + `nt_allocate_virtual_memory` flipped to a
  `native_syscall8` primitive (MR4/5 via the IPC buffer, args via a stack `req` array to stay within
  register pressure). `native_transport` feature (default ON for the DLL emit).
- **ckpt 3** — the executive side + PROOF: `img_spawn.rs` skips `TCBSetHostedSyscalls` for the native
  spawn (gated on `ldrpinit_rva != 0` = our-ntdll smss only → all fallbacks byte-identical); the fault
  EP + its `CT_FAULT` cap double as the service channel (no second endpoint). `service_sec_image.rs`
  gained the `mi>>12 == NT_NATIVE_SYSCALL_LABEL` recv arm that NORMALIZES the native message into the
  fault-frame register slots the `(mi>>12)==2` UnknownSyscall arm reads (`set_recv_mr`), then re-labels
  to 2 so the FULL existing servicing body (dispatch + out-writes + spawn/park/delay post-actions) runs
  UNCHANGED. `NT_NATIVE_SYSCALL_LABEL = 0x4E54` lives in `nt-syscall-abi` (single source of truth).

**The out-param FRICTION-KILLER (this cut):** ntdll passes the SAME pointer args (into smss's mapped
memory) in the message; the executive services with the SAME handlers writing out-params through the
SAME stack/heap/image MIRROR (MR1 carries rsp, so the mirror reads/writes work). The reply is a NORMAL
IPC reply (the native caller has `pending_fault == 0`, so the kernel's normal `deliver_message` fans
`result → MR0 → the caller's r10`, which the native stub reads as NTSTATUS — NOT the register-restoring
fault reply). The pure out-params-as-VALUES (no mirror) layers on later, handler-by-handler, during the
systematic body port — the transport is proven without touching the ~100 handlers.

**PROOF (flag-ON boot log, `/tmp/step6a.log`):**
- `[dbg] nt-ntdll: snap resolved=103 missing=0` — our LdrpInitialize ran + snapped smss's IAT.
- **ZERO `[unknown syscall]` after the loader snap** (grep: 0 occurrences past that line; the 18 before
  are the demo SEC_IMAGE trap-path test + the kernel specs, NOT the live smss). Every one of smss's
  ~130 syscalls arrived as a native seL4 `Call` (raw label 0x4E54, re-labeled to 2 internally).
- `[sec-stop] badge=0 (smss) … iters=246 … stop_ssn=190 ssns: 0:96 0:181 0:181 0:125 0:256 0:256 0:256
  0:125 0:185 0:185 0:27 … 0:129 0:12 0:249 0:249 … 0:145 0:37 0:228 0:129 0:12 0:27 0:190` — the SAME
  deep-SmpInit progression as trap-transport ckpt 6: registry env + CPU keys + KnownDlls/DOS-devices +
  dynamic env + `[sm-loop] spawned tcb` (the SM API loop thread) + the csrss create-process probe
  (145/37/228), stopping at the SAME `NtRaiseHardError(190)` wall.
- `LIVE ReactOS smss+env: faulted 57 page(s) (33 in ntdll) … ntalloc_serviced=3`; the 5 smss live specs
  PASS (`exec_reactos_smss_live_paged/_calls_into_ntdll/ldrinit_runs_deep/creates_heap/reads_image`).

**Spec/boot state (spec-break, as permitted):** flag `SMSS_USE_OUR_NTDLL = true` → gate **141/98**
(smss doesn't yet spawn csrss under the transport-only cut → no desktop paint — the EXPECTED state,
same as trap-transport ckpt 6's 143-145). Flag-OFF (real-ntdll trap) is the untouched fallback: the
executive's native arm is dormant (no native message arrives) and `native_transport = ldrpinit_rva!=0`
is 0, so the real-ntdll / pi>=1 path keeps `TCBSetHostedSyscalls` + the trap path. Host tests:
`nt-ntdll` 150, `nt-syscall-abi` 12. **RECONVERGE later** (user sequence step 3): the 174/98 gate + paint
return once the systematic body port brings smss (then all 5 processes) far enough on the native
transport to spawn csrss again.

**What the systematic body port wires next (user sequence steps 2+4):** with the clean native
transport in place, port the ReactOS `Rtl*`/`Ldr*` bodies test-driven into `crates/nt-ntdll` (apitest OR
I/O test + ported body, batched by module), so smss's `NtRaiseHardError(190)` wall dissolves into the
`SmpExecuteImage → RtlCreateProcessParameters → RtlCreateUserProcess → NtCreateSection(SEC_IMAGE) →
NtCreateProcessEx` csrss spawn. Add the executive **SSN-50** (`NtCreateProcessEx`) arm when smss emits it.
The out-param VALUE-return (retiring the stack mirror per handler) is an optional cleanliness pass on
top of the working transport. The seL4/SURT arg-marshalling in `marshal.rs` remains available for a
future IPC-buffer-batched or async surface.

---

## ★ RETIRE THE REAL-NTDLL FALLBACK (user, 2026-07-16) — our ntdll IS `ntdll.dll`, no fallback
Directive: "just give our dll the same name as the reactos one; don't leave any fallback paths; don't
even copy the reactos ntdll to the image." DONE:
- **make_image.sh**: our Rust ntdll (`.tmp/nt-ntdll.dll`) is staged AS `\reactos\system32\ntdll.dll`,
  OVERWRITING the ReactOS one from the recursive tree copy. No `nt-ntdll.dll` leaf, no flat
  `::NTDLL.DLL`. Real ReactOS ntdll bytes never persist on the image. Build fails hard if our DLL
  isn't built (it is now THE ntdll).
- **Executive**: removed `SMSS_USE_OUR_NTDLL` + `OUR_NTDLL_FS_PATH` + the flag/fallback branch. The
  storage host reads `ntdll.dll` (= ours) into NTDLLBUF as before; the executive DERIVES
  `LdrpInitialize`'s RVA from the loaded ntdll's export table (never hardcodes the retired real-ntdll
  `0x8e70`) and publishes it to `img_spawn::OUR_LDRP_RVA`, so EVERY hosted SEC_IMAGE spawn
  (smss + csrss/winlogon/services/lsass) calls OUR LdrpInitialize + uses the native seL4-Call
  transport uniformly (`effective_ldrp_rva(explicit) = explicit ?: OUR_LDRP_RVA`).

## ☑ SYSTEMATIC PORT — BATCH 1: process-launch Rtl group (test-driven) + THE PORT PATTERN
**Milestone: smss runs FULLY on OUR ntdll and SPAWNS csrss** (SmpExecuteImage →
RtlCreateProcessParameters → RtlCreateUserProcess → NtCreateSection(SEC_IMAGE, 52) →
NtCreateProcessEx(50) → `[ntos-exec] NtCreateProcess: spawned csrss (badge 2)`). csrss then runs on
OUR ntdll too (its own LdrpInitialize snaps its 10 ntdll imports, then NtAllocateVirtualMemory/
NtSetInformationProcess). nt-ntdll host tests **157** (+7). Gate 146/98 (spec-break, permitted).

### ★ THE PORT PATTERN (the repeatable 6 steps — copy this for every later batch)
1. **Identify** the ReactOS source (`file:function`) + its exact prototype/semantics. Rtl bodies live
   in `references/reactos/sdk/lib/rtl/`; loader/Ldr in `references/reactos/dll/ntdll/`.
2. **Tests first.** If a ReactOS apitest exists (`references/reactos/modules/rostests/apitests/ntdll/`
   — e.g. `RtlDosPathNameToNtPathName_U.c`, `RtlGetFullPathName_U.c`), port its cases; else WRITE I/O
   validation tests (known input → expected output, derived from the C semantics). Every ported body
   gets host tests in `crates/nt-ntdll` (`#[cfg(test)]`, run under `cargo test -p nt-ntdll`).
3. **Port the body** to `crates/nt-ntdll/src/rtl/` as PURE logic over `nt-ntdll-layout` structs (real
   edge cases + error codes; reuse existing helpers, don't duplicate). For a state-coupled/syscall body
   (live PEB/heap/create plane), the pure part lives in `nt-ntdll` and the live driver in
   `crates/nt-ntdll-dll/src/on_target.rs` (target-only, over our `Nt*` stubs).
4. **Export** the C-ABI wrapper in `crates/nt-ntdll-dll/src/exports.rs`
   (`#[export_name = "RtlXxx"] pub unsafe extern "system" fn`, real x64 signature; add it to the
   `export_anchor` list so DCE keeps it). Non-`Nt*` new exports bump the DLL export count.
5. **Host-green**: `cargo test -p nt-ntdll` (new tests + all prior). `./scripts/build_ntdll_dll.sh`
   (emits + verifies the PE32+; asserts smss's import set 0-missing).
6. **Boot-verify**: `components/ntos-executive/build.sh` → `rust-micro/scripts/build_kernel.sh
   extern-rootserver` → `run_specs.sh`. Grep the log for the SSN ring / `[dbg] nt-ntdll: snap
   resolved` / `spawned csrss` / `stop_ssn` to confirm smss (then each process) runs further. Since
   our ntdll is now THE ntdll (no fallback), the boot directly exercises the ported bodies.

### Functions ported this batch (ReactOS source cited + tests)
| function | source | tests | where |
|---|---|---|---|
| `RtlCreateProcessParameters` | `sdk/lib/rtl/ppb.c:49` (+ `RtlpCopyParameterString`) | 6 new I/O tests (no apitest): image/cmdline placement, current-dir trailing `\`, EmptyString-vs-NullString, env-after-strings, layout-offset cross-check vs `nt-ntdll-layout`, all-buffers-within-block | pure builder `rtl/process_params.rs`; live wrapper `on_target::rtl_create_process_parameters` (PEB NULL-subst + heap copy); export `exports.rs` |
| `RtlDestroyProcessParameters` | `ppb.c:242` | (covered by build) | export → `process_heap_free` |
| `RtlNormalizeProcessParams` | `ppb.c:280` | `normalize_denormalize_roundtrip` | pure `process_params::normalize`; export rebases Buffers+Environment |
| `RtlDeNormalizeProcessParams` | `ppb.c:255` | (same roundtrip test) | pure `process_params::denormalize`; NEW export (+1 = 255 total) |
| `RtlCreateUserProcess` | `process.c:194` (+ `RtlpMapFile:20`, `RtlpInitEnvironment:68`) | transport-heavy driver, boot-verified (spawns csrss) | `on_target::rtl_create_user_process` — NtOpenFile→NtCreateSection(SEC_IMAGE)→NtCreateProcessEx(50)→NtQuerySection→NtQueryInformationProcess→NtAllocate/NtWriteVirtualMemory→RtlCreateUserThread |

### The executive SSN-50 arm (added — smss emitted SSN 50)
Our `RtlCreateUserProcess` issues the IMPORTED stub **NtCreateProcessEx (SSN 50)** (not `NtCreateProcess` 49).
Added `(NativeService::NtCreateProcess, 50)` to `build_nt_table()` so SSN 50 dispatches to the existing
NtCreateProcess handler (49's args are a prefix of 50's; SectionHandle is arg6 = `sp+0x30` in both).
`crates/nt-syscall-abi` already carried `NtCreateProcessEx=50`.

### NEXT BATCHES (remaining Rtl/loader modules, by spec-priority)
1. **csrss's surface** — csrss now runs on our ntdll (frontier). Port the Rtl bodies csrss/csrsrv
   exercise (it stops early after 2 syscalls). Then winlogon/services/lsass, each climbing on our ntdll.
2. **string / time / security / registry Rtl** — the pure modules (`unicode.c`, `time.c`, SD/ACL/SID,
   `registry.c`) — highly parallelizable (independent functions), fan out per the pattern.
3. **loader (`Ldr*`)** — the `nt-ntdll/src/loader/` engine is host-tested; wire the remaining live
   `LoaderHost` ops as processes need them.
Reconverge the 174/98 gate + paint once winlogon completes its bring-up on our ntdll.

## ☑ SYSTEMATIC PORT — BATCH 2: the recursive dependent-DLL loader + the Win32-stack ntdll surface
**Milestone: csrss's loader cascades the FULL Win32 client stack on OUR ntdll.** The frontier was
csrss stopping at a NULL/low-deref (`ip=0x2440`) = its unresolved `csrsrv.dll!CsrServerInitialization`
IAT slot. smss imports ONLY ntdll, so our `LdrpInitialize` only snapped the ntdll descriptor; csrss
also statically imports **csrsrv.dll**, which was never loaded/snapped. Fixed by wiring the real
`LdrpWalkImportDescriptor` recursion into the on-target loader.

### The recursive loader (`crates/nt-ntdll-dll/src/on_target.rs`)
- **`snap_all_imports`/`snap_module`** — walk EVERY import descriptor. `ntdll` → snap against our
  export table (as before); any OTHER DLL → **load it** (NtOpenFile → NtCreateSection(SEC_IMAGE) →
  NtMapViewOfSection; the executive assigns its pinned/fixed base — csrsrv @ 0x8000_0000, then
  basesrv/winsrv/gdi32/user32/… demand-loaded up the arena), recursively snap ITS imports, then snap
  this descriptor against the loaded DLL's exports. A process-wide **`MODULE_TABLE`** (name→base)
  de-dupes loads so a diamond/repeat dep maps once + recursion terminates.
- **`syscall_map_view`/`native_map_view`** — NtMapViewOfSection (SSN 113, 10 args) over BOTH the trap
  + native seL4-Call transports (the 6 tail args on the stack at the exact slots the executive's map
  handler reads; a3=`*BaseAddress` in MR4 → `set_recv_mr(7)`).
- **`export_rva_by_ordinal`** + by-ordinal thunk snap.
- **Ldr* runtime drivers** (`LdrLoadDll`/`LdrGetDllHandle`/`LdrGetProcedureAddress`/`LdrUnloadDll`) —
  csrsrv's `CsrLoadServerDll` uses these to bring up its ServerDlls; same load+snap+export-walk
  machinery over the MODULE_TABLE.

### Functions ported this batch (23 new exports; ReactOS source cited)
| batch | functions | source |
|---|---|---|
| **ckpt 1** (csrsrv's 12 missing) | `RtlFreeSid`, `RtlGetDaclSecurityDescriptor`, `RtlCharToInteger`, `RtlCreateHeap`, `RtlUnhandledExceptionFilter`, `memmove`(weak)/`strchr`/`strncpy`, `LdrLoadDll`/`LdrGetDllHandle`/`LdrGetProcedureAddress`/`LdrUnloadDll` | `sid.c:186`, `sd.c:199`, `unicode.c:261`, single-heap sentinel, `libsupp.c`; `ldrapi.c` for the Ldr* |
| **ckpt 2** (basesrv's 11 missing) | `RtlCopyLuid`, `RtlInitString`, `RtlDeleteCriticalSection`, `RtlInitializeCriticalSectionAndSpinCount`, `RtlReAllocateHeap`, `RtlExpandEnvironmentStrings_U`, `RtlOpenCurrentUser`, `_snwprintf`/`wcsncpy`/`wcscat`/`_wcsnicmp` | `luid.c:19`, `critical.c`, heap `reallocate` (+ new `process_heap_realloc`), `env.c:264`, `registry.c:702` |

The pure bodies delegate to the host-tested `nt_ntdll::{rtl::*,crt,heap}` logic (tests already green);
the exports are thin C-ABI wrappers (target-only, boot-verified). Live drivers (env-expand /
current-user key) issue real syscalls over our own Nt* stubs.

### How far csrss runs now (the parity signal)
csrss's `LdrpInitialize` snaps csrss+csrsrv (resolved=103/87, **missing=0**), runs
`CsrServerInitialization` → `CsrLoadServerDll` → **`LdrLoadDll` cascades the entire dependency graph
on OUR ntdll**: csrsrv → basesrv → winsrv → gdi32 → user32 → advapi32 → rpcrt4 → kernel32 → ws2_32 →
ws2help → msvcrt — **all DEMAND-LOADed + NtCreateSection + NtMapViewOfSection + import-snapped**.
csrss runs **2374 service-iters** (was 333 at ckpt 1, 2 at the start), ~2000 demand-paged pages deep.

### The next wall = EXECUTIVE-side (NOT an ntdll port gap)
csrss now stops at a demand-fault **`[map-fail] map=8` at `kernel32+0xa9954`** (va 0x80449000),
`exc#=21` — err `0x15` = present+user+**instr-fetch** = a **protection fault executing an NX-mapped
page**. The executive's `page_rights` (`img_spawn.rs:244`) classified a `.text` page of a multi-MB DLL
as RW_NX (a `virtual_size` section-span rounding edge for the big DLLs — kernel32 is 2.7 MB), so the
code page maps non-executable. This is an **executive demand-paging / page-rights issue for the full
Win32 stack**, to be fixed executive-side (the ntdll loader did its job — the whole stack mapped +
snapped 0-missing). Committed: **ckpt 1 `9f171a6`, ckpt 2 `0af3d04`**. Gate 144 pass / 33 fail
(reconverging — the downstream winlogon/paint specs await csrss completing). nt-ntdll host tests 157;
DLL emits 278 exports (was 255 at BATCH 1).

### BATCH 3 candidates (the path to reconvergence)
1. **[executive] the `map=8`/page-rights fix** — the immediate csrss unblock (executive-side, not
   ntdll). Then csrss finishes CsrServerInitialization + the CSR↔SM handshake → winlogon spawns.
2. **winsrv's ~19 remaining ntdll imports** — winsrv (loaded, will snap once reached) needs
   `RtlDuplicateUnicodeString`, the `RtlInitializeResource`/`RtlAcquireResource*` RW-lock family,
   `RtlCopyUnicodeString`, `RtlNtStatusToDosError`, `RtlExitUserThread`, `RtlFindMessage`,
   `RtlAnsiCharToUnicodeChar`, the bitmap family (`RtlAreBitsSet/Clear`, `RtlInitializeBitMap`,
   `RtlSetBits`), `NlsMbCodePageTag` (data) — mostly pure (`nt-ntdll` bodies exist), port per the pattern.
3. **the Win32 client stack's ntdll imports** (gdi32/user32/advapi32/rpcrt4/kernel32/msvcrt) — the big
   surface; port as each DLL's DllMain/init exercises it (frontier-driven). Reconverge 174/98 + paint
   once winlogon completes its bring-up on our ntdll.
