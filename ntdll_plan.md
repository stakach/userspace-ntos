# nt-ntdll — a Rust ntdll.dll (our userspace kernel-ABI half)

**Status:** PLANNING · Steps 1/2a/2b/2c/3 DONE · Step 4.0 + 4.0b DONE · **Step 4.A (FIRST LIVE BOOT on OUR ntdll — smss/pi 0, revertible flag, observable marker proven) DONE 2026-07-16** · Step 4.B next
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
### ☐ Step 4.B — real LoaderHost (map/write_iat/PEB->Ldr/transfer) + snap smss's ntdll-only imports → smss reaches NtProcessStartup under our ntdll. (Trampoline already points at OUR LdrpInitialize RVA — done in 4.A.)
### ☐ Step 4.C — parity: smss progresses as far under our ntdll as under real (spawns csrss); add the SSN-50 arm; keep fallback; gate green (174/98, paint 768/768) throughout.
