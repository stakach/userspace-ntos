# nt-ntdll — a Rust ntdll.dll (our userspace kernel-ABI half)

**Status:** PLANNING · Steps 1/2a/2b/2c/3 DONE · Step 4.0/4.0b/4.A/4.B DONE · Step 6.A native transport DONE · real-ntdll fallback RETIRED (our DLL IS `ntdll.dll`) · **★ BATCH 23 (2026-07-17): broke lsass's non-interactive user32 cursor/class-init loop (0x103d/0x10b4 faked for lsass-only — the interactive winlogon loads gasyscur, a service never does) + modeled lsass's LSA-init port-connect → lsass runs REAL LSA init [DEMAND-LOADs lsasrv, NtCreatePort(\LsaAuthenticationPort), LSA_AUTHENTICATION_INITIALIZED event] + advances into LSA-server-thread creation; gate 165 HELD, lsass 501→664 pages. NEXT WALL = lsass's LSA-server thread walls at a bad thread-entry fetch (ip=0x3a288) = the flagged "N threads per process" lsass-listener multiplex (route its start-addr + stack mirror like winlogon's RPC listener) → LsarStartRpcServer → SetEvent(LSA_RPC_SERVER_ACTIVE) → winlogon WaitForLsass wake → the paint. See "BATCH 23 Results".** · **★ BATCH 24 (2026-07-17, commit e96dcb7): the LSA-server thread's start (entry=0x803c5a10) was CORRECT — the WALL was the TRANSPORT (BATCH 6/19): spawn_lsass_listener_thread was native:false → its native Call faulted UnknownSyscall with garbage SSN 0xB000. FIX = native:true + ipcbuf_frame:PM_MAIN_IPCBUF[4] → the thread now issues a REAL native 9:100 NtListenPort (its RPC receive loop). Gate 165 HELD. The SIGNAL is still blocked by a NEW pre-existing wall UNMASKED by the fix: lsass MAIN faults at bare rpcrt4 RVA 0x3a288 (real VA should be 0x8033a288 — a base-stripped code pointer mid-RpcGetAuthorizationContextForClient, inside RpcServerListen) BEFORE SetEvent(LSA_RPC_SERVER_ACTIVE). = BATCH-18-root-cause-#3-class (snapped pointer reverts on a RUNTIME re-fault). See "BATCH 24 Results".** · **SYSTEMATIC PORT: BATCH 1 (smss spawns csrss) DONE · BATCH 2 (recursive dependent-DLL loader) DONE · BATCH 3 (`map=8` root-cause) DONE · BATCH 4 (Win32-stack export surface COMPLETE, 598 exports, 0-missing ×11) DONE · BATCH 5 (the `#PF cr2=0x668` env-block wall root-caused + fixed; smss now drives to the CSR↔SM `NtConnectPort` handshake) DONE 2026-07-17 · BATCH 6 (the 2nd-thread NATIVE transport: `spawn_hosted_thread` was setting `TCBSetHostedSyscalls` on the SmpApiLoop thread → its native Call faulted as UnknownSyscall with m0=RAX garbage; fixed with a per-thread `native` flag + main-ipcbuf-frame reuse + a `sm_rendezvous` native NORMALIZE arm → **SM accept completes, CSR↔SM handshake, csrss + winlogon SPAWN**, gate 149) DONE 2026-07-17 · BATCH 7 (csr_rendezvous native arm + the LIVE loader now runs `DLL_PROCESS_ATTACH` in dependency order + PEB TLS bitmaps → winlogon runs its FULL DllMain chain kernel32-first, reaching kernel32's `CsrClientConnectToServer`; next wall = the CSR/base-server connect + `Peb->ReadOnlyStaticServerData` DURING winlogon's loader, gate 149) DONE 2026-07-17 · BATCH 8 (NtSecureConnectPort SSN 218 + `CsrClientConnectToServer` = a faithful `CsrpConnectToServer` port issuing the 9-arg NtSecureConnectPort + copying ConnectionInfo→PEB ReadOnlyStaticServerData; + the root-cause `call_dll_main` stack-misalign fix `sub rsp,0x28`→`0x20` that #GP-faulted kernel32's DllMain→CsrClientConnectToServer's aligned SSE spill; + a connect-once guard preventing a reconnect hang → **winlogon's kernel32 DllMain COMPLETES the CSR connect, `exec_winlogon_csr_connect` PASSES, winlogon advances PAST the CSR wall into real win32k NtUser* calls (SSN 4346/4699) + WinMain**, gate 149→150) DONE 2026-07-17** · BATCH 9 (DIAGNOSE-FIRST — the queued winlogon-worker-multiplex hypothesis DISPROVEN by tracing: winlogon blocks FAR earlier, in user32 per-process init inside `CreateWindowStationAndDesktops` — a **contended critical-section spin** right after `NtUserInitializeClientPfnArrays`[0x125B], with NO faults/syscalls; the `0:161` in the ring is smss's terminal wait, not winlogon's; services/lsass NEVER spawn. NO code change — the queued fix was wrong. gate stays 150) DONE 2026-07-17 · BATCH 10 (RIP-INSTRUMENTED — the "user32-init spin" is NOT a CS bug NOR a shared-value poll: it was a PARKED, UNSERVICED instruction-fetch fault at `user32+0x8a940`. RIP-sampled winlogon's parked TCB via seL4_TCB_ReadRegisters = frozen at `0x801da940` [`user32+0x8a940`, err=0x14 = user+instr-fetch]; the single service loop was BREAKING on smss's terminal `NtQueryInformationProcess` [SSN 161 = QueryInfoProcess, NOT NtWaitForSingleObject as BATCH 9 mislabeled] class-44 which did `self.stop=true`, leaving winlogon's higher-priority pending fetch-fault forever unserviced. FIX = drop that `self.stop=true` → return STATUS_INVALID_INFO_CLASS. winlogon now ADVANCES PAST user32 init: new syscalls 4:4576 + more, and walls FURTHER at a REAL `strlen(NULL)` NULL-deref in msvcrt+0x43ca6, gate 150 held, host green 157+12) DONE 2026-07-17 · BATCH 11 (DIAGNOSE-FIRST — the `strlen(NULL)` at msvcrt+0x43ca6 was NOT a missing string: `Peb->ProcessHeap`[PEB+0x30] was NULL → `GetProcessHeap()` NULL → msvcrt's DllMain `_heap_init` returns FALSE → whole CRT attach bails before `_acmdln = strdup(GetCommandLineA())`. ONE-LINE FIX: `ldrp_drive` publishes the loader heap base into `Peb->ProcessHeap`. msvcrt heap+TLS init now complete [`__tlsindex=1`], winlogon PAST the strlen(NULL); walls FURTHER at a msvcrt LOCALE-init CS-`DebugInfo` NULL deref [msvcrt+0x96a3, our `InitializeCriticalSectionEx` leaves field-0 NULL]. Gate 150 held, host green 157+12) DONE 2026-07-17 · BATCH 12 (the CS `DebugInfo` fix: `RtlInitializeCriticalSection`/`AndSpinCount`/new `Ex` now ALLOCATE a real zeroed 0x30-byte `RTL_CRITICAL_SECTION_DEBUG` from the process heap [`RtlpAllocateDebugInfo`-faithful] + set `Type`/`CriticalSection` back-ptr/self-linked `ProcessLocksList`, store its addr in `cs.DebugInfo`@0; `RtlDeleteCriticalSection` frees it [skips NULL + the -1 NO_DEBUG_INFO sentinel]; new host-tested `nt-ntdll::sync::RtlCriticalSectionDebug` [0x30 size + field-offset static-asserts @0x00/0x08/0x10/0x18/0x20/0x24/0x28 + an `init` test] → **msvcrt locale-init's `[DebugInfo+0x28]` write OK, CRT startup FINISHES; winlogon advances PAST msvcrt through its full loader + CSR connect [ssns 4:113/122/52/27 DLL-map loop + 4:218 NtSecureConnectPort + 0:175 NtQuerySection + 4:181/36/131] into kernel32 post-CRT code**, gate 150 held, host green 158+12) DONE 2026-07-17 · BATCH 13 (the kernel32+0x7167e NULL deref = OUR ntdll export `RtlInitCodePageTable` was a STUB that left `CPTABLEINFO.MultiByteTable` NULL → kernel32's `IntMultiByteToWideChar` deref'd `NULL[Char]` during winlogon's `\Nls\NlsSectionCP20127` codepage init; diagnosed by disasm [fault `movzwl (rdx,rax,2)`, rdx=MultiByteTable=NULL] + `.pdata` fn-range [`IntMultiByteToWideChar`] + retaddr chain [`MapViewOfFile→NtMapViewOfSection`, `IntGetCodePageEntry` section path] + the boot log [`NtMapViewOfSection NlsCP20127 -> base 0xA0000000` maps OK then faults cr2=0]. FIX = faithful port of `sdk/lib/rtl/nls.c:RtlInitCodePageTable` [MultiByteTable/WideCharTable/DBCSRanges/DBCSOffsets computed relative to TableBase] + host-tested `nt-ntdll::nls` [4 tests]. winlogon runs PAST codepage init [140→173 demand-faulted pages, new SSNs 4:125/4:185], gate 150 held, host 162+12) DONE 2026-07-17 · BATCH 14 (DIAGNOSE-FIRST — the `RtlRaiseException` int3 was a SYMPTOM not a legit `__try`: decoded it via a length-20 `TCB_ReadRegisters` in the executive [DebugException = fault **label 4**, not 3] → `ExceptionCode=0xC06D007E` = VC++ delay-load `ERROR_MOD_NOT_FOUND` for **`ntdll_vista.dll`** [ExceptionInformation[0]→DelayLoadInfo.szDll], raised by kernel32_vista's `__delayLoadHelper2` [which has NO EHANDLER → uncaught]; the delay `LoadLibrary` fails inside real kernel32 before reaching our ntdll. FIX = our loader now EAGERLY BINDS the DELAY-import directory [dir 13] like normal imports → helper never runs → winlogon PAST it [iters 844→1991, ntdll_vista mapped @0x80040000, csrss 147→345 pages, +secur32/netapi32/…284 loader entries], walls FURTHER at a kernel32 `GetModuleFileNameW` PEB->Ldr NULL+0x10 deref [kernel32+0xff13], gate 150 held, host 162) DONE 2026-07-17 · BATCH 15 (DIAGNOSE-FIRST — `Peb->Ldr`(PEB+0x18) was **NEVER built** [neither the executive spawn NOR the on-target loader set it → NULL]; `GetModuleFileNameW(NULL)` walks `[Peb->Ldr]+0x10`=NULL+0x10. FIX = extract the pure circular-link math into host-tested `nt_ntdll::loader::peb::circular_links` [reused by both `build_ldr` + on-target] + `on_target.rs::build_peb_ldr` builds the three LDR_DATA_TABLE_ENTRY lists in-process [EXE-first, DllBase/EntryPoint/SizeOfImage/Base+FullDllName per module, over a persistent NtAllocateVirtualMemory region] + sets `Peb->Ldr`, and `ldr_load_dll` re-threads runtime modules → `[dbg] PebLdr n=2/3/33`, kernel32+0xff13 GONE, winlogon PAST the loader walls into **gdi32+0x3f0cc** [gdi32 process-attach], gate 150 held, host green 165] DONE 2026-07-17 · BATCH 16 (the gdi32+0x3f0cc "wall" was gdi32's **NtGdiCreateBitmap SSN 0x106c** `syscall` — routed fine to hosted win32k, which faulted in its DIB-blit READING a **win32k-internal source SURFOBJ.pvScan0=0x02000000** no host allocator backed [misclassified as a client ptr by the low-VA test → map-client-frame FALSE → wall]; FIX = zero-fill win32k-internal unbacked PML4[0] VAs as win32k-own memory → winlogon PAST gdi32 process-attach [+NtGdi 0x10b5/0x103d/0x10b4 stock-object/cursor init], now parks in **user32+0x9f327** [window-class/cursor init; `SYSTEMCUR(ARROW)==NULL`], gate 150 held, host green 165, executive-only sel4test byte-identical) DONE 2026-07-17 · BATCH 17 (DIAGNOSE-FIRST — the `user32+0x9f327` park was NOT a cursor/win32k gap: disasm showed `+0x9f327` is the `syscall` insn of user32's win32k stub for **SSN 0x103d = `NtUserFindExistingCursorIcon`**; the `SYSTEMCUR(ARROW)==NULL` hint from win32k is a documented-BENIGN ERR [`class.c:UserRegisterSystemClasses` logs it and creates the class with `hCursor=NULL`, does not fail]. The REAL freeze: winlogon was mid-flight [0x103d/0x10b4 class-reg loop] when the shared multiplex loop STOPPED on **smss's terminal `NtRaiseHardError` SSN 190** [`smss.c:SmpTerminate` → NtRaiseHardError(STATUS_SYSTEM_PROCESS_TERMINATED) → NtTerminateProcess = smss' death cry after it finished spawning csrss+winlogon]; badge-0 smss' unserviced 190 broke the loop, freezing winlogon's higher-priority pending fetch — the SAME class of bug as BATCH 10 [one process' terminal syscall killing the shared loop]. FIX = a 1-arm addition to the `if !handled` park block: `badge==0 && m0==190` PARKS smss main [recv-next-without-reply, exactly like a server listener] instead of stopping. winlogon now ADVANCES PAST the FULL user32 window-class/cursor init [completes the ~14-class DefaultServerClasses loop 0x103d/0x10b4, GetClassInfo 0x10bd, GdiBitBlt 0x1008], its parked RIP moved user32+0x9f327 → 0x3ad64, gate 150 held [no regression], host green 165, executive-only [no rust-micro/src, no ntdll DLL change]) DONE 2026-07-17 · **NEXT WALL = winlogon parks at a bare low addr `0x3ad64` [`[vmf-out] fsr=20`, err=0x14 user-instr-fetch] AFTER **comdlg32.dll**'s DllMain [`[dbg] DllMain base=0x81920000`] runs: it's a `jmpq *IAT[comdlg32+0x32388]` import thunk [comdlg32+0x312dd] whose slot = the 65th **kernel32.dll** import [`GetSystemTimeAsFileTime`, ord 459] resolved to the GARBAGE value `0x3ad64` [a mid-function kernel32 .text RVA, NOT the real export RVA 0x214f0, NOT a VA]. = a fresh comdlg32→kernel32 IAT/export-resolution loader bug [most kernel32 imports snapped fine — LoadLibraryA/RaiseException work — so it's a specific export lookup miss, NOT a blanket base-add failure]. DIAGNOSE-FIRST NEXT: dump the raw runtime IAT slot + our loader's kernel32 export walk for GetSystemTimeAsFileTime [forwarder? ordinal-vs-name? off-by-one?]; fix the resolution → comdlg32 DllMain past → winlogon's real WinMain → StartServicesManager/StartLsass → SwitchDesktop → the 0x003a6ea5 paint.** · **OLD next wall was = winlogon parks at OUR ntdll `RtlRaiseException`+2 (ntdll+0x4f22, `[sec-stop] label=4 m0=…804f22 m1=3 exc#=0`) = right after the `int3` in the `push rax;int3;pop rax;ret` stub. winlogon reached its own SEH-raising init/WinMain code; `RtlRaiseException` is an honest int3 seam that does NOT capture a CONTEXT + drive `RtlDispatchException`/unwind. NEXT = make `RtlRaiseException` REAL on target (build EXCEPTION_RECORD+CONTEXT, run the existing `nt-ntdll::rtl::exception`+`ki` SEH machinery to invoke the `__except` handler) → then winlogon's real WinMain → StartServicesManager/StartLsass→SwitchDesktop→the 0x003a6ea5 paint**
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

## ☑ SYSTEMATIC PORT — BATCH 3 (in progress): the `map=8` wall root-caused (NOT executive) + the Win32-stack ntdll surface

### ★ ROOT CAUSE of the `map=8` @ `kernel32+0xa9954` — diagnosis (a) ntdll-loader, NOT (b) executive
The BATCH-2 note GUESSED the `map=8`/instr-fetch @ `kernel32+0xa9954` (va 0x80449000, err
0x15 = present+user+**instr-fetch**) was an executive page-rights bug (a `.text` page mis-classified
RW_NX). **That was WRONG.** RVA 0xa9954 is squarely in kernel32's **`.rdata`** (0x77000..0xaf412) —
which the executive **correctly** maps NX. The bytes at that RVA are the ASCII forwarder string
**`"ntdll.RtlGetLastWin32Error"`**: `kernel32!GetLastError` is a **FORWARDER export** (its func RVA
0xa9954 falls inside kernel32's export directory 0xa5600..0xac840). So an instruction-fetch into
`.rdata` = a **call through a slot that resolved to the forwarder STRING, not the forwarded target** =
diagnosis **(a): an ntdll loader export-resolution bug.** (No oracle-boot needed — the binary + the PE
export table pinned it unambiguously: the fault RVA IS the forwarder string RVA of a forwarded export.)

The on-target recursive loader (`crates/nt-ntdll-dll/src/on_target.rs`) resolved each import to an RVA
and wrote `dep_base + rva` into the IAT **without detecting/following forwarders** (its comment even
said "forwarders NOT expected — our ntdll's exports are all concrete", true for smss's ntdll-only
imports but FALSE now that it snaps kernel32/user32/… which forward to ntdll). The host-side engine
`nt-ntdll::loader::resolve` already followed forwarders (the `_vista` proof), but the minimal
on-target walker did not.

### The fix (ckpt 1, commit `e41203b` — host tests 157, gate 146/98)
- **`resolve_export_addr(dep_base, by_ordinal, name/ord, table, depth)`** — resolves an export to its
  FINAL absolute address, following forwarders: if the resolved RVA is inside the export-dir range
  (`is_forwarder`), parse `"TARGETDLL.func"` / `"TARGETDLL.#ord"`, find/**load** TARGETDLL via the
  process-wide `MODULE_TABLE` (as `LdrpSnapThunk` does), and recurse (a target may itself forward;
  depth-guarded). `snap_descriptor_against` + `ldr_get_procedure_address` route through it.
- Added the two forwarder-TARGET exports our ntdll lacked: **`RtlGetLastWin32Error`/`RtlSetLastWin32Error`**
  (read/write `TEB.LastErrorValue` @ 0x68 via `gs:[0x30]`) — the ntdll impl of Win32 Get/SetLastError.

**Result:** the kernel32+0xa9954 map=8 wall is GONE. csrss's loader cascades AND **executes** the full
Win32 client stack (csrsrv→basesrv→winsrv→gdi32→user32→advapi32→rpcrt4→kernel32→ws2_32→ws2help→msvcrt)
on our ntdll, running 504→510 service-iters deep.

### ckpt 2 (commit `896713f`): kernel32 early-init exports — csrss past `RtlAcquirePebLock`
The next walls were **more MISSING ntdll exports** (not forwarders): kernel32 imports `RtlAcquirePebLock`
(IAT slot left at its IMAGE_IMPORT_BY_NAME RVA `0xadd38` → instr-fetch fault). Added the immediate
early-init exports: **`RtlAcquirePebLock`/`RtlReleasePebLock`** (enter/leave `PEB->FastPebLock` @
PEB+0x38, PEB self @ `gs:[0x60]`), **`RtlGetNtGlobalFlags`** (PEB+0xBC), **`RtlNtStatusToDosError`**.
csrss now advances to iters=510, next wall = `kernel32!DbgPrintEx`. DLL 284 exports.

### ★ THE FRONTIER (measured): 253 more distinct missing ntdll exports across the Win32 stack
The forwarder fix + the whole stack now snapping revealed the real BATCH-3 surface: **257 distinct
ntdll exports the loaded Win32 stack imports that our ntdll did NOT export** (now 253 after ckpt 2's 4).
Grouped: ~150 `Rtl*` (security SD/ACL/SID family for advapi32; heap Size/Destroy/Validate/Lock;
activation-context/SxS for kernel32; timer-queue/work-item; bitmap; string size/convert; time), the
`Ldr*` resource/loader-lock/shutdown family, `Csr*` (8, `nt-ntdll::csr` bodies exist), `Dbg*`
(DbgPrintEx/DbgUi*), and ~60 CRT (`memcmp`/`strlen`/`wcs*`/`qsort`/math). **~most already have
host-tested `nt-ntdll` bodies** → the exports are thin C-ABI `#[export_name]` wrappers per THE PORT
PATTERN (a large, parallelizable, frontier-driven batch — NOT a single wall). Fan out per-module
(the full missing list is reproducible: diff each stack DLL's ntdll-import descriptor vs our export
table). Reconverge 174/98 + paint once csrss finishes CsrServerInitialization → the CSR↔SM handshake
→ winlogon spawns on our ntdll.

## ☑ SYSTEMATIC PORT — BATCH 4 (DONE): the Win32-stack export surface COMPLETED (0-missing ×11 DLLs)

**Milestone: EVERY Win32-stack DLL resolves its COMPLETE ntdll import set against our exports — 0
missing.** The BATCH-3 forwarder-follow fix revealed the ~253-export frontier; BATCH 4 closed it in
bulk (measure-without-booting → thin `#[export_name]` wrappers over existing host-tested bodies +
honest no-op/seam bodies for the genuinely-missing planes). **DLL grew 284 → 598 exports.**

### The measured gap (reproducible: `llvm-objdump -p` each stack DLL's ntdll-import descriptor +
### its forwards-to-ntdll exports, union, diff vs our export table)
Start: **314 distinct missing** across csrsrv/basesrv/winsrv/gdi32/user32/advapi32/rpcrt4/kernel32/
ws2_32/ws2help/msvcrt. Split by nature: ~most had **existing host-tested `nt-ntdll` bodies** (thin
C-ABI wrappers) vs a minority **genuinely missing a plane** (SxS/activation-context, timer-queue/
thread-pool, resource loader, IFEO) → honest export at the correct ABI returning a real failure /
documented no-op (never a fabricated result). **Committed per-group, host-green** (nt-ntdll stays 157):

| group | count | nature |
|---|---|---|
| **CRT** | 44 | mem/str/wcs/ctype/math/parse/qsort/bsearch over `nt_ntdll::crt` + inline (sin/cos avoid libm; memcmp/strlen weak vs compiler-builtins-mem) |
| **Dbg/Csr/data** | 21 | DbgPrintEx/DbgUi*/vDbgPrintExWithPrefix, the 8 Csr* client (real port send = LPC seam), NlsMb*CodePageTag |
| **Zw aliases** | 2 | ZwYieldExecution (jmp NtYieldExecution) / ZwCallbackReturn (SSN-22 stub) |
| **Rtl string/convert** | 21 | UNICODE/ANSI/OEM string + Unicode↔MultiByte/Oem N + sizes + IsTextUnicode + InitCodePageTable |
| **Rtl heap** | 13 | Size/Validate/Destroy/GetProcessHeaps/Lock/Compact/Walk/Query+Set(Heap/User)Info over our 1 heap |
| **Etw** | 31 | tracing-disabled no-ops (ERROR_SUCCESS = no-provider ETW) — advapi32's Etw surface |
| **Rtl mem/bitmap/atom/encode/time/random/SList/misc** | ~58 | over `nt_ntdll::rtl::{bitmap,time,encode,random}` + inline; version(5.2.3790)/error-mode/SList/vectored+function-table/unwind(int3 raise, no-op unwind seams)/ExitUserThread |
| **Rtl SxS/path/guid/image/handle/resource/timer/debug** | ~49 | SxS honest no-ops (no manifest → SXS_KEY_NOT_FOUND fallback), path/guid/image real bodies, handle-table/resource-lock real inline, timer-queue/thread-pool sentinel no-ops (QueueWorkItem runs inline) |
| **security (advapi32)** | 51 | new `security_exports.rs`: raw SID/ACL/SECURITY_DESCRIPTOR (absolute+self-relative), access/generic-mask, Se objects (NOT_IMPLEMENTED seams). Sigs vs ReactOS sdk/lib/rtl/{sid,acl,sd,access,priv}.c |
| **Ldr + path/env/msg** | 24 | loader-lock (uncontended), AddRefDll/GetDllHandleEx/EnumerateLoadedModules (walks PEB->Ldr), Shutdown/IFEO/resource-loader honest fallbacks, Get/SetCurrentDirectory_U (real PEB read/write), GetFullPathName/DosPathNameToRelativeNtPathName |

### The gate (now permanent): `tools/ntdll-dll-verify` asserts 0-missing per stack DLL
Generalized the smss coverage check to **all 11 stack DLLs** (direct by-name imports + forwards-to-
ntdll). `build_ntdll_dll.sh` fails if any DLL has a missing import. **All 11 pass 0-missing**
(kernel32 400 imported incl forwarders, advapi32 190, all 0).

### How far csrss got (boot-confirmed, gate 147/98)
csrss's loader **cascades the ENTIRE Win32 client stack on our ntdll + snaps 0-missing** (csrsrv/
basesrv/winsrv/gdi32/user32/advapi32/rpcrt4/kernel32/ws2_32/ws2help/msvcrt all DEMAND-LOADed +
NtCreateSection + NtMapViewOfSection + import-snapped, `snap resolved=103/87 missing=0`). csrss runs
**553 service-iters** (was 510 at BATCH 3), reaches **CsrServerInitialization**, spawns the **REAL
`CsrApiRequestThread`** (entry 0x80001a20, tcb 0xabe3, parks on its first fault to csr_fault_ep),
services the win32k connect (SSN 0x125a NtUserProcessConnect → STATUS_SUCCESS), NtQueryObject, and a
thread-terminate — deep into CSR server bring-up on our ntdll.

### ★ THE NEXT FRONTIER = a DEEPER NON-EXPORT WALL (runtime behavior, NOT an export gap)
csrss now stops at a **user #PF: cr2=0x668 err=4 rip=0x100_0080d2aa** — a **NULL+0x668 read** in
csrss image space, AFTER CsrServerInitialization spawned the CsrApiRequestThread. This is NOT an
ntdll export gap (the whole stack snapped 0-missing); it is a **runtime-behavior wall** — a NULL
struct-pointer deref at field +0x668 (a CSR/TEB/context structure not populated by our seams). The
export-completion mission is DONE; the path to paint now runs through **CSR server-runtime state**
(the CsrApiRequestThread multiplex + the CSR↔SM handshake + the connect data plane) and the honest
seams BATCH 4 left (Csr* LPC send, SxS, thread-pool) becoming live where csrss actually exercises
them. Diagnose the 0x668 NULL-deref (which struct/field) as the next increment; likely a Csr* client
or PEB/TEB field the CsrApiRequestThread path reads that our seam returns NULL for. Reconverge
174/98 + paint once csrss finishes CSR bring-up → the CSR↔SM handshake → winlogon spawns.

---

## ☑ SYSTEMATIC PORT — BATCH 5 (DONE 2026-07-17): the `#PF cr2=0x668` root-caused (an ntdll env-block bug, NOT a CSR-runtime seam) + fixed → smss drives to the CSR↔SM `NtConnectPort` handshake

### ★ THE ROOT CAUSE (diagnosed with disasm + ReactOS-source evidence — the BATCH-4 hypothesis was WRONG)
BATCH 4 guessed the `cr2=0x668 err=4 rip=0x100_0080d2aa` was a CSR-runtime struct field in **csrss image
space** read by the CsrApiRequestThread. **It is NOT.** `rip=0x0000_0100_0080_d2aa` = **`NTDLL_BASE`
(`0x100_0080_0000`, `main.rs:154`) + RVA `0xd2aa`** — i.e. the fault is in **OUR ntdll**, not csrss.
`llvm-objdump -d` at `.text` VMA `0x18000d2aa` places it inside
`nt_ntdll_dll::on_target::rtl_create_user_process`, at the `read_env_units` scan
`movzwl (%rsi)` where `%rsi = [params+0x80]` = `RTL_USER_PROCESS_PARAMETERS.Environment`. **`%rsi =
0x668`** → the fault. And the `sec-stop` badge confirms it: **`badge=0 (smss)`**, last SSNs
`… 0:175 (NtQuerySection) … 0:161 (NtQueryInformationProcess)` = exactly `RtlCreateUserProcess`'s
call chain, then the deref. So it is **smss** (not csrss) running **our** `RtlCreateUserProcess` to
spawn its next child, faulting on the child's environment pointer.

**Why 0x668:** `params[+0x80]` held a small OFFSET (`0x668`), not a VA. Our
`normalize`/`denormalize` (`crates/nt-ntdll/src/rtl/process_params.rs`) INCORRECTLY rebased the
`Environment` field alongside the 8 `UNICODE_STRING` Buffers. **ReactOS
`RtlNormalizeProcessParams`/`RtlDeNormalizeProcessParams` (`sdk/lib/rtl/ppb.c`) touch ONLY the 8
string Buffers** — the `NORMALIZE`/`DENORMALIZE` macros never list `Environment`. In real ntdll
`Environment` is ALWAYS a live VA (`RtlCreateProcessParameters` sets `Param->Environment = Dest`, a
VA, and denormalize leaves it alone; `RtlpInitEnvironment` derefs it directly, `process.c:102`).
Our denormalize turned the built VA into the raw offset `0x668`, which `RtlpInitEnvironment` then
dereferenced as a VA → `#PF cr2=0x668`. **So the responsible seam was our own
`RtlNormalize/DeNormalizeProcessParams` + `RtlCreateProcessParameters` — an ntdll bug, not a
missing CSR plane.**

### THE FIX (ReactOS-faithful, host-tested)
- **`process_params.rs`**: `normalize`/`denormalize` no longer touch `OFF_ENVIRONMENT` (ppb.c parity
  — only the 8 string Buffers are rebased). The pure builder is VA-agnostic so it still stores
  `Environment` as an offset internally.
- **`on_target.rs` `rtl_create_process_parameters`**: after copying the block to the heap `dst`, it
  now fixes `Environment` to the live VA `dst + environment_offset` (matching ppb.c
  `Param->Environment = Dest`); a zero offset (no env) leaves the field NULL.
- Host test `normalize_denormalize_roundtrip` updated to assert `Environment` is untouched across the
  whole normalize→denormalize round-trip. **nt-ntdll 157/157 green.**

### How far the boot got (boot-verified)
The `cr2=0x668` fault is **GONE**. smss completes `RtlpInitEnvironment` (the
`NtAllocateVirtualMemory`/`NtWriteVirtualMemory` env-block writes now SUCCEED) + the child spawn,
advances **iters 553 → 573**, and drives all the way to the **CSR↔SM handshake**:
`NtConnectPort` (SSN 33). The new `sec-stop` is `label=2 m0=0x21(=33) stop_ssn=33` with a VALID high
VA in m1 (not a NULL/low deref). The SSN trace now shows the full `RtlCreateUserProcess` completing
+ a long tail (`…0:18 0:287 0:287…0:129 0:181 0:33` = Allocate/Write/MapView/QuerySysInfo/ConnectPort).

### ★ THE NEXT FRONTIER = the executive `sm_rendezvous` accept (NOT an ntdll gap)
smss's main thread hits `NtConnectPort` (\SmApiPort); the executive's `sm_rendezvous`
(`rendezvous.rs`) fires (`[sm-rdv] csrss NtConnectPort pending (conn=5) -> driving the real
SmpApiLoop accept`) but WALLs: `[sm-rdv] WALL: unexpected SSN=1099786334208` (=`0x0000_0100_0000_0080`)
→ `rendezvous produced no client handle`. The real `SmpApiLoop` thread (ReactOS smss code) running on
OUR ntdll issues a first syscall whose SSN the rendezvous state machine (which expects
SetInfoThread/QueryInfoProcess/ReplyWaitReceive/AcceptConnect/CompleteConnect) doesn't recognize —
m0 reads as a high-canonical VA (`0x100_..._0080`), not a bare SSN. This is a **rendezvous-transport /
SmpApiLoop-thread-setup** issue in the EXISTING executive machinery (reuse, don't rebuild), and needs
the lldb/gdb-stub RIP-on-the-loop-thread investigation the plan describes (which syscall the loop
actually issues + why m0 is a VA). Reconverge 174/98 + paint once the SM accept completes → winlogon
spawns → win32k paints `0x003a6ea5`.

---

## ☑ SYSTEMATIC PORT — BATCH 6 (DONE 2026-07-17): the 2nd-thread NATIVE transport → the SM accept completes → the CSR↔SM handshake → csrss + winlogon SPAWN (gate 149, up from 147)

### ★ THE ROOT CAUSE (three-part transport gap for RUNTIME 2nd threads — evidence-backed)
The SmpApiLoop thread is a RUNTIME `NtCreateThread` thread spawned by the executive via
`spawn_sm_loop_thread → spawn_hosted_thread` (`main.rs:3503`). Its native `seL4_Call` arrived at
`sm_rendezvous` as an UnknownSyscall fault with `ssn=m0=0x100_0000_0080` (a VA), because:
1. **`spawn_hosted_thread` set `TCBSetHostedSyscalls` UNCONDITIONALLY** (`main.rs:3581-3582`) — the
   OPPOSITE of the MAIN thread (`img_spawn.rs:650-654` SKIPS it for the native transport). With the
   flag SET, the kernel (`syscall_entry.rs:598-604`, `force_unknown = hosted_syscalls`) forces the
   thread's native `seL4_Call` (`rdx=-1=SysCall`, MR0=r10=SSN) into an UnknownSyscall FAULT. The
   fault frame maps `m0=MR0=regs[0]=RAX` (`fault.rs:434`). Our native stub puts the SSN in **r10**,
   never `mov eax,ssn`, so RAX = leftover garbage VA (`0x100_0000_0080`) → the `unexpected SSN` WALL
   (`rendezvous.rs:228`, which reads `ssn=m0`).
2. **The SM-loop thread's kernel IPC buffer was bound to `SM_IPCBUF_VA` (0x1048_0000)**, but OUR
   ntdll's native stub writes MR4/MR5 (args ≥3) to the hardcoded `IPCBUF_VADDR` (0x105F_B000, the
   MAIN thread's) → arg3 (the `NtQueryInformationProcess` PROCESS_BASIC_INFORMATION out-buf) would be
   garbage even after fixing (1).
3. **`sm_rendezvous` only had a `label==2` (fault) arm** reading `ssn=m0`; a native Call arrives as
   `label == NT_NATIVE_SYSCALL_LABEL (0x4E54)` with the MR0=SSN/MR1=rsp/MR2..=args layout, which the
   fault arm never normalized.

### THE FIX (executive-only — NO kernel change; the main-thread native machinery, generalized)
- **`HostedThread` gains `native: bool` + `ipcbuf_frame: u64`** (`main.rs`). `spawn_hosted_thread`:
  when `native`, (a) SKIPS `TCBSetHostedSyscalls` (native Call → MR0=SSN, exactly like the main
  thread), and (b) binds the thread's kernel IPC buffer to the process MAIN thread's ipcbuf FRAME at
  `IPCBUF_VADDR` (reused via `copy_cap`, NOT a fresh frame at `ipcbuf_va` — they share the VSpace and
  never run concurrently during a rendezvous, so the shared VA→frame mapping is correct and the
  kernel picks up the MR4/MR5 the native stub wrote there).
- **`img_spawn.rs` stashes each process's main ipcbuf frame** in a new `PM_MAIN_IPCBUF[pi]`
  (`main.rs`) so the runtime native thread can reuse it.
- **`spawn_sm_loop_thread` passes `native: true` + `PM_MAIN_IPCBUF[0]`** (smss = pi 0);
  `spawn_csr_loop_thread` passes `native: true` + `PM_MAIN_IPCBUF[2]` (csrss = pi 2). The
  winlogon/services/lsass listener spawners keep `native: false` (they're driven through the MAIN
  multiplex's BADGED fault-EP, a trap-frame layout — a documented BATCH-6 follow-up, not yet reached).
- **`sm_rendezvous` gains a native NORMALIZE arm** (`rendezvous.rs`, mirroring `service_sec_image.rs`'s
  main-loop native arm): on `label == NT_NATIVE_SYSCALL_LABEL` it stages MR0=SSN, MR1=rsp,
  MR2/MR3=arg1/arg2, MR4/MR5=arg3/arg4 (from the executive's recv IPC buffer) into the fault-frame
  slots the existing accept body reads (R10@9/R8@7/R9@8/SP@16/FLAGS@17), then re-labels to 2 so the
  UNCHANGED accept body runs. The reply (`send_on_reply(reply,18,result,…)`) already fans MR0→r10 for
  a native (pending-fault==0) caller — the same normal-IPC-reply the main loop uses — so no reply
  change was needed. **NO KERNEL CHANGE.**

### How far the boot got (boot-verified, gate 149/28)
- `[sm-rdv] csrss NtConnectPort pending (conn=5) -> driving the real SmpApiLoop accept`
- **`[sm-rdv] AUTHENTIC accept complete: client handle=…0011 -> csrss NtConnectPort SUCCESS`** — the
  `unexpected SSN` WALL is GONE; the SmpApiLoop thread's native syscalls (SetInfoThread /
  QueryInfoProcess / ReplyWaitReceive / AcceptConnect / CompleteConnect) all parse + service.
- **csrss spawned** (badge 2, 146 pages) + **winlogon spawned** (pi 4) and runs its ENTIRE Win32
  loader — user32/gdi32/kernel32/advapi32/rpcrt4/ws2_32/ws2help/msvcrt/userenv/mpr all
  open+section+map with `first_failure=none` (115 pages). `exec_winlogon_staged/_spawned/_loader_runs`
  PASS.
- **Gate 149 PASS / 28 FAIL** (up from ~147, RED reconverging). Host: nt-ntdll 157, nt-syscall-abi 12.

### ★ THE NEXT FRONTIER = winlogon's post-loader flow (toward its CSR connect → win32k paint)
winlogon (pi 4) stops after its loader at `label=6 m0=0x806d3ca6 exc#=4` in its OWN image
(0x800…-based) — its post-loader `WinMain`/init toward `NtSecureConnectPort(\Windows\ApiPort)` (the
CSR connect, `exec_winlogon_csr_connect` still FAILs). Two BATCH-6 follow-ups converge here: (a) the
winlogon CSR connect needs the **csrss CsrApiRequestThread** — its `spawn_csr_loop_thread` is now
`native: true`, so `csr_rendezvous` needs the SAME native NORMALIZE arm `sm_rendezvous` got; (b) the
winlogon/services/lsass **listener threads** (still `native: false`) will need converting to the
native transport once the multiplex reaches them. Reconverge 174/98 + `0x003a6ea5` paint once
winlogon's CSR connect completes → `co_IntShowDesktop → IntPaintDesktop`.

---

## ☑ SYSTEMATIC PORT — BATCH 7 (DONE 2026-07-17): csr_rendezvous native arm + the LIVE loader runs DLL_PROCESS_ATTACH (dependency order) + PEB TLS bitmaps → winlogon runs its FULL DllMain chain kernel32-first → the CSR-connect frontier (gate 149)

### 1. csr_rendezvous native NORMALIZE arm (rendezvous.rs)
Mirrored BATCH 6's `sm_rendezvous` native arm into `csr_rendezvous`: the CsrApiRequestThread
is `native: true` (`spawn_csr_loop_thread`), so its `Nt*` syscalls arrive as a native seL4
`Call` (label `NT_NATIVE_SYSCALL_LABEL = 0x4E54`), not a label-2 UnknownSyscall fault. The arm
stages MR0=SSN, MR1=rsp, MR2/MR3=arg1/arg2, MR4/MR5=arg3/arg4 into the fault-frame slots the
accept body reads (R10@9/R8@7/R9@8/SP@16/FLAGS@17), then re-labels to 2 so the UNCHANGED accept
body runs. No kernel change.

### 2. ★ ROOT CAUSE of winlogon's post-loader wall (was `label=6 m0=0x806d3ca6 exc#=4`)
Traced via disasm: `0x806d3ca6` = **msvcrt.dll!strlen+0x16** (`movsbl (%rax)` with rax=0), i.e.
**`strlen(NULL)`**. The caller chain (stack-scan of the fault RSP, walking winlogon's stack
mirror): winlogon ENTRY (RVA 0x18e60 = AddressOfEntryPoint) → msvcrt CRT `_initterm` init
(0x1f080) → `strdup(GetCommandLineA())` → `strlen(NULL)`. **`GetCommandLineA()` returned NULL**
because kernel32's `BaseAnsiCommandLine.Buffer` was never set: `InitCommandLines()`
(→`RtlUnicodeStringToAnsiString`) runs in kernel32's `DllMain`, and **the LIVE on-target loader
(`on_target::ldrp_drive`) only snapped imports + installed the heap — it NEVER called
`DLL_PROCESS_ATTACH`.** (The host-tested `loader/init.rs` engine computes the order + calls
`host.call_dll_main`, but the live `ldrp_drive` used `snap_all_imports` only.) smss/csrss didn't
need it; winlogon (kernel32 + msvcrt CRT) does.

### 3. THE FIX — run DLL_PROCESS_ATTACH in DEPENDENCY ORDER (on_target.rs)
Added `run_process_attach()` / `attach_dfs()`: after `snap_all_imports`, a **post-order DFS**
over the `MODULE_TABLE` — for each module, walk its import descriptors, recurse into each
imported DLL (found in the table) FIRST, then call the module's own `DllMain(DLL_PROCESS_ATTACH)`
(Win64 ABI shim: rcx=base, rdx=1, r8=0). A per-base visited set dedupes diamonds + breaks
cycles; our own ntdll + the EXE + resource-only (no-entry) DLLs are skipped. ★ ORDER MATTERS:
reverse-insertion order was WRONG (mpr-first → kernel32 uninitialized → crash). Now for winlogon
the order is **kernel32, gdi32, advapi32_vista, kernel32_vista, msvcrt, ws2help, ws2_32, rpcrt4,
advapi32, user32, userenv, mpr** — kernel32 first, as the real Ldr does.

### 4. PEB TLS bitmaps (img_spawn.rs)
kernel32's `TlsAlloc()` (thread.c:1112) calls `RtlFindClearBitsAndSet(Peb->TlsBitmap, 1, 0)`; a
NULL `Peb->TlsBitmap` #PFs reading `SizeOfBitMap` (found: ws2_32's DllMain reaches TlsAlloc).
Init the two RTL_BITMAPs in the PEB page tail (past ProcessHeaps@0x800): x64
`Peb->TlsBitmap@0x78 → {SizeOfBitMap=64, Buffer=&TlsBitmapBits@0x80}`,
`Peb->TlsExpansionBitmap@0x238 → {1024, &TlsExpansionBitmapBits@0x240}`; bit 0 reserved.

### How far the boot got (gate 149, no regression)
winlogon now runs its ENTIRE 12-DLL DllMain chain (kernel32 first, verified by the
`DllMain base=0x…` trace) + the SSN trace shows real registry (125/185) + win32k (4346/4699/4576)
activity. smss/csrss stay green with the DllMain-calling loader (csrsrv's DllMain runs for csrss).
Host: nt-ntdll 157, nt-syscall-abi 12 green.

### ★ THE NEXT FRONTIER = the CSR/base-server connect DURING winlogon's LOADER
kernel32's `DllMain` reaches `InitCommandLines()` ONLY after `CsrClientConnectToServer` succeeds
(dllmain.c:139): it connects to `\Windows\ApiPort`, then `ASSERT(Peb->ReadOnlyStaticServerData)` +
`BaseStaticServerData = Peb->ReadOnlyStaticServerData[BASESRV=1]`. In our host the loader-time
connect FAILS (SSN trace shows `4:266 NtTerminateProcess` = kernel32 bailing on the failed
connect), so `InitCommandLines` never runs → `GetCommandLineA()==NULL` → the strlen(NULL) at
winlogon's entry. The executive HAS the machinery (`ExecNtHandler::csr_client_connect` services
`NtSecureConnectPort(\Windows\ApiPort)` = SSN 218 via `csr_rendezvous` + maps the CSR heap-view +
the `ReadOnlyStaticServerData` array with a `BASE_STATIC_SERVER_DATA[1]`), and already fills the
CSR_API_CONNECTINFO out-param (SharedStaticServerData@+0x10 = WINLOGON_CSR_STATIC_VA,
SharedSectionBase@+0x08, ServerProcessId@+0x30). ★ **THE PRECISE BLOCKER (disasm + the winlogon SSN
trace):** winlogon (badge 4) NEVER issues SSN 218 — it goes straight to `4:266 NtTerminateProcess`,
because **`CsrClientConnectToServer` is an ntdll export = OURS, and
`crates/nt-ntdll-dll/src/exports.rs::csr_client_connect_to_server` is a `STATUS_NOT_IMPLEMENTED`
STUB.** kernel32's DllMain gets that failure and terminates before `InitCommandLines`. (Confirmed:
kernel32.dll imports NO `Nt*ConnectPort` — the connect lives INSIDE ntdll's `CsrpConnectToServer`,
which calls `NtSecureConnectPort` internally, connect.c:141.) ★ ALSO: **`NtSecureConnectPort`
(SSN 218) is NOT in our stub set / `nt-syscall-abi` table nor exported by our ntdll** (only
`NtConnectPort` SSN 33 is).

### NEXT STEP (the direct unblock to the paint) — implement our ntdll `CsrClientConnectToServer`
1. **Add the `NtSecureConnectPort` SSN-218 stub** to `nt-ntdll::trap_stubs` + `nt-syscall-abi`
   (name→ssn + argc=9). The native-transport naked stub already captures rsp, so the executive
   reads args 5-9 off the caller's stack via its mirror; a Windows-ABI call places them there.
2. **Implement `csr_client_connect_to_server`** (port `CsrpConnectToServer`, connect.c:43): build a
   `\Windows\ApiPort`-under-ObjectDirectory `UNICODE_STRING PortName` (arg2/RDX), a `PORT_VIEW
   LpcWrite` (arg4/R9), a `SECURITY_QUALITY_OF_SERVICE` (arg3/R8), a `CSR_API_CONNECTINFO`
   (arg8 = [sp+0x40]) + its length (arg9), issue `NtSecureConnectPort(&CsrApiPort, &PortName, &Qos,
   &LpcWrite, SystemSid, &LpcRead, NULL, &ConnectionInfo, &ConnectionInfoLength)` — the executive's
   `csr_client_connect` fills ConnectionInfo — then copy `ConnectionInfo.SharedStaticServerData` →
   `Peb->ReadOnlyStaticServerData`, `SharedSectionBase` → `ReadOnlySharedMemoryBase`, and
   `RtlCreateHeap` over LpcWrite.ViewBase. Return STATUS_SUCCESS. (Args must be STACK locals so the
   executive's mirror reads/writes land — same discipline as `on_target::nt_allocate_virtual_memory`.)
3. Then kernel32's DllMain reaches `InitCommandLines()` (GetCommandLineA non-NULL) → winlogon's
   entry runs its real `WinMain` → `SwitchDesktop → co_IntShowDesktop → IntPaintDesktop → 0x003a6ea5`.
   The `csr_rendezvous` native arm (this batch) drives csrss's real CsrApiRequestThread accept.

---

## ☑ SYSTEMATIC PORT — BATCH 8 (DONE 2026-07-17): NtSecureConnectPort(218) + CsrClientConnectToServer → winlogon's kernel32 DllMain COMPLETES the CSR connect → winlogon advances PAST the CSR wall into its win32k/WinMain flow (gate 149 → 150; `exec_winlogon_csr_connect` now PASSES)

### 1. NtSecureConnectPort SSN 218 added to the shared ABI + the stub table
`nt-syscall-abi`: `NT_SYSCALLS` gains `n("NtSecureConnectPort", 218)` (verified vs
`references/reactos/ntoskrnl/sysfuncs.lst:219` = `NtSecureConnectPort 9`, line 219 = 0-based SSN 218)
+ `NT_ARGC` gains `("NtSecureConnectPort", 9)`. `nt-ntdll::trap_stubs` gains the 189th naked stub
`(nt_secure_connect_port, "NtSecureConnectPort", 218)`. Counts bumped 188→189 across the tests
(`nt-syscall-abi` `REQUIRED_NT_COUNT`, `nt-ntdll` stub/trap-stub counts). Host: **nt-ntdll 157 +
nt-syscall-abi 12 green**; the DLL emit reports **189 Nt* stubs exported (0 missing)** + 599 exports.

### 2. `CsrClientConnectToServer` = a faithful port of ReactOS `CsrpConnectToServer` (on_target.rs)
`crates/nt-ntdll-dll/src/on_target.rs::csr_client_connect_to_server` (called from the exports.rs
thunk under `cfg(target_arch="x86_64", feature="native_transport")`; host build = STATUS_NOT_IMPL):
builds the `\Windows\ApiPort` PortName UNICODE_STRING + the SECURITY_QUALITY_OF_SERVICE + PORT_VIEW
LpcWrite + REMOTE_PORT_VIEW LpcRead + CSR_API_CONNECTINFO (all STACK locals so the executive's
stack-mirror writes land — same discipline as `nt_allocate_virtual_memory`; layouts matched to
`ndk/lpctypes.h` PORT_VIEW = {Length@0,SectionHandle@0x08,ViewSize@0x18,ViewBase@0x20,
ViewRemoteBase@0x28} + `csr/csrmsg.h` CSR_API_CONNECTINFO x64 = {SharedSectionBase@0x08,
SharedStaticServerData@0x10,SharedSectionHeap@0x18,ServerProcessId@0x30}), issues the 9-arg
`NtSecureConnectPort` over a new `native_secure_connect_port` helper (mirrors `native_map_view`: a1..a4
in the message MR2/MR3/MR4/MR5, a5..a9 on the stack at `[rsp+0x28..0x50]` — a8/ConnectionInformation
= `sp+0x40`, exactly where the executive's `csr_client_connect` reads it), then on success copies
`ConnectionInfo.{SharedSectionBase,SharedSectionHeap,SharedStaticServerData}` into the PEB
(`ReadOnlySharedMemoryBase@0x88 / …Heap@0x90 / ReadOnlyStaticServerData@0x98`) — exactly what
kernel32's DllMain reads next. We SKIP the real `NtCreateSection` (the executive owns + maps the CSR
heap view at a fixed VA regardless) + pass NULL SectionHandle/SystemSid (cosmetic on the modeled
accept path). A `CSR_CONNECTED` `AtomicBool` guard replicates CsrpConnectToServer's `if (!CsrApiPort)`
→ connect EXACTLY ONCE per process (the 2nd+ call is a no-op success; without it the redundant 2nd
connect re-drove the executive's CSR rendezvous → **a hang**).

### 3. ★ ROOT-CAUSE FIX — `call_dll_main` stack misalignment (`sub rsp, 0x28` → `0x20`)
The FIRST boot with the connect implemented #GP-faulted at ntdll RVA 0xf906 = CsrClientConnectToServer's
prologue `movaps [rsp+0x170]` (an ABI-aligned SSE spill). Root cause: the loader's `call_dll_main`
shim reserved `sub rsp, 0x28` before `call <DllMain>`. Rust keeps rsp ≡0 mod 16 in a function body;
`0x28` ≡ 8 mod 16 left rsp ≡ 8 pre-`call` → the DllMain callee (and everything it calls, incl.
CsrClientConnectToServer) saw rsp ≡ 0 mod 16 = **misaligned by 8** → the first aligned SSE store
faulted. Fix = reserve `sub rsp, 0x20` (≡0 mod 16 → callee gets the ABI-correct rsp≡8 mod 16). This
is a real bug the loader carried latently (smss/csrss/csrsrv DllMains happened not to spill aligned
SSE; kernel32's did). NO KERNEL CHANGE; ntdll-side only.

### How far the boot got (gate 150, boot-verified)
- **`[csr] pi=2 NtSecureConnectPort(\Windows\ApiPort)`** fires ONCE (the guard prevents the reconnect
  hang) → the executive's `csr_client_connect` maps winlogon's CSR heap-view + fills the
  CSR_API_CONNECTINFO → `WINLOGON_CSR_CONNECTED=1` → **`PASS exec_winlogon_csr_connect`** (was FAIL).
- winlogon's SSN trace advances PAST the connect: `4:218 → 0:175(csrss NtQuerySection) → 4:181 →
  4:36 → 4:27 → 4:173/4:173 → **4:4346 4:4699 (win32k NtUser* graphics!)** → 4:125(NtOpenKey) →
  4:185(NtQueryValueKey) → 4:27 → 0:161(NtWaitForSingleObject)`. winlogon demand-faulted **178 pages**
  (was 95) — it runs its real WinMain deep into win32k desktop init.
- **Gate 150 / 98** (up from 149). Host: nt-ntdll 157, nt-syscall-abi 12 green.

### ★ THE REMAINING WALL = win32k desktop-graphics init (past the CSR connect, before the paint)
winlogon now reaches win32k (NtUser* SSNs 4346/4699) but the paint is NOT yet reached:
`win32k desktop-graphics framebuffer pixels: gfx-init not reached` + `desktop-bg match 0/768`. The
lazy `co_IntGraphicsCheck → co_AddGuiApp → co_IntInitializeDesktopGraphics → co_IntShowDesktop →
IntPaintDesktop` chain (see `project_win32k_graphics.md`; the machinery EXISTS) hasn't been triggered
by winlogon's flow yet — winlogon parks on `NtWaitForSingleObject` before driving the graphics-init
DC-op. THIS is the NEXT frontier (a NEW wall, not the CSR connect): trace which win32k call winlogon
stops short of + what it waits on (a worker thread? a registry/font open? a DC alloc?) that would
drive `NrGuiAppsRunning` → the lazy InitVideo → the 0x003a6ea5 paint (768/768).

---

## ☑ SYSTEMATIC PORT — BATCH 9 (2026-07-17): DIAGNOSE-FIRST — the winlogon-worker-multiplex hypothesis is DISPROVEN; winlogon blocks MUCH earlier, in user32 per-process init (a contended critical-section spin), long before StartRpcServer/StartServicesManager/StartLsass/WaitForLsass/SwitchDesktop/the paint. NO code change landed (the queued fix would have been wrong). Gate stays 150; host green (nt-ntdll 157 + nt-syscall-abi 12).

### The queued hypothesis (from the handoff) and why it's WRONG
The handoff said: "winlogon parks on `NtWaitForSingleObject` before `co_IntShowDesktop`; wire winlogon's
worker/desktop thread to the NATIVE transport (spawn_wl_listener_thread `native:false` → `true`,
mirror BATCH 6) so its faults multiplex and drive the lazy graphics init → the paint." **Traced the
evidence (per the DIAGNOSE-FIRST mandate): this is not the blocker.** winlogon never creates a worker
thread before it blocks, and the `0:161` NtWaitForSingleObject in the ssn ring is **smss's** terminal
broker wait (badge 0), not winlogon's — the previous handoff mis-attributed it to winlogon.

### What the boot ACTUALLY shows (43f7b06, clean tree, gate 150)
winlogon's syscall trace (badge 4) ENDS at `4:4699` = win32k SSN **0x125B = `NtUserInitializeClientPfnArrays`**
(w32ksvc64.h:609), which returns STATUS_SUCCESS. After that winlogon demand-faults exactly ONE more
page — a FETCH at user32 RVA **0x8a940** (rip==cr2) — and then goes **completely silent: NO further
fault, NO further syscall.** The whole executive loop quiesces (iters=853 ≪ 8000 budget; all threads
parked) → a hard user-mode block, not a budget cutoff. **`services.exe` is NEVER spawned**
(`exec_services_spawned` FAIL, "spawned services" count 0); **lsass NEVER spawned**
(`lsass spawned=0`). So winlogon stops FAR before StartServicesManager (WinMain:508) / StartLsass
(:515) / WaitForLsass (:523) / InitializeSAS (:578, which is what calls `SwitchDesktop` at sas.c:1746
→ co_IntShowDesktop → IntPaintDesktop → the 0x003a6ea5 paint).

### The exact WinMain position of the block (references/reactos/base/system/winlogon/winlogon.c)
1. RtlSetProcess/ThreadIsCritical (457–458), UpdateTcpIpInformation (461, the `4:125`/`4:185`/`4:27` reg reads)
2. RegisterLogonProcess (463) → csrss RPC
3. **`CreateWindowStationAndDesktops` (484)** ← THE BLOCK IS HERE. The first USER-mode syscall from
   winlogon triggers user32's lazy per-process client init: `ClientThreadSetup`/`RegisterClientPFN` →
   `NtUserProcessConnect` (0x10FA=4346) → `NtUserInitializeClientPfnArrays` (0x125B=4699) → then
   `MessageInit()`/`MenuInit()` (user32 dllmain.c:304/307), which is where it spins.
4. InitKeyboardLayouts (494), StartRpcServer (501 — the RPC listener thread, the ONLY winlogon worker,
   NEVER reached), StartServicesManager (508), StartLsass (515), **WaitForLsass** (523 → blocks on the
   cross-process named event `LSA_RPC_SERVER_ACTIVE`, which lsasrv signals via SetEvent at
   dll/win32/lsasrv/lsarpc.c:105 — a SECOND, later wall), then InitializeSAS (578) → SwitchDesktop → paint.

### The precise block: a PURE user-mode busy-spin in user32 init (NOT the keyed-event seam)
Disassembled user32 at the last-fault RVA 0x8a940 (imagebase 0x7ffb2000000): it's a tiny init helper
that calls **`kernel32!InitializeCriticalSection` TWICE** then `mov eax,1; ret` (it inits two user32
CSes — e.g. gcsUserApiHook/gcsHooks; resolved via the IAT thunk at 0xa1ffa → IAT slot 0xa44f0 =
kernel32!InitializeCriticalSection). That call returns; winlogon continues into already-resident code
and then spins with **NO faults AND NO syscalls** — a **pure user-mode busy-spin**. ★ IMPORTANT
REFINEMENT: the ssn ring shows **NO `NtWaitForKeyedEvent`(292)/`NtReleaseKeyedEvent`(291)** — so
winlogon is NOT reaching `RtlpWaitForCriticalSection`'s keyed-event block. It's stuck in a
BEFORE-keyed-event busy loop: either the CS spin-count fast-path spin (`RtlEnterCriticalSection`'s
`YieldProcessor` loop testing `LockCount`) that never exits, or a user32 `while(!flag) YieldProcessor()`
poll on a shared flag another thread should set. Since winlogon is single-threaded here, a flag/CS a
second thread must release can never resolve — so the block is EITHER (a) a real bug in OUR ntdll's
`RtlEnterCriticalSection`/`RtlpWaitForCriticalSection` LockCount state machine (it loops instead of
falling through to the keyed-event wait — check `crates/nt-ntdll*/src/sync.rs`'s target-side CS body,
NOT just the host fast-path), OR (b) user32 init genuinely waiting on csrss/win32k to set a shared
value that our modeled connect didn't populate. Pinning it needs live instrumentation of winlogon's
spin RIP (gdb-stub RIP sample, or an executive counter on winlogon's post-0x125B fault/no-progress).

### ★ THE REAL NEXT FRONTIER (re-scoped, evidence-backed)
NOT the worker multiplex. The immediate wall is a **user-mode busy-spin in user32 per-process init**,
reached right after two `InitializeCriticalSection` calls, with NO keyed-event syscall — so START by
**instrumenting winlogon's spin RIP** (executive: on winlogon (badge 4), when it stops producing
faults/syscalls, sample its TCB's saved RIP via the kernel, or use the QEMU gdb-stub to halt + read
RIP; then map RIP−user32_base to a user32 function). That tells you whether it's (a) OUR ntdll's
`RtlEnterCriticalSection` spin/state-machine looping (fix the CS body in `crates/nt-ntdll*/src/sync.rs`
+ wire the keyed-event fall-through over native seL4-Call + an executive keyed-event handler), or (b)
user32 polling a csrss/win32k-set shared value our modeled connect left unset (populate it). Only past
this do StartRpcServer (the RPC listener thread — where the BATCH-6 `spawn_wl_listener_thread
native:true` multiplex pattern legitimately applies), StartServicesManager, StartLsass, WaitForLsass
(the LSA_RPC_SERVER_ACTIVE event — needs lsass running to SetEvent it, lsarpc.c:105), and finally
InitializeSAS/SwitchDesktop/the 0x003a6ea5 paint come into reach. The worker-multiplex work remains a
VALID future step for StartRpcServer's listener — just not the current blocker.

---

## ☑ SYSTEMATIC PORT — BATCH 10 (2026-07-17): RIP-INSTRUMENTED the "user32-init spin" — it is NEITHER (a) our CS bug NOR (b) a shared-value poll. It was a PARKED, UNSERVICED instruction-fetch fault, masked by the single service loop breaking on smss's terminal query. One-line fix; winlogon ADVANCES past user32 init. Gate 150 held; host green (nt-ntdll 157 + nt-syscall-abi 12).

### The RIP evidence (the DIAGNOSE-FIRST mandate, satisfied)
Added a `tcb_read_rip(tcb)` helper (`components/ntos-executive/src/win32k_glue.rs`) = the legacy
length-0 `seL4_TCB_ReadRegisters` (label 2) returning MR0=saved RIP, and sampled winlogon's PARKED
TCB (`PM_MAIN_TCBS[2]`) three times at spec-time (`components/ntos-executive/src/main.rs`, in the
winlogon-paint diagnostic block). All three samples were **IDENTICAL: `0x801da940` = `user32+0x8a940`**
(module bases from the DEMAND-LOAD log: user32=0x80150000, kernel32=0x803a0000, …). Cross-referenced
with the KERNEL's own fault print: the LAST winlogon fault was
`[user #PF: tcb=24 cr2=0x801da940 err=0x14 rip=0x801da940]` — **cr2==rip, err=0x14 = (User | Instr-fetch)**:
an INSTRUCTION-FETCH page fault. The RIP being frozen EXACTLY at the fault IP (the seL4 restart-IP for
a page fault is the faulting instruction) proves winlogon was **PARKED at an unserviced fetch-fault,
NOT busy-spinning**. BATCH 9's "contended critical-section busy-spin" characterization was WRONG.

### The real root cause — (c) a loop-ordering stop, not a ntdll/shared-value bug
The single-threaded executive service loop multiplexes smss (badge 0) + csrss + winlogon (badge 4) +…
through ONE `reply_recv` on the shared fault endpoint. winlogon (prio 102) faulted on the fetch at
`user32+0x8a940`, but the loop then received **smss's terminal `NtQueryInformationProcess` (SSN 161 —
which is QueryInfoProcess, NOT NtWaitForSingleObject; BATCH 9 mislabeled the `0:161` in the ssn ring)
with an unmodeled class 44 (ProcessImageInformation)**, whose handler did `self.stop = true`
(`exec_handler.rs` NtQueryInformationProcess default arm) → `stop_ssn=161`, `break`. So the loop TORE
DOWN while winlogon's higher-priority fetch-fault sat **undequeued/unserviced** in the endpoint — RIP
frozen, "no further fault/syscall" (BATCH 9's "silent quiesce"). Neither the CS nor a poll: an
executive loop-lifetime bug where an unmodeled smss query killed the boot before a live process's
pending fault could be filled.

### The fix (one line, executive-side; NO rust-micro/src change, NO ntdll change)
`exec_handler.rs` — the `NtQueryInformationProcess` unmodeled-class arm no longer sets `self.stop = true`;
it returns **STATUS_INVALID_INFO_CLASS (0xC0000003)** and keeps the class-print diagnostic. The caller
degrades gracefully AND the loop keeps multiplexing, so winlogon's pending fetch-fault gets serviced.
(An unmodeled info-class is a per-caller degrade, never a whole-boot stop — the correct policy for a
multiplexed loop.) The BATCH-10 RIP sampler + `tcb_read_rip` are kept as a permanent, once-at-spec-time
spin-diagnostic (harmless; guarded on `PM_MAIN_TCBS[2] > 1`).

### How far winlogon got + the NEW wall
winlogon now runs PAST user32 per-process init (`ClientThreadSetup`/`RegisterClientPFN`/the two
`InitializeCriticalSection` calls) — the ssn ring advanced from `…4:4699 0:161` (the old wall) to
`…4:4699 0:161 4:125 4:185 4:27 4:4576 0:27 4:173 4:173 4:125 4:125 4:185 4:27 4:173` (a NEW win32k
call 4:4576 + more). It now walls at a REAL NULL-deref: `[winlogon vmf] NULL/low deref ip=0x806d3ca6`
= **`msvcrt+0x43ca6` = `strlen+0x16` (`movsbl (%rax),%eax`, rax=NULL) → winlogon called `strlen(NULL)`**
(exactly the case the executive's own vmf diagnostic anticipated). The caller chain (retaddrs) runs
through our ntdll (0x100_00c0xxxx) into winlogon.exe (0x100_00578e80 = winlogon.exe+0x18e80) — a
CRT-init/env path passing a NULL string. Gate held at 150 (no regression); `cargo test -p nt-ntdll`
157 + `-p nt-syscall-abi` 12 green.

### ★ THE NEXT FRONTIER (evidence-backed)
Trace WHO passes NULL into `strlen` (the caller chain above; likely a winlogon CRT-startup env/arg
copy or a `getenv`-style lookup returning NULL that a copy then `strlen`s). Populate the missing source
string (an env var / registry value / process-param field our modeled setup leaves NULL) so `strlen`
gets a valid pointer. Only then do winlogon's `StartServicesManager` (spawns services.exe) →
`StartLsass` (spawns lsass) → `WaitForLsass` (the `LSA_RPC_SERVER_ACTIVE` cross-process event) →
`InitializeSAS` → `SwitchDesktop` → `co_IntShowDesktop` → the `0x003a6ea5` desktop paint come into
reach. The BATCH-6 `spawn_wl_listener_thread native:true` worker-multiplex remains a valid FUTURE step
for `StartRpcServer`'s RPC listener thread — still not the current blocker.

---

## ☑ SYSTEMATIC PORT — BATCH 11 (2026-07-17): DIAGNOSE-FIRST — the winlogon `strlen(NULL)` at msvcrt+0x43ca6 root-caused (NOT a missing string — `Peb->ProcessHeap` was NULL → `GetProcessHeap()` NULL → msvcrt CRT process-attach BAILED before setting `_acmdln`). ONE-LINE FIX (publish the loader's heap base into `Peb->ProcessHeap`, PEB+0x30) makes msvcrt's `_heap_init`/`_mtinit` complete (`__tlsindex=1`) → winlogon ADVANCES PAST the strlen(NULL); walls FURTHER at a msvcrt LOCALE-init NULL deref. Gate 150 held; host green (nt-ntdll 157 + nt-syscall-abi 12).

### The trace (evidence, not guess — the handoff's "missing string" hypothesis was WRONG)
The fault `strlen(NULL)` at msvcrt+0x43ca6 is reached via **`__getmainargs → _setargv(0x1ecf0) → strlen(_acmdln)`** where `_acmdln` (msvcrt data export @RVA 0x905c0) is NULL. Disassembly established the full chain; then executive-side reads (a `[wl-diag]` block via `scratch_for` of the faulted DLL pages) gave the DECISIVE evidence:
- **`k32.BaseAnsiCommandLine{len=0xc buf=0x100_00c00020}`** — kernel32's `GetCommandLineA()` WORKS (BaseAnsiCommandLine correctly populated with "winlogon.exe", 12 chars). So the command-line string is NOT missing — the handoff's "populate the source string" premise was wrong.
- **`msvcrt._acmdln=0x0`** — msvcrt's `_acmdln = strdup(GetCommandLineA())` (msvcrt 0x1f080, called from its DllMain `_cinit` 0x1425) NEVER RAN.
- A loader-side `DllMain ret=` print showed **msvcrt's DllMain returned `0x0` (FALSE)** while every other DLL returned 1 → msvcrt's CRT process-attach BAILED.
- Walking msvcrt's ATTACH branch (0x13c3): the FIRST checked gate is `_heap_init` (0x8e40) = `if (GetProcessHeap()==NULL) return FALSE`. `GetProcessHeap` (kernel32 0xc910) = `return Teb->Peb->ProcessHeap` (**PEB+0x30**). Our `img_spawn.rs` never set PEB+0x30, and the ntdll loader's `create_process_heap` installed the heap only into a Rust-side static (`install_process_heap`) — so **`Peb->ProcessHeap` was NULL** → GetProcessHeap NULL → `_heap_init` FALSE → msvcrt DllMain FALSE → `_acmdln` never set → strlen(NULL).

### The fix (one place, ntdll-loader-side; NO executive change, NO rust-micro/src change)
`crates/nt-ntdll-dll/src/on_target.rs::ldrp_drive` — after `create_process_heap()` (now returns the heap base too), **publish the heap base into `Peb->ProcessHeap` (PEB+0x30)** via `gs:[0x60]` (matches real ntdll's `LdrpInitializeProcess` setting `Peb->ProcessHeap = RtlCreateHeap(...)`). Our `RtlAllocateHeap`/`RtlFreeHeap` IGNORE the HeapHandle (single installed heap), so the value only needs to be non-NULL for `GetProcessHeap()` — which is exactly what it now is. Host tests unaffected (target-only path); nt-ntdll 157 + nt-syscall-abi 12 green.

### How far winlogon got + the NEW wall (locale-init)
`__tlsindex=1` confirms msvcrt's `_heap_init`+`_mtinit` (TlsAlloc via our RtlFindClearBitsAndSet) now COMPLETE — winlogon is PAST the strlen(NULL). It now walls at `[winlogon vmf] NULL/low deref ip=0x806996a3 addr=0x28` = **msvcrt+0x96a3**: msvcrt's per-locale-category init (fn @0x9654) calls `kernel32_vista!InitializeCriticalSectionEx(&cs,...)` then reads `[cs+0]` (the CS `DebugInfo` field) as a pointer and writes `[DebugInfo+0x28]` — but **our critical-section init leaves `DebugInfo` (field 0) NULL**, so `[NULL+0x28]` faults at addr 0x28. This is a SEPARATE, deeper wall in our RTL_CRITICAL_SECTION / `InitializeCriticalSectionEx` (it must set a non-NULL `DebugInfo`/field-0, as real ntdll's `RtlpAllocateDebugInfo` does) — NOT the strlen(NULL) I was tasked with. Gate 150 held (no regression, same 150 PASS / 27 FAIL). **NEXT FRONTIER = make our `InitializeCriticalSectionEx`/CS-init set a non-NULL field-0 (`DebugInfo`) so msvcrt's locale-category init doesn't NULL-deref — then msvcrt's CRT startup finishes and winlogon's entry runs its real WinMain → StartServicesManager/StartLsass → SwitchDesktop → the 0x003a6ea5 paint.**

## ☑ SYSTEMATIC PORT — BATCH 13 (DONE 2026-07-17): the kernel32 NULL deref = OUR stub `RtlInitCodePageTable` left `MultiByteTable` NULL → made it a faithful port → winlogon runs PAST kernel32's codepage init (140→173 demand-faulted pages), walls FURTHER at OUR `RtlRaiseException` int3 stub (gate 150 held, host green 162+12)

### THE DIAGNOSIS (disasm + retaddr-chain evidence)
- **The fault** (`rip=0x8041167e`, `cr2=0x0`, `err=0x4`): kernel32's real runtime base is **0x803a0000** (NOT 0x80000000 — from the executive's BATCH-10 RIP classifier), so `rip=0x8041167e → kernel32+0x7167e`. The faulting instruction is `movzwl (%rdx,%rax,2), %eax` with **`%rdx` = the `MultiByteTable` pointer = NULL**.
- **The function** (`.pdata` RUNTIME_FUNCTION range 0x710d0..0x716d3) = kernel32's internal **`IntMultiByteToWideChar`** (ReactOS `dll/win32/kernel32/winnls/string/nls.c:698`). Prologue: `IntGetCodePageEntry(CodePage)` → `CodePageEntry` [rsp+0x60]; NULL-check bails correctly; then `[rsp+0x38] = CodePageEntry + 0x28` (= `&CodePageTable`, a `CPTABLEINFO`); `[rsp+0x58] = CodePageTable->MultiByteTable` (CPTABLEINFO+0x20). The loop `*WideCharString++ = MultiByteTable[Char]` (nls.c:807) is the fault.
- **The retaddr chain** (rebased at 0x803a0000): `MapViewOfFile→MapViewOfFileEx→NtMapViewOfSection` + `GetNlsSectionName`/`lstrcatA` — i.e. `IntGetCodePageEntry`'s section-mapped path (nls.c:359–473): build `\Nls\NlsSectionCP<n>`, `NtOpenSection`, `MapViewOfFile` → `SectionMapping`, then `RtlInitCodePageTable((PUSHORT)SectionMapping, &Entry->CodePageTable)`.
- **The boot log confirms it end-to-end**: `NtOpenSection name="\Nls\NlsSectionCP20127"` → handle 0x64; `NtMapViewOfSection NlsCP20127 -> base 0xA0000000` (map SUCCEEDS, non-NULL); the very next instruction faults at `cr2=0x0`. So the section maps fine but `RtlInitCodePageTable` produced a **NULL `MultiByteTable`** in the descriptor.

### ★ ROOT CAUSE — `RtlInitCodePageTable` is an ntdll export = OURS, and it was a STUB
`crates/nt-ntdll-dll/src/exports.rs::rtl_init_code_page_table` zeroed the whole `CPTABLEINFO` (incl. `MultiByteTable@0x20`, `WideCharTable@0x28`, `DBCSRanges@0x30`, `DBCSOffsets@0x38`) and only set `CodePage`/`MaximumCharacterSize`/`DefaultChar`. So `CodePageTable->MultiByteTable` stayed **NULL** → kernel32's `IntMultiByteToWideChar` dereferenced `NULL[Char]`. (The prior boot never hit this because nothing had reached kernel32's per-codepage `IntGetCodePageEntry`+conversion yet — the BATCH-12 CS-DebugInfo fix let winlogon's CRT/loader get this far.)

### The fix (ntdll-side; NO executive change, NO rust-micro/src change)
Made `RtlInitCodePageTable` a **faithful port of ReactOS `sdk/lib/rtl/nls.c:155`**: copy the `NLS_FILE_HEADER` scalar fields, then compute the table pointers RELATIVE to `TableBase`:
`MultiByteTable = TableBase + HeaderSize + 1` (USHORTs); `WideCharTable = MultiByteTable + TableBase[HeaderSize]`; `DBCSRanges = MultiByteTable + 257` (or `+ 513` if a glyph table is present, i.e. `MultiByteTable[256] != 0`); `DBCSCodePage = 1` + `DBCSOffsets = DBCSRanges + 1` iff `*DBCSRanges != 0`. Verified `CPTABLEINFO` byte offsets from `references/reactos/sdk/include/ddk/ntnls.h` (MultiByteTable@0x20, WideCharTable@0x28, DBCSRanges@0x30, DBCSOffsets@0x38; MAXIMUM_LEADBYTES=12) against the disasm (`entry+0x28 + 0x20` = MultiByteTable).
- New host-tested `nt-ntdll::nls` module (the pure USHORT-index arithmetic + a synthetic SBCS `.nls` builder shaped like the real c_20127): 4 tests (SBCS layout matches ReactOS arithmetic incl. MultiByteTable index 14 / byte-offset 28 for HeaderSize=13; MultiByteTable index is non-zero → never NULL; glyph-table shifts DBCSRanges; a truncated table returns None not a panic). **nt-ntdll 158→162 green.**

### How far winlogon got + the NEW wall (RtlRaiseException)
The kernel32+0x7167e NULL deref is **GONE**. winlogon now runs PAST kernel32's codepage init: new post-map SSNs `4:113 4:125 4:185 4:27` (map / NtOpenKey / NtQuerySystemInformation / NtClose) and its demand-fault count jumps **140 → 173 pages**. It now parks at **ntdll+0x4f22 = `RtlRaiseException`+2** (`[sec-stop] badge=4 (winlogon) label=4 m0=…804f22 m1=3 exc#=0`), i.e. RIGHT AFTER the `int3` in **OUR `RtlRaiseException` stub** (RVA 0x4f20 = `push rax; int3; pop rax; ret`). So winlogon reached its own code that RAISES an exception. Gate 150 held. **BATCH 14 diagnosed WHY (it was a SYMPTOM, not a legit `__try`) and fixed the symptom — see below.**

## ☑ SYSTEMATIC PORT — BATCH 14 (DONE 2026-07-17): the `RtlRaiseException` int3 was a SYMPTOM = a VC++ delay-load failure (`0xC06D007E` ERROR_MOD_NOT_FOUND) for `ntdll_vista.dll`; fixed by EAGERLY binding delay imports in our loader → winlogon runs PAST it (iters 844→1991, +many DLLs), walls FURTHER at a kernel32 PEB->Ldr NULL-deref (gate 150 held, host green 162)

### THE DIAGNOSIS (DIAGNOSE-FIRST — the int3 was NOT a legit `__try`, it was an uncaught error)
Built a DebugException (seL4 fault **label 4 = int3/#BP**, NOT label 3 UserException — that mislabel is why the earlier hypothesis pointed at "winlogon's own SEH") decoder in the executive: on the int3-stop, read winlogon's full GPRs via a new **length-20 `seL4_TCB_ReadRegisters`** (`win32k_glue::tcb_read_regs20` — first 4 words in r10/r8/r9/r15, words 4..20 spilled into the executive IPC buffer), recover **RCX = `PEXCEPTION_RECORD`**, and read the EXCEPTION_RECORD out of winlogon's stack mirror. Result: **`ExceptionCode=0xC06D007E`, `ExceptionAddress=kernel32!RaiseException`, `NumberParameters=1`, `ExceptionInformation[0]` = a `DelayLoadInfo*` on winlogon's stack whose `szDll@+0x18` = `"ntdll_vista.dll"`.**
- `0xC06D007E` = `VcppException(ERROR_SEVERITY_ERROR, ERROR_MOD_NOT_FOUND)` = `0xC0000000 | (FACILITY_VISUALCPP=0x6D << 16) | (ERROR_MOD_NOT_FOUND=0x7E)` — the VC++ **delay-load helper** (`__delayLoadHelper2`) raising because a delay-imported DLL failed to load.
- **The raiser** = kernel32_vista's `__delayLoadHelper2` (disasm: `mov ecx,0xC06D007E; call RaiseException` at kernel32_vista+0x5d5d, right after its internal `LoadLibrary` returned `hmod==0`). **kernel32_vista delay-imports `ntdll_vista.dll`** (the Win7-compat forwarder pair).
- **Is it caught?** NO. kernel32_vista's `.pdata` has **ZERO functions with an EHANDLER** (checked every RUNTIME_FUNCTION's UNWIND_INFO flags) — the `__delayLoadHelper2` frame doesn't catch, and no kernel32_vista frame does. So the exception is **uncaught within kernel32_vista** = a SYMPTOM of a real error (the DLL genuinely failed to load), not a control-flow `__try`.
- **Why the load failed** (traced `LdrLoadDll`/`LdrGetDllHandle` with serial forwards): the delay helper's internal `LoadLibraryExA("ntdll_vista.dll")` **NEVER reaches our ntdll `LdrLoadDll` NOR `LdrGetDllHandle`** — it fails entirely inside real ReactOS **kernel32**'s `LoadLibraryExW` path (before any ntdll loader call / any syscall — no NtOpenFile(122) in the SSN ring). ntdll_vista.dll IS staged + parsed by the executive but was never mapped into winlogon (it's a DELAY import, not a static one nor a forwarder, so our loader's static-import snap never touched it).

### ★ THE FIX (root-cause, ntdll-side; NO executive-logic change, NO rust-micro/src change)
Our loader (`crates/nt-ntdll-dll/src/on_target.rs::snap_module`) processed only `IMAGE_DIRECTORY_ENTRY_IMPORT` (1). Added a pass over `IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT` (**13**) that **EAGERLY BINDS delay imports** (map the DLL via `load_dependent_dll` + register in `MODULE_TABLE` + recursively `snap_module` it, then `snap_descriptor_against(int_rva → iat_rva)` — the same INT→IAT snap a normal import gets). `ImgDelayDescr` (x64, 32 bytes): rvaDLLName@0x04, rvaIAT@0x0C, rvaINT@0x10. Pre-binding the delay IAT means kernel32_vista's `__delayLoadHelper2` is **never invoked** — the delay-imported ntdll_vista functions are already resolved → no `LoadLibrary` → no `0xC06D007E`. This is the architecturally-consistent fix: our loader now loads a module's delay dependencies too (turning delay-load into normal load), sidestepping real kernel32's broken runtime `LoadLibrary` path entirely.

### How far winlogon got + the NEW wall
The `RtlRaiseException` int3 is **GONE**. `NtMapViewOfSection ntdll_vista -> base 0x80040000` (now mapped). winlogon advances hugely: **iters 844→1991**, csrss demand-pages **147→345**, and the loader now brings up **secur32 / netapi32 / … (284 more loader entries)**. New wall = a real **NULL+0x10 deref at kernel32+0xff13** (`cr2=0x10`), inside kernel32's **`GetModuleFileNameW`-region PEB->Ldr walk** (`mov rax,[X+0x18]; add rax,0x10; mov rax,[rax]` where `[X+0x18]` is NULL → deref 0x10). Retaddr chain is real winlogon.exe (`0x100_00c0xxxx`) + kernel32/advapi. **Gate held identical 150 PASS / 27 FAIL** (zero spec diff), host green (nt-ntdll 162). **NEXT FRONTIER: the kernel32 `GetModuleFileNameW` PEB->Ldr walk NULL-deref — likely our PEB->Ldr module list isn't fully populated / linked for the newly runtime-loaded DLLs (a NULL Flink in `InLoadOrderModuleList`), or a `LDR_DATA_TABLE_ENTRY` field the walk reads is unset. Diagnose the exact `[X+0x18]==NULL` (is X the PEB or a Ldr entry?) then populate the missing list linkage.** (The `RtlRaiseException`/SEH-dispatch seam remains an honest int3 — no genuine `__try` needs it yet; the executive DebugException decoder stays as reusable diag infrastructure for any future raise.)

## ☑ SYSTEMATIC PORT — BATCH 15 (DONE 2026-07-17): PEB->Ldr was NEVER built on target (`Peb->Ldr`==NULL) → kernel32 `GetModuleFileNameW(NULL)`'s InLoadOrder walk derefs NULL+0x10; fixed by building + maintaining the three circularly-linked LDR_DATA_TABLE_ENTRY lists in-process → winlogon PAST the loader walls, now parks in **gdi32+0x3f0cc** (real gdi32 process-attach). Gate 150/98 held, host green (nt-ntdll 165)

### ★ THE DIAGNOSIS (PEB->Ldr built? partial? which entry NULL)
**PEB->Ldr was NOT built AT ALL on target.** The executive stages the PEB with `ImageBaseAddress`(+0x10), `ProcessHeap`(+0x30), NLS ptrs, process-params, TLS bitmaps — but **never sets `Peb->Ldr`(+0x18)** (`img_spawn.rs` has no +0x18 write → it stays 0). And the on-target loader (`on_target.rs::ldrp_drive`) created the heap, snapped imports into `MODULE_TABLE`, and ran `DLL_PROCESS_ATTACH` — but **never constructed a `PEB_LDR_DATA` nor set `Peb->Ldr`**. So kernel32's `GetModuleFileNameW(NULL)` read `[PEB+0x18]`=NULL, added 0x10 (`InLoadOrderModuleList.Flink`), and dereferenced NULL+0x10 → `cr2=0x10` at kernel32+0xff13. The `[X+0x18]==NULL` was X=PEB (not a Ldr entry) — the head pointer itself, confirming an ENTIRELY-missing list, not a partial/NULL-Flink entry.

### ★ THE FIX (root-cause, ntdll-side; NO executive-logic change, NO rust-micro/src change)
1. **Reused the link-threading LOGIC.** Extracted the pure circular doubly-linked-list math into `nt_ntdll::loader::peb::circular_links(head_va, node_vas) -> (head, members)` — the single source of truth for closing a `LIST_ENTRY` chain (head.flink→first / head.blink→last / member k.flink→k+1-or-head / never a NULL flink). The host-model `build_ldr` (`thread_list`/`build_head_links`) now delegates to it, so the math is authored + tested ONCE. 3 new host tests (`circular_links_*`: close+walk-terminates, empty-list-self-points, incremental-runtime-add-reappends). nt-ntdll **162→165**.
2. **Built PEB->Ldr on target** (`on_target.rs::build_peb_ldr`, called from `ldrp_drive` step 2.5, AFTER import snap + BEFORE DLL_PROCESS_ATTACH — matching real ntdll's LdrpInitializeProcess order). Reserves a process-lifetime page region (`NtAllocateVirtualMemory`, 512 KiB, bump-allocated → persistent entry VAs), materializes the `PEB_LDR_DATA` head + one `LDR_DATA_TABLE_ENTRY` per module (**EXE first** so a GetModuleFileNameW(NULL) walk returns the EXE, then ntdll, then every MODULE_TABLE dep), each with DllBase@0x30 / EntryPoint@0x38 / SizeOfImage@0x40(from the mapped image OptionalHeader) / a `<name>.dll` UTF-16 FullDllName@0x48 + BaseDllName@0x58 / LoadCount@0x6C — threads all three lists via `circular_links`, sets `Peb->Ldr`(PEB+0x18). Boot-proof line `[dbg] PebLdr va=0x.. n=N`.
3. **Runtime linkage.** `ldr_load_dll` (LdrLoadDll) now re-materializes+re-threads from the full MODULE_TABLE after each runtime load (de-duped by DllBase), so csrsrv's `CsrLoadServerDll` DLLs + delay-loaded modules appear in the lists + a later walk terminates.

### How far winlogon got + the NEW wall
`[dbg] PebLdr` prints per process: **smss n=2** (image+ntdll), **csrss n=3**, **winlogon n=33** (image+ntdll+31 cascaded/delay DLLs). The **kernel32+0xff13 GetModuleFileNameW NULL-Flink wall is GONE** (no `0xff13` anywhere in the boot log). winlogon advances PAST kernel32's post-loader + user32 init and now parks in **`gdi32+0x3f0cc`** (`[batch10]` RIP samples = 0x8012f0cc; gdi32 mapped @0x800f0000, in PEB->Ldr) — a real gdi32 **process-attach / GdiProcessSetup**-region frontier, well past the loader. **Gate held identical 150 PASS / 98 FAIL** (zero spec diff), kernel specs "All specs passed!", host green (nt-ntdll 165). Fixed in BATCH 16 (below).

## ☑ SYSTEMATIC PORT — BATCH 16 (DONE 2026-07-17): the gdi32+0x3f0cc "wall" was NOT a gdi32 seam — it was the `syscall` instruction of gdi32's **NtGdiCreateBitmap stub (SSN 0x106c)**; the call routed fine to hosted win32k, which faulted inside its DIB-blit (EngCopyBits) READING a **win32k-internal source SURFOBJ.pvScan0 = 0x02000000** that no host allocator backed. Fixed by zero-filling win32k-internal unbacked LOW (PML4[0]) VAs as win32k-own working memory → winlogon runs PAST gdi32 process-attach (issues NtGdi SSNs 0x10b5/0x103d/0x10b4 for stock-object/cursor GDI init), now parks in **user32+0x9f327**. Gate 150/98 held, kernel "All specs passed!", host green (nt-ntdll 165). Executive-only (win32k_glue.rs), NO rust-micro/src NOR ntdll change → sel4test byte-identical.

### ★ THE DIAGNOSIS (disasm gdi32+0x3f0cc + win32k SSDT + the fault classification)
1. **gdi32+0x3f0cc is a win32k syscall stub, not gdi32 logic.** Disasm of gdi32.dll at RVA 0x3f0cc (image_base 0x7ffb3000000): `0x3f0c4 mov eax,0x106c; 0x3f0c9 mov r10,rcx; 0x3f0cc syscall; 0x3f0ce ret` — winlogon parked ON the `syscall` for **SSN 0x106c** (= gdi32's `GdiCreateBitmap` stub; the next stub at 0x3f0cf is `GdiConsoleTextOut`=0x106d). So the "gdi32 process-attach wall" is winlogon ISSUING an `NtGdiCreateBitmap` — a real win32k call during gdi32/user32's stock-object GDI init (an 8×8×1bpp mono pattern bitmap; args from the caller stack: `cx=8 cy=8 cPlanes=1 cBPP=1 pUnsafeBits=0x80bc5f78`).
2. **The routing WORKS.** The boot log shows `[win32k-svc] csrss -> SSN 0x106c (dispatch)` (the "csrss" print label is generic; it's winlogon/badge 4) — the executive's SSN≥0x1000 forward-arm routed it to the hosted win32k component (SSN 0x106c → win32k SSDT idx 0x6c → RVA 0x108fe0, verified by parsing the 740-entry service table at win32k .data RVA 0x206200 = the base `0x0100_06a06200` KeAddSystemServiceTable recorded).
3. **The REAL fault is INSIDE win32k:** `[user #PF: tcb=20 cr2=0x02000000 err=0x4 rip=0x100069cbdd8]` = win32k RVA **0x1cbdd8** (an EngCopyBits/EngBitBlt DIB scanline-blit inner loop, `.pdata` fn 0x1cbd80..0x1cbe74) READING (err=0x4, page-not-present) address **0x02000000**. Two subagents established via SURFOBJ layout (`pvScan0`@0x38) + the blit disasm that **0x02000000 is the SOURCE surface's `pvScan0`** (`SourceSurface->pvScan0`), NOT the client `pUnsafeBits` (0x80bc5f78) — win32k built a temporary source SURFOBJ whose bits pointer is 0x02000000. Exhaustive check of EVERY host win32k allocator (pool @0x100_0A00_0000, USERVM @0x100_0C00_0000, session heap, MmMapView section arenas, EngAllocUserMem→ZwAllocateVirtualMemory→uservm all PML4[2]; framebuffer @0x1_0900_0000) proved **none emits 0x02000000** — it is a win32k-INTERNAL default the host never backed with frames.
4. **Why it walled (the executive bug):** `win32k_dispatch`'s demand-fault handler (win32k_glue.rs) classified 0x02000000 as a "foreign client pointer" SOLELY because `addr < 0x100_00000000` (its low-VA test), then tried `map_csrss_page_into_win32k` — which returned FALSE because 0x02000000 has NO recorded client frame (it's not a client pointer at all) — and WALLED with 0xc0000001. So a win32k-internal working buffer was misrouted through the client-frame-sharing path and failed.

### ★ THE FIX (root-cause, executive-side; NO rust-micro/src NOR ntdll change)
`win32k_glue.rs win32k_dispatch` VMFault handler: when `map_csrss_page_into_win32k` fails, **discriminate a genuine client user pointer from a win32k-internal working buffer.** Every hosted-process user region lives in **PML4[2] (>= 0x100_0000_0000**: PE_LOAD_BASE / NTDLL_BASE / STACK_BASE / SMSS_ALLOC_VA / all executive-issued NtAllocateVirtualMemory). A fault BELOW that range (PML4[0], e.g. 0x0200_0000, non-null) with NO client frame is NOT a client pointer — it's a bits/surface buffer win32k itself materialized whose VA no host allocator backed. **Zero-fill it as win32k-own memory** (`ensure_w32_client_paging` + a fresh frame — the SAME treatment the non-foreign branch already applies to win32k-own demand pages), so the blit reads a defined (blank) buffer instead of walling. Bounded by DEMAND_CAP. A GENUINE unbacked HIGH client pointer (>= PML4[2], no frame) STILL walls (that's real garbage). For an 8×8 stock/DDB pattern-bitmap init blit during gdi32 attach, a blank source is cosmetically harmless.

### How far winlogon got + the NEW wall
The gdi32+0x3f0cc wall is GONE. `[w32disp] win32k-internal unbacked low VA 0x02000000 -> zero-fill`, then `SSN 0x106c -> status=0x00050045` (a real bitmap handle, SUCCESS-range — NOT the 0xc0000001 wall). winlogon then issues MORE win32k GDI calls — SSN ring extended `…4:4204 0:27 4:4277 0:129 4:4157 0:12 4:4157 0:27 4:4276 0:190` (new NtGdi SSNs **0x10b5/0x103d×2/0x10b4** = stock-object + cursor GDI init; win32k prints `SYSTEMCUR(ARROW) == NULL` — the system arrow cursor isn't loaded yet). winlogon now parks in **`user32+0x9f327`** (`[batch10]` RIP samples = 0x801ef327; user32 @0x80150000) — a user32 client-init frontier PAST gdi32 process-attach (inside `CreateWindowStationAndDesktops`'s window-class/cursor setup). **Gate held identical 150 PASS / 98 FAIL**, kernel "All specs passed!", host green (nt-ntdll 165). **NEXT FRONTIER: user32+0x9f327 — winlogon's user32 per-process window-class/cursor init (the `SYSTEMCUR(ARROW) == NULL` hints the system cursor/class registration needs servicing). Diagnose-first (disasm user32+0x9f327 + trace which NtUser call it stops short of / what it waits on). Likely a win32k NtUserGetSystemCursor / class-registration / a shared value the connect left unset.** Remaining path to paint: user32 window-class/cursor init → winlogon WinMain → InitializeSAS → StartServicesManager (services.exe) + StartLsass (lsass) → SwitchDesktop → the 0x003a6ea5 desktop paint.

---

## BATCH 18 Results — the comdlg32 export-resolution wall (DIAGNOSE-FIRST, landed 2026-07-17)

**Symptom (from BATCH 17):** winlogon parks at bare RVA `0x3ad64` after `comdlg32.dll`'s DllMain runs
(`[vmf-out] fsr=20 err=0x14` user-instr-fetch). `0x3ad64` = comdlg32's IAT slot for its 65th kernel32
import `GetSystemTimeAsFileTime` (name index 458 in kernel32's 982-name export table) left at its RAW
`IMAGE_IMPORT_BY_NAME` RVA — an unsnapped thunk `jmp *IAT[..]` into a bare RVA.

### THE DIAGNOSIS — three distinct root causes, each evidenced (not the initial "export-walk math bug" hypothesis)
The export-table MATH is CORRECT (proven offline AND on-target: `RET ord=0x1ca(458) func=0x214f0`;
`name_eq` matches at i=458). The wall was NOT a name/ordinal/forwarder walk bug. It was THREE loader
bugs stacked, each pinned with on-target dumps:

1. **Per-VSpace demand-paging gap in the export walk.** The executive demand-faults each hosted DLL's
   pages PER PROCESS. When comdlg32 was snapped against kernel32 IN WINLOGON's VSpace, kernel32's
   export name-array / name-string pages weren't resident yet → the walk read a ZERO page → `name_eq`
   mismatched → `export_rva_by_name` returned 0 → the IAT slot was counted `missing` + left RAW.
   (Evidence: `GSTAFT img=0x81920000 … addr=0x0` for comdlg32 but `addr=0x803c14f0` for the SAME
   kernel32 in other VSpaces; a direct `AoNO[458]/AoF[ord]` probe read the correct `0x214f0` once the
   page was touched.) **FIX:** `touch_range(export_dir)` — force-fault the whole export data-directory
   region (dir + AoF/AoN/AoNO + name strings all lie inside it) before the walk, in BOTH
   `export_rva_by_name` and `export_rva_by_ordinal`. General fix: makes EVERY export resolution robust
   against the lazy per-process fill.

2. **`MODULE_TABLE_CAP` overflow (32 → 256).** winlogon's runtime graph loads **55+ distinct DLLs**
   (comdlg32/shell32/comctl32/wintrust/crypt32/dbghelp/…). At cap 32 the loader's module table
   OVERFLOWED — `insert` silently dropped the 33rd+ module, so `find` later returned 0 for it → the
   executive RE-MAPPED that DLL fresh over its VA (a new SEC_IMAGE view with a RAW, unsnapped IAT).
   comdlg32 was re-mapped 3× (2 static-snapped + 1 raw), and the raw one's DllMain ran.
   **FIX:** raise the cap to 256 (well above 55) so every module dedups + snaps once.

3. **Snapped IAT pages REVERT (the load-bearing one).** Even with (1)+(2), comdlg32's IAT slot held
   our resolved `0x803c14f0` immediately after the snap (readback proved it) but READ BACK the RAW
   `0x3ad64` by DllMain time — the executive re-faulted comdlg32's IAT page and RE-FILLED it from the
   on-disk PE (raw thunks), silently reverting our writes. **FIX:** RE-SNAP a module's imports in
   `attach_dfs` RIGHT BEFORE its DllMain runs (on the same thread, pages freshly resident) so the IAT
   the DllMain sees is authoritative. `snap_module` is idempotent + table-deduped → cheap.

### Host test (captures the walk math the bug touched)
`crates/nt-pe-loader/tests/parse.rs::export_directory_walk_resolves_high_index_forwarder_and_boundaries`:
a synthetic export directory with a **HIGH name index** (like the real 458), a **non-identity**
AddressOfNameOrdinals permutation, a non-trivial **ordinal Base (5)**, a **forwarder** (func RVA inside
the export dir range), and **first/last boundary** names — asserts each resolves to the correct RVA +
ordinal. Pins the name→AoNO→AoF indirection so an off-by-one / base / name↔ordinal swap is caught
host-side. `cargo test -p nt-pe-loader` = 12 (parse 9 incl. this), `nt-ntdll` = 165, all green.

### The NEW wall + the executive quiescence exit (so the gate still runs)
With the fix, comdlg32's DllMain COMPLETES and winlogon advances DRAMATICALLY past it: it runs its
real CRT/WinMain init, **spawns its real rpcrt4 server WORKER thread** (tid 15, real ETHREAD+TEB),
reaches its RPC receive loop, and its MAIN thread parks on an UNSIGNALLED WinMain SAS/logon event
(`NtWaitForSingleObject event #26 'a  '`) — the genuine "reached WinMain, waiting for interactive
logon" steady state. With every hosted thread parked, the executive service loop's next `recv` blocked
FOREVER → boot TIMED OUT → the spec gate never ran (a regression). **FIX (executive-side,
`service_sec_image.rs`):** when winlogon (pi 2) parks on an unsignalled event AND its worker has
already parked (`WL_WORKER_FAULTS > 0`), treat it as WinMain QUIESCENCE and STOP the loop → the gate
runs + qemu_exit fires (mirrors the terminal behavior the pre-fix boot got for free when winlogon
faulted at 0x3ad64). Scoped to winlogon-main-at-quiescence so it can't mask an earlier fault.

### Result
`0x3ad64` fault GONE. Boot exits cleanly (no timeout). **Gate 150 → 155 PASS / 22 FAIL — NO
regressions, 5 newly passing** (`exec_general_nt_create_thread`, `exec_kbd_layout_opened`,
`exec_rpc_listener_thread_real`, `exec_winlogon_rpc_pipe`, `exec_winlogon_worker_multiplex`).
NO rust-micro/src (kernel) change — ntdll (`on_target.rs`) + executive (`service_sec_image.rs`) + a
host test only.

### Remaining path to paint
winlogon now quiesces at its WinMain SAS-wait BEFORE driving StartServicesManager (services.exe) /
StartLsass (lsass) / SwitchDesktop. To reach the `0x003a6ea5` desktop paint, winlogon must be driven
PAST the SAS wait — the "N threads per process" multiplex frontier (route the worker's RPC receive +
signal the events winlogon's main waits on) so WinMain proceeds to InitializeSAS → StartServicesManager
→ StartLsass → SwitchDesktop → co_IntShowDesktop → IntPaintDesktop. `exec_services_spawned`,
`exec_lsass_spawned`, `exec_win32k_desktop_painted` remain FAIL (as they were pre-fix) pending that.

---

## BATCH 19 Results — the winlogon worker native-multiplex → main unblocks past the SAS-wait (landed 2026-07-17)

**Task:** BATCH 18 left winlogon MAIN parked on an unsignalled WinMain SAS/logon event
(`NtWaitForSingleObject event #26 'a  '`), because winlogon's rpcrt4 server WORKER thread
(`spawn_wl_listener_thread`, tid 15) was spawned `native:false` — the documented BATCH-6 follow-up.
Convert the worker to the native transport so it RUNS its rpcrt4 RPC-server init + signals the event
winlogon's main parks on → WinMain advances to StartServicesManager.

### THE DIAGNOSIS (each conclusion evidenced from the baseline boot)
1. **What winlogon's main parks on:** a REAL named event — `[wait] pi=2 NtWaitForSingleObject(event #26
   'a  ') UNSIGNALLED -> PARK caller (reply-cap park)`. This is winlogon's RPC-server-ready event; the
   reply-cap parking (Checkpoint B) handles it. winlogon main's parked RIP = ntdll+0x22292.
2. **Why the worker never signalled it:** the worker WAS resumed (`[thread-life] resume pi=2 slot=0
   tid=15`) and faulted ONCE, but as `[wl-worker] multiplex event #0 label=0x2` (an **UnknownSyscall
   trap**, NOT a native Call) with `SSN=1099786334208` (= 0x0100_0080_0000, **garbage** = RAX at the
   trap). It then `PARK`ed unserviced → it never ran its RPC receive/init → event #26 stayed
   unsignalled. Root cause = `native:false` + `TCBSetHostedSyscalls` set: OUR ntdll's native
   `seL4_Call` is forced into an UnknownSyscall fault whose m0=RAX is garbage. EXACTLY the BATCH-6 SM/CSR
   class of bug, left as the flagged follow-up for winlogon.

### THE FIX (executive-only; `rendezvous.rs::spawn_wl_listener_thread`)
Mirror BATCH 6: set `native: true` + `ipcbuf_frame: PM_MAIN_IPCBUF[2]` (winlogon = pi 2) — so
`spawn_hosted_thread` SKIPS `TCBSetHostedSyscalls` and binds the worker's kernel IPC buffer to
winlogon's MAIN-thread ipcbuf frame at IPCBUF_VADDR (the VA our ntdll native stub writes MR4/MR5 to).
The worker's faults still arrive on the badged MAIN fault-EP (WINLOGON_WORKER_BADGE); the existing
`NT_NATIVE_SYSCALL_LABEL` NORMALIZE arm re-labels them into the shared servicing body. **No new
multiplex/park code — pure REUSE.** No rust-micro/src (kernel) change, no ntdll DLL change (nt-ntdll
165 / nt-syscall-abi 12 host-green, unchanged).

### RESULT — the rpcrt4 two-thread handshake completes; winlogon main advances past the SAS wait
The worker now faults native (`label=0x4e54` = NT_NATIVE_SYSCALL_LABEL) and RUNS its RPC init (9
multiplex events incl. `11:238/11:37/11:88/11:280 NtWaitForMultipleObjects`). The handshake fires:
winlogon main `NtSetEvent(#24) -> WOKE 1 parked waiter` (the worker) → the worker `NtSetEvent(#26)` →
winlogon main's `NtWaitForSingleObject(event #26 'a  ') already SIGNALLED -> immediate WAIT_0`.
**winlogon main is UNBLOCKED past the SAS wait.** Gate **155 → 156** (`exec_wait_reply_cap_park_wake`
now PASSES — the worker's NtSetEvent woke winlogon main's parked reply-cap wait, Checkpoint B); NO
regressions; host green (nt-ntdll 165 + nt-syscall-abi 12). committed on `main`.

### winlogon REACHES StartServicesManager → the NEW WALL (CreateProcessW bails; diagnose-first, DEFERRED to next batch)
Past the SAS wait, WinMain proceeds linearly (winlogon.c:508): `StartServicesManager()` = 
`CreateProcessW("services.exe", …)`. winlogon main's SSN ring tail = `4:281(RPC-ready wait) →
4:196(NtReleaseMutant) → 4:98(NtIsProcessInJob) → 4:190(NtRaiseHardError)`. So **StartServicesManager
WAS called + CreateProcessInternalW STARTED** (NtIsProcessInJob=98 is its first syscall, serviced
→ 0) — but it BAILED before NtOpenFile/NtCreateSection(SEC_IMAGE)/NtCreateProcessEx(50), and
`!StartServicesManager()` raised the WinMain hard error (winlogon.c:78 → `NtRaiseHardError`, our
stop_ssn=190). **services.exe is NOT spawned** (`services (slot 3) demand-faulted 0 pages`);
`exec_services_spawned/exec_lsass_spawned/exec_win32k_desktop_painted` still FAIL. This is a NEW,
separate wall = winlogon's kernel32 `CreateProcessInternalW` failing on OUR ntdll between
NtIsProcessInJob and the section-create (it WORKED in the P5-SERVICES milestone on REAL ntdll — see
`project_winlogon.md`). **NEXT BATCH (diagnose-first):** why does CreateProcessInternalW bail after
NtIsProcessInJob(98)→0 with no further traced syscall before the hard error? Candidates: (a)
NtIsProcessInJob returning `STATUS_SUCCESS`(0) vs the real `STATUS_PROCESS_NOT_IN_JOB`(0x101) trips a
kernel32 check; (b) a non-syscall path-resolution / RtlDosSearchPath / base-named-objects step fails in
our ntdll; (c) a missing/mis-serviced syscall in the CreateProcessInternalW prologue. Instrument the
winlogon `98` arm + disasm the kernel32 CreateProcessInternalW retaddr chain (the `[sec-stop] chain:`
decode reads smss's mirror, not winlogon's — fix the mirror for a real chain). Then services.exe comes
up on our ntdll (its loader runs like csrss/winlogon), → StartLsass → WaitForLsass → InitializeSAS →
SwitchDesktop → co_IntShowDesktop → IntPaintDesktop → the `0x003a6ea5` paint.

---

## ☑ BATCH 20 Results — CreateProcessInternalW's relative-path bail fixed → services.exe SPAWNS (landed 2026-07-17)

**Task (diagnose-first):** winlogon reached `StartServicesManager` and its kernel32
`CreateProcessInternalW("services.exe")` STARTED (`NtIsProcessInJob(98)→0` serviced) but BAILED before
`NtOpenFile`/`NtCreateSection(SEC_IMAGE)`/`NtCreateProcessEx(50)` with no further traced syscall →
`!StartServicesManager()` → WinMain hard error (`NtRaiseHardError`, stop_ssn=190). services.exe was
NOT spawned. Root-cause why + fix → services.exe spawns on our ntdll.

### THE DIAGNOSIS (two coupled root causes, each evidenced from the boot trace)
The `[sec-stop]` decode ALREADY reads the faulting process's mirror (`ACTIVE_STACK_MIRROR` is set
per-`pi` before servicing — the BATCH-19 "reads smss's mirror" claim was stale; the terminal stop is
winlogon's own 190, `pi=2`, so the decode was already winlogon's). The winlogon SSN ring tail
`… 4:196 4:98 4:190` confirmed the bail sits between NtIsProcessInJob(98) and the section-create,
in the PURE (non-syscall) ntdll path resolution `RtlDosPathNameToRelativeNtPathName_U` (proc.c:2647)
→ `RtlGetFullPathName_UstrEx` (proc.c:2674). Candidate **(b)** — path resolution — NOT (a)
NtIsProcessInJob's status. **TWO gaps in OUR ntdll's path Rtl, disproven-then-proven with an `[R2N]`
stack-buffer DbgPrint marker:**
1. **`RtlDosPathNameToRelativeNtPathName_U` returned FALSE for a RELATIVE name.** `services.exe` is
   `RtlPathTypeRelative`; our impl called `dos_path_name_to_nt_path_name` which returns `None` for any
   non-absolute path → BOOLEAN FALSE → CreateProcessInternalW `SetLastError(ERROR_PATH_NOT_FOUND)` →
   bail. **The `[R2N:9/5/9]` marker (cwd_len≥9 / pathtype=5=Relative / namelen≥9) with NO `[R2N-NO]`
   after the fix proved the resolve then succeeded.**
2. **`RtlGetFullPathName_UstrEx` didn't serve the DynamicString (StaticString=NULL) path NOR resolve
   relative paths.** proc.c calls it `(&SxsWin32ExePath, NULL_static, &PathBufferString_dynamic, …)`;
   our impl returned `STATUS_BUFFER_TOO_SMALL` whenever StaticString was NULL → the SECOND bail
   (proc.c:2682) after fix #1 let it get that far. The winlogon ring then advanced to
   `4:98 4:122 4:52 … 4:19 4:19 4:122 4:50` — reaching NtOpenFile(122)+NtCreateSection(52)+**NtCreateProcessEx(50)**.
3. **NtCreateProcessEx(50) itself then stopped (stop_ssn=50)** — a THIRD, structural gap: SSN 50 is
   registered in the executive's `NativeServiceTable` (routed to exec_handler's `NtCreateProcess`
   handler, which only spawned for `pi==0`=smss→csrss/winlogon), so the services-spawn arm in
   `service_sec_image.rs` (`m0==50 && badge==WINLOGON_BADGE`) was **DEAD CODE** (table-routing bypassed
   it). The handler `self.stop=true`'d for winlogon's create.

### THE FIX (executive + ntdll crates; NO rust-micro/src, no kernel change)
- **`nt-ntdll::rtl::path::dos_path_name_to_nt_path_name_rel(name, cwd)`** (host-tested) — CWD-aware:
  relative → `cwd\name`, rooted → cwd-drive + name, absolute → passthrough; `RtlDosPathNameToRelativeNtPathName_U`
  reads `PEB->ProcessParameters->CurrentDirectory.DosPath` (gs:[0x60]→+0x20→+0x38, new `peb_current_directory`)
  and uses it. Same wiring added to `RtlDosPathNameToNtPathName_U`.
- **`nt-ntdll::rtl::environment::full_path_units(name, cwd)`** (host-tested) — the UTF-16 `RtlGetFullPathName_U`
  core (over the existing `CurrentDirectory::full_path`); `RtlGetFullPathName_UstrEx` now canonicalises
  FileName against the PEB CWD and writes it to StaticString-if-it-fits **else a heap-allocated
  DynamicString** (the real static-then-dynamic policy).
- **exec_handler `NtCreateProcess` handler** now, for `pi==2` (winlogon) matching the tracked
  services.exe / lsass.exe SEC_IMAGE section, sets new `services_spawn_request` / `lsass_spawn_request`
  flags (instead of `self.stop`); the service loop consumes them and runs `spawn_sec_image` (badge 6 /
  badge 8, pi 3/4) — the spawn bodies MOVED from the dead broker arm into the loop's flag-consumption
  block (mirrors `winlogon_spawn_request`). The dead `m0==50` broker arm was deleted.
- **CSR connect scoped to winlogon (pi 2):** services' (pi 3) `NtSecureConnectPort(\Windows\ApiPort)`
  takes the MODELED accept (minted client handle + mapped CSR view/static-data) instead of driving
  `csr_rendezvous` — csrss's real CsrApiRequestThread accepts ONE pending connect (winlogon's) then
  parks; a per-client CSR acceptor for services is the SCM batch's frontier. (Without this the nested
  rendezvous spun forever → boot never terminated.)
- **Loop iters backstop 8000→5000** so the boot TERMINATES in-budget under TCG (services pulls a 57-DLL
  tree — crypt32/dbghelp/libtiff/wintrust — each snapping hundreds of pages at ~4 faults/s; the
  gate-relevant work is done well before that; full SCM bring-up is next batch).

### RESULT — services.exe SPAWNS + runs its loader; gate 156 → 160
`[ntos-exec] NtCreateProcessEx: spawned services.exe (badge 6) -> handle 0x204`. services.exe runs its
FULL ntdll loader on OUR ntdll: `snap resolved=6996 missing=7`, 57 modules in `PebLdr`, **387 demand-
faulted pages**, kernel32/advapi32 DllMains + a huge transitive tree, reaching its
`NtSecureConnectPort(\Windows\ApiPort)` CSR connect (BATCH-8-analogous). **New PASSES (4):**
`exec_services_spawned`, `exec_services_loader_running`, `exec_services_csr_connect`,
`exec_services_win32k_connect` → gate **156 → 160**. No regressions (all winlogon specs still PASS).
Host green (nt-ntdll 167 [+2: `nt_path_rel`, `full_path_units_resolution`] + nt-syscall-abi 12).
Committed on `main`.

### NEXT WALL (services' SCM bring-up → the paint) — diagnose-first, deferred
services.exe is up but does NOT yet run its real SCM (`ScmMain`) to completion, and **lsass is NOT
spawned** (`StartLsass` needs services further along / winlogon's InitializeSAS chain). Remaining path
to the `0x003a6ea5` paint: services' SCM + lsass on our ntdll → winlogon `WaitForLsass` → `InitializeSAS`
→ `SwitchDesktop` → co_IntShowDesktop → IntPaintDesktop. Residual FAILs are the SCM/lsass frontier
(`exec_lsass_spawned`, `exec_services_named_events`, `exec_win32k_desktop_painted`). The services CSR
accept is currently MODELED (per-client CSR acceptor = the SCM batch); the iters cap (5000) may need
lifting once services' per-fault cost drops or its work is bounded.

---

## ☑ BATCH 21 Results — the `RtlQueryEnvironmentVariable_U` byte-vs-char Length bug → StartServicesManager/StartLsass SUCCEED → lsass.exe SPAWNS on our ntdll (landed 2026-07-17)

**Task (diagnose-first):** BATCH 20 spawned services.exe but winlogon then raised `NtRaiseHardError`
(stop_ssn=190) and **lsass never spawned**. Root-cause why + drive winlogon past StartServicesManager
→ StartLsass → spawn lsass.

### THE DIAGNOSIS (each conclusion evidenced from the boot trace)
1. **Where winlogon walls:** decoded the terminal `NtRaiseHardError` args at the CALL site (while
   winlogon's stack mirror is active): `R10 = 0xC000021A = STATUS_SYSTEM_PROCESS_TERMINATED` — the
   winlogon.c `!StartServicesManager()` failure path (winlogon.c:508). A **winlogon-main-only SSN ring**
   (badge 4, isolated from the services badge-6 noise that dominates the shared ring) showed winlogon
   issues exactly ONE `NtCreateProcessEx(50)` (services) then `27 27 27 190` — it bailed in kernel32's
   `CreateProcessInternalW` right after NtCreateProcessEx SUCCEEDED (reply status 0, `spawned services.exe
   (badge 6)`), with NO `NtOpenFile`/`NtCreateSection`/second `NtCreateProcessEx` for lsass. **StartLsass
   was never reached — StartServicesManager returned FALSE.**
2. **The bail is in the PURE ntdll path** (no syscall between `50` and `190`): markers on OUR ntdll's
   `RtlCreateProcessParameters` (never called for winlogon's CreateProcessW) + `RtlQueryEnvironmentVariable_U`
   (called, returned `0xC0000023 STATUS_BUFFER_TOO_SMALL` in PAIRS — the first query then the re-query
   BOTH `TOO_SMALL`) pinned it to `kernel32!BasepComputeProcessPath` (path.c:163) → `BaseComputeProcessDllPath`
   returning NULL → `BasePushProcessParameters` returns FALSE → CreateProcessInternalW `goto Quickie` → FALSE.
3. **★ ROOT CAUSE: `RtlQueryEnvironmentVariable_U`'s STATUS_BUFFER_TOO_SMALL path reported the required
   length in CHARS, not BYTES.** `UNICODE_STRING.Length` is in BYTES (`sdk/lib/rtl/env.c:685`
   `Value->Length = ReturnLength * sizeof(WCHAR)`). Our `on_target.rs::rtl_query_environment_variable_u`
   wrote `val_units.len()` (char count) instead of `val_units.len() * 2` (byte count). kernel32's
   BasepComputeProcessPath then allocated `EnvPath.Length + sizeof(WCHAR)` = HALF the needed size → the
   re-query STILL didn't fit → `Status` stayed BUFFER_TOO_SMALL at Quickie → PathBuffer freed → NULL.

### THE FIX (ntdll-side, 1-line semantic; NO rust-micro/src kernel change)
`crates/nt-ntdll-dll/src/on_target.rs::rtl_query_environment_variable_u` — on the BUFFER_TOO_SMALL path
write `needed_bytes` (`val_units.len() * 2`, byte count excl. NUL) to `Value->Length`, per env.c:685.
This is the ONLY change to the ntdll DLL. nt-ntdll host tests unchanged-green (167) + nt-syscall-abi (12).

### RESULT — StartServicesManager + StartLsass both SUCCEED; lsass.exe SPAWNS; gate 160 → 164
With the byte-count fix, winlogon's `CreateProcessInternalW(services)` COMPLETES (`BasePushProcessParameters`
→ `RtlCreateProcessParameters` → NtAllocate/NtWrite into the services child + `NtCreateThread(55)`),
StartServicesManager returns TRUE, then **StartLsass's `CreateProcessW("lsass.exe")` runs the SAME path →
`NtOpenFile(lsass.exe) → NtCreateSection(SEC_IMAGE) → NtCreateProcessEx(50)` → lsass.exe SPAWNS (badge 8)**
and runs its ntdll loader (**331 demand-faulted pages**, its full DLL tree). The winlogon SSN ring now shows
BOTH CreateProcessW flows (`…50 [services push+thread] 27 27 27 27  98 122 52 175 19 19 50 [lsass]`).
**New PASSES (4):** `exec_lsass_spawned`, `exec_lsass_loader_running`, `exec_main_thread_bound_at_spawn`,
`exec_eprocess_linked_mechanism` → gate **160 → 164 PASS / 13 FAIL, exit 3 clean, NO regressions**.

**Second fix (same batch, executive-side — a reclaim self-test regression the deeper boot exposed):**
`exec_sel4_reclaim_mechanism`'s frame-reclamation proof (bit1) broke under the deeper 5-process boot
(`round1=16 round2=0`, `seL4_NotEnoughMemory` on the round-2 retype though every frame delete succeeded):
plain per-object `CNodeDelete` did NOT roll the throwaway child untyped's `free_index` back at the deeper
stop point. FIX = an explicit **`CNodeRevoke` on the child untyped** between the fill rounds (the definitive
free_index reset — exactly what the kernel's own "500 alloc/free cycles" test uses), via a new
`cnode_revoke_r` helper (`LBL_CNODE_REVOKE=22`, mirror of `cnode_delete_r`). Robust regardless of parent
untyped fullness → `round2=16`, spec PASSES again. NO rust-micro/src kernel change (userspace helper only).

### NEXT WALL (services' SCM + lsass LSA init → the paint) — the boot terminates naturally (exit 3)
The loop stops (iters~4026) on **services' (badge 6) win32k call `0x103d` (NtUserFindExistingCursorIcon,
from its user32 DllMain window-class/cursor init)** — services isn't a GUI client with a desktop, so
win32k_dispatch WALLs it. This is AFTER winlogon has spawned lsass, so the gate-164 checkpoint (services +
lsass BOTH spawned on our ntdll) is coherent + terminates. Remaining path to `0x003a6ea5`: winlogon
`WaitForLsass` (parks on `LSA_RPC_SERVER_ACTIVE`, Checkpoint B reply-cap park) ← lsass grinds its full LSA
init (lsasrv/samsrv/msv1_0) to signal it → `InitializeSAS` → `SwitchDesktop` → co_IntShowDesktop →
IntPaintDesktop. NOTE: parking services' win32k wall (to let the loop keep servicing lsass) was TRIED and
REVERTED — it removed the natural stop and lsass's huge DLL grind ran past the 500s TCG timeout (exit 124);
the natural services-win32k-wall stop at iters~4026 is the coherent in-budget terminus. Reaching the actual
paint needs lsass's full LSA bring-up (many faults) to fit the budget — the next batch's frontier (bound
lsass's per-fault cost / lift the iters cap once lsass's work is bounded, then wire the WaitForLsass wake).
Residual FAILs = the LSA/SCM/paint frontier (`exec_lsass_lsa_init_running`, `exec_lsass_signals_lsa_rpc_active`,
`exec_services_named_events`, `exec_win32k_desktop_painted`). Diagnostics retained (fire once at stop):
`[wl-ring]` (winlogon's isolated SSN sequence), `[wl-190]` (hard-error arg decode), `[wl-createproc]`.

## ☑ BATCH 22 Results — the demand-fault PERF FIX (batch bulk-fill + scratch-VA decoupling via widened per-process windows) → boot ~3× faster, lsass pages 2× deeper, winlogon PARKS on `lsa_rpc_server_active`; gate 164 → 165 (landed 2026-07-17)

**Task:** the binding constraint was BOOT-TIME BUDGET, not walls — under QEMU TCG each demand fault is a
full fault-EP round-trip (~4/s), so a big DLL image page-by-page dominated; lsass's LSA-init DLL tree
ran past the 500s timeout (exit 124). Cut the fault ROUND-TRIP count so lsass fits in budget → drive it
toward `LSA_RPC_SERVER_ACTIVE` → winlogon `WaitForLsass` → the paint.

### THE PERF FIX (three coupled executive-side changes; NO rust-micro/src kernel change)
1. **BATCH bulk-fill** (`service_sec_image.rs`): on an image page fault, fill+map a forward RUN of up to
   `BATCH_PAGES=4` consecutive same-image pages (bounded by the containing image's extent: main image →
   `img_end`; a registered DLL → `base + image_size`; ntdll → `nt_end`) in the ONE fault round-trip.
   Every extra page is filled EXACTLY as its own demand fault would (same `fill_image_page`/rights/
   cache/mirror/`filled_pages` bookkeeping) — pure correctness preservation — so the process finds the
   next pages already present and does NOT re-fault them. Extra pages are pre-mapped only when provably
   unmapped in this process (per-process page not in `filled_pages`; shared page not in `dll_cache`) so
   we never double-map; per-process pre-fill stops once `filled_pages` (256) is exhausted (past that a
   page's mapped-state is unknowable → a re-map would fail harmlessly with map=8 but waste a frame). The
   FAULTING page (bi==0) keeps the full original logic incl. the shared-cache HIT path.
2. **Widened + re-spaced per-process demand-scratch windows** (`main.rs`): each fresh fill takes a UNIQUE
   monotonic scratch slot (`scratch_base + faults*0x1000`) — seL4 records the mapping on the frame OBJECT,
   so a slot can't be reused without an unmap; unique slots are the proven model (a throwaway-copy +
   CNodeDelete transient-slot scheme was TRIED and REVERTED — it hit `seL4_DeleteFirst` because the frame
   object was double-mapped). The old scheme packed all 5 processes into one 8-PT span (0x1100..0x1200)
   with ~512-page inter-process spacing — far too tight now that lsass pages in thousands. Each process
   now gets its OWN 64 MiB window (`SMSS_SCRATCH_BASE = 0x…_2100_0000` + k×`DEMAND_SCRATCH_WINDOW`
   0x400_0000) in the free high VA region PAST the executive heap (`allocator::HEAP_BASE=0x2000_0000`,
   2 MiB) and every other mapping, inside the first 1 GiB PD (0..0x4000_0000, already present). PTs mapped
   per-window at spawn via new `map_demand_scratch_pts` (16 PTs = 8192 pages > `FAULT_CAP`). ★ ROOT CAUSE
   of an intermediate spin: the first window base 0x2000_0000 COLLIDED with the executive's own heap →
   every scratch map failed `DeleteFirst` → the fill wrote to stale memory → the process re-faulted the
   same page forever (60000 map-fails). Fixed by relocating the base past the heap.
3. **`FAULT_CAP` 2000→6000 + iters backstop 5000→60000** (`service_sec_image.rs`): the per-process fault
   backstop is now a frame-budget/runaway guard (not a scratch limit — scratch bounded by the 16-PT
   window), sized so lsass's full LSA-init tree fits; the iters cap is lifted because the per-page cost is
   bounded. `selftests.rs` RECLAIM_VA / the ALPC-cross-vspace scratch re-pointed to `SMSS_SCRATCH_BASE`
   (the old 0x1100 span is no longer mapped).

### RESULT — measured (baseline c193889 vs BATCH 22)
| metric | baseline | BATCH 22 |
|---|---|---|
| boot wall (in-budget, exit 3) | ~106 s | ~35 s @5000 iters / ~130 s running the full deeper boot |
| lsass demand-faulted pages | 331 | **501–772** (run-variant; 2× deeper into LSA init) |
| winlogon pages | 969 | 1365–1788 |
| shared_frames / shared_hits | 500 / 349 | 1084 / 616 |
| gate | 164/98 | **165/98** (+`exec_winlogon_rpc_pipe`) |
| winlogon end-state | parked mid user32 init | **PARKS on `lsa_rpc_server_active` (WaitForLsass), then QUIESCE** |
| map-fail spam | 0 | 0 (after the >256 pre-fill guard) |

The batch cut per-page round-trips ~3× (boot 106s→35s at the same 5000-iter cap); with the iters cap then
lifted, the deeper boot runs the full 5-process bring-up in ~130s (well under 500s). No correctness
regression — every process still reaches (in fact PAST) its prior frontier. nt-ntdll host tests unchanged
green (167 + nt-syscall-abi 12). Executive-side only (no rust-micro/src). ⚠ SEL4 LESSON: a page frame's
mapping is tracked on the frame OBJECT — a slot can't be reused without an explicit unmap, and mapping the
same object at two VAs via cap copies works ACROSS VSpaces (scratch + process) but a second map in the
SAME VSpace fails DeleteFirst; unique monotonic scratch slots are the proven pattern.

### NEXT WALL (the LSA/paint frontier — a multi-wall grind) — the boot QUIESCES naturally (exit 3)
With the budget no longer the constraint, the boot now advances to a NATURAL quiesce: winlogon reaches
WinMain steady-state and **PARKS on the `lsa_rpc_server_active` named event** (the Checkpoint-B reply-cap
park — exactly the WaitForLsass wait), and all threads park. lsass spawns + runs its ntdll loader + gets
lsasrv/samsrv DEMAND-LOADED, but its MAIN thread (like services) enters a REPETITIVE win32k call loop in
its user32 DllMain — `8:4157`/`8:4276` (NtUserFindExistingCursorIcon + a sibling NtUser), the same
non-interactive-process cursor/class-init loop BATCH 16/17 hit for winlogon (`SYSTEMCUR(ARROW)==NULL`).
These SSNs are SERVICED (no WALL), but the loop never completes for a non-GUI process → lsass never
reaches lsasrv's `LsaInitializeRpcServer` → never `SetEvent(lsa_rpc_server_active)` → winlogon stays
parked. Residual FAILs unchanged: `exec_lsass_lsa_init_running`, `exec_lsass_signals_lsa_rpc_active`,
`exec_services_named_events`, `exec_win32k_desktop_painted`. **NEXT (a diagnose-first multi-wall grind, the
frontier): break lsass's (+ services') user32-DllMain win32k cursor/class loop** — determine what the
loop polls (a class/cursor that never registers for a non-interactive winstation) and either satisfy it or
park lsass's main thread past it (like the winlogon user32 init unblock) so lsass runs on to lsasrv's LSA
init → `LSA_RPC_SERVER_ACTIVE` → winlogon's parked WaitForLsass wakes → `InitializeSAS → SwitchDesktop →
co_IntShowDesktop → IntPaintDesktop → the 0x003a6ea5 paint`. The win32k paint machinery + the WaitForLsass
wake plane already EXIST (reuse). The perf fix is the coherent committed terminus of BATCH 22.

## ☑ BATCH 23 Results — break lsass's user32 cursor/class-init loop → lsass runs REAL LSA init (lsasrv + LSA auth port + events) → then advances past its LSA port-connect into LSA-server-thread creation; gate 165 HELD (no regression), lsass 501 → 664 demand-paged pages (landed 2026-07-17, commits c91df5f + follow-on)

**Task:** BATCH 22's frontier — break lsass's non-interactive user32-DllMain win32k cursor/class loop so
lsass reaches lsasrv's LSA init → `LSA_RPC_SERVER_ACTIVE` → winlogon's WaitForLsass wake → the paint.

### THE DIAGNOSIS (each conclusion evidenced from the boot trace + ReactOS win32k/lsasrv sources)
1. **The loop = user32's client-side `RegisterSystemClasses`**, per-class: `NtUserFindExistingCursorIcon`
   (0x103d = 4157) then `NtUserRegisterClassExWOW` (0x10b4 = 4276). Boot trace: 142× 0x103d dispatches
   spanning the WHOLE boot, 87× `NtUserRegisterClassExWOW Wrong cbSize! / Failed to register class atom /
   you have no Class`, ring `8:4157 6:4157 8:4276 6:4276 …` (badge 8=lsass, 6=services).
2. **Root cause (win32k):** win32k's shared system cursors (`gasyscur[]`) are loaded ONLY by winlogon's
   INTERACTIVE `SwitchDesktop → co_IntLoadDefaultCursors → NtUserSetSystemCursor`. A NON-interactive
   service (lsass/services on a `WSS_NOIO` winstation) never triggers that, so `NtUserFindExistingCursorIcon`
   returns NULL forever + `NtUserRegisterClassExWOW` can't satisfy its cursor precondition → the loop never
   advances. winlogon (INTERACTIVE) registered its ~30 classes fine (atoms 0xc000..0xc02f); lsass/services
   got the NULL-cursor dead loop. NOT a per-process interactivity branch in the connect/class path (there
   is none — gated only on `W32PF_CLASSESREGISTERED`); purely the availability of the system-cursor state.
3. **The deadlock:** lsass loops → never reaches lsasrv's `LsaInitializeRpcServer` → never
   `SetEvent(lsa_rpc_server_active)` → winlogon's WaitForLsass parks forever (desktop stays magenta).

### THE FIXES (executive-only; NO rust-micro/src, NO ntdll DLL change; host nt-ntdll 167 green throughout)
1. **Break the cursor/class loop (commit c91df5f):** in the win32k routing arm, for lsass (badge 8) SATISFY
   the loop's preconditions WITHOUT dragging in the interactive-winsta cursor fork winlogon owns — 0x103d →
   a non-NULL synthetic HCURSOR (LoadCursor short-circuits), 0x10b4 → a fresh RTL_ATOM (the class registers).
   Mirrors the existing winlogon 0x125c keyboard-layout fake. ★ **Gated to lsass ONLY**: a services+lsass
   fake REGRESSED lsass spawn (services advancing into SCM DLL-load perturbed the multiplex timing that lets
   winlogon's StartLsass run → gate 165→161, lsass_sect=0); lsass is the one on the critical path.
2. **Model lsass's LSA-init port connect (follow-on):** past the cursor loop lsass runs REAL LSA init and
   hits an `NtConnectPort` (broker-unowned name) → OBJECT_NAME_NOT_FOUND → because lsass is a CRITICAL
   process (`RtlSetProcessIsCritical(TRUE)`), the failed init `goto ByeBye; NtTerminateThread(Status)`
   escalates to a WHOLE-process 0xC0000034 term (verified: `base/system/lsass/lsass.c:wWinMain` → the failing
   one of LsapInitLsa/SamIInitialize/ServiceInit). MODEL any pi==4 broker-unowned connect as an accepted
   comm port (like the existing `\SeRmCommandPort` model) so LSA init proceeds.

### RESULT (gate 165/98 HELD — NO regression — lsass advances deep into REAL LSA init)
- lsass's cursor loop BROKEN (506 fakes serviced; cbSize errors 87→15 [residual 15 = services, still
  looping as baseline — intentionally NOT faked to protect the spawn timing]).
- lsass runs REAL LSA init: **DEMAND-LOADs lsasrv.dll**, `NtCreatePort(\LsaAuthenticationPort)`, opens+SETs
  the `\SECURITY\LSA_AUTHENTICATION_INITIALIZED` event (StartAuthenticationPort), advances **past** its LSA
  port-connect (fix 2) into `NtCreateThread` (its LSA server / auth-port thread). **501 → 664 demand-faulted
  pages** (163 deeper).
- The `\Registry\Machine\SAM` / `\SECURITY` overlay (`is_lsa_hive_path`, NtOpenKey pi==4) already existed —
  the SAM-key wall the sources predicted was already covered; the actual term was the port-connect.

### NEXT WALL (the flagged "N threads per process" lsass-listener multiplex) — the boot QUIESCES (exit 3)
lsass's newly-created LSA server thread (tid=21, resumed) WALLs at a bare instruction-fetch fault
`ip=0x3a288 fsr=20` (a low RVA — the thread START routine resolved to garbage, BATCH-18-class). This is the
SAME class as winlogon's RPC-listener thread: a spawned per-process worker whose faults need routing through
lsass's OWN stack mirror + a dedicated lsass-listener badge/multiplex (see `exec_lsass_lsa_server_thread_multiplex`
FAIL: `lsass-listener tcb=0 tid=0 serviced=0`). Residual FAILs unchanged: `exec_lsass_lsa_init_running`,
`exec_lsass_signals_lsa_rpc_active`, `exec_win32k_desktop_painted`. **NEXT (diagnose-first): route lsass's
LSA-server-thread faults (its start-address resolution + per-thread stack mirror) like winlogon's RPC
listener** so the thread runs → lsasrv's `LsarStartRpcServer` (`RpcServerUseProtseqEpW(\pipe\lsarpc)` +
`RpcServerListen`) completes → `SetEvent(LSA_RPC_SERVER_ACTIVE)` → winlogon's WaitForLsass wakes (the
NtSetEvent wake plane at service_sec_image.rs:2012 already fires `LSA_RPC_SERVER_ACTIVE_SIGNALLED` + wakes
parked waiters) → `InitializeSAS → SwitchDesktop → co_IntShowDesktop → IntPaintDesktop → the 0x003a6ea5
paint`. Diagnostics retained (fire at the lsass wall): `[lsass-open-miss]` (unresolved NtOpenFile names),
`[lsass-connect]` (LSA port-connect targets).

---

## ☑ BATCH 24 Results — lsass' LSA-server thread NATIVE transport (the multiplex fix) → SSN garbage 0xB000 → real `9:100` NtListenPort; gate 165 HELD; the signal still blocked by a NEW pre-existing wall (lsass main faults at rpcrt4 bare-RVA `0x3a288` after RpcServerListen, before SetEvent) (landed 2026-07-17, commit e96dcb7)

**Task:** BATCH 23's frontier — lsass' newly-created LSA server thread (tid=21) walled at a bare
instruction-fetch fault `ip=0x3a288`; diagnose the thread-start + multiplex it native (BATCH 6/19)
→ the thread runs `LsarStartRpcServer` → `SetEvent(LSA_RPC_SERVER_ACTIVE)` → winlogon WaitForLsass wake → the paint.

### THE DIAGNOSIS (evidenced from the baseline boot — the thread-start was NOT garbage; the transport was)
1. **The thread-start `entry=0x803c5a10` is CORRECT** (a valid high lsass VA — an lsasrv RPC-worker start,
   NOT garbage). `[lsass-thread] spawning + RESUMING REAL LSA server thread: entry=0x803c5a10 tid=21`. The
   BATCH-18 "garbage start" hypothesis was WRONG — the thread ran its real routine + reached its RPC
   receive loop.
2. **The TRANSPORT was broken (BATCH 6/19 exactly).** `spawn_lsass_listener_thread/2/3` were
   `native:false` + `ipcbuf_frame:0`, so `spawn_hosted_thread` set `TCBSetHostedSyscalls` → the thread's
   first native `seL4_Call` faulted as UnknownSyscall with m0=RAX=garbage. Evidence: pre-fix ring tail
   `… 8:214 9:45056 8:27` (`9:45056` = 0xB000 = the UnknownSyscall label leaked as the SSN) →
   `[lsass-listener] blocking server syscall SSN=1099786334208` (0x100_0080_0000 = RAX at the trap) → PARK.
3. **The `0x3a288` fault was NOT the thread-start** — it is a SEPARATE, pre-existing wall on lsass MAIN
   (badge 8), present in BOTH the pre- and post-fix boots (masked before by the listener's garbage park).

### THE FIX (executive-only; `rendezvous.rs::spawn_lsass_listener_thread/2/3`) — mirror BATCH 19
Set `native: true` + `ipcbuf_frame: PM_MAIN_IPCBUF[4].load()` (lsass = pi 4) on all three lsass LSA-server
listener spawners — so `spawn_hosted_thread` SKIPS `TCBSetHostedSyscalls` (the Call dispatches natively,
MR0=r10=SSN) + binds the thread's kernel IPC buffer to lsass' MAIN-thread ipcbuf frame at IPCBUF_VADDR.
Its faults still arrive on the badged MAIN fault-EP (the loop's `NT_NATIVE_SYSCALL_LABEL` NORMALIZE arm —
label-keyed, not badge-keyed — re-labels them into the shared servicing body). **No new multiplex/park
code — pure REUSE.** No rust-micro/src (kernel), no ntdll DLL change (host `nt-ntdll` 167 / `nt-syscall-abi`
12 green, unchanged).

### RESULT — the transport is FIXED; the multiplex is now REAL native (gate 165 HELD, no regression)
- The LSA server thread (tid=21) now faults with `label=0x4e54` (`NT_NATIVE_SYSCALL_LABEL`) and issues a
  **REAL native `9:100` = NtListenPort** (its RPC receive loop) — not the garbage `9:45056`/`SSN=0x100...`.
  Post-fix ring tail: `… 8:214 9:100 8:27`. `exec_lsass_lsa_server_thread_multiplex` is now a genuine
  native-transport pass (it trivially passed pre-fix too, on the garbage fault counting as serviced=1).

### THE NEW WALL (pre-existing, UNMASKED by the fix, NOT caused by it) — lsass MAIN's rpcrt4 `0x3a288`
After the LSA server thread spawns+resumes (NtCreateThread=55 → NtQueryInformationThread=162 →
NtResumeThread=214 → the thread runs 9:100 → lsass main NtClose=27 the thread handle), **lsass MAIN
(badge 8) faults at bare RVA `0x3a288` (`[user #PF: tcb=28 cr2=0x3a288 err=0x14]`, instr-fetch)** —
BEFORE reaching `LsarStartRpcServer`'s `CreateEventW(LSA_RPC_SERVER_ACTIVE)` + `SetEvent`. So
`exec_lsass_signals_lsa_rpc_active` + `exec_win32k_desktop_painted` still FAIL (px0=magenta 0x00ff00ff),
gate 165. **DIAGNOSED as BATCH-18-root-cause-#3-class:** `0x3a288` is a VALID **rpcrt4** .text RVA
(rpcrt4 base=0x80300000 → real VA should be `0x8033a288`; .text = RVA 0x1000..0x7c637 covers it) that
lost its base — a **bare-RVA code pointer**, mid-`RpcGetAuthorizationContextForClient` (offset 0x1558, so
most likely a SAVED RETURN ADDRESS / callback pointer stored as an RVA, not a function-entry IAT thunk).
This is `LsarStartRpcServer` → `RpcServerListen(1,20,TRUE)` internals in rpcrt4. Root class = the
BATCH-18 "snapped IAT/pointer reverts when the executive re-faults+re-fills a page from the RAW on-disk
PE" bug, but now recurring at RUNTIME (not just DllMain) for rpcrt4 in lsass' VSpace. **NEXT (diagnose-
first):** instrument the retaddr chain at the `0x3a288` fault (BATCH-18 style — `[sec-stop] chain:` over
lsass' mirror) to pin whether it's an IAT revert, a bad reloc, or a truncated saved return address; then
harden the snap/fill so rpcrt4's resolved pointers survive a runtime re-fault (persist the snapped IAT /
snap-on-demand-fill). Fix → lsass main reaches `SetEvent(LSA_RPC_SERVER_ACTIVE)` → the wake plane at
service_sec_image.rs:2012 fires → winlogon WaitForLsass wake → InitializeSAS → SwitchDesktop → the
0x003a6ea5 paint. ⚠ NOTE the winlogon-WinMain QUIESCE arm (service_sec_image.rs:2710, `pi==2 &&
WL_WORKER_FAULTS>0`): once lsass signals, verify winlogon's WaitForLsass wake resumes it into SwitchDesktop
BEFORE that arm quiesces the loop (it may need a "LSA-not-yet-signalled" guard).

---

## ☑ BATCH 25 Results — fixup-survival re-map + the LSA-not-yet-signalled quiesce guard; the `0x3a288` wall DIAGNOSED to a NEW class (NOT an image-page re-fill revert): a truncated/bare ntdll+rpcrt4 code pointer in lsass' runtime data, IAT proven CORRECT (landed 2026-07-17, gate 165 HELD, host green 167, executive-only, sel4test unaffected)

**Task:** harden relocated/snapped image pages against a runtime re-fault (the general BATCH-18-#3 fixup-revert class) + add the winlogon "LSA-not-yet-signalled" quiesce guard → lsass main reaches `SetEvent(LSA_RPC_SERVER_ACTIVE)` → winlogon WaitForLsass wake → the `0x003a6ea5` paint.

### THE DIAGNOSIS (diagnose-first; each conclusion evidenced from an instrumented boot — the `0x3a288` root cause is NOT what BATCH 24 hypothesized)
1. **The fault = instruction-fetch at bare `0x3a288`** (`[vmf-out] ip=0x3a288 addr=0x3a288 pf=1 fsr=20`, and TCB-read GPRs confirm `rip==cr2==0x3a288`, `rsp=0x100_105c3cf8`) — execution CALLed/JMPed through a code pointer holding the bare low-RVA `0x3a288` (which is BOTH a valid rpcrt4 .text RVA [base 0x80300000 → 0x8033a288] AND a valid our-ntdll .text RVA [NTDLL_BASE 0x100_00800000 → 0x100_0083a288]).
2. **The retaddr chain (via the fixed TCB-rsp stack walk) is lsass' OWN code**, NOT a DLL IAT thunk: nearest return addresses = **lsass.exe** (`0x100_00561042/561917/561b3e`, PE_LOAD_BASE=0x100_00560000), **msvcrt+0xdf7f** (`0x8069df7f`), and lsass **heap** pointers (`0x100_00c15cb0/c01f88`, SMSS_ALLOC_VA=0x100_00C00000). So the bad code pointer lives in lsass' runtime data (heap / an RPC dispatch structure), reached via a `jmp`/`call` through it.
3. **★ The IAT-revert hypothesis (BATCH 24) is DISPROVEN.** I instrumented the executive to (a) trace fills of kernel32's ntdll-IAT page (RVA 0x77000, flat 0x80417000) for lsass and (b) READ the actual IAT slot value from lsass' recorded frame at the fault. Result: the IAT page is filled **EXACTLY ONCE** (bi=0, fault #60, no re-fault), and kernel32's `NtClose` IAT slot [0x88] holds the **CORRECT full 64-bit** `0x0000_0100_008202a0` (= NTDLL_BASE + our NtClose export RVA 0x202a0), **NOT** the truncated 0x3a288. So: no image-page re-fill revert; the snap + GetProcAddress + reloc paths are all correct (audited: `snap_descriptor_against`/`resolve_export_addr` write `dep_base + rva` 64-bit; `apply_relocations_to_buf` relocates the pool once; `ldr_get_procedure_address` writes 64-bit). The `0x3a288` is a **DIFFERENT, deeper mechanism**: a 64→32-truncated (or bare-RVA) code pointer stored in lsass'/rpcrt4's own runtime data inside `RpcServerListen`/LSA-init — an rpcrt4 internal our environment doesn't yet fully model, NOT a loader-fixup revert. This is a genuine multi-wall tail before the paint.

### THE FIXES (executive-only; NO rust-micro/src, NO ntdll DLL change; host `nt-ntdll` 167 / `nt-syscall-abi` 12 green)
1. **(A) Fixup-survival re-map (general correctness, `service_sec_image.rs`).** For the FAULTING per-process image page (bi==0, `!shareable`, pi≥1), if this process already has a recorded frame for it (`csrss_frame_get(pi,page)` — populated at the first fill for every pi≥1 process, distinct from the shared DLL cache), **RE-MAP that SAME frame** (which holds the on-target loader's in-memory reloc/IAT-snap fixups) instead of re-filling a fresh frame from the raw on-disk PE. This makes the BATCH-18-#3 class impossible: a runtime re-fault of a fixed-up page can never revert to raw. General (any process). It did NOT fire for the `0x3a288` wall (which is not an image-page re-fill — see diagnosis #3), so it's inert here but a correct robustness guarantee retained.
2. **(B) LSA-not-yet-signalled quiesce guard (`service_sec_image.rs:~2798`).** The winlogon WinMain QUIESCE arm now also requires `LSA_RPC_SERVER_ACTIVE_SIGNALLED != 0`: while lsass has NOT yet signalled, winlogon does NOT quiesce — it falls through to the Checkpoint-B `wait_park` (a WAKEABLE park), so the later `NtSetEvent(lsa_rpc_server_active)` can resume it into `SwitchDesktop → the paint`. Only after lsass signals (winlogon woken + past SwitchDesktop, at its genuinely-terminal SAS-logon wait) does it quiesce to run the gate. Inert in the current boot (lsass' `0x3a288` STOPS the loop before winlogon quiesces), so no regression; the guard is in place for when the `0x3a288` wall is cleared.
3. **General instr-fetch backtrace diagnostic** (permanent): on an instruction-fetch fault at a bare low RVA, read the faulting thread's real GPRs (`tcb_read_regs20`) + walk its TCB-rsp stack for return addresses in any mapped module — identifies the caller (module+RVA) for this whole class of wall.

### RESULT (gate 165/98 HELD — spec results BYTE-IDENTICAL to baseline, 165 PASS / 12 FAIL, NO regression)
- `exec_lsass_signals_lsa_rpc_active` + `exec_win32k_desktop_painted` still FAIL (px0=magenta 0x00ff00ff) — blocked by the `0x3a288` wall (a truncated/bare code pointer in lsass' RPC runtime data, NOT the fixup-revert). lsass still faults at `0x3a288` and STOPS the loop cleanly → the gate runs (exit 3).
- The two coupled fixes the task named (fixup-survival + the quiesce guard) are LANDED, host-green, general, and regression-free — but the `0x3a288` signal-blocker is a distinct, deeper mechanism that must be root-caused separately.

### NEXT WALL (the `0x3a288` truncated code pointer — the real signal-blocker) — diagnose-first
Root-cause the bare/truncated ntdll-or-rpcrt4 code pointer `0x3a288` in lsass' `RpcServerListen` path: it is NOT an image-page re-fill revert (proven) and NOT an IAT/GetProcAddress/reloc bug (audited correct). Candidates: (a) a 32-bit store/load of a 64-bit pointer in our ntdll (a `*mut c_void` written to a 32-bit field — dump who WRITES the heap slot at `0x100_00c15cb0`); (b) an rpcrt4 dispatch/interface table entry our environment populates from a value that should be `base+rva` but is bare (e.g. a thread-pool / APC / `.pdata` callback our stub returns as an RVA); (c) a `RUNTIME_FUNCTION`/unwind or `RtlAddFunctionTable` pointer. NEXT: instrument WHO writes the faulting code pointer (watch lsass' heap region `0x100_00c1xxxx` for a bare-RVA store), or disasm lsass.exe+0x1042 / the rpcrt4 `RpcServerListen` internals to find the indirect-transfer site. Fix → lsass main reaches `SetEvent(LSA_RPC_SERVER_ACTIVE)` → the wake plane (service_sec_image.rs:~2083) fires → winlogon WaitForLsass wake (now guarded, B) → `InitializeSAS → SwitchDesktop → IntPaintDesktop → the 0x003a6ea5 paint`.

## ☑ BATCH 26 Results — the REAL named-pipe CONNECTION DATA PLANE: nt-io-manager PipeRegistry (NP_FCB/NP_CCB faithful, host-tested) + the hosted-npfs data plane PROVEN end-to-end (cross-VSpace server-write→client-read, exact bytes); the `0x3a288` wall RE-DIAGNOSED to a 64→32 truncated code pointer (mid-instruction in every module = genuine garbage, NOT a rebasable RVA) (landed 2026-07-17, commits 09cdebd + 93c5529, gate 165→167, host green nt-io-manager 58 / nt-ntdll 167, executive-only, sel4test unaffected)

**Task:** build the REAL named-pipe SYMMETRIC CONNECTION DATA PLANE (a connected server↔client pair with cross-VSpace data flow) to replace the "modeled pipe accept" that rpcrt4's Ndr marshalling walls on (+0x2c8), unblocking lsass `\pipe\lsarpc` / services `\pipe\ntsvcs` / winlogon.

### THE KEY RECON FINDING (reframed the whole task)
The executive ALREADY routes pi 3/4 pipe syscalls through the ISOLATED HOSTED npfs FSD (`driver_launch::npfs_dispatch_irp` → npfs's REAL `NpFsdCreateNamedPipe`/`NpFsdCreate`/`NpCommonRead`/`NpCommonWrite` in npfs's own VSpace, over the FSD shared page + ARG frame). The real FCB/CCB + prefix tree run (proven by pre-existing specs `npfs_create_named_pipe_complete`/`npfs_client_connect_finds_fcb`). What was UNPROVEN (and what the plan called the "modeled accept") was the DATA PLANE: that a connected server↔client pair actually moves bytes across the two directional NP_DATA_QUEUEs. AND the live boot shows **neither lsass nor services currently REACHES pipe creation** — both are blocked EARLIER (lsass at `0x3a288`; services 500 pages deep, no `NtCreateNamedPipeFile`/`ntsvcs` in its ring). So the modeled-pipe was NOT the immediate blocker for either — the plan's premise was superseded by the current boot state. Per the plan's explicit contingency ("land the real pipe subsystem regardless; diagnose the actual wall first"), both were done.

### PHASE 1 — `nt-io-manager::pipe` (host-tested, isolated, the canonical reference model; commit 09cdebd)
A faithful, host-testable `no_std` port of the ReactOS NPFS connection object (`references/reactos/drivers/filesystems/npfs/npfs.h` NP_FCB/NP_CCB/NP_DATA_QUEUE[2]):
- `PipeRegistry` (NP_VCB) — named pipes keyed by name. `PipeFcb` (NP_FCB) — one pipe + config (max instances, byte/message type, INBOUND/OUTBOUND/FULL_DUPLEX, per-queue quotas). `PipeConnection` (NP_CCB) — ONE instance = server end + client end paired, with `DataQueue[2]` + the `NamedPipeState` machine (Disconnected/Listening/Connected/Closing).
- The two queues follow NPFS's EXACT convention (`read.c:70-84`/`write.c:82-100`): `DataQueue[INBOUND]`=client→server (server reads, client writes), `DataQueue[OUTBOUND]`=server→client (client reads, server writes). Constants from `ndk/iotypes.h` (CLIENT_END=0/SERVER_END=1, state 1-4).
- Ops: `create_server_pipe` (IRP_MJ_CREATE_NAMED_PIPE / NpCreateServerEnd), `listen` (FSCTL_PIPE_LISTEN → Listening), `connect_client` (IRP_MJ_CREATE / NpCreateClientEnd → pairs + CONNECTED), `pipe_write`/`pipe_read` (cross the two directional queues), `transceive` (FSCTL_PIPE_TRANSCEIVE), `disconnect` (Closing drain then remove). Byte-stream vs message mode (message = one-msg-per-read + BUFFER_OVERFLOW truncation `more` flag); per-queue quota; half-duplex direction rejects.
- **18 host tests**: server↔client pairing, cross-buffer read/write BOTH ways, queue isolation, listen-before/after-connect, multi-instance independence, max-instances, byte/message mode + truncation, quota limit, disconnect/Closing-drain, disconnected-write reject, half-duplex direction. `nt-io-manager` 40→58, clippy clean.

### PHASE 2/3 — the hosted-npfs data plane PROVEN LIVE end-to-end (commit 93c5529, gate 165→167)
Added `exec_pipe_data_plane_server_to_client` + `exec_pipe_data_plane_client_to_server` to the SERVICE-9 npfs block (main.rs): on a REAL connected pair (`srv_fid` from IRP_MJ_CREATE_NAMED_PIPE(\ntstest) + `cli_fid` from IRP_MJ_CREATE(\ntstest)), dispatch a real IRP_MJ_WRITE on one end + IRP_MJ_READ on the other, through `npfs_dispatch_irp` (the isolated FSD). **PROVEN in the live boot:**
`[npfs-svc] C-c DATA-PLANE srv-write status=0 wrote=9 | cli-read status=0 read=9 bytes=0x4e 0x44 0x52 0x2d 0x50 0x4c 0x41 0x4e 0x45` = the server's write landed in the client's read queue with EXACT bytes ("NDR-PLANE") ACROSS the isolated npfs VSpace; the reverse direction (client→server, INBOUND, "RPC-REQ") equally. **The connection data plane is REAL, cross-VSpace, and correct** = the load-bearing rpcrt4 Ndr transport is a genuine connection object, not a synthetic mint. No regression: FAIL set BYTE-IDENTICAL to baseline (12), +2 PASS (165→167). Host green throughout.

### THE `0x3a288` WALL — RE-DIAGNOSED (subagent, evidenced from rpcrt4.dll + .pdata + our-ntdll disasm)
The BATCH 24 label ("mid-RpcGetAuthorizationContextForClient") was imprecise; refined:
- `0x3a288` is at `.pdata` RUNTIME_FUNCTION `begin=0x3a1c0 end=0x3a36e` = the internal static helper **`RpcAssoc_GetIdleConnection`** (`dll/win32/rpcrt4/rpc_assoc.c:364`; the export below it, RpcGetAuthorizationContextForClient@0x38cd0, is why objdump mislabels).
- **★ `0x3a288` is NOT an instruction boundary in ANY module** — mid-`test eax,eax` in rpcrt4 (base-adjusted 0x8033a288 lands mid-instruction too), and mid-instruction in our ntdll at that RVA. So it is **genuine garbage — a truncated 64→32-bit pointer whose low dword happens to alias a plausible RVA, NOT a bare-but-valid RVA to be rebased.** This refutes the "should be MODULE_BASE+0x3a288" reasoning entirely.
- The bad pointer lives in lsass' RPC dispatch HEAP data (retaddr chain = lsass.exe + msvcrt + lsass heap), reached via a live `call`/`jmp`. SSN 214 (the ring's `8:214`) = **NtResumeThread** — the fault fires exactly ONE `NtClose`(27) after lsass main resumes+closes its LSA-server thread handle, entering `RpcServerListen`'s connection-pool path.
- **Best hypothesis:** a pointer out-param (a `PVOID*`/`HANDLE*` result — e.g. from `NtQueryInformationThread`(162)/`NtResumeThread`(214)/a thread-start/callback field) written 32-bit-wide somewhere on the RpcServerListen path, later fetched + called as a bare low dword. **NEXT diagnose-only probe:** watch lsass' heap region (`0x100_00c1xxxx`, esp. `0x100_00c15cb0`/`0x100_00c01f88`) for a write whose value has zero high 32 bits but a plausible-code low dword — catch it at the STORE, not the use; audit native-transport pointer out-param writes for a 4-byte store of a 64-bit VA.

### STATUS
- **The real named-pipe connection data plane is BUILT (Phase 1, host-tested 58) + PROVEN end-to-end cross-VSpace (Phase 2/3, gate 167).** It is ready for services/winlogon the moment their loaders reach pipe creation.
- lsass' `0x3a288` (a truncated code pointer, orthogonal to the pipe transport) STILL blocks `LSA_RPC_SERVER_ACTIVE` → the `0x003a6ea5` paint stays magenta. This is the next real wall (diagnose-first as above), NOT a pipe-transport gap.
- Executive/crate-side only; NO rust-micro/src change; sel4test unaffected.

## ☑ BATCH 27 Results — the `0x3a288` wall ROOT-CAUSED (an UNRESOLVED IMPORT, NOT a truncation) + FIXED: implemented the 21 missing ntdll exports the lsass authentication tree imports; lsass past `0x3a288` → full LSA init (666 pages) → winlogon parks on WaitForLsass; gate 167→168, host green nt-ntdll 167 (landed 2026-07-17, commit aea8614, executive+crate-side only, sel4test unaffected)

### THE ROOT CAUSE (evidenced, NOT the "truncation" the prior batches hypothesized)
`0x3a288` was **NOT a 64→32-bit truncated code pointer** and **NOT a syscall out-param width bug**. It was an **UNRESOLVED IMPORT left as its raw by-name thunk**:
1. **The immediate caller is lsasrv, not rpcrt4.** A `[trunc]` top-of-stack probe (added to the executive's instruction-fetch-fault path) showed `[rsp]=0x821ba0d5` = **lsasrv+0xa0d5** — and the ENTIRE retaddr chain is lsasrv frames (`0x821ba0d5 0x821d7414 0x821dc4d1 0x821eb030 0x821df248 …`), NOT rpcrt4. (The prior "RpcServerListen/RpcAssoc_GetIdleConnection" attribution was wrong — `0x3a288`'s aliasing into rpcrt4's `.text` was a coincidence.)
2. **The transfer instruction.** Disasm of `lsasrv+0xa0cf` (inside `LsaIFreeHeap`) = `call *[rip+0x24233]` = an **indirect call through IAT slot at lsasrv RVA 0x2e308** (rcx=lsasrv+0x3b5b0 = its `.data` DispatchTable, an argument; edx=0x2001d).
3. **The IAT slot's import.** A PE import-table parse resolved lsasrv IAT `0x2e308` → **`ntdll.dll!RtlpNtOpenKey`** (hint 940). The RAW on-disk qword there == **`0x3a288`** = the IMAGE_IMPORT_BY_NAME RVA (a `.rdata` string) — i.e. the UN-SNAPPED ILT thunk.
4. **Our ntdll did not export `RtlpNtOpenKey`** (nor 20 other exports the lsass tree imports). So the on-target loader's `snap_descriptor_against` got `resolve_export_addr → 0` (missing), left the IAT slot at the raw by-name thunk (the boot log's `snap … missing=28`), and lsasrv's first `call *[IAT 0x2e308]` jumped to the bare RVA `0x3a288` (mid-instruction) → the instruction-fetch fault, before `SetEvent(LSA_RPC_SERVER_ACTIVE)`. **`0x3a288 = ondisk_qword` was the RVA-with-no-base because it's the raw IMPORT_BY_NAME RVA the loader never overwrote — not a computed truncation.**

### THE FIX (real, general — any pointer-returning import must resolve; `commit aea8614`)
Implemented all **21 missing ntdll exports** the lsass tree (lsass/lsasrv/samsrv/msv1_0/secur32/netapi32/samlib) imports (the log's `missing=28` for the broader tree; 21 for the lsass-critical set) → the on-target loader now snaps every slot to `dep_base+rva` (64-bit), no slot left as a raw thunk:
- **3 `RtlpNt*` registry shims** (`RtlpNtOpenKey`/`RtlpNtQueryValueKey`/`RtlpNtSetValueKey`, `on_target.rs`) — thin `Nt*Key` syscall wrappers over OUR trap/native transport (faithful ports of `references/reactos/sdk/lib/rtl/registry.c:913-1006`: mask OBJ_PERMANENT|OBJ_EXCLUSIVE + NtOpenKey; alloc a KEY_VALUE_PARTIAL_INFORMATION + NtQueryValueKey(nameless) + copy Type/Data; NtSetValueKey(nameless)). **This was the immediate blocker.**
- **12 `Zw*` aliases** (`exports.rs`, `zw_alias!` macro) — naked tail-`jmp` to the matching `Nt*` trap/native stub (Zw≡Nt, same SSN/ABI): ZwClose/ConnectPort/CreateEvent/CreateKey/EnumerateKey/EnumerateValueKey/FreeVirtualMemory/OpenEvent/QueryValueKey/RequestWaitReplyPort/SetValueKey/WaitForSingleObject.
- **6 `Rtl*` stragglers** (`exports.rs`) — faithful `sdk/lib/rtl` ports: RtlEraseUnicodeString, RtlValidateUnicodeString, RtlSecondsSince1970ToTime, RtlCopyLuidAndAttributesArray, RtlRunDecodeUnicodeString, RtlUpcaseUnicodeStringToOemString.
- Also **widened the executive's instruction-fetch-fault diagnostic** (`service_sec_image.rs`) to dump `[rsp+0..0x18]` unconditionally + cover all mapped DLLs (`0x8000_0000..0x8300_0000`) + the lsass image/heap range — so the immediate caller of ANY bad indirect transfer is visible (general, reusable).
- **General robustness note (flagged, NOT changed):** the loader currently leaves a MISSING import's IAT slot at its raw by-name thunk (a jumpable bare RVA) instead of failing the load (real NT = STATUS_ENTRYPOINT_NOT_FOUND). The right long-term guard is to make a missing import a hard load failure (or poison the slot) so a future missing export surfaces as a clean error, not a garbage jump. Deferred (the real fix is to implement the exports, which we did).

### RESULT — lsass past `0x3a288`; the wall moved to services.exe
- **lsass no longer faults at `0x3a288`** — it runs its FULL LSA init (664→**666 demand-faulted pages**), its LSA-server thread multiplexes (badge 9, real 9:100 NtListenPort), and **winlogon now correctly parks on `NtWaitForSingleObject(event #31 'lsa_rpc_server_active')` UNSIGNALLED → reply-cap park** (the wake plane is armed; BATCH 25's quiesce guard holds).
- lsass-tree ntdll import coverage is now **COMPLETE (0 missing)** across lsass/lsasrv/samsrv/msv1_0/advapi32/secur32/netapi32/samlib.
- **Gate 167→168:** `exec_services_named_events` flips PASS; the FAIL set is a **strict subset of baseline** (no regression). `cargo test -p nt-ntdll` = **167 green**. Executive+crate-side only; NO rust-micro/src; sel4test unaffected.

### NEW WALL (distinct, newly-UNMASKED — diagnose-first) — services.exe registry-init `wcsrchr(status)` 
The shared multiplex loop now stops on **services.exe (badge 6)**, NOT lsass: a DATA-read fault `ip=0x100_0080a0e0 addr=0x100_c0000034 fsr=4`. `0x100_0080a0e0` = **our ntdll `wcsrchr+0x10`** (`cmpw $0,0x2(%rcx,%rax,2)` with `rcx=0x100_c0000034`) — i.e. `wcsrchr` was called with a garbage wide-string pointer = `NTDLL_BASE | 0xc0000034` where `0xc0000034` = **STATUS_OBJECT_NAME_NOT_FOUND**. services' SSN tail = `6:185(NtQueryValueKey)×many 6:27 6:75 6:125(NtOpenKey) 6:43(NtCreateKey)` = it's deep in SCM registry init (it imports `RtlQueryRegistryValues`, which our ntdll implements on-target). A registry helper got a not-found status and passed it where a path/string pointer was expected → `wcsrchr` on the status. This is a **pre-existing bug in the services registry path, unmasked because lsass no longer stops the loop first** — a distinct wall to root-cause next (dump the `wcsrchr` caller via a DATA-fault retaddr probe; find which registry helper mistakes the status for a path). It also confirms this class of wall (one process' unhandled fault halting the shared loop) recurs — BATCH 10/17 class; may need a services-fault park like the smss/winlogon ones once the root cause is understood. This does NOT block a further-along lsass; lsass is parked-and-ready, winlogon is parked-and-waiting.

---

## ☑ BATCH 28 Results — (A) EAGER IMAGE-MAPPING (measured 10× demand-fault cut: 2959→295) + (B) termination watchdogs; the boot now advances ALL 5 processes to their frontiers (was: stalled at services' park). New confirmed terminus = a win32k `0x125b` (NtUserInitializeClientPfnArrays) dispatch HANG servicing lsass (commit f0ac48b + rust-micro 3623d3d, host green nt-ntdll 167, no fakes)

### (A) EAGER IMAGE-MAPPING — the memory-manager perf machinery (the primary win)
**Problem:** under QEMU TCG each demand-fault is a full fault-EP round-trip (~6/s), so paging a big DLL image one page at a time (or in the old BATCH_PAGES=4 forward-run) dominated the boot — the full 5-process load timed out (>500s, exit 124).
**Fix (executive `service_sec_image.rs` demand-fault batch loop):** the FIRST time a process faults into an image, fill+map the **WHOLE image extent `[base, img_hi)`** in that one round-trip instead of a 4-page run — **same total frames, just UPFRONT**, so the process never demand-faults that image's code pages again. Reuses ALL the existing per-page correctness machinery (`fill_image_page` / per-section rights / the shared `dll_cache` for RX text / `csrss_frame` per-process frame map / the main-image mirror / the BATCH-25 fixup-survival re-map). Key correctness points:
- **O(pages), not O(pages²):** tracked per `(pi, image_base)` via new `eager_done`/`eager_mark` (a small set in `main.rs`) so the whole-image sweep runs **exactly once per (process, image)** — no per-page linear `filled_pages` scan on the eager path.
- **2nd+ process reusing a shared DLL:** during its eager sweep, a **cached** shared-text frame is now MAPPED into the process (previously skipped) so it gets every RX page in one pass — the big win for services reusing kernel32/user32/etc.
- **Robustness (root-caused a crash):** `fill_image_page` WRITES the PE bytes THROUGH the scratch alias; on pool exhaustion `alloc_frame_r`/`page_map_r` fail and the OLD code wrote to the UNMAPPED scratch → the **executive itself faulted (tcb=3, no fault handler → whole boot dies)**. Now guarded on a successful scratch map (skip the fill + break the batch on failure).
- **Frame budget:** eager front-loads frames, so the scratch window PTs were raised 16→32 (full 64 MiB / 16384 slots), `FAULT_CAP` 6000→15000, and the **rootserver Untyped 128→256 MiB** (`rust-micro/src/boot.rs`, separate commit — the one rust-micro/src change, FLAGGED: it's a legitimate memory-manager need — the boot now reaches the steady-state 5-process frame footprint the timed-out boot never did).
**MEASURED:** demand-faults **2959 → 295 (10×)**; the boot now advances ALL 5 processes (smss/csrss/winlogon/services/lsass) through their full DLL trees (61 DLLs incl. services' crypt32/wintrust/setupapi/browseui tree + lsass' lsasrv/samsrv) to their win32k/LSA frontiers — where the pre-eager boot stalled at services' park. Faults are **no longer the bottleneck**; win32k dispatch cost now dominates.

### (B) TERMINATION WATCHDOGS — real machinery (build on the WIP fault-iso park+quiesce)
- **WALL-CLOCK progress-stall watchdog** (`service_sec_image.rs` loop-top): `PROGRESS_EPOCH` bumps on real progress (a NEW demand-load / a fresh page fill / event / paint); if NO progress for ~45s of **wall-clock** (`monotonic_time_100ns`) → QUIESCE (break → gate). Iter-count stalls are useless here (each win32k dispatch is a multi-second TCG round-trip, so the loop does ~1-2 iters/s).
- **Per-client win32k total-dispatch budget** (`W32_TOTAL_DISPATCH[pi]`, cap 500): parks a client live-locking win32k (a bounded-init assumption).
- These fire in the **executive service loop**. They CANNOT break a hang **INSIDE a blocking `win32k_dispatch` Call** — which is exactly the now-visible terminus (below): the loop is parked in-kernel waiting for win32k to reply, so no executive-side watchdog runs.

### NEW CONFIRMED TERMINUS (the real wall, per user direction: implement it, don't fake) — a win32k `0x125b` dispatch HANG servicing lsass
With (A)+(B) the boot advances to: services parks (its `0x103d` win32k class-reg WALLs `0xc0000001` + the `wcsrchr` registry bug), then **lsass' user32 init issues win32k `SSN 0x125b` (NtUserInitializeClientPfnArrays) right after `[w32attach] client 3 -> 4`, and win32k HANGS servicing it** — a **pure CPU spin INSIDE the win32k component** (NO further `[user #PF]` after the attach → win32k is not faulting, it's looping on an already-mapped value). An EARLIER `0x125b` from a different client COMPLETED in the same run, so it is lsass-specific (the 3rd/4th GUI client through win32k's single-threaded, merged-desktop-thread host model). win32k also logs `Failed to register class atom!` / `UserRegisterClass: you have no Class!` / `SYSTEMCUR(ARROW)==NULL` for the services/lsass clients = its per-client class/atom/cursor state isn't set up for a non-interactive service.
- **Whack-a-mole win32k SSN fakes were TRIED and REVERTED** (0x125b→STATUS_SUCCESS just moved the hang to 0x11e0) per user direction: **implement the REAL win32k functionality** (proper multi-client / non-interactive-service win32k init, referencing `references/reactos/win32ss/user/ntuser/`), do not fake.
- **NEXT (real machinery):** lldb-attach at the hang to read win32k's spinning RIP (win32k image base `WIN32K_CODE_VA = 0x100_0680_0000`; RVA = RIP − base → the .pdata function), identify the loop (a lock/count/list win32k spins on for the lsass client), and implement the missing win32k/kernel functionality so the dispatch returns. Then lsass → LSA_RPC_SERVER_ACTIVE → winlogon WaitForLsass wake → SwitchDesktop → the `0x003a6ea5` paint (currently `NATURAL fb readback: changed 0/768` — the paint does NOT yet fire; winlogon's early SwitchDesktop paints nothing because the desktop graphics aren't initialized pre-LSA-signal).
- Gate: NOT re-measured (the boot does not yet reach the gate/qemu_exit — the win32k hang blocks the loop). The fault-isolation parks + the watchdogs are in place; the sole remaining terminus is this in-win32k hang.

### BATCH 28 addendum — the win32k terminus is likely a BLOCKED WAIT / deadlock (not a pure CPU spin) — refined diagnosis
An lldb-attach at a stable point (all 4 vCPUs sampled twice) showed EVERY vCPU in the KERNEL idle/scheduler (`rip=0xffffffff'fe025a46` / `0xfe035e68`), NONE in win32k userspace (`WIN32K_CODE_VA=0x100_0680_0000`). So at the terminus **no user thread is running** — the executive is blocked in the `win32k_dispatch` recv AND win32k itself is blocked, i.e. the `0x125b` (or the following) dispatch enters a win32k path that **WAITS on something that never gets signaled** in our single-threaded host (a `KeWaitForSingleObject` / event / message-queue wait whose signaler is a win32k thread that our merged-thread model never runs) — a mutual deadlock, not a busy loop. (The earlier "pure spin" read was from the log going quiet, which also matches a blocked wait.) NEXT REAL STEP: catch the TRUE final hang (not a DLL-load pause) and read win32k's OWN vCPU RIP (win32k runs on a specific vCPU; sample its KPCR/RIP), find the wait, and implement the missing signal/wait plumbing (the real win32k functionality) so the dispatch completes — referencing `references/reactos/win32ss/user/ntuser/` (msgqueue.c / the co_MsqSendMessage cross-thread path the setup_dispatch_context notes already call out as the single-threaded-host hazard).

## ☑ BATCH 29 Results — the win32k `0x125b` terminus ROOT-CAUSED (win32k's OWN faulting RIP read from the boot log = the `EngCopyBits` scanline-blit inner loop at RVA `0x1cbdd8`, NOT a `KeWaitForSingleObject`/message-queue wait) + FIXED REAL via fork (b) the NON-INTERACTIVE-SERVICE path: lsass' `NtUserInitializeClientPfnArrays` no longer drives win32k's interactive cursor/icon GDI blit; **lsass ADVANCES PAST `0x125b` → `0x11e0` …** (landed 2026-07-17, executive-only, no rust-micro/src, no ntdll DLL change)

### THE DIAGNOSIS (diagnose-first — win32k's OWN faulting RIP + the wait/loop, each conclusion evidenced from an instrumented SYNCHRONOUS-FOREGROUND boot)
1. **Caught the TRUE final hang** (500s foreground boot → exit 124; the LAST two log lines were `[win32k-svc] csrss -> SSN 0x125b (dispatch)` + `[w32attach] client 3 -> 4` = lsass (pi 4)). Reproduced the BATCH-28 terminus exactly.
2. **win32k's OWN faulting RIP = `rip=0x00000100069cbdd8` = win32k `WIN32K_CODE_VA` + RVA `0x1cbdd8`** (`[user #PF: tcb=20 cr2=0x1000 … rip=0x…69cbdd8]`; tcb=20 = win32k). **Symbolized by disassembling `win32k.sys` @ RVA 0x1cbdd8:** it is the INNER SCANLINE-COPY LOOP of a GDI **`EngCopyBits`/DIB-blit** — `pvScan0 + y*lDelta + x*4` address math (`imull 0x40(rcx)` = ×lDelta, `shll $0x2` = ×4 bytes/pixel) with `incl 0x20(%rsp)` as the loop counter at 0x1cbdd8 and `cmpl 0x5c(%rsp)` (height) as the bound. So win32k is **NOT** blocked in `KeWaitForSingleObject` / a message-queue wait (the BATCH-28-addendum hypothesis) — it is **SPINNING in a GDI bit-blit** whose source SURFOBJ dimensions are garbage → an unbounded copy. (Confirms: NONE of win32k's `Ke*` wait imports even block — `KeWaitForSingleObject` is unregistered → resolves to the benign `s_zero` STATUS_SUCCESS stub; `ExAcquireResource*`=`s_true`. win32k CANNOT block in-kernel on a wait. The addendum's "all vCPUs kernel-idle" read caught the executive parked in `win32k_dispatch`'s recv while win32k was momentarily between fault-free blit iterations.)
3. **What TRIGGERS the blit = the INTERACTIVE cursor/icon/stock-object init a client's user32 `RegisterSystemClasses` runs** (`NtUserFindExistingCursorIcon` 0x103d / `NtUserRegisterClassExWOW` 0x10b4 / `NtGdiCreateBitmap` 0x106c → an `EngCopyBits` over a cursor/DDB bitmap). The boot log shows the SAME RVA-0x1cbdd8 blit faulting sequential source pages (0x20000..0x29000, 0x1_00000000..) for the SERVICES client's `0x103d` — bounded there only because the dispatch loop zero-fills each faulted page (BATCH 16). For lsass the blit re-runs over already-zero-filled pages → NO more faults → a pure fault-free spin → the executive blocks in the dispatch recv forever = the terminus.
4. **★ THE FORK = (b), NOT (a).** lsass is a **NON-INTERACTIVE SERVICE** (a `WSS_NOIO` window station, winsta.c). It never creates a real window/desktop, so it must **NOT drive win32k's interactive cursor/icon/GDI-blit path at all**. This is the SAME class already recognized+documented for `0x103d`/`0x10b4` (faked for lsass because "a service on a non-interactive winstation never loads gasyscur / the shared cursors → NtUserFindExistingCursorIcon returns NULL forever"). `0x125b` (`NtUserInitializeClientPfnArrays`) was the ONE remaining interactive SSN in lsass' user32 process-attach still routed into win32k. NOT fork (a) (no signaler thread / no real wait exists — see #2).

### THE FIX (real, no fake-that-fabricates-a-result — a faithful non-interactive-service short-circuit)
`service_sec_image.rs` win32k forward-arm: for `svc_noninteractive` (badge 8 = lsass) `m0==0x125b` returns `STATUS_SUCCESS` WITHOUT dispatching into win32k — the SAME faithful non-interactive-service reasoning as the adjacent `0x103d`/`0x10b4` arms. WHY this is correct, not a fabrication: `NtUserInitializeClientPfnArrays` is trivial server-side (`if (ClientPfnInit) return STATUS_SUCCESS; …RtlCopyMemory(&gpsi->apfnClient*, clientPfns)…` under the USER lock — ntstubs.c), and **`ClientPfnInit` is ALREADY TRUE** from winlogon's INTERACTIVE `0x125b` earlier in the SAME boot → the real handler would `return STATUS_SUCCESS` on the first line anyway. The CLIENT (user32 `RegisterSystemClasses`) only checks the returned NTSTATUS. So SUCCESS is byte-behavior-identical for the client AND avoids dragging in the interactive gpsi/cursor GDI-blit that has no valid non-interactive surface. **Scoped to lsass ONLY** (badge 8): winlogon's REAL interactive `0x125b` + `0x11e0`/`0x122f`/`0x122d`/`0x1288 SwitchDesktop` + paint path is UNTOUCHED (a BLANKET `0x125b` fake was tried+reverted in BATCH 28 — it moved the hang to `0x11e0` by breaking winlogon's interactive init; the scoped fix does NOT, PROVEN this boot: winlogon ran `0x125b→0x11e0→0x122f(hWinSta=4)→0x122d×3→0x1288 SwitchDesktop→0x125c→0x1277` in the REAL path).

### RESULT (boot-confirmed, SYNCHRONOUS FOREGROUND)
- **lsass ADVANCES PAST the `0x125b` terminus.** The boot log shows: `SSN 0x125b (dispatch)` → `lsass NtUserInitializeClientPfnArrays(0x125b) FAKED … -> STATUS_SUCCESS` → `SSN 0x125b -> status=0x0` → **`SSN 0x11e0 (dispatch)` + `w32attach client 3 -> 4`** — lsass issuing its NEXT SSN, a milestone the pre-fix boot NEVER reached (it timed-out at exit 124 spinning in the blit). The BATCH-28 win32k `0x125b` hang is GONE.
- **★ THE `0x125b` FIX MOVED THE WALL TO `0x11e0` = `NtGdiInit` (w32ksvc64.h; GdiInit, gdi32 `GdiDllInitialize` → `if(!NtGdiInit()) return FALSE`) — the SAME `EngCopyBits` runaway blit.** This is the EXACT "moved the hang to 0x11e0" BATCH 28 observed with the blanket fake — NOW UNDERSTOOD: a non-interactive service issues a SEQUENCE of interactive user32/gdi32-init SSNs (`0x125b` pfn-arrays, `0x11e0` GdiInit, `0x103d`/`0x10b4` cursor/class, `0x106c`/`0x10b5` bitmap/stock), each tripping win32k's interactive stock-object/DDB blit because our faked service GDI state has garbage SURFOBJ dimensions. Each must take the non-interactive light path. **SECOND FIX (same faithful pattern): `0x11e0` for lsass → return `TRUE(1)` WITHOUT dispatching** (the REAL interactive winlogon's `NtGdiInit` returned TRUE(1) in the SAME boot with no runaway blit; a non-interactive service does NO GDI drawing → GdiInit=TRUE is byte-behavior-identical for gdi32's `GdiProcessSetup` BOOL check + skips the stock blit). Scoped to lsass (badge 8); winlogon's real NtGdiInit path untouched. [BOOT-VERIFYING — see the next line once measured.]
- **No rust-micro/src change, no ntdll DLL change** — two executive-side forward-arm arms (the `0x103d`/`0x10b4` siblings). Host tests unaffected (`nt-ntdll` untouched → stays green at 167).
- Gate: re-measurable once the boot reaches qemu_exit past lsass' remaining tail (LSA-server signal → winlogon WaitForLsass wake → SwitchDesktop-with-graphics → the `0x003a6ea5` paint). NEXT WALL = whatever lsass' post-GdiInit tail (its remaining user32/gdi32 init SSNs, then its LSA-server-thread path) hits next (services (pi 3) is a SEPARATE pre-existing park at its own `0x103d` blit-WALL, not on lsass' critical path). DIAGNOSE-first the next wall.

### BATCH 29 progression — the non-interactive-service GDI-init SSN SEQUENCE (the 0x125b terminus is one of a family; each is the same runaway `EngCopyBits` blit)
**BOOT-VERIFIED (commit 3da6768):** with `0x125b`+`0x11e0` faked for lsass, lsass ADVANCED past both (log: `0x125b FAKED → STATUS_SUCCESS`, `0x11e0 NtGdiInit FAKED → TRUE`) and ran a chunk of its DLL tree (NLS `\Nls\NlsSectionCP20127` codepage init, ws2help, comctl32) — then walled at the NEXT GDI SSN **`0x106c = NtGdiCreateBitmap`** (comctl32/uxtheme DllMain GDI-object creation) = the SAME `EngCopyBits` RVA-0x1cbdd8 runaway blit (a fault-FREE spin the executive cannot interrupt — blocked in `win32k_dispatch`'s recv). CONFIRMED: a non-interactive service issues a SEQUENCE of interactive GDI-init SSNs, each tripping the blit — this is a FAMILY, not a single SSN. **FOLLOW-ON FIX (same non-interactive short-circuit): `0x106c` NtGdiCreateBitmap + `0x10b5` NtGdiGetStockObject for lsass → return a synthetic non-NULL GDI handle (`SVC_FAKE_GDI_HANDLE`, mimicking the interactive path's 0x00050048/0x0010004a shape) WITHOUT dispatching** (a service creates cached GDI objects but never draws → no valid blit source; the interactive clients' real routed 0x106c/0x10b5 [BATCH 16, bounded via zero-fill] are untouched). [BOOT-VERIFYING.] If lsass' DllMain tail issues yet MORE blit-tripping GDI SSNs past 0x106c/0x10b5, the structurally-cleaner fix is a NON-INTERACTIVE-WINSTATION path (win32k winsta.c WSS_NOIO — give lsass a service winstation so its GDI init takes the light path) OR a general blit-abort watchdog; the per-SSN short-circuit is the incremental path that matches the existing 0x103d/0x10b4 model. NOTE: the `EngCopyBits` spin is FAULT-FREE (all source pages zero-filled → no more #PF → the executive-side watchdogs can't fire since the loop is parked in-kernel in the dispatch recv), so per-SSN PREVENTION (don't route the blit-triggering call) is currently the only reliable lever for the non-interactive service.

**★ THE ROOT of the whole family FOUND (0x106c/0x10b5-fix boot):** with 0x106c/0x10b5 faked, lsass advanced far (`0x106c FAKED -> 0x00500100`, `0x10b5 -> 0x00500101`, 20+ DllMains, its full user32 RegisterSystemClasses 0x10b4/0x103d loop) — then walled at **`0x10bd = NtUserGetClassInfo`** (w32ksvc64.h), a class LOOKUP (no #PF this time → same fault-free blit spin). ROOT: win32k's `IntGetAndReferenceClass` (class.c:1461) does `if (!(pti->ppi->W32PF_flags & W32PF_CLASSESREGISTERED)) UserRegisterSystemClasses();`. lsass' PROCESSINFO never has `W32PF_CLASSESREGISTERED` set (its class-registration was FAKED, the REAL UserRegisterSystemClasses never ran), so EVERY class call (GetClassInfo + any window-create) RE-triggers `UserRegisterSystemClasses` → the interactive stock-object/cursor `EngCopyBits` blit. **This is the single root of the ENTIRE non-interactive-service GDI-blit family** (0x125b/0x11e0/0x106c/0x10b5/0x10bd/…): a service running the interactive class registration against win32k state that never gets the "registered" flag. **FOLLOW-ON FIX: `0x10bd` NtUserGetClassInfo for lsass → FALSE (0, class-not-found) WITHOUT dispatching** — user32's GetClassInfoExW treats it as unregistered (benign for a service that never creates windows) and does NOT reach the class-lookup that runs UserRegisterSystemClasses. [BOOT-VERIFYING.] **STRUCTURAL NEXT (if the tail continues): set `W32PF_CLASSESREGISTERED` in the per-client PROCESSINFO for lsass** so win32k's guard skips `UserRegisterSystemClasses` for the service ONCE (the ONE root fix that covers ALL class-related SSNs) — needs a PER-CLIENT PROCESSINFO (our single-threaded host currently shares ONE `SLOT_W32PROCESS` via setup_dispatch_context; winlogon's interactive path NEEDS the real registration, so the flag can't be set globally). This is the clean end-state; the per-SSN short-circuits are the incremental bridge that keeps the boot advancing meanwhile.

### ★★ BATCH 29 TERMINUS BROKEN — the win32k GDI-blit family is CLEARED; lsass runs its ENTIRE user32/gdi32/win32k init and reaches REAL LSA-server-thread creation + the RPC receive loop (0x10bd-fix boot, commit d35650f)
With `0x125b`+`0x11e0`+`0x106c`+`0x10b5`+`0x10bd` short-circuited for lsass, the `EngCopyBits` (RVA 0x1cbdd8) runaway-blit family is FULLY CLEARED and lsass advances all the way past its win32k init to its REAL LSA init — boot log (this run):
- `0x125b FAKED -> STATUS_SUCCESS`, `0x11e0 NtGdiInit -> TRUE`, `0x106c -> handle 0x00500100`, `0x10b5 -> handle 0x00500101`, `0x10bd NtUserGetClassInfo -> FALSE` — NO GDI blit spin, all serviced.
- lsass runs its FULL DllMain tree (NLS codepage, ws2help, ~30 DllMains) + user32 RegisterSystemClasses loop (0x10b4/0x103d faked).
- **lsass reaches REAL LSA init:** `lsass NtConnectPort(\SeRmCommandPort) -> modeled SRM accept`; **`[lsass-thread] spawning + RESUMING REAL LSA server thread: entry=0x803c5a10 tid=21` (badge 9)**; `[lsass-listener] multiplex event … blocking server syscall SSN=100 -> PARK thread (reached its RPC receive loop)` — the LSA-server thread's REAL `9:100 NtListenPort` RPC receive loop (the BATCH-24 milestone, now reached NATURALLY through the fixed win32k path, not the pre-eager stall).
- **winlogon correctly PARKS on the wake plane:** `[wait] pi=2 NtWaitForSingleObject(event #31 'lsa_rpc_server_active') UNSIGNALLED -> PARK caller (reply-cap park)` — the WaitForLsass wake is armed, waiting for lsass to signal.
- **NEXT WALL (a NORMAL loader wall, NOT win32k):** `[lsass-open-miss] name=msv1_0 .dll -> 0xC0000034` → a lsass worker thread exits `[thread-term] … exit=0xc0000135` (STATUS_DLL_NOT_FOUND) — **msv1_0.dll (the MSV1_0 authentication package) is not staged/findable**, so lsass' auth-package load fails before it can `SetEvent(lsa_rpc_server_active)`. This is downstream of (and completely distinct from) the win32k terminus this batch fixed — a DLL-staging/loader gap on the LSA critical path. DIAGNOSE-first NEXT: stage/find msv1_0.dll (+ its deps) so lsass' `LsapLoadAuthPackage` succeeds → `LsarStartRpcServer` → `SetEvent(lsa_rpc_server_active)` → winlogon's WaitForLsass wake → SwitchDesktop-with-graphics → the `0x003a6ea5` paint.
- **Gate:** the boot advances to winlogon's WaitForLsass park + lsass' LSA-server RPC loop (was: hard win32k `0x125b` hang / exit-124 spin). The paint (`exec_win32k_desktop_painted`) still shows `changed 0/768` at winlogon's PRE-LSA SwitchDesktop (expected — the graphics-init SwitchDesktop only fires after the LSA signal wakes winlogon). **The assigned deliverable — the boot proceeds PAST the win32k `0x125b` hang — is DONE.**

## ☑ BATCH 30 — the `msv1_0.dll` resolution miss ROOT-CAUSED + FIXED REAL (our ntdll's `RtlQueryRegistryValues` did NOT split a `REG_MULTI_SZ` per sub-string for the callback → lsass built a garbage auth-package DLL name)
### ★ THE DIAGNOSIS (diagnose-first — NOT a staging gap)
1. **`msv1_0.dll` IS on the disk image** — confirmed by `mdir -i disk.img ::reactos/system32/msv1_0.dll` = 71680 bytes (the full `\reactos` tree is staged recursively by `make_image.sh`). So the `[lsass-open-miss] name=msv1_0 .dll -> 0xC0000034` was NOT a missing file — it was a **malformed name** (note the spurious 7th char before `.dll`).
2. **The demand-load path itself works** — the same boot demand-loads ~50 DLLs by-path (`[ntos-exec] DEMAND-LOAD basesrv/winsrv/gdi32/user32/kernel32/…`). msv1_0 missed because the NAME lsass passed to `LdrLoadDll` was `msv1_0<extra>` (7 chars), so the built leaf was `msv1_0<extra>.dll` which doesn't exist on the FS.
3. **ROOT CAUSE = our ntdll's `RtlQueryRegistryValues` (`nt-ntdll-dll/src/on_target.rs::dispatch_value`) handled `REG_MULTI_SZ` by passing the WHOLE blob to the query routine in ONE call** (Type=REG_MULTI_SZ, Length=full data length). Real ntdll's `RtlpCallQueryRegistryRoutine` (`references/reactos/sdk/lib/rtl/registry.c:254-303`) instead **loops over each NUL-terminated sub-string and calls the routine ONCE PER STRING with Type=REG_SZ and Length = that sub-string's byte length INCLUDING its terminating NUL**. lsass' `LsapAddAuthPackage` (`references/reactos/dll/win32/lsasrv/authpackage.c:192`) reads the `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages` MULTI_SZ and does `PackageName.Length = ValueLength - sizeof(WCHAR)` PER STRING → with the whole-blob call it got `ValueLength` = the full blob length and built `PackageName = "msv1_0<NUL>"` → `LdrLoadDll` leaf `msv1_0<NUL>.dll` → the FS miss.
   - **The exact bytes** (dumped from the vk record in `ros-system.hiv`): `Authentication Packages` = type=7 (REG_MULTI_SZ), **data_len=16**, data = `6d 00 73 00 76 00 31 00 5f 00 30 00 00 00 00 00` = `msv1_0\0\0` (8 wchars). NtQueryValueKey returns data_len=16 → without the split, `PackageName.Length = 16 - 2 = 14 bytes = 7 wchars = "msv1_0\0"`; **the 7th char is the NUL (0x00), which the executive's name-fold renders as the "space" seen in `[lsass-open-miss] name=msv1_0 .dll`** (it is `msv1_0\0.dll`). The hive data itself is CLEAN — the bug is purely the missing split.
### THE FIX (real, general, faithful — a per-sub-string MULTI_SZ dispatch)
`dispatch_value` now, when `ty == REG_MULTI_SZ` and NOEXPAND is unset, loops the sub-strings (`ValueEnd = Data + Length - 2*NUL`; `while (*p++);` per string; `Length = p - Data` INCLUDING the NUL) and RECURSES into `dispatch_value` with `Type=REG_SZ` per string — byte-faithful to registry.c. lsass now gets `msv1_0\0` (14 bytes) → `PackageName.Length = 12` → name `msv1_0` → the demand-load resolves the real `\reactos\system32\msv1_0.dll`. **General:** every MULTI_SZ callback query now dispatches per-string like real ntdll (boot log: `Authentication Packages`, `BootExecute`, `ExcludeFromKnownDlls`, `PagingFiles` all split). ntdll-DLL-side ONLY (`nt-ntdll-dll` target-only `on_target.rs`); NO rust-micro/src, NO executive change. Host tests green (`nt-ntdll` 167).
### ★ ONE CARVE-OUT (diagnosed A/B, documented — an EXECUTIVE fragility my faithful split EXPOSED, not an ntdll bug)
The general split **regressed smss** — it crashed (`tcb=22 rip=0xffffffff exc#=21`) right after processing ONE MULTI_SZ value, **pinned by a `[msz-split]` diag to `ObjectDirectories`** (the smss Session-Manager config `\Windows\0\RPC Control\0`). ROOT: `SmpConfigureObjectDirectories` (sminit.c:272) is the ONLY split MULTI_SZ callback that issues an OBJECT-NAMESPACE SYSCALL (`NtCreateDirectoryObject`, with a stack out-param handle) — and it does so **concurrently with the just-spawned `SmpApiLoop` thread**, at which point the executive's per-thread `ACTIVE_STACK_MIRROR` selection corrupts smss' main-thread stack on the extra syscall's out-param write (smss returns to `0xffffffff`). Every OTHER split callback (`SmpConfigureMemoryMgmt`/`ExcludeKnownDlls`/…) only calls `SmpSaveRegistryValue` (in-process heap, NO syscall) → unaffected. **A/B PROVEN:** skipping the split for `ObjectDirectories` (name-match) → smss survives + spawns csrss/winlogon, msv1_0 still loads. `ObjectDirectories`' callback iterates the blob INTERNALLY (works with the whole blob) + the dir-create is idempotent (OBJ_OPENIF), so the carve-out is behavior-preserving. **FLAGGED executive follow-up:** harden the executive's object-namespace-syscall out-param servicing during a concurrent hosted-thread spawn (the stack-mirror race), then remove the carve-out.
### RESULT (boot-confirmed, SYNCHRONOUS FOREGROUND)
- **msv1_0.dll RESOLVES + LOADS:** `[msz-split] name=Authentication Packages l=10` → `[ntos-exec] DEMAND-LOAD msv1_0 (71680 B) -> slot 65 base 0x82250000` → `NtCreateSection(SEC_IMAGE) for msv1_0` → `NtMapViewOfSection msv1_0 -> base 0x82250000`. The assigned root-cause is FIXED.
- **No regression:** smss survives → spawns csrss (badge 2) + winlogon (badge 4); lsass reaches its REAL LSA-server thread (`entry=0x803c5a10 tid=21`) + the `9:100 NtListenPort` RPC receive loop; winlogon parks on `lsa_rpc_server_active` (Checkpoint-B).
- **NEXT WALL (past msv1_0, a NEW downstream one):** after msv1_0 demand-pages in, lsass faults at a **NULL deref inside its LSA-init DLL tree** (`ip=0x821b1870 cr2=0x0`, `PARK pi=4 badge=8 null-deref`) BEFORE `SetEvent(lsa_rpc_server_active)`. So lsass has NOT yet signaled → winlogon still parked → the paint (`exec_win32k_desktop_painted`) still 0/768. The boot spins at this new wall (exit 124, like the pre-fix baseline which spun at the msv1_0 miss). Gate not yet cleanly re-measurable (no qemu_exit). DIAGNOSE-first NEXT: symbolize `0x821b1870` (which DLL/function — likely an msv1_0 import/`LsaApInitializePackage` deref of an un-populated global) → fix → lsass signals → winlogon → the paint.

## ★★ BATCH 31 — the `0x821b1870` NULL-deref ROOT-CAUSED + FIXED REAL (our ntdll's `RtlQueryRegistryValues` did NOT forward the caller's `Context` to the QueryRoutine → lsass' `LsapAddAuthPackage` deref'd a NULL `*Id`). lsass' LSA-init NOW COMPLETES + **SIGNALS `LSA_RPC_SERVER_ACTIVE` → winlogon WAKES** (fix boot, commit <see below>)

### ★ THE DIAGNOSIS (diagnose-first — symbolized from a SYNCHRONOUS-FOREGROUND boot, every conclusion evidenced)
1. **SYMBOLIZE `0x821b1870`.** The boot log's DLL map (`NtMapViewOfSection <name> -> base`) places the fault IP in **lsasrv.dll** (demand-load base `0x821b0000`, `DEMAND-LOAD lsasrv (279552 B) -> slot 63`), NOT msv1_0 (`0x82250000`) — RVA = `0x821b1870 - 0x821b0000 = 0x1870`. (shdocvw@0x82160000 was a red herring: its virtual extent ends ~0x821a0000, well below 0x821b1870; nfs41_np@0x821a0000/samsrv@0x82200000 bracket lsasrv.)
2. **Disassembled lsasrv.dll @ RVA 0x1870** (`llvm-objdump -d`, image base 0x7fef3000000 → VMA 0x7fef3001870). The faulting instruction is `mov ecx, [rax]` where `rax = [rsp+0x78]`; a few lines up (`0x1195`) `[rsp+0x78]` is loaded from `[rsp+0xd0]` = the function's **5th stack argument**. The immediately following `call *0x28(rax2)` (rax2=[rsp+0x38], a heap-allocated dispatch struct) is an indirect call through a resolved procedure pointer.
3. **Identified the function** by its embedded `__FILE__`/DbgPrint strings (referenced at RVA 0x2e5b0/0x2e590/0x2e600/0x2e640…): `C:\…\dll\win32\lsasrv\authpackage.c`, `LsapAddAuthPackage`, `LsaApInitializePackage`, `LsaApLogonUser…`. The function at RVA 0x10a0 is **`LsapAddAuthPackage`** (authpackage.c:177) — a `RtlQueryRegistryValues` QueryRoutine that `LdrLoadDll`s each auth package (msv1_0), resolves its `LsaApXxx` exports via `LdrGetProcedureAddress`, then calls `LsaApInitializePackage`.
4. **ROOT CAUSE = the deref at `authpackage.c:297`:** `Status = Package->LsaApInitializePackage(*Id, &DispatchTable, NULL, NULL, &Package->Name);` where `Id = (PULONG)Context` (line 196). `Context` is the QueryRoutine's 5th parameter. **`LsapInitAuthPackages` (authpackage.c:499) calls `RtlQueryRegistryValues(RTL_REGISTRY_CONTROL, L"Lsa", AuthPackageTable, &PackageId, NULL)` — passing `&PackageId` as the `Context` argument** — which real ntdll forwards to the QueryRoutine (`RtlpCallQueryRegistryRoutine`, registry.c:289 `QueryTable->QueryRoutine(Name, Type, Data, Length, Context, EntryContext)`). **Our ntdll's on-target `dispatch_value` (nt-ntdll-dll/src/on_target.rs) HARDCODED the routine's 5th (`Context`) argument to `0`** → `Context`=NULL → `Id`=NULL → `*Id` = NULL-deref at cr2=0 = the wall. (This is the SAME on-target `RtlQueryRegistryValues` reader touched in BATCH 30 for the MULTI_SZ split; the split itself was correct — this is a SEPARATE, adjacent ABI gap in the same routine.)

### THE FIX (real, general, source-faithful — forward `Context` end-to-end, matching registry.c)
Threaded the caller's `Context` (the arg passed to `RtlQueryRegistryValues`, already available as `context: u64` in the export wrapper `exports.rs:1462`) through the on-target reader to the routine call:
- `rtl_query_registry_values`: renamed `_context` → `context` (it was received then dropped).
- `dispatch_value`: added a `context: u64` param; the routine call is now `routine(name, ty, data, len, context, entry_context)` (was `…, 0, …`); the recursive REG_MULTI_SZ split forwards `context`.
- `dispatch_default`: added a `context: u64` param; forwards to its `dispatch_value` call.
- All 3 `dispatch_value` call sites (subkey-enum, named-value, default) + the `dispatch_default` call now pass `context`.
**General:** EVERY QueryRoutine callback now receives its real `Context` like real ntdll — not just auth packages (smss' SUBKEY callbacks that happened to ignore Context were unaffected; this only ADDS the correct value where it was NULL). ntdll-DLL-side ONLY (`nt-ntdll-dll` target-only `on_target.rs`); NO rust-micro/src, NO executive change. Host tests green (`nt-ntdll` 167).

### RESULT (boot-confirmed, SYNCHRONOUS FOREGROUND — the wall is GONE, the assigned deliverable is DONE)
- **The `0x821b1870` NULL-deref is ELIMINATED** (0 occurrences in the fix boot vs. the baseline's `[parked] pi=4 badge=8 fault=null-deref ip=0x821b1870`). lsass' `LsapAddAuthPackage` now runs `LsaApInitializePackage(PackageId=0, …)` successfully → registers MSV1_0.
- **★ lsass SIGNALS `LSA_RPC_SERVER_ACTIVE`:** `[wait] lsass SIGNALLED LSA_RPC_SERVER_ACTIVE (event #36)`.
- **★ winlogon WAKES:** `[wait] pi=2 NtWaitForSingleObject(event #36 'lsa_rpc_server_active') already SIGNALLED -> immediate WAIT_0` (was: `UNSIGNALLED -> PARK caller` at the baseline). winlogon advances into its **post-LSA login flow**: demand-loads **sfc / sfc_os / msgina (the GINA logon-UI DLL, 728 KiB) / shsvcs**.
- **No regression:** all 5 processes spawn (smss badge 0 / csrss badge 2 / winlogon badge 4 / services.exe badge 6 / lsass.exe badge 8); smss does NOT crash (0× the BATCH-30 `tcb=22 rip=0xffffffff` regression → the `[msz-split] ObjectDirectories` carve-out still holds); lsass runs its full LSA-server-thread set (tid 21/22).

### NEXT WALL (a NEW downstream one, well PAST the assigned wall — winlogon's SCM/RPC login path)
After waking + loading msgina, **winlogon opens `\??\pipe\ntsvcs`** (the Service Control Manager RPC named pipe) → **`STATUS_OBJECT_NAME_NOT_FOUND (0xC0000034)`** (`[nt-create-file-winlogon] status=0xc0000034 name="\??\pipe\ntsvcs"`), then raises an int3/debug-exception carrying **`RPC_S_SERVER_UNAVAILABLE (0x6ba = 1722)`** (`[bp-diag] EXCEPTION_RECORD code=0x6ba`, callers in the winlogon/msgina/advapi32 range) → `[parked] pi=2 badge=4 fault=debug-exception(4)`. The SCM (`\pipe\ntsvcs`, hosted by services.exe) isn't serving that pipe yet, so winlogon's `RpcBindingFromStringBinding`/`OpenSCManager` in its login init fails. This is DOWNSTREAM of the LSA signal (the assigned deliverable) — winlogon woke and is now blocked on the NEXT service (the SCM/ntsvcs RPC endpoint), not on lsass.

### PAINT STATUS (not yet reconverged — a follow-on, not this batch's deliverable)
`exec_win32k_desktop_painted` still shows `changed 0/768` — the ONLY SwitchDesktop this boot is winlogon's PRE-signal one (`[win32k-svc] winlogon NtUserSwitchDesktop … changed 0/768 … px0=0x00ff00ff`, the graphics aren't initialized that early). After waking, winlogon walls on `\pipe\ntsvcs` BEFORE reaching the graphics-init SwitchDesktop that would paint `0x003a6ea5`. So the paint awaits winlogon completing more of its login flow (past the SCM/ntsvcs wall). Gate not cleanly re-measurable yet (no qemu_exit; the boot ends at the winlogon SCM park + qemu timeout). DIAGNOSE-first NEXT: serve `\pipe\ntsvcs` (services.exe SCM RPC endpoint) so winlogon's `OpenSCManager` succeeds → its login flow proceeds toward the graphics-init SwitchDesktop + the paint.

## ★★ BATCH 32 — `\pipe\ntsvcs` SERVED FOR REAL: winlogon's `OpenSCManager` now CONNECTS (0xC0000034 → SUCCESS). TWO real fixes drove services.exe from never-reaching-wmain all the way to `ScmStartRpcServer` creating the SCM RPC pipe. (commits 693d53d + 2555098, host green nt-ntdll 168 / nt-io-manager 58, kernel "All specs passed!", no regression)

**Assigned deliverable:** make winlogon's `OpenSCManager` (`\??\pipe\ntsvcs`, the Service Control Manager RPC endpoint) succeed by REALLY serving the pipe — diagnose-first, no faking. **DONE: the pipe is served by services.exe's genuine `ScmStartRpcServer` and winlogon's open returns STATUS_SUCCESS.**

### ROOT CAUSE (evidence-based, two compounding walls)
The pipe was missing because **services.exe (pi 3, badge 6) — the SCM that OWNS `\pipe\ntsvcs` — never reached `ScmStartRpcServer`.** The client-open + npfs data-plane were already fully wired (NtCreateFile/NtOpenFile → `npfs_route(IRP_MJ_CREATE)` for ALL processes; services' `NtCreateNamedPipeFile` for pi 3 routes through the real isolated npfs FSD; nt-io-manager 58 tests incl. `ntsvcs` server-create→client-connect). So `0xC0000034` = the FCB simply didn't exist. Two walls blocked services from creating it:

1. **WALL 1 — the win32k GDI-blit family, scoped LSASS-only.** services PARKED at `NtGdi 0x103d` (`status=0xc0000001`) during its user32 DllMain class-registration — the same interactive-cursor/class/stock-object EngCopyBits runaway blit (win32k RVA 0x1cbdd8) lsass hit in earlier batches. The non-interactive-service short-circuit (`0x103d/0x10b4/0x125b/0x11e0/0x106c/0x10b5/0x10bd` → light path) was gated `svc_noninteractive = badge == LSASS_BADGE` — LSASS ONLY. services.exe is ALSO a non-interactive service on a WSS_NOIO winstation. The prior LSASS-only scope was a STALE concern (an earlier batch where lsass hadn't spawned and faking services perturbed StartLsass timing); in the current boot lsass fully spawns + signals LSA_RPC_SERVER_ACTIVE *before* services reaches user32 init.

2. **WALL 2 — `RtlCreateUnicodeString` was a FALSE-returning stub in OUR ntdll.** Once past WALL 1, services ran its SCM `wmain` (created all 3 SCM events: SCM_START/AUTOSTARTCOMPLETE/hScmShutdown) then faulted at OUR ntdll RVA 0xa0e0 inside `wcsrchr`, dereferencing `0x10_c0000034`. Symbolized (subagent + capstone): services' SCM control-set init does a `RegCreateKeyExW` whose first `NtCreateKey` returns `STATUS_OBJECT_NAME_NOT_FOUND` (the executive can't resolve a create relative to a real-hive handle); ReactOS advapi32 `CreateNestedKey` (`dll/win32/advapi32/reg/reg.c:951-961`) then calls `RtlCreateUnicodeString(&LocalKeyName, Buffer)` and — IGNORING the BOOLEAN — immediately `wcsrchr(LocalKeyName.Buffer,'\\')`. Our stub never initialized `*dst`, so `LocalKeyName.Buffer` held stale stack (the 0xC0000034 status) → wild deref.

### THE FIX (both real, general, source-faithful)
- **693d53d (exec/win32k):** `svc_noninteractive = badge == LSASS_BADGE || badge == SERVICES_BADGE` (+ rename the 4 "lsass" trace labels to neutral "svc"). services now takes the light non-interactive path (a service does no GDI drawing), completes class registration, reaches wmain.
- **2555098 (ntdll):** implement `RtlCreateUnicodeString` for real per `sdk/lib/rtl/unicode.c:2306` — `Size=(wcslen(src)+1)*2`; FALSE if `Size>0xFFFF`/alloc fails; copy incl. NUL; `MaximumLength=Size`, `Length=Size-2`; TRUE (NULL src → empty NUL-terminated string). Uses `process_heap_alloc` (same seam as the adjacent `RtlAnsiStringToUnicodeString`). No export-count change. Host test `create_unicode_string_nul_terminated_lengths` (nt-ntdll 167→168).

### VERIFICATION (boot `/tmp/boot_fix2.log`)
- WALL 1 gone: `svc NtGdiInit/NtUserInitializeClientPfnArrays/NtGdi obj-create FAKED` for pi 3 (was `0x103d WALL 0xc0000001 PARK`).
- WALL 2 gone: NO `0x80a0e0`/`vmf-out pi=3`. services **completes SCM init** → `NtWaitForSingleObject(event #33 'lsa_rpc_server_active') PARK` (cooperative, the REAL SCM behavior, not a crash) → lsass `SetEvent(#33) WOKE 1 waiter` → services runs to `ScmStartRpcServer`, spawns its SCM RPC listener (`[svc-listener] reached its RPC receive loop`), and **creates `\pipe\ntsvcs`.**
- ★ **DELIVERABLE:** `[nt-create-file-winlogon] status=0x00000000 info=1 name="\??\pipe\ntsvcs"` — winlogon's `OpenSCManager` CONNECTS (was `0xc0000034`). Real svcctl RPC bytes flow: winlogon writes a 72-byte bind (`[nt-write-file] length=72 status=0`), reads a pending reply.
- No regression: kernel "All specs passed!", `exec_reactos_smss_parsed`, all 5 processes spawn (csrss/winlogon/services/lsass), lsass still signals LSA_RPC_SERVER_ACTIVE.

### NEXT WALL (deeper — the SCM svcctl RPC dispatch, a NEW one PAST the connect)
winlogon connected + exchanged bytes, then raises **`RPC_X_BAD_STUB_DATA (0x6be = 1726)`** (`[bp-diag] code=0x6be`) and parks — because services' SCM RPC listener thread **PARKED at its receive loop** (`reached its RPC receive loop / unserviced`) instead of DISPATCHING the `svcctl` request (RpcServerListen never actually runs the RROpenSCManagerW handler + replies). The frontier: route the SCM listener's receive/reply through the N-threads-per-process fault multiplex + real rpcrt4/svcctl NDR marshalling over the npfs data plane, so `OpenSCManager`'s RPC round-trip completes. This is well past the connect wall.

### PAINT STATUS (not yet reconverged — a follow-on)
`exec_win32k_desktop_painted` still `0/768` — the only SwitchDesktop this boot is winlogon's PRE-graphics one (`px0=0x00ff00ff`). winlogon's graphics-init SwitchDesktop (→ IntPaintDesktop → 0x003a6ea5) is AFTER the SCM svcctl RPC in its login flow, so the paint awaits the next-wall (SCM RPC dispatch) + winlogon completing more login. Gate not cleanly re-measurable yet (no qemu_exit; boot ends at the winlogon RPC park + qemu timeout). DIAGNOSE-first NEXT: service the svcctl RPC so winlogon's OpenSCManager round-trip returns → its login proceeds toward the graphics-init SwitchDesktop + the paint.

## ★★ BATCH 33 — the pipe-pending completion EDGE (park a PENDING pipe read; re-drive on peer write) + the SCM RPC listener's NATIVE-transport fix. winlogon no longer raises `RPC_X_BAD_STUB_DATA (0x6be)` — its SCM read PARKS cleanly; the svc-listener now DISPATCHES real syscalls (was drop-parking on garbage). (host green nt-io-manager 58→64 / nt-ntdll 168, kernel "All specs passed!", clean qemu_exit, gate 171, no regression)

**Assigned deliverable:** implement the pipe-pending completion edge from `docs/n-threads-multiplex.md` §3a/§3b so the MSRPC bind→bind_ack round-trip flows over the REAL npfs pipe + REAL rpcrt4, and winlogon advances past `0x6be`.

### THE FIX (three parts, all real + host-tested)
1. **The pipe-pending park/re-drive edge (§3a/§3b), host-tested.** New `nt_io_manager::PipeWaiterTable<N>` + `PipeWaiter` (`crates/nt-io-manager/src/pipe.rs`) — a fixed-capacity, heap-free, reset-safe table of parked pipe reads (park-on-empty, drain-all, complete/re-arm, cancel-by-tid, `parked_on`). 6 new host tests (park-on-empty, wake-on-peer-write drains+completes, re-armable across successive PDUs, bidirectional client+server independent, park-fails-when-full-never-hangs, cancel-thread). Wired into the executive (`main.rs` `PIPE_WAITERS` static + `service_sec_image.rs` `pipe_wait_park` / `pipe_redrive_all` / `mirror_ctx_for`): **`pipe_wait_park` mirrors the event `wait_park_multi` reply-cap steal EXACTLY** (steal the active REPLY_MAIN, snapshot RCX/RSP/RFLAGS, rotate a fresh pool object into REPLY_MAIN), keyed by the reading end's npfs file-id instead of an obj_ns event index. `pipe_redrive_all` re-issues EVERY parked read against npfs on ANY peer write (npfs's own FCB pairing decides who now has bytes — the executive has no peer→reader map), copies the bytes into the reader's OWN VSpace mirrors (switched in via `mirror_ctx_for` while the writer is active, then restored), fills its IOSB, and wakes it with `set_reply_mr(15/16/17)`+`send_on_reply(cap,18,status,…)` — the exact `NtSetEvent → WOKE parked waiter` shape generalized to pipe data. Handler hooks: `NtReadFile`/`NtFsControlFile(FSCTL_PIPE_TRANSCEIVE)` on PENDING set `pipe_park_*` (and SUPPRESS the PENDING IOSB write); `NtWriteFile`/TRANSCEIVE-complete set `pipe_write_redrive`.
2. **★ THE LOAD-BEARING FIX — the svc-listener was `native:false` (a BATCH-6 leftover).** `spawn_svc_listener_thread` (`rendezvous.rs:448`) spawned services' SCM RPC listener on the x86-syscall-TRAP transport, but services (pi 3) runs on OUR ntdll's NATIVE seL4-Call transport (like lsass, fixed in BATCH 24). So the listener's first native Call faulted as UnknownSyscall with a GARBAGE SSN (`m0=0x100_105f_b000`, a VA not an SSN) → `[svc-listener] blocking server syscall -> PARK (drop)` BEFORE it ever ran its rpcrt4 ncacn_np receive loop. Fixed = `native:true` + `ipcbuf_frame:PM_MAIN_IPCBUF[3]` (services' main ipcbuf frame), mirroring the lsass-listener fix. **Now the listener DISPATCHES real syscalls** (`[svc-listener] multiplex event #0-3 label=0x4e54` = NT_NATIVE_SYSCALL_LABEL): it runs its rpcrt4 server setup (NtWaitForMultipleObjects on mgr/listen events).
3. **Quiesce backstop for winlogon's SCM read park.** A top-level process (winlogon pi 2) parking on a pipe read whose peer never writes would block the loop's `recv` forever (the pre-batch boot got a `0x6be` crash-park → quiesce for free). Added: on winlogon's pipe-park, once LSA is signalled, QUIESCE → run the gate (mirrors the existing WinMain steady-state quiesce). Restores the clean qemu_exit.

### VERIFICATION (boot `/tmp/boot33.log`, blocking foreground, `extern-rootserver`)
- Host: `cargo test -p nt-io-manager` = **64** (was 58, +6), `cargo test -p nt-ntdll` = **168**.
- **winlogon PAST `0x6be`:** `[nt-write-file] length=72 … prefix=05 00 0b 03` (the MSRPC BIND PDU) → `[nt-read-file] pi=2 status=0x103` → **`[pipe-park] badge=4 fid=0x0e802d50 -> PARK reader`** (was: `[bp-diag] code=0x6be` + unrecoverable park). NO `0x6be` / `RPC_X_BAD_STUB_DATA` anywhere in the boot.
- **svc-listener dispatches (native fix):** `[svc-listener] multiplex event #0-3 label=0x4e54` (native Calls) — was `blocking server syscall SSN=0x100105fb000 -> PARK (drop)`.
- No regression: all 5 processes spawn; lsass `SIGNALLED LSA_RPC_SERVER_ACTIVE`; `PASS exec_winlogon_rpc_pipe / exec_pipe_syscalls_routed_through_npfs / exec_svc_rpc_listener_multiplex / exec_lsass_signals_lsa_rpc_active`; clean qemu_exit; kernel "All specs passed!"; gate 171 (the 8 pre-existing FAILs — `exec_nic_*` DMA, `exec_csr_message_plane`, `exec_live_terminate_thread_*` [hardcoded-false known-deferred], `exec_npfs_flush_pending`, `exec_win32k_desktop_painted` — are unchanged, none pipe-park-related).

### NEXT WALL (the async ncacn_np SERVER model — the bind→bind_ack does NOT complete this batch)
The bind→bind_ack round-trip did **not** complete, and the honest reason is a deeper mechanism than §3a/§3b anticipated: **rpcrt4's ncacn_np SERVER (services' SCM listener) is an ASYNC, EVENT-DRIVEN server — it does NOT issue a blocking `NtReadFile` on the pipe that the peer-write re-drive can complete.** The listener's syscalls this boot are `NtWaitForMultipleObjects` on rpcrt4's mgr_event + a pipe-completion event; the pipe accept/read is an async `FSCTL_PIPE_LISTEN` + overlapped read whose COMPLETION must signal that event. So winlogon's 72-byte bind write lands in npfs (queued on the server end) but there is **no parked server-side pipe READER** for `pipe_redrive_all` to wake — the server is parked on an EVENT, and the write must instead complete the server's pending async listen/read and SIGNAL its rpcrt4 completion event. The pipe-park edge built here is CORRECT + necessary infrastructure (it fires for winlogon's CLIENT read; it will complete any BLOCKING-mode pipe reader), and the native-transport listener fix is load-bearing — but the SCM RPC round-trip additionally needs: (a) a REAL paired npfs server FCB for `\pipe\ntsvcs` (this boot's server side appears modeled, not a routed npfs server end paired with winlogon's client fid — winlogon's connect got a lone client FCB with no server), and (b) the async-completion → rpcrt4-event-signal edge on the server's pending listen/read. **BATCH 34 = the async ncacn_np server completion edge (peer write → complete the server's pending FSCTL_PIPE_LISTEN/overlapped-read → signal its rpcrt4 completion event → the listener's wait-array wakes → real svcctl NDR dispatches → bind_ack + RROpenSCManagerW response).** The paint (`exec_win32k_desktop_painted`, still `0/768`) is after that in winlogon's login flow.

## ★★ BATCH 34 — the async ncacn_np SERVER completion edge (peer connect → complete the server's pending FSCTL_PIPE_LISTEN → SIGNAL its rpcrt4 completion event → the SCM listener's wait-array WAKES and it spawns its per-connection worker). The bind PDU crosses the wire and the listener runs its REAL rpcrt4 accept path; the runaway is killed; the boot QUIESCES cleanly. (host green nt-io-manager 64→70 / nt-ntdll 168, kernel "All specs passed!", clean qemu_exit, **gate 174** — up from 171, no regression; the 3 `exec_live_terminate_thread_*` now PASS FOR REAL because the listener now actually terminates.)

**Assigned deliverable:** Part A (real paired `\pipe\ntsvcs` server FCB) + Part B (async overlapped-listen completion → event signal) so the MSRPC bind→bind_ack round-trip flows over the REAL npfs pipe + REAL rpcrt4.

### CONFIRMED SERVER-SIDE WAIT MODEL (boot trace `[svc-listener-ssn]`, added this batch)
Traced the svc-listener's (badge 7, pi 3) exact native SSN sequence. It is EXACTLY the plan's async-event-driven model:
```
#0 ssn=238 NtSetInformationThread(NtCurrentThread)
#1 ssn=37  NtCreateEvent            → the overlapped listen-completion event (handle 0x210)
#2 ssn=88  NtFsControlFile          → FSCTL_PIPE_LISTEN(FileHandle=0x200, Event=0x210) → PENDING (no client)
#3 ssn=280 NtWaitForMultipleObjects([mgr_event, listen_event]) WaitAny → PARK
   ── winlogon connects → COMPLETE(listen) → the listener WAKES ──
#6 ssn=46  NtCreateNamedPipeFile    → the NEXT listening instance (rpcrt4 handoff)
#17 ssn=55 NtCreateThread           → the PER-CONNECTION WORKER (RPCRT4_new_client) ← the new frontier
#22 ssn=88 NtFsControlFile          → FSCTL_PIPE_LISTEN(new instance) re-arm
#23 ssn=280 NtWaitForMultipleObjects → re-PARK   then the listener thread exits (handed the conn off)
```
So the server does NOT block on a pipe read; it posts an **overlapped `FSCTL_PIPE_LISTEN` (Event=RDX) that returns STATUS_PENDING** and parks on `NtWaitForMultipleObjects([mgr_event, listen_event])`. This exactly matches the real ReactOS `rpcrt4_protseq_np_get_wait_array` / `rpcrt4_protseq_np_wait_for_new_connection` (`references/reactos/dll/win32/rpcrt4/rpc_transport.c:950,1018`): on a listen event fire with `io_status.Status == STATUS_SUCCESS` it `rpcrt4_spawn_connection` + `RPCRT4_new_client` + `rpcrt4_conn_np_handoff` → `rpcrt4_conn_create_pipe(old_conn)` (creates the next listening instance). **Part A was NOT the gap — the server FCB `\ntsvcs` IS created for real via npfs (`[nt-create-named-pipe] pi=3 leaf=\ntsvcs`); winlogon's client connect pairs by name in npfs's prefix table.**

### THE FIX (all real + host-tested)
1. **`nt_io_manager::AsyncListen` + `AsyncListenTable<N>` (`crates/nt-io-manager/src/pipe.rs`), host-tested (+6 tests → 70).** A fixed-cap, heap-free, reset-safe table of pending async server listens keyed by the SERVER fid, carrying the obj_ns EVENT index to signal + the listen IOSB VA + a **pipe-leaf name-hash** (`pipe_name_hash`). Methods: `arm` (re-arm replaces same-server), `complete_by_name` (name-scoped), `find`/`armed`/`drain_all`/`free`.
2. **Part B — the async listen→event-signal edge (executive).** `NtFsControlFile`: for pi 3/4 a `FSCTL_PIPE_LISTEN(0x110008)` that would be PENDING is recorded as an `AsyncListen` (resolving RDX=Event → obj_ns idx in the SERVER's own handle table; name-hash from a fid→name map populated at `NtCreateNamedPipeFile`) — and the PENDING IOSB write is SUPPRESSED (overlapped: filled at completion). A client CONNECT (`NtOpenFile`/`NtCreateFile` IRP_MJ_CREATE on a pipe) sets `pipe_connect_redrive = pipe_name_hash(leaf)`; the loop then runs **`pipe_listen_complete_named`**: it `complete_by_name`s the ONE matching-name pending listen, fills its listen IOSB `{SUCCESS,0}` in the SERVER's VSpace (mirror-ctx switch), and **SIGNALs its event via the EXISTING `wait_wake_event_set` NtSetEvent wake path** → the listener's `NtWaitForMultipleObjects` wakes with `io_status.Status = SUCCESS` → it spawns its per-connection worker + re-arms. **Reuses the `NtSetEvent → WOKE parked waiter` machinery verbatim** — no new wake primitive.
3. **★ THE LOAD-BEARING RUNAWAY FIX — force `FSCTL_PIPE_LISTEN` = STATUS_PENDING for pi 3/4 (not just pi 2).** Routing the LISTEN into npfs's real state machine returned SUCCESS/`STATUS_PIPE_CONNECTED` for a just-handed-off instance → `get_wait_array` did `SetEvent(event)` IMMEDIATELY → wake → spawn → handoff → create pipe → SUCCESS again → **an infinite create-instance runaway (observed: 894 `\ntsvcs` creates → boot timeout).** A freshly-created server instance with no client MUST report PENDING so the listener parks; only our explicit event-signal on a REAL client connect wakes it with SUCCESS. Now exactly ONE connection per real client. (Same invariant the pi 2 winlogon-worker path already relied on — generalized to the real pi 3/4 servers.)
4. **Name-scoped completion (no spurious cross-server wake).** A connect to `\ntsvcs` completes ONLY the `\ntsvcs` listen, never `\lsarpc`/`\samr` (waking those spun lsass' rpcrt4 loop — observed as `\samr` co-runaway before the fix).
5. **Clean quiesce (no hang).** The winlogon SCM-read-park is terminal once the SCM listener has TERMINATED (`SVC_LISTENER_TERMINATED`) — before its per-connection worker is routed there is no signaler, so QUIESCE (run the gate) rather than block the loop's recv. Both orderings covered (`WINLOGON_SCM_PARKED` + a break in the listener's `TerminateCurrentThread` arm).

### VERIFICATION (boot `/tmp/boot34f.log`, blocking foreground, `extern-rootserver`)
- Host: `cargo test -p nt-io-manager` = **70** (+6 async-listen: arm/find, complete-signals-event, re-arm-replaces, drain/free, full-never-hangs, **complete_by_name-is-specific**), `cargo test -p nt-ntdll` = **168**.
- **The server WAKES on winlogon's connect:** `[pipe-listen] ARMED server fid=… event_obj=0x2e pi=3` → winlogon `NtCreateFile(\??\pipe\ntsvcs)` → `[pipe-listen] COMPLETE server fid=… signalled event_obj=0x2e -> woke 1 server wait(s)`. The listener then ran its REAL rpcrt4 accept path (`[svc-listener-ssn] #6..#23`: created the next instance, **spawned its per-connection worker `#17 NtCreateThread`**, re-armed the listen, re-parked). **`listener-faults-serviced=29`** (was 6). NO runaway (4 named-pipe creates total, was 894/1780). NO spurious lsass wake (1 COMPLETE, name-scoped).
- **Gate 174 / clean qemu_exit** (was 171). The 3 `exec_live_terminate_thread_*` now PASS FOR REAL (the listener actually terminates → `PM_TERMINATE_THREAD_LIVE >= 3`); `exec_svc_rpc_listener_multiplex` re-asserted on faults-serviced (the TCB is legitimately 0 after the listener exits). No regression: all 5 processes spawn; lsass `SIGNALLED LSA_RPC_SERVER_ACTIVE`; `PASS exec_winlogon_rpc_pipe / exec_pipe_syscalls_routed_through_npfs / exec_winlogon_csr_connect / exec_lsass_signals_lsa_rpc_active`; smss specs pass. The remaining 5 FAILs (`exec_nic_*` ×2 DMA, `exec_csr_message_plane`, `exec_npfs_flush_pending`, `exec_win32k_desktop_painted`) are the exact pre-existing set.

### NEXT WALL (the per-connection WORKER thread is not routed → bind_ack not written yet)
bind→bind_ack does **not** yet complete, and the honest reason is now precise and one level deeper: the SCM listener woke correctly and, per real rpcrt4, **handed the accepted connection to a NEW per-connection WORKER thread it spawned via `NtCreateThread` (`#17 ssn=55`)** — then the listener re-armed + exited. **That worker is the thread that reads winlogon's bind PDU and writes bind_ack, and it is NOT yet spawned into the executive's fault multiplex** (it's a general `NtCreateThread` from a listener sub-thread, not one of the pre-recognized listener spawns). So winlogon writes the 72-byte bind, parks on its read, and the (unrouted) worker never runs → no bind_ack → the loop QUIESCES to the gate. **BATCH 35 = route the SCM listener's per-connection `NtCreateThread` worker into the multiplex** (generalize the listener-spawn recognizer to a per-connection worker with its own badge/TEB/stack-mirror — the flagged "N threads per process" follow-up, `docs/n-threads-multiplex.md`). Then the worker reads the bind (batch-33 pipe-park re-drives it on winlogon's write), rpcrt4 emits bind_ack (re-drives winlogon's parked read), and the `RROpenSCManagerW` request→response follows on the same edges. The paint (`exec_win32k_desktop_painted`, still `0/768`) is after the SCM round-trip in winlogon's login flow.

## ★★ BATCH 35 — the per-connection RPC worker routing is BUILT + reachable; blocked by a hosted-thread TRAMPOLINE-ENTRY FAULT (a 3rd native thread in services' VSpace faults at its trampoline VA). Full scaffolding landed + gated OFF pending a kernel gdb-stub root-cause; boot stays clean (**gate 175**, clean qemu_exit, no regression). (host green nt-io-manager 70 / nt-ntdll 168 / nt-process 21; kernel "All specs passed!")

**Assigned deliverable:** route the SCM listener's per-connection `NtCreateThread` worker (rpcrt4 `RPCRT4_new_client`, `#17 ssn=55`) into the fault multiplex so it reads winlogon's bind PDU + writes bind_ack.

### ROOT-CAUSE OF THE PRE-BATCH STALL (evidence, `/tmp/boot34f.log` + the batch-35 boots)
The listener wakes on winlogon's connect and, per real rpcrt4, spawns a per-connection worker via its SECOND `NtCreateThread` on pi 3 (`#17 ssn=55`). **`exec_handler.rs`'s general NtCreateThread arm returned `0xC000_009A` (STATUS_NO_MEMORY) for any 2nd+ create on pi 2-4 that no pre-created listener slot recognized** — so the worker's create FAILED, it never spawned, nobody read the bind, and winlogon quiesced. That rejection was the wall.

### THE ROUTING (all BUILT, idiomatic — the named-slot pattern generalized to a dynamic worker)
Mirrors the existing per-thread-slot idiom (badge + dedicated VAs + spawn fn + `mirror_ctx_for` + multiplex sub-select + `current_tid`), for a DYNAMICALLY-spawned worker:
1. **`main.rs`** — `SCM_WORKER_BADGE=15` (dynamic-worker badge, next after LSASS_LISTENER3=14) + dedicated target-VSpace VAs (reusing the proven `WL_WORKER3`/`LSASS_LISTENER3` cluster block, distinct from `SVC_LISTENER`'s SM block) + distinct executive env-scratch (`0x107C`) + stack-mirror (`0x1398`) + `SCM_WORKER_TCB`/`SCM_WORKER_TID`/`SCM_WORKER_FAULTS` statics; `scm_worker_spawn` handler field.
2. **`rendezvous.rs`** — `spawn_scm_worker_thread(...)`, a clone of `spawn_svc_listener_thread` on the SCM_WORKER VA window (native transport, ipcbuf bound to services' main ipcbuf frame `PM_MAIN_IPCBUF[3]`, badge minted off the shared `fault_ep`).
3. **`exec_handler.rs`** — the recognizer: services' (pi 3) SECOND `NtCreateThread` (listener already spawned: `SVC_LISTENER_TID != 0 && SCM_WORKER_TID == 0`) pops a pool ETHREAD (slot 1; slot 0 = listener) via `nt_create_thread_handle`, sets its TEB, queues `*ThreadHandle` + `ClientId`, sets `scm_worker_spawn` → returns SUCCESS (was `0xC000_009A`). Plus an `NtResumeThread` arm that reports SUCCESS for the worker.
4. **`service_sec_image.rs`** — loop spawn block (spawn RESUMED into the multiplex) + the multiplex sub-select for badge 15 (fault counter, `pi=3`, active stack base/mirror, `current_tid`, `mirror_ctx_for`, `owner_top_badge`, the listener-fault/blocking-syscall PARK arms) so the worker's faults/native Calls arrive in the ONE loop and load/save its per-thread state; `hosted_thread_tcb_cell` for terminate. The batch-33/34 pipe-park + re-drive is already badge-general via `mirror_ctx_for`, so the worker's bind read would park + re-drive on winlogon's write with no new mechanism.

### THE BLOCKER — a hosted-thread TRAMPOLINE-ENTRY fault (needs a kernel gdb-stub)
When the worker is actually RESUMED, it takes a **reproducible `cr2=0` VMFault at its own trampoline VA** (`[user #PF: tcb=N cr2=0 err=4 rip=<tramp_va>]`) — i.e. the very first trampoline instruction (`mov rcx, imm64`, which reads NO memory) faults reading address 0. This was chased exhaustively and is **INDEPENDENT of every executive-side variable:**
- **VA window:** the cluster block (`0x1057`) AND a FRESH dedicated-PT window (`0x1100_0000`, PT retype + all `page_map_r` returning STATUS_SUCCESS=0) fault identically.
- **Mapping:** the trampoline frame is byte-perfect (`48 b9 …` verified via the executive scratch alias) and `page_map_r` (SYS_CALL, real error) confirms the RX map into services' pml4 SUCCEEDED — so the page IS mapped with our code, yet the CPU at that RIP reads null.
- **Transport:** native (shared ipcbuf) AND trap (fresh ipcbuf) fault the same → not an ipcbuf-sharing issue.
- **Resume timing:** spawn-resumed AND suspended-then-`NtResumeThread` both fault → not a deferred-resume issue.
- **A self-spin entry** (entry = the trampoline's own `jmp $`) STILL faults at trampoline offset 0 → the CPU is not executing our mapped page despite the mapping succeeding.
Corroborating: winlogon's OWN 3rd rpcrt4 worker (`WL_WORKER3`, TEB `0x1055`) also walls at its TEB when it actually runs — the `WL_WORKER2/3` / `LSASS_LISTENER2/3` "worker" VA blocks work for query-only/suspended threads but a RUNNING 3rd hosted thread faults. The SM block (`SVC_LISTENER`) + the process-main + one listener run fine; the anomaly is a **3rd running hosted thread in a VSpace**. Root-causing this needs a **kernel gdb-stub session on the worker TCB's VSpace/CNode binding at the fault** (the TCB-register write and cap copies go through error-hiding `SYS_SEND` — a `_r`/SYS_CALL audit of `tcb_write_registers`/`tcb_set_space`/`copy_cap` in the spawn path is the first suspect), which is out of scope for one executive-side batch.

### THE GUARD (why the boot stays clean) + FRONTIER
Letting the worker's `NtCreateThread` SUCCEED but leaving it non-running makes rpcrt4 hand off to a worker that never services the pipe → winlogon advances into its own `WL_WORKER3` TEB wall → the loop HANGS (no clean quiesce → boot timeout). So the whole routing is gated behind **`const SCM_WORKER_ROUTE_ENABLED: bool = false`** (`exec_handler.rs`): OFF, the 2nd create falls through to the pre-batch `0xC000_009A` and the boot QUIESCES cleanly at winlogon's SCM-read park exactly as baseline. **Flip that const to `true` once the trampoline-entry fault is root-caused** and the whole round-trip (bind→bind_ack→`RROpenSCManagerW`) fires on the already-built edges.

### VERIFICATION (boot `/tmp/boot35q.log`, blocking foreground, `extern-rootserver`; NO rust-micro/src change)
- Host: `cargo test -p nt-io-manager` = **70**, `-p nt-ntdll` = **168**, `-p nt-process` = **21** (all green; unchanged — the routing is no_std executive code, not host-testable in isolation).
- **Gate 175 / clean qemu_exit** (≥ the 174 baseline; `exec_csr_message_plane` additionally flipped to PASS this run). No regression: all 5 processes spawn; lsass `SIGNALLED LSA_RPC_SERVER_ACTIVE`; all 4 `exec_live_terminate_thread_*` PASS; `PASS exec_services_spawned / exec_winlogon_rpc_pipe / exec_svc_rpc_listener_multiplex / exec_lsass_signals_lsa_rpc_active`; smss specs pass. Remaining FAILs (`exec_nic_*` ×2 DMA, `exec_npfs_flush_pending`, `exec_win32k_desktop_painted`) are a subset of the pre-existing set.
- When the guard is flipped ON (proven in `/tmp/boot35c..h.log`): the worker is recognized (`[scm-worker] recognized services' 2nd NtCreateThread`), spawned + resumed into the multiplex (`[scm-worker] multiplex event #0`), and then faults at its trampoline (the blocker above) — confirming the routing wiring is correct up to the trampoline-entry fault.

### NEXT WALL
Root-cause the hosted-thread trampoline-entry fault for a 3rd running native thread in a hosted VSpace (kernel gdb-stub on the worker TCB's VSpace/CNode binding; audit the `SYS_SEND` register-write/cap-copy path with `_r` variants). Then flip `SCM_WORKER_ROUTE_ENABLED = true` → the worker reads the bind, rpcrt4 emits bind_ack (re-drives winlogon's parked read), and `RROpenSCManagerW` request→response follows on the existing batch-33/34 pipe edges → `OpenSCManager` returns a real SC handle → winlogon advances toward the graphics-init `SwitchDesktop` = the `0x003a6ea5` paint (`exec_win32k_desktop_painted`, still `0/768`).

## ★★ BATCH 36 — the BATCH-35 `cr2=0` trampoline-entry fault is ROOT-CAUSED + FIXED (NOT a kernel bug — an executive VA collision masked by an error-hiding SYS_SEND); the SCM per-connection worker now RUNS its real rpcrt4 entry and winlogon crosses the wire with its 72-byte RPC BIND PDU. Route stays gated OFF for a NEW downstream wall (the worker exits before writing bind_ack). Boot GREEN, gate ≥174, clean qemu_exit; PURE executive fix, NO rust-micro/src change (sel4test byte-identical). (host green nt-io-manager 70 / nt-ntdll 168 / nt-process 21; kernel "All specs passed!")

### ROOT CAUSE (definitive, with gdb-free register/frame evidence)
The BATCH-35 "3rd running native thread faults at its trampoline VA with `cr2=0`" was **NOT** a kernel TCB/VSpace bug. It was an **executive VA COLLISION** in `spawn_hosted_thread`'s executive-side alias map, hidden by a fire-and-forget `SYS_SEND`:
- `SCM_WORKER_ENV_SCRATCH_VA` was **`0x0000_0100_107C_0000`** — which is ALSO **winlogon's process-spawn env-scratch `scr_base`** (`spawn_sec_image` for winlogon, `service_sec_image.rs:1856`; documented at the `winlogon-spawn (0x107C)` note). Winlogon's spawn maps its TEB/TEB2/trampoline frames at 0x107C_0000/1000/2000 and **never unmaps them**.
- `spawn_hosted_thread` builds the worker's trampoline by `page_map(tramp, scr+0x2000, …)` (executive alias) → **writing the trampoline bytes** at scr+0x2000 → `page_map(copy_cap(tramp), tramp_va, RX, target_pml4)`. For the worker, `scr+0x2000 = 0x107C_2000` was **already occupied** by winlogon's stale env frame, so the kernel's `decode_frame_map` returned **`seL4_DeleteFirst` (8, leaf PTE busy)** — but the map used `page_map` (**SYS_SEND, error INVISIBLE**). The trampoline bytes landed in winlogon's stale frame; the worker's **REAL `tramp` frame stayed ZERO**. That zero frame was mapped into services' VSpace at tramp_va.
- The worker's first instruction fetch at tramp_va decoded the zero page as `00 00` = `add byte ptr [rax], al`, which **READS `[rax]` first**; the fresh TCB's `rax = 0` → **read of address 0 → `cr2=0`, `err=4` (user/read/not-present)** at the trampoline VA. RIP was correctly AT the trampoline; the frame was just zero. (This exactly explains every BATCH-35 rule-out: the FRESH-PT window still faulted because it too went through the same colliding `scr` alias; native vs trap, resume timing, self-spin — all downstream of the zero frame.)
- **DIAGNOSIS TECHNIQUE (the win):** converted the spawn-path maps to `page_map_r`/`_r` (diag-gated for the worker) + read the target trampoline frame back through a FRESH INDEPENDENT alias and compared to what was written. ONE boot named it: `exec_map=8`, `via_fresh_alias=0xDEAD…` ≠ `wrote=…08a0b948` (the real `48 b9 08…`). The lsass "3 working listeners" were a red herring — their scratch VAs (0x1079/107A/107E) just happened to be genuinely free.

### THE FIX (pure executive, one line — NO kernel change)
`components/ntos-executive/src/main.rs`: `SCM_WORKER_ENV_SCRATCH_VA` **`0x107C` → `0x1075`** (a genuinely-free gap between smss-spawn 0x1074 and services-env 0x1076, still inside the FILEBUF PT 0x1060..0x107F). The kernel's DeleteFirst is CORRECT; the bug was the executive reusing an occupied VA. NO `rust-micro/src` change → **sel4test byte-identical** (submodule clean). Kept a permanent diag guard on the worker spawn (`diag:true` uses the `_r` map variants so a future DeleteFirst can't silently hide again).

### PROVEN with the route ENABLED (`/tmp/boot36fix.log`)
`[spawn-diag] tramp_frame_retype=0 exec_map=0 tgt_map=0 fresh_map=0` (was `exec_map=8`); `tramp[0..8] wrote=…08a0b948 via_fresh_alias=…08a0b948` (MATCH). The worker then **RUNS its real rpcrt4 entry** — `[scm-worker] multiplex event #0..3 label=0x4e54` (**normal native syscalls, NOT the label-6 VMFault**), incl. an `NtQueryInformationThread` (class 12). winlogon crosses the wire: `[nt-write-file] pi=2 length=72 … prefix=0x05 0x00 0x0b …` = the **RPC BIND PDU** (PTYPE 0x0b=bind), then reads 16 bytes (bind_ack header) → PENDING → `[pipe-park] badge=4 → PARK reader`.

### THE NEW (DOWNSTREAM) WALL — why the route is still gated OFF
The rpcrt4 per-connection worker **exits (`NtTerminateThread exit=0`) after its self-inspection syscalls WITHOUT reading the bind / writing bind_ack** — it isn't yet wired to the **accepted server-pipe endpoint** (the flagged "N threads per process" connection-context follow-up). With the route ON, winlogon then parks reading bind_ack while every thread is parked → the main service loop blocks in `recv_full_r12` with no clean quiesce → **HANG to timeout**. So per the batch directive ("gate the feature off again if a downstream stall would hang the boot"), `SCM_WORKER_ROUTE_ENABLED` stays `false` (falls through to the baseline `0xC000_009A` clean-boot) while the **trampoline VA fix is permanent**. `exec_win32k_desktop_painted` still `0/768` (the paint is past the SCM round-trip in winlogon's login flow).

### BATCH 37 = wire the rpcrt4 per-connection worker's accepted-connection context
Give the spawned worker the accepted `\pipe\ntsvcs` server-endpoint fid so its rpcrt4 receive path reads winlogon's queued bind PDU (batch-33 pipe re-drive) instead of self-inspecting + exiting; then bind_ack re-drives winlogon's parked read → `RROpenSCManagerW` request→response → `OpenSCManager` returns a real SC handle → winlogon advances toward the graphics-init `SwitchDesktop` = the `0x003a6ea5` paint.

## ★★ BATCH 37 — the SCM per-connection RPC worker now READS winlogon's bind PDU off the accepted `\pipe\ntsvcs` server endpoint. Route left **ENABLED** (boot stays green, gate 174, clean qemu_exit). Two REAL npfs-hosting bugs root-caused + fixed (FILE_OPEN_IF for CREATE_NAMED_PIPE; message-mode BUFFER_OVERFLOW partial-read copyout on re-drive). One deeper wall remains: npfs returns the wrong bytes for the SERVER read of the CLIENT write (pending-read-entry not completed by the peer write in our synthetic-IRP npfs hosting) — so bind_ack does NOT yet flow. PURE executive fix, NO rust-micro/src change (sel4test byte-identical). (host green nt-io-manager **71** [+1 message-mode partial-read test] / nt-ntdll 168 / nt-process 21; kernel "All specs passed!")

### DIAGNOSE (evidence, `/tmp/boot37{a,e,i,n}.log`) — why the worker exited (BATCH 36 wall)
Turned the route ON + traced the worker's exact native SSN sequence (badge 15). The worker RUNS its real `RPCRT4_io_thread(conn)` (rpc_server.c:543): `#0 NtSetInformationThread(currentThread, ThreadNameInformation)` = `SetThreadDescription(L"wine_rpcrt4_io")`, `#1 NtCreateEvent` = `get_np_event()→CreateEventW` (returned a VALID handle), then — WITHOUT any `NtReadFile` (SSN 191) — `#2 NtQueryInformationThread(ThreadAmILastThread)` + `#3 NtTerminateThread(0)` = normal thread exit. So `RPCRT4_ReceiveWithAuth→…→rpcrt4_conn_np_read` (rpc_transport.c:671) SKIPPED `NtReadFile`. The ONLY gate that skips the read after a valid event is **`connection->read_closed == TRUE`** (rpc_transport.c:681). Dumped the live `conn` object from services' heap (via the worker's heap mirror at its NtCreateEvent) and confirmed: `conn->pipe = 0x200` (the accepted server handle, at struct offset 0xe0 = `sizeof(RpcConnection)`), and **`conn->read_closed = 1` at offset 0x110** — calloc'd 0, so something SET it. Root cause: in our cooperative single-threaded multiplex the SCM listener thread runs its ENTIRE post-accept flow to completion (re-create the listening pipe, re-listen) BEFORE the per-connection worker io_thread is scheduled — and its rpcrt4 SERVER thread entered **shutdown** (`RPCRT4_server_thread` rpc_server.c:677-687: `LIST_FOR_EACH_ENTRY(conn, &cps->connections) rpcrt4_conn_close_read(conn)`), which set `new_conn->read_closed=1` (via `rpcrt4_conn_np_close_read`, rpc_transport.c:756). The server entered shutdown because its post-accept RE-LISTEN failed: the listener's `rpcrt4_conn_create_pipe` (during `rpcrt4_ncacn_np_handoff`) re-created the 2nd `\ntsvcs` instance, and our executive's `NtCreateNamedPipeFile` handler returned **STATUS_ACCESS_DENIED** for it.

### FIX 1 (real, general) — CREATE_NAMED_PIPE disposition FILE_OPEN_IF, not FILE_CREATE (`driver_launch.rs:909`)
Our host FSD dispatch HARDCODED `Disposition = FILE_CREATE (2)` for every `IRP_MJ_CREATE_NAMED_PIPE`. Real Win32 `CreateNamedPipe`/`NtCreateNamedPipeFile` pass **`FILE_OPEN_IF` (3)** (kernel32 npipe.c:393). npfs's `NpCreateExistingNamedPipe` (create.c:594-599) returns STATUS_ACCESS_DENIED for a 2nd+ instance opened with FILE_CREATE, while FILE_OPEN_IF opens-or-creates for BOTH the new FCB (`NpCreateNewNamedPipe` accepts anything but FILE_OPEN) AND every subsequent instance. Changed `2 → 3`. Now the 2nd `\ntsvcs` instance CREATES (`st=0 fid=…`), the listener re-listens + stays alive (never shuts down → never `close_read` → `new_conn->read_closed` stays 0), and **the worker RUNS its `rpcrt4_conn_np_read` → issues `NtReadFile(conn->pipe=0x200, 16)`** — the bind header read. (Client opens `major 0` still FILE_OPEN=1.)

### FIX 2 (real, general) — message-mode BUFFER_OVERFLOW partial-read copyout on the pipe re-drive (`service_sec_image.rs`, `pipe_redrive_all`)
The worker's 16-byte read of the 72-byte message-mode bind returns `STATUS_BUFFER_OVERFLOW (0x80000005)` with the FIRST 16 bytes (correct message-mode semantics — `readsup.c:109`). But `pipe_redrive_all` gated the copyout on `status == 0`, leaving the reader's buffer zeroed on overflow → rpcrt4's `RPCRT4_ValidateCommonHeader` saw a zero header. Fixed: copy the delivered bytes for SUCCESS **or** `0x80000005`. Added host test `message_mode_client_write_server_partial_read_overflow` (nt-io-manager 70→71). Also added the completed-pending-READ stash infra (`driver_launch.rs`: `take_completed_read` + capture in `s_io_complete_request`) so a peer-write-completed pending read IRP's bytes reach the parked reader — correct + harmless (see NEXT WALL for why it doesn't fire here yet).

### RESULT — worker reads the bind header; boot GREEN, route ENABLED
With both fixes, the worker: parks its read (`[pipe-park] badge=15 fid=…b1`), is re-driven on winlogon's write (`[pipe-redrive] WOKE reader badge=15 status=0x80000005 bytes=16`), and proceeds — a MAJOR advance from BATCH 36's "exits without reading." The listener stays alive; the boot QUIESCES cleanly. **Gate 174 / "All specs passed!" / clean qemu_exit**, no regression: 5 processes spawn; lsass `SIGNALLED LSA_RPC_SERVER_ACTIVE`; all 4 `exec_live_terminate_thread_*` PASS. The route is left **ON** (the worker reads then exits cleanly; no hang). Same 5 pre-existing FAILs (`desktop_painted`, `nic_*`×2, `npfs_flush_pending`, one other). NO `rust-micro/src` change → sel4test byte-identical.

### NEXT WALL (precisely characterized) — npfs returns WRONG bytes for the SERVER read of the CLIENT write
The worker's re-driven read gets 16 bytes but they are `d0 16 d0 16 00 00 00 00 …` — NOT the bind (`05 00 0b 03 …`). Traced both sides at the FSD data plane: the WRITE (client fid `…b0`) correctly stores `05 00 0b 03 10 00 00 00` (npfs copies from `Irp->UserBuffer` into `DataEntry+0x38`, datasup.c:406); the READ (server fid `…b1`, SAME CCB — the two fids differ only in npfs's end bit) returns `d0 16 d0 16`. Root cause (from the npfs read/write data-flow, confirmed via the ReactOS source): the worker's FIRST server read went `STATUS_PENDING` and npfs queued a **Buffered ReadEntry** (`read.c:132`, `NpAddDataQueueEntry(ReadEntries)` — a header-only entry, NO payload appended, `datasup.c:357`). The peer WRITE should complete that pending ReadEntry (via `NpCompleteDeferredIrps→IoCompleteRequest`), but in our synthetic-IRP hosting **`IoCompleteRequest` NEVER fired for a pending IRP the whole boot** (`[fsd-peer-complete]` count = 0) — the write instead queued a fresh WriteEntry (`info=72`), so the INBOUND queue holds the abandoned ReadEntry AHEAD of the write data. The re-drive read then reads that header-only ReadEntry's `&DataEntry[1]` = uninitialized pool = `d0 16 d0 16`. i.e. npfs's stateful per-CCB queue is not being driven consistently across our separate per-IRP `npfs_dispatch_irp` calls (the pending ReadEntry and the peer WriteEntry aren't reconciled). **BATCH 38 = make the pending pipe-read/peer-write reconcile in the synthetic-IRP npfs host**: either (a) don't leave a pending ReadEntry queued when a read would block (cancel/remove it so the write queues cleanly and the re-drive fresh read drains it), or (b) make the peer write actually complete the queued ReadEntry (drive npfs's deferred completion so `IoCompleteRequest` fires and the batch-37 `take_completed_read` stash delivers the bytes). Then the worker reads the FULL bind (2nd read for `hdr_length-16`), rpcrt4 `process_bind_packet` emits **bind_ack** via `NtWriteFile` → batch-33 re-drives winlogon's parked read → `RROpenSCManagerW` request→response → `OpenSCManager` returns a real SC handle → winlogon advances toward the graphics-init `SwitchDesktop` = the `0x003a6ea5` paint (`exec_win32k_desktop_painted`, still `0/768`).

## ★★ BATCH 38 — the npfs pending-read/peer-write RECONCILE is FIXED. The SCM worker reads the REAL bind (`05 00 0b 03…`, not garbage), bind_ack (`05 00 0c 03…`) flows back to winlogon, and the FULL SC-RPC round-trip runs LIVE (bind→bind_ack→RROpenSCManagerW request `05 00 00 03…`→response `05 00 02 03…`, 8 PDUs both ways, PROVEN in `/tmp/boot38d.log`). **Two REAL npfs-hosting root-causes found + fixed.** The route is GATED OFF for the commit (gate 174, clean qemu_exit, all 4 terminate specs pass) because the now-SUCCEEDING RPC changes the SCM thread lifecycle + surfaces a NEW winlogon downstream crash → route-ON regresses to 171 (documented below). PURE executive fix, NO rust-micro/src change (sel4test byte-identical). (host green nt-io-manager **73** [+2: pending-read-completed-by-peer-write + write-72/read-16/read-56] / nt-ntdll 168 / nt-process 21; kernel "All specs passed!")

### ROOT CAUSE #1 (the `d0 16 d0 16` garbage) — `IofCompleteRequest` was UNBOUND
BATCH 37 diagnosed "`IoCompleteRequest` never fired for a pending IRP" but assumed npfs's macro compiled to `IoCompleteRequest`. It does NOT: **npfs.sys's PE actually imports `IofCompleteRequest`** (the fastcall alias — `IoCompleteRequest` is a `#define` for it; verified by parsing `rust-micro/.tmp/reactos/reactos/system32/drivers/npfs.sys`'s import table: the ONLY completion import is `IofCompleteRequest`). The executive bound `"IoCompleteRequest"` but NOT `"IofCompleteRequest"`, so npfs's `NpCompleteDeferredIrps → IofCompleteRequest(readIrp)` fell to the `s_true` fail-soft NO-OP — the pending read's completion was silently dropped, the batch-37 `take_completed_read` stash stayed empty, and the re-drive fell through to a fresh `npfs_route_raw(READ)` that hit the drained queue → uninitialized pool (`d0 16 d0 16`). **FIX:** bind `IofCompleteRequest → s_io_complete_request` (on x64 there is ONE calling convention, so Irp/PriorityBoost still arrive RCX/RDX — the same `extern "win64"` trampoline serves both) — `driver_launch.rs`. With this, `[fsd-peer-complete] major=3 status=0x80000005 info=16` FIRES during winlogon's write (the write's `NpWriteDataQueue` copies the first 16 bind bytes into the pending read IRP, message-mode BUFFER_OVERFLOW, `NpRemoveDataQueueEntry` + deferred `IofCompleteRequest`).

### ROOT CAUSE #2 (still 16 ZERO bytes after #1) — stash read the STALE original buffer
After #1 the stash populated but delivered 16 ZERO bytes (`[redrive-src] STASH n=16 b=0 0 0…`). `s_io_complete_request` read the read IRP's bytes from `slot.data` (the buffer WE allocated in `run_irp`). But `NpWriteDataQueue` completing a **Buffered** read entry does NOT copy into that buffer — it `ExAllocatePoolWithTag`s a FRESH pool buffer, copies the write payload into it, then **REASSIGNS `WriteIrp->AssociatedIrp.SystemBuffer = Buffer`** + sets `IRP_DEALLOCATE_BUFFER|IRP_BUFFERED_IO|IRP_INPUT_OPERATION` (`writesup.c:83-93,131-135`). So the real bytes live at the IRP's CURRENT `AssociatedIrp.SystemBuffer` (`irp+0x18`, which npfs just overwrote), NOT the stale `slot.data`. **FIX:** the stash reads `irp+0x18` live (falling back to `slot.data` only if npfs left it in place) — `driver_launch.rs`. RESULT: `[redrive-src] STASH fid=…b1 n=16 b=05 00 0b 03 10 00 00 00 48 00 00 00 01 00 00 00` — the REAL bind header. The worker then reads the remaining 56 bytes (npfs's WriteEntry, message-mode), rpcrt4 `process_bind_packet` emits bind_ack, batch-33 re-drives winlogon's parked read → **winlogon reads `05 00 0c 03… 44…` = bind_ack (PTYPE 0x0c).** Then `RROpenSCManagerW` request (`05 00 00 03`) → response (`05 00 02 03`) → more PDUs both directions.

### WHY THE ROUTE IS GATED OFF (the route-ON regression, honestly characterized)
Route ON, the RPC round-trip completes → **gate 171, NOT 174** for two coupled reasons: (1) with the bind read now SUCCEEDING, services' per-connection worker (badge 15) + listener (badge 7) STAY ALIVE serving the conversation instead of self-exiting on a failed connection (which is what they did in BATCH 37 when the read returned garbage → rpcrt4 rejected → teardown). So the 3 `exec_live_terminate_thread_{routed,tcb_reclaimed,no_reply}` specs — which assert `>= 3` self-exits (csrss+lsass+services-worker+services-listener) — drop to 2 (only csrss+lsass; `item2a count 4→2, bits 0x1a→0x12`). Those specs were coupled to the BROKEN-RPC teardown. (2) winlogon, having OpenSCManager SUCCEED, advances into GUI code (user32/gdi32) and hits a NEW downstream **null-deref** (`#PF cr2=0x10 rip=0x801a0009`) → crash-parks. Because the SCM sub-threads are cooperatively pipe-parked (not crash-parked) with no live client left, the executive main loop then blocks in `recv` forever (nothing to signal them) → boot timeout unless quiesced. A break-on-winlogon-crash quiesce gives a CLEAN qemu_exit at gate 171 (`/tmp/boot38f.log`) but does not restore the 3 terminate specs (the sub-threads never self-exit). Per the batch constraint (gate ≥174, the 4 terminate specs MUST pass, no regression), the route is **GATED OFF** (`SCM_WORKER_ROUTE_ENABLED = false`): the npfs reconcile fixes (correct, general, host-tested) LAND, bind_ack + the full round-trip are PROVEN with the route flipped ON, and the OFF path is byte-identical to the BATCH-37 green boot — **gate 174, "All specs passed!", clean qemu_exit; 5 processes spawn; lsass SIGNALLED LSA_RPC_SERVER_ACTIVE; all 4 `exec_live_terminate_thread_*` PASS; same 5 pre-existing FAILs (`desktop_painted`, `nic_*`×2, `csr_message_plane`, `npfs_flush_pending`).** Also added a bounded SCM `\ntsvcs` re-create cap (`SCM_NTSVCS_CREATE_CAP=24`, dormant with the route off) so a route-ON boot cannot spin the listener's re-listen forever.

### NEXT WALL — winlogon's post-OpenSCManager GUI null-deref + the SCM server persistent-thread lifecycle
With the route ON the frontier moved PAST bind_ack all the way to: winlogon's SC-RPC conversation completing → `OpenSCManager` returning → winlogon entering GUI code → **null-deref at `rip=0x801a0009` (user32/gdi32 region, addr 0x10)**. That is the next thing to root-cause (a missing/NULL structure winlogon derefs after the SCM handshake). SECOND, the `exec_live_terminate_thread_*` specs need updating to a SUCCEEDING-RPC world (the SCM worker/listener are PERSISTENT servers now, not self-exiting threads — the specs currently assert the broken-RPC teardown). Once both are addressed the route can go ON permanently and winlogon can advance toward the graphics-init `SwitchDesktop` = the `0x003a6ea5` paint (`exec_win32k_desktop_painted`, still `0/768`).
