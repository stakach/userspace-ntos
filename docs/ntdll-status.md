# Our Rust `ntdll.dll` — current state

**ntdll measurements updated through the 2026-08-01 runtime-cleanup gate; boot gate reports
`273/273` with ZERO FAILs.** This is the *current-state* document for the ntdll effort. The
blow-by-blow history (BATCH 1..54, §A..§F) lives in
`ntdll_plan.md`, which is now a historical log — read this file first, and go there only for the
diagnosis story behind a specific decision.

Every number below was **re-measured at `6dee67e`** against the built binary and the source tree (see
§2 for how), then incrementally updated by validated pickups. Where a claim in `ntdll_plan.md` did
not survive re-measurement it is corrected in §7.

---

## 1. What our Rust ntdll IS

| piece | where | what |
|---|---|---|
| the pure core | `crates/nt-ntdll` | `no_std` rlib, host-tested with plain `cargo test`. All the *logic*: `rtl/*.rs` (54 modules), `loader/*.rs`, `heap.rs`, `sync.rs`, `nls.rs`, `printf.rs`, `crt.rs`, `dbg.rs`, `csr.rs`, `ki.rs`, `trap_stubs.rs`. |
| the DLL | `crates/nt-ntdll-dll` | a `cdylib` in **its own workspace** (it never builds for the host). ~47 kLOC of thin export wrappers: `exports.rs`, `security_exports.rs`, `on_target.rs` (the target-only tails), `seh.rs`, `lib.rs`. |
| byte-exact layouts | `crates/nt-ntdll-layout` | static-asserted x64 `PEB`/`TEB`/`LDR_DATA_TABLE_ENTRY`/`KUSER_SHARED_DATA` offsets. The one place ntdll and the executive agree on a field offset (e.g. `PEB_BEING_DEBUGGED_OFFSET`). |
| the shared SSN table | `crates/nt-syscall-abi` | **single source of truth** for the syscall ABI: `NT_SYSCALLS` (216 services), `ZW_ALIASES` (216), `NT_ARGC` (217 — `NtCreateThreadEx` has an arity row without a service row). SSNs are the **0-based line index in `references/reactos/ntoskrnl/sysfuncs.lst`**; both ntdll and the executive read this crate. |
| the build | `scripts/build_ntdll_dll.sh` | nightly + `-Zbuild-std`, a custom no-CRT `x86_64-pc-windows-gnullvm-nostd` target, `rust-lld`. Emits `.tmp/nt-ntdll.dll` (1 782 272 bytes at `6dee67e`). Hard gate: `tools/ntdll-dll-verify` parses the result with **the executive's own `nt-pe-loader`** and asserts PE32+/`IMAGE_FILE_DLL`, the complete `Nt*` ABI, `LdrpInitialize`, a `.reloc` directory, and per-stack-DLL import coverage. |
| staging | `rust-micro/scripts/make_image.sh:166-180` | copies `.tmp/nt-ntdll.dll` onto the image **as `\reactos\system32\ntdll.dll`**, overwriting the real ReactOS one. **There is no fallback** — no real ReactOS ntdll bytes exist on the image; every hosted process that loads "ntdll" gets ours. |

**Transport.** `Nt*` stubs do *not* issue a Windows `syscall`. They issue a real native seL4
`Call` on the process's fault endpoint (`CT_FAULT`), label `NT_NATIVE_SYSCALL_LABEL = 0x4E54` ("NT"),
6 message registers (SSN, caller RSP, arg1..arg4); reply = 1 MR (NTSTATUS). Wire format and the pure
pack/unpack live in `crates/nt-ntdll/src/native_call.rs`; the seam abstraction is
`crates/nt-ntdll/src/transport.rs`. Hosted ReactOS threads still set rust-micro's
`TCBSetHostedSyscalls` flag in hybrid mode: this exact native ntdll envelope is allowed through as a
real seL4 Call, while raw ReactOS DLL syscall stubs fault as NT syscalls even when `rdx` collides with
seL4 syscall numbers. Out-params ride on the existing client stack/heap/image mirror (MR1 = rsp).

**The loader** is ours end to end: `crates/nt-ntdll/src/loader/` (module graph, import resolution
incl. forwarders, dependency-ordered `DLL_PROCESS_ATTACH`, `PEB->Ldr` construction and the three
circular lists, TLS, loader lock, DLL notifications, IFEO) driven on target by
`nt-ntdll-dll/src/on_target.rs`'s recursive loader from `LdrpInitialize`. Delay imports are bound
eagerly. `Peb->ProcessHeap` is published by the loader (msvcrt's CRT init depends on it).

**SEH** is real x64 table-based dispatch: `.pdata`/`.xdata` unwind-code interpreter + live
module-scan `RtlLookupFunctionEntry`, `RtlVirtualUnwind`, `RtlDispatchException`, `RtlUnwindEx`,
`__C_specific_handler`, `RtlRaiseException` (`crates/nt-ntdll-dll/src/seh.rs` +
`crates/nt-ntdll/src/rtl/exception.rs`). C++ EH is scoped-deferred.

**The `KiUser*` seams** are exported and real: `KiUserExceptionDispatcher`,
`KiUserCallbackDispatcher` (win32k reverse callbacks), `KiUserApcDispatcher`,
`KiRaiseUserExceptionDispatcher`.

---

## 2. COMPLETENESS — the measured facts

> **Measure, don't grep.** `grep -c '#\[export_name'` **undercounts by ~470** because the `Nt*` trap
> stubs (`generate_trap_stubs!`), the `Zw*` aliases (`zw_alias!`) and the ETW no-ops (`etw_ok!`) are
> macro-generated. The only truthful source is the **export directory of the built PE**.

### 2.1 Exports in the built `.tmp/nt-ntdll.dll`

**1355 exports, 0 forwarders.**

| prefix | count | note |
|---|---|---|
| `Nt*` | 218 | 216 SSN trap stubs + `NtCurrentTeb` + `NtGetTickCount` |
| `Zw*` | 216 | `zw_alias!` of the `Nt*` stubs; the five Dbgk aliases and registry hive variants are included |
| `Rtl*` | 598 | incl. 13 `Rtlp*` |
| `Ldr*` | 54 | incl. `LdrpInitialize` |
| `Etw*` | 64 | 46 `etw_ok!` + 2 `etw_scenario_write!` no-ops + real ones |
| `Dbg*` | 18 | of which 10 `DbgUi*` |
| `Csr*` | 16 | |
| `Ki*` | 4 | the user dispatchers |
| CRT / crypto / Alpc / data | 167 | `mem*`/`str*`/`wcs*`/`sprintf`/`qsort`/math, `A_SHA*`/`MD4*`/`MD5*`, `Pfx*`, `Alpc*`, `__C_specific_handler`, `__chkstk`, `VerSetConditionMask`, the 3 `Nls*` data exports |

Roughly: 871 hand-written `#[export_name]` items + 216 macro trap stubs + 216 `zw_alias!` + 48 ETW
macros + a handful of data exports.

### 2.2 Required imports — is anything missing?

Measured by parsing the **`ntdll.dll` import descriptors (data directory 1) *and* the delay-import
descriptors (data directory 13)** of every staged PE under
`rust-micro/.tmp/reactos/reactos/`, then diffing against our export set.

| population | PEs | distinct `ntdll` imports | **missing from our DLL** |
|---|---|---|---|
| the live-loaded set (42 binaries: smss/csrss/winlogon/services/lsass + kernel32(+vista), user32, gdi32, advapi32(+vista), rpcrt4, msvcrt, csrsrv, basesrv, winsrv, secur32, netapi32, msgina, lsasrv, samsrv, msv1_0, userenv, mpr, ws2_32, ws2help, win32k.sys, ntdll_vista, comdlg32, comctl32, shell32, shlwapi, ole32, oleaut32, version, ntmarta, psapi, imm32, setupapi, winspool.drv, ftfd, framebuf) | 42 | **554** | **0** |
| the whole `system32` tree, recursive | 726 | **593** | **0** |
| the whole `\reactos` tree, recursive | 747 | **596** | **0** |
| …plus every *forwards-to-ntdll* export target in that tree | — | +87 (union **656**) | **0** |

**The import surface is CLOSED.** Every `ntdll` name any staged ReactOS binary imports — directly,
by delay-load, or by export forwarding — exists in our DLL. Nothing that remains is a *gap*; it is
all *breadth*.

### 2.3 Genuinely unconditional stubs: **0**

Classification of every `STATUS_NOT_IMPLEMENTED` occurrence in `crates/nt-ntdll-dll/src/`:

| bucket | count |
|---|---|
| raw `grep -c` tokens (101 in `exports.rs` + 7 in `security_exports.rs`) | 108 |
| **exported functions** that mention it | **87** |
| …**every** occurrence is a `#[cfg(not(target_arch = "x86_64"))]` **host-build fallback arm** — dead code, since the DLL only ever builds for x86_64 | 83 |
| …a host arm **plus** a genuine error arm inside a real body: `RtlQueryInformationActivationContext` (unsupported info class), `RtlQueryProcessDebugInformation` (unsupported query flags) — exactly what NT returns | 2 |
| …**unconditional single-statement bodies** | **2** |

The 2 unconditional bodies are `RtlWow64EnableFsRedirection` and `RtlWow64EnableFsRedirectionEx`.
These are **not stubs** — they are ReactOS-faithful *fidelity corrections* (§E.3 of the log):
`dll/ntdll/rtl/libsupp.c:1166/1178` is `@implemented` and returns exactly `STATUS_NOT_IMPLEMENTED`
("this is what Windows returns on x86"), because the redirection layer only exists in the WOW64 thunk
ntdll. Returning SUCCESS was a fabricated success and was removed.

**So: `grep -c STATUS_NOT_IMPLEMENTED` is a MISLEADING metric** — 85 of the 87 functions carrying the
token have a real body on target. Use the classification, not the token count.

A separate, honest category is the handful of exports that mirror ReactOS's own `@unimplemented`
observable contract: `RtlCreateTagHeap` ⇒ 0, `RtlQueryTagHeap` ⇒ NULL,
`RtlCheckForOrphanedCriticalSections` ⇒ void no-op, `LdrAlternateResourcesEnabled` /
`LdrFlushAlternateResourceModules` ⇒ FALSE, `LdrUnloadAlternateResourceModule(Ex)` ⇒ TRUE,
`RtlGetCurrentProcessorNumber(Ex)` ⇒ 0 (single-CPU boot). Changing these would be invention, not
completion. (`RtlCompactHeap` is **no longer** in this group — it has a real coalescing body.)

### 2.4 Breadth vs the ReactOS spec

Measured against `references/reactos/dll/ntdll/def/ntdll.spec`, excluding `-arch=i386`-only rows:

* **1882** x64-applicable spec names; **397** of them are `-stub` in ReactOS itself.
* We export **1346** names; **24** of ours are not in the spec at all (`LdrpInitialize`, `DllMain`,
  `RtlGetTickCount`, the `Rtl*_Ustr` helpers, `RtlUTF8ToUnicodeN`, `fma`/`fmaf`, …).
* **560** spec names we do not export — **285 of which ReactOS `-stub`s too**. By prefix:
  185 `Nt*`, 179 `Zw*`, 103 `Rtl*`, 23 `Rtlp*`, 42 `Tp*` (threadpool), 6 `Ldr*`, 22 other
  (`Exp*` SList, setjmp/longjmp, `sscanf`, ARM helpers).
* **None of the 560 is imported by anything we host** (§2.2).

### 2.5 Host tests

`cargo test -p <crate>` prints **one `test result:` line per target** (lib + doc-tests) — **sum
them**, don't read the last one.

| crate | tests | status |
|---|---|---|
| `nt-ntdll` | **699** | green |
| `nt-process` (incl. the Dbgk state machine) | **79** | green |
| `nt-syscall` | **45** | green |
| `nt-syscall-abi` | **15** | green |
| `nt-ntdll-layout` | **12** | green |

`nt-ntdll-dll` has no host tests by construction — it is a target-only `cdylib`; its correctness is
covered by the pure core's tests plus the boot gate.

---

## 3. What's implemented for real

Brief, by area — the code is the reference.

* **`Nt*`/`Zw*` transport stubs** (`nt-ntdll/src/trap_stubs.rs` + `nt-syscall-abi`) — 216 services,
  arity-checked. Semantics live executive-side in `ExecNtHandler`.
* **`Rtl*`** (`nt-ntdll/src/rtl/`, 54 modules) — strings/Unicode/case/NLS · path + DOS↔NT conversion ·
  environment blocks + process parameters · time/timezone · security (SIDs/ACLs/SDs/privileges/tokens/
  `Rtl*SecurityObject`) · a real first-fit process heap (+ walk/compact/lock/user-value/tag) · bitmaps ·
  generic/AVL/splay tables · prefix tables · compression · atoms · FLS · vectored handlers · random ·
  GUIDs · converters · image + import-table hash · message tables · activation contexts (real registry
  with refcounting + a TEB activation stack) · the **RTL_RESOURCE** family · **RXACT** registry
  transactions · `RtlpNt*` registry helpers · critical sections (with `RtlpWaitForCriticalSection`/
  `RtlpUnWaitCriticalSection` as real slow paths).
* **`Ldr*`** — the loader (§1) plus a real `.rsrc` walker (`LdrFindResource_U`/`Ex_U`,
  `LdrAccessResource`, `LdrEnumResources`, `LdrRes*`) and `LdrQueryImageFileExecutionOptions`.
* **`Csr*`** — `CsrClientConnectToServer` is a faithful `CsrpConnectToServer` port;
  `CsrClientCallServer`, the capture-buffer family and `CsrNewThread` are real.
* **`Dbg*`/`DbgUi*`** — serial-forwarding `DbgPrint*` + the complete `DbgUi*` shim over the five
  debug-object SSNs (§4). All 10 `DbgUi*` are real.
* **CRT / NLS / crypto / SEH** — `mem*`/`str*`/`wcs*`/printf/`qsort`/`bsearch`/math; the real
  `RtlInitCodePageTable` with a populated `MultiByteTable`; `A_SHA*`/`MD4*`/`MD5*`; SEH per §1.

---

## 4. The debug plane (Dbgk) — the last big push

### 4.1 The five SSNs

Derived exactly like every neighbour: the **0-based line index in
`references/reactos/ntoskrnl/sysfuncs.lst`**.

| service | sysfuncs.lst line | SSN | argc |
|---|---|---|---|
| `NtCreateDebugObject` | 36 | 35 | 4 |
| `NtDebugActiveProcess` | 60 | 59 | 2 |
| `NtDebugContinue` | 61 | 60 | 3 |
| `NtRemoveProcessDebug` | 200 | 199 | 2 |
| `NtWaitForDebugEvent` | 280 | 279 | 4 |

Cross-checked against already-present neighbours (`NtQueryDebugFilterState` 149→148,
`NtSetInformationDebugObject` 233→232, `NtCreateFile` 40→39, `NtReadVirtualMemory` 195→194,
`NtWaitForMultipleObjects` 281→280). `NT_SYSCALLS`/`ZW_ALIASES` went 207 → 212.

### 4.2 The pure state machine

`crates/nt-process/src/dbgk.rs` (1347 lines, host-tested) — a faithful port of the pure half of
`ntoskrnl/dbgk/dbgkobj.c`: `DebugObject` (event list + `EventsPresent` signal +
`DebuggerInactive`/`KillProcessOnExit`), `DebugEvent`, all seven `DbgKmMessage` api numbers, `queue`,
`activate_backout_events`, `dequeue_for_wait` (one outstanding event per debuggee process),
`continue_event`, `flush_process`, `encode_wait_state_change` (the x64 `DBGUI_WAIT_STATE_CHANGE` byte
image, all 9 states), `wake_action`, `ReporterBlock`.

Lifecycle sits on `ProcessManager` (it owns the process/thread tables): `create_debug_object`,
`debug_active_process`, `wait_for_debug_event` (mints REAL process/thread handles in the *debugger's*
table), `debug_continue`, `remove_process_debug`, `destroy_debug_object`.

Handlers: the five services are registered in `build_nt_table` (`components/ntos-executive/src/main.rs`)
and dispatched in `exec_handler.rs` with typed-handle resolution + `DbgkDebugObjectMapping` access
checks; a real anonymous notification dispatcher event backs `EventsPresent` so a blocking
`NtWaitForDebugEvent` parks on the same `wait_park_event` seam as every other wait.

### 4.3 ⚠️ "fake" is NT's own word — do NOT "fix" it

`DbgkpPostFakeProcessCreateMessages`, `DbgkpPostFakeThreadMessages` and
`DbgkpPostFakeModuleMessages` are **NT's own function names**
(`references/reactos/ntoskrnl/dbgk/dbgkobj.c:792 / :594 / :457`, called from `:1850`). "Fake" means
**messages SYNTHESIZED AT ATTACH from real live state** — the debuggee already exists, so the kernel
manufactures the create-process / create-thread / load-dll events the debugger would have seen had it
been attached from the start. **They are not mocks, not stubs, and not test doubles.** Our
`ProcessManager::debug_active_process` uses the same names deliberately. A future reader must not
"replace the fakes with real ones".

### 4.4 Debug-event sources: WIRED vs DEFERRED

**WIRED** (real, generated by the real `nt-process` lifecycle):

| source | where |
|---|---|
| attach-time synthesized **create** messages (`DbgKmCreateProcessApi` for the first live thread + `DbgKmCreateThreadApi` for each other; `NOWAIT\|INACTIVE` with the attaching thread as backout, then activated) | `ProcessManager::debug_active_process` |
| attach-time synthesized **module** messages (one `DbgKmLoadDllApi` per tracked module, after the create message, attributed to the first reported thread) | same |
| **thread create / thread exit / process exit** | `create_thread`, `terminate_thread_at`, `exit_thread_at`, `terminate_process_at` |
| **exceptions / breakpoints** — label 3 (CPU exception → `exception_code_for_trap`), label 4 (`int3` → `STATUS_BREAKPOINT`), both label-6 unrecoverable page-fault branches (`STATUS_ACCESS_VIOLATION` + `MmAccessFault`'s two args) | `ExecNtHandler::dbgk_forward_exception`, from the REAL fault loop (`service_sec_image.rs`, macro `dbgk_forward_exception!`) |
| **module load / unload**, IMAGE-only both ways (anonymous/named sections and untracked bases report nothing) | the `NtMapViewOfSection` **SEC_IMAGE branch** + `NtUnmapViewOfSection` |
| **target-side blocking** — the reporter genuinely BLOCKS on the continue event via the same reply-capability steal every other wait uses; fault-shaped (`USER_EXCEPTION`/`DEBUG_EXCEPTION`/`VM_FAULT`) and syscall-shaped (length-18 reply, **resume IP = RCX (MR2)**, not the message's FaultIP slot). `DBG_TERMINATE_THREAD`/`DBG_TERMINATE_PROCESS` **ENFORCED**; three escape-hatch layers (teardown release, quiesce accounting, post-loop drain) so a debugger can never wedge the boot | `dbgk_block_reporter` / `dbgk_reporter_resume` / `dbgk_wake_target` |
| **cross-VSpace thread creation** — a real hosted thread (own stack/TEB/GS/IPC buffer/trampoline) in an *arbitrary* target VSpace at a caller-supplied entry+parameter; `PROCESS_CREATE_THREAD` access-checked; the FIRST foreign `NtCreateThread` for a target is its initial thread, every subsequent one a genuine remote create. This is what makes `DbgUiIssueRemoteBreakin` real | `rendezvous::spawn_slot_thread` + `ExecNtHandler::create_remote_thread` |
| **`PEB->BeingDebugged` write-through** into the target's live PEB page on attach, cleared on detach / object destruction, via the same cross-process path `NtWriteVirtualMemory` uses | `ExecNtHandler::dbgk_mark_process_peb` |

**Safety property, everywhere:** every divert is gated on the process actually having an
`EPROCESS.DebugPort` (module hooks additionally on `debug_object_count() != 0`). Nothing on the
current boot attaches a debugger, so **the live serial is byte-identical** — verified by normalized
diffs at each batch.

**Gate coverage:** 21 `exec_dbgk_*` specs, driven by five post-loop self-tests that go through the
REAL dispatch route (`nt_dispatcher.dispatch(SSN, …)`, arguments marshalled in smss's client memory)
and the REAL fault-path entries, including a genuinely real throwaway client thread in its own VSpace.
Each batch was validated by a **BYPASS experiment** (one-line disable ⇒ the new specs FAIL).

**DEFERRED** — see §5.

---

## 5. REMAINING WORK — the pickup list

Prioritised. Each item states why it matters and what it needs. Everything here is **breadth or
fidelity**; nothing here is a missing import or an unconditional stub.

**Completed pickup (2026-07-30):** the five Dbgk `Zw*` aliases
(`ZwCreateDebugObject`, `ZwDebugActiveProcess`, `ZwDebugContinue`, `ZwRemoveProcessDebug`,
`ZwWaitForDebugEvent`) are now exported, and `ntdll-dll-verify` checks the complete
`ZW_ALIASES` table so alias drift is gated.

**Completed pickup (2026-08-01):** `RtlZeroHeap` is now exported and backed by the real
`nt-ntdll` heap: it validates the heap, zeros payload bytes in every free block, preserves heap
metadata/live allocations, and is covered by focused host tests.

**Completed pickup (2026-08-01):** registry hive API variants are now real surface, not ReactOS-gap
mirrors: `NtLoadKey2`, `NtLoadKeyEx`, `NtUnloadKey2`, `NtUnloadKeyEx` and their `Zw*` aliases are
in the shared SSN table, exported by ntdll, and dispatched by the executive to the existing
`NtLoadKey`/`NtUnloadKey` CM mount/detach implementation with flag validation, trust-key validation,
and synchronous `NtUnloadKeyEx` event signalling.

**Completed pickup (2026-08-01):** the four named Tier-2 security `Rtl*` exports that ReactOS leaves
as Vista+ stubs are now real in our ntdll: `RtlOwnerAcesPresent` scans for Owner Rights ACEs,
`RtlAddMandatoryAce` appends validated mandatory-label ACEs, and `RtlSidDominates` /
`RtlSidEqualLevel` compare mandatory integrity label SIDs. They are exported, gate-verified, and
covered by focused pure security tests where the model is host-testable.

**Completed pickup (2026-08-14):** `ThreadHideFromDebugger` now affects Dbgk per-thread live
notifications. `NtSetInformationThread(ThreadHideFromDebugger)` already set
`ETHREAD.HideFromDebugger`; the `nt-process` Dbgk queue path now consults that flag before posting
notifications whose source is an explicit reporting thread. Hidden threads suppress exception,
mapped-image load/unload, and thread-exit messages while preserving the kernel's mapped-image
tracking. Covered by focused host tests including
`dbgk_thread_hide_from_debugger_suppresses_live_thread_reports`.

1. **Remaining Tier-2/3 `Rtl*` breadth — low value, do on demand.** The named Tier-2 security list is
   closed. The wider measured spec tail in §2.4 is remaining breadth. **None is imported by anything we
   host.** The rule that governs all of it:
   > **NEVER add a trap stub whose SSN the executive cannot service.** An unserviced SSN reaches
   > `park_and_log!(pi, b"unhandled-syscall", …)` and parks the process — a correct "not implemented"
   > answer would be replaced by a hang. This is why `RtlGetCurrentProcessorNumber` returns 0 rather
   > than forwarding to `NtGetCurrentProcessorNumber` (not in our table, not serviced), and why
   > `NtContinue`/`NtRaiseException` have no stubs.
2. **Dbgk deferred event sources / fidelity gaps** — each real, none blocking:
   * **`#DB` single-step.** The mapping exists and is host-tested (trap 1 → `STATUS_SINGLE_STEP` →
     `DbgSingleStepStateChange`) but **nothing sets `EFLAGS.TF`** anywhere in the tree, so a `#DB` is
     never generated. Needs the continue path to honour a debugger-set TF + vector-1 classification.
   * **Executive-internal fault walls never forward** (`fault-cap`, `win32k-spin`,
     `unhandled-syscall`, `image-map-resource`, `wl-stack-growth`, `other-fault`) — they are executive
     walls, not user exceptions, so they neither forward nor block. Which (if any) should become user
     exceptions is a design question, not a port.
   * **Modules mapped before any `DEBUG_OBJECT` existed** get no fake load-dll message: the modelled
     module list is only maintained while a debug object is alive, and that gate is exactly what keeps
     the extremely load-bearing `NtMapViewOfSection` path byte-identical. Closing it means recording
     IMAGE views unconditionally — deliberately not taken.
   * **A remote create posts no `DbgKmCreateThreadApi`** — `create_remote_thread` draws from the
     target's pre-created ETHREAD pool instead of `ProcessManager::create_thread`, bypassing the poster.
   * **The loop-side multiplex for a remote thread created into a LIVE process is wired but not
     live-exercised** — `spawn_requested_remote_thread` badges it onto the main fault EP and
     `mirror_ctx_for` already sub-selects it; nothing hosted issues `RtlCreateUserThread` against
     another live process, so the only proof is the self-test's private-endpoint client.
   * **`DbgkClearProcessDebugObject` on process-object *deletion*** — we clear only on explicit
     `NtRemoveProcessDebug` / debug-object destruction, so a terminated debuggee keeps its port and the
     debugger can still retrieve the final `ExitProcess` event.
   * **Nothing hosted drives any of this** — no binary in the current set issues the five debug
     syscalls; all 21 `exec_dbgk_*` specs are self-test-driven.
3. **`DBG_EXCEPTION_NOT_HANDLED` at a fault is a bookkeeping difference.** The reporter is left
   *cooperatively wait-parked* rather than *crash-parked*: the fault site's `[parked]` bookkeeping is
   not re-run from the wake path (the dead-client callback unwind **is**). The process still never
   resumes; only the park ledger it lands in differs.
4. **The contended critical-section path is structurally correct but never exercised.** `[cs-event]`
   is 0 on every boot, and the wait is issued with a NULL timeout (`RtlpTimeoutDisable`), so the
   `STATUS_POSSIBLE_DEADLOCK` arm cannot fire. Enabling a finite `RtlpTimeout` is a one-line change.
5. **`RtlWow64EnableFsRedirection`/`Ex` return `STATUS_NOT_IMPLEMENTED` by design** — do not "fix"
   them (§2.3).

**Not an ntdll item:** the desktop/logon-UI frontier past the SAS/logon-dialog park is a **win32k**
batch (message queue: `UserGetMessage 0x1006` / `UserPostMessage 0x100e`, the modal pump and the
`WM_PAINT` `KeUserModeCallback` cycle in `win32k_subsystem.rs`). No ntdll export blocks it.

> **Update (2026-07-26, gate 217/99).** That frontier moved twice more, still with no ntdll change.
> The msgina IDD_LOGON dialog is now **typed into**: the credential controls are resolved by
> `GetDlgItem`'s own rule over win32k's live PWND child list (`WND.IDMenu`), 13 real `WM_CHAR`s plus
> a `WM_KEYDOWN`/`VK_RETURN` are posted through the REAL `NtUserPostMessage` (SSN `0x100e`, the same
> shim as the simulated Ctrl-Alt-Del), the real `DIALOG_DoDialogBox`/`IsDialogMessageW`/edit-control
> code consumes them, the control's own `NtGdiExtTextOutW` render reads the text back, and the real
> `LogonDialogProc` -> `DoLogon` -> `DoLoginTasks` -> `ConnectToLsa` reaches
> `NtConnectPort("\LsaAuthenticationPort")`. Nothing publishes that port, so winlogon MILESTONE-parks
> there (a crash-park would mark it a dead win32k callback client and strand the callback plane).
> **The next wall is lsass' LSA authentication port**, not ntdll and not win32k. See the CREDENTIAL
> BATCH section of `ntdll_plan.md`.

> **Update (2026-07-26, gate 220/99) — the LSA authentication port is REAL.** Still no ntdll change.
> The diagnosis was *routing*, not a missing port: lsass' lsasrv already created
> `\LsaAuthenticationPort` in the LPC broker (winlogon's connect returned PENDING with a live
> connection id), but every pending connect funnelled into `sm_rendezvous` — *smss'* `SmpApiLoop`, the
> wrong server — while lsass' REAL `AuthPortThreadRoutine` sat in `NtReplyWaitReceivePort` with its
> reply capability already dropped by the generic listener park.
>
> `lsa_rendezvous` is now the third authentic LPC rendezvous (after `sm_` and `csr_`), and the first
> driven entirely by the MAIN service loop, because that server thread lives in the N-threads multiplex
> rather than on a private endpoint. It parks the server WAKEABLY (the same reply-capability steal
> `wait_park_multi`/`pipe_wait_park`/`dbgk_reporter_park` use), delivers winlogon's real
> `LPC_CONNECTION_REQUEST` + its own 148-byte `LSA_CONNECTION_INFO`, and blocks the connector. The real
> `LsapHandlePortConnection` then runs verbatim — `NtOpenProcess(ClientId)` → `NtOpenProcessToken` →
> `NtQueryInformationToken` ×2 → **its own `NtAcceptConnectPort(Accept = TRUE)`** →
> `NtCompleteConnectPort` — and the connector is woken with the broker's real client comm-port handle
> plus the server's own `ConnectInfo` (`OperationalMode = 0x43218765`).
>
> Over that port: `LsaLookupAuthenticationPackage(MSV1_0)` → **SUCCESS**, then `LsaLogonUser`, whose real
> `LsapCopyFromClient` made **6 cross-process reads into winlogon's heap** for the typed
> `MSV1_0_INTERACTIVE_LOGON` and reached MSV1_0's real `LsaApLogonUser2`. One new *kernel* service was
> needed on the way: **`NtAllocateLocallyUniqueId`** (SSN 15), implemented as the genuine
> `ExAllocateLocallyUniqueId` (`ExpLuid` seeded `0x3e9`, increment 1).
>
> **The wall is now `GetAccountDomainSid` (`msv1_0/sam.c:267`) → `STATUS_OBJECT_NAME_NOT_FOUND`**: the
> **LSA policy database** (`LsarQueryInformationPolicy(PolicyAccountDomainInformation)`) and behind it
> the **SAM database** do not exist on this host. That cascade was deliberately NOT forced — no logon
> success is fabricated, `WLX_SAS_ACTION_LOGON` is still not returned, and winlogon takes msgina's own
> failure path back to the credential dialog's blocking `GetMessage` (the pre-existing `[dialog-pump]`
> MILESTONE park). Gate specs: `exec_lsa_auth_port_connected`, `exec_lsa_logon_user_reached`,
> `exec_lsa_msv1_0_sam_validation_reached`. See the LSA BATCH section of `ntdll_plan.md`.

> **Update (2026-07-26, gate 223/99) — the SECURITY + SAM hives are REAL, and the LSA policy database
> is lsasrv's own.** This one DID need an ntdll change — a genuine bug. `RtlpNtOpenKey` /
> `RtlpNtCreateKey` stripped `OBJ_PERMANENT|OBJ_EXCLUSIVE` from `OBJECT_ATTRIBUTES.Attributes` at
> **+0x10**, the *32-bit* offset; on x64 that is the `ObjectName` **pointer**, so every such call
> silently cleared two bits of its own name pointer and the callee read a garbage `UNICODE_STRING`.
> That — not a missing policy database — is why lsasrv's first LSA-init call,
> `LsapOpenServiceKey(L"\Registry\Machine\SECURITY")`, returned `0xC0000034`
> (`database.c:548`). Fixed against host-tested offsets (`nt_ntdll::rtl::registry::
> OA_OFFSET_ATTRIBUTES` + `sanitize_key_object_attributes`); `nt-ntdll` 692 → **694**.
>
> `\Registry\Machine\SECURITY` and `\Registry\Machine\SAM` are now REAL read-only `regf`
> mounts, read BY PATH off `\reactos\system32\config\{security,sam}` by the isolated storage host
> — the same mechanism as the SYSTEM hive. There is a general **3-hive mount** (a `KeyRef`'s top
> nibble selects the hive; one `base_hive()` accessor feeds every registry helper), not per-key
> special-casing. Both staged hives are the genuine post-setup ones: **8192 B, root key only, zero
> subkeys** — and that emptiness is load-bearing. The old "auto-create any SECURITY/SAM path in the
> overlay" hack was deleted: it made lsasrv's `LsapIsDatabaseInstalled()` answer TRUE, so the real
> first-boot install was skipped. With a real empty hive the probe MISSES honestly and lsasrv runs
> **`LsapCreateDatabaseKeys` + `LsapCreateDatabaseObjects` for real** — 17 keys, with `PolAcDmS`
> holding a SID it minted itself in `LsapCreateRandomDomainSid` (24 B, rev 1, 4 sub-authorities, NT
> authority). **On the live logon path `GetAccountDomainSid` now SUCCEEDS** (4 real attribute reads
> while `LsaLogonUser` is in flight); its `msv1_0/sam.c:270` error is gone. **samsrv.dll is genuinely
> hosted** (293376 B, demand-loaded by path) and its own `SampInitializeSAM`/`SampSetupCreateServer`
> created `SAM\SAM` + `SAM\SAM\Domains` in the real SAM mount.
>
> **The wall moved one step, and no logon is fabricated.** `SamValidateNormalUser` now fails in
> **`SamIConnect`**: `SampOpenDbObject(NULL, NULL, L"SAM", …)` opens the leaf `SAM` with a NULL
> RootDirectory because `SamKeyHandle` was never set — `SamIInitialize` never reached
> `SampInitDatabase`, having blocked forever in `SampInitializeSAM` → `SampGetAccountDomainInfo` →
> **`LsaOpenPolicy`**, an ncacn_np `\pipe\lsarpc` **self-RPC** that lsass hosts no per-connection
> worker for (a cooperative wait park, so the boot still quiesces). `Administrator` is NOT validated
> and `WLX_SAS_ACTION_LOGON` is still NOT returned. **Next wall: an LSA RPC worker for lsass' own
> `\pipe\lsarpc`** (services' SCM `\ntsvcs` worker is the precedent) — only then can
> `SampInitializeSAM` finish and mint the Administrator account. Gate specs:
> `exec_lsa_security_hive_backed`, `exec_samsrv_hosted`,
> `exec_msv1_0_account_domain_sid_resolved`. See the SAM/SECURITY BATCH section of `ntdll_plan.md`.

> **Update (2026-07-26, gate 225/99) — the "lsass hosts no per-connection LSA RPC worker" wall was a
> MISSING KERNEL SERVICE, not a missing worker.** No ntdll change. A bounded per-SSN trace of lsass'
> `\lsarpc` rpcrt4 server thread showed `RPCRT4_new_client` was **never reached**: after the connect
> completed its `FSCTL_PIPE_LISTEN`, `rpcrt4_ncacn_np_handoff` (`rpc_transport.c:599`) got as far as
> `GetComputerNameA`, whose fresh-boot fallback `SetActiveComputerNameToRegistry`
> (`kernel32/client/compname.c:131`) ends in **`NtFlushKey`** — an SSN (83) the executive did not
> service, so the SERVER THREAD parked mid-handoff. `NtFlushKey` is now a real service
> (`nt-syscall` 41 → **42**), implemented exactly as `ntoskrnl/config/ntapi.c:1085` +
> `HvSyncHive`'s `HIVE_VOLATILE` / no-dirty-block early return (`sdk/lib/cmlib/hivewrt.c:477`) — which
> is literally this host's registry (read-only `regf` mounts + an in-memory overlay that IS the store).
> A second real fix went in alongside: the FSD pool free list is now double-free-proof and
> cycle-bounded, closing a latent *whole-executive* hang (`s_io_complete_request` frees
> `slot.file_object` per completion, so two concurrent IRPs on one FILE_OBJECT could make
> `pool_alloc`'s first-fit walk loop forever with no fault and no log).
>
> The per-connection worker itself (badge 26, its own lsass-VSpace window + mirror/scratch,
> `spawn_lsa_worker_thread`, caller-identity recognizer, full N-threads sub-selection) is **built and
> proven end to end** — with the route enabled the whole self-RPC runs for real: bind (`05 00 0b 03`)
> → `process_bind_packet` → bind_ack (`05 00 0c 03`, waking lsass' own parked client read) →
> `LsarOpenPolicy` request (`05 00 00 03`) → `QueueUserWorkItem(RPCRT4_worker_thread)` → the real
> server stub (it opens `SECURITY\Policy`) → the 48-byte response (`05 00 02 03`). It is **GATED OFF**
> for the commit (the BATCH-38 precedent) because that response write is the first pipe write issued
> while a SECOND IRP is outstanding on the same npfs FILE_OBJECT, and **npfs.sys spins forever** in its
> `NpWriteDataQueue`/`NpGetNextRealDataQueueEntry` data-queue walk (zero faults, zero imports — its own
> consistency `ASSERT`/`KeBugCheckEx` is a fail-soft-unbound import, so the inconsistency is skipped
> rather than caught) and the boot never quiesces.
>
> **Nothing is fabricated:** `LsaOpenPolicy` still does not return, `SamKeyHandle` is still unset,
> `SamIConnect` still fails, `Administrator` is NOT validated and `WLX_SAS_ACTION_LOGON` is NOT
> returned. **Next wall: npfs.sys must tolerate two concurrent IRPs on one FILE_OBJECT** — that single
> thing is all that stands between here and a served LSA self-RPC. Gate specs:
> `exec_reg_flush_key_serviced`, `exec_lsa_rpc_handoff_reaches_new_client`. See the LSA-RPC BATCH
> section of `ntdll_plan.md`.

---

## 6. How to work on it

### Build → boot → verify

```sh
# 1. the DLL (only when nt-ntdll / nt-ntdll-dll / nt-syscall-abi changed)
./scripts/build_ntdll_dll.sh          # -> .tmp/nt-ntdll.dll  (+ the ntdll-dll-verify hard gate)

# 2. the executive (rootserver)
cd components/ntos-executive && ./build.sh && cd ../..

# 3. the image + boot  (or just `./run.sh`, which does 1-4)
cd rust-micro && ./scripts/make_image.sh && ./scripts/run_specs.sh
```

**The gate** is the serial line

```
[ntos-exec summary: 273/273 executive->isolated-service checks passed]
```

followed by `[microtest sentinel matched -- exiting QEMU]` and `RUNEXIT=3`. **Zero `FAIL` lines** is
the bar; the denominator is produced by the gate at runtime rather than a historical constant.
Sanity anchors that must stay PASS: `exec_win32k_desktop_painted` (768/768 px @
`0x003a6ea5`), `exec_desktop_shell_frontier`, `exec_msgina_logon_dialog_painted`,
`exec_msgina_credential_keystrokes_delivered`,
`exec_msgina_credentials_entered`, `exec_msgina_logon_validation_reached_lsa`, `exec_lsa_auth_port_connected`,
`exec_lsa_logon_user_reached`, `exec_lsa_msv1_0_sam_validation_reached`,
`exec_lsa_security_hive_backed`, `exec_samsrv_hosted`, `exec_msv1_0_account_domain_sid_resolved`, `exec_reg_flush_key_serviced`,
`exec_lsa_rpc_handoff_reaches_new_client`,
`exec_user_callback_dead_client_unwind`, `exec_user_callback_real_api0_nested_roundtrip`, all 21
`exec_dbgk_*`.

### Boot discipline (this has burned us repeatedly)

* **`build.sh` silently leaves a STALE `rootserver.elf` if `cargo build` fails** — its tail still
  prints "staged". ALWAYS check `rust-micro/.tmp/rootserver.elf` mtime > your edits and
  `grep -E 'error\[|error:'` the build output. Same for `.tmp/nt-ntdll.dll`.
* Keep byte-string literals **ASCII-only** (`-`, not `—`): a non-ASCII char in `b"…"` is a hard error.
* **Kill stray QEMU first. ONE foreground boot. A unique log file per boot.** Never boot while a
  background subagent is live (disk.img lock races + QEMU contention give misleading results).
  Terminal markers: `microtest sentinel matched`, `All specs passed`, `ntos-exec summary`,
  `terminating on signal`.
* Three consecutive clean boots with the PASS lists of boots 1 and 3 `diff`-identical is the standard
  of proof for a landed batch.

### The work pattern

1. **Pure core first.** Logic goes in `crates/nt-ntdll/src/rtl/<module>.rs` as `no_std` code with
   `cargo test -p nt-ntdll` coverage; the DLL export is a thin forward. Only registry/TEB/syscall
   tails live in `on_target.rs`, gate-verified on boot.
2. **Cite the source.** Every ported body names its `references/reactos/…:line`; deviations are stated
   in the doc comment with a reason.
3. **No fabricated success.** Returning `STATUS_SUCCESS` from something that did nothing is the exact
   failure mode that cost several batches (§E.3 of the log). Mirroring ReactOS's `@unimplemented`
   contract is correct; inventing one is not.
4. **Counter-backed specs + a BYPASS experiment.** A spec that still passes with the fix disabled is
   worthless. Every dbgk batch was validated by a one-line disable ⇒ the new specs FAIL, then restored
   and re-verified green. Do the same for anything non-trivial.
5. **Prove byte-identity when you touch a load-bearing path** — normalized `diff` of the boot serial
   against the previous commit; the only differences should be per-build addresses/timestamps/tids,
   known-nondeterministic interleaves, and your new spec lines.

> **Update (2026-07-27, gate 230/99) — the "npfs concurrent-IRP hang" was never npfs, and never an
> ntdll item either. It was the SHARED COMPONENT-DISPATCH TRANSPORT.** The LSA self-RPC's 48-byte
> `LsarOpenPolicy` response write *completes correctly* inside the hosted `npfs.sys`
> (`[fsd-ret] ret=0`, `[fsd-done] st=0 info=48`, both data queues consistent on the way in). What
> never came back was the **executive**: `component_main` publishes its completion (`send_done`)
> *before* it waits for the next request, and `component_pump` accepted **any** `dispatch_label`
> message as the answer to the request it had just sent. A `done` queued for an earlier cycle
> satisfies that `Recv` just as well, the two sides drift one message apart, and one dispatch later
> BOTH are blocked in `Send` on the dispatch endpoint — a deadlock with no fault, no log line and no
> driver involvement. The extra concurrency of the LSA route (the per-connection worker badge 26 plus
> the ntdll thread-pool worker badge 25) is what made the drift happen: **8 slips on the route-ON
> boot**, zero with a single IRP driver.
>
> Fixed by a **sequence handshake**: the pump samples `SH_REQ_SEQ` before sending and accepts only a
> `done` that carries a new sequence, consuming stale ones and re-waiting (`PUMP_STALE_DONES`).
> Scoped to the IRP substrate — win32k's Syscall pump deliberately re-enters around usermode
> callbacks, where an unmoved sequence IS the outer dispatch's real completion.
>
> Three further real fixes landed with it, all executive-side: **one FILE_OBJECT per OPEN** instead of
> per IRP (npfs stores it in `Ccb->FileObject[end]` and writes through it on disconnect — with the old
> lifetime the pool had recycled the block, and the audit measures **30 dangling FSD-held pointers**
> in the bypass arm vs 0 now); **`KeBugCheckEx` bound**, so a hosted driver's own `NpBugCheck` is
> caught, reported with its code + 4 parameters + raising component, and the dispatch unwound
> fail-closed instead of the assertion being silently skipped; and a **pre-dispatch npfs data-queue
> audit** that turns the one call-free spin state `NpGetNextRealDataQueueEntry` can reach into a
> bounded, counter-backed report (`FSD_QUEUE_REPAIRS`, 0 on a healthy boot).
>
> Gate specs: `exec_npfs_concurrent_irp_read_and_write`, `exec_npfs_write_split_across_pending_read`,
> `exec_npfs_file_object_lifetime`, `exec_kebugcheck_bound_and_reported`,
> `exec_component_dispatch_in_phase`. **The LSA worker route is still GATED OFF**: with it on the boot
> now sails past the LSA response write (msgina demand-loads, the SCM pipe traffic resumes) and stops
> at a **win32k** dispatch (`csrss -> SSN 0x1002`) — the same transport class on the substrate the
> handshake is scoped out of. That is the next frontier; no logon, token or RPC reply is fabricated.
> See the NPFS CONCURRENT-IRP BATCH section of `ntdll_plan.md`.

> **Update (2026-07-27, gate 231/99) — the win32k Syscall substrate now has a NESTING-SAFE
> request↔reply binding, and the LSA-route wall is a DIFFERENT problem than we thought.** The
> `SH_REQ_SEQ` handshake above repairs the IRP substrate only; it cannot be used on win32k, whose
> dispatch loop legitimately RE-ENTERS (an outer dispatch parks inside `KeUserModeCallback` while the
> client's redirected `WndProc` issues nested `NtUser*`/`NtGdi*` syscalls, unwound innermost-first).
> A shared-memory counter cannot name the LEVEL a completion belongs to. Each request now carries a
> **per-dispatch token in MR0** which the component ECHOES in its completion, so every pump level
> matches ONLY its own token; the one level that sends no request of its own — the callback RESUME —
> takes its token off an explicit LIFO stack, which is exact because the re-entrancy is strictly LIFO.
> Switch `W32_DISPATCH_TOKEN_BINDING`; gate spec `exec_win32k_dispatch_in_phase_nested` (a real
> post-quiesce `WM_NULL` callback park + real client redirect + a real NESTED dispatch preceded by a
> `done` carrying the SUSPENDED OUTER dispatch's token). Bypass: the nested dispatch returns the outer
> dispatch's `0x0` instead of its own `0x600D600D` **and the boot HANGS (RUNEXIT=124)**. The live boot
> nests to depth **5** on its own. See `docs/component-harness.md` §7.
>
> **The LSA worker route stays GATED OFF — for a newly isolated reason.** With the route on, npfs is
> exonerated (its 48-byte response write completes) and so is dispatch CORRELATION: a route-ON boot
> records ZERO token mismatches, ZERO pump walls and a callback plane that drains to depth 0. What it
> stops on is the executive's WAKE `Send` for a fresh `csrss -> SSN 0x1002` dispatch never returning.
> Instrumented: 907 of 908 healthy wakes sample win32k's RIP at `send_done_on`+2, 3 at the
> `recv_req_on` syscall — the single wake that never completes is the only sample at `recv_req_on`+2,
> and the dispatch-endpoint cap is stable across all 909 wakes. So the remaining wall is win32k
> **rendezvous availability** under the route's extra concurrency, not reply correlation. A
> timing-perturbed route-ON run also diverges earlier and loses the desktop paint, so enabling it is
> not safe yet. **No logon, token or RPC reply is fabricated**: `LsaOpenPolicy` still does not return,
> `SamIConnect` is not reached, `Administrator` is not validated, `WLX_SAS_ACTION_LOGON` is not
> returned.

> **Update (gate 234/99) — the component-dispatch transport MIGRATION IS COMPLETE, and the LSA
> route's wall has MOVED.** `docs/transport-migration.md` Phases 0-4: both substrates (npfs/FSD and
> win32k) now speak seL4 `Call` ⇄ **MCS reply objects**, the executive's legacy per-TCB `reply_to`
> reply is retired so `Cap::Reply` is its ONLY reply mechanism on every plane, and the whole 34-item
> kill-list — the `SH_REQ_SEQ` sequence handshake, the 32-deep dispatch-token stack, the two bypass
> switches, the two fault injectors, the duplicated transport fork, the wake `Send` itself — is
> DELETED. **Everything the two updates above describe as the live mechanism is GONE**; they are
> retained as the record of why.
>
> **The availability defect those updates end on is structurally gone, and it was measured, not
> assumed.** With `LSA_WORKER_ROUTE_ENABLED = true` the boot NO LONGER HANGS: it reaches the gate
> with `RUNEXIT=3` on every run, with zero pump walls and zero reply errors, and the self-RPC
> completes a real MS-RPC handshake inside lsass (the routed per-connection worker reads the ncacn
> **bind** `0x0b` off npfs and writes the **bind_ack** `0x0c`). Two route-ON boots were fully green
> at 232/99 with the paint intact. There is no wake `Send` left to block in: the component is the
> CALLER, and the executive answers with `reply_on` (`decode_reply`), which cannot block.
>
> **Turning it on root-caused two further REAL defects.** (1) `component_pump` did not screen
> BOUND-NOTIFICATION deliveries: the executive's root TCB has the HPET notification bound to it, so a
> tick can satisfy any blocking `Recv` including a pump's — the kernel returns `rdi = badge`,
> `rsi = 0` and leaves the message registers untouched, and the pump read that as a component message
> with label 0 and WALLED npfs (`[pump] WALL label=0 ip=0x771`). Fixed unconditionally and proven by
> `exec_pump_screens_bound_notification` (a real injected delivery on a real dispatch, with a bypass
> experiment that reproduces the wall). (2) Pipe parking was per-CONNECTION rather than
> per-DIRECTION, so an rpcrt4 server's pending READ refused its own response WRITE with
> `STATUS_INSUFFICIENT_RESOURCES` — which is how the 48-byte `LsarOpenPolicy` RESPONSE was silently
> lost. Fixed + host-tested (`PipeWaiterTable::parked_on_dir`), gated behind `PIPE_FULL_DUPLEX_PARK`.
>
> **DESKTOP FRONTIER — where the logon now stands.** With both fixes and the route on, the chain
> advances for real: the `LsarOpenPolicy` responses are DELIVERED (status 0, 48 bytes),
> `SamIConnect-null-root-miss` goes 1 → 0, `sam-setup-keys` 2 → 36, `sam-mount-opens` 1 → 2, and
> lsass reaches `NtCreateNamedPipeFile(\samr)` — samsrv publishes its own RPC endpoint. It does NOT
> reach a logon: `Administrator` is not validated and `WLX_SAS_ACTION_LOGON` is not returned.
> **Nothing is fabricated.** The route is re-gated OFF because the paint is not deterministic with it
> on — across five route-ON boots the desktop paint survived twice and was lost three times (no crash,
> no hang; winlogon starves while the self-RPC churns and the 45 s no-progress watchdog quiesces
> before the SAS window). **The remaining wall is FORWARD-PROGRESS SCHEDULING, not availability and
> not correlation** — a materially better-isolated problem than the one this section started with,
> and the next frontier.

> **Update (batch 51, gate 236/99) — BOTH FLAGS ARE ON PERMANENTLY. The "forward-progress
> scheduling" wall was a MISDIAGNOSIS: it was an HPET INTERRUPT STORM in the executive's own delay
> timer.** `LSA_WORKER_ROUTE_ENABLED = true` and `PIPE_FULL_DUPLEX_PARK = true`, with the paint
> DETERMINISTIC — **six consecutive foreground boots, all RUNEXIT=3, `microtest sentinel`, ZERO
> FAILs, gate 236/99, `diff`-identical 236-line PASS lists, paint 768/768 changed @ `0x003a6ea5`**.
> No kernel change (`rust-micro` untouched); **no scheduling context, budget, period or priority was
> changed anywhere**.
>
> **The measurement that turned it around.** The executive's service loop is single-threaded, so
> "who is starving whom" is countable. A per-badge census of it (loop events + wall-clock per badge,
> plus per-SSN histograms for lsass and winlogon) showed the LSA self-RPC is TINY — the
> per-connection worker costs **51** service events, against **49** for the known-good SCM `\ntsvcs`
> worker, and lsass' whole process issues ~1,300 native syscalls across ~40 distinct SSNs with no
> repeated SSN, no poll and no retry loop. Meanwhile the HPET delay-timer notification badge showed
> **2,773,385** events consuming **82 s**. Instrumenting the timer: **2,745,192 deliveries, of which
> 2,745,189 woke nothing.**
>
> **Root cause.** `delay_timer_rearm` toggled Timer-0 Configuration **bit 1** to arm/disarm. Bit 1 is
> `Tn_INT_TYPE_CNF` (edge/level); the enable is bit **2**, `Tn_INT_ENB_CNF`, set once by
> `delay_timer_init` and never cleared. "Disarm" only flipped the timer to edge-triggered and left it
> enabled with a comparator permanently behind the main counter, so it re-fired at ~34 kHz forever —
> each delivery a full round trip through the one service loop, which is what actually starved
> winlogon. It had never been seen because on a route-OFF boot the one-shot is **never armed at all**
> (measured: `ticks-seen = 0` on a control boot); the LSA route is simply the first thing that ever
> calls `NtDelayExecution`. Fixed by naming the bits and using the real enable: deliveries per boot
> 2,745,192 → **3-60**, woke-nothing → **0-1**. Proven by `exec_delay_timer_disarms`, which reads the
> LIVE `T0_CONFIG` back off the HPET at gate time. The 45 s no-progress watchdog fired CORRECTLY — it
> was reporting the storm, not causing it — and with the storm gone it does not fire at all.
>
> **DESKTOP FRONTIER — the logon chain now runs to token creation.** Against a route-OFF control boot
> of the same binaries: `SamIConnect-null-root-miss` 1 → **0** (the wall is GONE), `sam-setup-keys`
> 2 → **36**, `sam-mount-opens` 1 → **2**, LSA policy attribute reads 8 → **12**. The real LSA server
> thread runs the WHOLE `LsapLogonUser` → MSV1_0 → `SamValidateNormalUser` chain against a real
> `SampInitDatabase`, through the privilege lookups, and stops at the last step before it could
> answer: **`NtCreateToken` (SSN 57), which the executive does not service.** The connector is
> released with `STATUS_UNSUCCESSFUL` and msgina logs the real `LsaLogonUser failed (Status
> 0xc0000001)`. **Nothing is fabricated**: `Administrator` is not validated, no token is minted and
> `WLX_SAS_ACTION_LOGON` is not returned. **`NtCreateToken` is the next frontier** — a real service
> to implement (the token store, SID/group/privilege types and handle insertion already exist;
> `NtOpenProcessToken`, `NtDuplicateToken` and `NtQueryInformationToken` are already serviced).
> Four specs that pinned the OLD wall were re-pointed at the new one, each strictly stronger — see
> `docs/transport-migration.md` §Phase 5.5.

> **Update (batch 52, gate 239/99) — `NtCreateToken` IS SERVICED AND THE INTERACTIVE LOGON
> COMPLETES.** `LsaLogonUser` returns **STATUS_SUCCESS**. Three consecutive foreground boots, all
> RUNEXIT=3, `microtest sentinel`, **ZERO FAILs**, gate **239/99**, `diff`-identical 239-line PASS
> lists, paint **768/768 changed @ `0x003a6ea5`**. No kernel change (`rust-micro` untouched).
>
> **The service.** `NtCreateToken` is a **13-argument** system service: four arguments in
> `r10/rdx/r8/r9`, **nine off the caller's stack** at `[rsp+0x28 .. rsp+0x60]`. No new marshalling
> machinery was needed — the arity was already in `nt_syscall_abi::NT_ARGC` and the executive's
> dispatcher reads exactly `entry.max_args` slots through the client mirror; the handler asserts it
> received all 13 and fails closed otherwise (measured: `argc = 13`, **9/9** stack slots non-zero,
> including `TokenSource` at the very last slot). Six of the thirteen point at **variable-length
> structures in lsass' address space**, several of them arrays of pointers to SIDs; that walk is the
> pure, host-tested `nt_security::create_token` capture behind a `ClientMemory` trait (the executive
> plugs in `xas_read`). It fails closed at every step: the SID header is validated *before* its
> sub-authority tail is read, `GroupCount`/`PrivilegeCount` are bounded, the ACL is read exactly
> `AclSize` bytes and structurally validated, and every allocation goes through `try_reserve_exact`.
> **`SeCreateTokenPrivilege` is enforced** (ReactOS' order: token type first, then
> `SeSinglePrivilegeCheck`), and lsass really does hold it — its own
> `RtlAdjustPrivilege(SE_CREATE_TOKEN_PRIVILEGE, TRUE, …)` (`lsasrv.c:314`) enables the
> present-but-disabled privilege in the LocalSystem token through the real `NtAdjustPrivilegesToken`.
>
> **What the real chain produced.** `SamValidateNormalUser` validates **`Administrator`** against the
> real `SampInitDatabase`; `LsapSetPrivileges` honestly fails `LsapOpenDbObject(Accounts/S…)` on the
> fresh database, so the token carries **0 privileges** — that is the truth, not a gap we filled. The
> minted token, read back **out of the token store**: user SID with **5 sub-authorities, RID 500**,
> **8 groups**, `AuthenticationId = 0x3eb` (msgina's real `NtAllocateLocallyUniqueId`),
> `TOKEN_SOURCE = "User32  "`, `TokenPrimary`. `LSA_API_MSG.Status` = **STATUS_SUCCESS**, lsass
> duplicates the token into winlogon (`NtDuplicateObject … DUPLICATE_CLOSE_SOURCE`, handle `0x2a0`)
> and winlogon queries that same token object. New specs: `exec_se_create_token_serviced`,
> `exec_se_create_token_logon_token_shape`, `exec_winlogon_logon_token_received`. Four LSA specs that
> pinned the old wall were re-pointed at the completion, each strictly stronger (wall SSN → **no wall
> at all**; `replies + 1 == requests` → **`replies == requests`**; reply status **unset** → **0**;
> logon **in flight** → **completed**).
>
> **A real win32k defect the success exposed, and fixed.** `PsSetThreadWin32Thread` wrote only the
> executive's side cell; real NT writes `Thread->Tcb.Win32Thread` (`ntoskrnl/ps/thread.c:909`) and the
> MSVC win32k build **inlines** that read — `NtUserCallNoParam(NOPARAM_ROUTINE_DESTROY_CARET)`
> compiles to `call PsGetCurrentThread; mov rcx,[rax+0x250]; call co_IntDestroyCaret`. The first
> thing a SUCCESSFUL logon does is `EndDialog(WLX_SAS_ACTION_LOGON)` → dialog teardown → that path,
> so hosted win32k took a `#PF` at `cr2 = 0x60` (`pti->MessageQueue`) and the pump RETIRED it. Fixed
> by storing the pointer in the thread object (moved to its own DATA page, since `+0x250` overlapped
> the `SE_EXPORTS` placeholder) and publishing the dispatch THREADINFO there before every dispatch.
>
> **NEW FRONTIER — winlogon's post-logon path, and it is an ntdll item.** winlogon proceeds past the
> logon (spawns a real worker, allocates) and then faults **in our own ntdll**:
> `RtlQueryInformationActivationContext` (`nt-ntdll.dll` RVA `0x1d1d0+0xbd`) walks
> `gs:[0x30] → TEB+0x2C8 (ActivationContextStackPointer) → [0] (ActiveFrame) → [+8]` and finds the
> **non-pointer** value `0x0000_0006_0010_0000` in `ActiveFrame` (`cr2 = 0x6_0010_0008`,
> `rip = 0x1_0081_d28d`). `RtlAllocateActivationContextStack` is idempotent and zeroes `ActiveFrame`,
> so either `TEB+0x2C8` does not point at an `ACTIVATION_CONTEXT_STACK` for this thread or that field
> was overwritten. The thread takes a **MILESTONE park** at the achieved logon (never a crash park —
> a crash park latches the whole process as a dead win32k callback client, which is wrong when only
> one thread is stuck). `WLX_SAS_ACTION_LOGON` reaching `userinit.exe` is downstream of that fix.

> **Update (batch 54, gate 241/99) — the post-logon path RUNS: `WLX_SAS_ACTION_LOGON` really comes
> back and winlogon reaches `LoadUserProfileW`. Two real defects fixed, NEITHER of them ntdll.**
> Three consecutive foreground boots, all RUNEXIT=3, `microtest sentinel`, **ZERO FAILs**, gate
> **241/99**, `diff`-identical 241-line PASS lists, paint **768/768 changed @ `0x003a6ea5`**. No
> kernel change (`rust-micro` untouched). **`RtlQueryInformationActivationContext` was CORRECT all
> along** — the batch-52 fault was a memory-ownership bug in the executive, not an ntdll bug.
>
> **(1) A thread's `ACTIVATION_CONTEXT_STACK` now has its OWN PRIVATE PAGE.** `TEB+0x2C8` pointed at
> `TEB+0x1800` — inside the TEB's *second page*. Both TEB pages are deliberately
> `csrss_frame_put`-registered as CLIENT FRAMES, because hosted win32k dereferences the caller's TEB
> directly under the KeStackAttachProcess model, so a win32k fault at either TEB VA is answered with
> the client's own frame. win32k's USER server-side writes therefore landed in the client's real TEB
> and scribbled the ACS: the page was dumped live holding RECT-shaped values, `0xffff` sentinels and
> `0x00c8d0d4` (`COLOR_BTNFACE`) repeatedly, spanning `TEB+0x1000..0x18B8`, with the non-pointer
> `ActiveFrame = 0x0000_0006_0010_0000` that batch 52 faulted on. `TEB+0x2C8` itself was always
> right; the memory under it was not. Real NT never puts this structure in the TEB either — it is a
> heap allocation (`RtlAllocateActivationContextStack`) reachable ONLY through `TEB+0x2C8`. It now
> gets its own page on BOTH spawn paths (`img_spawn::spawn_sec_image` for a process' main thread,
> `spawn_hosted_thread` for every hosted thread), deliberately **not** client-frame-registered, with
> the layout asserts tightened (`teb_va + 0x3000 <= tramp_va`, 5 scratch pages per worker env).
> Spec `exec_ntdll_activation_context_valid` reads winlogon's live mapping at gate time: the pointer
> targets the private page, the structure is the empty one the spawn wrote, **every byte past it is
> still zero**, the page is absent from the client-frame registry *while both TEB pages are in it*.
> **BYPASS** (move the ACS back to `TEB+0x1800`): 241/99 ZERO FAILs → **239/99 with 2 FAILs**,
> `exec_ntdll_activation_context_valid` and `exec_winlogon_logon_action_returned` both red, the
> post-logon path never reaching `HandleLogon` (ProfileList opens 1 → **0**).
>
> **(2) The user-callback nesting invariant is PER-CLIENT-THREAD.** Fixing (1) exposed a second, older
> defect immediately. `USER_CALLBACK_ACTIVE`/`USER_CALLBACK_CONTINUATIONS` were single GLOBAL LIFO
> stacks and the nesting test compared the incoming client identity against the stack's **global
> top** — sound only while one client thread ever has win32k work outstanding. Post-logon winlogon is
> genuinely multi-threaded, and it was measured twice on one boot: main (`badge 4/tid 6`) issuing
> `NtGdiGetTextMetricsW` (`0x1076`) while worker `badge 13/tid 21` sat redirected in
> `WM_WINDOWPOSCHANGING` from `NtUserSetFocus` (`0x1050`), and worker `badge 12/tid 20` issuing
> `0x1082` while main was redirected in `WM_NCCREATE`. Each was rejected as a "client identity
> mismatch", walled `0xC000000D`, and killed winlogon as a **dead callback client**. In NT a callback
> runs on the thread that entered win32k, so a call from a *different* thread is a **concurrent root**
> dispatch, not a nested one. Both stacks now hold the interleaved union of every thread's chain and
> every lookup is identity-scoped; "no frame for this identity" means root dispatch, not error. This
> is strictly stronger, not laxer — a nested frame's parent is *selected by* identity, so cross-thread
> misrouting is unrepresentable. The two glue-side arrays that were indexed in lockstep with the
> callback stack (the suspended `DispatchContext`, the bridged `CallbackWnd` triple) moved onto the
> frame, which is what makes removing a non-top frame safe. `nt-user-callback` 42 → **44** tests. Live
> boot: 1598 nested dispatches, nesting high-water 5, **zero** rejections, both injection proofs full.
> See `docs/user-callback-dispatch.md` §7b.
>
> **DESKTOP FRONTIER — where the logon now stands.** winlogon's own state machine runs on for real:
> `WlxLoggedOutSAS` → **`WLX_SAS_ACTION_LOGON`** → `DoGenericAction` (`sas.c:1214`) → `HandleLogon`
> (`sas.c:571`) → `LoadUserProfileW` (`sas.c:626`) → `userenv!GetProfilesDirectoryW`
> (`profile.c:1592`). Spec `exec_winlogon_logon_action_returned` pins it on the ProfileList key open,
> which is reachable from nowhere else in winlogon; the recogniser is **count-only** and changes no
> outcome. **`userinit.exe` was NOT spawned and nothing is fabricated.** The wall is
> `RegOpenKeyExW(HKLM, "Software\Microsoft\Windows NT\CurrentVersion\ProfileList")` →
> **`ERROR_FILE_NOT_FOUND`**, because **this host mounts no SOFTWARE hive** (SYSTEM, SECURITY and SAM
> only). `GetProfilesDirectoryW` fails → `LoadUserProfileW` fails → `HandleLogon` takes
> `goto cleanup` (`sas.c:628-629`) → `WlxDisplaySASNotice` and back to the logon screen, and the boot
> quiesces at its normal SAS milestone (no crash park). **Next frontier: mount the real SOFTWARE hive
> as a 4th `regf` mount.** The genuine 471 KiB ReactOS `software` hive is already in the fetched tree
> and does contain `ProfileList\ProfilesDirectory`; `userinit.exe` (300544 B) is already staged and
> resolvable at `\reactos\system32\userinit.exe` via the recursive full-FS copy. Downstream of that
> hive: `CreateUserEnvironment` → `SetDefaultLanguage` → `AllowAccessOnSession` →
> `StartUserShell` → `CreateProcessAsUserW(userinit.exe)` as a real 6th hosted process under the
> logon token.
>
> **One spec re-pointed, honestly.** `exec_general_nt_create_thread` sampled the LIVE `WL_LISTENER_TCB`
> cell. That cell is zeroed by the real thread-termination mechanism, and it now legitimately is:
> past the logon winlogon's two transient workers (tids 20/21) run to completion and self-terminate,
> so the post-quiesce dead-client injection — which deliberately kills an *expendable* winlogon worker
> — reaches its last candidate, the RPC listener, and reclaims its TCB before the gate. The liveness
> clause was measuring the injection's victim choice, not the service. It now reads the **write-once
> mint latch** of the TCB the service created (`WL_LISTENER_TCB_MINTED`) and **adds** a clause that
> the created thread actually RAN (`WL_WORKER_FAULTS >= 1`), which the old form never asserted. Same
> precedent as `exec_svc_rpc_listener_multiplex`.

---

## 7. Corrections to `ntdll_plan.md`

Found while re-measuring at `6dee67e`. The log is not being edited (it is history); these are the
authoritative values.

| claim in the log | status | truth |
|---|---|---|
| §A's whole completeness table (377 classified exports, 189 `Nt*`, 276 `Rtl*`, "6 explicit NOT_IMPLEMENTED", "1 truly-missing required import `RtlDeleteResource`") | **superseded** | §2 above. §A is flagged stale in the log itself; treat none of its numbers as current. |
| §A: exports enumerated via `heap_noop_bool!`/`dbgui_noop!` macros | **stale** | those macros no longer exist. The live macros are `generate_trap_stubs!`, `zw_alias!`, `etw_ok!`, `etw_scenario_write!`. |
| §E.0/§E.5: "97 raw `STATUS_NOT_IMPLEMENTED` tokens, 77 host-build fallback arms" | **moved** | now **108** raw tokens across 87 exported functions: 83 pure host arms + 2 host-arm-plus-real-error-arm + 2 deliberate unconditional. The *conclusion* (0 genuine unconditional stubs) still holds. |
| §E.5/§F: "1303 spec names, 194 still unexported, 26 of them `Rtl*`/`Ldr*`" | **not reproducible; understated** | `ntdll.spec` minus `-arch=i386` rows = **1882** names; **564** unexported (185 `Nt*`, 179 `Zw*`, 107 `Rtl*`, 23 `Rtlp*`, 42 `Tp*`, 6 `Ldr*`, 22 other), 289 of which ReactOS `-stub`s too. I could not derive 1303/194 from the spec under any filter and cannot verify where it came from. |
| §E.5: "add the ~26 spec `Zw*` aliases that already have an `Nt*` twin" | **wrong, now closed** | the only five unexported `Zw*` names with exported `Nt*` twins were the Dbgk aliases, and the 2026-07-30 alias pickup exported them. Everything else would need its `Nt*` twin *and* an executive service first. |
| §D: for the 5 dbgk SSNs, "`Zw*` aliases + `NT_ARGC` rows added alongside" | **now true** | originally only added to `ZW_ALIASES`; the 2026-07-30 alias pickup exported all five Dbgk `Zw*` names and added a verifier gate over the complete alias table. |
| §D: "`Thread->HideFromDebugger` — we have no such flag" | **false; fixed 2026-08-14** | the flag exists (`crates/nt-process/src/lib.rs:429`), is set through `NtSetInformationThread` class 17 (`exec_handler.rs:2155`) and is queryable (class 17 read at `lib.rs:940`). Dbgk per-thread live event posting now consults it before queueing reporting-thread notifications. |
| §E.5: "`RtlCompactHeap` (⇒ 0) already matches ReactOS's `@unimplemented`" | **stale** | it now has a real body (`heap_compact`: coalesce + return the largest free payload extent), with an `INVALID_PARAMETER` error path. |
| §E.0: "546 distinct `ntdll` imports across the live-loaded set (38 binaries)" | **consistent, different population** | my 42-binary live list gives **554**; the whole-`system32` figure (**593**) reproduces exactly. Both are **0-missing**, which is the load-bearing claim. |
| §A/§E: `CsrClientCallServer`/`CsrGetProcessId` are NOT_IMPLEMENTED stubs | **stale** | both are real bodies; §E.0 already corrected this. |

Anything in `ntdll_plan.md` not listed here was either verified or not re-checked; when in doubt,
**re-measure** with the recipes in §2 rather than trusting the prose.

> **Update (batch 55, gate 243/99) — the SOFTWARE hive is a REAL 4th `regf` mount and
> `GetProfilesDirectoryW` SUCCEEDS. Neither change is an ntdll change.** Four consecutive
> foreground boots, all RUNEXIT=3, `microtest sentinel`, **ZERO FAILs**, gate **243/99**,
> `diff`-identical 243-line PASS lists, paint **768/768 changed @ `0x003a6ea5`**. No kernel change
> (`rust-micro` untouched).
>
> **(1) The 4th slot is the SAME general mechanism.** `HIVE_SEL_SOFTWARE = 0x2000_0000` joins
> SYSTEM (0) / SECURITY (`0x4000_0000`) / SAM (`0x6000_0000`) in the `KeyRef` top-nibble scheme, so
> `base_hive()`, `hive_mount()`, `registry_target_path`, `registry_value(s)`, `registry_subkeys`,
> the relative open/create arms and the overlay all serve `\Registry\Machine\SOFTWARE` with no new
> code paths; `resolve_key` gains one arm, placed AFTER the CPU/Winlogon synthetic checks so no
> pre-existing resolution changes. **Budget:** the genuine 471040 B hive is ~57x the 8 KiB
> SECURITY/SAM hives and does NOT fit in the leftover of the shared 0xA0-0xC0 input page table, so
> it got its own 2 MiB window + **dedicated PT** at `0x0000_0100_10E0_0000` (128 frames = 512 KiB),
> mirrored into the isolated storage host — **+128 frames, +1 PT, ~+257 root CSpace slots**, and
> nothing else had to be raised. FS-by-path hits 33 → 34, **fallbacks still 0**.
> `ProfileList\ProfilesDirectory` reads back as `REG_EXPAND_SZ "%SystemDrive%\Profiles"`, asserted
> by content in `exec_software_hive_mounted`.
>
> **(2) ★ Broad `HKLM\Software` success REGRESSES THE PAINT — measured.** The first cut accepted any
> winlogon open that resolved into the SOFTWARE hive. `…\CurrentVersion\Drivers32` then resolved for
> the first time, winmm's DllMain took its REAL legacy-driver path (beepmidi/msacm32.drv/msacm32 +
> a `system.ini` probe), and the SAS window's `WM_NCCREATE` died in a hosted-win32k `#PF` at
> `cr2=0xb0` → **"WL: Failed to create SAS window"** → "WL: Failed to initialize SAS": gate
> **218/99, 23 FAILs**. Same hazard the keyboard-layout and Winlogon-key notes already record. The
> winlogon route is therefore EXACT-NAME scoped on the existing `is_profile_list_key` recogniser, in
> the established pattern; the general mechanism serves SOFTWARE everywhere else.
>
> **(3) One pre-existing tripwire removed, honestly.** `NtCreateFile` on an unsupported file
> namespace used to set `self.stop` — an unrecoverable **process park**. The mount made it reachable
> for the first time (services/lsass find `Drivers32` too) and it killed pi 3 and pi 4 mid-boot. It
> now returns **STATUS_NOT_IMPLEMENTED**: no fabricated handle, the caller decides. Behaviour-
> preserving for every earlier boot — the branch was never taken before.
>
> **DESKTOP FRONTIER — and it is no longer a registry frontier.** `HandleLogon` →
> `LoadUserProfileW` → `GetProfilesDirectoryW` **SUCCEEDS** → `CreateUserProfileW`, which reaches
> the real profile SID (`profile.c:2056  Loading profile S-1-5-21-…-500` — the token lsass minted)
> and opens ProfileList a SECOND time; both opens are served by the mount and both
> `ProfilesDirectory` reads are copied out (`exec_winlogon_profile_directory_resolved`). It then
> calls `CreateDirectoryW("C:\Profiles")` (`profile.c:929`) and **this host has no writable
> filesystem** → `GetLastError() == 1` → `profile.c:933  Error: 1` → `CreateUserProfileW() failed`
> → `LoadUserProfileW` fails → `goto cleanup`. **`userinit.exe` was NOT spawned; `StartUserShell` /
> `WlxActivateUserShell` are NOT reached, and nothing is fabricated.** The boot quiesces at its
> normal SAS milestone (no crash park). **Next frontier: a WRITABLE filesystem — directory create +
> file write — for hosted processes.** Note also that `WlxActivateUserShell` (`msgina.c:487-510`)
> reads `Userinit` from the Winlogon key, still answered by `SYNTH_WINLOGON_KEY`; the real hive has
> `Userinit = "%SystemRoot%\system32\userinit.exe"` but ALSO `AutoAdminLogon = "1"`, which would
> change the logon flow that currently produces the paint — routing that one key to the real hive is
> a deliberate, separate decision.
>
> **BYPASS** (`SOFTWARE_HIVE_MOUNTED = false`): 243/99 ZERO FAILs → **241/99 with exactly 2 FAILs**,
> `exec_software_hive_mounted` and `exec_winlogon_profile_directory_resolved` both red,
> `[dbg] GetProfilesDirectoryW() failed (Error 2)` back, ProfileList opens 2 → 1, served-from-mount
> 2 → 0, `ProfilesDirectory` value-reads 2 → 0. Paint stays 768/768; every other spec stays green.

> **Update (batch 56, gate 245/99) — a REAL WRITABLE FILESYSTEM is mounted, and
> `CreateDirectoryW("C:\Profiles")` SUCCEEDS.** Not an ntdll change (executive + `nt-fs`), and no
> kernel change (`rust-micro` untouched). Four consecutive foreground boots, all RUNEXIT=3,
> `microtest sentinel`, **ZERO FAILs**, gate **245/99**, `diff`-identical 245-line PASS lists, paint
> **768/768 changed @ `0x003a6ea5`**.
>
> **(1) A general "writable mount at prefix P", not a per-call fake.** A path belongs to the writable
> volume iff its canonical volume-relative form — the SAME `nt_path_to_volume_relative`
> canonicalisation the read-only FAT reader uses — is at or under one of
> `writable_fs::WRITABLE_PREFIXES` (today one entry, `profiles` = `%SystemDrive%\Profiles`). The test
> is `nt_fs::writable_mount_relative` / `is_under_prefix`, component-wise (`profiles2` is not under
> `profiles`) and still `..`-escape-rejecting. Adding a writable subtree is ONE table entry.
> `\reactos\…` is outside every prefix and keeps resolving through the read-only reader untouched.
>
> **(2) The backing REUSES `nt-fs`'s `MemFs`** behind its `FileSystem` `Zw*` facade — no new
> filesystem was written. `MemFs` gained the pieces a writable volume owes a caller: DOS attributes,
> a parent link, `.`/`..`-first enumeration through the SAME `nt_fs::query_directory` encoder the FAT
> volume uses, `FileBasic`/`FileDisposition`/`FilePosition`/`FileEndOfFile`/`FileAllocation`
> set-information, delete-on-close that really unlinks, and file-object reference counting. Routed
> syscalls: `NtCreateFile`, `NtOpenFile`, `NtQueryAttributesFile`, `NtRead/WriteFile`,
> `NtQuery/SetInformationFile`, `NtQueryDirectoryFile`, `NtFlushBuffersFile`,
> `NtQueryVolumeInformationFile`, `NtClose`, `NtDuplicateObject`. Handles are real per-process
> `nt-process` handles (`HandleObject::OverlayFile`). The volume survives the service loop's
> per-syscall bump reset via a `writable_fs_dirty` mark pin — the exact `overlay_dirty` contract the
> CM write plane already uses.
>
> **(3) It is REAL, proven two ways.** A mount-time self-test runs the whole surface on a scratch
> subtree outside every writable prefix (so `\profiles` is left pristine): directory create; the SAME
> create COLLIDING; file create; write; read-back of the same bytes; metadata agreeing; enumeration
> finding `.`, `..` and the file; delete-on-close really unlinking both so the by-path attribute
> queries MISS; and a volume left with exactly its root. All 9 bits set (`selftest=0x1FF`). Plus the
> live syscall counters: winlogon really created 2 directories through `NtCreateFile` and really
> missed 1 by-path attribute query through `NtQueryAttributesFile`.
>
> **★★ UPDATE (batch 58, gate 248/99) — THE "TIME BUDGET" WAS A HANG, AND THE PROFILE FLOW NOW
> SHIPS ON.** Batch 57's claim (repeated below) that the profile flow "no longer reaches quiesce
> inside the ~555 s TCG budget" because its post-logon UI work "grows ~2.5x" was **wrong, and the
> census says so**. Host-side timestamps on the serial log show the boot goes **completely silent at
> t = 310 s and produces ZERO output for the remaining 245 s**, with the last line a
> `[win32k-svc] -> SSN 0x1006 (dispatch)` that never replies. `0x1006` is `NtUserGetMessage`, and
> win32k is driven **synchronously by the single-threaded service loop** — so
> `co_IntGetPeekMessage`'s wait blocks the whole system AND the loop-top wall-clock stall watchdog
> with it, which is why the boot could not even quiesce to the gate. `RUNEXIT=124` was a DEADLOCK,
> never a budget overrun.
>
> **THE GENERAL FIX** is NT's own definition of GetMessage — *peek, then wait*: before letting a
> blocking `NtUserGetMessage` into win32k the executive dispatches the caller's own arguments through
> the non-blocking `NtUserPeekMessage(PM_NOREMOVE)`. A non-empty queue dispatches exactly as before;
> an EMPTY queue — the only case that could hang — takes the established milestone park. Guarded by
> `GET_MESSAGE_EMPTY_QUEUE_GUARD` and asserted by `exec_win32k_blocking_getmessage_guarded`
> (preflight peeks 6, empty-queue parks 2). **BYPASS: `false` ⇒ `RUNEXIT=124` at 555 s, the gate
> never runs.** A worker thread's empty pump parks the THREAD and lets the loop continue (bounded
> grace); only winlogon's MAIN thread's empty SAS loop still ends the boot — quiescing on the worker
> cut `CopyDirectory` off mid-tree.
>
> **`PROVISION_DEFAULT_USER_PROFILE = true` NOW SHIPS**, and `userenv!CopyDirectory` REALLY RUNS:
> **20 subdirectories** created below `C:\Profiles\Administrator` and **2 files copied**, with
> `C:\Profiles\Administrator\My Documents\livecd_start.cmd` reading back off the LIVE writable volume
> with the ISO source's exact 9 bytes (`exec_winlogon_profile_copied`). Getting there needed four
> more MEASURED fixes: (1) `NtQueryInformationFile` served only `FileStandardInformation`, so
> `CreateDirectoryExW`'s `FileBasicInformation`/`FileEaInformation` queries failed ⇒ `Error: 87`
> (both now encoded honestly — real kind, zero timestamps, `EaSize = 0`); (2) the writable overlay
> inherited the isolated-FSD 16 KiB argument-window cap, so `CopyLoop`'s 64 KiB `NtReadFile` was
> refused ⇒ `Error: 1784` (an overlay read is served in-process and never crosses that transport);
> (3) `NtSetInformationFile`'s staging buffer was **32** bytes while `FILE_BASIC_INFORMATION` is
> **40**, so `SetLastWriteTime` — which ends every `CopyFileW` — arrived truncated ⇒ `Error: 24`;
> (4) a latent **executive stack overflow** (two whole-`VmRegionMap` copies per VM syscall, on a
> rootserver stack that floats right after `.bss`) — both snapshots moved to static scratch.
>
> **WHERE WINLOGON STOPS NOW (verified):** `directory.c:148  Error: 1450` on
> `…\Quick Launch\Command Prompt.lnk`, traced to **`SSN=18 -> 0xC000009A`** — winlogon's
> `NtAllocateVirtualMemory` of `CopyLoop`'s 64 KiB buffer. **NOT** the VAD map: a control boot at
> `VM_REGION_CAPACITY = 256` gave the same status at the same file with byte-identical overlay
> counters, so it is the frame / page-table commit under `vm_map_private_page` (the executive's boot
> frame budget). `NtLoadKey`/`NtUnloadKey`, `\Registry\User` and `userinit.exe` are still ahead.
>
> **WHERE THE WALL-CLOCK GOES** (now measurable — the census dumps every 30 s including from inside
> the nested win32k pump, and the per-SSN histogram covers the win32k shadow table): of a 323.6 s
> boot, **201.6 s across 3787 win32k dispatches (avg 53 ms)**. Hottest: `0x10fa`
> NtUserProcessConnect 90.7 s, `0x10bd` NtUserGetClassInfo 40.8 s, `0x1058` 22.1 s, `0x125a`
> NtUserInitialize 20.0 s, `0x10b4` 10.7 s. Per-pi: winlogon 3540, services 122, lsass 122, csrss 4.
> Nothing pathological — demand-faults **2**, heap **36 %**, user-callback pushes == unwinds, timer
> ticks 3 with 0 spurious. TCG really is that slow per win32k round-trip; the budget is fine.
>
> **★ UPDATE (batch 57, gate 246/99) — THE PROFILE SOURCE WAS A STAGING GAP, NOT MISSING MEDIA.**
> The claim below that "our media is a LiveCD extract with no profile tree" was WRONG. The ReactOS
> LiveCD ISO carries a real **76-entry `Profiles/` tree** (`Default User/…`, `All Users/…`) as a
> **TOP-LEVEL sibling of `reactos/`**, and every extraction in `fetch_reactos.sh` was scoped to
> `reactos`, so it was silently dropped and never reached the disk image. It is now extracted
> (`.profiles-ok` marker) and laid down at **`::Profiles`** — exactly what `%SystemDrive%\Profiles`
> resolves to — and proved BY PATH off the read-only FAT volume: `\Profiles\Default User` is a real
> directory and `\Profiles\Default User\My Documents\livecd_start.cmd` reads back the ISO's exact
> 9 bytes (`exec_default_user_profile_staged`). The ISO has **no `ntuser.dat` anywhere**; the real
> `\reactos\system32\config\default` prototype hive (`$$$PROTO.HIV`, 139264 B) is now staged into
> its own DEFHIVEBUF window for the `NtLoadKey` / `\Registry\User\.Default` work.
>
> **Composition:** `C:\Profiles` is a writable-volume (MemFs) prefix while the staged tree is on the
> read-only FAT volume, so the executive **materialises** the staged tree onto the writable volume at
> mount (chosen over a union layer: one code path, so `CopyDirectory` enumerates/reads the source and
> writes the destination with no per-operation arbitration). Measured working — `dirs=45 files=31
> bytes=5307`, `Default User` enumerating its real 17 records, a staged file's bytes read back — but
> it **ships behind `PROVISION_DEFAULT_USER_PROFILE = false` for a measured TIME reason, not a
> defect**: with it on, winlogon's profile flow runs on instead of dying at `FindFirstFileW`, its
> post-logon win32k/UI work grows ~2.5x, and the boot stops reaching quiesce inside the gate's ~555s
> TCG budget (RUNEXIT=124). **That budget is now the binding constraint on advancing winlogon past
> the logon.**
>
> **Three real enumeration bugs were root-caused and fixed** (each MEASURED with a bounded
> `[query-dir]` trace, because `Error: 998`/`1450` are ambiguous): (1) our `NtQueryDirectoryFile`
> demanded an 8-byte-aligned output buffer where NT does `ProbeForWrite(…, sizeof(ULONG))` = 4, and
> kernel32's `FindFirstFileExW` buffer is literally `DECLSPEC_ALIGN(4)`; (2) `probe_user_output` did
> not know a hosted stack GROWS BELOW its declared window (the 16 KiB `FindFirstFileExW` buffer lands
> ~12 KiB under it and is demand-faulted in) — widened MONOTONELY, and only via a real
> `client_range_has_backing` check; (3) `Length`/`ReturnSingleEntry`/`RestartScan` are ULONG/BOOLEAN
> **stack** arguments whose high bits are caller junk (`0x0000_0100_0000_4000` for 16384) — truncated
> to the declared width, scoped to the writable volume because widening the FAT path unblocks a large
> population of loader enumerations at once and destabilised the boot.
>
> **The bump heap was at 93%** (1953957/2097152, now instrumented at the gate). A no-free bump heap at
> its cap does not panic — allocations return null and callers take error paths, which is what a
> mysteriously slow, never-quiescing boot looks like. `HEAP_FRAMES` 512 -> 1536 (executive only;
> `SERVICE_HEAP_FRAMES` stays 512 per the recorded lesson).
>
> **`NtLoadKey`/`NtUnloadKey`, `\Registry\User` and the 5th dynamic mount are NOT implemented** —
> nothing claims a hive was loaded. `userinit.exe` was **NOT** spawned; there is no 6th hosted
> process. `Userinit`/`AutoAdminLogon`: nothing changed, and `AutoAdminLogon` cannot leak (winlogon's
> SOFTWARE route stays exact-name scoped on `is_profile_list_key`).
>
> **DESKTOP FRONTIER — the profile TREE is built; the profile SOURCE and the user HIVE are not.**
> `CreateUserProfileW` now creates `C:\Profiles` (`profile.c:929` — the old `Error: 1`) and
> `C:\Profiles\Administrator` (`profile.c:963`), then calls `CopyDirectory(…, "C:\Profiles\Default
> User")` (`profile.c:1000`) and fails at **`profile.c:1002  Error: 3`** (ERROR_PATH_NOT_FOUND): our
> media is a LIVECD extract with no profile tree, because ReactOS SETUP is what creates one. So
> `LoadUserProfileW` still fails and **`userinit.exe` was NOT spawned; `StartUserShell` /
> `WlxActivateUserShell` are NOT reached.** Behind that sits a second, larger wall:
> `RegLoadKeyW(HKEY_USERS, <SID>, "…\ntuser.dat")` — **`NtLoadKey` (102) / `NtUnloadKey` (272) are
> not serviced**, and an unserviced SSN PARKS the caller, so a real `ntuser.dat` + those two services
> + an `HKEY_USERS` namespace is the next milestone. Provisioning the `Default User` skeleton was
> measured for one boot and is NOT a clean advance (`Error: 998` from the enumeration, and the boot
> hung, `RUNEXIT=124`); it stays off behind `PROVISION_DEFAULT_USER_PROFILE`.
> **`Userinit`/`AutoAdminLogon`: nothing was changed** — `WlxActivateUserShell` was never reached, the
> Winlogon key is still `SYNTH_WINLOGON_KEY`, and `AutoAdminLogon` cannot leak because winlogon's
> SOFTWARE route stays exact-name scoped on `is_profile_list_key`.
>
> **★ TRACKED FOLLOW-UP — persistent FAT32 write-through.** The volume is RAM-backed; everything
> written is gone at the next boot. That is a deliberate, user-approved staging step. Making it
> persist is a separate milestone: the seam is already in place (every caller is above `nt-fs`'s
> `Zw*` surface and `writable_fs` is the only module that knows what backs the volume), and the work
> is FAT cluster allocation + FAT-chain update, directory-entry creation (8.3 + LFN write), size /
> timestamp update on close, and write ordering through the isolated storage host.
>
> **BYPASS** (`WRITABLE_OVERLAY_MOUNTED = false`): 245/99 ZERO FAILs → **243/99 with exactly 2
> FAILs**, `exec_writable_overlay_mounted` and `exec_winlogon_profile_directories_created` both red,
> `profile.c:933  Error: 1` back, every overlay counter 0. Paint stays 768/768; every other spec
> stays green.

> **★★ UPDATE (batch 59, gate 250/99) — THE "FRAME BUDGET" WAS A MISSING VSpace ASID, AND
> `CopyDirectory` NOW COMPLETES.** Not an ntdll change, and no kernel change (`rust-micro`
> untouched — the fix uses an invocation the kernel already implements). Three consecutive
> foreground boots, all `RUNEXIT=3`, `microtest sentinel`, **ZERO FAILs**, gate **250/99**,
> `diff`-identical 250-line PASS lists, paint **768/768 changed @ `0x003a6ea5`**.
>
> **(1) THE ROOT CAUSE, measured — not a budget at all.** Batch 58 traced winlogon's
> `userenv directory.c:148 Error: 1450` to `SSN=18 -> 0xC000009A`, the `NtAllocateVirtualMemory` of
> `CopyLoop`'s 64 KiB buffer, and (correctly) ruled out the VAD map. A new **pool census** — a
> high-water mark next to the capacity of every pool that backs hosted private memory, printed at the
> gate and every 30 s as `[pools]` — showed the boot Untyped at **167 MiB of 256 MiB (64 %)**, the
> frame registry at **9657/16384**, the recycled-frame free list at **16/4096**, the VAD at
> **20/64**, and **zero** exhaustion refusals anywhere. What it did show was `vm-fail map=1`: the
> refusal came from `page_map_r`, with seL4 error label **8 = `seL4_DeleteFirst`** — the leaf PTE at
> `0x0000_0100_305b_0000` was **already occupied**. A bounded `[vm-watch]` map/unmap trace over that
> one VA gave the whole story in one boot: winlogon mapped 16 pages there, unmapped all 16, and the
> next commit was refused.
>
> **Why the unmap did nothing.** seL4 finds the VSpace an `X86Page::Unmap` must edit by looking the
> FRAME cap's recorded ASID up against every PML4 cap (`invocation.rs pml4_paddr_for_asid`). A PML4
> retyped out of an Untyped starts with `asid == 0`, for which that lookup returns "no vspace" — so
> the unmap clears **nothing** and still returns **success** (`unmap-fails=0` for the whole boot,
> even through the `page_unmap_r` SYS_CALL form this batch introduced). The executive had never
> assigned ASIDs, so **every unmap of a hosted process's private page had always been a silent
> no-op**: the frame cap was freed and recycled while the leaf PTE stayed live. Nothing noticed until
> a VA was RE-COMMITTED — and then it surfaced as a phantom `STATUS_INSUFFICIENT_RESOURCES`, i.e. an
> exhausted-looking pool with 89 MiB of Untyped to spare.
>
> **(2) THE FIX is the piece seL4 always expected the root task to do:** `spawn_sec_image` /
> `spawn_pe_thread` now call `X86ASIDPoolAssign` on the fresh PML4 before anything is mapped into it
> (`vspace_assign_asid`, root-CSpace slot 6 = `seL4_CapInitThreadASIDPool`, legacy `a2 = vspace slot`
> ABI). **7 VSpaces assigned, 0 failures.** Shipped ON behind `VSPACE_ASIDS`. Component VSpaces
> (`spawn_component`, win32k) are deliberately left unassigned for now — `w32_client_attach`'s detach
> is written against the current no-op semantics, and making it real is a separate, measured step.
>
> **(3) PROVEN BY CONSTRUCTION, not by the absence of a symptom.** `exec_vspace_asid_unmap_clears_pte`
> runs a commit → decommit → **RE-COMMIT** of one private page in winlogon's real VSpace, on the real
> `vm_map_private_page` / `vm_unmap_private_page` path, at the very top of the private window
> (`PRIVATE_VM_LIMIT - 0x1000`, above every placement the boot makes): mapped, registered, released,
> **re-mapped at the same VA**, the released frame recycled, VA left clean (`proof=0x3f/0x3f`), plus
> `assigned >= 5`, `assign-failures == 0`, `private-map refusals == 0`, `unmap error-labels == 0`.
>
> **(4) WHAT IT BOUGHT.** `Error: 1450` is gone and `userenv!CopyDirectory` runs on:
> overlay **creates 23 -> 28, dirs 21 -> 25, reads 1 -> 3, writes 1 -> 3** — the Quick Launch
> `Command Prompt.lnk` / `ReactOS Explorer.lnk` and `livecd_start.cmd` really copy, and
> `exec_winlogon_profile_copied` still verifies destination content byte-for-byte.
>
> **(5) THE POOL CENSUS + THE 6th-PROCESS ANSWER (`exec_vm_pool_headroom`).** At the gate:
> Untyped **167601 KiB / 262144 KiB (64 %)**, root-CSpace slots **107704 / 130363 (82.6 %)**, frame
> registry **9657 / 16384 (59 %)**, free list **16 / 4096**, VAD **20 / 64 (31 %)**, and every
> refusal counter 0. **Root-CSpace slots are the binding constraint for a 6th hosted process**:
> `alloc_slot` is a pure bump allocator (a deleted cap's slot is never reused) and the root CNode's
> size is the KERNEL's `init_thread_cnode_size_bits`, so `userinit.exe` will hit that ceiling first.
> The spec holds cslots to 90 % and every other pool to 75 %. **Tracked follow-up: recycle freed
> root-CSpace slots** (a free list fed by the `cnode_delete_r` sites) — worth roughly the 22 k slots
> the boot currently leaks through `copy_cap` and the win32k attach path.
>
> **(6) THE NEW FRONTIER — the client TEB TAIL is server-writable, and kernel32 ASSERTs on it.**
> With the copy running, winlogon reaches kernel32
> `ASSERT(NtCurrentTeb()->StaticUnicodeString.MaximumLength == sizeof(StaticUnicodeBuffer))`
> (`dll/win32/kernel32/client/file/fileutils.c:26`), whose `int 3` lands as `cpu-exception(3)` at
> `ntdll+0x34477`. It is not a guess: `observe_client_teb_tail` reads the field through the
> executive's persistent alias of the client's 2nd TEB page (`env-scratch + 0x5000`) after every
> win32k dispatch and reports **`MaximumLength = 33`, `Buffer = 0xffff00c8_d0d40000`** — win32k's own
> USER server data, the same clobber batch 53 measured (both TEB pages are deliberately registered as
> win32k client frames under the `KeStackAttachProcess` model). **The repair is deliberately NOT
> shipped**: a boot with it applied was measured to run winlogon straight past the assertion into its
> post-profile MS-RPC path — `\pipe\lsarpc` opened, async `NtReadFile` pending, winlogon wait-parked
> on the completion event with lsass ALSO parked in `NtWaitForMultipleObjects` and no runnable
> signaler left. That deadlock is invisible to the service loop (blocked in `recv`, so even the
> loop-top wall-clock stall watchdog never runs) ⇒ `RUNEXIT=124`, no gate. **Making the TEB tail
> durable belongs with the RPC-completion work that has to follow it.**
>
> **(7) TWO PARK/DIAGNOSTIC FIXES that fell out of it.** (a) `park_and_log!` suppressed its
> `[parked]` line on the PROCESS's crash bit, so a genuinely new fault on a SECOND thread of a
> process whose worker had already milestone-parked printed **nothing** — the boot quiesced with no
> fault line at all. The log line is now keyed on the THREAD badge (the crash bit stays per process).
> (b) The winlogon POST-LOGON **milestone park** now covers *any* winlogon thread badge and the
> `cpu-exception(3)` arm as well as the `#PF` arm. That matters, not cosmetically: `park_and_log!`
> latches the whole process as a dead win32k callback client, which disarms the two post-quiesce
> callback injections (`exec_user_callback_dead_client_unwind`,
> `exec_win32k_transport_call_nested` — both went red for exactly this reason before the fix). The
> guard that keeps it honest is unchanged: `!client_has_active_callback_frames(2)`.
>
> **`NtLoadKey`/`NtUnloadKey`, `\Registry\User` and `userinit.exe` are NOT implemented in this
> batch** — nothing claims a hive was loaded and there is no 6th hosted process. `Userinit` /
> `AutoAdminLogon`: nothing changed; `WlxActivateUserShell` is still not reached and winlogon's
> SOFTWARE route stays exact-name scoped on `is_profile_list_key`, so `AutoAdminLogon` cannot leak.
>
> **BYPASS** (`VSPACE_ASIDS = false`): 250/99 ZERO FAILs → **249/99 with exactly 1 FAIL**,
> `exec_vspace_asid_unmap_clears_pte` red (`selftest=0x2f`, the RE-COMMIT bit unset),
> `[dbg] (dll\win32\userenv\directory.c:148) Error: 1450` back, `vm-fail map` 0 → 2, `asids` 7 → 0,
> and the overlay counters collapse to the pre-batch numbers (creates 28 → 23, dirs 25 → 21,
> reads 3 → 1, writes 3 → 1). Paint stays 768/768; every other spec stays green.

> **BATCH 60 (gate 250 -> 252/99, ZERO FAILs, RUNEXIT=3, sentinel, paint 767/768 @ `0x003a6ea5` plus
> cursor overlay, four consecutive foreground boots at 317-331 s with `diff`-identical 252-line PASS
> lists).**
>
> **(1) THE TEB-TAIL CLOBBER IS NOT win32k — the standing attribution is REFUTED.** The tail page is
> never handed to win32k at all (`win32k ro-maps = 0`); with it mapped READ-ONLY into win32k, win32k
> took ZERO store faults on it (`store-faults = 0`); the frame is not aliased (exactly one
> registration); and the good→bad transition never straddled a win32k dispatch — sampled before and
> after every dispatch at `win32k_dispatch_wide` (the funnel every nested dispatch also uses) and
> after every serviced native syscall. It only ever appeared across the window in which the CLIENT
> runs. `0x00c8d0d4` looking like `COLOR_BTNFACE` was a coincidence that cost two batches.
>
> **(2) WHAT SHIPS.** *The mapping class fix*: the tail page is read-only to win32k and the first
> store copy-on-writes into a private shadow seeded from the live page — the mapping-borne class is
> structurally impossible, measured cost zero, and its counters are the proof of (1). *The enforced
> invariant*: the page is also read-only in winlogon's own VSpace,
> `RtlNtStatusToDosError+0x12` (`ntdll+0x1c2c2`, the `TEB.LastStatusValue` store) is EMULATED in
> place so the protection stays continuously armed, every other client store is reported with its
> RIP, and `StaticUnicodeString`'s shape is re-asserted on every service-loop event. *The guard that
> generalises*: a 64-byte spawn CANARY at `TEB+0x1FC0`, asserted at the gate — it catches a field
> nobody has thought of yet, which an assertion on `StaticUnicodeString` alone never could.
>
> **(3) THE `\pipe\lsarpc` DEADLOCK WAS A REFUSED THREAD CREATE.** winlogon's post-profile
> `LsaOpenPolicy` binds `\??\pipe\lsarpc`; lsass' `\lsarpc` `RPCRT4_server_thread` accepts and calls
> `RPCRT4_new_client` → `CreateThread(RPCRT4_io_thread)`, and the executive refused it —
> `rpc_server.c:631 failed to create thread, error=5aa` (`ERROR_NO_SYSTEM_RESOURCES`) — because there
> was ONE named per-connection LSA worker slot and lsass' own self-RPC worker never frees it. rpcrt4
> released the connection, nobody read winlogon's bind PDU, and both sides parked. The fix COMPLETES
> the RPC: the additional connection worker is routed onto a FREE generic `(pi, slot)` hosted-thread
> layout, which is already general enough to need no new named slot.
>
> **(4) A WATCHDOG THAT FIRES INSIDE `recv`.** A coarse 20 s deadline joins `delay_timer_rearm`'s
> existing `min()` and is checked inside `recv_full_r12` — the one place the executive ever blocks,
> so nested component-pump receives are covered too (`watchdog_nested_rearm` re-arms + Acks from the
> pump path, which the main loop cannot do while blocked). Two consecutive silent periods TRIP it: it
> prints a full report (waiters, resume IPs, timer state) and the loop quiesces to the gate, so a
> deadlock ends as a gate line instead of `RUNEXIT=124`. `exec_delay_timer_disarms` is respected by
> construction — the trigger-type bit is never an arm control, every comparator write is strictly
> ahead of `now`, and a watchdog delivery counts as WORK so `spurious <= 64` keeps its meaning.
>
> **(5) NEW FRONTIER.** `CreateUserProfileW` completes and the `\pipe\lsarpc` bind is served; past it
> winlogon raises an unhandled CPU exception at `ntdll+0x13284 = RtlEnterCriticalSection+0x14`
> (milestone park, clean quiesce). **`NtLoadKey`/`NtUnloadKey` (SSN 102/272) were NOT reached and are
> NOT implemented; no hive is loaded and `userinit.exe` did not spawn.**

> **★★ BATCH 61 (gate 252 -> 253/99, ZERO FAILs, RUNEXIT=3, sentinel, paint 767/768 @ `0x003a6ea5`
> plus cursor overlay, three consecutive foreground boots at 326/329/323 s with `diff`-identical
> 253-line PASS lists) — THE WHOLE TEB-CLOBBER FAMILY WAS ONE MISSING KERNEL STEP:
> `KeGdiFlushUserBatch`.**
>
> **(1) THE MEASUREMENT, before any theory.** The `#GP(0)` at `ntdll+0x13284` disassembles to
> `RtlEnterCriticalSection+0x14 = lock incl 0x8(%rcx)` — the FIRST dereference of the critical
> section, so nothing about `DebugInfo`, `LockSemaphore` or our `Enter` logic was ever involved.
> A GPR dump at the fault gave `rcx = rax = 0x0005_0005_0018_010F`, **non-canonical** (which is why
> it is a `#GP(0)` and not a `#PF`), and `ret@sp+0x38 = rpcrt4+0x4d97e`. That call site is
> `RPCRT4_SetThreadCurrentConnection`: it calls `get_or_create_threaddata()`, which returns
> `NtCurrentTeb()->ReservedForNtRpc` (**x64 TEB+0x1698**) *without validating it* and then enters
> `tdata->cs` at `tdata + 0x10` (`0x…001800FF + 0x10 = 0x…0018010F`). A watch on that one slot
> showed `0 -> 0x0000_0100_3003_a240` (the REAL `HeapAlloc`'d `threaddata`, stored by rpcrt4 itself
> at `rpcrt4+0x5001f`) `-> 0x…300300ff -> 0x0000_0002_0058_00ff -> 0x0005_0005_0018_00ff`, with
> `TEB+0x1680 = 0xff`, `TEB+0x1690 = 0xffff00c8_d0d40000` and `TEB+0x16a0 = 0x8000` appearing
> around it — the same `0x00c8d0d4` bytes batches 53/59/60 chased.
>
> **(2) THE ROOT CAUSE.** `gdi32!GdiAllocBatchCommand` (`win32ss/gdi/gdi32/include/gdi32p.h:406`)
> writes every deferred GDI command into `TEB.GdiTebBatch.Buffer` at `TEB + 0x300 +
> GdiTebBatch.Offset` and bumps `Offset` / `GdiBatchCount`. Its overflow guard calls `NtGdiFlush()`
> and then **appends anyway**, because in real NT the flush is not what empties the buffer — the
> KERNEL is: `KiSystemCallHandler` (`ntoskrnl/ke/amd64/traphandler.c:180`) reads
> `NtCurrentTeb()->GdiBatchCount` **before dispatching any win32k system call** and calls
> `KeGdiFlushUserBatch()`, i.e. win32k's `NtGdiFlushUserBatch` (`win32ss/gdi/ntgdi/gdibatch.c:487`),
> whose last act is `GdiTebBatch.Offset = 0; GdiBatchCount = 0; GdiTebBatch.HDC = 0`. **Our
> executive — which is what plays `KiSystemCallHandler` for a hosted process' win32k syscalls —
> never did that step.** So `Offset` grew without bound (measured **`0x15BA`, 11.8x
> `GDIBATCHBUFSIZE`**) and marched GDI records through the caller's TEB: `Win32ClientInfo` (0x800),
> `StaticUnicodeString` (0x1258), the TLS slots (0x1480) and `ReservedForNtRpc` (0x1698). That is
> the single root cause of batch 53's `ACTIVATION_CONTEXT_STACK` clobber, batch 59/60's
> `StaticUnicodeString` clobber AND this `#GP` — and it is why win32k measured innocent every time
> it was accused (`w32 ro-maps = 0`, `store-faults = 0`): the writer was always the client's own
> gdi32, in the client's own window.
>
> **(3) THE FIX** is the kernel step, at the kernel's site, done by the kernel: `ke_gdi_flush_user_batch`
> runs at the win32k system-call entry and clears `Offset`/`GdiBatchCount` through the executive's
> OWN persistent aliases of the client's two TEB pages — never through win32k's view, so
> `exec_teb_not_clobbered_by_win32k`'s "win32k stored zero times" clause keeps its meaning. Ship
> switch `GDI_USER_BATCH_FLUSH`. **No `rust-micro` change.**
>
> **(4) WHAT BOUNDING `Offset` COSTS, AND WHY THE FLUSH WALKS THE RECORDS.** `ExtTextOutW`
> (`objects/text.c:603`) and `PolyPatBlt` (`objects/painting.c:655`) re-check the LIVE `Offset` after
> `GdiAllocBatchCommand` and fall through to the real `NtGdiExtTextOutW` **only when the record would
> not fit** — the runaway `Offset` is what forced those calls to reach win32k at all. Bounded, they
> start fitting and get batched, and this host does not execute batch records: winlogon's credential
> edit `ExtTextOut` moved off the syscall path exactly that way (`gdi-readbacks` 1 -> 0). The DATA did
> not disappear, only its transport, so the flush WALKS the records it clears (host-tested
> `nt_user_callback::walk_gdi_batch`, 5 new tests) and reads the `GdiBCTextOut` record's inline
> string — `[cred-inject] IDD_LOGON edit control RENDERED the injected user name (13 chars via
> GdiBCTextOut batch record)`. `GdiTebBatch.HDC` is deliberately NOT cleared (the one knowing
> deviation from `NtGdiFlushUserBatch`): left claimed, `gdi32p.h:443` refuses every other DC and
> gdi32 issues a real win32k system call, which is what this boot already did. **A control experiment
> that disabled batching outright (a non-HDC sentinel in `GdiTebBatch.HDC`) was measured and
> REJECTED: 226/99 with 27 FAILs — winlogon never reached its SAS post.** Executing the records via
> win32k's registered `BatchFlushRoutine` is the tracked next step; it changes what is DRAWN.
>
> **(5) THE SECOND `\pipe\lsarpc` WORKER WAS AN EMPTY ETHREAD POOL.** Past the `#GP`, winlogon
> really reaches its post-profile `LsaOpenPolicy`; rpcrt4 accepts a SECOND connection and asks for its
> per-connection `RPCRT4_io_thread`. Batch 60's "claim a generic worker slot" reached the create and
> it STILL failed — `[thread-pool] REFUSED NtCreateThread pi=4 used-mask=0x1f slots=5 pool-tids:
> 29 30 31 32 33`: the slot existed, the pre-created ETHREAD behind it did not.
> `PM_RUNTIME_THREAD_SLOTS` 5 -> 8. The RPC now completes and the in-`recv` deadman never trips.
>
> **(6) NEW SPEC** `exec_gdi_user_batch_flushed`: the kernel step really ran on a live client win32k
> syscall (`flushes = 221`), `Offset` never exceeded `GDIBATCHBUFSIZE` (`max 0x1EE / 0x4D8`),
> winlogon's live `ReservedForNtRpc` is canonical, `TEB+0x1680/0x1690/0x16a0` are still what the
> spawn left, and the `TEB+0x1FC0` canary is intact.
>
> **BYPASS** (`GDI_USER_BATCH_FLUSH = false`): 253/99 ZERO FAILs -> **252/99 with exactly 1 FAIL**
> (`exec_gdi_user_batch_flushed`), `live-Offset = 0x15BA`, `TEB+0x1690 = 0xffff00c8_d0d40000`,
> `ReservedForNtRpc = 0x0005_0005_0018_00ff`, and the `[cs-diag] #GP` at
> `RtlEnterCriticalSection+0x14` is back. Paint stays 767/768; every other spec stays green.
>
> **★ NEW FRONTIER.** `LoadUserProfileW` proceeds and reaches `profile.c:1094` — the
> `RegLoadKeyW(HKEY_USERS, <SID>, "<profile>\ntuser.dat")` site — which returns **`Error: 2`
> (ERROR_FILE_NOT_FOUND)**: the copied profile has no `ntuser.dat` (the ISO has none; `config\default`
> is staged in DEFHIVEBUF as the source). `NtLoadKey` (SSN 102) never appears in the trace and the
> caller does NOT park; `CreateUserProfileW` then fails and winlogon quiesces cleanly at its own
> main-loop `GetMessage`. **No hive is loaded, `NtLoadKey`/`NtUnloadKey` are still unimplemented, and
> `userinit.exe` did NOT spawn** — so `Userinit`/`AutoAdminLogon` is unchanged (`WlxActivateUserShell`
> is still not reached; winlogon's SOFTWARE route stays exact-name scoped). Root-CSpace slots at the
> gate: **107883 / 130357 (82.8 %)** with five processes.
