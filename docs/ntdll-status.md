# Our Rust `ntdll.dll` — current state

**ntdll measurements as of `6dee67e` (2026-07-26); boot gate now `225/99`, ZERO FAILs** (the
credential-input and LSA-authentication-port batches noted below §5 added 3 specs each and changed no
ntdll code — the LSA batch is executive/LPC work). This is the *current-state*
document for the ntdll effort. The blow-by-blow history (BATCH 1..54, §A..§F) lives in
`ntdll_plan.md`, which is now a historical log — read this file first, and go there only for the
diagnosis story behind a specific decision.

Every number below was **re-measured at `6dee67e`** against the built binary and the source tree (see
§2 for how). Where a claim in `ntdll_plan.md` did not survive re-measurement it is corrected in §7.

---

## 1. What our Rust ntdll IS

| piece | where | what |
|---|---|---|
| the pure core | `crates/nt-ntdll` | `no_std` rlib, host-tested with plain `cargo test`. All the *logic*: `rtl/*.rs` (54 modules), `loader/*.rs`, `heap.rs`, `sync.rs`, `nls.rs`, `printf.rs`, `crt.rs`, `dbg.rs`, `csr.rs`, `ki.rs`, `trap_stubs.rs`. |
| the DLL | `crates/nt-ntdll-dll` | a `cdylib` in **its own workspace** (it never builds for the host). ~47 kLOC of thin export wrappers: `exports.rs`, `security_exports.rs`, `on_target.rs` (the target-only tails), `seh.rs`, `lib.rs`. |
| byte-exact layouts | `crates/nt-ntdll-layout` | static-asserted x64 `PEB`/`TEB`/`LDR_DATA_TABLE_ENTRY`/`KUSER_SHARED_DATA` offsets. The one place ntdll and the executive agree on a field offset (e.g. `PEB_BEING_DEBUGGED_OFFSET`). |
| the shared SSN table | `crates/nt-syscall-abi` | **single source of truth** for the syscall ABI: `NT_SYSCALLS` (212 services), `ZW_ALIASES` (212), `NT_ARGC` (213 — `NtCreateThreadEx` has an arity row without a service row). SSNs are the **0-based line index in `references/reactos/ntoskrnl/sysfuncs.lst`**; both ntdll and the executive read this crate. |
| the build | `scripts/build_ntdll_dll.sh` | nightly + `-Zbuild-std`, a custom no-CRT `x86_64-pc-windows-gnullvm-nostd` target, `rust-lld`. Emits `.tmp/nt-ntdll.dll` (1 782 272 bytes at `6dee67e`). Hard gate: `tools/ntdll-dll-verify` parses the result with **the executive's own `nt-pe-loader`** and asserts PE32+/`IMAGE_FILE_DLL`, the complete `Nt*` ABI, `LdrpInitialize`, a `.reloc` directory, and per-stack-DLL import coverage. |
| staging | `rust-micro/scripts/make_image.sh:166-180` | copies `.tmp/nt-ntdll.dll` onto the image **as `\reactos\system32\ntdll.dll`**, overwriting the real ReactOS one. **There is no fallback** — no real ReactOS ntdll bytes exist on the image; every hosted process that loads "ntdll" gets ours. |

**Transport.** `Nt*` stubs do *not* issue a Windows `syscall`. They issue a real native seL4
`Call` on the process's fault endpoint (`CT_FAULT`), label `NT_NATIVE_SYSCALL_LABEL = 0x4E54` ("NT"),
6 message registers (SSN, caller RSP, arg1..arg4); reply = 1 MR (NTSTATUS). Wire format and the pure
pack/unpack live in `crates/nt-ntdll/src/native_call.rs`; the seam abstraction is
`crates/nt-ntdll/src/transport.rs`. Because our ntdll owns *every* syscall, the per-thread
`TCBSetHostedSyscalls` flag is simply left clear — **this needed no kernel change**. Out-params ride
on the existing client stack/heap/image mirror (MR1 = rsp).

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

**1337 exports, 0 forwarders.**

| prefix | count | note |
|---|---|---|
| `Nt*` | 214 | 212 SSN trap stubs + `NtCurrentTeb` + `NtGetTickCount` |
| `Zw*` | 207 | `zw_alias!` of the `Nt*` stubs — see §5 item 1 |
| `Rtl*` | 593 | incl. 13 `Rtlp*` |
| `Ldr*` | 54 | incl. `LdrpInitialize` |
| `Etw*` | 64 | 46 `etw_ok!` + 2 `etw_scenario_write!` no-ops + real ones |
| `Dbg*` | 18 | of which 10 `DbgUi*` |
| `Csr*` | 16 | |
| `Ki*` | 4 | the user dispatchers |
| CRT / crypto / Alpc / data | 167 | `mem*`/`str*`/`wcs*`/`sprintf`/`qsort`/math, `A_SHA*`/`MD4*`/`MD5*`, `Pfx*`, `Alpc*`, `__C_specific_handler`, `__chkstk`, `VerSetConditionMask`, the 3 `Nls*` data exports |

Roughly: 866 hand-written `#[export_name]` items + 212 macro trap stubs + 207 `zw_alias!` + 48 ETW
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
* We export **1337** names; **24** of ours are not in the spec at all (`LdrpInitialize`, `DllMain`,
  `RtlGetTickCount`, the `Rtl*_Ustr` helpers, `RtlUTF8ToUnicodeN`, `fma`/`fmaf`, …).
* **569** spec names we do not export — **289 of which ReactOS `-stub`s too**. By prefix:
  185 `Nt*`, 184 `Zw*`, 107 `Rtl*`, 23 `Rtlp*`, 42 `Tp*` (threadpool), 6 `Ldr*`, 22 other
  (`Exp*` SList, setjmp/longjmp, `sscanf`, ARM helpers).
* **None of the 569 is imported by anything we host** (§2.2).

### 2.5 Host tests

`cargo test -p <crate>` prints **one `test result:` line per target** (lib + doc-tests) — **sum
them**, don't read the last one.

| crate | tests | status |
|---|---|---|
| `nt-ntdll` | **692** | green |
| `nt-process` (incl. the Dbgk state machine) | **79** | green |
| `nt-syscall` | **42** | green |
| `nt-syscall-abi` | **15** | green |
| `nt-ntdll-layout` | **12** | green |

`nt-ntdll-dll` has no host tests by construction — it is a target-only `cdylib`; its correctness is
covered by the pure core's tests plus the boot gate.

---

## 3. What's implemented for real

Brief, by area — the code is the reference.

* **`Nt*`/`Zw*` transport stubs** (`nt-ntdll/src/trap_stubs.rs` + `nt-syscall-abi`) — 212 services,
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

1. **The 5 `Zw*` dbgk aliases (`ZwCreateDebugObject`, `ZwDebugActiveProcess`, `ZwDebugContinue`,
   `ZwRemoveProcessDebug`, `ZwWaitForDebugEvent`).** *Cheapest real item.* They already exist in
   `ZW_ALIASES` (212 rows) — the executive can service their SSNs — but `exports.rs` has only 207
   `zw_alias!` lines, so the DLL does not export them. Five mechanical lines. **This is the only
   unexported `Zw*` name in the whole spec that already has an exported `Nt*` twin** — the log's
   "~26 `Zw*` aliases" figure is wrong (§7).
2. **Tier-2/3 `Rtl*` breadth — low value, do on demand.** Of §C's named Tier-2 list only 5 names
   remain unexported: `RtlZeroHeap` (the only one ReactOS actually implements) plus
   `RtlOwnerAcesPresent`, `RtlAddMandatoryAce`, `RtlSidDominates`, `RtlSidEqualLevel` (all `-stub`
   +Vista in ReactOS). The wider tail is 569 spec names (§2.4). **None is imported by anything we
   host.** The rule that governs all of it:
   > **NEVER add a trap stub whose SSN the executive cannot service.** An unserviced SSN reaches
   > `park_and_log!(pi, b"unhandled-syscall", …)` and parks the process — a correct "not implemented"
   > answer would be replaced by a hang. This is why `RtlGetCurrentProcessorNumber` returns 0 rather
   > than forwarding to `NtGetCurrentProcessorNumber` (not in our table, not serviced), and why
   > `NtContinue`/`NtRaiseException` have no stubs.
3. **Dbgk deferred event sources / fidelity gaps** — each real, none blocking:
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
   * **`Thread->HideFromDebugger` is not consulted.** The ETHREAD flag **does exist** and is settable
     via `NtSetInformationThread` class 17 (`crates/nt-process/src/lib.rs:429/994`), but `dbgk.rs`
     never reads it, so every thread reports. (The log claims the flag does not exist — see §7.)
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
4. **`DBG_EXCEPTION_NOT_HANDLED` at a fault is a bookkeeping difference.** The reporter is left
   *cooperatively wait-parked* rather than *crash-parked*: the fault site's `[parked]` bookkeeping is
   not re-run from the wake path (the dead-client callback unwind **is**). The process still never
   resumes; only the park ledger it lands in differs.
5. **The contended critical-section path is structurally correct but never exercised.** `[cs-event]`
   is 0 on every boot, and the wait is issued with a NULL timeout (`RtlpTimeoutDisable`), so the
   `STATUS_POSSIBLE_DEADLOCK` arm cannot fire. Enabling a finite `RtlpTimeout` is a one-line change.
6. **`RtlWow64EnableFsRedirection`/`Ex` return `STATUS_NOT_IMPLEMENTED` by design** — do not "fix"
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
[ntos-exec summary: 225/99 executive->isolated-service checks passed]
```

followed by `[microtest sentinel matched -- exiting QEMU]` and `RUNEXIT=3`. **Zero `FAIL` lines** is
the bar. Sanity anchors that must stay PASS: `exec_win32k_desktop_painted` (768/768 px @
`0x003a6ea5`), `exec_msgina_logon_dialog_painted`, `exec_msgina_credential_keystrokes_delivered`,
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

---

## 7. Corrections to `ntdll_plan.md`

Found while re-measuring at `6dee67e`. The log is not being edited (it is history); these are the
authoritative values.

| claim in the log | status | truth |
|---|---|---|
| §A's whole completeness table (377 classified exports, 189 `Nt*`, 276 `Rtl*`, "6 explicit NOT_IMPLEMENTED", "1 truly-missing required import `RtlDeleteResource`") | **superseded** | §2 above. §A is flagged stale in the log itself; treat none of its numbers as current. |
| §A: exports enumerated via `heap_noop_bool!`/`dbgui_noop!` macros | **stale** | those macros no longer exist. The live macros are `generate_trap_stubs!`, `zw_alias!`, `etw_ok!`, `etw_scenario_write!`. |
| §E.0/§E.5: "97 raw `STATUS_NOT_IMPLEMENTED` tokens, 77 host-build fallback arms" | **moved** | now **108** raw tokens across 87 exported functions: 83 pure host arms + 2 host-arm-plus-real-error-arm + 2 deliberate unconditional. The *conclusion* (0 genuine unconditional stubs) still holds. |
| §E.5/§F: "1303 spec names, 194 still unexported, 26 of them `Rtl*`/`Ldr*`" | **not reproducible; understated** | `ntdll.spec` minus `-arch=i386` rows = **1882** names; **569** unexported (185 `Nt*`, 184 `Zw*`, 107 `Rtl*`, 23 `Rtlp*`, 42 `Tp*`, 6 `Ldr*`, 22 other), 289 of which ReactOS `-stub`s too. I could not derive 1303/194 from the spec under any filter and cannot verify where it came from. |
| §E.5: "add the ~26 spec `Zw*` aliases that already have an `Nt*` twin" | **wrong** | exactly **5** unexported `Zw*` names have an exported `Nt*` twin — the dbgk ones. Everything else would need its `Nt*` twin *and* an executive service first. |
| §D: for the 5 dbgk SSNs, "`Zw*` aliases + `NT_ARGC` rows added alongside" | **half true** | added to `ZW_ALIASES` (212 rows, and `nt-syscall-abi`'s own test enforces the table's self-consistency) but **not exported**: `exports.rs` has 207 `zw_alias!` lines and the built PE exports 207 `Zw*`. See pickup item 1. |
| §D: "`Thread->HideFromDebugger` — we have no such flag" | **false** | the flag exists (`crates/nt-process/src/lib.rs:429`), is set through `NtSetInformationThread` class 17 (`exec_handler.rs:2155`) and is queryable (class 17 read at `lib.rs:940`). What is true is that `dbgk.rs` never consults it. |
| §E.5: "`RtlCompactHeap` (⇒ 0) already matches ReactOS's `@unimplemented`" | **stale** | it now has a real body (`heap_compact`: coalesce + return the largest free payload extent), with an `INVALID_PARAMETER` error path. |
| §E.0: "546 distinct `ntdll` imports across the live-loaded set (38 binaries)" | **consistent, different population** | my 42-binary live list gives **554**; the whole-`system32` figure (**593**) reproduces exactly. Both are **0-missing**, which is the load-bearing claim. |
| §A/§E: `CsrClientCallServer`/`CsrGetProcessId` are NOT_IMPLEMENTED stubs | **stale** | both are real bodies; §E.0 already corrected this. |

Anything in `ntdll_plan.md` not listed here was either verified or not re-checked; when in doubt,
**re-measure** with the recipes in §2 rather than trusting the prose.
