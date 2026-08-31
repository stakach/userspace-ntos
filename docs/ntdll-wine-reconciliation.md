# Wine ntdll Reconciliation

This document is the semantic companion to the checked catalog at
`tools/ntdll-dll-verify/fixtures/wine-ntdll-reconciliation-2ecc2f84.tsv`. It covers the exact 372
names missing from `.tmp/nt-ntdll.dll` at the pinned Wine baseline. The verifier checks the exact
tracked-manifest content hash, joins every catalog row to the frozen Wine kind, argument, flag, and
alias row, and separately checks the effective arguments and return/data class selected from the
strongest source. A catalog state change and a PE export change must agree; otherwise
`--wine-report` fails with reconciliation drift.

The catalog is an implementation ledger, not permission to export placeholders. `planned` means the
ABI and contract are known but the name remains absent. `blocked-abi` means none of the NT5,
ReactOS, or Wine references establishes a safe callable signature; the export must remain absent
until a stronger source or real caller provides one. `implemented` is valid only after the built PE
contains executable code or writable non-executable data of the cataloged shape, rejects
forwarders, and preserves every exported alias by a shared RVA or verified direct tail jump. Native
Nt/Zw pair states cannot diverge. The later generated-wrapper gate still proves the complete calling
ABI before final compatibility closure.

## Frozen authority

- Wine commit: `2ecc2f84b45ec42afbf1725d756181180a8204b1`.
- Wine `ntdll.spec` blob: `10d42eeb1387204518711814923e19b6bbed25cf`.
- Spec SHA-256: `25fafa3c7f9c2f981f1dcd70ee4315d8dedb13a695a20528a80843df86fff15c`.
- Tracked normalized manifest SHA-256:
  `bea27b141201215aebc8bc82b2ab6a75913f3a348ec0146690d5cea273627177`.
- Baseline gap: 372 names, SHA-256
  `a42e5d3ab87a3d9538e1451c109ceb06f3c7bd4dbf131ac48f017ab002e206e6` over the sorted,
  newline-terminated name list.
- Classification: 49 slices, SHA-256
  `dfe7d4e030b44e7da62020a10b1820895513cc16d9f783e12fd05a973d8573f6` over
  `name/group/owner/abi-authority/effective-args/return-class`.
- Ownership: 71 genuine kernel services, 71 `Zw` aliases of those services, 227 user-mode ntdll
  routines, and 3 ntdll data/TLS exports.

On x86-64, Wine's `stdcall` and `cdecl` rows both use the Windows x64 calling convention. Wine
argument tokens remain the normalized inventory ABI unless `effective-args` records a stronger
source override. `return-class` records the caller-visible scalar, pointer, nonreturning, or data
shape for every planned row. Wine `-syscall` values are Wine host ordinals and are never our ABI
input.

### ABI overrides and blockers

- `NtTraceEvent` is the ReactOS four-argument ABI `(ULONG handle, ULONG flags, ULONG header_length,
  EVENT_TRACE_HEADER*)`; Wine marks it as a bare stub.
- `NtWaitForMultipleObjects32` is the ReactOS five-argument WOW64 adapter ABI `(ULONG count,
  LONG32* handles, WAIT_TYPE, BOOLEAN alertable, LARGE_INTEGER*)`; handles must be widened, not
  pointer-cast.
- `_vsnprintf_s` has five arguments `(char*, size_t, size_t count, const char*, va_list)`. The
  pinned Wine spec incorrectly records four; Wine's implementation and CRT header are authoritative.
- `_fltused` is a writable 32-bit data export initialized to `0x9875`, not a callable Wine stub.
- `LdrSystemDllInitBlock` is writable `SYSTEM_DLL_INIT_BLOCK` data. The four `Ntdll*WndProc*`
  bridges use `LRESULT(HWND, UINT, WPARAM, LPARAM)`, not four undifferentiated scalar arguments.
- `CsrAllocateCapturePointer`, `CsrClientMaxMessage`, `CsrClientSendMessage`,
  `CsrClientThreadConnect`, `CsrpProcessCallbackRequest`, and `RtlSetPropertyClassId` remain
  `blocked-abi`. Do not infer prototypes from Wine bare-stub rows or partial NT5 call sites.

## Native service slices

Every native slice is kernel-owned and must enter through `nt-syscall-abi`; its `Zw` row is an
ntdll tail alias to the same shared SSN and body. An export, argc row, dispatcher route, real
mechanism, and alias land atomically. No unsupported service is exported with a success or generic
failure body.

Current frontier (2026-08-31): `NtQueryMutant`/`ZwQueryMutant` and `NtQueryTimer`/`ZwQueryTimer` are
implemented. The built PE has 1,376 exports and covers 1,093 of the 1,461 Windows-visible names;
368 names remain absent. The reconciliation ledger contains 362 planned, 6 ABI-blocked, and 4
implemented rows. The fixed 372-name baseline and classification hashes remain unchanged.

| group | count | mechanism and initial exact contract |
|---|---:|---|
| `K-security` | 3 | Audit access captures type lists/mapping and returns granted access, access status, and generate-on-close under real privilege policy. Token comparison uses token-equivalence rules. LowBox creation requires a restricted AppContainer token, capabilities, and allowed-handle set. |
| `K-thread` | 14 | Alert/resume/APC operations reference real threads, preserve suspend counts, consume reserve objects atomically, and wake only the matching alertable wait. `NtQueryMutant` initially supports only exact-size `MutantBasicInformation`. CreateThreadEx publishes TEB/client-ID attributes. Worker-factory readiness waits for a real factory object. |
| `K-object` | 2 | Reserve objects are typed, quota-owned, one-shot APC/IOCP resources. Object comparison succeeds only for the same canonical object and otherwise returns `STATUS_NOT_SAME_OBJECT`. |
| `K-vm` | 7 | Extended allocation/map/section calls capture and validate every parameter record; count zero may share the canonical operation. Mapped-file comparison distinguishes unmapped, private, different-file, and same-file views. Unmap accepts only documented placeholder/boost flags. Process write-buffer flush is a real cross-CPU barrier. |
| `K-process` | 3 | Process/thread enumeration follows canonical live object order and ends with `STATUS_NO_MORE_ENTRIES`. CreateUserProcess implements the complete `PS_CREATE_INFO` state machine and `PS_ATTRIBUTE_LIST`, publishes both handles atomically, and reports failure-state fields before rollback. |
| `K-io` | 6 | Cancellation selects real live IRPs by file/thread/IOSB and drains the selection before return. DeleteFile uses open-for-delete and filesystem share/disposition rules. FlushBuffersFileEx validates flag-specific input. IOCP Ex calls preserve packet order, counts, timeout/APC behavior, and reserve-object consumption. |
| `K-config` | 9 | Multi-key notification and multi-value query use one coherent registry snapshot. QueryMultipleValueKey owns buffer length in/out, offsets, types, and required length. Rename is atomic under one parent. The first SetInformationKey slice supports exact-size `KeyWriteTimeInformation` and `KeyUserFlagsInformation`; other classes return `STATUS_INVALID_INFO_CLASS`. Transacted calls wait for a real config/KTM transaction view. |
| `K-lpc` | 3 | Read/WriteRequestData validate port, message/client provenance, data-info index, bounds, and cross-process copy. ReplyWaitReceivePortEx combines reply and receive in order and honors timeout without consuming an unrelated message. |
| `K-alpc` | 6 | Typed ALPC ports retain immutable sender/message provenance, connection attributes, security QoS, timeout/cancel state, and disconnect wakeups. Connect/accept/send/receive never fall back to classic LPC. |
| `K-nls` | 2 | Initialize maps authoritative system NLS data and returns base/default LCID/size. Section lookup caches the requested real type/id mapping and reports unknown types or IDs exactly. |
| `K-time` | 6 | UUID allocation persists monotonic time/sequence/node state. Timer query supports only exact-size `TimerBasicInformation`. Resolution calls expose actual scheduler increments, maintain per-process requests, and recompute global resolution; a clearing process with no request gets `STATUS_TIMER_RESOLUTION_NOT_SET`. Profiling and auxiliary-counter conversion must affect real clock domains or return a defined unsupported status. |
| `K-system` | 6 | CurrentProcessorNumber reports the current logical CPU. Initial SystemInformationEx classes are logical-processor relationships, CPU sets, idle cycles, and supported architectures with class-specific length failures. Firmware query uses the real platform store. Debug requires privilege and per-command sizes. ETW/trace needs real session/event state and never drops work with success. |
| `K-ktm` | 3 | Create/commit/rollback operate on typed transaction and participant state with timeout, legal transitions, isolation, prepare/commit/rollback, and wait semantics. Fake handles and dropped success are prohibited. |
| `K-arch` | 1 | Native x64 SetLdtEntries returns the architecture's defined failure. Descriptor validation is added only with a real WOW64 LDT contract; fake success is not compatibility. |

Twenty-seven names retain their ReactOS `sysfuncs.lst` SSNs:

```text
4 AccessCheckByTypeAndAuditAlarm     13 AlertResumeThread
14 AlertThread                       17 AllocateUuids
20 AreMappedFilesTheSame             30 CompareTokens
65 DeleteFile                        118 NotifyChangeMultipleKeys
168 QueryMultipleValueKey            169 QueryMutant
179 QuerySystemEnvironmentValue       183 QueryTimer
184 QueryTimerResolution              193 ReadRequestData
200 RenameKey                         204 ReplyWaitReceivePortEx
229 SetEventBoostPriority             235 SetInformationKey
240 SetIntervalProfile                242 SetLdtEntries
254 SetTimerResolution                264 SystemDebugControl
269 TraceEvent                        286 WriteRequestData
290 OpenKeyedEvent                    294 GetCurrentProcessorNumber
295 WaitForMultipleObjects32
```

`NtCreateThreadEx` already has argc 11 and an executive mechanism, but the self-test-private SSN
`0xA5` collides with the fixed ReactOS table and must be retired. Allocate public post-ReactOS
services from a named project extension range. The six ALPC services use the separately reserved
`0x1000` range only when direct marshalling is complete. Never reuse Wine ordinals.

Strongest local sources are NT5 timer/mutant/config/LPC implementations, ReactOS
`ntoskrnl/sysfuncs.lst` and typed prototypes, and Wine's newer API tests. ReactOS registry, x64 LDT,
and trace stubs are gaps to implement, not behavior to preserve.

## Rtl slices

| group | count | ownership, behavior, and failure boundary |
|---|---:|---|
| `U1-context` | 19 | Extend the existing dynamic-function and unwind cores. Growable tables enforce allocation and monotonic count/max. Extended contexts validate architecture/XSTATE masks and return invalid-parameter, not-supported, or buffer-overflow as appropriate. VirtualUnwind2 preserves handler filtering and bad-table/access failures. |
| `U2-sync` | 6 | WaitOnAddress supports sizes 1/2/4/8 only, compares before parking, and has real wake-one/all and timeout races. Barriers accept only the documented flag, cap spin count, are cyclic, return true only to the last entrant, and wait safely during deletion. |
| `U3-security` | 6 | Implement trust-label ACE validation, SHA-1 service SIDs, SHA-256 capability SIDs, SD creation/inheritance, and secure-memory callback registration from NT5. Only user-security-object creation needs token queries. |
| `U4-property` | 13 | A pure mapped-stream property-set implementation supports read/write/create/create-if/delete, simple/non-simple values, GUID/name conversion, enumeration/query/set/delete, and flush failures. `RtlSetPropertyClassId` remains absent pending an ABI oracle. |
| `U5-nls` | 14 | UI-language state and list parsing are process/thread-local and validate flags/syntax. Full IDN/normalization waits for authoritative NLS sections and validates forms, UTF-16, flags, labels, output sizes, and mapping availability. Do not copy ReactOS's unconditional locale success. |
| `U6-path` | 5 | Search mode is process-local, permanent mode denies later changes, and ExePath honors `NoDefaultCurrentDirectoryInExePath`. FullPathName_UEx returns exact byte lengths/path type and DOS-device behavior. ReleasePath frees the allocated plan. |
| `U7-heap` | 6 | Add a real process heap registry and committed/reserved/protection metadata. Enumeration is concurrent-safe and callback-stoppable. Usage/backtrace/lock data is reported only when real; invalid heap and protection transitions remain observable. |
| `U8-bitmap` | 6 | Implement backward/longest/set-run scans and a separate NT5-quality range-list module. FindRange must honor shared/conflict/callback rules; Wine's zero-return semantic stub is not sufficient. |
| `U9-pe-rb` | 3 | PE lookup rejects absent, zero-RVA, and forwarder entries. A new intrusive red-black tree maintains parent/color bits, root/min, rotations, and invariants; the existing AVL tree is not a substitute. |
| `U10-misc` | 14 | Time wrappers use real system/performance sources. RegistryValuesEx is an exact alias/wrapper over the existing query engine. NtUser PFN tables validate sizes, initialize once, reject pre-init retrieve/reset, and publish synchronized stable tables. Package/placeholder identity needs honest process state. RemoteCall needs suspend/context/remote-stack primitives. |
| `U11-wow64` | 17 | Pure CPU-layout and lock-free offset-list helpers may land first. Native-only queries may report AMD64 and guest unsupported. Context/APC/emulator calls remain absent until WOW64 TEB/CPU-area, ThreadWow64Context, guest-machine, LDT, and APC contracts exist. No fake native WOW64 success. |

NT5 is the authority where Wine/ReactOS mark security, property, heap, range, remote-call, or WOW64
rows as stubs. Wine supplies the stronger wait/barrier, XSTATE, path, IDN, language, red-black tree,
and modern-process contracts. The checked manifest still records bare Wine-stub ABI as `-`; the
catalog names the stronger source or blocks the export.

## Thread-pool slices

All 35 `Tp*` routines are user-mode ntdll policy over existing thread, wait, timer, event, mutant,
semaphore, duplicate-object, file-completion, and IOCP primitives. They must be implemented as one
coherent object/lifetime model over `nt-rtl-work-item` and `nt-rtl-timer-wait`; partial independent
exports would create unsafe cleanup and refcount behavior.

| group | count | required contract |
|---|---:|---|
| `T1-pool` | 6 | Three priority queues, min/max workers, busy accounting, stack reserve/commit, environment versions 1/3, and exact invalid stack-info failures. |
| `T2-cleanup` | 3 | Group membership/refcounts, optional cancellation, wait-running behavior, caller data, and safe self-release/reentrancy. |
| `T3-work` | 5 | Each post is an independent pending unit; waits optionally cancel pending work and wait for running callbacks; simple post propagates allocation/queue failures. |
| `T4-timer` | 5 | Absolute/relative/immediate due times, period/window, disarm, armed query, generation-safe rearm, and cancel-pending/wait-running behavior. |
| `T5-wait` | 4 | Duplicate the waited handle, support signal and absolute/relative timeout, one callback per registration generation, disable, cancellation, and wait-running. |
| `T6-io` | 5 | Associate the file with a pool IOCP; Start/Cancel/completion balance outstanding counts exactly and dispatch ordered completion data. |
| `T7-callback` | 7 | Deferred cleanup actions execute after callbacks, first registration wins, MayRunLong reports wrong-thread/max-worker failures, and Disassociate releases waiters without ending execution. |

## Loader, CSR, and compatibility slices

| group | count | required contract |
|---|---:|---|
| `A1-apiset` | 2 | A bounds-checked immutable `PEB.ApiSetMap` view shared by queries, imports, and forwarders. PresenceEx rejects dots, distinguishes schema membership from resolvable presence, and returns success with false outputs for absence. Remove pseudo-DLL loading fallback. |
| `L1-search` | 6 | One locked `DllSearchState` and coherent search plan for explicit, static, dependent, delay, and forwarder loads. Validate flag combinations and absolute canonical directories before mutation. Cookies carry slot+generation and stale/double removal returns invalid-parameter. Remove fixed System32/ASCII-only policy. |
| `L2-resolve` | 2 | FullName uses the live module table and exact buffer lengths. Delay resolution loads, resolves name/ordinal, atomically patches IAT once, then invokes DLL reason-4 or system failure hooks; unresolved work is never synthetic success. |
| `L3-data` | 1 | Publish and populate writable SystemDllInitBlock only when its dispatcher entries, including RtlUserThreadStart, are real. |
| `W1-user-proc` | 4 | Call the dynamically installed A/W user32 proc tables and preserve exact LRESULT. Land with the NtUser PFN trio, then remove executive callback-result stamping only after end-to-end proof. |
| `S1-winsqm` | 3 | Disabled telemetry has a complete observable void/no-mutation contract. These are user-mode no-ops, not NTSTATUS stubs or kernel services. |
| `C1-csr` | 5 | ABI blocked. Once a native oracle exists, implement user-mode capture/marshal wrappers over the existing real CSR LPC transport. Never add per-name kernel operations. |
| `D1-data-tls` | 2 | `_errno()` returns stable per-thread storage from an explicitly reserved loader-private TEB TLS slot. `_fltused` is 32-bit writable data `0x9875`. |
| `J1-jump` | 3 | One x64 assembly/SEH slice saves/restores nonvolatile GPRs, XMM6-15, control state, stack/frame/RIP; zero longjmp value becomes one and non-null frames unwind finally handlers. |

## CRT slices

| group | count | required contract |
|---|---:|---|
| `C2-integer` | 11 | Secure conversions validate destination/radix, clear writable output on failure, handle exact signed minima, and distinguish invalid from range. `_wcstoi64` handles base 0/2..36, whitespace/sign/prefix/end, saturation, and per-thread errno. |
| `C3-path-case` | 8 | Validate every pointer/size pair, plan before publishing, clear all supplied outputs on split failure, insert path punctuation exactly, and require a NUL within bounded case-conversion input. |
| `C4-printf` | 12 | Use `nt-printf` and a real scanner. Counts exclude NUL; secure forms clear and return -1 on overflow, support `_TRUNCATE`, and preserve exact varargs. Scanner supports width, suppression, bases, lengths, `%c/%s/%[]/%n`, assignment count, and EOF. |
| `C5-classify` | 4 | Return matching C1 masks (not normalized one) except boolean `iswascii`; zero for unsupported/nonmatching input. |
| `C6-memory-string` | 15 | Secure memory/string validation, destination clearing, `_TRUNCATE`/`STRUNCATE`, bounded lengths, caller-owned `_s` tokenizer context, and per-thread legacy `wcstok` state. Do not copy Wine's process-global tokenizer gap. |
| `C7-sort` | 2 | Validate width/base/comparator and multiplication overflow. Secure comparators receive context first. |
| `C8-math` | 6 | Use a proven no_std libm core with IEEE signed-zero/NaN/infinity behavior, argument reduction, ULP tests, and per-thread errno/domain/range plus floating exceptions. Do not extend the existing cosmetic small-range approximation. |

## Implementation order

1. Land pure low-risk Rtl bitmap/range, PE lookup/red-black tree, growable table, path, time/registry
   aliases, NtUser table, WinSqm, `_fltused`, and per-thread `_errno`.
2. Add secure integer/path/string/classification/sort CRT, then formatter/scanner and libm. Land the
   three x64 jump routines atomically.
3. Implement WaitOnAddress/barrier and security SID/SD helpers in host-testable crates.
4. Implement fixed legacy native services whose object/timer/config/file/LPC mechanisms exist,
   preserving the fixed SSNs, exact information classes, and real failures.
5. Build the complete user-mode thread-pool model and wire it only after lifetime/cancellation tests
   cover every object type.
6. Add loader search state with the Rtl path prerequisites and remove ignored/hardcoded search
   machinery; then ApiSet, FullName, delay resolution, and SystemDllInitBlock.
7. Publish CreateThreadEx on a project extension SSN, then ALPC, I/O/IOCP Ex, extended VM/section,
   process enumeration, and CreateUserProcess through shared typed ABIs.
8. Complete NLS mappings, system-information classes, firmware, transactions, LowBox, profiling,
   tracing, and worker factories only with their real mechanisms.
9. Implement WOW64/emulator calls only after an explicit guest-architecture contract. Resolve the
   six blocked ABIs from a native oracle before admitting those exports.

Each slice needs host behavior tests first, target DLL wrappers second, the serialized PE verifier,
and finally a genuine ReactOS desktop boot. No slice may introduce a kernel policy shortcut, Wine
host syscall number, synthetic result, fake handle, ignored parameter array, or fallback path.
