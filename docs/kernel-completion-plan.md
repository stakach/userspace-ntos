# Kernel Completion Plan

Last updated: 2026-08-10

## Objective

Move from the current ReactOS desktop frontier toward a small, durable NT kernel that hosts
ReactOS through real NT mechanisms. The kernel should provide core traits only: object identity,
process/thread execution, virtual memory and sections, I/O and driver dispatch, registry hives,
security/synchronization, and IPC. Service policy, launch policy, and compatibility shaping belong
in SCM, user-mode system processes, and our ntdll where possible.

## Working Rules

- Keep the kernel mechanism-only. Do not add process-name, service-name, or executable-order policy
  unless it is bootstrapping state that NT itself owns.
- Do not add fallback success paths. Missing behavior should return the real failure and get tracked.
- Prefer host-testable crates for registry, VAD, cache, security, and service metadata before wiring
  behavior into the executive.
- Replace old machinery when a dynamic path supersedes it. Do not leave parallel special cases behind.
- Validate one build/spec path at a time; do not run kernel builds or boot specs in parallel.
- Commit each green, meaningful slice.

## Status Legend

- `[ ]` pending
- `[~]` in progress
- `[x]` complete

## Workstreams

### Current Desktop Frontier

Completed boot-fix slice: `.tmp/boot-final-async-setevent-20260810-124334.log` rebuilt ntdll,
the executive, rust-micro, and the disk image, then reached `[microtest done]` with QEMU exiting via
the sentinel and the harness reporting `SUCCESS -- the ReactOS stack booted and the win32k desktop
painted (0x003a6ea5)`. The services.exe main-image-header/list-walk fault
(`PE_LOAD_BASE+0x20`, later `PE_LOAD_BASE+0x10`) was service-list memory corruption, not image
ownership: an internal ntdll async wake called `NtSetEvent` with a stale non-null previous-state
pointer after queuing a work item. The fix keeps async wake on the canonical `NtSetEvent(handle,
NULL)` export stub, removes the stale fixed-address EventLog/list diagnostics, and keeps the native
seL4-Call helpers honest by not claiming `options(nostack)` while reserving stack space. The proof
lines are `scm-worker-ssn #22 ssn=228 ... arg2=0x00000000` and `#28 ... arg2=0x00000000`; the old
services list `vmf-out` no longer appears.

The current frontier is later profile/logon shell activation, not SCM list integrity. The latest
boot still paints the base desktop and services/LSA/SAM paths progress, but user profile resolution
and shell activation remain red in that harness run: `ProfileList` opens stay at zero,
`NtLoadKey`/profile copy do not run, `userinit.exe` is not spawned, and explorer shell chrome is not
painted beyond the magenta sentinel strip. The next slice should stay in real registry/profile/logon
mechanisms: make winlogon's profile directory and `ProfileList` reads route through the mounted
SOFTWARE hive and writable overlay, then drive `LoadUserProfile`/`NtLoadKey` far enough for
`userinit.exe` to launch naturally.

Current I/O lifecycle slice: routed FILE_OBJECTs now use NT-style close ownership. The
completion table separates user-handle references from pending I/O references; `NtClose` dispatches
`IRP_MJ_CLEANUP` at the last user handle and `IRP_MJ_CLOSE` at the final file-object reference, and
the hosted-driver shim preserves the same FILE_OBJECT between cleanup and close. This targets the
real EventLog/RPC context-handle frontier by fixing NPFS instance cleanup rather than synthesizing
RPC context state. Serialized boot `.tmp/boot-file-lifecycle-20260811-011725.log` proves the old
EventLog context-handle fault does not recur and the base desktop readback still passes; the active
red edge has moved to Winlogon profile/shell activation, where `ProfileList` opens remain zero and
`userinit.exe`/`explorer.exe` are not launched.

The current kernel fix is generic: root `FSCTL_PIPE_WAIT` has a bounded name waiter with real
timeout/deadline handling and exact name completion, `NtOpenFile` clears failed output handles, and
hosted-thread quiesce now tracks the actual parked thread badges. Dispatcher waits, pipe reads,
pipe-name waits, keyed waits, IOCP removers, GUI message waits, Dbgk blocks, and LSA rendezvous parks
all update one per-thread parked-state table; a process owner only counts as wait-parked when every
live hosted thread with a real TCB is parked. The old SCM-listener exit/read-park flags and
role-counted quiesce shortcuts have been removed. The active diagnostic slice adds generic named-pipe
I/O traces, DCE/RPC PDU summaries, dispatcher wake traces, root `NtOpenFile` pipe traces, root
`FSCTL_PIPE_WAIT` branch traces, and post-park owner-mask traces so the remaining `\ntsvcs` stall can
be fixed in the pipe/wait/RPC-unwind machinery rather than through service identity. The latest
implementation slice removes another static thread-hosting assumption: ntdll scheduler/completion
entries still prefer their historical low worker lanes, but real `NtCreateThread` is no longer
rejected just because that preferred lane is occupied; it can claim any available per-process
runtime lane. The slice also keeps `FSCTL_PIPE_TRANSCEIVE` on the same synchronous-vs-overlapped
split as `NtReadFile`/`NtWriteFile`: synchronous pipe handles park the syscall on a reply cap, while
overlapped pipe handles return `STATUS_PENDING` immediately and complete later through the pipe
waiter, IOSB, event, and IOCP paths. Follow-up structural debt: the NPFS root handle should become
a real hosted-FSD file object so
`FSCTL_PIPE_WAIT` pending IRPs live inside the npfs driver instead of the executive carrying a
root-handle wait queue.

Boot proof `.tmp/boot-dynamic-hive-flush-gate-20260810.log` reaches `[microtest done]` at
`291/295`:
winlogon authenticates, the real profile/SAM/USER-object-security path reaches `userinit.exe`,
genuine `explorer.exe` launches, shell COM classes are served, explorer creates windows, and the
harness reports `SUCCESS -- the ReactOS stack booted and the win32k desktop painted (0x003a6ea5)`.
The previous `desktop.cpp:193`/`hres=80004005` blocker is gone, and the old `\ntsvcs`/`\lsarpc`
process/name-scoped pipe re-listen caps are no longer present.

The fix is mechanism-owned rather than a shell paint shortcut: THREADINFO now carries the real
message-queue client/server event pair expected by ReactOS `IntMsqSetWakeMask`, and native wait
resolution accepts win32k event handles after process-local wait objects and dispatcher probes. That
lets explorer's `MsgWaitForMultipleObjectsEx` wait on the queue event instead of failing before its
desktop browser/tray path can continue. The component pump can also park an empty blocking GUI
`GetMessage` on the thread's real queue event and redrive it when win32k signals that event; this is
generic queue-event machinery, not an explorer-specific message fabrication.

Dynamic profile hive flush is now real for the current user hive path: `NtFlushKey` encodes the
mounted `NtLoadKey` hive and atomically replaces the source `ntuser.dat`; `RegUnLoadKey` detaches the
mount, and the next `NtLoadKey` remounts the checkpoint image. `exec_profile_ntuser_dat_present` and
`exec_ntloadkey_serviced` are green on that path.

Latest full proof before the current slice remains
`.tmp/boot-reply-pool-kernel-scale-20260810-130750.log`, which rebuilt the stack after scaling reply
cap wait parking through the executive and rust-micro kernel reply pool. It reached
`[microtest done]` at `246/295`, kept `exec_csr_message_plane`, `exec_kbd_layout_opened`,
`exec_lsa_worker_route`, `exec_vm_pool_headroom`, and `exec_win32k_desktop_painted` green, and
proved real winlogon SAS-window creation plus `NtUserSetLogonNotifyWindow(0x127c)`.

Latest hosted executable validation
`.tmp/boot-dynamic-probe-instance-scoped-rerun-20260810.log` proves the repeated dynamic executable
frontier moved forward. The hosted executable catalog can now admit duplicate executable leaf names
as distinct runtime identities, hosted file opens carry an exact `SpawnTarget`, and
`NtCreateProcessEx`/the SEC_IMAGE service resolve by that target instead of by leaf. `NtOpenFile`
also refuses to reuse an already-spawned dynamic image when the caller is opening a new child image,
so repeated SCM `svchost.exe` starts get fresh identities. The proof lines show fresh dynamic
admissions and successful spawns for `svchost.exe` at `pi=8`, `pi=10`, `pi=12`, and `pi=13`, plus
`wlansvc.exe` and `spoolsv.exe`; there is no remaining `BasePushProcessParameters` or
`STATUS_INVALID_HANDLE` process-parameter failure. The run still parks later, but the active frontier
has moved to real service GUI/IPC mechanics: `spoolsv.exe` reaches win32k, fails default
window-station/desktop thread callout with `STATUS_INSUFFICIENT_RESOURCES`, then SCM reports
`ConnectNamedPipe failed (Error 1450)`. The next useful A4 slice should fix service process win32k
desktop/winsta assignment and the generic NPFS/dispatcher resource path, not executable-name or
service-name policy.

Latest service desktop validation
`.tmp/boot-service-desktop-cache-20260810.log` moves that win32k service-process frontier forward.
The win32k Ob layer now models desktop opens by `(RootDirectory window-station, leaf name)`, keeps
service window stations from replacing the cached interactive WinSta0 identity, and gives the USER
object table enough handle/alias capacity for service desktop creation. Noninteractive processes no
longer get an executive-side WinSta0 shortcut: ReactOS `InitThreadCallback` resolves their
`Service-<LUID>$\Default` desktop through the real Ob open/create path, and the dispatcher only
reasserts a desktop that the real path has selected. Validation: `cargo fmt --all`,
`cargo test -p nt-object-manager`, `cargo check --manifest-path
components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, `git diff --check`, and boot
`.tmp/boot-service-desktop-cache-20260810.log`. Result: `services.exe` reaches
`NtUserProcessConnect`, `InitThreadCallback` publishes a W32THREAD with `status=0`, the old
`ObOpenObjectByName failed to open/create desktop` / `Failed to assign default desktop and winsta`
errors are absent, and the harness exits cleanly with
`SUCCESS -- the ReactOS stack booted and the win32k desktop painted (0x003a6ea5)`. Review
adjustment: the immediate boot frontier is now LSA/SAM RPC completion and generic ObjectDirectory
query behavior. The LSA RPC worker reads bind/request PDUs and writes bind_ack, but then spends the
quiesce window in `NtDelayExecution`; `exec_lsa_msv1_0_sam_validation_reached`,
`exec_winlogon_logon_token_received`, userinit/explorer spawn, and `exec_services_query_dir_object`
remain red.

Latest TP-worker/runtime validation
`.tmp/boot-tp-resume-runtime-slot-20260810.log` removes the LSA/SAM completion-worker stall without
adding service policy. `NtResumeThread` now resolves the target hosted thread by its runtime identity
before raw-resuming its TCB, while the process-manager pool slot remains the owner of the suspended
bit. This matters for generic TP workers whose hosted runtime slot can differ from the process-manager
thread slot. Proof: the LSASS worker `tid=316` resumes at runtime `slot=1` while the pool slot is `4`,
then services real IOCP/pipe syscalls and writes LSA RPC responses. No `NtQueryDirectoryObject`
caller appears in this boot, so the previous `exec_services_query_dir_object` red gate is stale proof
debt rather than a justified synthetic implementation target.

Latest win32k resource validation `.tmp/boot-win32k-uservm-reclaim-20260810.log` keeps the ReactOS
desktop paint gate green while removing another no-op resource path. The boot rebuilds ntdll, the
executive, rust-micro, and the disk image, then reports
`SUCCESS -- the ReactOS stack booted and the win32k desktop painted (0x003a6ea5)`. The earlier
`.tmp/boot-win32k-heap-reclaim-20260810.log` proof moved `spoolsv.exe` past the old session-heap
exhaustion wall: `spoolsv` reaches real `NtUserProcessConnect`, publishes its `W32THREAD` with
`status=0`, and continues issuing win32k syscalls. The previous 32 MiB pre-mapped heap candidate was
rejected after `.tmp/boot-win32k-heap-32m-20260810.log` regressed early in dxg private mapping. The
current fix keeps the known VA layout, replaces the old no-op `RtlFreeHeap` path with reclaiming
heap blocks plus `RtlSizeHeap`/`RtlReAllocateHeap`, and makes win32k's GDI user-attribute
`ZwFreeVirtualMemory(MEM_RELEASE)` return released 64 KiB reservation slots to the pre-mapped
`WIN32K_USERVM` arena instead of keeping a no-op success path. The active red edge is still generic
resource lifetime: the later `svchost.exe` GUI connect (`pi=15`) now reaches real
`NtUserProcessConnect` but fails desktop heap mapping with `[win32k-host] HEAP EXHAUSTED
size=0x00100000 used=0x00f082a0`, then desktop assignment unwinds and SCM pipe control reports
`ConnectNamedPipe failed (Error 1450)`. The current implementation slice makes win32k USER/desktop
heaps real section-backed allocation objects: `RtlCreateHeap(HeapBase=Mm section view, ...)` returns
that section view as the heap handle, `RtlAllocateHeap`/`RtlFreeHeap`/`RtlSizeHeap`/`RtlReAllocateHeap`
route by validated heap handle instead of ignoring it, and the old `pheapDesktop`/`pvDesktopBase`
repair code now fails honestly if ReactOS desktop initialization did not publish a valid heap.
`MmUnmapView*` imports are also bound to descriptor-backed logical unmap with map counts rather than
falling through to a success stub, and the old foreign-section private mapping fallback has been
removed. Local validation for this slice is green (`cargo fmt --all`, `cargo test -p nt-kernel-exec`,
the executive `cargo check`, and `git diff --check`). A live `./run.sh` boot on 2026-08-10 again
reported `SUCCESS -- the ReactOS stack booted and the win32k desktop painted (0x003a6ea5)`; the old
late `HEAP EXHAUSTED` / failed-desktop-map signature did not recur. The active red edge moves back to
generic service/control resource lifetime: the late service client reaches root pipe wait/open paths
and times out on `\net\NtControlPipe11`. The next implementation slice removes the artificial
eight-entry async `FSCTL_PIPE_LISTEN` ceiling that produced the preceding
`ConnectNamedPipe failed (Error 1450)` resource failure: `AsyncListenTable` now starts from a small
reservation and grows on demand, and thread cancellation releases every retained server FILE_OBJECT
without a fixed scratch array. Local validation is green (`cargo fmt --all`,
`cargo test -p nt-io-manager async_listen`, the executive `cargo check`, and `git diff --check`);
live boot validation `.tmp/boot-growable-async-listens-20260810.log` confirms the old
`ConnectNamedPipe failed (Error 1450)` wall is gone. The run reaches repeated real shell dependency
loads (`shell32`, `browseui`, `shdocvw`, `propsys`), advances pipe control traffic through
`NtControlPipe5`, and then parks `services.exe` (`pi=3`, `badge=6`) on syscall `0x18` after
`\pipe\ntsvcs` listen/connect churn. The next red edge is native service syscall/reply correctness,
not pipe-listen capacity.

Latest pipe-cancellation validation `.tmp/boot-ntcanceliofile-20260810.log` supersedes that syscall
`0x18` edge. `NtCancelIoFile` is now registered at SSN 24, validates a target handle as a FILE_OBJECT
with zero desired access, cancels only pending I/O issued by the current thread for that file, and
completes the cancelled pipe read/write/transceive, async `FSCTL_PIPE_LISTEN`, and root
`FSCTL_PIPE_WAIT` records through their own IOSB/event/file-object/IOCP surfaces with
`STATUS_CANCELLED`. The cancel request's own IOSB reports `STATUS_SUCCESS`, matching ReactOS IoMgr
semantics. Validation: `cargo fmt --all`, `cargo test -p nt-io-manager cancel_thread -- --nocapture`,
`cargo test -p nt-syscall -- --nocapture`, `cargo check --manifest-path
components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, `git diff --check`, and a live
`./run.sh` boot. Result: the log shows `[nt-cancel-io-file] ... cancelled=1`, the unhandled-syscall
park does not recur, and the harness again reports
`SUCCESS -- the ReactOS stack booted and the win32k desktop painted (0x003a6ea5)`. Review
adjustment: the next A4 edge is service-control startup timing/IPC (`WLAN Service`
`EVENT_CONNECTION_TIMEOUT` / control pipe `Error 1053`) before resuming richer explorer shell
chrome proofs; do not reintroduce service-name pipe or executable fallbacks.

Latest pipe fid-name authority slice removes the service-control pipe miscorrelation found in
`.tmp/boot-ntcanceliofile-20260810.log`: a later client connect to `\net\NtControlPipe5` could
complete an unrelated armed listen because the old fixed 32-entry fid-name table silently lost
metadata and hash zero was treated as a wildcard. The pipe metadata table is now growable,
zero hashes are invalid/non-matching, pipe endpoint create/open records the leaf hash before a
handle is handed to user mode, `FSCTL_PIPE_LISTEN` refuses to arm without recorded metadata, and
fid mappings are forgotten only after the last file-completion reference/handle is released.
Local validation is green (`cargo fmt --all`, `cargo test -p nt-io-manager pipe_fid_name
-- --nocapture`, `cargo test -p nt-io-manager async_listen -- --nocapture`,
`cargo test -p nt-io-manager -- --nocapture`, `cargo check --manifest-path
components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, and `git diff --check`).
Serialized boot proof in `.tmp/boot-current-headless-20260810.log` reaches the real desktop-painted
gate (`SUCCESS ... win32k desktop painted (0x003a6ea5)`) with `\net\NtControlPipe5` reported as
`armed=1 known=1`, exact-hash wakes for fids `0e814c80` and `0e814c81`, and no `known=0`,
`[pipe-listen] REFUSED unnamed`, `NtCancelIoFile`, `EVENT_CONNECTION_TIMEOUT`, service `Error 1053`,
or `unhandled-syscall` signatures.

Current branch frontier after the SEC_IMAGE/ntdll SEH slice:
`.tmp/boot-cow-alias-desktop-20260810-225615.log` rebuilds through the desktop runner and moves past
the previous winsrv media-event initialization failure. `winsrv.dll` imports are complete,
`NtUserInitialize` publishes the power/media events, winlogon reaches the real base desktop
framebuffer readback (`desktop-bg 768/768`), real user callbacks continue, and dynamic service
children run through wkssvc/browser/srvsvc/wlansvc/spoolsv paths. This is not yet an accepted
desktop-shell proof: the run was manually stopped before harness success, periodic census still
reports `explorer total=0`, and repeated service `RpcServerListen() failed (Status 6b1)` messages
are the active red edge. Continue from generic RPC/NPFS association/listener semantics and dynamic
service-thread behavior; do not add service-name, executable-order, userinit/explorer, or paint
fallbacks.

Current desktop recovery target after `.tmp/boot-desktop-retry-20260810-230340.log`: the service/RPC
frontier narrowed to the CSR/LPC receive path. A dynamic Win32 client reached
`NtSecureConnectPort(\Windows\ApiPort)` at connection 16, but the nested `csr_rendezvous` receive saw
a seL4 timer notification as `label=0`, treated it as an unexpected worker message, and dropped the
real `CsrApiRequestThread` parked-receive latch. The next `BaseCreateThread` CSR notification then
failed because no parked CSR worker remained. The current slice screens timer notifications in the
nested SM/CSR/SB rendezvous receivers, matching the main loop and component pump, and records
dynamic CSRSS `CsrApiRequestThread` receive parks on the main endpoint so ReactOS-created CSR API
workers remain available if the static private worker is exhausted. Serialized boot
`.tmp/boot-csr-dynamic-workers-20260810-231746.log` proves the old ApiPort connection-16 wall is gone:
pi=11 and pi=12 both complete real `NtSecureConnectPort(\Windows\ApiPort)`, a timer notification is
absorbed inside CSR API rendezvous instead of becoming `unexpected label=0`, and later CSR request
traffic continues. This is still not a desktop-shell proof: the run was manually stopped after a
quiet period, periodic census still reports `explorer total=0`, and the next red edge remains generic
service/RPC/NPFS association behavior with repeated `RpcServerListen() failed (Status 6b1)` before
natural userinit/explorer launch.

Current RPC association diagnostic slice: the existing PDU trace only reported a context handle when
the first NDR argument started at request/response/fault body offset 24. Recent failures show ReactOS
rpcrt4 rejecting context handles whose UUID is not visible in that narrow trace, so the executive
now scans a bounded set of aligned NDR context-handle candidates across each generic DCE/RPC
request/response/fault body and prints their offsets without changing transport behavior. The first
broadened run (`.tmp/boot-rpc-context-scan-20260810.log`) reproduced the browser/service
`NCA_S_FAULT_CONTEXT_MISMATCH` edge for `{3fbf3a60-8daf-458d-8c09-882755293bfc}` after base desktop
paint and real browser service DLL load, but also showed that counted strings and pointer fields were
crowding out the real deeper context handle candidates. The trace now keeps only UUID-shaped
generated context handles so the next serialized desktop run can decide whether the missing desktop
path is an NPFS instance routing issue, an association-group lifetime issue, or a thread
teardown/reuse issue.

### A. SCM-Controlled Service Startup

- `[x]` A0: Inventory the current SCM/service startup path and mark the static boundaries still in
  use.
- `[x]` A1: Define typed service metadata in the Configuration Manager for `Type`, `Start`,
  `ImagePath`, `ErrorControl`, load group, tag, object name, dependencies, display name, and account
  data.
- `[x]` A2: Provide host-tested service selection helpers for auto-start Win32 services and
  boot/system driver candidates, without embedding launch policy in the kernel.
- `[x]` A3: Route SCM start requests through generic process creation or `NtLoadDriver` based on
  service metadata.
- `[~]` A4: Remove remaining executive service-name/executable-name launch decisions once SCM owns
  the policy boundary.
- `[x]` A5: Add boot gates proving the first auto-start service and demand-start service are selected
  dynamically from registry state.

### B. Driver Stack Bring-Up From Service Metadata

- `[x]` B1: Unify `NtLoadDriver`/`NtUnloadDriver`, SCM driver start/stop, and boot/system driver
  launch on one service-key to driver-object path.
- `[x]` B2: Order boot/system drivers by `Start`, group, and tag metadata instead of compiled-in
  driver lists.
- `[~]` B3: Bind PnP devnodes to driver services from registry `Enum`/`Services` data and let
  drivers create device objects/interfaces through I/O Manager mechanisms.
- `[x]` B4: Replace fixture-specific driver proof paths with generic driver lifecycle gates:
  load, `DriverEntry`, dispatch, stop, unload, object teardown.

### C. Memory Manager And VAD Correctness

- `[~]` C1: Compare live executive `NtAllocateVirtualMemory`, `NtFreeVirtualMemory`,
  `NtProtectVirtualMemory`, `NtMapViewOfSection`, and fault handling with `nt-address-space`.
- `[~]` C2: Move process address-space state onto a host-tested VAD model with reserve, commit,
  decommit, release, protect, query, and unmap semantics.
- `[~]` C3: Wire image and data section views into the VAD/fault path so mapped files own page fill
  and dirty writeback.
- `[~]` C4: Add regression gates for overlapping VADs, partial decommit, protection changes,
  `MEM_TOP_DOWN`, guard/no-access faults, and view teardown.

### D. Registry And Filesystem Durability

- `[~]` D1: Audit mutable registry and writable filesystem paths: `NtFlushKey`, `NtSaveKey`,
  `NtLoadKey`, `NtUnloadKey`, file writeback, rename/delete, and profile hive usage. Root-hive
  `NtSaveKey`, writable-overlay `FileRenameInformation`, and file-backed hive atomic image
  replacement are now real; D2/D3 still own live hive authority plus explicit system/user flush and
  reboot persistence proofs.
- `[~]` D2: Make the Configuration Manager/Hive Manager the live authority for mutable hives rather
  than executive-local mirrors. Mounted boot/user hives are mirrored into `MutableHiveSet`, registry
  reads prefer that authority, and `NtCreateKey`/`NtSetValueKey`/`NtDeleteValueKey` now use
  mutable-hive key handles for non-volatile keys under mounted hives instead of creating overlay
  shadows. Mounted mutable hives also advertise path ownership, so shared value/subkey/key-stat
  queries no longer fall back to the borrowed boot image when the mutable authority owns a missing
  path. `NtOpenKey` now resolves full registry paths through one authority order for normal names,
  PE-literal recovery names, HKEY_USERS, explorer HKCR, and hosted-process HKLM opens: volatile
  overlay keys first, mounted mutable hives second, and borrowed read-only `regf` only when no
  mutable mount owns the path. The old SECURITY/SAM/SOFTWARE boot-hive bypass switches were removed;
  present hive images mount, absent images miss honestly. `NtDeleteKey` is now registered and
  deletes leaf keys through the same authority, including mounted mutable hives, while root/non-leaf
  keys return `STATUS_CANNOT_DELETE` and borrowed `regf` keys remain read-only. Mounted mutable-hive
  keys now preserve class strings, round-trip them through host-tested hive images, and expose them
  through `NtCreateKey`, `NtQueryKey`, `NtEnumerateKey`, and key-stat maximum class lengths. Registry
  keys now also own real self-relative security descriptor metadata: `NtCreateKey` captures initial
  descriptors, `NtSetSecurityObject` merges selected components into mounted mutable hives/volatile
  overlay keys, and `NtQuerySecurityObject` returns sized descriptor data instead of relying on a
  no-op success path. The normal-boot `HKLM\SYSTEM\Setup`, `.Default` locale setup writes, and
  explorer HKCR shell COM class seeding now mutate the mounted hives directly instead of creating
  overlay shadows. Remaining D2 work is a final persistent-path overlay audit before D3
  flush/reboot proofs.
- `[~]` D3: Implement explicit flush and reboot persistence proofs for system hive, user profile
  hive, and writable filesystem overlay changes. Dynamic `NtLoadKey` profile hives now checkpoint on
  `NtFlushKey` through an atomic writable-overlay replace and remount from that checkpoint after
  `NtUnloadKey`; remaining D3 work is system/boot hive backing plus explicit reboot proofs.
- `[ ]` D4: Complete volatile-key, transaction/log replay, setup-state, and user-profile durability
  behavior needed for repeat boots.

## Immediate Iteration

1. Continue B3 cleanup after the NDIS-backed PCI path for ReactOS `e1000.sys`: generated SYSTEM hive
   state carries the registry-selected `E1000` service, PCI `Enum` devnode, class driver key, and
   explicit `Linkage\Export`; `E1000` completes `AddDevice` and `START_DEVICE` with
   `STATUS_SUCCESS`; the generic grant path proves NT-style PCI config reads, full
   MMIO/I/O/interrupt resource-list projection, multiple common-buffer allocations from the
   per-devnode DMA grant, cap-backed inline `out dx,eax` I/O-port service,
   `IoSetDeviceInterfaceState` publication, connected-ISR dispatch, and KDPC bottom-half delivery.
   Hosted PCI and root-bus resource grants now use selected per-devnode component windows instead
   of NIC-named globals or root-bus proof VAs, publication is selected from the boot/system PnP
   launch plans, and the PCI broker discovers grant material for every registry-selected eligible
   PCI function. Existing `E1000` PCI grant registration, DMA grant allocation, and IOMMU mapping now
   flow through generic broker helpers that derive BAR size and DMA domain/request identity from the
   enumerated PCI device. Hosted PCI/root resource publication now allocates component resource VAs
   from the real hosted-driver VA arena and reports VA exhaustion instead of using fixed PCI/root
   window caps. Hosted driver instance, reply-cap, and executive alias bookkeeping now grows on
   demand; per-instance executive VAs come from a checked high arena with on-demand PD/PT coverage.
   Hosted common-buffer allocation records now use the per-instance shared arena capacity instead of
   a fixed eight-record table, hosted device bindings, root-PDO bindings, registry identities, and
   hosted launch side tables now grow on demand while reusing teardown holes, the shared-frame DPC
   queue now publishes arena-derived capacity instead of using a fixed inline queue, and the old raw
   e1000 TX liveness proof has been retired. Pre-storage PCI setup now registers a generic hosted PCI
   BAR/common-buffer/IOMMU grant without hand-programming NIC TX registers, and later registry-selected
   discovery reuses or creates those grants for selected PCI devnodes. The remaining driver-object
   audit found no object-service driver construction, kept hosted-driver/win32k `DRIVER_OBJECT`
   allocation classified as the generic compatibility harness that calls real `DriverEntry`, and moved
   boot-video `Video0` projected driver/device/file bodies behind a generic `nt-io-manager` WDM
   projection helper. Remaining display debt is hosting real videoprt/miniport instead of the
   boot-framebuffer bridge.
2. Continue A3/A4 for Win32 service starts. SCM-owned service metadata now produces typed
   `Win32ServiceLaunchSpec` and `ServiceStartSpec::{Win32, Driver}` records, the hosted executable
   catalog/runtime lanes can admit non-bootstrap children dynamically, and services.exe's real
   `CheckForLiveCD`/control-set copy path is no longer corrupting its advapi32 `RegCopyTreeW`
   buffers. `Win32ServiceLaunchSpec` now also projects the service `ImagePath` into a generic
   process-launch command line plus normalized NT image path, and the executive SCM selection gate
   requires that projection for both auto-start and demand-start Win32 services. A registry syscall
   prerequisite exposed by the latest desktop boot has also been removed: `NtQueryKey` now answers
   the standard key information classes from the merged base-hive/overlay view instead of only
   `KeyFullInformation`, so HKCR, SCM, shell, and driver registry consumers can size and retry those
   queries normally. The current slice also corrected `NtCreateKey`'s relative-root handling so the
   root key handle is used as an object-parse root rather than requiring `KEY_CREATE_SUB_KEY` before
   CM creates the target child; this keeps ReactOS SCM's `Services\<Name>\Security` creation on the
   real registry write path when service keys were opened for read. The latest boot proof
   `.tmp/boot-dynamic-probe-instance-scoped-rerun-20260810.log` now shows services.exe repeatedly
   reaching non-bootstrap service children through the ordinary dynamic image path: duplicate
   `svchost.exe` launches admit fresh target-scoped identities, `NtCreateSection(SEC_IMAGE)` and
   `NtCreateProcessEx` run for each, and the old process-parameter invalid-handle wall is gone. A3 is
   complete. Continue A4 by removing remaining SCM pipe/listener thread special coordination once the
   generic LPC/pipe/thread model can carry it. The service GUI desktop/winsta assignment has moved onto
   the real win32k/Ob path; the active A4 validation frontier is generic hosted TP-worker resume
   identity plus reclaiming win32k session-heap and GDI user-VM allocations for multiple dynamic
   GUI-capable service clients.
3. Work the current proof-gate frontier now that genuine explorer shell chrome renders again. The
   SAM/setup bridge is green through real SAM database creation, Administrator token minting,
   profile hive mount/read-back, userinit, genuine explorer launch, served explorer shell COM
   classes, and non-background shell chrome pixels. Directory and symbolic-link object opens now
   return process-local handles instead of new callers receiving legacy `OBJ_HANDLE_BASE` indexes,
   and `RootDirectory`/`NtQueryDirectoryObject` resolve through the same handle-table path. ReactOS
   `GetDriveType(C:\)` now sees the mounted DOS drive through `ProcessDeviceMap`, so the previous
   `CStartMenu`/`startmnu` `ERROR_PATH_NOT_FOUND` route is gone. Generic hosted-thread
   sched-context ownership now keeps explorer/RPC worker churn from leaking seL4 SC objects: SC
   attach is checked, hosted thread mechanisms own the SC cap, and thread teardown recycles the SC
   plus TCB root slot. The old `retype: sc pool exhausted`, `failed to create thread, error=5aa`,
   and local worker `0xff` frontier is gone in the latest boot. `SSN=188` is now routed as
   `NtQueueApcThread`: process-manager ETHREADs carry bounded user APC queues, alertable
   `NtDelayExecution`, `NtWaitForSingleObject`, `NtWaitForMultipleObjects`, and `NtTestAlert` can
   redirect the current hosted thread into ntdll's real `KiUserApcDispatcher`, and the ordinary
   syscall reply is suppressed while the APC context carries `STATUS_USER_APC`. The old fixed
   object-namespace ceiling is also gone: object entries now grow by checked reserve, so late debug
   objects can bind real `EventsPresent` dispatcher events after explorer has consumed namespace
   slots. Dbgk object/event storage is now precharged during process-manager bootstrap and reused
   from bounded slot bodies, so late `NtCreateDebugObject` and blocked-reporter release no longer
   allocate out of the post-desktop bump frontier; the executive heap cap was rebased to `7 MiB` for
   that durable kernel-owned state and later to `8 MiB` once mounted mutable hives started owning
   installed setup state and shell COM class provisioning directly, while spawned service heaps stay
   at `512 KiB`. The latest FSD
   transport and handle-lifetime cleanup moves past the profile hive/user
   shell activation regression and the explorer icon/image-list wall again. Explorer now captures
   register-window messages, serves all required shell COM classes, redirects real api0 callbacks,
   installs WndProcs from client code, produces direct GDI returns, and leaves a wide non-background
   framebuffer span. Paint accounting now records explorer `BeginPaint`/`EndPaint` only after a
   successful isolated win32k return. The latest dynamic callback-client and handle-reserve proof
   `.tmp/boot-handle-reserve-512-20260808.log` carries the boot back to genuine shell chrome:
   `exec_desktop_shell_frontier` and `exec_explorer_shell_chrome_painted` pass, explorer reaches
   `7704` syscalls (`5920` native, `1784` win32k), final explorer framebuffer proof has `34873`
   non-background pixels, and the stale callback/allocator-panic walls are gone. The remaining red
   gate was resource headroom, not shell behavior: `exec_vm_pool_headroom` failed because
   root-Untyped free was `48385 KiB`, just below the measured `48 MiB` runway floor. The current
   slice trims per-component spawned service heaps while keeping the executive heap unchanged, and
   boot proof `.tmp/boot-service-heap-512k-20260808.log` flips `exec_vm_pool_headroom` green with
   `51457 KiB` root-Untyped free while preserving genuine shell chrome. The follow-up
   win32k-dispatch proof fixed the bootstrap harness side of the same transport boundary: hosted
   clients still register callback identity per live dispatch, while callback-less bootstrap probes
   run through the real component pump without advertising a non-existent user callback client.
   Boot proof `.tmp/boot-win32k-bootstrap-callbackless-20260808.log` is fully green at `291/291`:
   `win32k_dispatch_loop_roundtrip`, `win32k_dispatch_fault_via_reply_cap`,
   `exec_vm_pool_headroom`, `exec_desktop_shell_frontier`, and
   `exec_explorer_shell_chrome_painted` all pass, with no stale or unregistered user-callback
   requests. The next C1/C2 slice replaces the old `NtProtectVirtualMemory` success shim with a real
   private-memory path: ReactOS-compatible argument validation, process-handle access checks,
   committed-range validation, old-protect/base/size writeback, and seL4 page-right reprotection.
   The first real implementation exposed that protection changes must be modeled as PTE-level state,
   not VAD extent splits. `nt-address-space` now keeps private allocation/commit extents separate from
   per-page protection overrides, clears overrides on release/decommit/recommit, and the executive
   pool census tracks those overrides as `prot-ovr`. Boot proof
   `.tmp/boot-pte-protect-overrides-20260808.log` is fully green at `291/291`: `exec_vm_pool_headroom`
   passes with `vad=40/64`, `prot-ovr=9/128`, and `51631 KiB` root-Untyped free, while genuine
   explorer shell chrome still paints `34873` non-background pixels. `NtQueryVirtualMemory`
   `MemoryBasicInformation` now uses the live VM authorities instead of the old committed-private
   shim: private VADs report reserve/commit/protection overrides, generic section views report
   `MEM_MAPPED`, loaded images/DLLs report `MEM_IMAGE` by PE section rights, registered client-frame
   mappings and spawn-created bootstrap pages report their real ranges, and `MEM_FREE` spans are
   bounded by the next known mapping. Boot proof
   `.tmp/boot-query-virtual-memory-rerun-20260808.log` is fully green at `291/291` with `vad=40/64`,
   `prot-ovr=9/128`, `51457 KiB` root-Untyped free, and explorer shell chrome still paints `34873`
   non-background pixels. Spawn-created bootstrap mappings now register in a per-process committed
   mapping table at their real map sites, and the old query-only static spawn mapping catalog is
   removed. Boot proof `.tmp/boot-committed-mapping-table-gated-rerun2-20260808.log` is fully green
   at `291/291` with `committed-map=11/32`, `committed-map-fails=0`, and explorer shell chrome still
   paints `34873` non-background pixels. C3's first view-ownership slice now records main
   executable images, hosted ntdll, SEC_IMAGE DLL views, and generic data-section views in the same
   per-process committed mapping table, removes mapped-view records on `NtUnmapViewOfSection`, and
   retires the old generic-section `NtQueryVirtualMemory` query branch. Boot proof
   `.tmp/boot-committed-image-views-20260808.log` is fully green at `291/291` with
   `committed-map=85/128`, `committed-map-fails=0`, `exec_vm_pool_headroom` green, and explorer
   shell chrome still painting `34873` non-background pixels. C3's section-granular image committed
   state is now green: main executable images, hosted ntdll, and SEC_IMAGE DLL views publish
   allocation-owned `MEM_IMAGE` runs grouped by PE page protection; `NtQueryVirtualMemory` no longer
   uses PE/global-DLL image query shortcuts, and DLL unmap removes all runs under the image
   allocation base. Boot proof `.tmp/boot-section-granular-image-views-20260809.log` is fully green
   at `291/291` with `committed-map=233/512`, `committed-map-fails=0`, `exec_vm_pool_headroom`
   green, and explorer shell chrome still painting `34873` non-background pixels. The follow-up C3
   fault-owner slice now routes image page faults through the per-process committed image allocation
   table; PE/global-DLL state only selects backing bytes after committed-view ownership is proven.
   Hosted SEC_IMAGE VSpace creation also clears stale committed-view records so reused diagnostic
   slots cannot leak prior address-space state into a live process. Boot proof
   `.tmp/boot-committed-image-fault-owner-20260809-r2.log` is fully green at `291/291` with
   `committed-map=233/512`, `committed-map-fails=0`, `exec_vm_pool_headroom` green, and explorer
   shell chrome still painting `34873` non-background pixels. The latest C3 mapped-view protection
   slice moves mapped data-section `NtProtectVirtualMemory` ownership into the committed-view table:
   the table can split committed mapped/image ranges on protect, generic section faults map pages
   with the live committed protection, and the stale per-view protection field is gone. Boot proof
   `.tmp/boot-committed-mapped-protect-20260809.log` is fully green at `291/291` with
   `committed-map=233/512`, `committed-map-fails=0`, `exec_vm_pool_headroom` green, and explorer
   shell chrome still painting `34873` non-background pixels. The current dirty/writeback slice adds
   host-tested mapped-view write-fault policy, maps writable data-section pages read-only until a
   real store fault promotes them, records dirty overlay-backed section pages beside the shared
   frame, and writes those dirty pages back through the writable filesystem before generic view
   teardown. Boot proof `.tmp/boot-generic-section-dirty-writeback-20260809.log` is fully green at
   `291/291` with `committed-map=233/512`, `committed-map-fails=0`, `exec_vm_pool_headroom` green,
   and explorer shell chrome still painting `34873` non-background pixels. The follow-up C4 proof
   now adds a dedicated overlay-backed mapped-section writeback gate: a post-quiesce selftest creates
   a real writable-overlay file, attaches it to a generic data section, fills a real shared section
   frame, marks that page dirty, runs the production `service_generic_section_writeback_view` path,
   and requires read-back of the mapped-section payload through `exec_mapped_section_writeback`.
   Boot proof `.tmp/boot-mapped-section-writeback-gate-20260809.log` is fully green at `292/292`:
   `exec_mapped_section_writeback` passes with proof `0x7f/0x7f`, `22` bytes written and read back,
   `committed-map=233/512`, `committed-map-fails=0`, `exec_vm_pool_headroom` green, and explorer
   shell chrome still painting `34873` non-background pixels. The current MEM_IMAGE protect slice
   routes `NtProtectVirtualMemory` for committed fixed mappings through the committed-view table
   instead of falling through to private VADs, uses the data-section read-only dirty probe only for
   `MEM_MAPPED`, keeps `MEM_IMAGE` resident page rights literal, and preserves execute rights for
   `PAGE_EXECUTE_WRITECOPY`. Host tests cover image committed-view writecopy protection, and boot
   proof `.tmp/boot-committed-image-protect-20260809.log` is fully green at `292/292` with
   `committed-map=233/512`, `committed-map-fails=0`, `exec_vm_pool_headroom` green, and explorer
   shell chrome still painting `34873` non-background pixels. The current image demand-protect slice
   adds a host-tested `image_view_fault_plan`, makes image faults derive seL4 rights from the live
   committed `MEM_IMAGE` protection instead of PE-section defaults, refuses no-access/guard image
   faults as protection failures instead of treating them as successful fills, and keeps shared DLL
   text sharing disabled whenever the live image protection would map writable. Boot proof
   `.tmp/boot-image-demand-protect-20260809.log` is fully green at `292/292` with
   `committed-map=233/512`, `committed-map-fails=0`, `exec_vm_pool_headroom` green, and explorer
   shell chrome still painting `34873` non-background pixels. The resident MEM_IMAGE writecopy
   follow-up now promotes shared resident image pages into private owned shadows and tears them down
   through the ordinary image-unmap path, and the follow-up C4 gate now proves the promoted private
   frame can be mutated without changing the shared source frame. The latest C4 teardown slice
   removes the exact-base committed-view unmap assumption: `NtUnmapViewOfSection` now accepts any
   address inside a generic section view, releases the whole view, and removes every committed
   mapping run covering that view, including runs split by `NtProtectVirtualMemory`. Boot proof
   `.tmp/boot-committed-view-range-unregister-20260809.log` is fully green at `293/293` with
   `exec_mapped_section_writeback`, `exec_image_writecopy_cow_isolated`, `exec_vm_pool_headroom`,
   and `exec_explorer_shell_chrome_painted` all passing. The latest C4 mapped-view fault access
   slice adds a host-tested `mapped_view_fault_access_status` verdict and makes generic section
   faults fail guard/no-access mappings, read-only writes, and unsupported mapped writecopy writes
   with real `STATUS_ACCESS_VIOLATION` before any page is demand-filled. Boot proof
   `.tmp/boot-mapped-view-fault-access-20260809.log` is fully green at `293/293` with
   `exec_mapped_section_writeback`, `exec_image_writecopy_cow_isolated`, `exec_vm_pool_headroom`,
   and `exec_explorer_shell_chrome_painted` all passing. The follow-up C4 execute-fault access slice
   extends the same verdict model to read/write/execute faults: `nt-address-space` now rejects
   mapped and image NX instruction fetches before fill, allows executable mappings only for the
   executable protection family, preserves image writecopy COW access, and lets the live executive
   decode the x86 page-fault access kind instead of treating every non-write fault as a read. Boot
   proof `.tmp/boot-execute-fault-access-20260809.log` is fully green at `293/293`, including
   `exec_mapped_section_writeback`, `exec_image_writecopy_cow_isolated`, `exec_vm_pool_headroom`,
   and `exec_explorer_shell_chrome_painted`. The follow-up C4 mapped writecopy slice now treats
   generic data-section `PAGE_WRITECOPY` and `PAGE_EXECUTE_WRITECOPY` write faults as true
   copy-on-write promotions into process-owned private frames, and the post-quiesce gate proves the
   shared mapped source frame remains unchanged after a private mutation. Boot proof
   `.tmp/boot-callback-invalid-header-20260809.log` is fully green at `294/294`, including
   `exec_mapped_section_writecopy_cow_isolated`, callback/LSA route gates, VM pool headroom, and
   explorer shell chrome. Continue the plan from the remaining structural debt rather than
   shell-paint scaffolding. The latest host-side C4 regression slice now pins middle
   `MEM_RELEASE` behavior: right-side VAD rebasing, free-gap query reporting, reuse of the released
   hole, zero-size release of the rebased survivor, and failed split state preservation under
   bounded VAD capacity. Continue with A4's SCM pipe/listener special coordination, B3's real
   video/driver binding, broader C4 private/mapped protect, partial decommit, overlap, and
   `MEM_TOP_DOWN`. The latest private-access slice also makes `NtReadVirtualMemory`-style checks
   reject private execute-only and guarded pages through the shared `VmRegionMap` permission helper,
   matching the fault-access verdicts instead of treating every non-`PAGE_NOACCESS` committed page
   as readable. The latest host-side decommit slice pins partial `MEM_DECOMMIT` query/protect
   interactions: decommitted pages report `MEM_RESERVE`, protection overrides are cleared, protects
   across the hole fail with `STATUS_NOT_COMMITTED`, recommit can restore a committed subrange with
   new protection, and capacity failures preserve the original committed allocation. The latest
   protect-rollback slice pins both private override exhaustion and committed mapped-range split
   exhaustion as transactional failures. The latest `MEM_TOP_DOWN` slice pins high-address
   placement through occupied top ranges and free-gap query reporting after top-down allocation.
   The latest overlap-authority slices add host-tested committed-range overlap selection, bounded
   lower/upper private VAD auto-placement, executive retry around committed mappings, KUSER aliases,
   or unowned registered frames before private allocation/generic data-section map-view publication,
   and a live boot gate for cross-authority placement retry. Continue with A4 SCM pipe/listener
   cleanup, B3 real video miniport hosting, or D1/D2 mutable registry/filesystem authority.
4. Keep reducing registry/filesystem debt while doing that work. The executive no longer duplicates
   mounted base/user-profile hives into the overlay just to open existing keys, and `NtQueryKey`
   now computes merged key counts/max lengths with length-only indexed reads and returns
   `KeyBasicInformation`, `KeyNodeInformation`, `KeyFullInformation`, `KeyNameInformation`,
   `KeyCachedInformation`, and `KeyFlagsInformation` with NT buffer-retry statuses. ntdll's
   `RtlQueryRegistryValues` now also handles ReactOS SCM/group-list registry shapes: strict SUBKEY
   opens, required empty enumeration failure, NOVALUE callbacks, DELETE-on-query, and
   ReactOS-compatible length-bounded `REG_MULTI_SZ` walking. `NtSaveKey` is now a registered native
   service and the supported root-hive case writes the mounted hive's real borrowed `regf` image to a
   caller-opened writable overlay FILE_OBJECT after enforcing `SeBackupPrivilege`, file write access,
   and `KEY_READ`; volatile/overlay keys, non-writable file backends, and subkey export return real
   failures instead of synthetic success. Writable-overlay `FileRenameInformation` now renames real
   MemFs nodes, supports root-directory handle translation at the executive boundary, obeys
   no-replace/replacement collision semantics, preserves the open FILE_OBJECT across rename, and lets
   delete-on-close remove the renamed path; variable-length rename buffers use the bounded overlay
   scratch path instead of the old 64-byte staging limit. D2/D3/D4 still need the Configuration
   Manager/Hive Manager to become the live authority for mutable hives, durable setup/profile state,
   subtree save serialization, and remaining long-lived registry data. The first bridge is now
   host-tested: real read-only `regf` trees can be imported into clean mutable `Hive` arenas and
   checkpointed/rebooted through `HiveManager`. A host-tested `MutableHiveSet` now also owns mounted
   mutable hives behind the NT registry namespace, including `CurrentControlSet` resolution,
   create/set/query, longest-mount selection, and unmount. The real file-backed Hive I/O provider
   now installs primary images with temporary-file plus `FileRenameInformation` replacement and
   reports real log length; the obsolete inert `nt-hive-core` placeholder provider is gone. The
   executive now instantiates a `MutableHiveSet` beside its borrowed `RegfHive` mounts for the boot
   machine hives, `.Default`, and every `NtLoadKey` user hive; value reads can resolve through that
   mutable authority by NT path while current handles keep their existing `KeyRef` encoding.
   Value enumeration, key statistics, and subkey enumeration now also treat `MutableHiveSet` as the
   base mounted-hive view before falling back to the borrowed `RegfHive` reader. Mounted-key opens
   now use the same authority through `NtOpenKey`, including PE-recovered registry names and
   HKEY_USERS paths, and the old boot-hive bypass toggles have been removed instead of retained as
   fallback routes. `NtDeleteKey` is also registered at SSN 66 and deletes leaf keys in mounted
   mutable hives or the volatile overlay with ReactOS/NT-style root and non-leaf refusal. Mutable
   mounted keys now also store/query/enumerate key-class metadata instead of reporting every mounted
   key as classless; the host hive image tests prove class data survives checkpoint/decode. The
   object-security fallback is also gone for registry handles: `NtQuerySecurityObject` is registered
   at SSN 176, `NtSetSecurityObject` no longer returns unconditional success, and key security
   descriptors are captured, queried, merged, and stored through the mutable-hive/overlay authority.
   Win32k USER object handles now participate in native object security too: modeled
   window-station/desktop objects store bounded self-relative security descriptors, expose their
   granted-access metadata through the win32k subsystem boundary, and route `NtQuerySecurityObject`
   and `NtSetSecurityObject` by real object identity before registry fallback. The
   `.tmp/boot-userobj-security-20260810.log` boot cleared the old `AllowAccessOnSession` break,
   reached real `WlxActivateUserShell`, launched `userinit.exe` and `explorer.exe`, and produced
   non-background explorer framebuffer pixels. The remaining shell frontier is no longer process
   launch scaffolding; it is the real explorer chrome paint proof, where `BeginPaint`/`EndPaint`
   accounting was still `0/0` even though direct GDI returns and batch flushes reached the
   framebuffer.
5. Complete the native syscall argument-width audit. The latest SCM/LSA runs exposed several x64
   stack-slot high-half leaks where NT `ULONG`/`BOOLEAN` parameters had been read as pointer-sized
   values. Keep fixing these at the declared ABI boundary, prefer dispatcher-captured `args[]` over
   manual stack rereads for services whose metadata already carries all arguments. The old
   read-only `NtQueryDirectoryFile` width exception is gone and the genuine FAT path stayed inside
   the boot budget. `NtQueryFullAttributesFile` is now registered at its ReactOS SSN and implemented
   against the same writable-overlay/FAT path authorities as `NtQueryAttributesFile`; `NtOpenFile`
   now consumes dispatcher-captured `ShareAccess`/`OpenOptions` instead of rereading stack slots.
   `NtFreeVirtualMemory` now probes the `PSIZE_T RegionSize` argument as a full eight-byte SIZE_T
   before reading and writing it, matching the existing x64 return path instead of accepting a
   four-byte writable tail. The next slices should continue auditing remaining native stack
   arguments while the shell frontier moves to real resource capacity instead of path-status
   failures.

## Review Log

### 2026-08-05

- Created this plan after closing the dynamic shell paint debt at commit `9bb1bcf`.
- Current boot frontier before this plan: desktop gate passes `285/285`, genuine explorer launch,
  shell chrome framebuffer pixels proven.
- A0 started. Existing dynamic driver launch can read `Services\<Name>` values from the SYSTEM hive,
  but selection still happens through named service probes in the executive. The first cleanup target
  is typed service metadata in `nt-config-manager`, then converging executive service/driver readers
  onto that API.
- A0/A1/A2 complete. `nt-config-manager` now exposes a registry-authoritative
  `ServiceMetadata` view, `REG_MULTI_SZ` dependency decoding, typed service constants, and
  host-tested selectors for SCM auto-start Win32 services and boot/system drivers. This keeps
  policy out of the kernel while giving SCM/driver launch code a shared typed metadata boundary.
  Validation: `cargo test -p nt-config-manager` and `cargo test -p nt-config-store`.
  Review adjustment: A3 should replace executive-local service value parsing helpers with this
  metadata boundary, then delete the duplicate parser code.
- A3 started. Driver service `Type` decoding moved behind `nt-config-manager`'s
  `driver_service_class_from_type`, and the executive's SYSTEM-hive driver lookup now has one
  parameterized helper for boot/system and demand-start routes. The old demand-start duplicate
  parser was removed. Validation: `cargo test -p nt-config-manager` and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: next A3 slice should move the actual early-boot hive import toward
  `ConfigManager::service_metadata_list()` or an equivalent snapshot-backed live CM view so the
  executive stops naming individual services while selecting driver candidates.
- A3 continued. `nt-hive-core` now imports `ControlSetXXX\Services` into a `ConfigManager`
  registry subtree, preserving values and nested service keys. The generated config-hive driver
  proof uses that import plus `boot_system_driver_candidates()` to select its second driver and
  derives `\Driver\<ServiceName>` from the selected service metadata; it no longer probes
  `IrpFsdTest` by name. Validation: `cargo test -p nt-hive-core` and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: real `REGF` SYSTEM hive import is still needed so `Npfs` and demand
  `NtLoadDriver` service reads can use the same live CM metadata path.
- A3 continued. `nt-hive-regf` now preserves original-case subkey enumeration and imports real
  `REGF` `ControlSetXXX\Services` trees into `ConfigManager`, including nested service keys and
  typed values. The executive's real SYSTEM hive driver lookup now imports services and reads
  `ServiceMetadata` for both the existing NPFS boot proof and dynamic `NtLoadDriver` demand-start
  requests; the old local raw `ImagePath`/`Type`/`Start` parser was removed. Validation:
  `cargo test -p nt-hive-regf` and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: A3 still needs the actual SCM service-start request path to choose Win32
  service process creation from `ServiceMetadata`, and B2 should replace the NPFS-specific boot
  proof with ordered boot/system driver enumeration.
- A3 continued. `nt-config-server` can now be constructed around an already-seeded
  `ConfigManager`, and the client/server host test proves a seeded `Services\<Name>` tree is visible
  through the existing CM wire API. This is the construction hook needed for a single boot-seeded CM
  authority instead of a fresh empty registry service. Validation: `cargo test -p nt-config-client`
  and `cargo test -p nt-config-server`. Review adjustment: the executive still has to pass imported
  boot hive state into the isolated CM service, or retire the parallel executive-local registry read
  path behind that service.
- B2 started. `nt-config-manager` now reads `Control\ServiceGroupOrder\List` and orders boot/system
  driver candidates by `Start`, service group order, `Tag`, and name. Validation:
  `cargo test -p nt-config-manager`. Review adjustment: the executive still needs to consume this
  full ordered candidate list for boot/system driver bring-up rather than explicitly asking for
  NPFS as a proof-only service.

### 2026-08-06

- B2 continued. `nt-hive-regf` now imports `ControlSetXXX\Control\ServiceGroupOrder` alongside
  `Services` for boot-driver selection snapshots, and the executive's real SYSTEM-hive
  `ConfigManager` view uses that broader import. Validation: `cargo test -p nt-hive-regf`. Review
  adjustment: the ordered metadata is now available from real REGF hives; the next B2 slice should
  replace the remaining NPFS-named launch proof with an ordered boot/system launch plan.
- B2 complete for the current hosted FSD boundary. The executive now builds an ordered boot/system
  driver launch plan from real SYSTEM-hive service metadata, narrows it to the registry `File System`
  load-order group that the current FSD host can execute, launches those candidates through the
  generic driver path, and discovers the named-pipe provider by the `\Device\NamedPipe` object it
  publishes rather than by `Npfs` service name. Validation: `cargo test -p nt-hive-regf` and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: B3/B4 now own expanding the same ordered plan to boot bus, device, filter, and
  PnP-bound drivers instead of filtering to the FSD load group.
- B1 started. Boot FSD launch and `NtLoadDriver` now consume the same `DriverServiceLaunchSpec`
  shape: registry service name, derived `\Driver\<Service>` object path, normalized image path, and
  driver class. `NtLoadDriver` no longer keeps a separate image-path/class tuple parser or local
  driver-object path builder. Validation:
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: finish B1 by routing SCM driver start/stop onto the same spec and making unload
  policy share service metadata rather than only the derived object path.
- B1 complete. `nt-config-manager` now owns the NT service-key to driver-object path rule:
  driver `ObjectName` wins when present, filesystem/recognizer services derive `\FileSystem\<Name>`,
  and device/kernel services derive `\Driver\<Name>`. The executive consumes that single resolver
  for generated-hive driver proof launch, ordered SYSTEM-hive boot FSD launch, `NtLoadDriver`, and
  `NtUnloadDriver`; the old local `\Driver\<Service>` builder was removed. ReactOS SCM driver
  start/stop was reviewed and confirmed to enter the kernel through `NtLoadDriver`/`NtUnloadDriver`,
  so no extra SCM-specific kernel hook is required. Validation: `cargo test -p nt-config-manager`
  and `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: B4 should now turn the existing named driver proof into generic lifecycle
  gates, while B3 owns expanding beyond the current registry `File System` group filter.
- B4 complete. The service-selected driver proof now validates the full generic lifecycle: registry
  service metadata selects the driver, `load_driver` runs `DriverEntry`, the driver object route is
  published through the Object/I/O Manager path, IRP dispatch runs through the shared harness, a real
  `DriverUnload` is invoked, and the I/O route, Object Manager path, and live instance are gone after
  unload. The synthetic `IrpFsdTest.sys` fixture now installs a no-op `DriverUnload` so the proof
  exercises the same stop/unload path that `NtUnloadDriver`/SCM stop use. Plan review found and
  fixed the matching namespace prerequisite: Object Manager bootstrap now creates `\FileSystem` and
  `\FileSystem\Filters`, so filesystem driver objects can be created under the NT FSD namespace
  rather than relying on `\Driver`. Validation: `cargo test -p nt-object-manager`,
  `cargo test -p nt-driver-test-fixtures`, and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: B3 is now the main driver-stack gap. The current boot/system plan is still
  filtered to the registry `File System` load group because hosted device/bus/filter bring-up needs
  devnode-to-service binding and PnP-owned device creation.
- B3 started. `nt-config-manager` can now persist and index `Enum\<InstanceId>` devnodes from the
  registry tree, including `Service`, `PdoName`, `HardwareID`, and `CompatibleIDs`, and can enumerate
  devnodes by bound service without requiring fixture registration. Both generated hives and REGF
  hives now import `ControlSetXXX\Enum` into the live Configuration Manager registry and build that
  devnode index after import. Validation: `cargo test -p nt-config-manager`,
  `cargo test -p nt-hive-core`, `cargo test -p nt-hive-regf`, and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: the next B3 slice should feed these registry-indexed devnodes into the PnP
  Manager's lifecycle model, replacing static fixture devnode creation with service-bound devnode
  creation and preserving the kernel/policy split.
- B3 continued. `nt-pnp-manager` now models service-bound devnodes directly: callers pass the
  Configuration Manager-selected `Enum\<InstanceId>`, optional service, PDO object id, and resource
  assignment, while PnP owns only lifecycle/resource state. The existing `driver-host-pnp` proof now
  creates PnP lifecycle entries from its CM-materialized root-enumerated devnodes and uses each
  devnode's assigned resources for START instead of the MMIO fixture constructor. Validation:
  `cargo test -p nt-pnp-manager` and
  `cargo check --manifest-path components/driver-host-pnp/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: the old fixture constructor still exists for `driver-host-power`,
  `driver-host-dma`, and isolated `pnp-svc`; the next B3 slice should move `pnp-svc` to
  descriptor/resource payloads and then retire or test-scope the compatibility helper.
- B3 continued. The isolated `pnp-svc` SURT path now creates devnodes from a fixed
  `PnpCreateDevnodeReq` shared-frame payload containing `Enum\<InstanceId>`, service, PDO id, and
  resource assignment. The PnP manager child validates that payload and calls the same
  `create_service_bound_devnode` API as the in-process PnP proof; query still returns the PnP-owned
  resources from the canonical devnode table. Validation: `cargo test -p nt-pnp-abi` and
  `cargo check --manifest-path components/pnp-svc/Cargo.toml --target x86_64-unknown-none`. Review
  adjustment: remaining B3 debt is now the executive boot plan filter: registry-indexed devnodes need
  to drive service-bound device-driver bring-up, after which the MMIO fixture helper can be made
  test-only or removed from production components.
- B3 continued. `nt-config-manager` now has a host-tested
  `boot_system_pnp_driver_candidates()` selector: boot/system device-class services are selected only
  when imported `Enum` state binds at least one devnode to the service. The executive boot-driver plan
  now uses that same CM authority inline: registry `File System` services still launch through the
  persistent IRP host, and device-class services enter the plan only through `Enum` service binding.
  Validation: `cargo test -p nt-config-manager` and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: the next B3 slice should carry the selected devnode descriptors/resources into
  hosted device-driver start/AddDevice, then retire production uses of the legacy MMIO fixture helper.
- B3 continued. Production hosted-driver proofs no longer call fixture devnode constructors:
  `driver-host-power`, `driver-host-dma`, and `driver-host-direg` all create service-bound PnP
  devnodes with explicit resources or `NO_RESOURCES`, and the public `nt-pnp-manager` fixture
  constructors were removed. Validation: `cargo test -p nt-pnp-manager`,
  `cargo check --manifest-path components/driver-host-power/Cargo.toml --target x86_64-unknown-none`,
  `cargo check --manifest-path components/driver-host-dma/Cargo.toml --target x86_64-unknown-none`,
  and `cargo check --manifest-path components/driver-host-direg/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: B3's remaining integration work is executive-owned AddDevice/StartDevice for
  registry-selected devnodes, not local component fixture cleanup.
- B3 continued. Config Manager now exposes `boot_system_pnp_driver_bindings()` so callers can carry
  selected device-driver service metadata with the exact imported `Enum` devnode records that bind
  to it. The executive's `DriverServiceLaunchSpec` now includes copied devnode descriptors
  (`instance_id`, `PdoName`, `HardwareID`, `CompatibleIDs`) for both boot and demand driver launch
  specs, and the boot trace prints the selected devnode count/first instance. Validation:
  `cargo test -p nt-config-manager` and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: the next B3 slice should consume these descriptors by invoking AddDevice and
  StartDevice through the hosted driver path once device resources are assigned.
- B3 continued. Hosted driver launch now captures `DriverExtension->AddDevice` after `DriverEntry`
  and preserves it in the live driver instance table. This gives the executive a real per-driver
  AddDevice entrypoint for the registry-selected devnodes now carried in `DriverServiceLaunchSpec`;
  it does not yet invoke AddDevice or project the PDO/start IRP. Validation:
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: the next B3 slice should add an executive dispatch path for AddDevice, backed by
  service-bound PDO projection and a subsequent `IRP_MN_START_DEVICE` dispatch with assigned
  resources.
- B3 continued. Device-class boot launch specs now invoke the hosted driver's real
  `DriverExtension->AddDevice` through the shared component pump. The component side allocates a
  WDM-shaped PDO, calls AddDevice inside the hosted driver's address space, and returns the FDO
  created by the driver's own `IoCreateDevice`; the executive publishes that FDO as an unnamed I/O
  Manager device and records the canonical device-id to hosted `DEVICE_OBJECT` binding for later IRP
  routing. Validation:
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: the next B3 slice should replace the structural PDO placeholder with
  registry/devnode-backed PDO identity and send `IRP_MN_START_DEVICE` with assigned resource lists.
- B3 continued. The generic WDM stack writer now models
  `Parameters.StartDevice.AllocatedResources{,Translated}` and the hosted driver IRP builder carries
  PnP minor functions. Device-class boot launch now follows successful AddDevice with a real
  `IRP_MJ_PNP/IRP_MN_START_DEVICE` dispatch through the hosted FDO, passing an explicit empty
  resource list for no-resource devnodes and preserving real failure statuses for drivers that need
  hardware resources. Validation: `cargo test -p nt-io-manager` and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: B3 still needs resource assignment from devnode/bus state, root-bus PDO
  identity/forwarding, and the device-driver ntoskrnl exports (`IoCallDriver`, `MmMapIoSpace`,
  `IoConnectInterrupt`) before hardware-backed StartDevice can replace the old NIC proof.
- B3 continued. Hosted AddDevice now preserves both sides of the WDM stack (`PDO` and `FDO`), PnP
  lifecycle IRPs no longer fabricate a `FILE_OBJECT`, and PnP dispatch reserves a lower
  `IO_STACK_LOCATION` for forwarding. The shared ntoskrnl import registry now binds stack-location
  helpers plus `IoCallDriver`/`IofCallDriver`/`PoCallDriver`, with forwarded IRPs completing only
  when the target matches the PDO carried from AddDevice. Validation:
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: B3 still needs real root-bus PDO objects/state and assigned hardware resource
  lists; after that, bind `MmMapIoSpace`/`IoConnectInterrupt` to resource-manager grants and retire
  the old bespoke NIC driver proof.
- B3 continued. `nt-pnp` now parses registry PCI IDs (`PCI\VEN_...&DEV_...`, `PCI\CC_...`, and
  `PCI#...`) and resolves imported `Enum` devnodes to enumerated PCI functions by hardware IDs,
  instance path fallback, and compatible IDs. This keeps PCI identity matching host-testable and out
  of the executive. Validation: `cargo test -p nt-pnp`. Review adjustment: the next B3 slice should
  use this matcher in the executive boot plan to assign per-devnode `CM_RESOURCE_LIST`s, map the
  matching BAR into the hosted component, and bind `MmMapIoSpace`/`IoConnectInterrupt` to the grant.
- B3 continued. The executive boot plan now resolves each registry-selected PCI devnode through the
  `nt-pnp` matcher, builds a physical-address `CM_RESOURCE_LIST` for START, maps the already-claimed
  BAR into the hosted driver's VSpace, and binds `MmMapIoSpace`, `MmUnmapIoSpace`,
  `IoConnectInterrupt`, and `IoDisconnectInterrupt` to the active grant instead of the unbound-import
  fallback. If a devnode resolves to hardware the broker has not granted yet, START is still sent
  without resources and the driver's real failure is preserved. Validation: `cargo test -p nt-pnp`
  and `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: B3 still needs devnode-backed root-bus PDO state and generic interrupt/DMA
  resource-manager grants before the old bespoke NIC driver proof can be removed.
- B3 continued. Hosted AddDevice now registers the component-local PDO with the executive's
  `nt-root-bus` table using the imported `Enum` instance path, hardware IDs, and compatible IDs.
  Lower-stack `IoCallDriver` records forwarded PnP minors in the shared frame, and successful hosted
  START applies the forwarded minor to root-bus PDO lifecycle state instead of leaving the PDO as a
  stateless structural placeholder. `nt-root-bus` also has a host-tested split helper for
  `Enum\<DeviceID>\<InstanceID>`. Validation: `cargo test -p nt-root-bus` and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: the remaining B3 gap before retiring the old NIC proof is real interrupt/DMA
  resource-manager grant state plus a boot proof that the generic registry-selected driver reaches
  the same hardware-backed lifecycle evidence.
- B3 continued. Hosted device-driver MMIO and interrupt grants now flow through the canonical
  `nt-resource-manager`: per-devnode resource owners and deterministic resource IDs are registered
  before `START_DEVICE`, stale no-resource projections are cleared, and post-START `MmMapIoSpace`
  / `IoConnectInterrupt` evidence is replayed into the resource manager with no success fallback.
  `nt-resource-manager` now replaces repeated assignments and can revoke all resources/usages for a
  single driver/device owner. Validation: `cargo test -p nt-resource-manager` and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: DMA/common-buffer ownership is still fixture-hosted; the next B3 slice should
  expose `IoGetDmaAdapter`/common-buffer allocation on the generic hosted-driver path using
  `nt-dma-manager`, then add the boot evidence needed to retire the bespoke NIC proof.
- B3 continued. Generic hosted device drivers now have a resource-bound DMA surface:
  `nt-dma-manager` can register broker-provided common buffers at a fixed logical address/IOVA,
  the executive binds `IoGetDmaAdapter` plus `AllocateCommonBuffer`/`FreeCommonBuffer` projections,
  maps the broker-owned DMA frame into the hosted driver's VSpace, creates a canonical adapter for
  the devnode owner, and records post-START common-buffer evidence back into `nt-dma-manager`.
  Validation: `cargo test -p nt-dma-manager` and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: MMIO, interrupt connection, and DMA/common-buffer ownership are now on the
  generic registry-selected boundary. The remaining B3 work before removing the old NIC proof is a
  boot gate showing the generic path reaches real hardware evidence and real interrupt delivery to
  the connected ISR token.
- B3 continued. The generic hosted-driver path now exposes a service-agnostic
  `HostedHardwareEvidence` snapshot after `START_DEVICE`, covering MMIO map evidence, interrupt
  connection evidence, DMA adapter/common-buffer evidence, and root-PDO started state. The boot
  driver loop prints per-devnode and aggregate hardware evidence when any registry-selected device
  driver receives a grant, without adding a service-name gate or making absent hardware evidence
  pass. Validation:
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: the next B3 slice should run the boot, inspect this generic evidence trace, and
  convert the dynamic evidence into real gates once the registry-selected path is confirmed.
- B3 continued. Headless boot `desktop-render-r104-generic-hw-evidence-20260806-093752` reached
  winlogon profile loading but stopped at the executive bump allocator after writable overlay mount.
  The trace showed no generic hardware evidence because the real SYSTEM hive currently selected only
  FSD boot services (`Msfs`, `Npfs`) for the hosted path, and the service-loop heap watermark was
  already `5957452/6291456` before profile loading. The executive boot/system driver plan now copies
  CM-selected service/devnode metadata into a bounded static snapshot and rewinds the large
  ConfigManager import scratch before loading drivers; AddDevice/PnP resource helpers now consume
  borrowed devnode ID slices so the snapshot does not need heap-backed `String` clones. Validation:
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: rerun the boot to confirm the heap regression is gone, then add a
  registry-selected device-driver proof fixture or real seeded service/devnode so the generic
  hardware evidence path can be gated and the bespoke NIC proof can be retired.
- B3 frontier validation continued. Headless boot
  `desktop-render-r109-dispatch-frame-split-20260806-102452` passed the previous boot/system plan
  heap wall and advanced through real winlogon dialog paint into profile loading. The trace shows
  real api0 `WM_PAINT` dispatches plus `NtUserBeginPaint`, `NtUserEndPaint`, and
  `NtGdiGetTextExtentExW`; it then stopped on an executive stack fault while servicing
  `NtQueryAttributesFile` during `LoadUserProfileW`. The large `ExecNtHandler::handle_service`
  frame has been split behind raw service-entry veneers, and the SSN 145 path now uses bounded
  no-allocation object-name/path buffers plus host-tested `nt-fs` relative-path helpers instead of
  growing `Vec`/`String` state at the profile frontier. Validation: `cargo test -p nt-fs` and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: run a staged release boot to confirm profile loading passes this stack wall,
  then reclassify the next real frontier before adding the generic hardware evidence gate.
- B3 frontier validation passed through the profile path and restored the full desktop baseline.
  `NtQueryAttributesFile` now runs through the split raw service entry with fixed-size object-name
  and folded relative path scratch buffers, and the old allocating attribute-query wrappers in the
  executive filesystem bridge were removed. Spawned service heap reservation was reduced to the
  smaller working set the current services actually use, restoring untyped-pool headroom without
  hiding failure paths. Validation: `cargo test -p nt-fs`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, and `./run.sh` passing `287/287` gates including
  `exec_explorer_shell_chrome_painted` and `exec_vm_pool_headroom`. Review adjustment: B3 remains
  active, but the baseline is clean again; resume with a registry-selected device-driver hardware
  proof and turn the generic hardware evidence trace into a gate before retiring the old NIC proof.
- B3 continued. The generated SYSTEM hive now seeds a root-enumerated
  `ROOT\USERSPACE_NTOS_DMA\0001` devnode for `DmaPnpPowerTest` instead of binding the proof driver
  to a real e1000 PCI identity, and `nt-pnp` owns a host-tested root-bus resource profile for that
  class. The executive grants the registry-selected root devnode a seeded MMIO page, interrupt
  vector metadata, and a common DMA buffer, then sends the real `IRP_MN_START_DEVICE` through the
  hosted AddDevice/FDO path. A Win64 dispatch-guard alignment bug exposed by the driver's MSVC
  `movaps` memset helper was fixed by force-aligning the guarded outbound call frame while preserving
  bugcheck unwind. Validation: `cargo fmt --all`, `cargo test -p nt-pnp`,
  `cargo test -p nt-hive-core`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, and `./run.sh`. The boot reached genuine explorer shell
  chrome pixels with `284/286` gates, and the generic hardware gates now pass:
  `exec_generic_hw_registry_selected`, `exec_generic_hw_mmio_interrupt_dma`, and
  `exec_generic_hw_root_pdo_started`. Review adjustment: B3's remaining cleanup is to deliver a real
  interrupt through the connected ISR token on the generic grant and then remove the older bespoke
  NIC proof machinery.
- B3 continued. Generic hosted device drivers now keep the canonical
  `nt-resource-manager` interrupt connection id in their shared evidence, and the executive can
  inject that exact id through the existing hosted-component dispatch pump. The component dispatcher
  executes the registered ISR in the driver's own VSpace using the `IoConnectInterrupt`
  PKINTERRUPT/service-context projection, records claimed/vector/delivery-count evidence, and the
  generated root-bus DMA proof asserts its test MMIO status register before requiring ISR claim plus
  MMIO acknowledgement in the new `exec_generic_hw_interrupt_delivered` gate. Validation so far:
  `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  and `./components/ntos-executive/build.sh`. Review adjustment: run the staged boot and inspect the
  new gate before removing any bespoke NIC proof machinery; the old NIC proof should remain until the
  generic path proves equivalent hardware interrupt/DMA behavior.
- B3 validation update. `./run.sh` booted through genuine explorer shell chrome again with
  `285/287` checks passing; the only failing checks in the streamed summary were the known
  `exec_irp_transport_call_bound` and `exec_client_reply_bound` transport-accounting gates. The new
  `exec_generic_hw_interrupt_delivered` gate is therefore green along with the existing generic
  registry/MMIO/interrupt/DMA/root-PDO gates. Review adjustment: do not delete the old raw NIC proof
  yet. The generic path now proves dynamic hosted-driver MMIO, DMA, and connected-ISR delivery for
  the root-bus DMA fixture; the remaining B3 cleanup is to move real PCI interrupt/DMA hardware
  evidence onto the same generic resource boundary, then remove the bespoke NIC-specific proof once
  that equivalence is demonstrated.
- B3 continued. Generic hosted device drivers now drain bounded KDPC work queued by the connected
  ISR before returning from the interrupt-dispatch pump. `KeInsertQueueDpc` records real KDPC
  pointers and system arguments in the hosted shared frame, the component dispatcher invokes each
  driver's deferred routine in the hosted driver address space, and boot evidence requires
  zero-drop DPC delivery in the new `exec_generic_hw_dpc_delivered` gate. Validation:
  `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, and `./run.sh` through genuine explorer shell chrome with
  `286/288` checks passing. The only failing checks remain the known
  `exec_irp_transport_call_bound` and `exec_client_reply_bound` transport-accounting gates. Review
  adjustment: the generic root-bus fixture now proves MMIO, DMA common-buffer allocation,
  connected-ISR execution, and DPC bottom-half execution. The next B3 slice should move the old real
  PCI/NIC hardware proof onto this generic resource boundary, then remove the bespoke NIC proof only
  after equivalent PCI-backed evidence is green.
- B3 cleanup continued. The SYSTEM-hive boot loop and generated-hive hardware proof now use one
  hosted-devnode resource grant helper for PCI and root-bus resources. The helper owns the dynamic
  devnode-to-resource selection, hosted resource-manager/DMA-manager grant, and START resource bytes;
  callers only decide whether a no-resource devnode may start with an empty list. Grant failures no
  longer fall through to an empty START list. Validation: `cargo fmt --all` and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: the old NIC proof still remains because the available WDM fixtures expect test
  register banks (`MMIO`/`DMA1`), and ReactOS `e1000.sys` requires the NDIS frontier. The next useful
  B3 work is either a real PCI-capable hosted test driver that consumes the e1000 BAR honestly, or
  enough NDIS/ReactOS driver support to let `e1000.sys` bind through the same generic grant helper.
- B3 cleanup continued. The hosted FSD PE import resolver no longer has a generic success fallback:
  unknown imports now fail image loading before `DriverEntry`. The old prefix-matched no-op
  machinery was replaced with exact bindings for the
  ReactOS `npfs.sys`/`msfs.sys` surface, including Unicode string helpers, optional registry query
  defaults, security/object helpers, cancel-safe queue callbacks, dynamic IRP allocation, timers,
  probes, and cleanup routines. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, and `./run.sh` through genuine explorer shell chrome with
  `286/288` checks passing; the only failing checks remain the known
  `exec_irp_transport_call_bound` and `exec_client_reply_bound` transport-accounting gates. Review
  adjustment: with the hosted FSD fallback removed, resume B3 at the PCI/NDIS equivalence frontier
  before deleting the old bespoke NIC proof.
- B3 cleanup continued. The hosted driver PE resolver is now provider-DLL-aware: imports are resolved
  as `dll!symbol`, `ntoskrnl.exe`/`hal.dll` exact imports bind through the executive registry, malformed
  import tables and ordinal imports fail closed, and unsupported dependency DLLs such as `ndis.sys`
  report the missing `dll!symbol` before `DriverEntry` instead of colliding on name-only exports.
  `hal!KeStallExecutionProcessor` is explicitly bound as a HAL timing primitive for the ReactOS e1000
  import surface, but `ndis.sys` remains a real dependency image frontier rather than an executive shim.
  Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, and `./run.sh` through genuine explorer shell chrome with
  `286/288` checks passing; the only failing checks remain the known
  `exec_irp_transport_call_bound` and `exec_client_reply_bound` transport-accounting gates. Review
  adjustment: next B3 work should load and resolve real dependency images such as `ndis.sys` (or add an
  honest PCI WDM fixture) before retiring the bespoke NIC proof.
- B3 cleanup continued. Hosted driver launch now discovers real dependency provider DLLs from raw
  import descriptors without heap allocation, maps `ndis.sys` into the same hosted image window after
  the primary image, and resolves `ndis.sys!symbol` from that loaded support image's export directory.
  The executive trampoline registry remains limited to the kernel providers (`ntoskrnl.exe` and
  `hal.dll`); `ndis.sys` is a real PE image, not an executive shim. The support image is not yet run
  through its own driver initialization, so loading ReactOS `e1000.sys` will now get as far as the
  real `ndis.sys` import surface and still fail truthfully on missing NT/HAL exports until those core
  imports are implemented. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, and `./run.sh` through genuine explorer shell chrome with
  `286/288` checks passing; the only failing checks remain the known
  `exec_irp_transport_call_bound` and `exec_client_reply_bound` transport-accounting gates. Review
  adjustment: next B3 work should implement the real NT/HAL import surface required by ReactOS
  `ndis.sys`, then initialize the NDIS support driver before binding `e1000.sys` through generic PCI
  grants.
- B3 cleanup continued. The hosted component harness can now initialize an optional support driver
  image before the primary hosted driver's `DriverEntry`, and support failure prevents the primary
  image from being marked entered or registered. ReactOS `ndis.sys` remains a real loaded PE support
  image: all NT/HAL imports from its import table have exact trampoline bindings, including RTL
  ANSI/Unicode/integer helpers, driver-object extensions, interlocked lists/SLists, work items,
  MDL/memory helpers, timers/DPC/spin helpers, bounded Zw registry/file failures, and grant-bound HAL
  bus translation/interrupt/PCI config reads. Generic hosted resource grants now also carry bus
  identity, PCI address, vendor/device/class, and interrupt line/pin so `IoGetDeviceProperty` and
  `HalGetBusDataByOffset` answer from assigned devnode state instead of hardcoded process identity.
  Validation found and fixed one harness-limit regression: the shared `DriverExportRegistry` was
  still capped at 160 entries while the real FSD/NDIS surface now binds 184 names, causing late
  imports such as `DbgPrint` to fail silently and preventing `Msfs`/`Npfs` from loading. The registry
  cap is now 256, exhaustion is tracked/tested, and FSD registration panics if capacity is exceeded.
  Validation: `cargo fmt --all`, `cargo test -p nt-compat-exports`, static `ndis.sys`/`npfs.sys`/
  `msfs.sys` import comparison against `register_fsd_trampolines()`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, and `./run.sh` through genuine explorer shell chrome with
  `286/288` checks passing; the only failing checks remain the known
  `exec_irp_transport_call_bound` and `exec_client_reply_bound` transport-accounting gates.
  Review adjustment: `e1000.sys` still cannot complete AddDevice because NDIS asks for
  `DevicePropertyDriverKeyName`/miniport `Linkage` registry data, and the hosted driver registry
  handle is currently an empty key that returns truthful missing/unsupported statuses. The next B3
  slice should project devnode-backed driver-key registry state, then run the staged boot and convert
  the real NDIS/e1000 startup evidence into gates before removing the old bespoke NIC proof.
- B3 cleanup continued. Devnode-backed driver registry identity is now carried by Config Manager and
  the executive boot plan: `ServiceMetadata` includes `ClassGUID`, `DevnodeRecord` includes the
  imported Enum `Driver` value, and hosted AddDevice receives both so `IoGetDeviceProperty` can
  answer `DevicePropertyDriverKeyName` and the hosted registry path can expose the miniport
  `Linkage` key without falling back to an empty registry handle. The staged boot initially exposed a
  separate rootserver infrastructure limit: the NT executive root task entered the guard page during
  ReactOS process bring-up after `NtQuerySection(csrss.exe)`. `rust-micro` now sizes the guarded
  rootserver stack separately for `extern-rootserver` builds and the loader spec asserts the mapped
  aux page count. Validation: `cargo fmt --all`, `cargo test -p nt-config-manager`,
  `cargo test -p nt-exe-image`, `cargo test -p nt-io-manager`, `cargo test -p nt-process`,
  `cargo test -p nt-address-space`, `cargo test -p nt-user-callback`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and headless boot `.tmp/full-boot-larger-rootstack-20260806.log` to genuine explorer shell chrome
  with `286/288` checks passing. The only failing gates remain the known
  `exec_irp_transport_call_bound` and `exec_client_reply_bound`; the generic hardware gates pass for
  registry selection, MMIO/interrupt/DMA, root-PDO start, ISR delivery, and DPC delivery. Review
  adjustment: B3 remains active until real `ndis.sys` initialization and ReactOS `e1000.sys` miniport
  startup run through the same generic PCI grant, after which the old raw NIC proof can be removed.
- B3 cleanup continued. The generated-hive PnP hardware proof no longer collapses
  `boot_system_pnp_driver_bindings()` to a single selected service. It now materializes an inline
  boot PnP launch plan, copies each selected devnode descriptor into the fixed executive plan buffer,
  and launches every eligible config-hive binding through the hosted AddDevice/START/resource path.
  The old owned-vector conversion used only by the single-binding path was removed. Validation:
  `cargo fmt --all`, `cargo test -p nt-config-manager`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and `./run.sh` through genuine explorer shell chrome with `286/288` checks passing. The generic
  hardware gates stayed green for registry selection, MMIO/interrupt/DMA, root-PDO start, ISR
  delivery, and DPC delivery.
  Review adjustment: the B3 frontier is still real NDIS/e1000. The proof selector is now dynamic
  enough to exercise multiple boot/system PnP bindings when the registry supplies them; next work is
  support-driver/miniport startup and then replacing the old raw NIC proof with PCI-backed generic
  evidence.
- B3 cleanup continued. Service-bound devnode start is now factored into `hosted_pnp_start`: the
  executive publishes the discovered PCI/NIC/root-bus resource context once, boot/system device
  services and the generated-hive hardware proof call the same AddDevice/resource-grant/StartDevice
  helper, and `NtLoadDriver` demand-start device services with Enum-bound devnodes use that helper
  after `DriverEntry`. The previous empty-resource START convenience path was removed; a selected
  devnode without an assigned resource now reports `STATUS_INVALID_DEVICE_REQUEST` instead of
  succeeding synthetically. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and `./run.sh` through genuine explorer
  shell chrome with `286/288` checks passing. The generated-hive hardware gates still pass for
  registry selection, MMIO/interrupt/DMA, root-PDO start, ISR delivery, and DPC delivery. Review
  adjustment: continue B3 at the NDIS boundary: support-driver initialization, miniport
  AddDevice/StartDevice, and adapter resource queries should now ride the generic demand-start PnP
  path.
- B3 cleanup continued. The generated SYSTEM hive now seeds a real registry-selected E1000 PCI
  service/devnode/class-linkage identity, and boot imports `Control\Class` alongside `Services`,
  `Enum`, and service-group order into Config Manager. The generated hive moved to the second
  storage shared page to avoid import-table overlap. Hosted registry identity is now explicit:
  devnodes carry `Linkage\Export` from the class key, hosted registry handles copy that identity,
  AddDevice publishes it through the shared frame, and the driver launch path rejects missing exports
  instead of deriving synthetic device names. Hosted driver instance slots now reserve the first free
  slot, clear stale mappings before reuse, and record exec-frame mappings for teardown. Validation:
  `cargo fmt --all`, `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `cargo test -p nt-config-manager`, `cargo test -p nt-hive-core`,
  `cargo test -p nt-hive-regf`, `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and `./run.sh` proof
  `.tmp/full-boot-e1000-pci-proof-5-20260806.log`. The boot reached genuine explorer shell chrome
  with `288/291` checks passing; `exec_generic_pci_registry_selected`,
  `exec_generic_pci_support_driver_entry`, and `exec_generic_pci_add_device_reached` are green. The
  remaining failures are the known transport-accounting gates
  `exec_irp_transport_call_bound`/`exec_client_reply_bound` plus `exec_vm_pool_headroom`. Review
  adjustment: B3 remains open at real ReactOS NDIS/e1000 `START_DEVICE`, which currently returns
  `STATUS_INVALID_DEVICE_REQUEST` before MMIO, interrupt, or DMA evidence is produced.
- B3 continued. The registry-selected ReactOS `e1000.sys` PCI path now receives a full
  memory+I/O-port+interrupt `CM_RESOURCE_LIST`, accepts NT `PCI_SLOT_NUMBER` config reads through
  real `ndis.sys`, maps the 128 KiB BAR, registers the 64-byte I/O port BAR, and allocates all three
  observed common buffers from one per-devnode DMA grant (two 2048-byte descriptor rings plus the
  262144-byte receive-buffer window). `nt-dma-manager` now scopes logical DMA addresses by
  `DmaOwner`, so multiple devices may reuse the same logical IOVA in separate domains, and hosted
  common-buffer evidence records each active allocation rather than one synthetic global result.
  The NDIS diagnostic interposition used to find the boundary was removed; dependency imports now
  call the real mapped `ndis.sys` export. Validation: `cargo fmt --all`,
  `cargo test -p nt-cm-resources`, `cargo test -p nt-pnp`, `cargo test -p nt-dma-manager`,
  `cargo test -p nt-hive-core`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and headless boot
  `.tmp/full-boot-e1000-cleaned-counts-20260806.log` through genuine explorer shell chrome with
  `284/291` checks passing. Generic config-PnP instrumentation is now count-based:
  `selected=2 attempted=2 add=2 started=1`, with PCI separately reported as
  `pci_selected=1 pci_attempted=1 pci_support=1 pci_add=1 pci_started=0
  pci_first_error=0xc0000001`. The remaining B3 frontier is inside real e1000 miniport start after
  resource and common-buffer setup, before interrupt connection. Review adjustment: do not claim
  arbitrary NIC/driver scale yet; hosted instance/device tables, shared-frame allocation-record
  slots, and fixed proof BAR/DMA windows are still bounded. The next cleanup should replace those
  fixed hosted arenas with per-devnode dynamic resource/window allocation before multi-NIC support is
  considered complete.
- B3 continued. Hosted hardware drivers now receive real x86 I/O-port caps for PnP-granted I/O BARs,
  and the component pump services only validated x86 #GP `out dx,eax` faults against the projected
  cap, resource range, opcode byte, and thread registers. Multi-instance hosted drivers now carry an
  executive image alias into the pump for instruction validation, the old send-only port-I/O helpers
  were replaced by shared error-reporting helpers, and boot evidence/gates now track generic PCI
  port-write service instead of relying on NIC-specific code. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and
  `.tmp/boot-ioport-out32-20260806.log`. Result: `exec_generic_pci_io_port_out32` passed, E1000
  evidence reported `io_out32=1 io_out32_count=4`, and the boot reached genuine explorer shell
  chrome with `285/292` checks passing. Review adjustment: the B3 frontier has moved past inline
  port I/O. The next target is the rootserver `RingChannel::raw` null destination fault at
  `rip=0x10000455944/cr2=0` during E1000 `START_DEVICE`, while longer-term multi-NIC support still
  needs dynamic per-devnode hosted instance/resource windows rather than fixed proof arenas.
- B3 continued. `IoSetDeviceInterfaceState` no longer mutates Object/I/O Manager state from hosted
  driver import context. The hosted call captures the requested interface link, target, and
  enable/disable state in the driver's shared frame, and the executive applies the symbolic-link
  create/delete after the parked `START_DEVICE` dispatch returns. Repeated enable/disable transitions
  are idempotent at the import boundary, and the executive's Object Manager/Configuration Manager
  clients are now heap-pinned for the rootserver lifetime instead of leaving raw global pointers to
  `_start` stack locals. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and
  `.tmp/boot-device-interface-idempotent-20260806.log`. Result: E1000 `AddDevice` and
  `START_DEVICE` both return `STATUS_SUCCESS`, `exec_generic_pci_io_port_out32` remains green, and
  the boot reaches genuine explorer shell chrome with `285/292` checks passing. Review adjustment:
  the rootserver `RingChannel::raw` null-destination wall is gone; the B3 frontier has moved to the
  explicit E1000 interrupt-delivery proof, which now walls at `label=3 ip=0x0e014abd
  addr=0x1000f01fd88` after start while ISR/DPC evidence for that PCI device is still absent.
- B3 continued. Hosted driver IRQL state is now per-component shared-frame state instead of a
  PASSIVE-only CR8 rewrite. ReactOS CR8 helper reads are patched to load that byte, hosted spin-lock
  imports raise/lower it according to the NT contract, `KeReleaseSpinLockFromDpcLevel` no longer
  lowers IRQL, `KeGetCurrentIrql` is a real trampoline, and queued KDPC routines run at
  `DISPATCH_LEVEL`. The pump also records label-3 exception/code details for future hosted-driver
  walls. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and
  `./rust-micro/scripts/run_specs.sh` proof `.tmp/boot-hosted-irql-20260806.log`. Result: boot
  reaches genuine explorer shell chrome with `286/292` checks passing; `E1000` reports
  `start=0x00000000`, `int_delivered=1`, `dpc=1`, `dpc_count=1`, `dpc_drops=0`, DMA common-buffer
  evidence, and generic PCI I/O-port evidence. The new generic gates
  `exec_generic_hw_interrupt_delivered` and `exec_generic_hw_dpc_delivered` pass for the real
  registry-selected E1000 path. Review adjustment: B3 is no longer blocked on E1000 ISR/DPC
  delivery. The remaining failures are the legacy direct NIC proof gates
  `exec_nic_has_msi_capability`/`exec_nic_raised_real_interrupt`/
  `exec_nic_irq_reached_isolated_host`, transport-accounting gates
  `exec_irp_transport_call_bound`/`exec_client_reply_bound`, and `exec_vm_pool_headroom`.
- B3 cleanup continued. The old direct NIC MSI/isolated-ISR proof was retired from the early
  hardware capstone. The remaining direct NIC checks still prove raw BAR mapping, live MMIO, TX DMA
  writeback, and VT-d confinement, while interrupt delivery now belongs only to the generic
  registry-selected hosted-driver/resource-manager gates that already exercise ReactOS `e1000.sys`
  through `IoConnectInterrupt`, ISR dispatch, and KDPC delivery. The obsolete
  `exec_nic_has_msi_capability`, `exec_nic_raised_real_interrupt`, and
  `exec_nic_irq_reached_isolated_host` gates and their hand-programmed MSI helper were removed.
  Review adjustment: the remaining cleanup targets are transport accounting, VM pool headroom, and
  dynamic per-devnode hosted resource/window allocation for multi-NIC and arbitrary driver scale.
- B3 cleanup continued. Transport accounting now uses a dedicated never-bound
  `REPLY_TRANSPORT_PROBE_SLOT` for the negative control, so the proof no longer depends on a spare
  dynamic hosted-driver instance slot. The FSD-class hosted-driver pool now matches the one 2 MiB
  page-table window that was actually mapped for each instance, reclaiming unused root-untyped
  capacity without changing the effective driver address space. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and
  `./rust-micro/scripts/run_specs.sh` proof `.tmp/boot-fsd-pool-headroom-20260807.log`. Result:
  `exec_generic_hw_interrupt_delivered`, `exec_generic_hw_dpc_delivered`,
  `exec_irp_transport_call_bound`, `exec_client_reply_bound`, `exec_vm_pool_headroom`, and
  `exec_explorer_shell_chrome_painted` all pass; the boot reaches genuine explorer shell chrome with
  `289/289` checks passing. Review adjustment: B3 cleanup now centers on replacing remaining fixed
  hosted proof arenas/windows with per-devnode dynamic resource windows for multi-NIC and arbitrary
  boot-driver scale.

### 2026-08-07

- B3 cleanup continued. Hosted PnP resource publication now carries a vector of
  `HostedPnpPciResourceWindow` records keyed by PCI bus/dev/function, with separate per-window
  component MMIO and DMA VAs. The grant path first resolves the registry-selected devnode against the
  enumerated PCI bus, then matches the corresponding published window before assigning resource
  lists, mapping BAR/DMA frames, and registering resource-manager/DMA-manager ownership. The old
  `HOSTED_PNP_NIC_*` globals and the combined PCI-match/resource-assignment helper were removed, and
  hosted resource mapping now creates every page-table leaf required by a multi-2MiB MMIO or DMA
  grant. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and
  `./rust-micro/scripts/run_specs.sh` proof `.tmp/boot-hosted-pci-windows-20260807.log`. Result:
  `E1000` receives PCI resources (`mmio_len=131072`, `io_len=64`, `dma_len=270336`), starts through
  the generic path, and keeps MMIO, I/O-port, DMA, ISR, and DPC evidence green; the boot reaches
  genuine explorer shell chrome with `289/289` checks passing. Review adjustment: this removes the
  NIC-named hosted resource context, but the publisher still exposes only the pre-claimed E1000
  hardware grant and root-bus proof resources still use fixed VAs. The next B3 cleanup should make
  resource publication originate from the registry-selected devnode set/resource broker for every
  eligible PCI function, then replace the fixed root-bus proof windows with the same allocator.
- B3 cleanup continued. Hosted PCI window publication now originates from the registry-selected
  boot/system PnP launch plans: the early hardware claim is only retained as broker grant material,
  the initial hosted PnP context publishes PCI enumeration without resource windows, and the final
  context exposes windows only for launch-plan devnodes that resolve to matching broker grants.
  Duplicate bus/dev/function windows are collapsed, missing grants and capacity exhaustion are
  reported explicitly, and the boot now gates this boundary with
  `exec_hosted_pci_windows_selected_from_registry`. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and
  `./rust-micro/scripts/run_specs.sh` proof `.tmp/boot-plan-derived-pci-windows-20260807.log`.
  Result: `selected=1 published=1 missing-grants=0 cap-exhausted=0`, the ReactOS `E1000` path keeps
  MMIO, I/O-port, DMA, ISR, DPC, and interface publication evidence green, and the boot reaches
  genuine explorer shell chrome with `290/290` checks passing. Review adjustment: PCI publication is
  no longer tied to a pre-published E1000 identity; remaining B3 resource-window debt is the fixed
  root-bus proof VAs and the bounded hosted window/instance tables before arbitrary multi-driver
  scale can be considered complete.
- B3 cleanup continued. Root-bus proof resources now use the same published resource-window
  boundary as PCI. `nt-pnp` exposes a tested root-bus profile matcher, the executive builds root
  windows only for registry-selected launch-plan devnodes, and the old static
  `HOSTED_PNP_ROOT_DMA_*` frame globals plus `NIC_VADDR`/`DMA_VADDR`/`NIC_IOVA` reuse were removed
  from the root grant path. The root proof still has an executive seed alias for its synthetic MMIO
  register page, but that alias is allocated by root-window index and looked up through the active
  resource evidence before interrupt injection. Validation: `cargo fmt --all`, `cargo test -p
  nt-pnp`, `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and
  `./rust-micro/scripts/run_specs.sh` proof `.tmp/boot-root-resource-windows-20260807.log`.
  Result: `pci-selected=1 pci-published=1 root-selected=1 root-published=1`, both
  `exec_hosted_pci_windows_selected_from_registry` and
  `exec_hosted_root_windows_selected_from_registry` pass, `DmaPnpPowerTest` and ReactOS `E1000`
  both receive resources through the generic hosted PnP path, and the boot reaches genuine explorer
  shell chrome with `291/291` checks passing. Review adjustment: the remaining B3 resource debt is
  no longer static hosted identity; it is bounded scaling and broker coverage. Next work should make
  hardware-grant discovery enumerate/claim every registry-selected eligible PCI function instead of
  carrying only the raw E1000 claim, then address fixed hosted instance/window caps where they become
  practical blockers.
- B3 cleanup continued. PCI grant discovery now walks the registry-selected boot/system PnP launch
  plans before resource-window publication, deduplicates selected bus/dev/function identities, keeps
  any existing real DMA/IOMMU grant, and can claim cap-only BAR/interrupt grants for selected PCI
  functions that do not require DMA. PCI resource windows and START validation now treat DMA as
  optional all-or-none state, so the broker no longer invents synthetic DMA or rejects legitimate
  BAR/interrupt-only devices. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and
  `./rust-micro/scripts/run_specs.sh` proof `.tmp/boot-pci-grant-discovery-20260807.log`. Result:
  `exec_hosted_pci_grants_discovered_from_registry` passes with
  `selected=1 existing=1 claimed=0 missing-mmio=0 missing-int=0 claim-failures=0 cap-exhausted=0`,
  PCI/root window publication remains clean, ReactOS `E1000` and `DmaPnpPowerTest` still start
  through the generic hosted PnP path, and the boot reaches genuine explorer shell chrome with
  `292/292` checks passing. Review adjustment: the next B3 cleanup should move the E1000
  DMA/common-buffer/IOMMU setup itself out of the raw proof block into generic broker grant
  construction, then replace fixed hosted instance/window caps with growable or per-launch
  allocation.
- B3 cleanup continued. Existing PCI grant registration now uses the same broker constructor as
  registry-selected PCI grant discovery: the E1000 path resolves the enumerated PCI device by
  bus/dev/function, derives BAR base and page count from the device's memory BAR, removes the fixed
  `NIC_BAR_PAGES` constant, and records the existing DMA/IOMMU grant only when the DMA grant is
  internally consistent. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and
  `./rust-micro/scripts/run_specs.sh` proof `.tmp/boot-brokered-existing-pci-grant-20260807.log`.
  Result: `exec_hosted_pci_existing_grant_brokered` passes with `count=1 failures=0`, PCI/root
  window publication remains registry-selected, ReactOS `E1000` and `DmaPnpPowerTest` still start
  through the generic hosted PnP path, and the boot reaches genuine explorer shell chrome with
  `293/293` checks passing. Review adjustment: the remaining B3 cleanup is moving DMA/common-buffer
  and IOMMU allocation itself behind the broker boundary, then replacing fixed hosted
  window/instance caps where they block arbitrary multi-driver scale.
- B3 cleanup continued. E1000 DMA/common-buffer grant allocation and IOMMU setup moved behind
  generic broker helpers: `allocate_hosted_pci_dma_grant` allocates the cap-backed common-buffer
  grant, `map_hosted_pci_dma_grant_iova` derives IO-space request/domain identity from the
  enumerated PCI device and maps the grant into the device IO space, and hosted PnP only receives
  the existing DMA grant after IOMMU mapping succeeds. The unused raw `alloc_slot_run` helper was
  removed. The raw direct TX proof still runs before VT-d as a hardware liveness proof, while the
  brokered boundary is now gated by `exec_hosted_pci_dma_grant_iommu_brokered`. Validation:
  `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and
  `./rust-micro/scripts/run_specs.sh` proof `.tmp/boot-brokered-pci-dma-grant-20260807.log`.
  Result: `exec_frame_get_paddr`, `exec_nic_tx_dma_writeback`,
  `exec_nic_iopt_hierarchy_built`, `exec_nic_dma_frame_io_mapped`,
  `exec_hosted_pci_dma_grant_iommu_brokered`, and `exec_nic_confined_dma` pass; registry-selected
  PCI/root window publication, ReactOS `E1000`, `DmaPnpPowerTest`, ISR/DPC evidence, and explorer
  shell chrome remain green with `294/294` checks passing. Review adjustment: B3 cleanup now moves
  to bounded hosted window/instance/allocation-record scaling and then removing the direct raw proof
  once generic PCI evidence fully replaces it.
- B3 cleanup continued. The fixed hosted PCI/root resource-window caps were removed from the
  publication path. `HostedPnpResourceVaAllocator` now hands out component MMIO/DMA VAs from the
  hosted-driver resource arena, root proof seed aliases from the actual executive seed scratch
  arena, and root DMA logical addresses independently; publication reports `pci-va-exhausted` or
  `root-va-exhausted` only when those real arenas run out. PCI grant discovery no longer rejects
  selected devices because of the old window cap. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and
  `./rust-micro/scripts/run_specs.sh` proof
  `.tmp/boot-dynamic-hosted-resource-windows-20260807.log`. Result: hosted PCI grant discovery
  reports `selected=1 existing=1 claimed=0 missing-mmio=0 missing-int=0 claim-failures=0`,
  resource publication reports
  `pci-selected=1 pci-published=1 pci-missing-grants=0 pci-va-exhausted=0 root-selected=1
  root-published=1 root-missing-grants=0 root-va-exhausted=0`, ReactOS `E1000` and
  `DmaPnpPowerTest` both receive generic resources, the generic MMIO/interrupt/DMA/ISR/DPC gates
  stay green, and explorer shell chrome remains green with `294/294` checks passing. Review
  adjustment: remaining B3 scaling debt is now the hosted driver instance table, shared-frame DMA
  allocation-record capacity, and any other launch-state caps that prevent arbitrary driver count.
- B3 cleanup continued. The fixed hosted driver instance table was removed. Live driver state,
  executive alias cap lists, and FSD reply caps now grow on demand; W^X rights storage is per-loaded
  image; executive code/aux PT maps are checked; high per-instance VA arena coverage is installed on
  demand. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and `./rust-micro/scripts/run_specs.sh` proof
  `.tmp/boot-dynamic-driver-instances-pd-20260807.log`. Result: `Msfs` instance 0, `Npfs` instance 1,
  `IrpFsdTest` instance 2, `DmaPnpPowerTest` reuses instance 2, and ReactOS `E1000` instance 3; generic
  PCI/root hardware gates and FSD transport gates stay green; explorer shell chrome remains green
  with `294/294` checks passing. Review adjustment: remaining B3 launch scaling debt is shared-frame
  DMA allocation records and any other fixed launch-state caps; then remove direct raw NIC proof once
  generic PCI evidence fully replaces it.
- B3 cleanup continued. The hosted common-buffer allocation record list no longer has a fixed
  eight-record shared-page cap. Each hosted driver now maps the full shared handoff arena up to the
  ARG window, publishes the derived record capacity in shared metadata, and validates the capacity and
  high-water mark before replaying allocations into `nt-dma-manager`. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and `./rust-micro/scripts/run_specs.sh` proof
  `.tmp/boot-dynamic-dma-record-arena-20260807.log`. Result:
  `exec_hosted_pci_dma_grant_iommu_brokered`, `exec_generic_hw_mmio_interrupt_dma`,
  `exec_generic_pci_registry_selected`, `exec_generic_pci_support_driver_entry`,
  `exec_generic_pci_add_device_reached`, `exec_generic_pci_io_port_out32`, and explorer shell chrome
  stay green with `294/294` checks passing. Review adjustment: remaining B3 launch scaling debt is now
  hosted device/root-PDO binding tables, hosted registry identity slots, and any small shared queues
  that block real multi-device drivers; then remove direct raw NIC proof once generic PCI evidence
  fully replaces it.
- B3 cleanup continued. Hosted device bindings, root-PDO bindings, and hosted registry identity state
  are no longer fixed 16-slot arrays. The launch path now uses growable `Vec`-backed state, reuses
  holes on teardown, widens hosted registry identity IDs to `usize`, and preserves existing lookup and
  update semantics for AddDevice, PDO, and linkage-registry correlation. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and `./rust-micro/scripts/run_specs.sh` proof
  `.tmp/boot-dynamic-hosted-bindings-20260807.log`. Result: `DmaPnpPowerTest` and ReactOS `E1000`
  generic hardware evidence stayed green, `exec_generic_hw_mmio_interrupt_dma`,
  `exec_generic_pci_registry_selected`, `exec_generic_pci_support_driver_entry`,
  `exec_generic_pci_add_device_reached`, `exec_generic_pci_io_port_out32`,
  `exec_fsd_on_shared_harness`, `exec_msgina_logon_dialog_painted`, and
  `exec_explorer_shell_chrome_painted` pass with `294/294` checks passing. Review adjustment:
  remaining B3 launch scaling debt is now driver registry handle slots, hosted interface
  registration slots, driver object extension slots if real drivers need more, and the small DPC queue
  policy; after those, retire the direct raw NIC proof.
- B3 cleanup continued. The remaining executive-side hosted launch tables now grow on demand:
  driver registry handles are `Vec`-backed with a widened low-16-bit handle index, hosted device
  interface registrations append dynamically while preserving idempotent updates, and driver object
  extension records append dynamically with stale extension metadata cleared on failed registration
  and unload. The old `DRIVER_REGISTRY_HANDLE_SLOTS`, `HOSTED_INTERFACE_REGISTRATION_SLOTS`, and
  `DRIVER_OBJECT_EXTENSION_SLOTS` fixed tables were removed. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and `./rust-micro/scripts/run_specs.sh` proof
  `.tmp/boot-dynamic-hosted-side-tables-20260807.log`. Result: `DmaPnpPowerTest` and ReactOS `E1000`
  generic hardware evidence stayed green, `exec_generic_hw_mmio_interrupt_dma`,
  `exec_generic_pci_registry_selected`, `exec_generic_pci_support_driver_entry`,
  `exec_generic_pci_add_device_reached`, `exec_generic_pci_io_port_out32`,
  `exec_fsd_on_shared_harness`, `exec_msgina_logon_dialog_painted`, `exec_vm_pool_headroom`, and
  `exec_explorer_shell_chrome_painted` pass with `294/294` checks passing. Review adjustment: the
  remaining B3 launch-state cap is the shared-frame DPC queue. Treat it as an ABI cleanup, not a
  Rust table conversion: publish queue capacity in shared metadata, move queue storage into the
  existing shared handoff arena, and keep overflow as a real drop/failure signal.
- B3 cleanup continued. The shared-frame KDPC queue no longer uses the fixed four-entry inline queue
  at `0x490`. The shared ABI now publishes `SH_DPC_QUEUE_CAPACITY`, stores queued KDPC pointers in an
  arena-derived prefix of the shared handoff arena, and moves DMA allocation records after that queue
  region so both queue and DMA records derive capacity from the mapped shared arena. Enqueue/drain
  paths validate the published capacity and preserve real drop accounting on overflow or invalid
  capacity. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and `./rust-micro/scripts/run_specs.sh` proof
  `.tmp/boot-dynamic-dpc-queue-20260807.log`. Result: `exec_generic_hw_mmio_interrupt_dma`,
  `exec_generic_hw_dpc_delivered`, `exec_generic_pci_registry_selected`,
  `exec_generic_pci_support_driver_entry`, `exec_generic_pci_add_device_reached`,
  `exec_generic_pci_io_port_out32`, `exec_fsd_on_shared_harness`,
  `exec_msgina_logon_dialog_painted`, `exec_vm_pool_headroom`, and
  `exec_explorer_shell_chrome_painted` pass with `294/294` checks passing. Review adjustment: B3
  launch-state fixed caps are closed; remaining B3 cleanup is to retire or reclassify the direct raw
  NIC liveness proof now that generic PCI evidence owns the driver path.
- B3 cleanup continued. The old direct e1000 TX liveness proof has been retired from the executive:
  the raw TX descriptor programming, NIC-specific DMA scratch mapping, `exec_nic_*` gates, and
  e1000 transmit-register constants are gone. The pre-storage step now only registers a generic
  hosted PCI grant for the enumerated device: it maps the BAR cap run needed by the legacy KMDF
  fixture, allocates a per-device common-buffer frame run, maps that grant into the PCI requester's
  IOMMU domain, and publishes it as an existing hosted PCI grant for later registry-selected launch
  discovery. Registry-selected PCI grant discovery now also allocates and IOMMU-maps DMA/common-buffer
  grants for newly claimed PCI devnodes, and its gate requires zero DMA failures for claimed grants.
  Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and `./rust-micro/scripts/run_specs.sh` proof
  `.tmp/boot-remove-raw-nic-proof-20260807.log`. Result:
  `exec_hosted_pci_existing_grant_brokered`, `exec_hosted_pci_dma_grant_iommu_brokered`,
  `exec_hosted_pci_grants_discovered_from_registry`, `exec_generic_hw_mmio_interrupt_dma`,
  `exec_generic_hw_dpc_delivered`, `exec_generic_pci_registry_selected`,
  `exec_generic_pci_support_driver_entry`, `exec_generic_pci_add_device_reached`,
  `exec_generic_pci_io_port_out32`, `exec_fsd_on_shared_harness`,
  `exec_msgina_logon_dialog_painted`, `exec_vm_pool_headroom`, and
  `exec_explorer_shell_chrome_painted` pass with `287/287` checks passing. Review adjustment: B3 raw
  NIC proof cleanup is closed; next B3 work is auditing remaining static driver-object construction
  sites and deciding which are fixtures versus real dynamic-boundary debt.
- B3 static driver-object audit closed for the current frontier. The object-service components do not
  construct WDM driver objects. Hosted FSD/win32k `DRIVER_OBJECT` allocation is the generic
  compatibility harness used to call the real image `DriverEntry`, not launch policy. The only
  remaining non-hosted projection was boot-video `Video0`; its projected driver/device/file WDM
  bodies now use `nt-io-manager::write_wdm_open_device_projection`, with a host test proving the
  driver/device/file back-links and object types. Validation: `cargo fmt --all` and
  `cargo test -p nt-io-manager`. Review adjustment: current B3 cleanup is closed; the remaining real
  display debt is future videoprt/miniport hosting, while the immediate kernel-completion work should
  return to A3/A4 SCM-owned Win32 service starts and A5 service-selection gates.
- A5 complete. `nt-config-manager` now has named selectors for demand-start Win32 services and
  demand-start driver services, backed by the existing generic start/type filter and host tests.
  The executive imports the real SYSTEM hive into Config Manager, copies the first auto-start Win32,
  demand-start Win32, and demand-start driver selections into inline proof storage, and gates that
  the selections have registry-owned service names and `ImagePath` values; demand-start driver
  selection also proves the NT service-key driver-object path. Boot evidence in
  `.tmp/boot-scm-service-selection-20260807.log`: auto-start Win32 count 14, first `Browser`;
  demand-start Win32 count 8, first `BITS`; demand-start driver count 12, first `btrfs` with object
  `\FileSystem\btrfs`; `exec_scm_autostart_win32_selected_from_registry`,
  `exec_scm_demandstart_win32_selected_from_registry`, and
  `exec_ntloaddriver_demand_driver_selected_from_registry` pass. Validation: `cargo fmt --all`,
  `cargo test -p nt-config-manager`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and `./rust-micro/scripts/run_specs.sh` proof
  `.tmp/boot-scm-service-selection-20260807.log` with `290/290` checks passing. Review adjustment:
  next work is A3/A4: turn SCM's actual Win32 service start requests into generic process creation
  from `ServiceMetadata`, without putting service-name policy back in the kernel.
- A3 continued. `nt-config-manager` now exposes a typed `Win32ServiceLaunchSpec` for SCM-owned
  service process starts. The spec rejects disabled services, missing `ImagePath`, and malformed
  own+share `Type` combinations, and carries process kind, interactive flag, account name, display
  name, and dependencies from the registry. The executive's SYSTEM-hive service selection proof now
  consumes these launch specs instead of copying raw Win32 `ServiceMetadata`, and its Win32 gates
  prove a typed process model is present for auto-start and demand-start services. Validation:
  `cargo fmt --all`, `cargo test -p nt-config-manager`, and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and `./rust-micro/scripts/run_specs.sh` proof
  `.tmp/boot-scm-win32-launch-spec-20260807.log`. Result: auto-start Win32 count 14 first `Browser`
  `kind=shared`, demand-start Win32 count 8 first `BITS` `kind=shared`,
  `exec_scm_autostart_win32_launch_spec_from_registry`,
  `exec_scm_demandstart_win32_launch_spec_from_registry`,
  `exec_ntloaddriver_demand_driver_selected_from_registry`,
  `exec_msgina_logon_dialog_painted`, and `exec_explorer_shell_chrome_painted` pass with `290/290`
  checks passing. Review adjustment: next A3 work is the concrete SCM service-start route:
  services.exe should use these launch specs to choose `CreateProcessW`/`CreateProcessAsUserW`, while
  the kernel exposes only generic process, section, token, and thread mechanisms.
- A3 continued. `nt-config-manager` now exposes a unified `ServiceStartSpec` that routes a service
  key to either a Win32 process launch spec or a driver load spec based solely on registry `Type`
  metadata. The driver spec carries service name, service key, image path, resolved NT driver-object
  path, driver class, start type, error control, group, class GUID, and tag. Mixed driver+Win32 type
  bits, disabled services, and missing image paths are rejected instead of treated as fallbacks. The
  executive demand-driver selection proof and `NtLoadDriver` lookup now consume
  `ServiceStartSpec::Driver`; the old local metadata-to-driver launch helper was removed. Validation:
  `cargo fmt --all`, `cargo test -p nt-config-manager`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and `./rust-micro/scripts/run_specs.sh` with proof in
  `.tmp/boot-service-start-spec-20260807.log`. Gates passed:
  `exec_scm_autostart_win32_launch_spec_from_registry`,
  `exec_scm_demandstart_win32_launch_spec_from_registry`,
  `exec_ntloaddriver_demand_driver_selected_from_registry`,
  `exec_msgina_logon_dialog_painted`, and `exec_explorer_shell_chrome_painted`; executive summary
  stayed at 290/290. Review adjustment: wire the concrete services.exe start path to the Win32 branch
  and start retiring the hosted executable catalog admission rule.
- A4 started. The hosted executable catalog and owner-local executable open/section/spawn table no
  longer use the historical `8`-slot type; both are now sized by `HOSTED_PROCESS_IMAGE_CAP`, tied to
  the existing `MAX_PI` process mechanism ceiling. This removes one static admission limit without
  pretending dynamic service-process execution works yet. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and `./rust-micro/scripts/run_specs.sh` with proof in
  `.tmp/boot-hosted-image-cap-20260807.log`; the SCM selection gates, IDD_LOGON paint, explorer shell
  chrome paint, and 290/290 executive summary all passed. Review adjustment: solve the runtime VA
  layout next. The current demand-scratch formula reaches explorer at `pi=6`; a dynamic service at
  `pi=7` would start at `0x100_3D00_0000`, which is already explorer's stack mirror, so dynamic
  process runtime registration must get a new non-overlapping scratch/mirror allocator before
  services.exe can admit arbitrary Win32 service children.
- A4 continued. Added pure `nt-hosted-runtime` layout helpers for checked runtime VA ranges and a
  dense high-arena allocator. The executive now keeps the existing `pi=0..6` hosted-process runtime
  layout byte-identical, assigns `pi>=7` scratch/stack/env/heap/image mirror lanes from a separate
  high arena above the hosted-driver executive alias range, and replaces fixed spawned-state matches
  for future process slots with table-backed dynamic spawned signals. Executive demand-scratch and
  SEC_IMAGE mirror PT setup now use a generic paging-chain helper instead of assuming the root VSpace
  already has the relevant PD/PDPT coverage. Validation: `cargo fmt --all`,
  `cargo test -p nt-hosted-runtime`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and `./rust-micro/scripts/run_specs.sh` captured in
  `.tmp/boot-dynamic-runtime-layout-20260807.log`; the run reached
  `exec_msgina_logon_dialog_painted`, `exec_explorer_shell_chrome_painted`, and
  `290/290` executive checks. Review adjustment: the remaining A4 blocker is loaded executable
  storage for non-bootstrap children. Dynamic catalog/runtime admission is possible structurally, but
  `HostedLoadedImageTable` still points at PE objects from the bootstrap-only
  `SERVICE_HOSTED_BOOTSTRAP_PES_WORK` array.
- A4 continued. `HostedLoadedImageTable` now owns parsed hosted executable PEs and resident pool VAs
  directly, so the old `SERVICE_HOSTED_BOOTSTRAP_PES_WORK` and pool-VA side arrays were removed.
  Bootstrap images and later executable images register through the same loaded-image table.
  `NtOpenFile` now admits a non-registered `.exe` opened by an eligible hosted parent by resolving the
  exact NT path to the mounted FAT volume, loading and relocating that PE into the resident pool,
  adding a fixed-copy catalog identity at the next post-bootstrap `pi`, registering the dynamic
  runtime lane, and then using the existing owner-local open/section/process table. The dynamic role
  is derived from the creator's hosted role: service descendants are non-interactive services, and
  shell descendants are interactive shell processes. Validation: `cargo fmt --all`,
  `cargo test -p nt-exe-image`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and `./rust-micro/scripts/run_specs.sh` captured in
  `.tmp/boot-dynamic-hosted-exe-20260807.log`; the proof run reached
  `exec_msgina_logon_dialog_painted`, `exec_explorer_shell_chrome_painted`, dynamic process
  allocation gates, and `290/290` executive checks with no `FAIL` or `exec-paging` markers. Review
  adjustment: A3 should now make services.exe consume `Win32ServiceLaunchSpec` for real Win32 service
  process creation, which will give A4 a live non-bootstrap child process gate.
- A3/A4 unblocker. services.exe now gets through its real `CheckForLiveCD`/control-set copy route
  without corrupting advapi32's `RegCopyTreeW` work queue: native registry syscalls truncate `ULONG`
  arguments captured from x64 syscall frames before using `Index`, `InfoClass`, and `Length`; the
  executive registry merge path can enumerate one value/subkey by index instead of materializing full
  snapshots; `nt-hive-core` and `nt-hive-regf` expose host-tested indexed subkey/value reads. The
  `NtCreateKey` disposition pointer and `NtSetValueKey` data pointer/size are also taken from the
  captured syscall arguments rather than stale stack reads. Validation before cleanup:
  `cargo test -p nt-hive-core hive_borrowed_indexed_enumeration_preserves_names_and_data`,
  `cargo test -p nt-hive-regf imports_services_into_config_manager`,
  `cargo test -p nt-ntdll regcopytree_realloc_buffer_does_not_overlap_queue_nodes`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and boot proof `.tmp/boot-registry-indexed-enum-20260807.log`. Result: no SCM registry-copy crash
  or allocator OOM; desktop/msgina paint and credential input still pass; the frontier moves to
  LSA/SAM/token/profile with `253/290` checks while old explorer/profile gates fail honestly because
  winlogon has not received a real logon token. Review adjustment: finish the LSA self-RPC/SAM
  validation/token chain before treating shell chrome as a reliable end-to-end gate again.
- Native argument-width cleanup continued. The same high-half leak showed up once `lsass.exe`
  reached object-directory enumeration: `NtQueryDirectoryObject` was seeing an 8192-byte buffer as
  `1099511635968` bytes because `Length` was treated as a full `u64`; that syscall now uses the
  dispatcher-captured stack arguments and truncates `ULONG`/`BOOLEAN` parameters at the NT ABI
  boundary. Nearby native `ULONG` lengths for token adjustment, system information, token
  information, file/volume information, file set-information, and pipe device-control buffers were
  narrowed too. Validation: the targeted hive/heap tests above, executive target check,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and boot proof `.tmp/boot-native-ulong-clean-20260807.log`. Result: `NtQueryDirectoryObject`
  logs `len=8192`, SCM registry copy and heap remain stable, and the honest frontier is unchanged at
  LSA/SAM/token/profile with `253/290` checks. Review adjustment: continue the declared-width audit
  and then route the LSA self-RPC/SAM validation worker so `NtCreateToken` can run for a real logon.
- LSA/SAM root cause update. The `253/290` boot showed `SamValidateNormalUser()` returning
  `STATUS_NO_SUCH_USER` while `SAM_SETUP_KEYS_CREATED` stayed `0`: the global normal-boot setup
  overlay made `samsrv!SampIsSetupRunning()` skip `SampInitializeRegistry()`, so the empty staged
  SAM hive never received the real `SAM\Domains\...\Users\Names\Administrator` database tree. The
  setup bridge is now narrower: Winlogon/SCM still see installed boot, but LSASS sees the SAM setup
  phase while the SAM database is absent, forcing ReactOS `samsrv` to build the database through real
  registry writes instead of fabricating validation. Review adjustment: validate that `sam-setup-keys`
  advances and then follow the resulting frontier, likely LSA self-RPC worker activity or
  `NtCreateToken`.
- SAM/token/profile slice. The narrow SAM setup bridge plus existing-key base-hive opens moved boot
  past `STATUS_NO_SUCH_USER`: `samsrv` creates the real SAM database, winlogon receives an
  Administrator token from `NtCreateToken`, userenv materializes and mounts
  `C:\Profiles\Administrator\ntuser.dat`, and explorer starts from the genuine shell launch path.
  Validation: `cargo fmt --all`,
  `cargo test -p nt-hive-core hive_borrowed_indexed_enumeration_preserves_names_and_data`,
  `cargo test -p nt-hive-regf imports_services_into_config_manager`,
  `cargo test -p nt-ntdll regcopytree_realloc_buffer_does_not_overlap_queue_nodes`,
  executive target check, `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and boot proof
  `.tmp/boot-profile-overlay-base-open-20260807.log`. Review adjustment: the next frontier was nested
  explorer callback returns.
- Explorer callback-return slice. The wait-reply pool and deferred callback-return queue now size to
  `MAX_CONTINUATION_DEPTH`; the explorer run shows six successful out-of-order `NtCallbackReturn`
  defer/drain pairs with no callback-return refusal and no old debug-exception/callback-not-redirected
  unwind. Validation: the same targeted hive/heap tests, executive target check, executive build,
  rootserver image build, and boot proof `.tmp/boot-callback-reply-budget-20260807.log`. Review
  adjustment: current blocker is allocator high-water at `6194072/6291456` followed by `alloc.rs:573`
  during deeper explorer shell chrome setup, so the next work should remove persistent registry/shell
  allocations before considering resource-budget changes.
- Registry query stats slice. `NtQueryKey(KeyFullInformation)` no longer materializes full merged
  subkey/value vectors just to compute counts and maximum lengths. `nt-hive-regf` now has direct
  subkey open, value-exists, value-name-only, and value-length-only indexed accessors; the overlay
  has borrowed unique child count/index helpers; the executive merge layer uses those helpers for
  allocation-conscious query-info. Validation: `cargo fmt --all`, full `cargo test -p nt-hive-regf`,
  full `cargo test -p nt-hive-core`, executive target check,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and boot proof `.tmp/boot-registry-query-stats-20260807.log`. Result: the prior allocator panic is
  gone, `exec_explorer_shell_chrome_painted` passes, final heap is `5942200/6291456`, and the run
  completes at `282/290`. Review adjustment: next work should close the remaining proof gates
  (`Dbgk*`, user-callback nested/dead-client bits, win32k nested transport bit) and then reduce or
  re-baseline VM pool headroom with real accounting rather than a resource-cap shortcut.
- Object-namespace handle cleanup. `NtOpenDirectoryObject`, `NtCreateDirectoryObject`,
  `NtOpenSymbolicLinkObject`, and `NtCreateSymbolicLinkObject` now publish real process-local
  `EPROCESS` handle-table entries tagged with the namespace object index and mapped directory/link
  access rights. `RootDirectory`, `NtQueryDirectoryObject`, `NtQueryObject`, and
  `ObjectSessionInformation` resolve both those handles and the older high namespace indexes, so
  existing compatibility callers still work while new opens have normal `NtClose` lifetime.
  Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and boot proof `.tmp/boot-object-namespace-handles-20260807.log`. Result: no regression,
  `exec_explorer_shell_chrome_painted` still passes, final heap is `5942512/6291456`, and the run
  remains at `282/290`. Review adjustment: the repeated SSN at the iteration backstop is
  `NtWaitForSingleObject` (SSN 281), not `NtOpenDirectoryObject`. The visible sequence waits on a
  dispatcher object before each `OutputDebugString` DBWIN probe, so the next slice should capture the
  actual wait object identity and fix the missing shell path/status driving that debug-output loop
  rather than changing callback proof gates.
- Native argument-width cleanup continued. `NtQueryDirectoryFile` now applies the NT ABI widths to
  every filesystem path: `Length` is truncated as `ULONG`, and `ReturnSingleEntry`/`RestartScan` are
  truncated as `BOOLEAN` before validation. This removes the old scoped writable-overlay-only
  exception and lets read-only FAT directory queries execute the same declared-width path instead of
  depending on high-half stack garbage. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and boot proof `.tmp/boot-query-dir-widths-20260807.log`. Result: no regression,
  `exec_explorer_shell_chrome_painted` still passes, final heap is `5944512/6291456`, and the run
  remains at `282/290` with the same known `Dbgk*`, user-callback proof-bit, win32k nested transport,
  and VM pool-headroom gates outstanding. Review adjustment: continue the ABI-width audit across
  remaining native stack arguments while the proof frontier stays on the debug/callback accounting
  gates and explorer's post-render wait/debug-output loop.
- Native file-query surface cleanup. `NtQueryFullAttributesFile` is now present in
  `NativeService`, registered in the Windows 7/ReactOS table at SSN 156, and backed by real path
  state: writable overlay paths return `FILE_NETWORK_OPEN_INFORMATION` from `nt-fs`
  `StandardInformation`, read-only install-tree paths return EOF/kind/attributes from the FAT
  loader, and misses stay `STATUS_OBJECT_NAME_NOT_FOUND`. The new service deliberately does not add
  the older hosted-image existence escape hatch. Validation: `cargo fmt --all`,
  `cargo test -p nt-syscall`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and boot proof `.tmp/boot-query-full-attrs-20260807.log`. Result: no regression,
  `exec_explorer_shell_chrome_painted` still passes, final heap is `5944656/6291456`, and the run
  remains at `282/290`. SSN 156 was not called in this boot; shell debug output still reports
  `HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND)` from `CStartMenu`/`startmnu`, so the next shell-path
  slice should trace the real `SHGetSpecialFolderLocation`/PIDL route rather than treating DBWIN
  debug-output waits as the cause.
- Shell path/device-map slice. ReactOS `GetDriveTypeW` now receives a real
  `PROCESS_DEVICEMAP_INFORMATION.Query` view from the mounted DOS drives, and `nt-fs` resolves both
  `\??\C:` and `\DosDevices\C:` as the FAT volume root. Directory/file mismatch statuses now match
  NT create semantics (`STATUS_NOT_A_DIRECTORY`/`STATUS_FILE_IS_A_DIRECTORY`), and `NtOpenFile` uses
  dispatcher-captured `ShareAccess`/`OpenOptions` values instead of manual x64 stack rereads.
  Validation: `cargo fmt --all`, `cargo test -p nt-fs`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, and
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`. Boot proof
  `.tmp/boot-device-map-root-20260807.log` was interrupted after it advanced beyond the old
  `CStartMenu`/`startmnu` `ERROR_PATH_NOT_FOUND` route and reached the next frontier:
  explorer/RPC worker creation exhausts bounded local worker/pool slots and eventually the seL4 SC
  pool. Review adjustment: do not add path fallbacks; the next work is generic worker/thread/SC pool
  capacity and accounting under real explorer activity.
- Hosted-thread sched-context lifecycle slice. `attach_sched_context` now uses checked `SYS_CALL`
  invocations for SC retype/configure/bind and returns the allocated SC cap. Isolated
  component/image spawners stop on attach failure, while hosted NT second-thread spawn unwinds the
  TCB/CNode/window reservation and returns real thread-creation failure instead of publishing an
  unschedulable worker. `HostedThreadMechanismCaps` now carries the SC cap, and hosted thread
  teardown recycles both the bound SC and the deleted TCB root slot. Validation:
  `cargo fmt --all`, `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and boot proof
  `.tmp/boot-sc-reclaim-20260807.log`. Result: genuine explorer shell chrome still passes,
  `win32k-pool-exhaustions=0`, final pool census has `ut-fails=0`, and the previous
  `retype: sc pool exhausted`/`failed to create thread`/local worker exhaustion loop does not recur.
  The run exits at `282/290` with the remaining known gates: dbgk syscall/wait wake proofs,
  user-callback nested/dead-client proof bits, win32k nested transport accounting, and VM
  pool-headroom accounting. Review adjustment: next work should debug unserviced worker syscall
  `SSN=188` and the later win32k `ClientThreadSetup` failures without adding fallback success paths.
- User APC syscall slice. `NtQueueApcThread` is registered at ReactOS/Win7 SSN 188 and backed by a
  real bounded `NtThread` user APC queue with `THREAD_SET_CONTEXT` handle checks, system-thread
  rejection, FIFO delivery, capacity failure, and lifecycle clearing on termination/reuse.
  `nt-thread-start` now owns the host-tested AMD64 APC `CONTEXT` frame layout expected by
  `KiUserApcDispatcher`; the executive resolves that ntdll export dynamically, writes APC frames to
  the current thread's user stack, rewrites the hosted TCB registers, and uses a length-0 fault reply
  so the restored context, not the syscall reply, returns `STATUS_USER_APC`. Alertable
  `NtDelayExecution`, `NtWaitForSingleObject`, the legacy `NtWaitForMultipleObjects` ladder, and
  `NtTestAlert` all share the same delivery primitive. Validation so far: `cargo fmt --all`,
  `cargo test -p nt-process`, `cargo test -p nt-thread-start`, `cargo test -p nt-syscall`, and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: run the full rootserver/kernel build and boot proof next; if `ClientThreadSetup`
  still fails, inspect whether the APC normal routine ran and whether follow-on waits should wake
  queued APC targets rather than only delivering when they re-enter the kernel.
- Dynamic object-namespace headroom slice. The object namespace no longer treats the original
  192-entry reservation as a hard limit: `ObjEntry` insertion now performs checked growth, and the
  anonymous event/semaphore/mutant helpers no longer reject creation solely because the initial
  reservation is full. This removes a real object-manager fixed-capacity wall that only showed up
  after genuine explorer activity filled the namespace before the post-loop dbgk proofs created
  debug-object `EventsPresent` events. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and boot proof `.tmp/boot-dynamic-objns-20260807.log`. Result: the run advances from `282/290` to
  `289/290`; all dbgk syscall/wait/exception/block proofs, user-callback nested/dead-client proofs,
  and win32k nested transport accounting are green, while genuine explorer shell chrome pixels still
  pass. Review adjustment: the last red gate was `exec_vm_pool_headroom`; the next slice should make
  that gate track current measured runway instead of the stale three-quarter ratio from the smaller
  pre-desktop frontier.
- VM-pool and callback-idle proof slice. `exec_vm_pool_headroom` now checks a named measured
  root-Untyped runway floor, prints `ut-free` in the pool census, and still fails on any real untyped,
  frame-registry, VAD, free-list, map, alias, ASID, or cslot exhaustion signal. The historical
  iteration backstop no longer enters post-loop proof injections while win32k has active suspended
  user-callback levels; it waits until the callback/continuation stacks, dispatch depth, and
  suspended outstanding count are idle, with a bounded diagnostic expiry if they never drain.
  Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and boot proof `.tmp/boot-callback-aware-backstop-20260807.log`. Result: genuine explorer shell
  chrome pixels still pass, win32k nested transport and user-callback dead-client proofs are green,
  `exec_vm_pool_headroom` passes with about 59 MiB root-Untyped free and zero allocation failure
  counters, and the executive proof summary reaches `290/290` (`run_specs.sh` exits with QEMU's
  sentinel code `3` after `[microtest sentinel matched -- exiting QEMU]`). Review adjustment: the
  immediate desktop frontier is green again; continue with the larger completion plan rather than
  adding more boot-frontier special cases.
- A3/A4 continued. `nt-config-manager` now projects a Win32 service `ImagePath` into the generic
  process-creation inputs services.exe ultimately drives: parsed executable path, normalized NT image
  path, and command line. The projection is host-tested for unquoted `%SystemRoot%\system32\svchost`
  service command lines, quoted executable paths, SystemRoot-relative paths, demand-start services,
  and malformed/unsupported values, including lookalike SystemRoot prefixes. The executive SCM
  selection proof now copies and requires the projected NT image path and command line for the first
  auto-start and demand-start Win32 services, so the gate proves registry data is launchable through
  the generic process path rather than only selected by name/type. Validation: `cargo fmt --all`,
  `cargo test -p nt-config-manager`, the executive x86_64 no-std `cargo check`,
  `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and the boot proof log
  `.tmp/boot-service-process-launch-20260807-rerun.log` (`290/290`, SCM launch-spec gates,
  services.exe, VM pool headroom, explorer shell chrome, and sentinel green). Review adjustment: keep
  A3 focused on live services.exe auto-start child proof without kernel-side service-name policy.

### 2026-08-08

- Registry syscall prerequisite slice. `NtQueryKey` now answers the standard NT key-information
  classes over the executive's merged base-hive/overlay registry view: basic, node, full, name,
  cached, and key user flags. The handler now reports `STATUS_BUFFER_TOO_SMALL` for buffers shorter
  than the fixed header, `STATUS_BUFFER_OVERFLOW` for retryable variable-length truncation, and the
  real full path for `KeyNameInformation`, removing the previous `STATUS_INVALID_INFO_CLASS` wall
  ReactOS advapi32 logged while resolving HKCR keys. Validation:
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: run the next single boot proof and inspect whether services.exe now advances
  farther through SCM database/HKCR handling toward a real non-bootstrap service child spawn; keep
  the proof dynamic and do not add service-name or executable-name launch policy.
- ntdll registry-query compatibility slice. `RtlQueryRegistryValues` now implements the remaining
  ReactOS SCM-facing flags instead of silently skipping them: `RTL_QUERY_REGISTRY_SUBKEY` propagates
  real `NtOpenKey` failures and rejects missing names, required empty subkey enumeration returns
  `STATUS_OBJECT_NAME_NOT_FOUND`, `RTL_QUERY_REGISTRY_NOVALUE` dispatches the query routine with
  `REG_NONE`, and `RTL_QUERY_REGISTRY_DELETE` routes through `NtDeleteValueKey` for named and
  enumerated values. The host-side `REG_MULTI_SZ` splitter now matches ReactOS' explicit-length walk
  and skips malformed trailing tails instead of requiring a perfect double-NUL terminator. Validation:
  `cargo test -p nt-ntdll rtl::registry --lib`, `./scripts/build_ntdll_dll.sh`,
  `git diff --check`, and boot proof `.tmp/boot-rtlqueryregistryvalues-rerun-20260808.log`
  (`290/290`, user-callback transport drained, LSA worker route green, explorer shell chrome green).
  Review adjustment: continue A3/A4 at the live SCM auto-start frontier; the gate still proves
  registry-selected launch specs but not yet a non-bootstrap `svchost.exe` child from services.exe's
  ordinary CreateProcess path.
- SCM database registry-create access slice. The live SYSTEM hive has Win32 service keys such as
  `AudioSrv` without `Security` subkeys, so ReactOS SCM's service database builder creates
  `Services\<Name>\Security` while the parent service key is open for read. `NtCreateKey` now treats
  `RootDirectory` as the relative object-parse root and defers requested access enforcement to the
  target key handle it mints, matching the ReactOS/NT call shape instead of pre-requiring
  `KEY_CREATE_SUB_KEY` on the parent handle. `NtSetValueKey` still requires `KEY_SET_VALUE` on the
  returned child key, so this is a registry access-boundary correction rather than a fallback.
  A follow-on NPFS transport fix moved hosted-FSD pending IRP and completion records out of shared
  image statics backed by component-private `Vec` heaps and into each hosted FSD instance's DATA
  arena. File handles now also track NT waitable-file signal state for pending/completed I/O.
  Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and boot proof
  `.tmp/boot-fsd-data-tables-20260808.log`. Result: kernel specs pass, NPFS
  `exec_npfs_concurrent_irp_read_and_write` and `exec_npfs_write_split_across_pending_read` pass,
  live pipe redrive wakes parked readers, LSA self-RPC remains green, and the run reaches the real
  Winlogon profile/user-shell frontier before failing at `exec_ntloadkey_serviced` and downstream
  userinit/explorer gates (`273/291`). Review adjustment: A3/A4 is no longer blocked by the SCM/LSA
  named-pipe pending-read path; next work is the real `NtLoadKey`/user profile hive lifecycle that
  Winlogon needs before `WlxActivateUserShell` reads `Userinit`.
- Hosted FSD pending-IRP capacity slice. The hosted FSD no longer stores parked IRPs in a fixed
  128-entry DATA table. Pending IRPs now live in a pool-backed per-instance linked list, while
  completed read/write records stay in the DATA arena used by the executive redrive path. This keeps
  long-lived NPFS/SCM/DCOM traffic from failing a real dispatch with `STATUS_INSUFFICIENT_RESOURCES`
  once explorer activity stretches the boot. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and boot proof
  `.tmp/boot-pending-irp-list-20260808.log`. Result: the previous `NtLoadKey` profile frontier is
  gone (`exec_ntloadkey_serviced`, `exec_winlogon_user_shell_activated`,
  `exec_userinit_process_spawned`, and `exec_explorer_process_spawned` pass), real explorer pixels
  are visible again, and the run advances to `288/291`. Review adjustment: the next frontier is not
  an FSD fallback; inspect the real userinit/explorer path around repeated `NtQueryInformationProcess`
  calls, missing explorer `RegisterWindowMessage` captures, the second shell COM class, and
  `WM_PAINT` begin/end dispatch.
- Process session-query cleanup. `NtQueryInformationProcess(ProcessSessionInformation)` now reads the
  process-manager-owned session id through the same access-checked handle path as the other process
  query classes, instead of returning a syscall-layer literal. New child processes inherit their
  parent's session id, and the host process-manager test covers the allowed and denied query paths.
  Validation: `cargo fmt --all`,
  `cargo test -p nt-process process_query_classes_use_access_checked_state_and_real_times`, and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: this removes one hardcoded process-information answer, but the desktop frontier
  remains the explorer shell icon/image-list path before shell chrome paint begin/end proof.
- GDI DIB-section marshal cleanup. `NtGdiCreateDIBSection` now stages the caller's full
  `BITMAPINFO` probe span for isolated win32k instead of copying only the declared fixed header. The
  shared `nt-kernel-exec` helper mirrors ReactOS win32k's `DIB_BitmapInfoSize` calculation for RGB,
  palette-index, bitfields, and core-header layouts, with host tests covering the ABI edge cases.
  Validation: `cargo fmt --all`, `cargo test -p nt-kernel-exec gdi_bitmap --lib`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and boot proof
  `.tmp/boot-dib-full-bmi-20260808.log`. Result: the boot remains green through genuine desktop
  rendering, `exec_msgina_logon_dialog_painted` passes, explorer spawns and leaves 1135 non-bg
  framebuffer pixels, and the run stays at `288/291`. Review adjustment: the shell icon failure is
  not solved by BMI staging; continue at explorer's failed small `IDI_SHELL_DOCUMENT` load,
  invalid image list, missing register-window-message capture, second shell COM class open, and
  absent explorer paint begin/end proof.
- ClientId and handle-lifetime cleanup. `nt-process` now allocates process and thread ClientIds from
  one NT handle-shaped namespace: non-zero multiples of four shared between PIDs and TIDs. This
  matches the owner-id shape ReactOS GDI expects after masking low metadata bits. The executive no
  longer enables the old append-only per-process handle allocator; handle slots can be reused like
  NT, and the DLL registry now clears process-local file/section handle bindings after a successful
  `NtClose` so recycled handle values cannot resolve through stale DLL state. A bounded mismatch-only
  GDI handle-table observer remains to catch future owner/type regressions without normal success
  spam. Validation: `cargo fmt --all`, `cargo test -p nt-dll-registry`,
  `cargo test -p nt-process`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and boot proof
  `.tmp/boot-handle-reuse-20260808.log`. Result: the previous GDI owner mismatch, `IDI_SHELL_DOCUMENT`
  load failure, invalid image list, and allocator panic are gone. Explorer captures three register
  window messages, serves all required shell COM classes, reaches `BeginPaint`/`EndPaint` at `17/16`,
  produces 54 direct GDI returns, flushes 112 batch records, and leaves 34873 non-background
  framebuffer pixels over a full-width lower-screen span. The follow-on paint-accounting slice now
  counts explorer `BeginPaint`/`EndPaint` only after isolated win32k returns successfully, so stale
  pre-dispatch accounting is no longer treated as a completed paint. A profile materialisation slice
  also moved the per-file read scratch out of the executive bump heap; the next boot proof passed the
  previous GDI owner/icon/image-list frontier and no longer exhausted hosted sched-context objects,
  but exposed the remaining heap-lifetime wall: demand-loaded DLL syscalls were pinning transient
  PE relocation/import/path buffers under the obsolete `dll_loaded_dirty` mark. The current slice
  makes `nt-pe-loader::PeFile` store bounded section metadata inline and removes that broad DLL-load
  heap pin, so the next proof should validate shell chrome under reclaimed demand-load transients
  before moving on.
- Hosted process allocation headroom. `nt-process` now supports explicit process/thread table
  reservation, bootstrap hosted processes reserve their runtime thread sets, child hosted processes
  reserve their expected thread slots at creation, and unnamed threads no longer allocate fixed
  thread-name buffers. This keeps process identity dynamic while avoiding bump-heap growth at the
  userinit -> explorer boundary. Validation: `cargo fmt --all`, `cargo test -p nt-process`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and boot proof
  `.tmp/boot-process-reserve-20260808.log`. Result: explorer is allocated and spawned through the
  genuine userinit shell path (`NtCreateSection` -> `NtCreateProcessEx`), reaches thousands of native
  and win32k syscalls, loads the user profile hive, and passes the old allocation frontier. Review
  adjustment: the next frontier is explorer nested user-callback request routing, not process-slot
  identity or profile materialisation.
- Dynamic win32k user-callback client routing. The pump no longer carries one static
  `callback_client` identity for the whole component receive loop. Each real win32k dispatch
  registers its live client context in a bounded `(pi, tid, badge, dispatch_id)` registry, and
  `service_user_callback` resolves the callback request from win32k's header through that registry.
  This matches NT's per-thread callback boundary when one suspended callback temporarily carries
  nested dispatches for another hosted thread through the single isolated win32k component TCB.
  The obsolete `PumpChannel.callback_client` field was removed, and temporary heap-pin diagnostics
  were removed before the proof run. Validation: `cargo fmt --all`,
  `cargo test -p nt-user-callback`, `cargo test -p nt-process`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and boot proof
  `.tmp/boot-callback-client-registry-20260808.log`. Result: the previous
  `[user-callback] invalid or stale component request` / win32k-retired wall is gone, explorer
  reaches `6798` syscalls (`5120` native, `1678` win32k), and the desktop-painted proof still passes.
  Review adjustment: the new frontier is heap headroom after deeper explorer shell activity admits
  `kbswitch.exe`; the last census before panic shows `heap=6262728/6291456`, active callback depth
  `3/6`, all explorer TP worker slots busy, and then a bump-allocator panic at `alloc.rs:573`.
- Shell chrome and resource-headroom closure. The executive now right-sizes the bootstrap
  per-process handle reserve to `512` and trims spawned component heaps to `512 KiB` without changing
  the executive's own `6 MiB` heap. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and boot proof `.tmp/boot-service-heap-512k-20260808.log`. Result: services.exe dynamically admits
  and spawns a non-bootstrap `svchost.exe`, userinit/explorer still launch through the real shell
  path, `exec_explorer_shell_chrome_painted` passes with `34873` non-background pixels, the stale
  callback and allocator-panic frontiers remain gone, and `exec_vm_pool_headroom` flips green with
  `51457 KiB` root-Untyped free. Review adjustment: the current red gates are the early
  `win32k_dispatch_loop_roundtrip` and `win32k_dispatch_fault_via_reply_cap` checks; inspect their
  real transport expectations before changing later shell behavior.
- Win32k bootstrap dispatch harness closure. The user-callback client registry now admits only real
  hosted client threads (`pi`, `tid`, `badge`, and TCB present), and bootstrap-only
  `win32k_dispatch()` probes run the same component pump with `usermode_callback=false` instead of
  registering a fake callback owner. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and boot proof `.tmp/boot-win32k-bootstrap-callbackless-20260808.log`. Result:
  `win32k_dispatch_loop_roundtrip` and `win32k_dispatch_fault_via_reply_cap` pass again, the full
  executive gate is `291/291`, `exec_vm_pool_headroom` holds at `52068 KiB` root-Untyped free,
  explorer shell chrome still paints `34873` non-background pixels, and there are no stale,
  registry-full, or unregistered user-callback request warnings. Review adjustment: the shell/frontier
  gates are green; continue with the remaining structural plan items instead of adding paint-path
  scaffolding.
- Private `NtProtectVirtualMemory` and PTE-style protection overrides. `nt-address-space` now
  validates ReactOS `NtProtectVirtualMemory` protection arguments, rejects private write-copy
  protects, requires the protected range to be committed within one allocation, returns the first
  page's old effective protection, and records protection changes as per-page overrides rather than
  splitting allocation/commit extents. The executive syscall now probes/writes the real out
  parameters, resolves the target process with `PROCESS_VM_OPERATION`, remaps changed private pages
  with seL4 rights, rolls back on remap failure, and tracks override high-water in the pool census.
  Validation: `cargo test -p nt-address-space`, `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and boot proof `.tmp/boot-pte-protect-overrides-20260808.log`. Result: the full executive gate is
  `291/291`; the prior VAD-fragmentation red gate is gone with `vad=40/64`, `prot-ovr=9/128`,
  `exec_vm_pool_headroom` green, and explorer shell chrome still paints `34873` non-background
  pixels. Review adjustment: continue C1/C2 with query/protect coverage for mapped section views and
  the larger C3 move of image/data section views into the VAD/fault model.
- Real `NtQueryVirtualMemory(MemoryBasicInformation)` over live mappings. `nt-address-space` now
  encodes x64 `MEMORY_BASIC_INFORMATION` and host-tests private VAD queries for free gaps,
  reserved/committed extents, and PTE-style protection override splits. The executive removed the old
  synthetic committed-private writer and now resolves the queried process handle, probes user output,
  and composes the result from private VADs, generic section views, loaded images, mapped DLLs,
  registered client-frame mappings, KUSER, and existing spawn-created bootstrap mappings, with free
  regions bounded by the next known mapping. Validation: `cargo fmt --all`,
  `cargo test -p nt-address-space`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and boot proof `.tmp/boot-query-virtual-memory-rerun-20260808.log`. Result: the full executive
  gate is `291/291`; `exec_vm_pool_headroom` remains green with `51457 KiB` root-Untyped free,
  `vad=40/64`, `prot-ovr=9/128`, and explorer shell chrome still paints `34873` non-background
  pixels. Review adjustment: C2/C3 should remove the query-only bootstrap mapping catalog by registering those
  spawn-created pages in first-class per-process VAD/view state; mapped DLL ownership is still
  process-global in the image registry and should become per-process mapped-view state before
  cross-process virtual-memory queries are considered complete.
- C2 committed runtime mapping ownership cleanup. `nt-address-space` now has a host-tested
  fixed-capacity `VmCommittedRangeTable` for committed non-private-VAD mappings. `spawn_sec_image`
  registers stack, TEB/PEB, params/env, ACS, DESKTOPINFO, trampoline, IPCBUF, and NLS mappings at
  their real map sites. `NtQueryVirtualMemory` asks this per-process table and the static
  `SPAWN_STATIC_MEMORY_RANGES` / `MemoryBasicRange` catalog is gone. The VM pool gate now tracks
  committed-map high-water and fails on committed-map registration errors. Validation:
  `cargo fmt --all`, `cargo test -p nt-address-space`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and boot proof `.tmp/boot-committed-mapping-table-gated-rerun2-20260808.log`. Result: the full
  executive gate is `291/291`; `exec_vm_pool_headroom` remains green with `51631 KiB` root-Untyped
  free, `vad=40/64`, `committed-map=11/32`, `committed-map-fails=0`, `prot-ovr=9/128`, and explorer
  shell chrome still paints `34873` non-background pixels. Review adjustment: continue C3 by moving
  image/data section view ownership into per-process mapped-view state and then broaden
  unmap/query/protect regression gates.
- Hosted worker/Dbgk resource durability closure. Hosted worker capacity now scales to the explorer
  and RPC worker churn seen after genuine shell paint, extern-rootserver seL4 sched-context slab
  capacity is raised for the same hosted-thread stress, and Dbgk storage is precharged before
  post-desktop object creation. `nt-process` keeps reusable debug-object slot bodies with bounded
  event queues, allocation-free process-flush/reporter-drain paths, and checked `STATUS_NO_MEMORY`
  queue refusal instead of late heap growth. Validation: `cargo fmt --all`,
  `cargo test -p nt-process`, `cargo test -p nt-dll-registry`, `cargo test -p nt-kernel-exec`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and boot proof `.tmp/boot-dbgk-precharged-heap7m-20260808.log`. Result: the full executive gate is
  `291/291`; Dbgk selftests report `bits=0x1fff` with `created=5`, `exec_vm_pool_headroom` remains
  green, explorer shell chrome still paints `34873` non-background pixels, and the previous
  `sc pool exhausted`, local-worker exhaustion, and allocator-panic frontiers are gone. Review
  adjustment: continue the structural plan from C3 image/data section view ownership and A4
  remaining SCM pipe/listener coordination, rather than adding shell-specific scaffolding.
- C3 committed image/data view ownership slice. `VmCommittedRange` now has a `MEM_IMAGE`
  constructor and exact-base unregister support, and the executive records real view ownership for
  main executable images, hosted ntdll, SEC_IMAGE DLL maps, and generic data-section maps in the
  per-process committed mapping table. `NtQueryVirtualMemory` now asks that table for mapped data
  views instead of the old generic-section query branch, `NtUnmapViewOfSection` removes the
  committed view record for generic and DLL image unmaps, and map paths fail with
  `STATUS_INSUFFICIENT_RESOURCES` when the committed-view table cannot publish the view. Validation:
  `cargo fmt --all`, `cargo test -p nt-address-space`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and boot proof `.tmp/boot-committed-image-views-20260808.log`. Result: the full executive gate is
  `291/291`; `committed-map=85/128`, `committed-map-fails=0`, `exec_vm_pool_headroom` remains green,
  Dbgk remains `bits=0x1fff`, and explorer shell chrome still paints `34873` non-background pixels.
  Review adjustment: finish C3 by making image views section-granular in committed state and using
  the same mapped-view authority for fault/protect/unmap across image and data sections.

### 2026-08-09

- C3 section-granular image committed-state slice. `VmCommittedRange::image_region` now preserves an
  image allocation base across section/protection runs, and `VmCommittedRangeTable` can tear down all
  committed ranges for one allocation base. Spawn and `NtMapViewOfSection(SEC_IMAGE)` walk the
  parsed PE and publish `MEM_IMAGE` runs grouped by live page protection for main executables,
  hosted ntdll, and DLL views. Hosted ntdll is passed to spawn as a parsed PE instead of publishing a
  global image size, so the old transient whole-ntdll committed record is gone. `NtQueryVirtualMemory`
  now uses the committed mapping table for image views instead of PE/global-DLL special query
  branches, and image unmap removes the whole allocation's committed runs. Validation:
  `cargo fmt --all`, `cargo test -p nt-address-space`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and boot proof `.tmp/boot-section-granular-image-views-20260809.log`. Result: kernel specs pass,
  the full executive gate is `291/291`, `committed-map=233/512`, `committed-map-fails=0`,
  `exec_vm_pool_headroom` is green with `52331 KiB` root-Untyped free, and explorer shell chrome
  still paints `34873` non-background pixels. Review adjustment: finish C3 by routing image fault
  ownership and mapped-image protect decisions through the same mapped-view authority, then add the
  C4 overlap/decommit/protect/view-teardown regression gates.

- C3 committed image fault-owner slice. `VmCommittedRangeTable` now reports the image allocation that
  owns a faulting page, including the allocation base and the highest committed image run for that
  allocation. The executive demand-fault path uses that committed-view ownership before selecting
  the backing PE bytes, eliminating direct main-image/ntdll/DLL page-range routing in the image fault
  path. Hosted SEC_IMAGE spawn now resets the process committed-view table at fresh VSpace creation,
  which removes stale ranges left by earlier diagnostic slots without allowing duplicate
  registrations. Validation: `cargo fmt --all`, `cargo test -p nt-address-space`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and boot proof `.tmp/boot-committed-image-fault-owner-20260809-r2.log`. Result: kernel specs pass,
  the full executive gate is `291/291`, `committed-map=233/512`, `committed-map-fails=0`,
  `exec_vm_pool_headroom` is green with `52069 KiB` root-Untyped free, and explorer shell chrome
  still paints `34873` non-background pixels. Review adjustment: continue C3 with mapped data-section
  dirty/writeback ownership and mapped-image protect semantics, then close the C4 regression gates.

- C3 committed mapped-view protect slice. `VmCommittedRangeTable::protect` now validates committed
  non-private views, rejects invalid section-cache flags and private writecopy upgrades, and rewrites
  only the affected page-aligned committed runs while preserving allocation base/type ownership.
  `NtProtectVirtualMemory` routes `MEM_MAPPED` committed views through committed-view snapshots before
  falling through to private VADs, reprotects resident pages with rollback on failure, and writes the
  normalized base/size plus old protection through the real syscall outputs. Generic section faults
  now require a committed `MEM_MAPPED` owner and derive seL4 page rights from that live committed
  protection, so the old `GenericSectionView.protection` field has been removed. Validation:
  `cargo fmt --all`, `cargo test -p nt-address-space`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and boot proof `.tmp/boot-committed-mapped-protect-20260809.log`. Result: kernel specs pass,
  the full executive gate is `291/291`, `committed-map=233/512`, `committed-map-fails=0`,
  `exec_vm_pool_headroom` is green with `52244 KiB` root-Untyped free, and explorer shell chrome
  still paints `34873` non-background pixels. Review adjustment: remaining C3 work is mapped
  data-section dirty/writeback ownership plus MEM_IMAGE protect/COW semantics, then the C4
  overlap/decommit/protect/view-teardown regression gates.

- C3 generic data-section dirty/writeback slice. `nt-address-space` now has a host-tested
  `mapped_view_fault_plan` that maps write-through data views read-only on read faults and requests
  dirty promotion on real write faults. The executive generic section fault path consumes the x86
  page-fault write bit, promotes resident writable data-section pages to their committed protection
  only after a write fault, and marks overlay-backed shared section frames dirty. Generic view
  teardown now writes dirty overlay-backed section pages through `writable_fs::write`, flushes the
  file object, and clears dirty state only after the write succeeds; failures return the real status
  and leave the view mapped. `NtProtectVirtualMemory` for resident mapped views now installs the
  read-only probe protection for write-through protections so later writes still take the dirty
  path. Validation: `cargo fmt --all`, `cargo test -p nt-address-space`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and boot proof `.tmp/boot-generic-section-dirty-writeback-20260809.log`. Result: kernel specs
  pass, the full executive gate is `291/291`, `committed-map=233/512`,
  `committed-map-fails=0`, `exec_vm_pool_headroom` is green with `52419 KiB` root-Untyped free, and
  explorer shell chrome still paints `34873` non-background pixels. Review adjustment: add the
  explicit C4 regression gate that maps an overlay-backed file, dirties bytes through the mapped
  view, unmaps or flushes the view, and verifies the backing file bytes. After that, continue with
  MEM_IMAGE protect/COW semantics and the remaining overlap/decommit/protect/view-teardown gates.

- C3 MEM_IMAGE demand-protect fault slice. `nt-address-space` now has a host-tested
  `image_view_fault_plan` for `PAGE_WRITECOPY` and `PAGE_EXECUTE_WRITECOPY` image faults: read
  faults map read/execute-read, write faults request writable private protection and mark the event
  as copy-on-write. The executive image demand-fault loop now requires a committed `MEM_IMAGE`
  owner for each page it fills, derives the process mapping rights from that live committed
  protection instead of the PE fill's original section rights, refuses faulting no-access/guard
  image pages as protection failures, and only uses the shared DLL text cache when the live mapping
  remains non-writable. Validation: `cargo fmt --all`, `cargo test -p nt-address-space`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and boot proof `.tmp/boot-image-demand-protect-20260809.log`. Result: kernel specs pass, the full
  executive gate is `292/292`, `committed-map=233/512`, `committed-map-fails=0`,
  `exec_vm_pool_headroom` is green with `52410 KiB` root-Untyped free, and explorer shell chrome
  still paints `34873` non-background pixels. Review adjustment: the remaining MEM_IMAGE COW work is
  now resident shared-image shadowing, not protection lookup: record enough source ownership for
  shared DLL image mappings, promote write-copy faults to private frames, reclaim the old shared
  mapping cleanly, and add a C4 gate that proves the shared frame is not modified.

- C3 resident MEM_IMAGE COW shadowing slice. Resident shared DLL mappings now use a dedicated
  growable image map-cap ownership table instead of polluting the GUI/client frame registry or
  creating per-page source caps. The pool census measures that table as `image-mapcaps`, tracks
  `image-mapcap-fails`, and pins durable heap state whenever growth occurs. Image writecopy faults
  and `NtProtectVirtualMemory` transitions that make a resident shared image page writable now
  promote the page into a new process-owned private frame copied from the exact resident source cap,
  source frame, or shared process mapping. Nonresident writecopy image faults still fill a private
  writable frame from image bytes, and `NtUnmapViewOfSection` for image allocations tears down both
  promoted private frames and remaining shared map-cap records. The private VAD table was right-sized
  from `64` to `96` entries because the real explorer path reached `48/64` while still making
  forward progress; this keeps the `<75%` headroom gate meaningful rather than relaxing it. Validation:
  `cargo fmt --all`, `cargo test -p nt-address-space`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  `./rust-micro/scripts/run_specs.sh`, and boot proof
  `.tmp/boot-shared-image-mapcaps-vad96-20260809.log`. Result: kernel specs pass, the full executive
  gate is `292/292`, `exec_vm_pool_headroom` is green with `ut-free=52244KiB`,
  `slot-free=81170`, `frame-reg=16900/32768`, `image-mapcaps=7748`,
  `image-mapcap-fails=0`, `vad=40/96`, `committed-map=233/512`, and explorer shell chrome still
  paints `34873` non-background pixels. Review adjustment: C4 should next add an explicit image
  writecopy regression that faults or protects a shared image page writable and proves the original
  shared frame remains unchanged. Continue A4 SCM pipe/listener cleanup, B3 real video/driver
  binding, broader C4 regressions, and D1/D2 registry/filesystem authority.

- C4 image writecopy isolation gate. A post-quiesce executive selftest now seeds a real source
  frame, maps it into winlogon's live VSpace through the same shared-image map-cap ownership table
  used by resident DLL image mappings, applies the `PAGE_EXECUTE_WRITECOPY` read/write fault plans,
  and promotes the page through `vm_promote_image_cow_page`. The gate mutates the promoted private
  frame through a temporary alias and then reads the original source frame back to prove the shared
  image source was not modified. Cleanup runs through the same ownership paths as production:
  shared map-cap entries are removed, promoted private pages are torn down with
  `vm_unmap_private_page`, and the source frame is released separately. Validation:
  `cargo fmt --all`, `cargo test -p nt-address-space`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  `./rust-micro/scripts/run_specs.sh`, and boot proof
  `.tmp/boot-image-writecopy-cow-20260809.log`. Result: kernel specs pass, the full executive gate
  is `293/293`, `exec_image_writecopy_cow_isolated` passes with proof `0x1ff/0x1ff`,
  `exec_vm_pool_headroom` remains green with `ut-free=52327KiB`, `slot-free=81172`,
  `frame-reg=16900/32768`, `image-mapcaps=7749`, `image-mapcap-fails=0`, `vad=40/96`,
  `committed-map=233/512`, and explorer shell chrome still paints `34873` non-background pixels.
  Review adjustment: continue the broader C4 VAD/view teardown gates, especially overlapping VADs,
  partial decommit/release, `MEM_TOP_DOWN`, guard/no-access faults, and committed-view teardown.

- C4 committed mapped-view range teardown slice. `VmCommittedRangeTable::unregister_range` is now
  host-tested for arbitrary page-aligned committed subranges: it removes every overlapping committed
  run, preserves left and right survivors when a smaller range is removed, and normalizes the table
  without mutating state on validation/capacity failure. The executive uses this range teardown from
  generic-section `NtUnmapViewOfSection`, and that syscall now follows NT semantics by accepting any
  address inside the view rather than only the original allocation base. A protected mapped view that
  was split into multiple committed runs is therefore fully released from both the VM mappings and
  the committed `MEM_MAPPED` authority; the old exact-base wrapper was removed. Validation:
  `cargo fmt --all`, `cargo test -p nt-address-space`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  `./rust-micro/scripts/run_specs.sh`, and boot proof
  `.tmp/boot-committed-view-range-unregister-20260809.log`. Result: kernel specs pass, the full
  executive gate is `293/293`, `exec_mapped_section_writeback` and
  `exec_image_writecopy_cow_isolated` remain green, `exec_vm_pool_headroom` remains green with
  `ut-free=52153KiB`, `image-mapcaps=7749`, `image-mapcap-fails=0`, `vad=40/96`,
  `committed-map=233/512`, and explorer shell chrome still paints `34873` non-background pixels.
  Review adjustment: committed-view teardown has a direct regression now; continue C4 with broader
  VAD overlap, partial decommit/release, `MEM_TOP_DOWN`, guard/no-access, and private/mapped protect
  matrix gates, then move into D1/D2 durability authority.

- C4 mapped-view fault access slice. `nt-address-space` now exposes a host-tested
  `mapped_view_fault_access_status` verdict for generic data-section faults: guard and no-access
  mappings fail before any page map, write faults require write-through protections, and mapped
  write-copy writes currently fail with a real access violation instead of being treated as
  successful dirty writeback. The executive generic-section fault path consumes that verdict before
  resident or nonresident mapping, so read-only writes cannot demand-fill a page and loop.
  Validation: `cargo fmt --all`, `cargo test -p nt-address-space`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  `./rust-micro/scripts/run_specs.sh`, and boot proof
  `.tmp/boot-mapped-view-fault-access-20260809.log`. Result: kernel specs pass, the full executive
  gate is `293/293`, `exec_mapped_section_writeback`, `exec_image_writecopy_cow_isolated`,
  `exec_vm_pool_headroom`, and `exec_explorer_shell_chrome_painted` all remain green,
  `ut-free=52153KiB`, `image-mapcaps=7749`, `vad=40/96`, `committed-map=233/512`, and explorer
  shell chrome still paints `34873` non-background pixels. Review adjustment: next C4 work is true
  mapped data-section writecopy COW and execute/NX fault verdicts, then broader private/mapped
  protect, decommit, release, overlap, and `MEM_TOP_DOWN` matrix gates.

- C4 execute-fault access slice. `FaultAccess::Execute` is now part of the host-tested protection
  verdict path instead of being ignored by the VAD fault resolver. `nt-address-space` accepts
  executable faults only for the `PAGE_EXECUTE*` family, rejects data reads from `PAGE_EXECUTE`,
  accepts writes through `PAGE_EXECUTE_READWRITE`, keeps mapped data-section writecopy writes
  denied until true mapped COW exists, and adds an image-specific access verdict that still allows
  image writecopy COW. The executive decodes the x86 page-fault error code into
  read/write/execute access for generic section faults, and applies the image access verdict to the
  actual faulting image page before any fill or COW promotion. Validation: `cargo fmt --all`,
  `cargo test -p nt-address-space`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  `./rust-micro/scripts/run_specs.sh`, and boot proof
  `.tmp/boot-execute-fault-access-20260809.log`. Result: kernel specs pass, the full executive gate
  is `293/293`, `exec_mapped_section_writeback`, `exec_image_writecopy_cow_isolated`,
  `exec_vm_pool_headroom`, and `exec_explorer_shell_chrome_painted` all remain green,
  `ut-free=52327KiB`, `image-mapcaps=7749`, `vad=40/96`, `committed-map=233/512`, and explorer
  shell chrome still paints `34873` non-background pixels. Review adjustment: the next C4 work is
  true mapped data-section writecopy COW, then the broader private/mapped protect, decommit,
  release, overlap, and `MEM_TOP_DOWN` matrix gates.

- C4 mapped data-section writecopy COW slice. `mapped_view_fault_plan` now treats
  `PAGE_WRITECOPY` and `PAGE_EXECUTE_WRITECOPY` write faults as copy-on-write events instead of
  dirty writeback or access failure. Generic section faults promote those mappings into
  process-owned private frames copied from the exact resident source mapping or from the shared
  section frame, then register the promoted page through the normal private owner path so unmap and
  teardown do not need special identities. A post-quiesce executive selftest seeds a shared mapped
  section source frame, promotes a winlogon `PAGE_WRITECOPY` mapping, mutates the private frame, and
  verifies the source frame is unchanged through `exec_mapped_section_writecopy_cow_isolated`. The
  win32k user-callback path also gained a bounded invalid-header diagnostic that preserves the
  fail-closed request validator while making future callback regressions actionable; it did not fire
  in the green boot proof. Validation: `cargo fmt --all`, `cargo test -p nt-address-space`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  `./rust-micro/scripts/run_specs.sh`, and boot proof
  `.tmp/boot-callback-invalid-header-20260809.log`. Result: kernel specs pass, the full executive
  gate is `294/294`, `exec_mapped_section_writecopy_cow_isolated` passes with proof `0x1ff/0x1ff`,
  `exec_user_callback_real_api0_nested_roundtrip`, `exec_user_callback_dead_client_unwind`,
  `exec_win32k_transport_call_nested`, and `exec_lsa_worker_route` are green again,
  `exec_vm_pool_headroom` remains green, `committed-map=233/512`, `vad=40/96`,
  `image-mapcaps=7749`, and explorer shell chrome still paints `34873` non-background pixels.
  Review adjustment: true mapped writecopy COW is closed; continue the broader C4 regression matrix
  for private/mapped protect, partial decommit/release, overlap, `MEM_TOP_DOWN`, guard/no-access
  verdicts, then D1/D2 durability authority plus the remaining A4/B3 cleanup.

- Native syscall width audit slice. `NtFreeVirtualMemory` now probes `RegionSize` as an eight-byte
  `PSIZE_T` before reading the size and returning the normalized size, matching the declared x64 NT
  ABI and the adjacent allocate/protect syscall paths. This removes a partial-width output probe
  that could accept a pointer whose first four bytes were writable while the eight-byte read/write
  was not fully valid. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  and `./components/ntos-executive/build.sh`. Review adjustment: continue the syscall ABI-width
  audit at each native boundary, especially services still mixing dispatcher-captured arguments with
  manual stack reads.

- C4 private VAD partial release regression slice. The host VM map tests now cover middle
  `MEM_RELEASE` splitting in the private VAD policy: the left survivor keeps its original
  allocation base, the right survivor is rebased to the page after the released hole,
  `NtQueryVirtualMemory`-style basic queries report the hole as `MEM_FREE` up to the next VAD, a
  new allocation can reuse the released range, and zero-size `MEM_RELEASE` against the rebased
  right survivor tears down only that survivor. A bounded-capacity failure test also proves a middle
  release that cannot allocate the second survivor returns `STATUS_INSUFFICIENT_RESOURCES` without
  mutating the original committed allocation. Validation: `cargo fmt --all` and
  `cargo test -p nt-address-space` with `43` tests passing. Review adjustment: partial
  `MEM_RELEASE` now has host-side regression coverage; continue the C4 matrix with partial
  decommit query/protect interactions, mapped/private protect gates, overlap, `MEM_TOP_DOWN`, and
  guard/no-access behavior.

- C4 private access-permission regression slice. `VmRegionMap::permits_read` and
  `VmRegionMap::permits_write` now delegate to the same protection/access verdict used by private
  fault resolution, so private `PAGE_EXECUTE` pages are not treated as data-readable and guarded
  pages deny both read and write access before `NtReadVirtualMemory`/`NtWriteVirtualMemory` try to
  copy bytes. Host tests now cover `PAGE_NOACCESS`, `PAGE_EXECUTE`, `PAGE_EXECUTE_READ`,
  `PAGE_EXECUTE_READWRITE`, `PAGE_READWRITE | PAGE_GUARD`, and unmapped pages through the
  committed-access helpers. Validation: `cargo fmt --all`, `cargo test -p nt-address-space`, and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: execute-only/guarded private access is pinned; continue C4 with partial
  decommit query/protect interactions, mapped/private protect rollback gates, overlap, and
  `MEM_TOP_DOWN` behavior.

- C4 private VAD partial decommit regression slice. Host VM map tests now cover the private
  `MEM_DECOMMIT` path after a protected page range has overrides: the decommit clears affected
  page-protection overrides, `NtQueryVirtualMemory`-style basic queries report the decommitted span
  as `MEM_RESERVE` with no active protection, `NtProtectVirtualMemory` over a range crossing the
  reserved hole returns `STATUS_NOT_COMMITTED`, and recommitting a subpage installs the requested
  protection without reviving stale overrides. A bounded-capacity failure test also proves a middle
  decommit split that cannot be represented returns `STATUS_INSUFFICIENT_RESOURCES` without
  mutating the original committed allocation. Validation: `cargo fmt --all` and
  `cargo test -p nt-address-space` with `45` tests passing. Review adjustment: private partial
  decommit query/protect/recommit behavior is pinned; continue C4 with mapped/private protect
  rollback, overlap, and `MEM_TOP_DOWN` gates.

- C4 protect rollback regression slice. Host VM map tests now prove failed protection rewrites are
  transactional in both private and committed-mapping authorities. Private `NtProtectVirtualMemory`
  override exhaustion over more than `VM_PROTECTION_OVERRIDE_CAPACITY` pages returns
  `STATUS_INSUFFICIENT_RESOURCES` with no partial overrides and the original write access intact.
  `VmCommittedRangeTable::protect` likewise preserves a single mapped range when a middle protect
  would need more split records than the table can hold. Validation: `cargo fmt --all` and
  `cargo test -p nt-address-space` with `47` tests passing. Review adjustment: mapped/private
  protect capacity rollback is pinned host-side; continue C4 with overlap and `MEM_TOP_DOWN`
  placement/query gates before moving back to A4/B3 or D1/D2.

- C4 `MEM_TOP_DOWN` placement regression slice. The private VAD policy now has host coverage for
  top-down placement through occupied high ranges: allocation skips a committed range at the top of
  the user arena, chooses the highest allocation-granularity gap below it, repeats into the next
  high gap, and `query_basic` reports the free span after a top-down one-page allocation as bounded
  by the next VAD. Validation: `cargo fmt --all` and `cargo test -p nt-address-space` with `48`
  tests passing. Review adjustment: top-down placement/query behavior is pinned host-side; continue
  C4 with overlap and cross-authority query/protect gates, then return to A4/B3 or D1/D2.

- C4 cross-authority overlap guard slice. `VmCommittedRangeTable::overlaps_range` is now
  host-tested for interior overlap, partial boundary overlap, adjacent free gaps, and invalid
  unaligned/empty inputs. The executive exposes the same predicate for per-process committed mapping
  tables and makes `NtAllocateVirtualMemory` plus generic data-section `NtMapViewOfSection` reject a
  selected private VAD range before publication when that range is already owned by a committed
  mapping, live KUSER alias, or registered client frame outside the existing private VAD authority.
  Registered-frame overlap checking is ownership-aware so ordinary private recommit over existing
  VAD-backed frames is not rejected, while unowned registered mappings still block private/generic
  VAD publication. Validation: `cargo fmt --all`, `cargo test -p nt-address-space` with `49` tests
  passing, and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: the remaining C4 overlap work is teaching auto-placement to retry around
  fixed-authority ranges, or replacing that with a live executive gate proving the selected arenas
  cannot collide; otherwise move back to A4/B3 or D1/D2.

- C4 cross-authority auto-placement retry slice. `VmCommittedRangeTable::first_overlap_range` now
  exposes the first committed fixed range blocking a selected span, and `VmRegionMap::allocate_between`
  gives the executive a host-tested lower/upper cursor for retrying ordinary bottom-up and
  `MEM_TOP_DOWN` placement without duplicating VAD gap search. `NtAllocateVirtualMemory` and generic
  data-section `NtMapViewOfSection` now route through a bounded retry helper: explicit-base callers
  still fail with `STATUS_CONFLICTING_ADDRESSES`, while auto-placement retries below or above the
  first fixed-authority overlap before publishing a private VAD or mapped-view record. The old
  committed-mapping boolean helper was removed in favor of first-overlap selection. Validation:
  `cargo fmt --all`, `cargo test -p nt-address-space` with `50` tests passing, and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: add a live executive/boot proof that exercises or at least guards the
  cross-authority retry path; then resume A4 SCM pipe/listener cleanup, B3 real video miniport
  hosting, or D1/D2 mutable registry/filesystem authority.

- C4 cross-authority placement live proof slice. The executive gate now includes
  `exec_vm_cross_authority_placement_retry`, a live selftest that creates separate private-VAD and
  committed-fixed authorities and proves bottom-up auto-placement skips upward, `MEM_TOP_DOWN`
  skips downward, explicit-base collisions remain conflicting, and the selected retry gaps are clean.
  Boot proof `.tmp/boot-cross-authority-placement-retry-20260809.log` is fully green at `295/295`:
  the new gate passes with proof `0x0f/0x0f`, `exec_vm_pool_headroom` remains green with
  `52240 KiB` root-Untyped free, `committed-map=233/512`, `committed-map-fails=0`,
  `exec_explorer_shell_chrome_painted` passes, and explorer shell chrome still paints `34873`
  non-background pixels. Validation also includes `cargo fmt --all`,
  `cargo test -p nt-address-space` with `50` tests passing, and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: C4 overlap/placement is now guarded host-side and live; resume A4 SCM
  pipe/listener cleanup, B3 real video miniport hosting, or D1/D2 mutable registry/filesystem
  authority.

- D1 `NtSaveKey` root-hive save slice. The owned ntdll ABI already exported `NtSaveKey`, but the
  typed native dispatcher and executive table did not model SSN 215. `NativeService::NtSaveKey` now
  carries the canonical two-argument contract, the executive registers SSN 215, enforces
  `SeBackupPrivilege`, validates the target file as a writable overlay FILE_OBJECT, resolves the
  source key with `KEY_READ`, and writes a mounted root hive's real borrowed `regf` bytes to the
  caller-opened file with exact EOF and flush. Non-root subkey saves, volatile/overlay keys, and
  non-writable file backends fail visibly until the CM/Hive Manager owns a subtree serializer and
  persistent store. Validation: `cargo fmt --all`, `cargo test -p nt-syscall`,
  `cargo test -p nt-hive-regf`, and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: continue D1 by auditing remaining mutable filesystem writeback/rename/delete
  paths, or move into D2/D3 by making the host-tested CM/Hive Manager the live mutable hive authority
  instead of executive-local overlay state.

- D1 writable-overlay rename slice. `nt-fs` now implements `FileRenameInformation` against real
  MemFs node identity instead of returning `STATUS_NOT_IMPLEMENTED`: absolute writable-volume
  targets, relative `RootDirectory` handles, same-node case rename, no-replace collisions,
  replacement of existing files, directory-cycle rejection, and delete-on-close after rename are all
  real storage operations. The executive `NtSetInformationFile` path now copies variable-sized
  overlay rename structures through the existing bounded 64 KiB scratch buffer, translates the
  caller's process-local `RootDirectory` handle into the writable FS file-object id before invoking
  the storage layer, and marks the writable overlay dirty only after a successful set-information
  operation. Validation: `cargo fmt --all`, `cargo test -p nt-fs`, and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: D1's rename/delete/writeback audit is now materially smaller; continue D2/D3
  by moving mutable hive state into the CM/Hive Manager authority and adding explicit flush/reboot
  persistence proofs, or resume A4/B3 structural cleanup.

- D2 REGF-to-mutable-hive bridge slice. `nt-hive-regf` now owns a clean layering adapter,
  `import_regf_into_hive`, that copies a real parsed `regf` tree into the `nt-hive-core::Hive`
  mutable cell arena without making `nt-hive-core` depend on the disk-format parser. The imported
  hive is finalized with `Hive::finish_clean_import`, so construction from already-persistent hive
  bytes does not appear as dirty runtime state and later `HiveManager` mutations start at sequence
  one. Host tests import the existing synthetic services/Enum/ServiceGroupOrder REGF fixture,
  validate values through the mutable `Hive` API, checkpoint it through `HiveManager`, and boot it
  back with the same data and a clean dirty set. Validation: `cargo fmt --all`,
  `cargo test -p nt-hive-core`, `cargo test -p nt-hive-regf`, and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: the next D2 slice can introduce an executive-side mutable hive mount table in
  parallel with the existing `RegfHive` selectors, then migrate `NtCreateKey`/`NtSetValueKey` off
  `RegistryOverlay` one mounted hive at a time.

- D2 mutable hive namespace slice. `nt-hive-core` now exposes `MutableHiveSet`, an owned mutable
  hive namespace that combines a `HiveMountTable` with the mounted `Hive` arenas themselves. It can
  mount and unmount hives, resolve full NT registry paths through the existing
  `CurrentControlSet -> ControlSet001` alias, create keys, set/query values, and preserve longest
  mount-root selection for machine/user hive boundaries. Host tests prove a SYSTEM service key is
  created through the alias, a SOFTWARE key lands in the SOFTWARE hive instead of SYSTEM, unmount
  detaches only that hive, and the remaining SYSTEM mount stays live. Validation: `cargo fmt --all`,
  `cargo test -p nt-hive-core`, `cargo test -p nt-hive-regf`, and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: the executive now has both prerequisites for the next migration: importing
  real `regf` bytes into clean mutable hives, and resolving/mutating those hives by NT registry path.
  The next D2 work should instantiate this beside the current `RegfHive`/`RegistryOverlay` state and
  move one syscall write path onto it.

- D3 file-backed hive image atomicity slice. `nt-fs::NtFileHiveIoProvider` now honors the
  `HiveManager` primary-image atomic-write contract by checkpointing to a temporary sibling and
  installing it through the real `FileRenameInformation` replace path, instead of overwriting the
  live hive image in place. Provider status now reports real `.LOG` length, and the obsolete inert
  `nt-hive-core::NtFileHiveIoProvider` placeholder plus its NotSupported test/doc language have
  been removed so the only `NtFileHiveIoProvider` in the tree is the filesystem-backed one. Host
  tests prove replace-install leaves no temp file, log length is observable/truncatable, and a temp
  write failure preserves the previously committed hive image. Validation: `cargo fmt --all`,
  `cargo test -p nt-fs` with `42` tests passing, `cargo test -p nt-hive-core` with `31` library
  tests plus `4` `gen_hive` tests passing, `cargo test -p nt-hive-regf` with `11` tests passing, and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: finish D2 by instantiating `MutableHiveSet` beside the current executive
  `RegfHive`/`RegistryOverlay` state and migrating one registry write syscall onto the live hive
  authority; D3 still needs explicit system/user hive and writable-overlay reboot proofs in the
  executive.

- D2 executive mutable hive namespace slice. `ExecNtHandler` now owns a live
  `nt_hive_core::MutableHiveSet` mounted at the same NT registry roots as the existing borrowed
  `RegfHive` selectors. Boot imports mirror SYSTEM, SOFTWARE, SECURITY, SAM, and `.Default` into
  clean mutable hive arenas; `NtLoadKey` imports mounted user hives into the same namespace and
  `NtUnloadKey` unmounts them. `registry_value` now reads mounted-hive values through the mutable
  authority by full NT path before falling back to the borrowed `RegfHive` navigator, while overlay
  tombstone/shadow semantics remain intact. Validation: `cargo fmt --all`,
  `cargo test -p nt-hive-regf` with `11` tests passing, `cargo test -p nt-hive-core` with `31`
  library tests plus `4` `gen_hive` tests passing, and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: the next D2 slice should migrate `NtCreateKey`/`NtSetValueKey` for one mounted
  hive root to mutate `MutableHiveSet` directly and retire the corresponding overlay shadow path.

- D2 mutable hive base-read completion slice. The executive's merged registry read helpers now use
  `MutableHiveSet` as the mounted-hive base for value enumeration, `NtQueryKey` statistics, and
  subkey enumeration, not just direct `NtQueryValueKey` name reads. Overlay tombstones and overlay
  value shadows are still applied first, and the borrowed `RegfHive` reader remains only as a
  fallback when a mounted hive has not yet been mirrored. Validation: `cargo fmt --all` and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: the next D2 slice can now give newly mutable-created keys a handle identity and
  move `NtCreateKey`/`NtSetValueKey` for a selected mounted hive root off `RegistryOverlay`, because
  the main query/enumeration paths already see the mutable authority as their base view.

- D2 registry key security metadata slice. `nt-security` now captures native absolute or
  self-relative `SECURITY_DESCRIPTOR`s into validated self-relative byte descriptors, can query
  selected owner/group/DACL/SACL components, and can merge `NtSetSecurityObject` updates while
  preserving unselected components and DACL/SACL protection bits. `nt-hive-core` stores key security
  descriptors as key metadata in schema-2 mutable hive images while remaining able to decode schema-1
  images, and the volatile overlay carries descriptor metadata separately from values. The executive
  now registers `NtQuerySecurityObject` at SSN 176, removes the no-op `NtSetSecurityObject` fallback,
  captures `OBJECT_ATTRIBUTES.SecurityDescriptor` for newly-created keys, enforces
  `READ_CONTROL`/`WRITE_DAC`/`WRITE_OWNER`/`ACCESS_SYSTEM_SECURITY` on registry handles, and serves
  real query/set descriptor bytes from mounted mutable hives or volatile overlay keys. Validation:
  `cargo fmt --all`, `cargo test -p nt-security`, `cargo test -p nt-hive-core`,
  `cargo test -p nt-syscall`, and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: D2 security/class metadata is now materially closed for live registry keys; the
  remaining D2 audit should look for persistent paths still forced through `RegistryOverlay`, then
  move to D3 explicit flush/reboot proofs.

- D2 mounted setup-state overlay reduction slice. The executive no longer provisions
  `HKLM\SYSTEM\Setup` normal-boot values or
  `HKU\.DEFAULT\Control Panel\International\Locale` through `RegistryOverlay`. Both paths now use a
  path-addressed mutable-hive setter and mark `mutable_hives_dirty`, so these installed-system setup
  writes live in the same mounted hive authority as ordinary `NtSetValueKey` writes. The HARDWARE
  hive remains overlay-backed because it is explicitly volatile runtime registry state. Validation:
  `cargo fmt --all` and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: continue the D2 overlay audit with SOFTWARE/HKCR shell COM seeding and any
  remaining setup/profile provisioning, then move to D3 flush/reboot proofs once persistent overlay
  writes are gone.

- D2 shell COM mutable-hive seeding slice. The ReactOS `.rgs` parser in `nt-hive-core` is now
  decoupled from `RegistryOverlay` behind a host-tested seed target, with public entry points for
  both volatile overlay use and mounted `MutableHiveSet` use. The executive now provisions explorer's
  HKCR shell COM classes into `\Registry\Machine\Software\Classes` through the mounted mutable
  SOFTWARE hive and marks `mutable_hives_dirty` when the expected class mask materializes; it no
  longer creates SOFTWARE/HKCR overlay shadows for this installed-system setup state. Validation:
  `cargo fmt --all`, `cargo test -p nt-hive-core`, and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: the known setup/class persistent provisioning paths are now mutable-hive owned.
  Finish D2 with a focused audit for any remaining non-volatile overlay writes, then start D3
  explicit flush/reboot persistence proofs.

- D3 flush classification starter slice. `NtFlushKey` no longer documents or proves the old
  overlay-only registry write model. The syscall now classifies every resolved flush target as
  volatile overlay or mounted mutable hive, records mutable flushes and the dirty-cell count observed
  on the mounted hive, and keeps bad handles on the real handle-resolution failure path. The
  `exec_reg_flush_key_serviced` gate now expects the ActiveComputerName handoff to flush a mutable
  SYSTEM-hive key, while volatile overlay flushes stay visible as D4 cleanup evidence. Validation
  `cargo fmt --all` and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: the next D3 work is the durable backing decision for mutable hive checkpoints:
  either add a real `regf` writer or make loaded hives boot from the `nt-hive-core` image/log
  provider before any syscall claims reboot persistence.

- D3 mutable hive checkpoint/load slice. `NtSaveKey` now writes a live `nt-hive-core` image for
  dynamically loaded `NtLoadKey` profile hive roots instead of saving stale borrowed `regf` bytes
  after runtime mutation. Boot hive roots deliberately retain their borrowed `regf` save backing
  until D3 adds a real checkpoint provider for SYSTEM/SOFTWARE/SAM/SECURITY/`.Default`; this avoids
  claiming reboot persistence for imported boot-hive mirrors before the backing strategy exists.
  `NtLoadKey` still accepts ordinary ReactOS/Windows `regf` hives, but also accepts saved
  `nt-hive-core` images and mounts them as mutable-only hives under `HKEY_USERS\<SID>`. The dynamic
  mount table now distinguishes borrowed-regf mounts from mutable-only checkpoint mounts, while
  hosted-process opens continue to resolve through `MutableHiveSet` before any borrowed fallback.
  Validation `cargo fmt --all` and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: this closes the save/load format loop for dynamically loaded profile hives; D3
  still needs a natural boot/reboot proof for that path and a boot-hive backing strategy before
  SYSTEM/SOFTWARE/SAM/SECURITY persistence can be claimed end to end.

- D2/D3 USER object security bridge. The current boot frontier was no longer the profile hive
  contents: `.tmp/boot-hive-childids-20260810.log` proved the staged `Default User\ntuser.dat` image
  parses and mounts, while winlogon failed later in `AllowAccessOnSession` when
  `NtSetSecurityObject` returned `STATUS_OBJECT_TYPE_MISMATCH` for a win32k USER object handle. The
  active fix gives modeled USER objects bounded self-relative security descriptor storage, exposes
  their granted-access metadata through the win32k subsystem boundary, routes native
  query/set-security calls by real object identity before registry fallback, and updates the mutable
  SOFTWARE proof counter to count mounted-hive reads served from `MutableHiveSet`. Validation:
  `cargo fmt --all`, `cargo test -p nt-object-manager`, and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Boot validation `.tmp/boot-userobj-security-20260810.log`: `exec_winlogon_user_shell_activated`,
  `exec_userinit_process_spawned`, `exec_explorer_process_spawned`,
  `exec_explorer_user_callbacks_redirected`, `exec_explorer_wndproc_installed_by_client`, and
  `exec_explorer_shell_com_classes_served` now pass. The framebuffer readback found `104517`
  non-background pixels with saturated unique color evidence, but `exec_explorer_shell_chrome_painted`
  still failed because explorer `BeginPaint`/`EndPaint` accounting was `0/0`; next work should find
  the real paint-dispatch or update-region boundary that keeps shell chrome from proving through the
  normal win32k paint path.

- Win32k queue-event wait bridge. The desktop wait frontier moved past the `desktop.cpp:193`
  failure and back to a genuine win32k desktop paint proof. Hosted THREADINFO setup now seeds the ReactOS
  `hEventQueueClient`/`pEventQueueServer` pair with a local synchronization event, so
  `NtUserxMsqSetWakeMask` can return a waitable message-queue event. Native wait-object resolution
  now checks process-local process/thread/file handles first, probes dispatcher events/semaphores/
  mutants without treating a missing process handle as final, then resolves win32k event handles by
  object identity. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  and boot proof `.tmp/boot-wait-object-win32k-event-20260810.log`, which ends with `SUCCESS -- the
  ReactOS stack booted and the win32k desktop painted (0x003a6ea5)`. Review adjustment: the immediate
  wait/dispatcher blocker is closed without adding a paint-accounting fallback; the later
  `.tmp/boot-no-pipe-relisten-caps-20260810.log` full gate still shows explorer shell chrome red at
  `BeginPaint`/`EndPaint=0/0`, so keep the shell-paint work honest.

- A4 pipe-listener cap cleanup. The executive no longer returns process/name-scoped
  `STATUS_PIPE_NOT_AVAILABLE` for `services.exe` `\ntsvcs` or `lsass.exe` `\lsarpc` re-listen loops.
  Those caps were old quiesce scaffolding; the current boot reaches the gate through the generic
  pipe-listen, pipe-park, and process quiesce machinery without those injected failures. The
  object-namespace growth path now marks dynamic namespace backing-store growth as durable and pins
  the service heap mark on the next loop tick, so namespace expansion is not invalidated by the
  bump-heap reset. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  and boot proof `.tmp/boot-no-pipe-relisten-caps-20260810.log`, which reaches `[microtest done]`
  at `290/295`, with no `re-create cap` messages and with `exec_win32k_desktop_painted`,
  `exec_desktop_shell_frontier`, `exec_winlogon_user_shell_activated`, `exec_userinit_process_spawned`,
  and `exec_explorer_process_spawned` passing. Review adjustment: A4 has one less hardcoded
  pipe/listener boundary; current frontier is real explorer shell paint plus VM headroom after durable
  namespace growth.

- D3 dynamic profile-hive flush slice. `NtFlushKey` now checkpoints dirty dynamically loaded profile
  hives by encoding the live `MutableHiveSet` hive and atomically replacing the source `ntuser.dat`
  through the writable filesystem's temp-file plus `FileRenameInformation` path. `NtLoadKey` no
  longer reattaches hidden overlay keys on remount; the overlay crate's detached-key model now keeps
  volatile overlay state hidden until an explicit new create reuses an empty slot. The profile
  `ntuser.dat` proof was updated to expect the post-`CreateUserHive` checkpoint image after
  `RegFlushKey`, not byte identity with the original copied source. Validation: `cargo fmt --all`,
  `cargo test -p nt-hive-core`, `cargo test -p nt-fs`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  and boot proof `.tmp/boot-dynamic-hive-flush-gate-20260810.log`. Result: `NtFlushKey` writes a
  `130708B` dynamic hive checkpoint with `17` dirty cells; the first `NtLoadKey` reads `130674B`,
  `NtUnloadKey` detaches the mount, the second `NtLoadKey` reads `130708B`, and both
  `exec_profile_ntuser_dat_present` and `exec_ntloadkey_serviced` pass. Review adjustment: dynamic
  profile hive flush/remount is closed for this path; D3 still needs boot/system hive backing and
  explicit reboot persistence proofs.

- Win32k GUI queue-event wait slice. The component pump can now park an empty blocking GUI
  `GetMessage` on the calling thread's real win32k queue event, steal a reply cap, and redrive
  `PeekMessage`/`GetMessage` when win32k signals that queue event. Win32k local event signals are
  recorded with their event bodies instead of a single pending bit, so multiple queue events can
  wake their own waiters. This is generic queue-event wait machinery and does not synthesize shell
  messages. Validation is included in `.tmp/boot-dynamic-hive-flush-gate-20260810.log`, which still
  reaches the desktop at `291/295` with no callback, pipe-listener, or win32k transport regression.
  Review adjustment: the shell frontier remains honest: explorer still has direct GDI returns and a
  broad non-background framebuffer span, but `BeginPaint`/`EndPaint` remains `0/0`; continue at the
  real explorer update-region/paint boundary.

- D2 keyboard-layout proof cleanup. `exec_kbd_layout_opened` no longer depends on the old
  keyboard-specific `NtOpenKey` arm, which the common mounted-registry path now bypasses. Successful
  opens of `HKLM\SYSTEM\CurrentControlSet\Control\Keyboard Layouts\<KLID>` are counted from the
  shared overlay/mutable/base registry authority for both mutable and borrowed SYSTEM hives, and the
  stale manual branch was removed. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  and partial boot logs `.tmp/boot-kbd-layout-common-registry-rerun-20260810.log` /
  `.tmp/boot-kbd-layout-common-registry-final-20260810.log`, both of which reached the real
  `NtUserLoadKeyboardLayoutEx` path and hosted `kbdus.dll` before the QEMU lane was externally
  SIGTERM'd. Review adjustment: rerun one uncontended full gate and require
  `exec_kbd_layout_opened` to flip green before treating that frontier item as closed.

- D3 writable system-config subtree slice. The writable filesystem can now mount
  `reactos\system32\config` through the same prefix mechanism as profiles, provision staged
  installed config files by folded volume-relative paths, and handle EventLog-style sparse file
  growth without materializing multi-megabyte zero buffers. The executive copies the staged
  `system32\config` tree into the writable volume on mount and records real SYSTEM/SOFTWARE hive
  content checks. Validation: `cargo fmt --all`, `cargo test -p nt-fs`, and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Boot attempts in `.tmp/boot-kbd-layout-common-registry-*.log` were not accepted as proof because
  competing Codex-owned QEMU lanes were holding or killing the disk image. Review adjustment: the
  next clean boot should confirm EventLog creates/writes its `.Evt` files through the writable
  config subtree and then continue D3 boot/system hive persistence proofs.

- A4/NPFS root wait and owner-quiesce slice. Root `FSCTL_PIPE_WAIT` now parses the full
  `FILE_PIPE_WAIT_FOR_BUFFER`, returns success for an already armed same-name async listen, returns
  honest `STATUS_OBJECT_NAME_NOT_FOUND` when no pipe FCB/name is known, and otherwise parks a bounded
  waiter with NT-style relative/absolute/unbounded timeout handling. Name-wait completions are exact,
  not wildcarded, and thread cancellation/timer wake releases retained reply caps. `NtOpenFile`
  now clears `*FileHandle` on failed paths so user-mode retry loops do not observe stale handles.
  Validation: `cargo fmt --all`, `git diff --check`, `cargo test -p nt-io-manager`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  and full boot `.tmp/boot-openfile-pipe-wait-20260810-092820.log`. The boot rebuilt all artifacts
  and timed out cleanly with `RUN_STATUS=124` at the real EventLog/SCM frontier:
  `services.exe` probed `\pipe\EventLog` and got `STATUS_OBJECT_NAME_NOT_FOUND` after EventLog had
  already connected to SCM and exchanged pipe/RPC traffic. Review adjustment: next work should
  instrument/repair EventLog `ServiceMain` progress into `ServiceInit`/`RpcThreadRoutine` so the
  genuine `\pipe\EventLog` server endpoint appears before SCM's event logging client bind.

- A4 hosted executable record authority slice. Hosted executable image-open/section/spawn records are
  now sized independently from `MAX_PI` because they are retained handle-lifetime/publication
  records, not live process slots. Dynamic process admission remains bounded by `MAX_PI`, but
  service churn can no longer consume the entire image-record table before winlogon reaches the real
  shell path. Hosted executable opens now fail loudly with NT status when the record cannot be
  installed, clear `FileHandle`/IOSB on failure, and only fall through to the read-only disk file
  fallback after hosted executable recording has either succeeded or been ruled out. Validation:
  `cargo fmt --all`, `cargo test -p nt-exe-image`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  and partial boot `.tmp/boot-hosted-exe-record-cap-rerun-20260810.log`. Result: the old
  `CreateProcessW failed, last error: 193` userinit frontier is gone; winlogon opens/sections and
  spawns `userinit.exe`, userinit runs win32k syscalls, and `explorer.exe` opens/sections far enough
  to run real win32k traffic. The run was interrupted after a repeated deadman, so the next accepted
  proof still needs a clean harness exit. Review adjustment: this frontier was superseded by the
  target-scoped dynamic executable slice below; do not add service/executable fallbacks.

- A4 target-scoped dynamic executable slice. Hosted executable catalog entries now distinguish
  repeated dynamic executable launches by exact `SpawnTarget` instead of executable leaf, and the
  image table preserves that target from `NtOpenFile` through SEC_IMAGE section creation and
  `NtCreateProcessEx`. A spawned dynamic identity is no longer reused for a subsequent child image
  open, while an unspawned identity remains idempotent for retry paths. Validation: `cargo fmt
  --all`, `cargo test -p nt-exe-image`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, `git diff --check`, and boot
  `.tmp/boot-dynamic-probe-instance-scoped-rerun-20260810.log`. Result: repeated SCM
  `svchost.exe` launches admit and spawn fresh `pi=8`, `pi=10`, `pi=12`, and `pi=13` identities, and
  `wlansvc.exe`/`spoolsv.exe` also launch through the same generic path. The old
  `BasePushProcessParameters`/`STATUS_INVALID_HANDLE` wall is gone. Review adjustment: the immediate
  A4 frontier is now service process GUI/IPC mechanics: `spoolsv.exe` reaches win32k, fails
  default desktop/winsta thread setup with `STATUS_INSUFFICIENT_RESOURCES`, SCM reports
  `ConnectNamedPipe failed (Error 1450)`, and the run then parks.

- A4 growable async-listen slice. The pipe wait/listen model no longer has a tiny global cap for
  pending overlapped `FSCTL_PIPE_LISTEN` IRPs. `AsyncListenTable` keeps its deterministic
  name-scoped completion and re-arm semantics, but grows from an initial reservation instead of
  returning `STATUS_INSUFFICIENT_RESOURCES` once eight RPC/service listeners are armed. Thread
  cancellation now walks the whole growable table and releases every retained server FILE_OBJECT.
  Validation: `cargo fmt --all`, `cargo test -p nt-io-manager async_listen`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, and `git diff --check`. Live boot
  `.tmp/boot-growable-async-listens-20260810.log` shows no repeat of the previous SCM
  `ConnectNamedPipe failed (Error 1450)` edge; shell dependency loading continues and the active
  blocker moves to `services.exe` parking on syscall `0x18` after `\pipe\ntsvcs` churn.

- A4 service desktop/object-manager slice. Win32k Ob desktop lookup now reopens an existing desktop
  by leaf name under the exact root window-station handle/body, so `Service-<LUID>$\Default` behaves
  like a real object-manager child instead of allocating duplicate desktop bodies. Service window
  stations are tracked per token authentication ID without replacing the cached interactive WinSta0,
  and noninteractive process desktop binding is left to ReactOS `InitThreadCallback` instead of
  being inherited from the interactive station. Validation: `cargo fmt --all`,
  `cargo test -p nt-object-manager`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, `git diff --check`, and boot
  `.tmp/boot-service-desktop-cache-20260810.log`. Result: the previous service desktop/winsta
  `STATUS_INSUFFICIENT_RESOURCES` failure is gone, `exec_services_win32k_connect` passes, and the
  run cleanly reaches the base desktop proof again. Review adjustment: continue A4 at the real
  LSA/SAM RPC request and ObjectDirectory query gates; do not reintroduce service/executable
  fallbacks.

- A4 pipe cancellation slice. `NtCancelIoFile` now follows the ReactOS IoMgr contract for the pipe
  IRP classes modeled by the executive: the syscall probes its caller IOSB, references the target
  file handle without requiring file access rights, cancels only current-thread IRPs for that file,
  and lets each cancelled operation complete through its original IOSB, event, file-object signal
  state, reply cap, and IOCP packet as applicable. `PipeWaiterTable`, `AsyncListenTable`, and
  `PipeNameWaiterTable` have file/root-handle scoped cancellation helpers, and successful async
  listens now use the same `post_file_completion` path as cancelled listens. Validation: `cargo fmt
  --all`, `cargo test -p nt-io-manager cancel_thread -- --nocapture`, `cargo test -p nt-syscall
  -- --nocapture`, `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `git diff --check`, and boot `.tmp/boot-ntcanceliofile-20260810.log`.
  Result: the previous `services.exe` unhandled syscall `0x18` park is gone, the live trace records
  a real `[nt-cancel-io-file] ... cancelled=1`, and the harness reports
  `SUCCESS -- the ReactOS stack booted and the win32k desktop painted (0x003a6ea5)`. Review
  adjustment: the next useful A4 work is generic service-control pipe timing/IPC after the WLAN
  service timeout, with explorer shell chrome proofs rerun once service startup is stable again.

- A4 pipe fid-name authority slice. The service-control timeout root cause in
  `.tmp/boot-ntcanceliofile-20260810.log` was not a missing pipe fallback; it was stale internal
  authority. The fixed 32-entry fid-name table could drop later server/client pipe fids, and the
  async-listen name match treated missing hash metadata (`0`) as a wildcard. That let a client
  connect for `\net\NtControlPipe5` complete an unrelated listen while the real SCM control-pipe
  server fid stayed pending until timeout/cancel. `PipeFidNameTable` is now growable and
  host-tested, zero hashes are rejected/non-matching, endpoint create/open records pipe leaf names
  before returning handles, listen arming fails honestly if metadata is missing, and mappings are
  removed only after the final file-completion reference is released. Validation so far:
  `cargo fmt --all`, `cargo test -p nt-io-manager pipe_fid_name -- --nocapture`,
  `cargo test -p nt-io-manager async_listen -- --nocapture`,
  `cargo test -p nt-io-manager -- --nocapture`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, and `git diff --check`.
  Serialized boot proof in `.tmp/boot-current-headless-20260810.log` reaches
  `SUCCESS ... win32k desktop painted (0x003a6ea5)`; the late `\net\NtControlPipe5` wait is
  `armed=1 known=1`, wakes only exact hash-matched fids `0e814c80`/`0e814c81`, and does not emit
  the previous `known=0`, timeout, cancel, service `Error 1053`, or unhandled-syscall signatures.

- A4 desktop runner contention preflight. A reported `./run.sh --desktop` failure was reproduced as
  host-runner contention, not accepted as a kernel desktop-paint regression: an existing headless
  `./run.sh`/QEMU lane was still holding `rust-micro/.tmp/disk.img`, so a second desktop lane could
  not own the boot image. The active log `.tmp/run-headless-baseline-20260810-182238.log` had only
  reached the normal post-`\pipe\ntsvcs` RPC/TEB sequence before it was manually stopped, while the
  prior desktop log `.tmp/run-desktop-shell-20260810-181820.log` had already reached the real
  win32k base desktop framebuffer proof at `px0=0x003a6ea5`. The root launcher now checks the
  actual boot image before rebuilding and again before QEMU launch, and fails loudly with the owning
  process list instead of starting a competing lane. Review adjustment: rerun exactly one
  uncontended boot lane for the next accepted proof, then continue toward explorer shell chrome
  pixels from the genuine desktop-paint path.

- A4 dynamic RPC worker role slice. The first uncontended post-I2 boot reached the real desktop
  background and service startup, but it became silent after winlogon connected to `\??\pipe\ntsvcs`;
  explorer still had `ssn-hist explorer total=0`. The next code slice removes another fixed-worker
  boundary before retrying that boot: SCM/LSA per-connection workers spawned through generic TP
  worker slots are now registered as slot-scoped RPC worker roles, service-loop routing and pipe PDU
  accounting classify them from runtime metadata, and win32k callback metadata preserves those roles.
  Validation so far: `cargo fmt --all`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, and `git diff --check`.
  Review adjustment: the next single boot should show dynamic `role=scm-rpc` workers in the late
  `\pipe\ntsvcs` path; if the log still parks there, debug the real service-control wait/reply edge
  from that role-aware trace.

- A4 fixed RPC worker route deletion. The stricter follow-up removed the old SCM/LSA fixed
  per-connection worker badges, dedicated VA windows, and dedicated spawn helpers. Those workers now
  have only the generic same-process worker route, with role metadata assigned from the listener
  caller and persisted as `ScmWorkerSlot`/`LsaWorkerSlot`; the generic high-slot mapping covers the
  configured dynamic worker slots directly. Validation: `cargo fmt --all`, `cargo check
  --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, and
  `git diff --check`. Review adjustment: rerun exactly one uncontended boot and use the dynamic
  worker trace to decide whether the next shell frontier is SCM pipe liveness, service-control RPC,
  or explorer chrome paint.

- J1/J2 SEC_IMAGE COW and native SEH slice. PE image pages now carry NT-style SEC_IMAGE allocation
  protections, including shared read/write/execute pages and non-shared write-copy pages. User-fault
  and kernel-copyout COW promotion preserve process-private ownership plus durable executive aliases,
  stale hosted image frame registrations are dropped on slot reuse, and image fault replay stops
  treating a promoted COW page as still filled from the shared source. ntdll now exports and dispatches
  `NtContinue`/`ZwContinue` and `NtRaiseException`/`ZwRaiseException`, while the executive applies
  `NtContinue` register state to the current hosted thread and routes last-chance raises through the
  Dbgk/process termination path. Validation: `cargo fmt --all`, `cargo test -p nt-pe-loader`,
  `cargo test -p nt-syscall-abi`, `cargo test -p nt-syscall`,
  `cargo test --manifest-path crates/nt-ntdll/Cargo.toml`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, `git diff --check`, and
  desktop run `.tmp/boot-cow-alias-desktop-20260810-225615.log`. Result: the winsrv media-event
  blocker is gone and dynamic services plus winlogon callbacks continue, but explorer has not
  launched (`explorer total=0`) and repeated service RPC listener failure (`Status 6b1`) is the next
  real target.

- I4 LPC broker handle-identity query staged. The current desktop recovery retry reaches real LSA
  `NtConnectPort(\LsaAuthenticationPort)` accept/complete and one ApiNumber=3 request/reply, then
  rejects later LSA requests because the executive only recognizes exact cached client comm-port
  handles. The port core now exposes `handle_info`, the LPC ABI/client/server expose
  `LPC_OP_QUERY_HANDLE`, and `ExecNtHandler::lpc_connection_is` verifies uncached handles against the
  broker before caching a dynamic alias. Verification is strict: the handle must be a connected
  client communication port and the folded broker port name must match the requested NT port. This is
  not a service-name fallback; invalid listen/server/stale handles still fail. Validation so far:
  `cargo fmt --all`, `cargo test -p nt-port-core`, `cargo test -p nt-lpc-server`,
  `cargo test -p nt-lpc-client`, `cargo test -p nt-lpc-abi`, and `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`. Review adjustment: run one
  serialized `./run.sh --desktop` and require the repeated `lpc-cache miss
  \LsaAuthenticationPort ... handle=0x...2a` edge either to turn into a broker-verified alias or to
  report a precise endpoint/state mismatch before moving deeper into service RPC/NPFS context-handle
  handling.

- I4 desktop validation update. Serialized desktop run
  `.tmp/boot-lpc-handle-query-20260810-234239.log` proves the LPC identity query is doing strict
  broker-backed resolution. Wrong connected handles are rejected with precise endpoint/state/name
  evidence (`\smapiport` and `\windows\apiport`), while later real LSA client comm-port handles are
  inserted dynamically for the requesting process. The boot now moves past the old profile frontier:
  `NtLoadKey` mounts `\Registry\User\S-1-5-21-2027863616-125950201-1543963175-500`,
  `WlxActivateUserShell` reads the real SOFTWARE `Userinit` value, `userinit.exe` launches
  `explorer.exe`, and explorer reaches real win32k/GDI traffic. This is still not a completed desktop
  paint proof: explorer stops during early shell GUI calls and the deadman reports every hosted thread
  parked on dispatcher/event waits with no further IPC. Review adjustment: the next slice should
  inspect the first explorer wait/event edge after SSN `0x1082` and fix generic dispatcher or win32k
  queue-event wake delivery, not add explorer, shell, or paint-specific success paths.

- I4 hosted listener stack/runtime slice boot-verified. A follow-up desktop run reached real base
  desktop paint and deep dynamic service/explorer dependency loading, then exposed a generic hosted-thread
  stack-context bug in the SCM listener: after `LdrInitializeThread`, listener syscalls use the
  caller-created `InitialTeb` stack, but `probe_user_output` still checked the loader bootstrap stack
  window. Multiplexed service/LSA listener spawns now retain that real stack range in hosted-thread
  runtime metadata, and the executive's cross-address-space read/write/probe helpers accept current
  hosted-thread stack ranges only when the target process has real page backing. NPFS server pipe
  creation/listen state is also stricter: clients connect to listening server endpoints, not to
  disconnected or historical endpoints. Validation: `cargo fmt --all`, `cargo test -p nt-io-manager
  pipe -- --nocapture`, the executive `cargo check`, `git diff --check`, and serialized desktop run
  `.tmp/boot-hosted-listener-stack-20260811-010115.log`. Result: the SCM listener `NtCreateEvent`
  probe wall is gone, base desktop paint is restored (`desktop-bg 768/768`), and the next red edge is
  later service RPC context-handle association: `RpcServerListen() failed (Status 6b1)` followed by
  `no context handle found for uuid {fb1f958e-c047-4b4f-ba6c-97645a18f1a1}` before explorer issues
  any syscalls.

- I4 desktop paint recovery through real callback-return GDI marshalling. A reported
  `./run.sh --desktop` failure exposed a later winlogon/user32 callback-return edge, not a need for
  paint scaffolding. The callback dispatcher now scrubs entry registers like ReactOS
  `KiUserCallbackExit`, the executive shares those context indexes with `NtContinue`, and completed
  `KeUserModeCallback` paths flush the caller's deferred GDI batch before resuming the parked win32k
  continuation. The late win32k bridge also stages/copies back real caller-owned buffers for
  `NtGdiGetTextMetricsW` and the non-Ex `NtGdiGetTextExtent`, so the modal/dialog paint path no
  longer succeeds by returning synthetic text metrics or sizes. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `cargo test -p nt-user-callback -- --nocapture`, `git diff --check`, and serialized desktop run
  `.tmp/boot-gdi-text-marshalling-20260810.log`. Result: the previous callback-memory instruction
  fault is gone, `PASS exec_win32k_desktop_painted` and `PASS exec_gdi_user_batch_flushed` are back,
  and the run reaches `249/295` executive checks. Review adjustment: the active frontier has moved
  to LSA auth-port request marshalling (`[lsa-rdv] WALL: could not marshal the message into the
  server's RequestMsg`), with msgina modal paint/profile/userinit/explorer gates still downstream of
  that real logon IPC path.

- I4 LSA auth-port peer-copy recovery. The request marshalling wall was caused by a generic
  cross-address-space helper short-circuit: parked peer copies intentionally clear `loop_ctx` and use
  mirror/recorded-frame access, but `xas_read`/`xas_try_write_buf` returned false as soon as the
  target range matched the current hosted thread's runtime stack. That was only visible when the
  pending LSA request was delivered from the server thread's next `NtReplyWaitReceivePort`, where
  `current_badge` already named the LSASS auth-port thread. The helpers now use the hosted-stack fast
  path only when a live loop context exists, otherwise they fall through to the existing
  mirror/recorded-frame path. Validation: `cargo fmt --all`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, and serialized desktop retry
  `.tmp/boot-lsa-peer-copy-20260810.log` (stopped after a later no-output window). Result: base
  desktop paint still occurs (`desktop-bg 768/768`), the LSA ApiNumber 3 request is now relayed to
  the real LSASS server and replied with `LSA_API_MSG.Status=0`, and the previous
  `could not marshal the message into the server's RequestMsg` signature is gone. Review adjustment:
  the next red edge is again generic service RPC context-handle association across dynamic workers:
  `RpcServerListen() failed (Status 6b1)`, `no context handle found for uuid
  {819b2278-105d-40eb-8f73-5969e6748dcd}`, then `rpc_message.c:1874` fault-packet status
  `0x1c00001a`. Userinit/explorer still have not launched in this retry (`explorer total=0`).
