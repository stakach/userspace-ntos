# Kernel Dynamic Tech Debt Plan

Last updated: 2026-08-02

## Objective

Replace remaining hardcoded, modeled, or synthetic kernel scaffolding with dynamic NT-style
subsystems so ReactOS components discover process identity, service tables, devices, registry
state, ports, and GUI/user callbacks through real kernel-owned contracts.

## Working Rules

- Do not add fallback success paths. Missing behavior should fail visibly or be implemented.
- Prefer runtime provider metadata, object manager state, process manager state, registry hives,
  LPC ports, and driver/device objects over name tables or boot-order checks.
- Keep the checked behavior moving in small commits. Update this file after every completed step.
- Preserve the existing boot frontier while replacing one boundary at a time.

## Status Legend

- `[ ]` pending
- `[~]` in progress
- `[x]` complete

## Workstreams

### A. Process Identity And Launch Topology

- `[x]` A0: Inventory the current hardcoded dynamic-debt boundaries.
- `[x]` A1: Remove fixed `pi` dispatch from hosted child executable metadata lookup.
- `[ ]` A2: Replace the static hosted image table with a dynamic image/session registration
  contract driven by created sections and process parameters.
- `[~]` A3: Move `PM_PIDS`, `PM_TIDS`, and thread pool mirrors behind process-manager keyed
  lookup APIs so callers stop indexing process identity through mechanism slots.
- `[~]` A4: Replace badge-to-process switches with registered thread/process runtime records.

### B. Win32k Process And Thread Context

- `[ ]` B1: Replace placeholder `EPROCESS`, `ETHREAD`, `W32PROCESS`, and `W32THREAD` addresses
  with object-manager/process-manager backed pointers.
- `[ ]` B2: Replace `WIN32K_CLIENT_*[pi]` tables with PID/TID keyed runtime state populated by
  `PsConvertToGuiThread`, process/thread callouts, and win32k allocations.
- `[ ]` B3: Remove bootstrap placeholder aliases once win32k can resolve current process/thread
  objects dynamically for every GUI caller.

### C. System Service Provider Boundary

- `[x]` C1: Route win32k services through `KeAddSystemServiceTable` and provider metadata.
- `[x]` C2: Reject provider service calls whose runtime arity does not match the registered
  metadata.
- `[ ]` C3: Audit remaining direct win32k/client service shims and convert them to provider-owned
  dispatch or documented narrow kernel callbacks.

### D. Driver, Device, And Registry Discovery

- `[ ]` D1: Replace hardcoded GDI/display/keyboard driver preloads with loader and service-control
  driven driver objects.
- `[ ]` D2: Replace driver-name matches in system information calls with registered module/device
  state.
- `[ ]` D3: Replace synthetic video, keyboard, CPU, and Winlogon registry overlays with real hive
  data and driver-created device interfaces.

### E. LPC, CSR, SRM, And LSA

- `[ ]` E1: Remove modeled CSR reply paths and require real CSR server rendezvous for connect and
  request/reply traffic.
- `[ ]` E2: Replace fixed LPC port-name creation order with object-manager named-port lookup.
- `[ ]` E3: Replace modeled SRM/LSA accept replies with real port messages and server-side
  processing.

### F. User32, GDI, And Paint Path Completion

- `[ ]` F1: Remove user32/GDI fake handle mirrors and global cursor/class state that bypasses real
  object ownership.
- `[ ]` F2: Complete api0 `WINDOWPROC` execution so `WM_PAINT` runs dialog/control paint procs
  instead of synthetic `LRESULT` completion.
- `[ ]` F3: Replace modal-pump synthetic `PeekMessage`/`GetMessage(WM_PAINT)` scaffolding with
  queue state produced by real window invalidation and dispatch.
- `[ ]` F4: Add framebuffer proof for the credential dialog after the real paint path is wired.

## Review Log

### 2026-08-02

- A0 complete. Current debt clusters are fixed hosted process topology, win32k placeholder process
  objects, preloaded/name-matched drivers, modeled LPC/CSR/SRM replies, synthetic registry
  overlays, and user32/GDI fake-handle paint scaffolding.
- A1 started. First cleanup target is `record_hosted_child_exe_open`, which still mapped executable
  metadata through fixed numeric `pi` values even though the open request already carries the
  executable leaf.
- A1 complete. `record_hosted_child_exe_open` now resolves the loaded PE metadata by hosted image
  leaf and records userinit/explorer telemetry by hosted role instead of numeric `pi`. Review
  adjustment: the loop-owned loaded image slots are still statically enumerated because the boot
  loop still owns those PE locals; that remaining debt is now explicitly covered by A2/A3.
- A3 started. Process/thread mechanism claim and reverse TID lookup now go through
  `ExecNtHandler` PID/TID accessors instead of reading `PM_PIDS`, `PM_TIDS`, or pool TID mirrors
  directly. Review adjustment: the accessors still preserve the existing mirror fallback while the
  boot loop and self-test scaffolding write those mirrors; the next A3 slice should move mirror
  writes into dedicated registration helpers and then remove fallback reads as the mechanism tables
  become authoritative.
- A3 continued. Bootstrap and child-spawn writes now go through dedicated hosted mirror
  reset/store helpers instead of open-coded `PM_PIDS`, `PM_TIDS`, and pool TID stores. Review
  adjustment: the remaining direct mirror accesses are concentrated in loop selection diagnostics
  and self-test scaffolding; production launch should next register ProcessManager/process
  mechanisms atomically so the old mirror fallback can be deleted.
- A3 continued. Bootstrap ProcessManager setup now preserves the real bootstrap PID/TID values and
  registers process/thread mechanisms from those values directly after `ExecNtHandler` is built.
  Dynamic child process creation registers the process and pool-thread mechanisms as part of the
  spawn path, with `PM_*` mirrors updated only after mechanism registration succeeds. Review
  adjustment: production process identity no longer depends on mirror reads to claim mechanisms;
  the remaining fallback reads are now compatibility for loop diagnostics and self-test-only
  temporary process slots.
- A3 continued. The GUI client-info TEB alias path now resolves hosted main TIDs through
  `ExecNtHandler::pm_main_tid_for_pi`, and the runtime thread diagnostic dump resolves pool TIDs
  through `pm_pool_tid_for_slot`. Review adjustment: remaining direct `PM_PIDS`/`PM_POOL_TID`
  writes are self-test temporary slots or the centralized mirror helper layer; remaining raw
  runtime read helpers should move behind handler-owned runtime lookup APIs before A3 can close.
- A3 continued. User-callback TEB aliasing no longer reads `PM_TIDS`; main-thread callback identity
  is accepted through the registered hosted image top badge, and explorer aliasing checks the hosted
  role/leaf instead of mirror state. Deleted the old `runtime_thread_slot` scanner, so
  `pm_pool_slot_for_tid` is now backed only by `ThreadMechanismTable`. Review adjustment:
  `hosted_thread_tcb_cell` still has a main-thread `PM_TIDS` fallback for callback TCB lookup; that
  should be replaced by carrying/resolving callback TCB identity through the registered thread
  runtime before A3 closes.
- A3 continued. User-callback dispatch now carries the client TCB explicitly in
  `Win32kClientContext`, `UserCallbackClient`, and the active callback frame. Callback redirect,
  chained callback, and `NtCallbackReturn` resume paths consume that frame-owned TCB instead of
  rediscovering it through TID mirrors. `ExecNtHandler` hosted TCB accessors are now backed only by
  the registered thread runtime, and hosted thread termination clears legacy TCB mirror cells by
  runtime role after releasing the runtime record. Deleted the old `hosted_thread_tcb_cell` /
  `tp_worker_identity_for_tid` scanner, including the main-thread `PM_TIDS` fallback. Review
  adjustment: remaining A3 mirror debt is now limited to synchronized mirror writes and self-test
  temporary `PM_POOL_TID` slots; production TCB lookup no longer has a mirror fallback.
- A3 continued. Post-quiesce debug self-tests now register throwaway debuggee processes through
  handler-owned temporary process slots instead of writing raw `PM_PIDS` entries, and the remote
  break-in proof registers its throwaway pool ETHREAD through the same thread mechanism table used by
  hosted runtime thread creation. `pm_pid_for_pi`, `pi_for_pid`, `pm_main_tid_for_pi`, and
  `pm_pool_tid_for_slot` no longer scan or read PID/TID mirrors; the table-backed lookup is
  authoritative, with temporary self-test slots explicit and bounded. Review adjustment: remaining
  A3 work is now the low-level mechanism state still keyed by `PM_PML4S` and
  `PM_POOL_SUSPENDED`, plus the compatibility mirror writes kept for code outside
  `ExecNtHandler`.
- A3 continued. Hosted VSpace publication/lookup and pool usage/suspend bookkeeping now go through
  `ExecNtHandler` APIs instead of open-coded `PM_PML4S`, `PM_POOL_USED`, or
  `PM_POOL_SUSPENDED` access in the service loop and rendezvous paths. The CSR worker
  `NtCreateThread` path consumes the published VSpace instead of its old `csrss_pml4` special case,
  and failed remote-thread handle insertion releases the claimed pool slot. Review adjustment:
  raw pool/PML4 atomics are now confined to reset/helper code and gate-only probes; the next A3/A4
  boundary is replacing the static TCB/worker slot arrays with registered runtime records.
- A3/A4 continued. `HostedThreadRuntimeTable` can now resolve a hosted TCB by registered process
  index and `HostedThreadRole`, and `ExecNtHandler` exposes that lookup as the production TCB
  boundary. Service-loop diagnostics, Winlogon desktop-info repair, CSR worker resume, CSR
  rendezvous gating, and Winlogon worker signal checks now recover TCBs from registered runtime
  roles instead of named TID cells or TP-worker TID mirrors. Review adjustment: remaining raw
  runtime identity reads are spawn-slot reservation/publication, gate-only debug probes,
  compatibility mirror cleanup, and the win32k callback TEB-alias/candidate paths until callback
  client context carries role-backed runtime identity.
