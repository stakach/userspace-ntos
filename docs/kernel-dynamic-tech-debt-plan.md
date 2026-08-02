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
- `[~]` A2: Replace the static hosted image table with a dynamic image/session registration
  contract driven by created sections and process parameters.
- `[x]` A3: Move `PM_PIDS`, `PM_TIDS`, and thread pool mirrors behind process-manager keyed
  lookup APIs so callers stop indexing process identity through mechanism slots.
- `[x]` A4: Replace badge-to-process switches with registered thread/process runtime records.
- `[x]` A5: Move remaining named hosted TCB cap cells into runtime-owned hosted-thread capability
  records and narrow proof queries.

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
- A4 continued. Win32k callback client context now carries the registered `HostedThreadRole`
  through `Win32kClientContext`, `UserCallbackClient`, and the active callback frame. Winlogon
  callback TEB aliasing resolves from that role instead of checking static winlogon/TP TID cells,
  and the post-quiesce nested/dead-client callback proof receives its victim from a service-side
  runtime-table lookup instead of selecting from win32k's legacy TID/TCB mirrors. Review adjustment:
  remaining A3/A4 runtime debt is now concentrated in spawn-slot reservation/publication,
  compatibility mirror cleanup, service-loop current-TID diagnostics, and gate-only debug probes.
- A3/A4 continued. The service loop's per-syscall `current_tid` derivation now resolves TP workers
  and named hosted workers through registered runtime roles instead of reading `TP_WORKER_TID`,
  `SVC_LISTENER_TID`, `WL_WORKER*_TID`, `LSASS_LISTENER*_TID`, or `LSA_WORKER_TID` cells. Review
  adjustment: remaining A3/A4 runtime debt is concentrated in spawn-slot reservation/publication,
  compatibility mirror cleanup, and gate-only/self-test probes.
- A3/A4 continued. Hosted thread runtime records now support a reserved state (`tid` present,
  `tcb == 1`) so TP worker badge slots are claimed before their seL4 TCB is spawned. Remote and
  in-process `NtCreateThread` paths choose free TP slots through runtime-role lookup and publish
  reservations through `ExecNtHandler`; `spawn_requested_tp_worker` consumes that reservation instead
  of reading `TP_WORKER_TID`. Review adjustment: the remaining `TP_WORKER_TID` writes are centralized
  compatibility publication/cleanup plus the isolated remote-breakin self-test reset; the next cleanup
  target is removing or replacing the TCB mirror arrays.
- A3/A4 continued. `spawn_sec_image` now returns a structured spawn result carrying both the VSpace
  cap and the main-thread TCB cap. SMSS and later hosted process main-thread runtime registration
  consumes that returned TCB directly, and `ExecNtHandler::new` no longer reads `PM_MAIN_TCBS` while
  constructing NT process/thread identity. Review adjustment: `PM_MAIN_TCBS` remains as a low-level
  cap publication for gate probes and mechanism cleanup only; the next cleanup target is replacing
  the remaining TP-worker TCB mirror cells with role-backed runtime registration.
- A3/A4 continued. Removed the `TP_WORKER_TID` and `TP_WORKER_TCB` mirror arrays. Normal TP-worker
  spawn, cross-VSpace remote thread spawn, the CSR rendezvous worker create path, and the remote
  break-in self-test now reserve, locate, register, suspend, and release worker mechanisms through
  hosted thread runtime records keyed by `HostedThreadRole::TpWorker`. Review adjustment: remaining
  TCB mirror cleanup is limited to named/bootstrap role cap cells that still back low-level gates and
  teardown; worker identity no longer has a static array fallback or compatibility publication.
- A3 continued. Removed the dead `PM_PIDS`, `PM_TIDS`, and `PM_POOL_TID` mirrors. Hosted PID/TID
  identity now lives only in ProcessManager plus the process/thread mechanism tables, and child
  `SEC_IMAGE` spawns receive their `TEB.ClientId` values directly from those objects instead of
  reading global identity cells. Review adjustment: the pre-handler SMSS spawn still passes explicit
  zero client IDs because the handler-owned bootstrap objects are constructed inside the service loop;
  closing that ordering gap belongs with the remaining mechanism-state mirror cleanup.
- A3 continued. Moved runtime ETHREAD-pool occupancy and initial-suspend masks out of the
  `PM_POOL_USED`/`PM_POOL_SUSPENDED` atomics and into `ExecNtHandler` fields. Pool claim/release,
  create-suspended handoff, diagnostics, CSR worker creation, and remote thread cleanup now mutate
  handler-owned state directly. Review adjustment: `PM_PML4S` remains as the last process-mechanism
  static in this cluster because post-loop gate probes still read it without an `ExecNtHandler`.
- A3 continued. Moved hosted process VSpace caps out of `PM_PML4S` and into `ExecNtHandler`
  process-mechanism state. Runtime cross-VSpace thread creation now resolves target PML4 caps from
  the handler-owned table, while post-loop userinit/explorer gates consume a narrow
  `PM_VSPACE_PUBLISHED_OK` proof bit instead of reading cap values. Review adjustment: the A3
  process/thread identity and mechanism-state mirrors are now gone; remaining A4 work is the named
  bootstrap/listener TCB/TID cap cells still used by low-level spawn and teardown glue.
- A3 complete. Source now has no `PM_PIDS`, `PM_TIDS`, `PM_POOL_TID`, `PM_POOL_USED`,
  `PM_POOL_SUSPENDED`, `PM_PML4S`, `TP_WORKER_TID`, or `TP_WORKER_TCB` arrays. Remaining dynamic
  launch-topology debt is tracked under A2 and A4.
- A4 continued. Named `NtCreateThread` routes for SM, CSR, Winlogon, services, SCM, LSASS, and LSA
  now gate and reserve through `HostedThreadRuntimeTable` roles instead of checking static
  `*_TID`/`*_TCB` cells. Reservation failure tears down the claimed ETHREAD/handle transactionally,
  and `NtResumeThread` resolves CSR/SCM behavior from hosted runtime role identity. Review
  adjustment: the named TID/TCB cells that remain are low-level cap publication, spawn handoff, and
  rendezvous diagnostics; the next A4 slice should make spawn handoff consume runtime role records
  directly so those compatibility cells can shrink further.
- A4 continued. The service-loop thread-spawn handoff now consumes reserved runtime-role TIDs for
  multiplexed services/SCM/LSASS/LSA threads, SM loop, CSR workers, Winlogon workers, and CSR
  resume-start bookkeeping. `HostedThreadSpawnSpec` no longer carries a static TID cell. Review
  adjustment: remaining named TID cell reads are now rendezvous/current-TID diagnostics and
  low-level post-loop gates; remaining named TCB cells are cap publication/teardown probes.
- A4 continued. SM/CSR rendezvous helpers now derive their worker `current_tid`, CSR message
  `ClientId.UniqueThread`, and SM-loop hosted thread spawn identity from runtime role records. The
  SM-loop spawner receives the reserved TID from its caller instead of reading `SM_LOOP_TID`.
  Review adjustment: named TID reads are now confined to post-loop gate probes in `main.rs`; named
  TCB cells still publish low-level seL4 caps for gates and teardown.
- A4 continued. Post-loop gates now consume `HOSTED_THREAD_RUNTIME_OK` proof bits published when
  named runtime roles are promoted to live TCB-backed records. Deleted the remaining named hosted
  TID cells and compatibility stores (`SM_LOOP_TID`, `CSR_*_TID`, Winlogon worker TIDs,
  services/SCM/LSASS/LSA worker TIDs); source now has no named hosted TID mirrors. Review
  adjustment: remaining A4 work is the badge-to-process selection helpers and named TCB cap cells
  used for low-level seL4 publication/teardown.
- A4 continued. Live fault routing for named listener/worker badges now resolves process ownership
  from registered hosted thread runtime badge metadata instead of a badge-to-executable switch.
  Top-level process badges and generic TP-worker badges remain mechanism-level decodes. Review
  adjustment: quiesce/crash owner accounting still has a non-handler badge owner map; the next A4
  cleanup should thread runtime context into those accounting sites or publish an owner snapshot.
- A4 complete. Quiesce/crash owner accounting now threads `ExecNtHandler` into owner resolution, so
  named listener/worker ownership comes from `HostedThreadRuntimeTable` badge metadata instead of
  `hosted_pi_for_owner_badge`. Syscall current-TID and hosted current-role lookup also consume
  runtime badge records; the static badge-to-role decoder is gone, and missing runtime identity logs
  a visible diagnostic instead of silently falling back to main-thread `pi`. Review adjustment:
  top-level process badges and generic TP-worker badges remain mechanism-level transport decodes.
  The remaining named hosted TCB cells are low-level seL4 cap publication/teardown state, now tracked
  separately as A5 rather than process-identity routing.
- A5 complete. Local hosted-thread spawn paths no longer claim or store named TCB cap cells, and
  `HostedThreadSpawnSpec` carries only role/badge/TEB/spawner metadata. Thread termination now
  suspends/deletes the TCB from the runtime record and releases that record without clearing a mirror.
  The `PM_MAIN_TCBS` array and `img_spawn` publication write are gone; userinit/explorer gates prove
  main-thread publication through `HOSTED_THREAD_RUNTIME_OK` for `HostedThreadRole::Main`. The
  winlogon listener post-loop proof is a boolean mint latch, so hosted TCB cap values live only in
  `HostedThreadRuntimeTable`. Review adjustment: remaining `_TCB` state belongs to non-hosted seL4
  mechanisms such as win32k/root-task plumbing, not hosted process/thread identity.
- A2 started. `nt-exe-image` now has a no-heap `HostedImageCatalog` registration/lookup contract
  separate from the historical `HOSTED_PROCESS_IMAGES` slice. Registration validates executable leaf
  shape, NT image path consistency, and duplicate `pi`/top-badge/leaf identities; lookups cover
  `pi`, leaf/path, top badge, role, noninteractive-service classification, probe fragments, count,
  and expected-mask derivation. New crate tests cover registration, duplicate rejection, invalid
  paths, bounded capacity, and SxS probe rejection. Review adjustment: the executive still calls the
  static wrappers; the next A2 slice should instantiate a runtime catalog in the service loop and
  route gate/lookup call sites through that catalog before deleting static-wrapper use.
- A2 continued. `ImageTable` spawn reservations can now bind to a dynamic catalog target through
  `reserve_spawn_registered`, producing a `SpawnRequest` with the registered target `pi`, top badge,
  and role while rejecting unregistered executable sections. The legacy `reserve_spawn` remains
  target-less for current executive callers, but the crate now has the policy boundary needed for
  `NtCreateProcessEx` to consume runtime catalog state instead of asking static leaf wrappers.
  Review adjustment: the next wiring slice should pass the runtime catalog into the executable
  create-process handler and make `spawn_requested_hosted_exe` consume `request.target` instead of
  re-resolving target identity from `HOSTED_PROCESS_IMAGES`.
- A2 continued. `nt-exe-image` now has an owned, fixed-capacity hosted image catalog for runtime
  registration. Runtime-discovered leaf, process name, NT image path, command line, image root,
  role, top badge, and probe fragment data can be stored without heap allocation, validated through
  the same contract as borrowed registrations, and used to produce target-bound spawn requests.
  Review adjustment: the executive can now carry a real runtime-owned catalog instead of borrowing
  from the historical static image slice; the next step is wiring that catalog into open/section
  tracking and deleting static-wrapper lookups from the spawn path.
- A2 continued. The service loop now owns an `OwnedHostedImageCatalog`, executable opens register
  admitted hosted images into it, and `NtCreateProcess` reserves spawns with
  `reserve_spawn_owned_registered`. The service-loop spawn consumer requires a target-bound request,
  verifies it against the runtime catalog, rolls back malformed requests, and passes the catalog's
  NT image path/command line into `spawn_sec_image`. Review adjustment: open-time admission still
  uses the historical hosted descriptors to supply badge/role/root policy for the bounded preloaded
  images; the next A2 cleanup is moving that policy source behind a real session/image registration
  API and converting remaining static wrapper lookups that only format names or classify faults.
- A2 continued. The duplicated live-hosted-process lookup helpers in service-loop and rendezvous
  code now compare the ProcessManager's live `image_file_name` leaf directly with
  `canonical_exe_leaf`, instead of round-tripping through the static hosted image table. Review
  adjustment: remaining static wrapper uses are now concentrated in boot/gate expectations,
  win32k callback classification, path-prefix formatting, and the open-time registration source for
  bounded preloaded hosted images.
- A2 continued. `ExecNtHandler` now owns a runtime hosted-image metadata catalog registered
  alongside process mechanism identity. Bootstrap and dynamic child processes publish metadata into
  that catalog, and ProcessManager identity gates, current-process role/leaf checks, service-loop
  GDI mapping, win32k service labels, and process image path-prefix formatting consume the handler's
  registered metadata instead of querying the static hosted image table. Review adjustment: the
  historical descriptors still seed bootstrap/open-time registration; remaining consumers are gate
  expectations, win32k callback classification, mechanism top-badge helpers, and executable probe
  admission.
- A2 continued. Service-loop top-badge ownership, quiesce masks, role-backed thread registration,
  and fault-badge labels now derive from `ExecNtHandler`'s registered hosted-process metadata
  instead of the static hosted image badge map. Review adjustment: remaining static uses are now
  bootstrap/open-time registration policy, executable probe admission, win32k callback
  classification, bootstrap spawn descriptors, and post-loop gate expectations.
- A2 continued. Win32k user-callback client identity now carries process role and top badge from
  `ExecNtHandler` metadata through `Win32kClientContext`, `UserCallbackClient`, and active callback
  frames. Callback support checks and TEB-alias selection classify winlogon/explorer from that
  carried metadata instead of consulting `HOSTED_PROCESS_IMAGES`. Review adjustment: remaining
  static uses are bootstrap/open-time registration policy, executable probe admission, bootstrap
  spawn descriptors, and post-loop gate expectations.
- A2 continued. The service loop now seeds the hosted executable-open catalog once from the loaded
  PE set, and `NtQueryAttributesFile`/`NtOpenFile` probe that runtime catalog directly. Open-time
  child image tracking no longer re-registers descriptors or resolves probe leaves through the
  historical static table. Review adjustment: remaining static uses are the startup seed policy,
  bootstrap process metadata registration, bootstrap spawn descriptors, and post-loop gate
  expectations.
- A2 continued. Post-loop process-manager gates now derive their expected hosted-process mask and
  userinit/explorer `pi` values from hosted-process metadata published during
  `ExecNtHandler` registration, not from `HOSTED_PROCESS_IMAGES`. Review adjustment: remaining
  static uses are the startup seed policy, bootstrap process metadata registration, and bootstrap
  spawn descriptors.
- A2 continued. Hosted process-manager gate publication/lookup moved out of the large root module
  into `hosted_gate.rs`, while preserving the existing crate-level namespace through re-export. This
  is a mechanical split with no policy change. Review adjustment: remaining static hosted-image
  uses are still the startup seed policy, bootstrap process metadata registration, and bootstrap
  spawn descriptors.
- A2 continued. `ExecNtHandler::new` now receives bootstrap hosted-process metadata from the
  runtime hosted-image catalog seeded by the service loop, and registers smss/csrss/winlogon
  identities from that catalog instead of looking up static descriptors by `pi` internally. The
  executable catalog now includes the already-loaded smss image so bootstrap gate publication remains
  complete. Review adjustment: remaining executive-side static hosted-image uses are the startup
  seed policy and the bootstrap spawn descriptor helper.
- A2 continued. Bootstrap hosted-image seed policy moved into `hosted_bootstrap.rs`, and the old
  `spawn_hosted_sec_image_for_pi` helper was removed. SMSS launch now passes an explicit
  `HostedProcessImageRef` from `smss_bootstrap_image()` into `spawn_hosted_sec_image_for_image`, so
  spawn no longer performs a hidden static descriptor lookup by `pi`. Review adjustment: the only
  remaining executive-side reference to `HOSTED_PROCESS_IMAGES` is the startup catalog seed; replacing
  that cleanly requires a real boot/session image manifest rather than another fallback table.
- A2 cleanup. Fixed hosted-process runtime placement, mirror selection, live-spawn latch lookup, and
  hosted SEC_IMAGE spawn construction moved from `service_sec_image.rs` into
  `hosted_process_runtime.rs`. This preserves the namespace and behavior but makes the remaining
  hardcoded per-`pi` mechanism layout explicit for the future allocator work. Review adjustment:
  this is a mechanical split; the runtime placement data is still fixed policy and should be replaced
  by a process-slot layout allocator after the startup image manifest exists.
- A2 continued. The executive no longer scans `nt_exe_image::HOSTED_PROCESS_IMAGES` to seed hosted
  executable metadata. `hosted_bootstrap.rs` now exposes explicit bootstrap image descriptors, and
  `service_sec_image` registers each descriptor only at the point where that PE was actually loaded
  for the current run. This removes the last executive-side dependency on the historical hosted-image
  slice and makes missing boot images a property of the load path, not a hidden catalog filter. Review
  adjustment: the compatibility slice and static lookup wrappers remain inside `nt-exe-image` for
  crate tests/legacy callers; the executive path is now runtime-catalog based. Remaining A2 debt is
  replacing the bootstrap descriptor functions with a real boot/session image manifest source.
- A2 cleanup. Hosted bootstrap image loading now consumes `HostedBootstrapLoadSpec` records and uses
  one `load_hosted_bootstrap_image` helper for load, EXE relocation, ImageBase patching, and catalog
  registration. This removes six duplicated load/register blocks from `service_sec_image.rs` and keeps
  disk path, stem, and NT process metadata together in the bootstrap boundary. Review adjustment: the
  specs are still compiled-in bootstrap policy; the next semantic step is a manifest handoff populated
  by the loader/session manager rather than functions in `hosted_bootstrap.rs`.
- A2 complete for static hosted-image tables. Removed `nt_exe_image::HOSTED_PROCESS_IMAGES`, the
  legacy `HostedProcessImage` static descriptor type, and the crate-level static lookup/spawn/probe
  wrappers. `nt-exe-image` tests now build explicit borrowed/owned catalogs, so the only supported
  production model is registration into a catalog and lookup through that catalog. Review adjustment:
  bootstrap descriptors remain in the executive's `hosted_bootstrap.rs` until a real boot/session
  manifest handoff exists, but there is no global hosted-image identity table left to fall back to.
- A2 continued. Hosted process runtime layout is now registered into a runtime table instead of
  selected by a hardcoded `match pi`. SMSS registers before the pre-service SEC_IMAGE spawn paths,
  and bootstrap child layouts register only when their image load succeeds. Mirror/scratch helpers
  and hosted SEC_IMAGE spawn construction now require a registered runtime layout instead of silently
  defaulting to SMSS mirrors. Review adjustment: layout values are still compiled-in bootstrap policy
  in `hosted_process_runtime.rs`; the next semantic step is replacing those constructors with an
  allocator or manifest-provided layout.
- A2 continued. Loop-owned hosted executable PEs now publish into `HostedLoadedImageTable`, keyed by
  the runtime hosted-image catalog. `ExecLoopCtx` carries that table instead of six named PE/pool
  pointers, `exec_handler` metadata lookup no longer has a fixed named-process slot list, and hosted
  spawn/current-PE selection no longer matches on `pi` to choose named PE locals. Review adjustment:
  the PE objects themselves still live as bootstrap loop locals because the loader has not yet handed
  off a durable image object store.
