# Kernel Dynamic Tech Debt Plan

Last updated: 2026-08-03

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

- `[x]` B1: Replace placeholder `EPROCESS`, `ETHREAD`, `W32PROCESS`, and `W32THREAD` addresses
  with object-manager/process-manager backed pointers.
- `[x]` B2: Replace `WIN32K_CLIENT_*[pi]` tables with PID/TID keyed runtime state populated by
  `PsConvertToGuiThread`, process/thread callouts, and win32k allocations.
- `[x]` B3: Remove bootstrap placeholder aliases once win32k can resolve current process/thread
  objects dynamically for every GUI caller.

### C. System Service Provider Boundary

- `[x]` C1: Route win32k services through `KeAddSystemServiceTable` and provider metadata.
- `[x]` C2: Reject provider service calls whose runtime arity does not match the registered
  metadata.
- `[~]` C3: Audit remaining direct win32k/client service shims and convert them to provider-owned
  dispatch or documented narrow kernel callbacks.

### D. Driver, Device, And Registry Discovery

- `[~]` D1: Replace hardcoded GDI/display/keyboard driver preloads with loader and service-control
  driven driver objects.
- `[~]` D2: Replace driver-name matches in system information calls with registered module/device
  state.
- `[~]` D3: Replace synthetic video, keyboard, CPU, and Winlogon registry overlays with real hive
  data and driver-created device interfaces.

### E. LPC, CSR, SRM, And LSA

- `[ ]` E1: Remove modeled CSR reply paths and require real CSR server rendezvous for connect and
  request/reply traffic.
- `[ ]` E2: Replace fixed LPC port-name creation order with object-manager named-port lookup.
- `[ ]` E3: Replace modeled SRM/LSA accept replies with real port messages and server-side
  processing.

### F. User32, GDI, And Paint Path Completion

- `[~]` F1: Remove user32/GDI fake handle mirrors and global cursor/class state that bypasses real
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
- A2 cleanup. CSR and SM rendezvous launch sites now fetch CSRSS's PE through
  `HostedLoadedImageTable` using the `pi` carried by `csrss_bootstrap_load_spec`, rather than
  reaching into the `csrss_pe` loop local directly. Review adjustment: rendezvous itself still
  correctly receives an explicit CSRSS PE parameter because it operates in CSRSS's address space; the
  remaining static topology there is the fixed SMSS/CSRSS rendezvous relationship, not PE ownership.
- A2 cleanup. The SEC_IMAGE service loop now consumes child hosted EXEs from
  `hosted_bootstrap_load_specs()` as a manifest array, with loaded PEs and pool VAs stored in indexed
  loop-owned arrays before publication into `HostedLoadedImageTable`. The six child load-spec
  constructors are private implementation details of `hosted_bootstrap.rs`, so service-loop loading
  no longer names each bootstrap child as a separate local. Review adjustment: the manifest itself is
  still compiled into the executive until the loader/session manager can hand off bootstrap image
  policy.
- A2 cleanup. Removed the root-module `USERINIT_BADGE` and `EXPLORER_BADGE` identity constants.
  Win32k service admission now recognizes non-native top-level hosted processes through registered
  hosted-process metadata, and the userinit shell-frontier wait mask derives userinit's top badge
  from its registered `InteractiveShellBootstrap` role. Review adjustment: several older
  winlogon/LSASS-specific frontier checks still compare against their transport badges and should be
  handled in a focused pass.
- A2 cleanup. The second-SAS injection helper no longer identifies winlogon through fixed `pi == 2`
  and `WINLOGON_BADGE`; it uses the process role and top badge already carried by registered hosted
  process metadata. Review adjustment: broader winlogon frontier diagnostics still contain fixed
  `pi == 2` checks because they name measured winlogon-only boot milestones, not just image identity.
- A2 cleanup. Several winlogon/LSASS main-thread frontier gates now resolve through registered
  hosted-process metadata instead of raw transport badge constants: winlogon wait-park clearing,
  post-logon CPU/VM/syscall milestone parks, TEB-tail write watch ownership, desktop-switch paint
  observation, hard-error diagnostics, and the LSASS post-LSA-signal crash park. Review adjustment:
  remaining `pi == 2` checks are mostly measured winlogon-only diagnostics or address probes and
  need a separate semantic pass before conversion.
- A2 repair. `ExecNtHandler` no longer owns a duplicate hosted-image catalog. It now reads the
  loop-owned runtime catalog and only publishes metadata that is already registered there, keeping
  process identity, image open, and hosted spawn on one dynamic authority. Review adjustment: this
  keeps the catalog lifetime in raw loop state for now; a later object-store/session-manifest pass
  should make that lifetime typed.
- A2 repair. `ExecNtHandler` construction now writes into a serialized BSS work slot instead of
  returning the large handler by value through the bounded rootserver stack. This preserves the
  dynamic metadata cleanup while removing the early SEC_IMAGE-demo stack fault. Review adjustment:
  this is still a rootserver-local singleton; a future typed executive object store should own it.
- A2 repair. Hosted thread-runtime lookup now treats badge 0 as a valid SMSS top-level badge rather
  than as "no badge"; live entries are already distinguished by TID. This keeps the dynamic
  badge-to-thread route valid for every hosted native process, including SMSS.
- A2 repair. Main-thread runtime publication now uses a dynamic per-process-index bit range instead
  of the old listener-only proof table. Later hosted images such as `userinit.exe` and
  `explorer.exe` can prove that their seL4 TCB-backed main ETHREAD is live without adding another
  kernel-side image-name branch. Review adjustment: listener-role gates are still role-specific
  because their startup paths are thread-service contracts, not hosted-image identities.
- C3 repair. `NtGdiOpenDCW` now crosses the isolated-client/win32k boundary with explicit argument
  marshalling instead of passing raw caller pointers into win32k. The executive stages the optional
  device/log-address strings, optional `DEVMODEW`, and optional `pUMdhpdev` output slot in the shared
  callback frame, forwards `bDisplay`/`hspool`/`pUMdhpdev` as provider-arity stack arguments, and
  copies the returned DHPDEV value back to the caller only after a successful HDC result. This cleared
  the previous `userinit.exe` OpenDCW wall: the full boot check reached `PASS
  exec_desktop_shell_frontier`, `PASS exec_userinit_process_spawned`, `PASS
  exec_userinit_shell_image_attempted`, and `PASS exec_explorer_process_spawned` with `RUN_RC=0`.
  Review adjustment: the next frontier is no longer userinit shell spawn; it is explorer's missing
  `RegisterWindowMessage` capture, api0/user-callback redirection, client-installed WndProc, and
  shell COM class provisioning gates.

### 2026-08-03

- C3 repair. `NtUserBuildHwndList` now stages caller-owned output buffers before dispatching to
  isolated win32k and copies the real returned `HWND` list and needed-count back into the client
  after a successful service return. The boundary also normalizes the seven-argument ReactOS win32k
  service shape and the eight-argument Vista/Wine user32 wrapper shape instead of letting isolated
  win32k probe client stack/output pointers directly. Validation:
  `.tmp/full-boot-build-hwnd-list-20260803-070653.log` reached `RUN_RC=0`, `PASS
  exec_win32k_desktop_painted`, `PASS exec_desktop_shell_frontier`, and explorer `0x101b`
  dispatches returned `status=0` where the previous run parked. Review adjustment: the next concrete
  explorer frontier is the later `NtGdiCreateBitmap` (`0x106c`) wall, followed by the existing
  explorer `RegisterWindowMessage`, api0 callback redirection, client WndProc, and shell COM gates.
- C3 repair. `NtGdiCreateBitmap` now treats the optional fifth argument as an explicit
  cross-address-space boundary for interactive hosted GUI clients. The executive probes the hosted
  caller stack for `pUnsafeBits`, computes the ReactOS bitmap initializer byte count, preloads
  source DLL/resource pages, copies bounded initializer bits into the win32k shared argument frame,
  and dispatches with an explicit stack argument for both copied-bit and NULL-bit calls. Failed input
  probes return NULL rather than inventing a successful bitmap handle. Validation:
  `.tmp/full-boot-create-bitmap-tail-20260803-073354.log` reached `RUN_RC=0`, `PASS
  exec_win32k_desktop_painted`, `PASS exec_desktop_shell_frontier`, `PASS
  exec_explorer_process_spawned`, and explorer completed 16 `0x106c` calls instead of parking at the
  previous `NtGdiCreateBitmap` wall. Review adjustment: the next concrete explorer wall is
  `NtGdiGetTextExtentExW` (`0x11d9`) after icon bitmap creation, while the still-failing gates remain
  explorer `RegisterWindowMessage` capture, api0/user-callback redirection, client-installed WndProc,
  and shell COM class provisioning. The older noninteractive service GDI handle fakes were not
  expanded by this slice and remain C3/F1 debt.
- C3 repair. `NtGdiGetTextExtentExW` now treats the caller-owned string and output buffers as an
  explicit isolated-client/win32k boundary. The executive probes the hosted caller stack tail for
  `UnsafeFit`, `UnsafeDx`, `UnsafeSize`, and `fl`, stages the WCHAR input and optional output arrays
  inside the win32k argument frame, dispatches with provider-owned stack arguments, and copies `SIZE`,
  `Fit`, and `Dx[]` back to the client only after a TRUE service return. Failed input or output probes
  return FALSE instead of fabricating measurements. Validation:
  `.tmp/full-boot-text-extent-marshal-20260803-074802.log` reached `RUN_RC=0`, `PASS
  exec_win32k_desktop_painted`, `PASS exec_desktop_shell_frontier`, `PASS
  exec_user_callback_dead_client_unwind`, `PASS exec_win32k_transport_call_nested`, `PASS
  exec_lsa_worker_route`, `PASS exec_msgina_logon_dialog_painted`, and `PASS
  exec_explorer_process_spawned`; explorer completed real `0x11d9` dispatches instead of parking at
  the text measurement wall. Review adjustment: remaining red gates are now the profile-directory
  value proof and explorer's `RegisterWindowMessage`, api0 callback redirection, client-installed
  WndProc, and shell COM class provisioning checks.
- Gate cleanup. `exec_winlogon_profile_directory_resolved` no longer requires a historical
  read-only-FAT create miss to prove the profile route. The real proof is the positive
  `ProfileList\ProfilesDirectory` hive read, real read-only FAT opens, zero unsupported file opens,
  and the later profile-copy/userinit/explorer gates. A boot with no readonly FAT misses is now
  treated as the stronger success case instead of a red proof artifact.
- C3 repair. `NtUserRegisterClassExWOW` now stages the ReactOS x64 stack-tail arguments
  (`fnID`, `Flags`, and `pWow`) into provider-owned dispatch arguments along with the existing
  captured class/version strings. Isolated win32k no longer reads those scalar tail arguments from a
  stale client stack mapping, so class registration observes the real caller flags instead of
  falling into the `Bad Flags` rejection path. Validation:
  `.tmp/full-boot-register-class-tail-20260803-081413.log` reached `RUN_RC=0`, `PASS
  exec_win32k_desktop_painted`, `PASS exec_desktop_shell_frontier`, `PASS
  exec_msgina_logon_dialog_painted`, `PASS exec_explorer_process_spawned`, and explorer completed
  65 `NtUserRegisterClassExWOW` dispatches. Review adjustment: the remaining red explorer gates are
  now `RegisterWindowMessage` capture, api0 callback redirection, client-installed WndProc, and
  shell COM class service; the next cleanup target is the dynamic boundary that prevents explorer
  from reaching/registering those shell window messages.
- C3 repair. `NtUserCreateWindowEx` now stages the ReactOS x64 stack-tail arguments (`dwStyle`,
  coordinates, size, parent/menu/instance handles, `lpParam`, flags, and `acbiBuffer`) before
  dispatching into isolated win32k, while retaining the original caller stack pointer in the dispatch
  context for callback/completion observers. The transport still supplies only the staged tail to the
  provider, so win32k does not dereference the hosted client stack; observers that need callsite
  context, such as dialog/style correlation, keep their original data. Validation:
  `.tmp/full-boot-create-window-tail-context-20260803-083601.log` reached `RUN_RC=0`, `PASS
  exec_win32k_desktop_painted`, `PASS exec_desktop_shell_frontier`, `PASS
  exec_msgina_logon_dialog_painted`, `PASS exec_explorer_process_spawned`, `PASS
  exec_explorer_register_window_messages_captured`, `PASS
  exec_explorer_user_callbacks_redirected`, `PASS exec_explorer_wndproc_installed_by_client`, and
  `PASS exec_explorer_shell_com_classes_served`. Review adjustment: explorer now reaches real api0
  `WM_NCCREATE`/create callback traffic and the previous explorer message/callback/COM gates are
  green. Remaining C3/F1 debt is the older noninteractive service GDI/user shims and global
  cursor/class reuse machinery, which should be replaced by real provider/object ownership rather
  than broadened.
- C3/F1 cleanup. Removed the service `NtUserFindExistingCursorIcon` fake HCURSOR path and the
  old monotonic service class-atom allocator. Non-interactive services now reuse only exact cursor
  identities and built-in class atoms that were observed from the real interactive win32k path, and
  service ScrollBar classinfo is assembled from the real session ScrollBar atom/cursor plus the
  service's own captured client PFN arrays. Cursor/class mirror misses return NULL/FALSE and are
  logged instead of counting as successful fallbacks. Validation:
  `.tmp/full-boot-service-class-mirror-fix-20260803-090312.log` reached `RUN_RC=0`, `276/276`
  checks passed, `PASS exec_services_scrollbar_classinfo_mirrored`, `PASS
  exec_win32k_desktop_painted`, `PASS exec_msgina_logon_dialog_painted`, and the explorer
  message/callback/WndProc/COM gates remained green. Review adjustment: F1 remains open because
  service GDI/init shortcuts (`NtGdiInit`, `NtGdiOpenDCW`, bitmap/pattern-brush creation) still use
  noninteractive service shortcuts; the next cleanup should move those toward provider/object-owned
  state instead of expanding the shortcut surface.
- C3/F1 cleanup. Removed the fake service GDI handle allocator and the noninteractive
  bitmap/pattern-brush successful shortcut path. Service `NtGdiCreateBitmap` still reuses the real
  observed session `DEFAULT_BITMAP` for the zero-sized stock-object case, but ordinary service
  bitmap and pattern-brush allocation misses now return NULL and log a visible mirror miss instead
  of minting process-owned GDI handles in the executive. Validation:
  `.tmp/full-boot-service-gdi-null-20260803-091616.log` reached `RUN_RC=0`, `276/276` checks
  passed, `PASS exec_services_scrollbar_classinfo_mirrored`, `PASS
  exec_win32k_desktop_painted`, `PASS exec_msgina_logon_dialog_painted`, and the explorer
  message/callback/WndProc/COM gates remained green while services and LSASS tolerated the NULL
  bitmap/brush results. Review adjustment: remaining F1/C3 service debt is now the
  `NtUserInitializeClientPfnArrays` service-safe capture, `NtGdiInit` TRUE shortcut,
  `NtGdiOpenDCW` NULL shortcut, and real provider-owned service GDI object ownership if a service
  later needs non-stock GDI objects.
- C3/F1 cleanup. Retired the old service win32k shortcut counter and log language.
  The noninteractive `NtUserInitializeClientPfnArrays` path is now documented as ReactOS' already
  initialized session-global PFN success case, with service PFN capture retained only so service
  classinfo mirrors can use the service client's own callback table. Service `NtGdiInit` is recorded
  as the ReactOS TRUE leaf result, and service `NtGdiOpenDCW` now logs the real WSS_NOIO no-display
  NULL outcome instead of fake accounting. Validation:
  `.tmp/full-boot-service-fake-counter-retired-20260803-092800.log` reached `RUN_RC=0`, `276/276`
  checks passed, `PASS exec_services_scrollbar_classinfo_mirrored`, `PASS
  exec_win32k_desktop_painted`, `PASS exec_msgina_logon_dialog_painted`, and the explorer
  message/callback/WndProc/COM gates remained green. Review adjustment: remaining F1/C3 service
  debt is real provider-owned per-service GUI/GDI process ownership, so the remaining WSS_NOIO
  service branches can shrink to ordinary provider/object outcomes instead of executive-owned
  service identity shortcuts.
- C3/F1 cleanup. Removed the class atom-name fallback accounting and the post-dispatch
  `NtUserGetAtomName` result overwrite. Shell clients now resolve `NtUserGetAtomName(0x10ad)` only
  from the observed class-atom mirror before dispatch; exact mirror misses return zero and stay
  visible in the log. The same slice replaced the remaining static userinit/explorer PID checks in
  DefSetText staging, global cursor mirror, built-in class mirror, and class
  atom-name mirror paths with hosted-process role metadata. Validation:
  `.tmp/full-boot-class-atom-mirror-no-fallback-20260803-094151.log` reached `RUN_RC=0`, `276/276`
  checks passed, `PASS exec_win32k_desktop_painted`, `PASS
  exec_msgina_logon_dialog_painted`, `PASS exec_services_scrollbar_classinfo_mirrored`, and the
  explorer message/callback/WndProc/COM gates remained green. The userinit and explorer summaries
  now report `atom-name-mirror-serves/failures=3/0`. Review adjustment: remaining C3/F1 debt is real
  per-process win32k `PROCESSINFO`/`W32PROCESS` ownership so shell and service clients can use
  ordinary provider-owned paths, followed by the remaining service WSS_NOIO branches and the F2/F3
  real paint path.
- B1 cleanup. Removed the executive `PROCESSINFO`/`W32PROCESS` fallback allocator from win32k
  attach. Bootstrap and per-client GUI attaches now require win32k's process-create callout to
  publish a non-null `W32PROCESS`/`PROCESSINFO`; missing publication is a visible attach failure
  instead of a synthetic process-info page. Validation:
  `.tmp/full-boot-w32process-callout-required-20260803-102311.log` reached `RUN_RC=0`, `276/276`
  checks passed, `PASS exec_win32k_desktop_painted`, `PASS
  exec_msgina_logon_dialog_painted`, `PASS exec_explorer_process_spawned`, and real non-zero
  process-callout publication for bootstrap plus `pi=2..6`. Review adjustment: B1 now moves to the
  thread half: call win32k's thread-create callout with real thread/process fields and kernel event
  services, then retire the `W32THREAD` placeholder path.
- B1 cleanup. Removed the `W32THREAD` placeholder allocator path and now require win32k's
  thread-create callout to publish a real `THREADINFO` through `PsSetThreadWin32Thread`. The
  executive seeds the routed `ETHREAD` with the compiled ReactOS x64 `Teb`, `Process`, `Cid`, and
  `ThreadsProcess` offsets, maps canonical high `KUSER_SHARED_DATA` for win32k, backs the event APIs
  used by `InitThreadCallback`, and stores `Win32Process` in the actual `EPROCESS.Win32Process`
  field rather than only in a side slot. Validation: `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none` passes with the existing warning
  set; `.tmp/full-boot-w32thread-offsets-20260803-125016.log` shows `thread callout pi=1
  status=0x00000000 pti=0x000001000a016b70` and `NtUserProcessConnect(0x10FA)` returning
  `STATUS_SUCCESS`, with `PASS win32k_dispatch_loop_roundtrip` and `PASS
  win32k_dispatch_fault_via_reply_cap`. A previous run,
  `.tmp/full-boot-w32process-field-20260803-124536.log`, reached the broader desktop-painted pass.
  Review adjustment: B1 remains open because the routed `EPROCESS`/`ETHREAD` bodies are still
  win32k-hosted scratch objects selected through `WIN32K_CLIENT_*[pi]`; the next B1/B2 step is to
  derive those from process-manager/thread-manager objects and remove the per-PI client context
  arrays.
- B1/B2/B3 cleanup. `nt-process` now has explicit kernel object pointer slots for process and
  thread records, including PID/TID reverse lookups for `EPROCESS`/`ETHREAD` bodies. The win32k
  shared dispatch ABI now carries the caller's real TID, and the win32k host removed the old
  `WIN32K_CLIENT_*[pi]` context arrays plus the fixed bootstrap `PH_EPROCESS`/`PH_ETHREAD`
  selection path. GUI process/thread context is now keyed by runtime PID/TID records and populated
  through the same process/thread callout path used for routed clients; the bootstrap DriverEntry
  context is allocated through that runtime path as well. Validation:
  `cargo test --manifest-path crates/nt-process/Cargo.toml` passed, and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`
  passed with the existing warning set. Review adjustment: B2 and B3 are complete. B1 remains open
  until the allocated `EPROCESS`/`ETHREAD` addresses are published back into `ProcessManager`, or
  allocated by the executive and handed to win32k, so process-manager object identity is
  authoritative end to end rather than mirrored by component-local GUI runtime records.
- B1 complete. The win32k shared dispatch ABI now carries ProcessManager-published `EPROCESS` and
  `ETHREAD` pointers when known, and win32k publishes the selected PID/TID plus `EPROCESS`,
  `ETHREAD`, `W32PROCESS`, and `W32THREAD` back through shared context slots before/after attach
  callouts. Service-loop win32k dispatches synchronize those publications into `ProcessManager`, so
  later GUI calls resolve object identity through the process/thread records instead of component-
  local scratch ownership. `ObReferenceObjectByHandle` no longer aliases arbitrary process-typed
  unknown handles to the current process; `NtUserProcessConnect` rewrites only
  `NtCurrentProcess()` or real process handles that ProcessManager resolves to the routed client.
  Validation: `cargo test --manifest-path crates/nt-process/Cargo.toml` passed, and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`
  passed with the existing 267-warning baseline. Review adjustment: workstream B is closed for the
  placeholder-object cleanup; the next dynamic-boundary work should move to C3/F1 or the D/E
  discovery and LPC routes unless full boot exposes a regression.
- B1 repair. Full boot exposed that `InitThreadCallback` cannot safely use the live hosted TEB VA
  inside win32k's component address space: winlogon's `NtUserProcessConnect` previously faulted at
  `win32k` RVA `0x39538` reading `TEB->PEB->ProcessParameters` from an image-window collision. The
  thread callout now gets a per-thread win32k-owned TEB/PEB/process-parameters mirror allocated from
  the win32k pool and seeded from PID/TID runtime context, while the live user TEB remains client
  state that the executive seeds after win32k publishes desktop/thread facts. The old shared
  kernel-TEB scratch fallback was removed from this path. Validation:
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none` passed with the existing warning baseline, and
  `.tmp/full-boot-dynamic-callout-teb-20260803.log` reached winlogon `NtUserProcessConnect`, real
  api7 callback redirection/return, and `thread callout tid=6 pi=2 status=0`. Review adjustment: the
  next full-boot frontier is user32 client setup after attach: `user32!UserClientDllInitialize+0x740`
  dereferences `gHandleTable->handles` with `gSharedInfo.aheList == NULL`, so the next C3/F1 target is
  real `USERCONNECT.siClient`/USER handle-table publication for non-CSRSS GUI clients.
- C3/F1 repair. `NtUserProcessConnect` `USERCONNECT` fix-up is now shared by the direct win32k
  dispatch path and the real `KeUserModeCallback`/`NtCallbackReturn` completion path. The win32k
  dispatch transport now carries original syscall arguments separately from the staged cross-address
  arguments, so callback-completed observers copy the filled `USERCONNECT` back to the caller's real
  user buffer while win32k still consumes the provider-owned shared frame. Validation:
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none` passed with the existing warning baseline, and
  `.tmp/full-boot-userconnect-original-args-20260803.log` got winlogon past the old
  `gHandleTable` null dereference into about 900 further real win32k/user32 initialization calls.
  Review adjustment: the next frontier is noninteractive hosted clients (`services.exe` and
  `lsass.exe`) reaching `NtUserProcessConnect`; they must either acquire real provider-owned GUI
  process state through the same dynamic identity route or fail before entering win32k, with no
  executive-owned fake success path.
- C3/F1 repair. api7 client-thread-startup callbacks now admit every registered hosted callback
  owner instead of being winlogon-only, while api0 and other user callbacks remain restricted to
  interactive GUI roles. The callback frame also carries primary-token AuthenticationId/SID context
  into win32k dispatch state so server-side security helpers can read caller token facts from a real
  per-process token record rather than a process-name special case. Focused validation passed:
  `cargo test -p nt-object-manager` and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`.
- B1/C3 repair. `NtUserSetThreadDesktop` preparation no longer zeroes `THREADINFO.rpdesk` while
  leaving `THREADINFO.PtiLink` on a ReactOS desktop list. `nt-object-manager` now exposes checked
  desktop thread-list unlink/link helpers, rejects live duplicate membership, and restores an empty
  self-linked `PtiLink` before the executive clears desktop fields for a real switch. Validation:
  `.tmp/full-boot-ptilink-unlink-20260803.log` reached `RUN_RC=0`, cleared the previous winlogon
  `NtUserSetThreadDesktop` fail-fast at win32k RVA `0x24b8a`, and passed
  `exec_win32k_desktop_painted` with natural `NtUserSwitchDesktop` framebuffer readback. Review
  adjustment: this boot regressed earlier full-stack green gates after the desktop switch:
  `exec_winlogon_sas_window`, real api0 nested/dead-client proofs, IDD_LOGON correlation/paint,
  LSA auth-port/logon, profile-copy/load, userinit, and explorer gates are red again. The next
  target is to restore the real SAS/dialog route on top of the stricter dynamic process/thread and
  service-callback boundaries, without reintroducing synthetic success paths.
- C3/F1 repair. User-callback resume context is now owned by the active callback frame instead of
  process-wide callback-client globals. The executive stages PID/TID, `EPROCESS`/`ETHREAD`, process
  role, top badge, PEB/TEB, scratch, and token-authentication SID facts through the shared callback
  frame, and win32k restores the current GUI/KPCR/THREADINFO context from that frame before resuming
  a parked continuation. The nested proof now drains real chained callback returns before declaring
  win32k idle, and the dead-client proof targets the most recent real WndProc callback with a real
  no-moving `SWP_FRAMECHANGED`/`WM_WINDOWPOSCHANGING` route instead of arming a synthetic callback.
  Validation: `cargo fmt --all`, `cargo test -p nt-user-callback`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, and `.tmp/full-boot-callback-resume-rerun-20260803.log` passed. The boot log
  reached `276/276`, including `PASS exec_user_callback_real_api0_nested_roundtrip`, `PASS
  exec_user_callback_dead_client_unwind`, `PASS exec_win32k_transport_call_nested`, `PASS
  exec_msgina_logon_dialog_painted`, and `PASS exec_explorer_process_spawned`. Review adjustment:
  the SAS/dialog/profile/userinit/explorer regression is closed again. Remaining open items are the
  hosted-image manifest handoff, provider-owned service GUI/GDI state, the driver/registry and LPC
  discovery workstreams, and the real WM_PAINT queue/framebuffer path.
- A2/C3 cleanup. The post-quiesce private-VM and win32k callback injection proofs no longer select
  their winlogon client through `pi == 2`, `WINLOGON_BADGE`, or a hardcoded PEB mirror. The service
  loop now resolves the interactive-logon process from registered hosted-process metadata, and the
  callback victim carries its runtime `pi`, process role, top badge, PEB mirror, and scratch layout
  into the proof client context. Validation: `cargo fmt --all` and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none` passed. A full boot attempt
  `.tmp/full-boot-dynamic-callback-victim-20260803.log` was stopped after serial output stalled
  before post-quiesce proof emission, so the next full-boot check should confirm the proof markers
  and the hosted-boot liveness frontier together.
- D2 started. `ZwSetSystemInformation(SystemLoadGdiDriverInformation)` no longer matches
  `dxg.sys`, `framebuf.dll`, or `kbdus.dll` through a local hardcoded branch or per-driver global
  image slots. The existing driver load hooks now register loaded GDI driver metadata into a bounded
  table, and the win32k import resolves the requested driver name only through that registered
  state. Validation: `cargo fmt --all` and `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none` passed. Review adjustment:
  D2 remains open for the registry/device side of display discovery and `NtQuerySystemInformation`
  module/device answers, but the GDI-driver system-information path is no longer name-switch owned.
- D3 started. The win32k `ZwOpenKey`/`ZwQueryValueKey` import shims no longer own unconditional
  synthetic `HKEY_*` handles or per-value `match hkey` branches for display and keyboard setup.
  `record_framebuf` and `record_kbdus` now publish a bounded registry mirror only after the
  corresponding hosted driver image is loaded, and the trampolines serve only registered mirror
  keys/values. Validation: `cargo fmt --all` and `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none` passed. Review adjustment:
  this is still a mirror, not the final Configuration Manager/device-interface path; D3 remains open
  to feed these keys from the real SYSTEM hive and replace the video `DEVICE_OBJECT` placeholder with
  a driver-created device object.
- D1 started. The first dynamic driver-launch proof no longer hardcodes
  `reactos\system32\drivers\npfs.sys` or an executive-selected FSD class. The rootserver reads the
  real SYSTEM hive `ControlSet001\Services\Npfs` service key, requires boot/system `Start`, derives
  FSD/device class from `Type`, normalizes NT/SystemRoot `ImagePath` values into the mounted ReactOS
  path, and passes that path/class to the existing isolated `load_driver` path. Missing or unsupported
  registry state now fails visibly instead of falling back to a synthetic launch. Validation:
  `rustfmt --edition 2021 --config skip_children=true components/ntos-executive/src/main.rs`,
  `git diff --check`, and `cargo check --manifest-path components/ntos-executive/Cargo.toml
  --target x86_64-unknown-none` passed. Review adjustment: D1 remains open for service-control
  driven launch beyond this NPFS proof and for the win32k GDI/display/keyboard preloads that still
  need real driver object ownership.
- D1/D3 continued. The win32k keyboard-layout host path no longer names `kbdus.dll` or publishes a
  fixed `Keyboard Layouts\00000409` registry mirror. The executive derives the layout id from real
  registry state (`HKU\.Default\Keyboard Layout\Preload\1`, with SYSTEM NLS default as another real
  registry source), reads that layout key's SYSTEM hive `Layout File`, validates the DLL leaf, loads
  `reactos\system32\<Layout File>`, registers the selected DLL with the GDI-driver table, and mirrors
  only the selected layout id/file pair back to win32k. Missing registry state now logs a visible
  keyboard-layout load failure; there is no hardcoded DLL success path. Validation:
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none` passed. Review adjustment: D1 still has display/DirectX preloads and D3 still
  has the hosted-process keyboard-layout key sentinel plus the display registry/device mirror.
- D1/D3 continued. The win32k display host path no longer pre-stages `framebuf.dll` through the
  storage host or publishes a fixed `Services\framebuf\Device0` registry mirror. The executive scans
  the real SYSTEM hive `ControlSet001\Services\*\Device0`, requires `InstalledDisplayDrivers`,
  `Device Description`, and `VgaCompatible`, validates that the selected display DLL exists on the
  mounted ReactOS filesystem, loads `reactos\system32\<selected display DLL>` through the dynamic
  pool loader, and registers the selected service/device-map values back to win32k. The old
  `FRAMEBUFBUF` mapping and storage-host file read are gone, and `IoGetDeviceObjectPointer` now
  succeeds only for the registered `\Device\Video0` route after display registration. Validation:
  `rustfmt --edition 2021 --config skip_children=true components/ntos-executive/src/main.rs`,
  `git diff --check`, and `cargo check --manifest-path components/ntos-executive/Cargo.toml
  --target x86_64-unknown-none` passed. Review adjustment: D1 still has DirectX/font preloads and
  broader service-control launch ordering; D3 still has a bounded win32k registry mirror and a
  temporary video object body until the Configuration Manager and real display miniport device stack
  can serve these imports directly.
- D3 continued. Removed the hosted-process `SYNTH_KBD_KEY` sentinel for
  `HKLM\System\CurrentControlSet\Control\Keyboard Layouts\<KLID>`. Early keyboard-layout opens still
  use the predefined-machine-root sentinel when advapi32 maps HKLM, but the layout subkey now has an
  exact key-shape check and resolves into the real SYSTEM hive through `resolve_key`; missing keys
  return `STATUS_OBJECT_NAME_NOT_FOUND`, and value reads on existing keys can flow through the normal
  hive-backed `NtQueryValueKey` path. Validation:
  `rustfmt --edition 2021 --config skip_children=true components/ntos-executive/src/main.rs
  components/ntos-executive/src/exec_handler.rs`, `git diff --check`, and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none` passed. Review adjustment: D3 still has the bounded win32k import registry
  mirror, synthetic CPU/HARDWARE and Winlogon-key compatibility keys, and the temporary video object
  body.
- D1 cleanup. Removed the storage-host staging buffers for `dxg.sys`, `dxgthk.sys`, and `ftfd.dll`.
  Win32k bring-up now reads those images from the mounted ReactOS filesystem into pool memory by
  path, then maps them into win32k exactly like the display/keyboard DLL path. The old `DXGBUF`,
  `DXGTHKBUF`, and `FTFDBUF` frame windows, atomics, storage-host file reads, and host-region
  mappings are gone; failures now report missing files or missing executive FS rather than a staged
  buffer miss. Validation:
  `rustfmt --edition 2021 --config skip_children=true components/ntos-executive/src/main.rs
  components/ntos-executive/src/win32k_glue.rs components/ntos-executive/src/win32k_subsystem.rs
  components/ntos-executive/src/spawn_hosts.rs components/ntos-executive/src/device_io.rs`,
  `git diff --check`, and `cargo check --manifest-path components/ntos-executive/Cargo.toml
  --target x86_64-unknown-none` passed. Review adjustment: D1 still needs real service-control/load
  ordering for GDI driver requests rather than bring-up pre-registration, plus driver-object/device
  ownership beyond the current win32k image-registration table.
