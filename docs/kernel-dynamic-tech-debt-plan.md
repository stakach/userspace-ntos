# Kernel Dynamic Tech Debt Plan

Last updated: 2026-08-10

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
- `[x]` A2: Replace the static hosted image table with a dynamic image/session registration
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
- `[x]` C3: Audit remaining direct win32k/client service shims and convert them to provider-owned
  dispatch or documented narrow kernel callbacks.

### D. Driver, Device, And Registry Discovery

- `[x]` D1: Replace hardcoded GDI/display/keyboard driver preloads with loader and service-control
  driven driver objects.
- `[x]` D2: Replace driver-name matches in system information calls with registered module/device
  state.
- `[x]` D3: Replace remaining win32k video/keyboard registry mirrors and temporary video object
  scaffolding with real hive data, Configuration Manager state, and driver-created device
  interfaces.

### E. LPC, CSR, SRM, And LSA

- `[x]` E1: Remove modeled CSR reply paths and require real CSR server rendezvous for connect and
  request/reply traffic.
- `[x]` E2: Replace fixed LPC port-name creation order with object-manager named-port lookup.
- `[x]` E3: Replace modeled SRM/LSA accept replies with real port messages and server-side
  processing.

### F. User32, GDI, And Paint Path Completion

- `[x]` F1: Remove user32/GDI fake handle mirrors and global cursor/class state that bypasses real
  object ownership.
- `[x]` F2: Complete api0 `WINDOWPROC` execution so `WM_PAINT` runs dialog/control paint procs
  instead of synthetic `LRESULT` completion.
- `[x]` F3: Replace modal-pump synthetic `PeekMessage`/`GetMessage(WM_PAINT)` scaffolding with
  queue state produced by real window invalidation and dispatch.
- `[x]` F4: Add framebuffer proof for the credential dialog after the real paint path is wired.

### G. Explorer Shell Chrome Pixels

- `[x]` G1: Keep generic sections, hosted-worker lifetime, and thread mechanism resources dynamic
  enough for genuine `userinit.exe` and `explorer.exe` launch without section or win32k pool
  exhaustion.
- `[x]` G2: Trace explorer shell-window paint from USER invalidation through real WndProc, GDI batch
  execution, surface dirtying, and framebuffer presentation until non-background shell chrome pixels
  are proven.
- `[x]` G3: Audit and reduce temporary shell-paint instrumentation now that the real framebuffer
  proof exists; keep only narrow counters that guard actual USER/GDI/surface boundaries, and replace
  any remaining modeled presentation helpers with real window/surface ownership.
- `[x]` G4: Add a stable framebuffer proof for explorer shell chrome, distinct from desktop
  background and cursor artifacts.

### H. Registry Namespace And Setup-State Cleanup

- `[x]` H1: Replace remaining exact-name winlogon HKLM registry arms with a real
  `\Registry\Machine` namespace resolver shared by predefined-root, absolute, and key-relative
  opens.
- `[x]` H2: Keep LiveCD/setup locale provisioning tied to real setup inputs: prefer
  `reactos\unattend.inf` `LocaleID` when present, otherwise use the staged SYSTEM hive's
  `Nls\Language\Default` value.
- `[x]` H3: Re-run one serialized boot after H1/H2 and require the post-SAS path to advance through
  `SetDefaultLanguage(NULL)` without reintroducing synthetic registry success.

### I. NT I/O Manager And Shell IPC Fidelity

- `[x]` I1: Honor NT overlapped event-handle tagging for file, pipe FSCTL, and directory I/O so
  ReactOS kernel32 can pass `OVERLAPPED.hEvent | 1` without failing event validation.
- `[x]` I2: Implement file I/O completion notification modes and audit completion-port packet/event
  suppression through `NtSetInformationFile(FileIoCompletionNotificationInformation)`.
- `[x]` I3: Re-run one serialized desktop boot from the current shell/RPC frontier and capture the
  next genuine red edge without reintroducing service-pipe or executable identity fallbacks.
- `[~]` I4: Fix the real service-control RPC/context-handle path now exposed by dynamic service
  startup, using NPFS/RPC/loader semantics rather than service-name, executable, or launch-order
  fallbacks.

### J. SEC_IMAGE And Memory Manager Fidelity

- `[x]` J1: Replace ad hoc image page-right classification with NT SEC_IMAGE allocation
  protections, including write-copy and execute-write-copy pages, so loader fixups and writable
  image data are backed by process-private ownership rather than broad writable mappings.
- `[~]` J2: Boot-verify writable image copy-on-write promotion under real ReactOS loader/service
  traffic and remove any remaining page-right callers that infer image semantics from section names
  or historical bootstrap assumptions.

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
- D3 continued. Removed the synthetic `SYNTH_WINLOGON_KEY` compatibility key and the selective
  `DefaultPassword`/`Userinit` value branches. `resolve_key` now lets
  `\Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` resolve through the real
  SOFTWARE hive, winlogon's PE-backed exact-name recovery mints a handle to that real key, and
  `NtQueryValueKey` observes `Userinit`/`DefaultPassword` reads after normal hive lookup instead of
  fabricating or suppressing values. The shell-frontier gate now counts real Winlogon-key value
  traffic rather than enforcing the old two-value surface. Validation:
  `rustfmt --edition 2021 --config skip_children=true components/ntos-executive/src/main.rs
  components/ntos-executive/src/exec_handler.rs`, `git diff --check`, and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none` passed. Review adjustment: this may expose the next real LSA/RPC/autologon
  behavior in full boot; that should be implemented in the LPC/LSA workstream rather than hidden by
  Winlogon-key filtering.
- A2/C3 cleanup. Message-buffer marshalling for `NtUserGetMessage`/`NtUserPeekMessage` now follows
  registered hosted-process role metadata instead of a fixed explorer `pi` check. The staged
  provider-owned MSG buffer path is limited to shell roles that require it; Winlogon keeps its real
  caller-owned MSG buffer path so the SAS/modal pump can observe queue state written by the provider
  directly. Validation:
  `rustfmt --edition 2021 --config skip_children=true components/ntos-executive/src/service_sec_image.rs`,
  `git diff --check`, and `cargo check --manifest-path components/ntos-executive/Cargo.toml
  --target x86_64-unknown-none` passed. Review adjustment: the broader
  `.tmp/full-boot-gui-msg-marshalling-20260803-214257.log` attempt was red after the real Winlogon
  key exposed `AutoAdminLogon`, so the validation proof moved to the follow-up autologon SAS route
  below rather than treating that red run as frontier-preserving.
- D3/F2/F3 repair. The real SOFTWARE Winlogon key enables ReactOS msgina's `AutoAdminLogon` branch:
  after SAS#1, msgina calls the real `WlxSasNotify`, which posts the second `WLX_WM_SAS` to
  Winlogon's SAS window instead of waiting for the executive's headless CAD injection after welcome
  notice paint. The executive now observes `Session->LogonState` immediately after SAS#1, accepts
  either the headless injected SAS or the real queue-retrieved SAS#2 as proof, latches
  `WINLOGON_SAS2_RETRIEVED`, and removed the old blind "subsequent SAS-window GetMessage" park so
  the real queue can deliver msgina's autologon post. Validation:
  `rustfmt --edition 2021 --config skip_children=true components/ntos-executive/src/main.rs
  components/ntos-executive/src/service_sec_image.rs`, `git diff --check`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, and `.tmp/full-boot-autologon-sas-route-20260803-223108.log` reached
  `RUN_RC=0` with 264/276 checks passed. The run passed `exec_winlogon_logged_out_sas`
  (`2nd-SAS injected=0 retrieved=1`), `exec_msgina_logon_dialog_painted`, credential input,
  LSA logon/SAM validation, `NtCreateToken`, `NtLoadKey`, profile copy/load, `WlxActivateUserShell`,
  and `exec_userinit_process_spawned`. Review adjustment: the current red frontier is no longer the
  Winlogon SAS/dialog path; it is `exec_desktop_shell_frontier`, the callback dead-client/nested
  transport selftests, `exec_lsa_worker_route`, `exec_userinit_shell_image_attempted`, and the
  downstream explorer gates.
- C3 repair. `NtUserLoadKeyboardLayoutEx` now stages its client-owned stack-tail
  `PUNICODE_STRING` KLID argument into the provider-owned win32k argument frame, forwards the real
  `dwNewKL`/`Flags` tail values, and returns visible NULL failure on bad probes instead of letting
  isolated win32k dereference a hosted-client descriptor. Validation:
  `rustfmt --edition 2021 --config skip_children=true components/ntos-executive/src/service_sec_image.rs`,
  `git diff --check`, and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none` passed. The full boot attempt
  `.tmp/full-boot-load-kbd-layout-20260803-224605.log` reached 272/276 checks, clearing the old
  userinit `0x125c` wall and passing the userinit shell-image and explorer spawn/callback/WndProc/COM
  gates. Review adjustment: the live red frontier is now explorer `NtGdiGetCharWidthW` (`0x10cb`),
  which faults inside isolated win32k on caller output/input pointer handling, plus the callback
  nested/dead-client proof counters and `exec_lsa_worker_route`.
- C3 repair. `NtGdiGetCharWidthW` now stages its optional caller WCHAR/glyph input buffer, the
  `fl`/output-buffer stack tail, and the returned INT/FLOAT-sized width array through the win32k
  shared argument frame. Bad input/output probes return visible FALSE rather than forwarding foreign
  pointers into isolated win32k. Validation: `git diff --check`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, and `.tmp/full-boot-char-width-marshal-20260803-225954.log` reached
  `276/276 executive->isolated-service checks passed`, with staged explorer `0x10cb` calls,
  `PASS exec_user_callback_real_api0_nested_roundtrip`, `PASS
  exec_user_callback_dead_client_unwind`, `PASS exec_win32k_transport_call_nested`, `PASS
  exec_lsa_worker_route`, and all userinit/explorer shell gates green. Review adjustment: the
  immediate boot frontier is green again; remaining plan work is the larger dynamic-debt backlog:
  boot/session image manifest handoff, service-control driver/device/registry ownership, real
  CSR/SRM/LSA LPC processing, provider-owned service GUI/GDI state, and the full real WM_PAINT
  queue/framebuffer path.
- A2 cleanup. Hosted bootstrap image metadata is now centralized in typed
  `HostedBootstrapManifestEntry` records instead of duplicated per-image constructor functions.
  The load loop derives `HostedBootstrapLoadSpec` values from that manifest, so path, role, NT image
  path, command line, top badge, and runtime constructor data stay in one checked shape while the
  old constructor scaffolding is removed. Validation:
  `rustfmt --edition 2021 --config skip_children=true components/ntos-executive/src/hosted_bootstrap.rs`,
  `git diff --check`, `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, and `.tmp/full-boot-bootstrap-manifest-20260803-231203.log` reached
  `276/276 executive->isolated-service checks passed`, including the userinit/explorer shell gates.
  Review adjustment: A2 remains open until SMSS/session-manager process creation can supply this
  topology dynamically and `hosted_process_runtime.rs` no longer bakes fixed runtime layouts in
  named per-image constructors.
- A2 cleanup. The fixed hosted-process runtime layouts are now immutable
  `HostedProcessRuntime` descriptors instead of named per-image factory functions. The bootstrap
  manifest carries the descriptor directly, derives image `pi` from it, and SMSS demo/live
  registrations use the same descriptor as the normal SEC_IMAGE loop. Validation:
  `rustfmt --edition 2021 --config skip_children=true components/ntos-executive/src/hosted_process_runtime.rs components/ntos-executive/src/hosted_bootstrap.rs components/ntos-executive/src/main.rs components/ntos-executive/src/service_sec_image.rs`,
  `git diff --check`, `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, and `.tmp/full-boot-runtime-descriptors-rerun-20260803-233453.log` reached
  `276/276 executive->isolated-service checks passed`, including IDD_LOGON framebuffer evidence,
  userinit/explorer spawn, real callback transport, and explorer WndProc/COM gates. Review
  adjustment: A2 still needs the real dynamic endpoint: SMSS/session-manager process creation must
  provide these records, and the fixed VA/cap placement should move behind an allocator rather than
  staying as static descriptor data.
- D3 continued. Removed the `SYNTH_CPU_KEY` sentinel and the per-value
  `Identifier`/`VendorIdentifier` branches from registry open, enumeration, and query handling.
  The executive now seeds the kernel-owned volatile HARDWARE registry hierarchy in the normal
  overlay from live CPUID-derived processor facts, so SMSS reads ordinary registry handles and the
  generic `NtEnumerateValueKey`/`NtQueryValueKey` paths serve the CPU values. The stale
  `is_synth_key` naming was also replaced with `is_virtual_registry_key` for overlay/predefined-root
  targets. Validation: `rustfmt --edition 2021 --config skip_children=true
  components/ntos-executive/src/exec_handler.rs components/ntos-executive/src/main.rs`,
  `git diff --check`, and `cargo check --manifest-path components/ntos-executive/Cargo.toml
  --target x86_64-unknown-none` passed. Full boot attempt
  `.tmp/full-boot-volatile-hardware-reg-20260803-235006.log` reached userinit/explorer and repeated
  real api0 explorer `WM_PAINT` callbacks before being manually stopped; review adjustment: the CPU
  HARDWARE compatibility key is closed, while the live frontier for the next plan slice is F2/F3
  paint invalidation/queue completion plus D3's remaining win32k registry/device mirrors.

### 2026-08-04

- C3/F2 repair. `NtUserMessageCall` now has explicit cross-address-space stack-tail marshalling for
  the simple `FNID_DEFWINDOWPROC` and `FNID_SENDMESSAGE` shapes used by client-side user32 during
  nested api0 paint/message callbacks. The executive probes `ResultInfo`, `dwType`, and `Ansi` from
  the hosted caller stack, stages an optional provider-owned result slot in the win32k argument
  frame, forwards the tail through `win32k_dispatch_wide`, and copies the result slot back only after
  a successful provider return. Unsupported message-call shapes still take the existing raw path so
  they remain visible as future boundary work instead of gaining a silent success path. Validation:
  `rustfmt --edition 2021 --config skip_children=true components/ntos-executive/src/service_sec_image.rs`,
  `git diff --check`, and `cargo check --manifest-path components/ntos-executive/Cargo.toml
  --target x86_64-unknown-none` passed. The broader boot attempt
  `.tmp/full-boot-message-call-marshal-20260804-000837.log` was manually stopped after reaching
  real winlogon/services/LSASS GUI-provider initialization, msgina loading, and LSA/RPC setup; it did
  not reach the explorer `WM_PAINT` loop before the stop, so F2 remains open. Review adjustment:
  the next executable cleanup target is the remaining service/class/cursor/DC mirror surface under
  C3/F1, plus E3's modeled SRM/LSA accept path.
- C3/F1 cleanup. Removed the static per-`pi` service GUI PFN/class-atom arrays
  (`SVC_CLIENT_PFNA_SCROLLBAR`, `SVC_CLIENT_PFNW_SCROLLBAR`, `SVC_CLIENT_HMOD_USER32`, and
  `SVC_SCROLLBAR_CLASS_ATOM`) plus their global boot-gate counters. Non-interactive service
  user32 PFNs and the service ScrollBar atom now live in an `ExecNtHandler`-owned fixed runtime
  table keyed by the real ProcessManager PID, and the post-loop proof reads a quiesced snapshot from
  that runtime table instead of from slot globals. Validation:
  `rustfmt --edition 2021 --config skip_children=true components/ntos-executive/src/main.rs
  components/ntos-executive/src/exec_handler.rs components/ntos-executive/src/service_sec_image.rs`
  and `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none` passed. Review adjustment: F1 remains open for the session-global
  cursor/class/stock-object mirrors and the remaining WSS_NOIO service GDI leaf branches; those
  should move behind provider-owned per-process/session GUI state rather than returning to
  executive-owned identity slots.
- C3/F1 cleanup. Moved the session GDI stock-object cache and service stock hit/miss counters out
  of root-module globals (`GLOBAL_GDI_STOCK_OBJECT_MIRROR`,
  `GLOBAL_GDI_STOCK_OBJECTS_OBSERVED`, `SVC_GDI_STOCK_OBJECT_HITS`, and
  `SVC_GDI_STOCK_OBJECT_MISSES`) into `Win32kSessionRuntime`, reset and accessed through
  `ExecNtHandler`. Service `NtGdiGetStockObject`, zero-sized service `NtGdiCreateBitmap`, and the
  post-dispatch real stock observation path now use explicit handler methods, and the post-loop
  proof reads a quiesced session-runtime snapshot. Validation:
  `rustfmt --edition 2021 --config skip_children=true components/ntos-executive/src/main.rs
  components/ntos-executive/src/exec_handler.rs components/ntos-executive/src/service_sec_image.rs
  components/ntos-executive/src/service_gui_runtime.rs
  components/ntos-executive/src/win32k_session_runtime.rs` and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none` passed. Review adjustment: the remaining F1 globals are cursor,
  built-in-class, class-atom-name, and ScrollBar class identity state; the next slice should keep
  moving those into provider/session runtime state before tackling the semantic WSS_NOIO GDI
  leaves.
- C3/F1 cleanup. Moved the session cursor identity mirror and built-in class atom mirror out of
  root-module globals (`GLOBAL_CURSOR_MIRROR`, `GLOBAL_CURSOR_IDENTITIES_OBSERVED`,
  `GLOBAL_CURSOR_PROMOTIONS`, `USERINIT_GLOBAL_CURSOR_*`, `GLOBAL_BUILTIN_CLASS_MIRROR`,
  `GLOBAL_BUILTIN_CLASSES_OBSERVED`, `USERINIT_BUILTIN_CLASS_*`, and
  `USERINIT_DIALOG_CLASS_ATOM`) into `Win32kSessionRuntime`. Shell/service cursor lookups, shell and
  service built-in class lookups, Winlogon cursor/class observations, and the userinit proof counters
  now all go through explicit handler methods and post-loop session snapshots. Validation:
  `rustfmt --edition 2021 --config skip_children=true components/ntos-executive/src/main.rs
  components/ntos-executive/src/exec_handler.rs components/ntos-executive/src/service_sec_image.rs
  components/ntos-executive/src/service_gui_runtime.rs
  components/ntos-executive/src/win32k_session_runtime.rs` and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none` passed. Review adjustment: F1's remaining session-global state is class atom
  name resolution and ScrollBar class identity, followed by the semantic WSS_NOIO GDI leaves.
- C3/F1 cleanup. Moved the class atom-name mirror and ScrollBar class identity/userinit
  classinfo counters out of root-module globals (`GLOBAL_CLASS_ATOM_NAME_MIRROR`,
  `GLOBAL_CLASS_ATOM_NAMES_OBSERVED`, `GLOBAL_CLASS_ATOM_NAME_MIRROR_*`,
  `GLOBAL_SCROLLBAR_CLASS_*`, and `USERINIT_SCROLLBAR_CLASSINFO_*`) into
  `Win32kSessionRuntime`. Shell `NtUserGetAtomName`, post-dispatch class-name observation, service
  ScrollBar classinfo synthesis, and userinit ScrollBar proof counters now go through explicit
  `ExecNtHandler` session methods, and the userinit/explorer post-loop summaries read quiesced
  session snapshots. Validation:
  `rustfmt --edition 2021 --config skip_children=true components/ntos-executive/src/main.rs
  components/ntos-executive/src/exec_handler.rs components/ntos-executive/src/service_sec_image.rs
  components/ntos-executive/src/service_gui_runtime.rs
  components/ntos-executive/src/win32k_session_runtime.rs`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `git diff --check`, and an old-symbol source search passed. Review
  adjustment: the root user32/GDI mirror state from F1 is now gone; F1 remains open for the
  remaining semantic WSS_NOIO service GUI/GDI branches and the larger provider-owned per-process
  GUI/GDI ownership model.
- A2/C3/F1 cleanup. Win32k dispatch and user-callback completion diagnostics no longer key their
  winlogon/userinit/explorer/service decisions off fixed hosted-process slots. The service-loop
  dispatcher now snapshots the registered hosted-process role once per win32k dispatch, uses that
  metadata for modal-pump budgeting, GDI/client-buffer marshalling, USERCONNECT/GDI shared-table
  publication, shell message staging, and winlogon/userinit/explorer proof counters, and removes the
  old helper predicates that wrapped static `pi` checks. Callback completion and NCCREATE tracing now
  classify clients through the process role carried by the active callback frame. Validation:
  `rustfmt --edition 2021 --config skip_children=true components/ntos-executive/src/service_sec_image.rs components/ntos-executive/src/win32k_glue.rs`
  and `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none` passed. Review adjustment: A2/C3/F1 remain open for the remaining measured
  winlogon frontier probes, semantic WSS_NOIO service branches, and the final provider-owned
  per-process GUI/GDI ownership model.
- C3/F1 cleanup. Removed the noninteractive-service executive leaf result for `NtGdiInit`; services
  now call ReactOS win32k's real `NtGdiInit` provider entry like other clients. The remaining service
  `NtGdiOpenDCW` NULL path is no longer keyed by role alone: win32k now exposes a narrow query over
  the real `Service-*` window-station body recorded for the caller token, and the executive returns
  the NULL display-DC result only when that object exists and its `WINSTATION_OBJECT.Flags` includes
  `WSS_NOIO`. Validation:
  `rustfmt --edition 2021 --config skip_children=true components/ntos-executive/src/service_sec_image.rs components/ntos-executive/src/win32k_subsystem.rs`
  and `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none` passed. Review adjustment: F1/C3 remain open for service cursor/class/stock
  reuse and process-owned GDI allocation, but the init/DC leaves now depend on provider or
  provider-created object state instead of an unconditional service identity shortcut.
- E3 cleanup. The LSA rendezvous runtime no longer initializes parked server/client process identity
  to fixed LSASS/winlogon slots. Server and client `pi`/badge records now start explicitly unset,
  every use of a parked `pi` goes through a checked load, and the client-side rendezvous context is
  cleared after a connect, request/reply, or server-wall wake. The obsolete live-hosted-PID helper
  left behind by the metadata migration was removed as dead code. Validation:
  `rustfmt --edition 2021 --config skip_children=true components/ntos-executive/src/service_sec_image.rs`
  and `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none` passed. Review adjustment: E3 remains open because the LSA route still uses
  executive-mediated rendezvous state instead of a complete LPC port-message server path, but it no
  longer has fixed hosted-process identity defaults.
- D3 cleanup. `\Device\Video0` no longer resolves to fixed data-page `DEVICE_OBJECT`/`FILE_OBJECT`
  placeholders. When the registry-selected display driver route is registered, win32k now allocates
  stable Video0 device/file object bodies from the win32k pool, seeds minimal x64 IO object headers,
  links `FILE_OBJECT.DeviceObject`, and only lets `IoGetDeviceObjectPointer` succeed if those runtime
  objects exist. Validation:
  `rustfmt --edition 2021 --config skip_children=true components/ntos-executive/src/win32k_subsystem.rs`
  and `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none` passed. Review adjustment: D3 remains open for replacing the bounded win32k
  registry mirror with direct Configuration Manager/device-interface service, but the Video0 object
  body is no longer a compile-time placeholder cell.
- A2/C3/F1 repair. The SEC_IMAGE service loop and `ExecNtHandler` construction no longer stage
  large hosted-image, process, and win32k session runtime state on the bounded rootserver stack.
  The loop consumes bootstrap load specs one at a time, moves serialized work arrays into BSS slots,
  clears win32k session mirrors in place, and initializes `ExecNtHandler` field-by-field inside its
  existing `MaybeUninit` slot instead of returning a large aggregate by value. Release prologues are
  back under the 16 KiB stack budget (`service_sec_image` about `0x1cf8`, `initialize_in` about
  `0x2d68`). The same repair maps the registered win32k pool into the executive VSpace because the
  dynamic bridge allocates provider-owned object bodies through win32k's own pool allocator. There
  is no synthetic object fallback: missing pool mapping still faults visibly, and successful object
  bodies come from provider-owned pool state. Validation:
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `components/ntos-executive/build.sh`, and
  `.tmp/full-boot-service-stack-final-20260804-014218.log` passed the old SEC_IMAGE and win32k-pool
  faults, reached CSRSS real loader/session startup, initialized win32k for CSRSS, spawned winlogon
  via SMSS/CSR, drove real winlogon win32k/user callbacks with natural desktop framebuffer readback,
  and continued into dynamic `services.exe` process/thread GUI attach before the run was manually
  stopped for checkpointing. Review adjustment: this closes the stack regression introduced by the
  runtime-dynamic cleanup, but A2 remains open for replacing the bootstrap manifest/runtime-layout
  descriptors with a session-manager handoff, C3/F1 remain open for the remaining provider-owned
  service GUI/GDI model, and the paint checklist status is reconciled in the next entry.
- F2/F3/F4 closed. The checklist had not been reconciled with the already-landed Phase 4 user
  callback work recorded in `docs/user-callback-dispatch.md`: the modal path now routes real
  `PeekMessageW`/`GetMessageW`/`DispatchMessageW` win32k SSNs for the correlated IDD_LOGON dialog,
  api0 WINDOWPROC callbacks run the real user32 dialog/control paint procedures, nested USER/GDI
  calls re-enter win32k through the continuation stack, and the final gate is a framebuffer readback
  over the credential dialog rectangle. The current source confirms the old synthetic modal prefix
  has been replaced by real modal dispatch observation; the remaining `NtUserGetMessage` preflight is
  the general NT `PeekMessage(PM_NOREMOVE)` empty-queue guard so a blocking wait cannot suspend the
  single-threaded host, not a synthetic `WM_PAINT` source. Review adjustment: workstream F remains
  open only for F1's provider-owned service GUI/GDI cleanup.
- F1 cleanup. Removed the noninteractive-service `NtGdiCreateBitmap` zero-size `DEFAULT_BITMAP`
  success shortcut. Service bitmap handles are process-owned GDI objects, so the executive no longer
  borrows a session stock-object handle for `0x0` or `0xN` service bitmap requests. Until
  provider-owned service GDI allocation exists, every noninteractive service bitmap allocation fails
  visibly with NULL. Review adjustment: F1 remains open for `NtGdiGetStockObject` stock-handle reuse,
  service cursor/class/ScrollBar classinfo mirrors, and the final provider-owned per-process service
  GUI/GDI object model. Validation: `rustfmt`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `components/ntos-executive/build.sh`, `git diff --check`, and
  `.tmp/full-boot-service-bitmap-no-default-20260804-015323.log` passed through natural framebuffer
  readback, dynamic `services.exe`, the new service bitmap NULL path, and dynamic `lsass.exe` spawn.
- C3/F1 cleanup. Removed the service `NtGdiGetStockObject` mirror path and deleted the
  `nt-kernel-exec` stock-handle mirror module. Service stock-object requests now dispatch to the
  real win32k provider instead of reusing executive-learned handles, while the userinit gate keeps
  only a small observation counter proving real stock objects were returned by win32k. Review
  adjustment: F1 remains open for the cursor/class and ScrollBar classinfo service mirrors; C3
  remains open for proving each remaining service branch is either provider-owned dispatch or a
  narrow kernel callback. Validation: `rustfmt`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `components/ntos-executive/build.sh`, stale-reference `rg`, and `git diff --check`.
- C3/F1 cleanup. Moved the remaining cursor, built-in-class, and class-atom-name storage out of
  `nt-kernel-exec`; that crate now keeps only USER identity parsing/layout helpers, while
  `Win32kSessionRuntime` owns the bounded session catalogs for real win32k observations and
  promotions. Service and shell diagnostics now report these paths as `SESSION` hits/misses, and
  `NtGdiCreatePatternBrushInternal` reports `SERVICE-GDI owner missing` instead of mirror language.
  Review adjustment: F1/C3 remain open for replacing the WSS_NOIO service cursor/class/ScrollBar
  narrow session queries with real per-process service USER/GDI ownership and for proving each
  remaining service branch is provider-owned dispatch or an explicit kernel callback. Validation:
  `rustfmt`, `cargo test -p nt-kernel-exec`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, `components/ntos-executive/build.sh`,
  stale-reference `rg`, and `git diff --check`.
- C3/F1 cleanup. Removed the service GUI runtime table and the synthetic
  `exec_services_scrollbar_classinfo_mirrored` gate. Noninteractive service
  `NtUserFindExistingCursorIcon`, `NtUserRegisterClassExWOW`, and `NtUserGetClassInfo` now fail
  visibly with `SERVICE-USER owner missing` instead of sharing session cursor/class atoms or building
  an executive-owned `WNDCLASSEXW`. The `nt-kernel-exec` ScrollBar classinfo/PFN helpers were deleted
  with the runtime they supported. Review adjustment: F1/C3 now has no service-side USER/GDI success
  fallback for cursor/class/classinfo; the remaining work is implementing real service
  PROCESSINFO/class/cursor ownership in win32k so those calls can dispatch to provider-owned state.
  Validation: `rustfmt`, `cargo test -p nt-kernel-exec`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `components/ntos-executive/build.sh`, stale-reference `rg`, and `git diff --check`.
- C3/F1 cleanup. Removed the remaining noninteractive-service USER/GDI leaf fabrications for
  `NtUserFindExistingCursorIcon`, `NtUserRegisterClassExWOW`, `NtUserGetClassInfo`,
  `NtGdiCreateBitmap`, `NtGdiCreatePatternBrushInternal`, and the WSS_NOIO `NtGdiOpenDCW` shortcut.
  Those service calls now enter the registered win32k provider through the same arity-checked
  dispatch path as interactive clients, with the existing cross-address-space argument staging and
  copyback code doing the boundary work. The service window-station runtime was also narrowed to the
  token-to-handle association still used by win32k object lookup; the executive no longer mirrors
  provider `WINSTATION_OBJECT` bodies or reads WSS_NOIO flags to synthesize DC results. Review
  adjustment: C3/F1 now has no known executive-side service USER/GDI result fallback for the
  service attach path. Full boot validation reached the win32k desktop proof, real services/LSASS
  win32k connects, real provider returns for service/LSASS `NtGdiCreateBitmap` and
  `NtGdiCreatePatternBrushInternal`, and provider-owned `NtGdiOpenDCW` NULL results with win32k's
  `Didn't find a suitable PDEV` diagnostic instead of an executive WSS_NOIO shortcut. The new
  frontier is higher-level LSA/profile/userinit/explorer work plus auditing the remaining shell
  `SESSION` catalog queries and moving any required sharing behind proper win32k session/process
  ownership.
  Validation: `rustfmt --edition 2021 --config skip_children=true
  components/ntos-executive/src/service_sec_image.rs components/ntos-executive/src/win32k_subsystem.rs`,
  stale-reference `rg`, `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `components/ntos-executive/build.sh`, `git diff --check`, and
  `.tmp/full-boot-service-user-gdi-provider.log` passed the harness desktop gate with
  `230/275 executive->isolated-service checks passed`.
- C3/F1 cleanup. Removed the shell-side `SESSION` catalog result paths for `NtUserGetAtomName`,
  `NtUserFindExistingCursorIcon`, and built-in `NtUserRegisterClassExWOW`. The cursor,
  built-in-class, and class-atom-name catalogs were deleted from `Win32kSessionRuntime`; that runtime
  now keeps only observation/proof counters for provider-returned facts. Userinit proof counters are
  recorded only after real provider dispatch returns, so a shell cursor/class miss is no longer
  hidden by an executive-owned session reuse result. Review adjustment: F1 has no known
  executive-owned USER/GDI handle, cursor, class, atom-name, stock-object, classinfo, service bitmap,
  brush, or display-DC result path left, so F1 is closed. C3 remains open: the full boot now reaches
  a real provider-owned winlogon `NtUserGetAtomName(0x10ad)` path during the post-SAS Winlogon-key
  route and walls inside isolated win32k instead of falling back to a session catalog. The next C3
  step is to implement that syscall's proper cross-address-space input/output boundary for all GUI
  clients. Validation: `rustfmt --edition 2021 --config skip_children=true
  components/ntos-executive/src/service_sec_image.rs components/ntos-executive/src/exec_handler.rs
  components/ntos-executive/src/win32k_session_runtime.rs`, stale-reference `rg`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `git diff --check`, `components/ntos-executive/build.sh`, and
  `.tmp/full-boot-shell-session-catalog-removed.log` passed the harness desktop gate with
  `230/275 executive->isolated-service checks passed`; the boot log contains no old shell `SESSION`
  catalog hit/miss lines.
- C3 continued. `NtUserGetAtomName(0x10ad)` now has a provider-owned cross-address-space output
  boundary. The executive captures the caller `UNICODE_STRING`, stages the descriptor and writable
  buffer in the win32k argument frame, forwards only provider-owned pointers, and copies the returned
  atom name bytes back to the caller buffer without restoring the descriptor, matching ReactOS'
  observed contract for this syscall. Invalid output descriptors fail visibly with a zero return
  instead of sending a foreign pointer into isolated win32k. Validation:
  `rustfmt --edition 2021 --config skip_children=true components/ntos-executive/src/service_sec_image.rs`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `git diff --check`, and `.tmp/full-boot-get-atom-name-marshalled.log`
  passed the harness desktop gate with `229/275 executive->isolated-service checks passed`. The log
  shows real staged winlogon `NtUserGetAtomName` returns for atom `0x8002` and no old
  `RVA=0x001cbddb` wall. Review adjustment: C3 remains open. This unblocks the later post-SAS
  Winlogon-key path enough to expose the next provider-boundary/user-callback frontier:
  `WM_NCCREATE` api0 reaches nested `NtUserDefSetText(0x1080)`, fails to unwind that nested
  dispatch, and leaves one outstanding callback continuation. Noninteractive service/LSASS
  `NtGdiOpenDCW(0x10de)` still returns win32k's real NULL/PDEV failure and should stay visible until
  D3's display-device/registry ownership is replaced by real driver-created state.
- C3 continued. `NtUserDefSetText(0x1080)` now has a required provider-owned
  cross-address-space input boundary for interactive GUI clients. Winlogon/Userinit/Explorer
  callers no longer pass a raw client `LARGE_STRING` graph into isolated win32k: the executive
  probes the descriptor, validates `Length`/`MaximumLength`/ANSI shape, stages the string and a
  provider-owned descriptor in the win32k argument frame, preserves empty-buffer descriptors, and
  fails visibly with `FALSE` on invalid input instead of fabricating success. Validation:
  `rustfmt --edition 2021 --config skip_children=true components/ntos-executive/src/service_sec_image.rs`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, and `.tmp/full-boot-defsettext-winlogon-marshalled.log` passed the
  harness desktop gate with `234/275 executive->isolated-service checks passed`. The log shows real
  staged winlogon `NtUserDefSetText` returns and no old `RVA=0xf9c82997` wall. Review adjustment:
  C3 remains open for a final audit of remaining win32k/client marshalling branches. F3/F4 are
  re-opened as the active user-callback frontier: with the `0x1080` wall removed, the run now
  creates and correlates IDD_LOGON (`modal-ready=1`) but then observes the correlated dialog being
  destroyed before the modal paint proof, so the current source no longer satisfies the older green
  modal/framebuffer checklist recorded before the service USER/GDI fallback cleanup sequence.

- C3 continued. `NtGdiStretchDIBitsInternal(0x1082)` now has a provider-owned
  cross-address-space input boundary for interactive GUI clients. The executive reads the complete
  ReactOS x64 stack tail, stages the optional DIB bits and required `BITMAPINFO` in the win32k arg
  frame, forwards the original scalar shape with only `pjInit`/`pbmi` rebased, and fails visibly
  with a zero return if the client graph is unreadable or oversized. This removes the raw client
  heap pointers that made ReactOS `user32!BITMAP_LoadImageW` log `StretchDIBits failed!` while
  loading the combo-box bitmap during the winlogon dialog/control path. The same checkpoint grows
  the ntdll process heap behind the real `Peb->ProcessHeap` handle with bounded VM-backed segments,
  so process-heap exhaustion no longer requires private synthetic handles or caller-visible heap
  substitution. Validation: `cargo test -p nt-ntdll` passed 699 tests,
  `components/ntos-executive/build.sh` passed, `git diff --check` passed, and
  `.tmp/full-boot-stretchdibits-marshalled.log` shows staged `NtGdiStretchDIBitsInternal` returns
  and no `StretchDIBits failed`, combo `NCCREATE message failed`,
  `co_UserCreateWindowEx failed`, or StretchDIBits input-probe rejection. The run advanced beyond
  the previous combo/load-bitmap wall into real desktop paint work plus services/LSASS win32k calls;
  it was then manually stopped after continued post-desktop progress, so F3/F4 remain open until a
  natural modal/credential framebuffer proof is restored.
- D3 continued. Removed the bounded win32k registry key/value mirror for display and keyboard
  imports. win32k's `ZwOpenKey` import now decodes the requested NT key name and mints a distinct
  handle to either a mounted SYSTEM-hive key or the runtime `\Device\Video0` device-map route;
  root-relative opens against those handles are supported, `ZwClose` releases them, and
  `ZwQueryValueKey` reads service and keyboard-layout values from the real SYSTEM hive at query time.
  The win32k component now receives the staged SYSTEM hive buffer read-only, so these imports parse
  the same mounted regf bytes as the executive instead of a synthetic key/value mirror. Keyboard
  layout driver registration no longer seeds registry values; the Video0 device-map value is still
  derived from the display route published when the registry-selected display driver is hosted.
  Validation: `rustfmt --edition 2021 --config skip_children=true
  components/ntos-executive/src/main.rs components/ntos-executive/src/win32k_subsystem.rs`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `components/ntos-executive/build.sh`, `git diff --check`, and
  `.tmp/full-boot-win32k-registry-imports-clean.log` passed with `234/275
  executive->isolated-service checks passed`, `PASS exec_win32k_desktop_painted`,
  `PDEVOBJ_lChangeDisplaySettings status=0x0x00000000`, and natural framebuffer readback
  `changed 768/768, desktop-bg 768/768`. Review adjustment: the old win32k registry mirrors are
  gone, but D3 remains open for replacing the host-published Video0 device-map route and
  `EngDeviceIoControl` framebuffer intercept with a real miniport-created device object/interface and
  Configuration Manager DeviceMap publication.
- D3 cleanup. The remaining host-published `\Device\Video0` state moved out of
  `win32k_subsystem` into the executive-owned `video_device` boundary. Win32k no longer owns the
  device-map value, projected `DEVICE_OBJECT`/`FILE_OBJECT` bodies, or display IOCTL state; it only
  opens/query-routes the runtime Video0 key and delegates `IoGetDeviceObjectPointer` plus
  `EngDeviceIoControl` to that kernel boundary. The route still fails visibly when unpublished or
  when the miniport handle is not the registered Video0 object. Validation:
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `components/ntos-executive/build.sh`, and
  `.tmp/full-boot-video-device-boundary.log` passed the desktop gate with
  `PDEVOBJ_lChangeDisplaySettings status=0x0x00000000`,
  `[video-device] IOCTL_VIDEO_MAP_VIDEO_MEMORY`, `PASS exec_win32k_desktop_painted`, and the
  microtest sentinel. Review adjustment: D3 remains open until a real hosted
  videoprt/display-miniport stack creates the device object/interface and Configuration Manager
  publishes `HARDWARE\DEVICEMAP\VIDEO`.
- C3 repair. `NtUserCreateWindowEx(0x1077)` now stages class/version/window `LARGE_STRING` graphs
  for every GUI client instead of only capturing explorer strings or buffers inside the colliding
  main-image range. Built-in control names such as msgina's `ComboLBox` live in user32.dll, so
  isolated win32k must receive provider-owned counted strings regardless of which image backs the
  caller buffer. The legacy main-image-only capture helper and its colliding-image predicate were
  removed; unreadable string graphs now fail through the shared capture/probe path instead of being
  hidden by a synthetic create-window result. Validation:
  `rustfmt --edition 2021 --config skip_children=true
  components/ntos-executive/src/service_sec_image.rs`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, and
  `.tmp/full-boot-create-window-strings-all-gui-final.log` passed the desktop gate with
  `PASS exec_win32k_desktop_painted`, `PASS exec_msgina_idd_logon_correlated`, IDD_LOGON modal pump
  observation `steps=3/3 completed=1 paints=830`, `233/275 executive->isolated-service checks
  passed`, and no `ComboLBox`, class-not-found, listbox, or `co_UserCreateWindowEx failed`
  signatures. Review adjustment: C3 remains open for the broader win32k/client marshalling audit.
  F3/F4 remain open because `exec_msgina_modal_paint_prefix` and
  `exec_msgina_logon_dialog_painted` still fail with a desktop-colored credential rect
  (`non-desktop=0`). The post-quiesce nested/dead-client proof also remains open because the current
  raw `WM_NULL`/frame-change probes do not arm a callback (`callback-parked=0`); the failed
  RedrawWindow/WM_PAINT proof-harness experiment was not kept.
- C3/F3 continued. `NtGdiStretchDIBitsInternal(0x1082)` now stages bulk DIB/BMI input through a
  dedicated 2 MiB provider argument window shared between the executive and isolated win32k instead
  of reusing the generic 16 KiB argument frame. This keeps larger icon/control DIB payloads on the
  real provider-owned path and preserves visible failure semantics with bounded reason/size
  diagnostics for missing stacks, unreadable client tails, invalid layouts, overflows, and copy-in
  faults. Validation: `rustfmt --edition 2021 --config skip_children=true
  components/ntos-executive/src/win32k_subsystem.rs components/ntos-executive/src/main.rs
  components/ntos-executive/src/service_sec_image.rs`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, and
  `.tmp/full-boot-bulk-gdi-stage.log` were run. The boot was manually stopped after it became a live
  long-running session, so it has no final `[microtest done]` sentinel, but it advanced through
  winlogon into services and LSASS, recorded `winlogon` `0x1082=93`, staged 4096-byte
  `NtGdiStretchDIBitsInternal` payloads at `0x10007200000`, and contains no
  `NtGdiStretchDIBitsInternal input probe failed` or `StretchDIBits failed` signatures. Review
  adjustment: C3 remains open for the final win32k/client marshalling audit, while F3/F4 remain open
  until the modal paint queue and credential framebuffer proof have a terminating, natural gate.
- C3 repair. `NtUserFindExistingCursorIcon(0x103d)` now stages both caller-owned
  `UNICODE_STRING` descriptors and the `FINDEXISTINGCURICONPARAM` block before isolated win32k
  dispatch. Counted module/resource strings are copied into the provider-owned argument frame, while
  zero-length `MAKEINTRESOURCE` descriptors preserve their integer `Buffer` identity so ReactOS'
  atom/resource probe path still sees the expected shape. Invalid probes return a visible NULL
  result instead of forwarding foreign pointers or fabricating a cursor/icon handle. Validation:
  `rustfmt --edition 2021 --config skip_children=true
  components/ntos-executive/src/service_sec_image.rs`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, `git diff --check`, and
  `.tmp/full-boot-cursor-lookup-marshalled.log` passed through the microtest sentinel with
  `PASS exec_win32k_desktop_painted`, `PASS exec_desktop_shell_frontier`, `PASS
  exec_msgina_modal_paint_prefix`, `PASS exec_msgina_logon_dialog_painted`, `PASS
  exec_userinit_shell_image_attempted`, `PASS exec_userinit_global_cursor_reused`, `PASS
  exec_userinit_builtin_classes_reused`, `PASS exec_userinit_scrollbar_classinfo`, and `PASS
  exec_explorer_process_spawned`. F3/F4 are closed again by this terminating natural modal paint and
  credential framebuffer proof. Review adjustment: C3 remains open for the remaining explorer
  provider-boundary/client-callback route; the current red gates are
  `exec_explorer_create_window_strings_captured`,
  `exec_explorer_register_window_messages_captured`, `exec_explorer_user_callbacks_redirected`,
  `exec_explorer_wndproc_installed_by_client`, and `exec_explorer_shell_com_classes_served`. The
  older post-quiesce proof gates `exec_user_callback_dead_client_unwind`,
  `exec_win32k_transport_call_nested`, and `exec_lsa_worker_route` also remain open.
- C3 repair. `NtGdiCreateDIBitmapInternal(0x10a0)` now stages its caller-owned
  `BITMAPINFO` and optional init-bits buffer in the provider bulk argument window before isolated
  win32k dispatch, and forwards the ReactOS x64 stack-tail scalars in canonical 32-bit form. This
  avoids treating undefined high 32 bits in `DWORD`/`UINT`/`FLONG` stack slots as part of
  `cjMaxInitInfo`, `cjMaxBits`, `iUsage`, or `fl`, while still failing visibly with NULL on missing
  stacks, unreadable client graphs, invalid layouts, or bounded-copy failures. Validation:
  `rustfmt --edition 2021 --config skip_children=true
  components/ntos-executive/src/service_sec_image.rs`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, and
  `.tmp/full-boot-createdibitmap-low32.log` passed through the microtest sentinel with
  `271/275 executive->isolated-service checks passed`, `PASS exec_win32k_desktop_painted`,
  `PASS exec_msgina_logon_dialog_painted`, `PASS exec_msgina_credential_keystrokes_delivered`,
  `PASS exec_lsa_logon_user_reached`, `PASS exec_winlogon_user_shell_activated`,
  `PASS exec_userinit_process_spawned`, `PASS exec_explorer_process_spawned`, `PASS
  exec_explorer_user_callbacks_redirected`, `PASS exec_explorer_wndproc_installed_by_client`, and
  `PASS exec_explorer_shell_com_classes_served`. F3/F4 remain closed by the natural modal,
  credential, and desktop framebuffer proofs. Review adjustment: the older explorer
  create-window/message/callback/WndProc/COM gates are now green. C3 remains open for the remaining
  win32k/client marshalling audit; the current log still shows one
  `NtGdiStretchDIBitsInternal(0x1082)` input-probe rejection with a high-32-bit-tainted
  stack scalar. The persistent red gates are `exec_user_callback_real_api0_nested_roundtrip`,
  `exec_user_callback_dead_client_unwind`, `exec_win32k_transport_call_nested`, and
  `exec_lsa_worker_route`.
- C3 repair. `NtGdiStretchDIBitsInternal(0x1082)` now also canonicalizes its ReactOS x64
  stack-tail scalar slots before isolated win32k dispatch. The executive preserves signed `INT`
  coordinate/extent shape and truncates `DWORD`/`UINT` slots (`dwUsage`, `dwRop4`, `cjMaxInfo`,
  and `cjMaxBits`) to their declared 32-bit widths before rebasing `pjInit`/`pbmi` into the
  provider bulk argument window. This closes the remaining high-32-bit-tainted `cjMaxBits`
  rejection seen in the explorer path without adding a fallback success result. Validation:
  `rustfmt --edition 2021 --config skip_children=true
  components/ntos-executive/src/service_sec_image.rs`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, and
  `.tmp/full-boot-stretchdibits-low32.log` passed through the microtest sentinel with
  `271/275 executive->isolated-service checks passed`, `PASS exec_win32k_desktop_painted`,
  `PASS exec_msgina_logon_dialog_painted`, `PASS exec_msgina_credential_keystrokes_delivered`,
  `PASS exec_lsa_logon_user_reached`, `PASS exec_winlogon_user_shell_activated`, `PASS
  exec_userinit_process_spawned`, `PASS exec_explorer_process_spawned`, and `PASS
  exec_explorer_shell_com_classes_served`. The log contains staged `NtGdiStretchDIBitsInternal`
  payloads for winlogon and explorer and no `NtGdiStretchDIBitsInternal input probe failed`
  signature. Review adjustment: the known `0x1082` marshalling rejection is closed, but C3 remains
  open for the final win32k/client marshalling audit. The persistent red gates remain
  `exec_user_callback_real_api0_nested_roundtrip`, `exec_user_callback_dead_client_unwind`,
  `exec_win32k_transport_call_nested`, and `exec_lsa_worker_route`.
- C3 repair. `NtGdiCreateDIBSection(0x109b)` now stages the caller-owned `BITMAPINFO` and optional
  `PVOID *Bits` output through the provider bulk argument window before isolated win32k dispatch.
  The ReactOS x64 stack-tail `DWORD`/`UINT`/`FLONG` scalars are canonicalized to their declared
  32-bit shape while `dwColorSpace` keeps pointer width, and failures for missing stacks, unreadable
  client tails, invalid layouts, BITMAPINFO copy-in, or Bits copy-out return visible NULL results
  instead of forwarding raw explorer heap/stack pointers. Validation:
  `rustfmt --edition 2021 --config skip_children=true
  components/ntos-executive/src/service_sec_image.rs`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, and
  `.tmp/full-boot-createdibsection.log` passed through the microtest sentinel with
  `271/275 executive->isolated-service checks passed`, `PASS exec_win32k_desktop_painted`,
  `PASS exec_msgina_logon_dialog_painted`, `PASS exec_msgina_credential_keystrokes_delivered`,
  `PASS exec_lsa_logon_user_reached`, `PASS exec_winlogon_user_shell_activated`, `PASS
  exec_userinit_process_spawned`, `PASS exec_explorer_process_spawned`, and `PASS
  exec_explorer_shell_com_classes_served`. The old explorer `0x109b -> WALL` route is gone:
  observed `NtGdiCreateDIBSection` calls were marshalled and returned handles, including nested api0
  dispatches. Review adjustment: C3 remains open because the next explorer nested win32k wall is
  now `NtGdi*`/USER SSN `0x104e`, which still contaminates the transport proof gates. The persistent
  red gates remain `exec_user_callback_real_api0_nested_roundtrip`,
  `exec_user_callback_dead_client_unwind`, `exec_win32k_transport_call_nested`, and
  `exec_lsa_worker_route`.
- C3 repair. `NtUserGetIconInfo(0x104e)` now stages all caller-owned output graphs before isolated
  win32k dispatch: optional `ICONINFO`, optional `DWORD *pbpp`, and the module/resource
  `UNICODE_STRING` descriptors plus caller buffers. The first ReactOS explorer icon path uses
  output-only descriptors with `MaximumLength == 0`, so the marshaller now treats that probe as a
  size query instead of reading uninitialized `Length`/`Buffer` fields. Successful provider returns
  copy staged descriptor updates, low integer resource IDs, and returned string bytes back to the
  original client address space; probe/copy failures return visible `FALSE` results instead of
  forwarding raw explorer heap/stack pointers. Validation: `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none` and
  `.tmp/full-boot-geticoninfo.log` passed through the microtest sentinel with
  `275/275 executive->isolated-service checks passed`, `PASS exec_win32k_desktop_painted`,
  `PASS exec_msgina_logon_dialog_painted`, `PASS exec_msgina_credential_keystrokes_delivered`,
  `PASS exec_lsa_logon_user_reached`, `PASS exec_winlogon_user_shell_activated`,
  `PASS exec_userinit_process_spawned`, `PASS exec_explorer_process_spawned`, `PASS
  exec_explorer_user_callbacks_redirected`, `PASS exec_explorer_wndproc_installed_by_client`, and
  `PASS exec_explorer_shell_com_classes_served`. The old explorer `0x104e -> WALL` route is gone:
  the log shows five staged `NtUserGetIconInfo` provider dispatches and no `0x104e` wall. Review
  adjustment: the known explorer marshalling frontier is closed and the previous transport/LSA red
  gates are green; C3 remains open only for the final direct-shim audit.
- C3 complete. The remaining direct win32k service branches were audited after the
  `NtUserGetIconInfo` frontier closed. The executive-side branches are now one of three explicit
  categories: cross-address-space argument marshalling/copyback before or after provider dispatch,
  provider-result observation for gates/client TEB/GDI mappings, or a documented wait-park for
  blocking GUI message waits whose queue was first tested with real `NtUserPeekMessage(PM_NOREMOVE)`.
  The wait-park path no longer logs as a win32k provider `WALL`, so actual provider failures remain
  distinguishable from cooperative single-host-thread waits. Validation:
  `rustfmt --edition 2021 --config skip_children=true
  components/ntos-executive/src/service_sec_image.rs` and `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none` passed with the existing
  warning set. `.tmp/full-boot-c3-audit.log` also reached the microtest sentinel with
  `275/275 executive->isolated-service checks passed`, `SUCCESS -- the ReactOS stack booted and
  the win32k desktop painted (0x003a6ea5)`, `PASS exec_win32k_desktop_painted`,
  `PASS exec_explorer_process_spawned`, `PASS exec_explorer_user_callbacks_redirected`, and
  `PASS exec_lsa_worker_route`; the win32k transport proof reported `walled=0`. Review adjustment:
  workstream C is closed; the remaining open plan work is A2, D1-D3, and E1-E3.
- E1 complete. The `\Windows\ApiPort` established-message modeled success path was removed:
  `model_csr_request_reply` is gone, missing parked `CsrApiRequestThread` state now fails visibly,
  and CSR connects require a pending broker connection that the real CSRSS worker accepts. The CSRSS
  native-subsystem bootstrap now follows ReactOS' server-process path in ntdll by avoiding
  `NtSecureConnectPort` and publishing only the minimal early `ReadOnlyStaticServerData` that
  kernel32 reads before CSRSRV publishes its real shared section. Validation:
  `scripts/build_ntdll_dll.sh` passed and `.tmp/full-boot-e1-r2.log` was run to the login/LSA path
  before manual stop. The log shows real ApiPort accepts for winlogon, services, and LSASS
  (`conn=8/9/10`), multiple `real CsrApiRequestThread reply completed` records, natural desktop
  framebuffer readback after `NtUserSwitchDesktop`, and real IDD api0 callbacks for the logon UI.
  Review adjustment: E3 is the next LPC frontier because the same log still reports
  `NtConnectPort(\SeRmCommandPort) -> modeled SRM accept`; A2 and D1-D3 also remain open.
- E3 complete. The SRM command port is now kernel-owned state registered in the LPC broker during
  executive initialization, and LSASS' `NtConnectPort(\SeRmCommandPort)` drains the broker
  connection request, accepts it on the executive SRM side, completes the client handle, and records
  the established LPC connection. `\SeLsaInitEvent` is provisioned up front as an object-manager
  event instead of being auto-created by the LSASS open path. Removed the generic LPC request/reply
  modeled success path, the scoped LSASS unknown-port accept fallback, and the old modeled SRM
  connect. Validation: `cargo fmt --manifest-path components/ntos-executive/Cargo.toml`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, and `.tmp/full-boot-srm-rdv-20260804-082749.log` passed through the
  microtest sentinel with `PASS exec_srm_command_port_registered`,
  `[srm-rdv] kernel SRM accepted \SeRmCommandPort`, `PASS exec_lsass_lsa_init_running`, `PASS
  exec_lsass_signals_lsa_rpc_active`, `PASS exec_msgina_logon_dialog_painted`, and `PASS
  exec_win32k_desktop_painted`. Review adjustment: the remaining open plan work is A2, D1-D3, and
  E2.
- E2 complete. LPC listen ports are now registered as object-manager `Port` objects carrying their
  broker listen handles. `NtCreatePort` requires a real object name, broker port creation, and
  namespace registration; the old CSRSS `\Windows\ApiPort`/`\Windows\SbApiPort` creation-order
  naming and opaque-handle broker fallback are gone. CSR secure connects, generic `NtConnectPort`,
  SRM, and LSA server receive routing now resolve the named port object dynamically instead of
  reading fixed global listen handles. Validation: `cargo fmt --manifest-path
  components/ntos-executive/Cargo.toml`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, `git diff --check`, and
  `.tmp/full-boot-lpc-port-objects-20260804-084449.log` reached the microtest sentinel with
  `PASS exec_srm_command_port_registered`, `[srm-rdv] kernel SRM accepted \SeRmCommandPort`,
  `PASS exec_lsass_lsa_init_running`, `PASS exec_lsa_auth_port_connected`, and
  `PASS exec_win32k_desktop_painted`. The remaining red frontier matches
  `.tmp/full-boot-srm-rdv-20260804-082749.log`, so this cleanup preserved the current boot state.
- D2 complete. `NtQuerySystemInformation(SystemModuleInformation)` now reports the live
  kernel-module registry instead of rejecting class 11 or answering from name-specific branches.
  The registry is populated only by actual PE load paths: generic `load_driver` instances,
  `win32k.sys`, and the win32k-hosted GDI/font/display/keyboard images after they are mapped.
  The NT5 x64 `RTL_PROCESS_MODULES` layout and short-buffer policy live in `nt-syscall` with
  host tests; the executive syscall body only snapshots registered module state and copies the
  encoded result to the caller. Validation: `cargo test --manifest-path
  crates/nt-syscall/Cargo.toml system_information`, `cargo fmt --manifest-path
  crates/nt-syscall/Cargo.toml`, `cargo fmt --manifest-path components/ntos-executive/Cargo.toml`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, and `git diff --check` passed. Review adjustment: D2 is closed; the
  remaining open plan work is A2, D1, and D3.
- D1 continued. `SystemLoadGdiDriverInformation` now uses a real component-to-executive
  rendezvous instead of relying on win32k bring-up preloads. The win32k import extracts the requested
  GDI driver leaf, checks the registered driver table, and sends a bounded `W32_GDI_LOAD_LABEL`
  request through the shared component pump when the driver is not loaded. The executive side
  validates the leaf and performs the filesystem/capability work in root context, demand-loading
  `dxg.sys`, the registry-selected display driver, or the registry-selected keyboard layout only
  when win32k asks for that leaf. Display registry/device-route publication is still available before
  win32k probes `HARDWARE\DEVICEMAP\VIDEO`, but the display image and keyboard layout image are no
  longer eagerly hosted during win32k initialization. Validation:
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none` passed, and `.tmp/full-boot-gdi-load-rendezvous-20260804.log` reached the
  microtest sentinel with demand-loaded `dxg.sys`, `framebuf.dll`, and `kbdus.dll`, `PASS
  exec_win32k_desktop_painted`, and `PASS exec_msgina_logon_dialog_painted`. Review adjustment: D1
  remains open for `ftfd.dll`'s static win32k import load contract and for full service-control
  driver object/device ownership beyond the current GDI-driver image registration table.
- D1 continued. The named `ftfd.dll` preload is gone. Win32k non-native static imports are now
  discovered from win32k's own PE import descriptors, loaded from System32 into bounded static-import
  image slots, registered as system modules, and IAT-patched against the loaded dependency's real
  exports. The loader records discovered/loaded/patched/failure counters, and
  `exec_win32k_load_contract` now requires `deps=1 loaded=1 iat-patches=34 failures=0`, so unresolved
  static imports fail visibly instead of silently continuing with unresolved dependency thunks. The
  shared PE driver loader's relocation and import-table walking is also bounded to the destination
  image span. Validation: `cargo fmt --manifest-path components/ntos-executive/Cargo.toml`, `cargo
  check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, and
  `.tmp/full-boot-win32k-static-imports-gated-20260804.log` reached the microtest sentinel with
  `PASS exec_win32k_load_contract`, `PASS exec_win32k_desktop_painted`, `PASS
  exec_msgina_modal_paint_prefix`, `PASS exec_msgina_logon_dialog_painted`, and `243/276`
  executive-to-isolated-service checks passing. Review adjustment: D1 remains open for
  service-control-created driver objects/device ownership and for replacing the fixed static-import
  image slot with dynamic driver-image address allocation.
- D3 continued. `\Device\Video0` no longer exposes two anonymous pool blocks as the display object
  boundary. The SYSTEM-hive selected display service name is carried into the win32k display
  registration, and `video_device` publishes a registered route with projected NT `DRIVER_OBJECT`,
  `DEVICE_OBJECT`, and `FILE_OBJECT` bodies linked through the expected x64 fields. `IoGetDeviceObjectPointer`
  and `EngDeviceIoControl` now require that registered projection, and the desktop gate proves
  `exec_video_device_objects_registered` before accepting framebuffer paint. Validation: `cargo fmt
  --manifest-path components/ntos-executive/Cargo.toml`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, `git diff --check`, and
  `.tmp/full-boot-video-objects-20260804.log` reached the microtest sentinel with
  `[video-device] projection ready=1`, `PASS exec_video_device_objects_registered`, `PASS
  exec_win32k_desktop_painted`, `PASS exec_msgina_modal_paint_prefix`, `PASS
  exec_msgina_logon_dialog_painted`, and `244/277` executive-to-isolated-service checks passing.
  Review adjustment: D3 remains open for a real videoprt/miniport-created device stack and any
  remaining keyboard/device route scaffolding.
- D1 continued. Win32k static-import dependencies still come from win32k's PE import descriptors,
  but their placement no longer uses a fixed `WIN32K_STATIC_IMPORT0` slot. The executive reads each
  dependency PE, derives the required frame count from `SizeOfImage`, reserves a bounded VA span from
  the win32k static-import arena, and maps/loads/patches that image at the allocated base. The old
  `WIN32K_STATIC_IMPORT_SLOTS` and exported slot constants are gone; PE parse/allocation failures
  increment the loader failure counter and fail the visible load-contract gate. Validation:
  `cargo fmt --manifest-path components/ntos-executive/Cargo.toml`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, `git diff --check`, and
  `.tmp/full-boot-static-import-allocator-20260804.log` reached the microtest sentinel with
  `hosted static win32k import ftfd.dll ... base=0x0000010008700000 frames=248 iat-patched=34`,
  `PASS exec_win32k_load_contract`, `PASS exec_video_device_objects_registered`, `PASS
  exec_win32k_desktop_painted`, `PASS exec_msgina_modal_paint_prefix`, `PASS
  exec_msgina_logon_dialog_painted`, and `244/277` executive-to-isolated-service checks passing.
  Review adjustment: D1 remains open for service-control-created driver objects and real device
  ownership beyond the current GDI/display driver request path.
- D1 continued. Removed the last static `DriverSpec`/`DRIVERS` proof-driver list from the
  executive. `IrpFsdTest.sys` is now declared as
  `ControlSet001\Services\IrpFsdTest` in the generated config hive with `ImagePath`, `Type`, and
  `Start`; the boot path decodes that hive, applies the same boot/system driver policy used for
  regf-backed services, and launches the second isolated IRP driver from service metadata. The
  missing/malformed-service path now leaves the launch gate visibly red instead of falling back to a
  compiled-in path. Validation: `cargo fmt --manifest-path crates/nt-hive-core/Cargo.toml`,
  `cargo fmt --manifest-path components/ntos-executive/Cargo.toml`,
  `cargo test --manifest-path crates/nt-hive-core/Cargo.toml
  generated_hive_declares_irp_fsd_test_service`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, `git diff --check`, and
  `.tmp/full-boot-service-driven-proof-driver-20260804.log` reached the microtest sentinel with
  `SYSTEM.DAT ... size=663`, `Config Manager decoded hive (663 bytes)`, `launching service
  IrpFsdTest from config hive path=reactos\system32\drivers\irpfsdtest.sys`, `PASS
  exec_second_irp_driver_via_harness`, `PASS exec_pump_screens_bound_notification`, `PASS
  exec_fsd_on_shared_harness`, `PASS exec_win32k_load_contract`, `PASS
  exec_video_device_objects_registered`, `PASS exec_win32k_desktop_painted`, `PASS
  exec_msgina_modal_paint_prefix`, `PASS exec_msgina_logon_dialog_painted`, and `244/277`
  executive-to-isolated-service checks passing. Review adjustment: D1 remains open for real
  IoManager/service-control-created `DRIVER_OBJECT`/`DEVICE_OBJECT` ownership; D3 remains open for a
  real videoprt/miniport-created video device stack.
- D1 continued. The Object Manager service ABI now supports typed `OB_OP_CREATE_DRIVER` and
  `OB_OP_CREATE_DEVICE` requests, with client/server support and host coverage. The live
  driver-launch `IoCreateDevice` path validates and captures the driver-declared `DeviceName`
  instead of treating the component pool pointer as the only device identity, and malformed
  `UNICODE_STRING` inputs fail with `STATUS_INVALID_PARAMETER`. `IoCreateSymbolicLink` no longer
  blindly succeeds; it captures validated link/target declarations for root-side namespace
  publication. NPFS now publishes `\Driver\Npfs` and the captured `\Device\NamedPipe` through
  Object Manager before accepting the existing IRP gates. Validation:
  `cargo test --manifest-path crates/nt-object-server/Cargo.toml`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, `git diff --check`, and
  `.tmp/full-boot-driver-io-objects-20260804.log` reached the microtest sentinel with `PASS
  npfs_driver_object_registered`, `PASS npfs_named_device_declared`, `PASS
  npfs_device_object_registered`, `PASS exec_fsd_on_shared_harness`, `PASS
  exec_video_device_objects_registered`, `PASS exec_win32k_desktop_painted`, `PASS
  exec_msgina_logon_dialog_painted`, and `247/280` executive-to-isolated-service checks passing.
  Review adjustment: D1 remains open because guest-visible `DRIVER_OBJECT`/`DEVICE_OBJECT` bodies
  are still component pool projections and IRPs still dispatch by component instance/device pointer;
  the next D1 step should move dispatch/projection ownership into a proper IoManager boundary.
- A2 complete. Bootstrap hosted-image records now carry only image/session intent; SMSS is registered
  as process index 0 and child process indexes are derived from manifest order at load time. Runtime
  placement is allocated when loaded image metadata is admitted into the runtime catalog via
  `register_hosted_process_runtime_for_image`, preserving the current VA bands while removing the
  per-image `*_PROCESS_RUNTIME` constants and manifest runtime payloads. Standalone SMSS SEC_IMAGE
  demos use the same registration path, so the executive no longer has a parallel static runtime
  table to fall back to. Validation: `cargo check --manifest-path components/ntos-executive/Cargo.toml
  --target x86_64-unknown-none`, `git diff --check`, and
  `.tmp/full-boot-hosted-runtime-allocator-20260804.log` reached the microtest sentinel with
  `247/280 executive->isolated-service checks passed`, `PASS
  exec_process_manager_dynamic_allocations`, `PASS exec_services_spawned`, `PASS
  exec_lsass_spawned`, `PASS exec_video_device_objects_registered`, `PASS
  exec_win32k_desktop_painted`, `PASS exec_msgina_logon_dialog_painted`, and
  `PASS exec_fsd_on_shared_harness`. Review adjustment: the remaining static policy is the
  bootstrap manifest itself and the conserved VA-band layout; those are now future session-manager
  and address-space allocator work, not hosted-image-table fallbacks.
- D1 continued. Driver/device namespace publication now stores canonical executive I/O route ids in
  Object Manager `Driver`/`Device` bodies instead of component instance numbers or guest pool
  pointers. `OB_OP_QUERY_OBJECT` returns fixed route metadata for Driver/Device/File bodies, NPFS
  binds `\Driver\Npfs` and `\Device\NamedPipe` by querying Object Manager metadata, and public IRP
  dispatch helpers route by driver id, device id, Object Manager device object id, or the
  driver-declared named-device route. The raw component instance dispatcher is now private transport
  machinery, redundant `register_npfs` re-registration is gone, and the second proof driver uses its
  driver route id even though it has no control device. Validation: `cargo test --manifest-path
  crates/nt-object-server/Cargo.toml`, `cargo fmt --manifest-path components/ntos-executive/Cargo.toml`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  and `git diff --check` passed. Review adjustment: D1 remains open until these executive route
  tables are folded into the canonical `nt-io-manager` driver/device stores and driver-created
  projections are owned from that boundary rather than `driver_launch`.
- D1 continued. The route ids published through Object Manager are now actual generation-protected
  `nt-io-manager` `DriverId`/`DeviceId` values. `load_driver` receives the NT driver-object path from
  service policy, registers a `DriverRecord` in the canonical I/O manager catalog, creates a
  `DeviceRecord` from the driver-declared `IoCreateDevice` name, and backfills the Object Manager
  object ids into those records after namespace publication. The private transport table now maps
  canonical I/O ids to the isolated component instance; it no longer allocates its own driver/device
  identities. Validation: `cargo fmt --manifest-path components/ntos-executive/Cargo.toml` and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`
  passed, and `.tmp/full-boot-driver-route-iomanager-20260804.log` reached `RUN_RC=0`,
  `247/280 executive->isolated-service checks passed`, `PASS exec_fsd_on_shared_harness`, `PASS
  exec_services_spawned`, `PASS exec_lsass_spawned`, `PASS exec_video_device_objects_registered`,
  `PASS exec_win32k_desktop_painted`, and `PASS exec_msgina_logon_dialog_painted`. Review
  adjustment: D1 remains open for replacing the private seL4 transport map with an `nt-io-manager`
  dispatch backend/IRP lifecycle path and moving WDM `DRIVER_OBJECT`/`DEVICE_OBJECT` projection
  construction out of `driver_launch`.
- D1 continued. Hosted FSD dispatch now runs through an `nt-io-manager` backend and synchronous IRP
  lifecycle instead of public helpers jumping directly to the component instance pump. The I/O
  Manager now has a host-testable external dispatch adapter that builds a canonical IRP, projects
  buffered input/output extents, routes by registered driver/device dispatch target, preserves raw
  NTSTATUS completions, and frees the IRP. The executive registers each isolated hosted driver as an
  I/O Manager backend; public driver/device/Object Manager/NamedPipe routes build an I/O Manager IRP
  and leave the seL4 pump as private backend transport only. Validation: `cargo test --manifest-path
  crates/nt-io-manager/Cargo.toml`, `cargo fmt --manifest-path components/ntos-executive/Cargo.toml`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `git diff --check`, and `.tmp/full-boot-driver-dispatch-iomanager-20260804.log` reached `RUN_RC=0`,
  `247/280 executive->isolated-service checks passed`, `PASS exec_fsd_on_shared_harness`, `PASS
  exec_irp_transport_call_bound`, `PASS exec_video_device_objects_registered`, `PASS
  exec_win32k_desktop_painted`, and `PASS exec_msgina_logon_dialog_painted`. Review adjustment: D1
  remains open for moving WDM `DRIVER_OBJECT`/`DEVICE_OBJECT` projection construction and any
  driver-created device-stack ownership still embedded in `driver_launch` into the I/O Manager/driver
  host boundary.
- D1 continued. WDM x64 compatibility layout writing for hosted drivers moved into
  `nt-io-manager`. `driver_launch` still owns the transport pool allocation and completion lifetime,
  but it now delegates `DEVICE_OBJECT`, `FILE_OBJECT`, IRP, and `IO_STACK_LOCATION` byte images plus
  `DRIVER_OBJECT` layout constants to shared, host-testable writers instead of open-coding NT5 x64
  offsets in the executive. Validation: `cargo test --manifest-path crates/nt-io-manager/Cargo.toml`,
  `cargo fmt --manifest-path components/ntos-executive/Cargo.toml`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `git diff --check`, and `.tmp/full-boot-wdm-projection-writers-20260804.log` reached `RUN_RC=0`,
  `247/280 executive->isolated-service checks passed`, `PASS exec_fsd_on_shared_harness`, `PASS
  exec_irp_transport_call_bound`, `PASS exec_video_device_objects_registered`, `PASS
  exec_win32k_desktop_painted`, and `PASS exec_msgina_logon_dialog_painted`. Review adjustment: D1
  remains open for moving driver-created device-stack ownership/lifetime and remaining hosted-driver
  projection state out of `driver_launch`; D3 remains the real videoprt/miniport-created video stack.
- D1 continued. Removed the duplicate executive `DRIVER_BINDINGS` and `DEVICE_ROUTES` route tables.
  Canonical driver/device lookup by route id, Object Manager object id, and NT device path now comes
  from `nt-io-manager` records, with host-test coverage for the new lookup helpers. `driver_launch`
  keeps only the private seL4 transport instance table needed to wake a hosted driver component, and
  public dispatch wrappers resolve through the I/O Manager before entering that transport backend.
  Validation: `cargo test --manifest-path crates/nt-io-manager/Cargo.toml`,
  `cargo fmt --manifest-path components/ntos-executive/Cargo.toml`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `git diff --check`, and `.tmp/full-boot-driver-routes-iomanager-only-20260804.log` reached
  `RUN_RC=0`, `247/280 executive->isolated-service checks passed`, `PASS
  exec_fsd_on_shared_harness`, `PASS exec_irp_transport_call_bound`, `PASS
  exec_video_device_objects_registered`, `PASS exec_win32k_desktop_painted`, and `PASS
  exec_msgina_logon_dialog_painted`. Review adjustment: D1 remains open for moving the
  guest-visible `IoCreateDevice` projection ownership/lifetime out of `driver_launch`; D3 remains the
  real videoprt/miniport-created video stack.
- D1 continued. The shared component entry path now builds hosted `DRIVER_OBJECT` headers through
  the `nt-io-manager` WDM x64 layout module instead of writing Type, Size, and DriverExtension
  offsets directly in `spawn_hosts`. The component still allocates its local driver object and
  extension from its own pool, but all hosted WDM object header bytes now come from one
  host-testable layout boundary. Validation: `cargo test --manifest-path
  crates/nt-io-manager/Cargo.toml`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, `git diff --check`, and
  `.tmp/full-boot-driver-object-writer-20260804.log` reached `RUN_RC=0`, `247/280
  executive->isolated-service checks passed`, `PASS exec_fsd_on_shared_harness`, `PASS
  exec_irp_transport_call_bound`, `PASS exec_video_device_objects_registered`, `PASS
  exec_win32k_desktop_painted`, and `PASS exec_msgina_logon_dialog_painted`. Review adjustment: D1
  remains open for real I/O Manager ownership of guest-visible `IoCreateDevice` allocation/lifetime;
  D3 remains the real videoprt/miniport-created video stack.
- D3 continued. The executive-owned boot framebuffer `video_device` projection now uses the shared
  `nt-io-manager` WDM x64 writers for its `DRIVER_OBJECT`, `DEVICE_OBJECT`, and `FILE_OBJECT`
  headers instead of carrying local object-size constants and raw offset writes. The module still
  owns the temporary Video0 route until videoprt/display miniport hosting creates the real stack, but
  the compatibility object bytes are no longer a separate video-only implementation. Validation:
  `cargo test --manifest-path crates/nt-io-manager/Cargo.toml`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, `git diff --check`, and
  `.tmp/full-boot-video-wdm-writers-20260804.log` reached `RUN_RC=0`, `247/280
  executive->isolated-service checks passed`, `PASS exec_video_device_objects_registered`, `PASS
  exec_win32k_desktop_painted`, and `PASS exec_msgina_logon_dialog_painted`. Review adjustment: D3
  remains open for replacing the temporary boot framebuffer route with a real videoprt/miniport
  created device object/interface and I/O path.
- D1 continued. Hosted `IoCreateDevice` allocation and `DriverObject->DeviceObject` insertion moved
  out of the `driver_launch` ntoskrnl export trampoline into `hosted_driver_projection`. The
  trampoline now validates/captures the optional `DeviceName`, delegates component-local WDM
  `DEVICE_OBJECT` allocation/header writing/linking plus allocation rollback to the focused
  projection boundary, and only publishes the out-param/shared-page verdict for the executive to
  reconcile with canonical I/O Manager records. Validation: `cargo fmt --manifest-path
  components/ntos-executive/Cargo.toml`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, `git diff --check`, and
  `.tmp/full-boot-hosted-device-projection-module-20260804.log` reached `RUN_RC=0`, `247/280
  executive->isolated-service checks passed`, `PASS exec_fsd_on_shared_harness`, `PASS
  exec_irp_transport_call_bound`, `PASS exec_video_device_objects_registered`, `PASS
  exec_win32k_desktop_painted`, and `PASS exec_msgina_logon_dialog_painted`. Review adjustment: D1
  remains open for making this projection boundary part of canonical I/O Manager/driver-host
  lifetime, including `IoDeleteDevice`, unload cleanup, and real device-stack attachment; D3 remains
  the real videoprt/miniport-created video stack.
- D1 continued. Device lifetime and stack ownership now have canonical I/O Manager APIs instead of
  raw store removal. `remove_device` unlinks the owning driver's device list and clears stale stack
  edges; `attach_device_to_stack`, `detach_device_from_stack`, and `delete_device` maintain
  `attached_to`, `top_of_stack`, `stack_size`, and `delete_pending` invariants with host tests for
  stale ids, stacked filters, detach, and open-file delete-pending behavior. Hosted ntoskrnl exports
  now bind `IoDeleteDevice`, `IoAttachDeviceToDeviceStack`, and `IoDetachDevice` explicitly: registered
  devices update canonical I/O Manager state before freeing/unlinking their component-local WDM
  projections, pre-registration DriverEntry cleanup clears the shared capture, and mixed known/unknown
  attach requests fail with `NULL` rather than falling through to the old fail-soft import path.
  Validation: `cargo test --manifest-path crates/nt-io-manager/Cargo.toml`, `cargo fmt --manifest-path
  components/ntos-executive/Cargo.toml`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, `git diff --check`, and
  `.tmp/full-boot-driver-device-lifetime-stack-20260804.log` reached `RUN_RC=0`, `247/280
  executive->isolated-service checks passed`, `PASS exec_fsd_on_shared_harness`, `PASS
  exec_irp_transport_call_bound`, `PASS exec_video_device_objects_registered`, `PASS
  exec_win32k_desktop_painted`, and `PASS exec_msgina_logon_dialog_painted`. Review adjustment: D1
  remains open for real driver unload/SCM stop lifetime and Object Manager device-object teardown;
  D3 remains the real videoprt/miniport-created video stack.
- D1 continued. `nt-io-manager` now has Object Manager-aware teardown APIs for driver/device
  lifetime. The Object Manager port contract can delete named `Driver` and `Device` objects; the mock
  port and library adapter implement those deletes, and `destroy_device`, `request_driver_unload`,
  and `destroy_driver` drive delete-pending state, owned device removal, namespace teardown, and
  `DriverUnloadState::Unloaded` without half-unloading a driver that still has open device references.
  Host tests cover device route removal, full driver unload with multiple devices, and unload refusal
  while an open file still references a device. Validation: `cargo test --manifest-path
  crates/nt-io-manager/Cargo.toml` and `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`. Review adjustment: the live
  executive still instantiates `IoManager<()>`, so D1 remains open for switching the executive to a
  real Object Manager port and routing `NtUnloadDriver`/SCM stop through `destroy_driver`; D3 remains
  the real videoprt/miniport-created video stack.
- D1 continued. Object Manager namespace deletion is now a real service/client ABI operation instead
  of an in-process-only helper. `nt-object-abi` exposes `OB_OP_DELETE_OBJECT`, the client stub sends
  bounded UTF-16 path requests, the server unlinks named objects through `remove_named_object`, and
  host roundtrips prove deleted symbolic links and device objects disappear from lookup. The live
  executive publishes its Object Manager client as the single executive-side service channel, and the
  hosted `IoDeleteDevice` path now preflights canonical I/O Manager deleteability, marks
  delete-pending when references/upper attachments block removal, deletes the Object Manager namespace
  route for published named devices, and only then removes the canonical device record plus hosted WDM
  projection. Validation: `cargo test --manifest-path crates/nt-object-server/Cargo.toml`,
  `cargo test --manifest-path crates/nt-io-manager/Cargo.toml`, `cargo fmt --manifest-path
  components/ntos-executive/Cargo.toml`, and `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, `git diff --check`, and
  `.tmp/full-boot-object-delete-20260804.log` reached `RUN_RC=0`, `249/282
  executive->isolated-service checks passed`, `PASS exec_ob_delete_symbolic_link`, `PASS
  exec_ob_lookup_deleted_symbolic_link`, `PASS exec_fsd_on_shared_harness`, `PASS
  exec_irp_transport_call_bound`, `PASS exec_video_device_objects_registered`, `PASS
  exec_win32k_desktop_painted`, and `PASS exec_msgina_logon_dialog_painted`. Review adjustment: D1
  remains open for routing driver-object unload/SCM stop through live driver teardown and then
  eliminating the residual `IoManager<()>`/post-create bind split; D3 remains the real
  videoprt/miniport-created video stack.
- D1 continued. Native driver service control now has real syscall identities and live hosted-driver
  lifetime routing. `NtLoadDriver` and `NtUnloadDriver` are registered in the Windows 7 service table,
  capture SCM `\Registry\Machine\System\...\Services\<name>` paths, require `SeLoadDriverPrivilege`,
  resolve demand-start service image paths from the SYSTEM hive, launch the `.sys` through the dynamic
  driver loader, and publish `Driver`/`Device` Object Manager routes transactionally. Hosted
  `DRIVER_OBJECT` layout now uses the NT x64 `DriverExtension` and `DriverUnload` offsets, captures a
  real `DriverUnload` pointer after `DriverEntry`, and routes unload through the component dispatch
  loop before deleting Object Manager namespace routes and canonical I/O Manager records. Validation:
  `cargo test --manifest-path crates/nt-syscall/Cargo.toml`, `cargo test --manifest-path
  crates/nt-io-manager/Cargo.toml`, `cargo fmt --manifest-path components/ntos-executive/Cargo.toml`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, and `git diff --check` passed. Review adjustment: D1 remains open only for
  eliminating the residual `IoManager<()>`/post-create bind split by giving the live executive a real
  Object Manager-backed I/O Manager port; D3 remains the real videoprt/miniport-created video stack.
- D1 complete. The live executive driver route no longer instantiates `IoManager<()>` and no longer
  post-creates Object Manager `Driver`/`Device` objects through a separate bind step. The Object
  Manager service ABI now exposes the missing routed File object operations needed by a full
  brokered `ObjectManagerPort`; the executive's port delegates driver, device, symbolic-link,
  file-handle, lookup, and close operations to the live Object Manager service client. Hosted driver
  registration now calls `IoManager::create_driver_peer_with_major_table`, `IoManager::create_device`,
  and `IoManager::create_symbolic_link`; failure unwinds the registered driver route instead of
  leaving half-published namespace state. Hosted `IoDeleteDevice` and native unload teardown now flow
  through `destroy_device`/`destroy_driver`, so Object Manager namespace deletion is owned by the
  I/O Manager port. Validation: `cargo test --manifest-path crates/nt-object-abi/Cargo.toml`,
  `cargo test --manifest-path crates/nt-object-server/Cargo.toml`, `cargo test --manifest-path
  crates/nt-io-manager/Cargo.toml`, `cargo fmt --manifest-path components/ntos-executive/Cargo.toml`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `git diff --check`, and a source search for the retired `IoManager<()>` /
  post-create bind symbols passed. Review adjustment: D1 is closed. The remaining open plan work is
  D3's real videoprt/miniport-created video stack.
- D3 continued. The win32k display route no longer bakes in the old 1024x768, 4096-byte stride, or
  0x300000-byte framebuffer assumptions. Phase 0a now publishes the real BOOTBOOT framebuffer width,
  height, scanline, byte size, and bits-per-plane into the display registration contract, and
  `video_device` receives that discovered mode when it answers Video0 mode and map-memory IOCTLs.
  Validation: `cargo fmt --manifest-path components/ntos-executive/Cargo.toml`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, and `git diff --check` passed. Review adjustment: D3 remains open for
  replacing the temporary boot framebuffer route with a real videoprt/miniport-created device
  object/interface and I/O path.
- D3 continued. Extracted the boot-framebuffer Video0 miniport IOCTL contract into the new
  host-testable `nt-video-miniport` crate. `video_device` now validates the BOOTBOOT framebuffer
  mapping through that crate and delegates `VIDEO_NUM_MODES`, `VIDEO_MODE_INFORMATION`,
  `VIDEO_MODE`, and `VIDEO_MEMORY_INFORMATION` encoding instead of carrying executive-local IOCTL
  constants and raw field writers. Unsupported video IOCTLs still fail visibly; only the proven
  framebuf display-driver mode/query/map path is implemented. Validation: `cargo test
  --manifest-path crates/nt-video-miniport/Cargo.toml`, `cargo fmt --manifest-path
  components/ntos-executive/Cargo.toml`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, and `git diff --check`
  passed. Review adjustment: the temporary Video0 object projection remains in `video_device`; the
  next D3 step is to register that route through canonical I/O Manager driver/device/file records
  instead of direct projection-pointer lookups.
- D3 continued. Video0 now registers as a canonical kernel-owned I/O Manager route instead of a
  video-only dispatch path. `nt-io-manager` has an explicit `DispatchTarget::Kernel` and
  `create_kernel_driver_with_major_table` for in-kernel backends, while the executive registers
  `\Driver\<display-service>` and `\Device\Video0` through the live Object Manager-backed I/O
  Manager. `video_device` keeps the win32k-facing projected WDM bodies, but validates them against
  the canonical device record and routes `EngDeviceIoControl` through
  `IoManager::build_and_dispatch_external_to_device`; the boot framebuffer miniport handles the IRP
  from the same `METHOD_BUFFERED` system-buffer contract as other I/O Manager drivers. Validation:
  `cargo test --manifest-path crates/nt-io-manager/Cargo.toml`, `cargo test --manifest-path
  crates/nt-video-miniport/Cargo.toml`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, and `git diff --check`
  passed. Review adjustment: the remaining D3 debt is the win32k import bridge still returning a
  static projected `FILE_OBJECT` for `IoGetDeviceObjectPointer`; the next step is to create/reference
  a canonical I/O Manager file object for that open.
- D3 continued. `IoGetDeviceObjectPointer("\\Device\\Video0")` now has a canonical I/O Manager open
  behind its projected win32k `FILE_OBJECT`. `nt-io-manager` exposes
  `reference_open_file_details`, the executive opens `\Device\Video0` through the live Object
  Manager-backed I/O Manager during video route publication, records the canonical handle/file id/file
  object id, and rewrites the projected WDM `FILE_OBJECT.FsContext` with that file id. Video
  `EngDeviceIoControl` now uses the normal handle-based `IoManager::device_control` path instead of
  the temporary external device dispatch wrapper, so IRPs carry the canonical open file id. Validation:
  `cargo test --manifest-path crates/nt-io-manager/Cargo.toml`, `cargo test --manifest-path
  crates/nt-video-miniport/Cargo.toml`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, and `git diff --check`
  passed. Review adjustment: D3 remains open only for the broader replacement of the boot
  framebuffer miniport/projection with a real videoprt/display-miniport-created stack and for auditing
  the remaining win32k import hooks against Configuration Manager/Object Manager boundaries.
- D3 complete. Video0's DeviceMap registry state now flows through the live Configuration Manager
  service instead of a video-private key/value emitter. The CM ABI/client/server support raw typed
  values in addition to DWORDs; the executive installs the live CM client as a kernel service channel;
  `video_device` publishes `\Registry\Machine\Hardware\DeviceMap\Video` with `MaxObjectNumber` and
  `\Device\Video0` values during canonical Video0 route registration; and win32k's
  `ZwOpenKey`/`ZwQueryValueKey` import bridge reads those DeviceMap bytes back from CM while still
  requiring the registered I/O Manager Video0 route to be live. The old bounded display/keyboard
  registry mirrors, direct DeviceMap value synthesis, fixed framebuffer geometry, direct projection
  pointer dispatch, and anonymous Video0 open path are gone. Validation: `cargo test --manifest-path
  crates/nt-config-client/Cargo.toml`, `cargo test --manifest-path crates/nt-config-server/Cargo.toml`,
  `cargo test --manifest-path crates/nt-config-abi/Cargo.toml`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `components/ntos-executive/build.sh`, and `git diff --check` passed. Review closure: this closes
  the dynamic-tech-debt plan. A fully hosted videoprt/display-miniport stack remains the next feature
  frontier for replacing the boot framebuffer miniport, but it is no longer masking a hardcoded
  registry/device fallback in this plan.

## Explorer Shell Chrome Frontier

- E1 complete. Explorer now survives interleaved nested user callbacks by deferring out-of-order
  `NtCallbackReturn` packets until the corresponding callback frame is at the global top of the
  parked continuation stack. Validation: `rustfmt --edition 2021 --config skip_children=true`
  over the touched files, `cargo test -p nt-user-callback`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, `git diff --check`,
  `./components/ntos-executive/build.sh`, `cd rust-micro && ./scripts/build_kernel.sh
  extern-rootserver`, and headless gate `desktop-render-r40-deferred-callback-20260805-123654`
  passed. Screenshot follow-up `desktop-render-r41-screenshot-20260805-124745` proved genuine
  explorer launch, shell class/message registration, real WndProc install, `WM_PAINT`,
  `NtUserBeginPaint`, GDI text/fill calls, and `NtUserEndPaint`, but the framebuffer still contained
  only the desktop background plus cursor/bottom artifacts. Review adjustment: the remaining E2 work
  is real shell chrome pixels, starting with USER/GDI syscall pointer contracts used by explorer paint.
- E2 complete. `NtUserBeginPaint`/`NtUserEndPaint` now stage `PAINTSTRUCT` across the isolated
  win32k boundary instead of passing a hosted-client stack pointer directly. This mirrors ReactOS'
  `NtUserBeginPaint` copy-to-caller and `NtUserEndPaint` probe/copy-in contracts, returns zero on
  failed probes/copyout, and leaves win32k responsible for the real `IntBeginPaint`/`IntEndPaint`
  state transitions. Validation: `rustfmt --edition 2021 --config skip_children=true
  components/ntos-executive/src/service_sec_image.rs`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, `git diff --check`,
  `./components/ntos-executive/build.sh`, `cd rust-micro && ./scripts/build_kernel.sh
  extern-rootserver`, and graphical boot run `desktop-render-r42-paintstruct-20260805-130406`
  passed with `284/284` checks. The run exercised staged `PAINTSTRUCT` for winlogon and explorer
  paint, explorer spawned genuinely, installed client WndProcs, and ran real nested paint callbacks.
  Screenshot analysis still shows only the desktop background, cursor, and the two bottom artifacts
  (`311` non-background pixels, same as r41). Review adjustment: E3 is the remaining real shell
  chrome pixel work; inspect dirty-window accounting, window-surface flush, and any USER/GDI geometry
  copyback gaps instead of adding framebuffer scaffolding.
- E3 started. `KeGdiFlushUserBatch` no longer clears `GdiTebBatch` records in the executive without
  executing them. The syscall-entry path now passes the dynamic `Win32kClientContext` into a private
  win32k callout selector, and the component invokes the real
  `WIN32_CALLOUTS_FPNS.BatchFlushRoutine` that ReactOS registered through
  `PsEstablishWin32Callouts`. The bridge opens a narrow writable mapping for the caller's
  `TEB.GdiBatchCount` while `NtGdiFlushUserBatch` runs, then restores the normal read-only TEB-tail
  policy. Validation so far: `rustfmt --edition 2021 --config skip_children=true` over the touched
  Rust files and `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none` passed. Review adjustment: finish E3 by building/booting and comparing the
  screenshot for new explorer chrome pixels; if framebuffer remains background-only, inspect
  dirty-window accounting and geometry copyback with batch replay no longer masking GDI draws.
- E3 continued. Graphical run `desktop-render-r44-gdibatch-remap-20260805-134117` proved the first
  TEB-tail fault was gone and reached real winlogon/userinit progress, but the batch callout still
  failed because the win32k client attach remap tried to map over a live leaf after an unchecked
  fire-and-forget unmap. The attach table now tracks page rights, and TEB-tail COW, explicit
  `NtGdiFlushUserBatch` remaps, ordinary client attach maps, and detach cleanup use checked
  map/unmap calls so stale attach records fail visibly instead of masquerading as insufficient
  resources. Validation so far: `rustfmt --edition 2021 --config skip_children=true` over the
  touched Rust files and `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none` passed. Review adjustment: rerun the single graphics boot and close this
  slice only if the real batch flush completes with zero failures.
- E3 continued. Graphical run `desktop-render-r45-gdibatch-checked-20260805-135300` showed the
  remaining `NtGdiFlushUserBatch` remap failure was `seL4_FailedLookup`, not `DeleteFirst`: the
  sparse win32k pager had marked paging levels as present after fire-and-forget structure maps whose
  failures were invisible, then later leaf maps skipped the missing PT rebuild. The win32k sparse
  pager now uses checked retype/map calls and records a level only after success or a genuine
  already-present (`DeleteFirst`) response; win32k private/zero-fill demand maps are checked too, so
  missing paging infrastructure cannot be hidden behind an anonymous page. Review adjustment: rerun
  the single graphics boot and require zero GDI batch callout failures before moving back to dirty
  region/window-surface diagnostics.
- E3 continued. Graphical run `desktop-render-r46-gdibatch-paging-20260805-140643` reached genuine
  `userinit` launch of `explorer.exe`, explorer CSR connect, win32k process/thread callouts, and
  system-font load, but repeated `NtGdiFlushUserBatch` callouts still failed while remapping the
  caller TEB tail because the leaf `Page_Map` saw `seL4_FailedLookup` after the sparse pager believed
  the covering hierarchy existed. The attach mapper now performs checked cap-copy plus checked leaf
  map through one helper for normal client attach, GDI batch remap, and TEB-tail COW; on a real
  `FailedLookup` it invalidates the cached PDPT/PD/PT keys for that page, rebuilds the hierarchy,
  and retries once with diagnostics instead of returning a synthetic success. Review adjustment:
  rerun the single graphics boot and require the repair to eliminate `BatchFlushRoutine failed`
  before using the run for shell-chrome framebuffer analysis.
- E3 continued. Graphical run `desktop-render-r47-gdibatch-repair-20260805-142127` reached the
  desktop framebuffer, started real services and LSASS, and exercised LSASS `NtUserProcessConnect`
  through the win32k process/thread callout path without the old batch-remap `FailedLookup`
  signatures. It exposed a stale shared-context publication instead: while LSASS was suspended in an
  api7 callback, a services win32k dispatch later consumed LSASS' published PID/TID as if it were
  services' result. Win32k context publication is now a one-shot handoff: dispatch entry clears it,
  dispatch completion takes and clears it, and `NtCallbackReturn` completion imports the callback
  owner's publication before waking deferred callers. Review adjustment: rebuild and run r48; require
  no `published PID mismatch`/stale-context diagnostics before treating LSASS/service overlap as
  clean and moving back to explorer shell chrome pixels.
- E3 continued. Graphical run `desktop-render-r48-context-take-20260805-143218` advanced past the
  previous LSASS/services overlap to genuine `userinit.exe` launch of `explorer.exe`; explorer opened
  its real image, entered `NtUserProcessConnect`, completed the api7 client callback, and seeded its
  private system font. The run also proved that clearing the shared slot only after the executive
  wrapper returns is too late: a win32k dispatch can publish process context, suspend in
  `KeUserModeCallback`, and allow another client dispatch before the wrapper has consumed that
  publication. The handoff now captures and clears the publication at the callback-suspension
  boundary, keyed by dynamic client identity, and the executive imports that captured context before
  falling back to the shared slot. Review adjustment: rebuild and run r49; require zero
  `stale published` diagnostics. The remaining visible pager issue is the real
  `seL4_InvalidCapability` while retyping the win32k mirror PT for winlogon's
  `0x10000511000` user page during profile loading; keep it visible rather than treating it as an
  already-present mapping.
- E3 continued. Graphical run `desktop-render-r49-suspended-context-20260805-144652` proved the
  first suspension-time capture point was not sufficient: LSASS still published pid 8 during
  `NtUserProcessConnect`, suspended in api7, and services later saw that stale publication while
  expected pid 7. The handoff is now also captured at the glue-level component-pump return whenever
  `win32k_dispatch_wide_with_completion_args` observes `callback_suspended`, which is the last common
  point before any caller-path wrapper, redirect, or deferred resume can let another client dispatch.
  Review adjustment: rerun as r50 and require the LSASS/services overlap to complete with zero
  `stale published` diagnostics before committing this slice.
- E3 continued. Graphical run `desktop-render-r51-owned-context-20260805-150608` proved the
  publication handoff is now owned by the suspended client instead of a shared stale slot: no
  `stale published`, `identity mismatch`, or suspended-publication mismatch diagnostics appeared
  while winlogon, services, LSASS, userinit, and explorer all reached real `NtUserProcessConnect`.
  Explorer genuinely spawned, completed api7, redirected api0 callbacks, installed client WndProcs,
  and opened the shell COM classes. The remaining shell-chrome blocker is lower level:
  `NtGdiFlushUserBatch` still failed every callout because the narrow writable remap could not copy
  the caller TEB-tail frame cap (`seL4_FailedLookup` on winlogon's worker TEB), so
  `tail-write-windows` stayed zero; the run also kept the visible VM pool-headroom and
  `0x10000511000` win32k sparse-pager diagnostics. Review adjustment: keep the dynamic context
  ownership fix, repair durable GUI-client TEB frame ownership for the real batch callout, then rerun
  a single graphics boot and require zero GDI batch failures before returning to framebuffer chrome
  analysis.
- E3/F continued. Graphical run `desktop-render-r76-user-stack-vad-reclaim-20260805-190233`
  reached real explorer shell traffic but exhausted hosted-thread CNode objects while short-lived
  worker threads were churned. Hosted thread spawn now returns structured mechanism caps, runtime
  records own those private CNodes, and thread termination deletes/recycles them alongside TCB,
  user-stack VAD, and worker-window resources. The follow-up run
  `desktop-render-r77-thread-cnode-reclaim-20260805-191418` exposed an earlier cleanup regression:
  win32k's component image had been punched with hosted-client env holes at `0x1000051..55`, but
  those pages contain real rootserver text (`win32k_ob::ObHandleTable` among others). The hole
  machinery is now removed, hosted SEC_IMAGE TEB/params/PEB/desktop/trampoline pages live in a
  dedicated env band at `HOSTED_CLIENT_ENV_BASE = 0x10001600000`, and hosted process/selftest VSpaces
  reserve that PT explicitly. Review adjustment: rebuild and run the single graphics boot again;
  require win32k DriverEntry to return and the `0x10FA` dispatch-loop proof to pass before measuring
  whether CNode reclamation carries explorer past the r76 worker churn frontier.
- G1 complete. Graphical run `desktop-render-r83-typed-generic-sections-20260805-202526` reached
  genuine `userinit.exe` and `explorer.exe` launch with explorer win32k traffic, real api0 callback
  redirects, client WndProc installation, shell COM class opens, and `win32k-pool-exhaustions=0`.
  Generic non-image sections now back anonymous/disk/overlay sections through real
  `HandleObject::Section` handles, so duplicated section handles (`0x1168`, `0x116c` in the run)
  map/fault through the same section object instead of falling into `NtMapViewOfSection unsupported`.
  Validation: `rustfmt`, `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `./components/ntos-executive/build.sh`,
  `cd rust-micro && ./scripts/build_kernel.sh extern-rootserver`, and the single graphical boot all
  completed to the microtest sentinel. Review adjustment: G2 starts at real shell chrome pixels. The
  framebuffer proof still reports only desktop background (`non-bg 0`), and the remaining known
  failing gates are DBGK callback selftests, user-callback drain/dead-client harness checks,
  nested win32k transport drain, and VM pool headroom.
- G2/G4 complete. Explorer shell chrome is now proven through real USER/GDI execution and a stable
  full-framebuffer readback rather than screenshot-only inspection. The explorer path records
  `NtUserBeginPaint`/`NtUserEndPaint`, message calls, update-region calls, direct GDI draw returns,
  GDI object creation, and `KeGdiFlushUserBatch` records for the dynamic explorer client; the final
  gate requires those draw/batch signals plus a wide, multi-color non-background framebuffer region
  distinct from the desktop fill and cursor. Validation: `rustfmt
  components/ntos-executive/src/main.rs components/ntos-executive/src/service_sec_image.rs`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `./components/ntos-executive/build.sh`,
  `cd rust-micro && ./scripts/build_kernel.sh extern-rootserver`, and graphical boot
  `desktop-render-r85-explorer-shell-chrome-gate-20260805-204308` passed to the microtest sentinel
  with `277/285` executive checks. Evidence from the run: explorer paint begin/end `14/14`,
  message-call `147`, update-region `58`, direct-gdi/returns `54/54`, GDI objects `107`, batch
  flush/records `100/100`, max batch offset `0x62`, framebuffer `28672` non-background pixels over
  bounds `0,740..1023,767`, and `unique-non-bg>=32 saturated`; `exec_explorer_shell_chrome_painted`
  passed. Review adjustment: G3 remains for trimming trace-only shell-paint counters and auditing
  presentation ownership. The next functional debt is reply-cap/wait parking pressure plus the
  nested user-callback/dead-client transport drain and DBGK selftest failures; shell paint no longer
  needs a modeled framebuffer path.
- G3/C cleanup continued. Removed the old service-level fake mutant ladder and immediate wait
  fallback: `NtCreateMutant`, `NtOpenMutant`, and `NtReleaseMutant` now route through the native
  service table, mutants participate in dispatcher waits, wrong-owner release returns
  `STATUS_MUTANT_NOT_OWNED`, and thread termination abandons owned mutants before wake dispatch.
  Also widened the inline object namespace for long `BaseNamedObjects` names and added session/BNO
  symlink resolution so CSR/userenv object paths resolve dynamically instead of by compatibility
  identity. CSR shared heap/static pages are now registered with the client XAS mirror and the
  returned `PORT_VIEW`/`CSR_API_CONNECTINFO` are written through the current process address-space
  path. The shell-paint proof was tightened by deleting trace-only explorer counters and requiring a
  real GDI batch flush for `exec_explorer_shell_chrome_painted`.
- G3 validation follow-up. Graphical run
  `desktop-render-r99-overlay-scratch-20260805-221743` showed the user-profile source was present
  but the boot stopped in `userenv` profile load: `::Profiles` materialised with 45 directories, 32
  files, and a 139264 byte regf `Default User\ntuser.dat`, then winlogon faulted after
  `NtCreateFile` on the writable profile path. Root cause was the lazy writable-volume mount being
  reached from a non-mutating probe after the dirty marking was narrowed; the service loop reset the
  bump heap while the mounted `FileSystem` and materialised profile tree still owned allocations
  above the mark. The fix is a one-shot mount/materialisation dirty bit consumed by the existing
  writable-filesystem heap pin, while attribute/read/query buffers remain transient and overlay
  writes use a fixed 64 KiB scratch buffer.
- G3 validation complete. Graphical run `desktop-render-r100-mount-dirty-20260805-222253` passed to
  the microtest sentinel with `283/285` executive checks and a real desktop screenshot at
  `.tmp/desktop-render-r100-mount-dirty-20260805-222253.png` showing the taskbar and clock. Evidence:
  `C:\Profiles` collision was honest, `C:\Profiles\Administrator` and copied subdirectories/files
  were created, `Administrator\ntuser.dat` was copied byte-exact from `Default User\ntuser.dat`,
  `NtLoadKey` mounted the copied 139264 byte hive twice with five root subkeys, `userinit.exe` and
  `explorer.exe` launched dynamically, `KeGdiFlushUserBatch` had 251 flushes and zero failures, and
  explorer shell chrome produced 27375 non-background framebuffer pixels over `0,384..1023,767`.
  The remaining red gates are the existing `exec_user_callback_dead_client_unwind` and
  `exec_win32k_transport_call_nested` harness drains; profile load, userinit, explorer, and visible
  shell chrome are back on the genuine path.
- G3 callback-drain validation complete. The post-quiesce nested/dead-client proof helpers now use
  runtime-built `Win32kClientContext` records instead of rebuilding winlogon identity inside
  `win32k_glue`, and the stale `pi=2` callback-return/client-copyout literals in those helpers are
  gone. The nested proof still exercises the expendable winlogon worker for the actual outer/nested
  callback chain, but its final "win32k idle" dispatch now probes with winlogon's live main-thread
  context, matching the dead-client recovery proof and avoiding a follow-on worker
  `ClientThreadSetup` callback. Unexpected idle-probe callbacks are explicitly cancelled so a failed
  probe cannot contaminate the next gate. Validation: `rustfmt`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `cd rust-micro && ./scripts/build_kernel.sh
  extern-rootserver`, and graphical boot `desktop-render-r102-nested-main-idle-probe-20260805-225007`
  passed to the microtest sentinel with `285/285` executive checks. Evidence: nested transport proof
  `0x3f/0x3f`, dead-client unwind proof `0x3f/0x3f`, `suspended-outstanding=0`, both idle probes
  returned `0x600d600d` with `parked=0`, profile load/userinit/explorer gates stayed green, and
  `.tmp/desktop-render-r102-nested-main-idle-probe-20260805-225007.png` shows the rendered desktop
  taskbar and clock.
- G3 complete. The remaining shell-paint cleanup audit found one explorer-only GDI batch max-offset
  trace and a bounded explorer `SetWindowLong`/WndProc trace logger that no longer guarded behavior.
  Both were removed while keeping durable gates for the real boundaries: explorer BeginPaint/EndPaint,
  direct GDI draw returns, GDI batch flush/record counts, client-installed WndProc without replay,
  shell COM class service, and full framebuffer readback. No modeled shell presentation helper was
  found in the explorer chrome path; pixels still come from win32k USER/GDI ownership and the boot
  framebuffer readback. Validation: `rustfmt`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `cd rust-micro && ./scripts/build_kernel.sh
  extern-rootserver`, and headless boot `desktop-render-r103-g3-closeout-20260805-231053` passed to
  the microtest sentinel with `285/285` executive checks. Evidence: `exec_explorer_shell_chrome_painted`,
  `exec_user_callback_dead_client_unwind`, and `exec_win32k_transport_call_nested` all passed;
  explorer paint proof was `begin/end=6/6`, `direct-gdi-returns=47`,
  `batch-flush/records=41/41`, and framebuffer readback found `27375` non-background pixels over
  bounds `0,384..1023,767`.

### 2026-08-10

- Wait/reply-cap capacity cleanup complete. The executive wait parking path no longer depends on a
  single-word reply-cap bitmap or a fixed 16-slot dispatcher waiter table: reply caps and waiter
  records now scale with the hosted-thread runtime capacity, all parkers share the same reply-pool
  helpers, and rust-micro's `extern-rootserver` profile has enough kernel Reply objects for the
  larger NT rootserver shape. Validation: `cargo fmt --all`,
  `cd rust-micro && cargo +nightly fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, and full boot `.tmp/boot-reply-pool-kernel-scale-20260810-130750.log`.
  Evidence: the boot prints `reply-pool live=545 capacity=545`, has no reply-pool exhaustion or
  wait-array resource failures, passes `exec_csr_message_plane`, and reaches real winlogon SAS HWND
  creation plus `NtUserSetLogonNotifyWindow(0x127c)`. Review adjustment: the next honest shell
  frontier is the post-SAS message loop. In that boot, `exec_winlogon_sas_window` and
  `exec_win32k_desktop_painted` pass, but post-SAS `GetMessage` remains `0`, so msgina dialog
  creation/profile activation/userinit/explorer are downstream again.
- H1/H2 started. The clean TEB-emulation boot proof
  `.tmp/boot-clean-teb-emulation-20260810-134455.log` reaches desktop background paint and the
  winlogon SAS window, then `InitializeSAS` fails immediately after
  `NtUserSetLogonNotifyWindow(0x127c)`. The final native sequence has one `NtOpenKey` and then
  `NtTerminateProcess`, with no `NtQueryValueKey` or `NtSetDefaultLocale`, so the blocker is the
  registry open that should feed `SetDefaultLanguage(NULL)`. Review adjustment: remove the old
  exact NLS-key matcher and route HKLM opens through a real machine namespace parser instead.
- H2 correction. A diagnostic boot with the in-progress locale setup code printed
  `[locale-setup] reactos\unattend.inf LocaleID absent -> no setup locale`, so relying only on
  `unattend.inf` regressed the previously working `.DEFAULT` locale seed. The setup provisioner must
  use real data only, but it needs both legitimate sources: `unattend.inf` when present and the
  staged SYSTEM hive's `Nls\Language\Default` otherwise.
- H1-H3 complete. Fresh serialized boot
  `.tmp/boot-setup-locale-clean-20260810-135954.log` provisions
  `HKU\.DEFAULT\Control Panel\International\Locale <- 00000409` from
  `reactos\unattend.inf`, writes `HKLM\...\Nls\Language` `Default=0409`, and reaches the existing
  desktop proof without the previous `WL: Failed to initialize SAS` abort. The run finishes at the
  current shell frontier (`246/295`, `exec_win32k_desktop_painted` passes); post-SAS
  `GetMessage`/msgina/profile/userinit/explorer gates remain the next blockers.
- A4 pipe cancellation complete for modeled pipe IRPs. `NtCancelIoFile` is now a real native
  service at SSN 24 instead of an unhandled syscall: it probes the caller IOSB, validates the target
  FILE_OBJECT with no required access rights, cancels only current-thread pending pipe read/write,
  transceive, async listen, and root name-wait operations for that handle, and completes those IRPs
  through their original IOSB/event/file-object/IOCP surfaces with `STATUS_CANCELLED`. Successful
  async listens now share the same file-completion path. Validation: `cargo fmt --all`,
  `cargo test -p nt-io-manager cancel_thread -- --nocapture`, `cargo test -p nt-syscall
  -- --nocapture`, `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `git diff --check`, and boot `.tmp/boot-ntcanceliofile-20260810.log`.
  Evidence: `[nt-cancel-io-file] ... cancelled=1` appears, the old service `0x18` park does not
  recur, and the harness reports the base desktop-painted success. Review adjustment: continue A4 at
  real service-control pipe timing/IPC after the WLAN service `EVENT_CONNECTION_TIMEOUT`; no
  service-name pipe/executable fallback should be reintroduced.
- A4 pipe fid-name authority continued. The next service-control timeout came from internal pipe
  metadata authority, not a missing policy shortcut: the old fixed 32-entry fid-name table dropped
  late service pipe fids, and async-listen completion treated `name_hash == 0` as a wildcard. A
  client connect for `\net\NtControlPipe5` could therefore wake an unrelated pending listen while
  the actual SCM control pipe stayed pending until `NtCancelIoFile`. `PipeFidNameTable` is now a
  growable host-tested structure, zero hashes are invalid/non-matching, named-pipe create/open
  records the leaf hash before publishing a handle, `FSCTL_PIPE_LISTEN` fails rather than arming an
  unnamed server fid, and file-id mappings are removed only after the last file-completion reference
  is released. Local validation: `cargo fmt --all`, `cargo test -p nt-io-manager pipe_fid_name
  -- --nocapture`, `cargo test -p nt-io-manager async_listen -- --nocapture`,
  `cargo test -p nt-io-manager -- --nocapture`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, and `git diff --check`.
  Serialized boot proof in `.tmp/boot-current-headless-20260810.log` reaches
  `SUCCESS ... win32k desktop painted (0x003a6ea5)`; the late `\net\NtControlPipe5` wait is
  `armed=1 known=1`, wakes only exact hash-matched fids `0e814c80`/`0e814c81`, and no longer shows
  the previous `known=0`, timeout, cancel, service `Error 1053`, or unhandled-syscall signatures.
  Review adjustment: continue only from the next real red edge after the desktop proof.
- I1 complete. The executive now strips the NT file-I/O completion-port suppression bit from
  overlapped event handles before validating, resetting, or signaling events in `NtFsControlFile`,
  `NtReadFile`, `NtWriteFile`, and `NtQueryDirectoryFile`. A raw `hEvent == 1` is treated as
  "no event object" rather than an invalid handle, matching the kernel32 convention of using the low
  bit to suppress completion packets while keeping the real event handle in the upper bits. Review
  adjustment: the next I/O-manager debt is `FileIoCompletionNotificationInformation`, because
  ReactOS kernel32 exposes `SetFileCompletionNotificationModes` on top of `NtSetInformationFile`.
- I2 complete. `FileIoCompletionNotificationInformation` is now backed by kernel-owned per-file
  state: `NtSetInformationFile` records sticky notification flags, `NtQueryInformationFile` returns
  the real four-byte flag structure, `FileCompletionInformation` association updates FILE_OBJECT
  waitability unless `FILE_SKIP_SET_EVENT_ON_HANDLE` is active, inline successful completions honor
  `FILE_SKIP_COMPLETION_PORT_ON_SUCCESS`, and `OVERLAPPED.hEvent | 1` is carried through pending
  pipe read/write/transceive/listen records to suppress their final completion-port packet. Local
  validation: `cargo fmt --all`, `cargo test -p nt-io-completion -- --nocapture`,
  `cargo test -p nt-io-manager -- --nocapture`, and `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`. Review adjustment: I3 remains
  the next accepted proof; use one uncontended boot lane and capture the genuine explorer/shell
  frontier after this I/O completion state is present.
- A4 runtime-role cleanup continued. Dynamically spawned SCM and LSA per-connection workers now keep
  their exact hosted-thread role while using the generic TP worker badge/stack/TEB window. The
  runtime table resolves those workers by badge, the service loop treats their role as
  SCM/LSA-RPC policy metadata instead of relying on the historical fixed worker badges, pipe/RPC PDU
  accounting uses the registered role, and win32k callback metadata round-trips the slot-scoped
  roles. Local validation: `cargo fmt --all`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, and `git diff --check`.
  Review adjustment: the next serialized boot should prove the late `\pipe\ntsvcs` worker churn uses
  `role=scm-rpc` dynamic workers before deciding whether the remaining shell frontier is service IPC
  liveness or explorer paint itself.
- A4 fixed-worker deletion complete. The historical SCM/LSA per-connection worker recognizers,
  fixed worker badges, fixed target/mirror/scratch windows, and dedicated spawn helpers are gone.
  Per-connection SCM/LSA RPC workers are admitted only through the generic same-process worker
  route, then classified from the caller's registered hosted-thread role as
  `ScmWorkerSlot`/`LsaWorkerSlot`. The generic high-slot mapper now sizes itself from
  `TP_WORKER_SLOT_COUNT` instead of reserving space for an extra LSA-specific window. Local
  validation: `cargo fmt --all`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, and `git diff --check`.
  Review adjustment: retry one uncontended boot next; the expected proof is a real late
  `role=scm-rpc` worker on the `\pipe\ntsvcs` path, with no fallback fixed badge/window route left
  to mask the next frontier.
- I3 in progress. Fresh serialized desktop boot
  `.tmp/boot-current-desktop-repro-20260810-191348.log` first required clearing a stale QEMU holder
  of `rust-micro/.tmp/disk.img`, then rebuilt and reached real win32k desktop background paint:
  `winlogon NtUserSwitchDesktop ... desktop-bg 768/768`. The boot does not reach `userinit.exe` or
  `explorer.exe`; it parks after late `\pipe\ntsvcs` churn. The dynamic SCM worker route is real
  (`role=scm-rpc` generic slot 6) and the final workers execute
  `NtSetInformationThread -> NtCreateEvent -> NtReadFile -> NtQueryInformationFile -> NtClose
  -> NtClose -> NtQueryInformationThread -> NtTerminateThread`, then services re-arms the listen and
  all SCM threads park. Review adjustment: keep the next slice on generic SCM/NPFS/RPC result
  tracing and I/O semantics; do not restore fixed worker windows or service-name fallbacks.
- I3 pipe-waiter capacity fix staged. The late dynamic SCM worker slot was failing
  `NtReadFile(\pipe\ntsvcs)` with `STATUS_INSUFFICIENT_RESOURCES` before NPFS routing, even though
  the handle, IOSB, event, buffer, and file route were valid. The parked pipe-IRP table is now
  growable like async listens, the executive reserves pipe-waiter storage before issuing pending
  read/write/transceive routes, post-route park refusals count as real allocation failures, and
  terminating-thread cancellation releases detached reply caps without a fixed scratch array. Local
  validation: `cargo fmt --all`, `cargo test -p nt-io-manager pipe_waiter`, `cargo check
  --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`, and
  `git diff --check`. Review adjustment: run one serialized desktop boot next; expected proof is
  that the late slot-6 `NtReadFile` reaches NPFS/pends or completes instead of returning
  pre-route `0xc000009a`.
- I3 growable-pipe-waiter boot proof captured in
  `.tmp/boot-growable-pipe-waiters-20260810-193356.log`. The old pre-route failure is gone:
  dynamic SCM worker slot 6 now routes `NtReadFile` on fid `0e8138d1` through NPFS, gets real
  synchronous reads and `STATUS_PENDING` parks, and is later woken by pipe redrive. The boot still
  paints the winlogon desktop background (`desktop-bg 768/768`) and now reaches a genuine dynamic
  `wlansvc.exe` process (`pi=11`, pid 652) with its own control pipe and worker threads. Explorer
  has not launched (`ssn-hist explorer total=0`). The next red edge is `wlansvc`/rpcrt4 service
  control IPC: ReactOS logs `TransactNamedPipe(Schedule, 80) failed (Error 231)`, then reports no
  context handle for UUID `{60ed3641-4ff2-4e3b-adc8-7747e364f201}` and a fault packet with status
  `0x1c00001a`. Review adjustment: continue at real RPC/context-handle semantics for that service
  path; do not reintroduce service-name, executable, or pipe-capacity fallbacks.
- I4 started. ReactOS rpcrt4/WLAN tracing shows the UUID in the failure is a generated context
  handle owned by the server RPC association, not the WLAN interface UUID. The first kernel-side
  cleanup is therefore generic NPFS/RPC transport fidelity: async `FSCTL_PIPE_LISTEN` completion now
  uses the exact server-end fid for the accepted CCB (`(client_fid & !1) | FILE_PIPE_SERVER_END`)
  instead of consuming the first pending listen with the same name, and the host pipe model matches
  ReactOS `NpTransceive` preconditions (`STATUS_INVALID_PIPE_STATE` for
  non-connected/non-full-duplex/non-message-mode, `STATUS_PIPE_BUSY` when unread reply data is
  already queued before writing a new request).
  Review adjustment: validate this with focused pipe tests/checks, then run one serialized desktop
  boot to see whether the remaining `wlansvc` context-handle fault is association reuse or the next
  service-control pipe semantic gap.
- I4 validation boot `.tmp/boot-shell-chrome-20260810-194922.log` moved the dynamic service path as
  far as `wlansvc.exe` (`pi=11`, pid 652) but did not reach explorer. The exact-listen change is
  working (`[pipe-listen] completed 1 pending server listen(s) on client connect`), and the
  ReactOS-faithful `NpTransceive` precondition exposed the next real bug:
  `TransactNamedPipe(Schedule, 80)` now returns `STATUS_PIPE_BUSY` because the executive redrive path
  was issuing a second synthetic `IRP_MJ_READ` for a parked transceive instead of consuming the
  retained npfs completion stash. Review adjustment: parked READ/TRANSCEIVE completion must be
  delivered only from `IoCompleteRequest`'s exact completed-read stash; no executive re-read fallback.
- I4 transceive redrive cleanup complete. `pipe_redrive_all` no longer issues a fresh read for parked
  `FSCTL_PIPE_TRANSCEIVE`; pending READ/TRANSCEIVE waiters now complete only from the driver bridge's
  exact `IoCompleteRequest` completed-read stash, which matches the retained-IRP ownership model and
  removes the synthetic duplicate read entry that tripped the real `NpTransceive` busy check.
  Validation: `cargo fmt --all`, `cargo check --manifest-path components/ntos-executive/Cargo.toml
  --target x86_64-unknown-none`, `cargo test --manifest-path crates/nt-io-manager/Cargo.toml`,
  `git diff --check`, and serialized boot
  `.tmp/boot-no-transceive-reissue-20260810-195411.log`. Evidence: kernel specs passed, winlogon
  desktop background still paints (`desktop-bg 768/768`), no `TransactNamedPipe(Schedule)` or
  `0xc00000ae` transceive failure recurs, and service startup advances through dynamic `spoolsv.exe`,
  `browser` `ServiceMain`, and `srvsvc`. Review adjustment: I4 remains open at the later generic
  rpcrt4/server-association context-handle fault on SCM worker slot 9
  (`{2d5427c4-1402-43d3-8929-6d5b131898a2}` / fault `0x1c00001a`) plus `browser`
  `RpcServerListen() failed (Status 6b1)`; keep the next slice on real RPC association/context-handle
  state and do not add service-name, executable, or pipe read fallbacks.
- I4 LSA LPC data-plane cleanup staged. The same boot also exposed a separate pre-RPC boundary:
  dynamically launched service clients such as `wkssvc` could complete a real
  `NtConnectPort(\LsaAuthenticationPort)`, but their accepted client handles were not cached in the
  generic LPC connection table. Their subsequent `NtRequestWaitReplyPort(LsaHandle, ...)` therefore
  fell through as an unregistered LPC handle and `LsaLookupAuthenticationPackage` failed with
  `STATUS_INVALID_HANDLE`. The first fix cached every successful manual accept under the original
  connector process and keyed the LSA request recognizer off the generic `\LsaAuthenticationPort`
  connection record instead of winlogon's milestone latch. Serialized boot
  `.tmp/boot-lsa-lpc-cache-20260810-200140.log` proved that was still insufficient: the
  pre-reserved LPC connection vector had reached its fixed 16-entry capacity and silently refused the
  late `wkssvc` LSA record. The cache now deduplicates by client handle, grows in chunks, marks its
  storage dirty when it reallocates, and the service loop pins that storage even for post-dispatch
  manual rendezvous completions. Review adjustment: revalidate with a serialized desktop boot and
  require the old unregistered-LPC `LsaLookupAuthenticationPackage` failure to disappear before
  returning to the rpcrt4 context-handle frontier.
- I4 LSA LPC copyout cleanup continued. Manual LSA accepts can complete while the server process is
  running, but the connector's `PortHandle` and `ConnectInfo` buffers live in the original client's
  address space. `lsa_complete_connect` now performs those writes through the same mapped/fill
  copyout path used by ordinary cross-process syscall completions before caching the successful
  `\LsaAuthenticationPort` connection for that connector process. A short headless validation
  `.tmp/boot-lsa-copyout-headless-20260810-202925.log` still reaches the base desktop-background
  gate (`desktop-bg 768/768`), while the long graphics/no-exit boot
  `.tmp/boot-lsa-copyout-20260810-202758.log` was interrupted during later explorer DLL demand-load
  (`shell32`) before it reached the prior late service/RPC context-handle fault. Review adjustment:
  run one fresh serialized graphics/no-exit boot after committing this cleanup; the proof must show
  either genuine explorer syscalls/paint or the next precise red edge after the LSA handle fix.
- I4 LSA LPC copyout/request follow-up. The accepted handle was still vulnerable to a wrong-process
  publication: `client_copyout_or_fill_mapped(pi, ...)` tried the current `ACTIVE_*` mirrors before
  its explicit target process path, so an LSA completion running in lsass could report success after
  writing through lsass' image mirror instead of the connector's image/global storage. Explicit
  copyout helpers now only use active mirrors when `ACTIVE_CLIENT_PI == pi`, and
  `lsa_complete_connect` selects the parked client's mirror context while publishing `*PortHandle`
  and `ConnectInfo`. Serialized headless boot
  `.tmp/boot-lsa-request-timing-20260810-204100.log` still passed the base desktop-background gate
  (`exec_win32k_desktop_painted`) but quiesced before any `\LsaAuthenticationPort` client connect
  was delivered. Review adjustment: keep the copyout fix, then remove the remaining LSA LPC
  receive-order assumptions so the service wave can reach `wkssvc` without synthetic progress.
- I4 queued LSA auth-port rendezvous staged. The later serialized headless run
  `.tmp/run-headless-lsa-lpc-20260810-203214.log` did reach `wkssvc`'s real
  `NtConnectPort(\LsaAuthenticationPort)`, copied back and cached the accepted handle, then exposed a
  real LPC wait-order bug: `wkssvc` immediately issued `LsaLookupAuthenticationPackage` while the LSA
  server thread was between receive calls, so the executive fell through to the generic
  `NtRequestWaitReplyPort` failure path and returned `STATUS_INVALID_HANDLE`. NT queues both
  connection and request messages on the port until the server calls `NtReplyWaitReceivePort`; the
  LSA rendezvous now parks auth-port connects and data-plane requests with their payloads and drains
  whichever pending client is present when the real server receive parks. Local validation:
  `cargo fmt --all`, `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, and `git diff --check`. Review adjustment: run one serialized boot next and
  require the old `LsaLookupAuthenticationPackage() failed! (Status 0xc0000008)` edge to disappear
  before returning to the rpcrt4 context-handle frontier.
- I4 queued LSA auth-port rendezvous boot-proven by
  `.tmp/boot-queued-lsa-rendezvous-20260810-204744.log`. The old
  `LsaLookupAuthenticationPackage() failed! (Status 0xc0000008)` edge did not recur: a later
  service client connected to `\LsaAuthenticationPort`, the real LSA server accepted it, the
  connector cached the accepted handle, and the queued `ApiNumber=3` request was relayed and replied
  through the parked server receive. Service startup advanced into the dynamic Browser service wave
  (`browser ServiceMain`, real pipe listens, and SCM workers) before hitting the next genuine
  frontier: `LoadLibraryExW(c:\windows\system32\wbem\wmisvc.dll)` reported `STATUS_DLL_NOT_FOUND`
  even though the staged ReactOS tree contains `reactos\system32\wbem\wmisvc.dll`, and Browser's
  real `RpcServerListen` then faulted after rpcrt4 could not find server context handle
  `{209079a8-dd34-44b7-a91e-549be2d50a15}` on its association. Review adjustment: keep the LSA
  queued rendezvous, then run one combined boot with the generic worker alias-paging cleanup before
  splitting the next slice between real DLL search/image-demand lookup for `wbem` modules and
  rpcrt4/NPFS association reuse. No fallback DLL success, service-name routing, or synthetic RPC
  context handle should be added.
- A4 worker alias-paging cleanup complete. The generic TP-worker spawn path no longer tracks a fixed
  64-entry mirror page-table bitset derived from the historical services listener window. It now uses
  the executive's growable paging helper for the requested stack mirror and scratch aliases, and
  fails the thread spawn visibly if those aliases cannot be made reachable. Validation:
  `cargo fmt --all`, `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `git diff --check`, and combined headless boot
  `.tmp/boot-combined-lsa-worker-alias-20260810-205754.log` (manually interrupted after the new
  service/RPC frontier because headless QEMU did not self-exit once Browser faulted). Evidence: the
  LSA queued connect/request/reply proof recurred with this change built into the image, generic
  Browser/WKSSVC TP workers spawned on slots 3/4/9/10 without the old fixed-window alias failure, and
  the run reached the same real red edge: `wmisvc.dll` file-missing demand load followed by rpcrt4
  context-handle fault `0x1c00001a`. Review adjustment: commit this cleanup, then implement the
  loader/image-demand path for nested `system32\wbem` DLLs before returning to RPC association state.
- I4 nested service DLL loader boundary staged. Our ntdll runtime loader no longer collapses every
  `LdrLoadDll` request to a basename before issuing `NtOpenFile`; it now keeps a separate module key
  (`wmisvc`) and open name (`c:\windows\system32\wbem\wmisvc.dll`) so full service-DLL paths reach
  the kernel. The executive demand loader now resolves exact DOS/NT paths against the mounted
  ReactOS volume and uses `\reactos\system32` search only for bare or System32-relative dependency
  names. `NtQueryAttributesFile`/`NtOpenFile` System32 existence probes also preserve nested
  subdirectories such as `wbem\wmisvc.dll` instead of dropping to the leaf. Absolute paths outside
  System32 are no longer claimed by the System32 leaf search; they must resolve by exact volume path.
  Local validation: `cargo fmt --all`, `cargo check --manifest-path
  components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `scripts/build_ntdll_dll.sh`, and `git diff --check`. Review adjustment: run one serialized boot
  next and require the old `LoadLibraryExW(c:\windows\system32\wbem\wmisvc.dll)` /
  `wmisvc.dll` file-missing edge to disappear before taking the rpcrt4 context-handle fault as the
  active frontier again.
- I4 nested service DLL loader boundary boot-verified. The serialized headless boot
  `.tmp/boot-ntdll-path-wmisvc-20260810-210804.log` reached desktop background paint at line 5163,
  then loaded WMI from the nested System32 path: `DEMAND-LOAD wmisvc` at line 24908,
  `NtCreateSection(SEC_IMAGE) for wmisvc` at line 24911, and `NtMapViewOfSection wmisvc` at line
  24918. The prior `wmisvc.dll` file-missing edge did not recur; the only demand miss in this run
  was the intentional `apphelp.dll` denied-diverter probe. The run continued through genuine Browser
  service entry (`ServiceMain` at line 25233), then loaded `srvsvc` and `wuauserv`. Current frontier:
  real service RPC listeners still fail with `RpcServerListen() failed (Status 6b1)` at lines 24842,
  25313, and 25486, and the spooler process later hits the existing out-of-image user fault at
  line 25706. Review adjustment: commit the nested loader fix, then make endpoint mapper/RPC server
  listen registration the next target before treating shell chrome pixels as blocked by WMI loading.
- I4 service RPC worker loader initialization staged. The `0x6b1` listener frontier is not a simple
  missing-protseq failure: the same run shows `wkssvc`, `browser`, and `srvsvc` posting real
  `FSCTL_PIPE_LISTEN` waits before their service threads report `RpcServerListen() failed`. The
  dynamic SCM/LSA worker role path was still spawning those generic same-process threads with
  `use_loader: false`, a mode documented for targets without ntdll and not for live ReactOS service
  processes. SCM/LSA RPC worker roles now retain their dynamic runtime identity but enter through the
  same loader-initialized hosted-thread path as ordinary user threads, allowing per-thread loader
  attach/TLS setup before the requested start routine runs. Review adjustment: validate with one
  serialized boot and require the `RpcServerListen() failed (Status 6b1)` edge to move before
  chasing endpoint-mapper/context-handle state.
- I4 GUI client shared-arena fix staged. The later `spoolsv.exe` out-of-image user fault from
  `.tmp/boot-ntdll-path-wmisvc-20260810-210804.log` came from publishing
  `CLIENTINFO.pDeskInfo=0x96ce9280`, then faulting at `pDeskInfo+0x130`. The live server
  `DESKTOPINFO` pointer is allocated under the win32k USER heap, not the POOL arena, so the old
  unconditional pool-delta rewrite made every client-side desktop-info dereference point below the
  mapped shared window. GUI client seeding now maps the USER heap first, translates `DESKTOPINFO`
  through whichever arena owns the live server pointer, and refuses to publish CLIENTINFO if the
  required arena mapping cannot be established. Review adjustment: validate with one serialized
  `./run.sh --desktop`; require `spoolsv.exe`/pi 12 to receive a `pDeskInfo` in the USER shared
  window (`0x98...`) and require the old `0x96ce93b0` parked fault not to recur before taking the
  next shell/print frontier.
- I4 GUI client shared-arena fix boot-verified by
  `.tmp/boot-current-desktop-recover-20260810-212412.log`. The run reached the base desktop paint
  path, then admitted real dynamic `spoolsv.exe` as pi 12 and seeded
  `CLIENTINFO.pDeskInfo=0x988e9280` with the USER heap delta; the old `0x96ce93b0` parked fault did
  not recur. `spoolsv.exe` continued through real win32k dispatches until the boot returned to the
  service RPC frontier, where Browser reports `no context handle found for uuid
  {2fb14db6-8a4f-4dac-bfe2-98821804da45}` followed by `RpcServerListen() failed (Status 6b1)`.
  Review adjustment: commit this shared-arena/print-worker progress, then continue I4 at the
  RPC association/context-handle data path. Do not add UUID-specific handling or service-name
  fallbacks; the fix belongs in generic RPC/NPFS message transport.
- I4 GUI client shared-arena fix re-run with explicit log
  `.tmp/run-user-arena-sas-20260810-212858.log`. This clean lane rebuilt from the dirty tree and
  reproduced the moved edge: winlogon's `CLIENTINFO.pDeskInfo` is now `0x982c5600`, later service GUI
  clients publish `0x98...` USER-window desktop-info pointers (for example pi 3 `0x985c5ef0` and pi
  12 `0x988e9280`), and the old bad `0x969c5ef0`/`0x96ce93b0` dereference is absent. The lane was
  externally terminated before the harness summary, so it is not a shell-pixels proof: periodic
  census still shows `explorer total=0`, and winlogon has not reached the SAS/login message loop in
  this run. Review adjustment: the shared-arena fix is commit-worthy because it removes a real
  generic GUI-client mapping bug; the next blocker remains the generic service RPC/NPFS association
  path (`no context handle found` followed by `RpcServerListen() failed (Status 6b1)`), not explorer
  painting.
- I4 ntdll completion-worker fleet staged. ReactOS `rpcrt4` queues server request packets through
  `QueueUserWorkItem(...WT_EXECUTELONGFUNCTION)`, but our on-target ntdll adapter still funneled
  every `RtlQueueWorkItem`/completion callback through one process-global completion worker even
  though the pure `nt-rtl-work-item` model already had bounded fleet growth. The target adapter now
  uses `WorkerFleet` for completion workers, publishes slot TIDs for `rtl_async_on_worker`, starts
  extra workers for backlog/long-function isolation, retires idle extra workers through the model,
  and releases slots on unexpected transport exit. Persistent work commits the retirement floor only
  after a registered wait is published or a work item is successfully posted. Validation:
  `cargo fmt --all`, `cargo test -p nt-rtl-work-item`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./scripts/build_ntdll_dll.sh`, and `git diff --check`. Review adjustment: run one serialized
  boot with the rebuilt `.tmp/nt-ntdll.dll` and require the service RPC context-handle frontier to
  move or produce a narrower NPFS/RPC association fault before changing endpoint semantics.
- J1 SEC_IMAGE write-copy boundary staged. The PE loader now exposes `ImageProtection`
  (`ReadOnly`, `WriteCopy`, `ExecuteRead`, `ExecuteWriteCopy`) so the executive can classify SEC_IMAGE
  pages through NT allocation protection rather than the old executable-vs-RW helper. Image mapping
  now records process-private image pages only after the process-side map succeeds and retains the
  source cap needed for later write-copy promotion. Validation: `cargo test -p nt-pe-loader`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  and `git diff --check`. Review adjustment: J1 remains in progress until a serialized boot proves
  loader fixups and service DLL writable sections still survive the new write-copy bookkeeping.
- J1 complete / J2 in progress. SEC_IMAGE protection classification now distinguishes shared
  read/write/executable pages from non-shared write-copy pages, and both user-fault and kernel
  copyout COW promotion preserve durable executive aliases for the promoted private frame. Reused
  hosted process slots drop stale SEC_IMAGE frame registrations before publishing fresh main-image
  and ntdll views, and filled-page replay is cleared when a real COW promotion owns the faulted
  page. The same slice wires `NtContinue`, `NtRaiseException`, and their Zw/export stubs through
  ntdll and the executive so native SEH has a real kernel path instead of a breakpoint terminator.
  Validation: `cargo fmt --all`, `cargo test -p nt-pe-loader`, `cargo test -p nt-syscall-abi`,
  `cargo test -p nt-syscall`, `cargo test --manifest-path crates/nt-ntdll/Cargo.toml`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, and `git diff --check`. Serialized desktop run
  `.tmp/boot-cow-alias-desktop-20260810-225615.log` moved past the previous winsrv media-event
  initialization failure: `winsrv.dll` imports are covered, `NtUserInitialize` publishes power/media
  events, base desktop readback succeeds with `desktop-bg 768/768`, real winlogon user callbacks
  continue, and dynamic service children reach wkssvc/browser/srvsvc/wlansvc/spoolsv paths. The run
  was manually stopped before a harness success and still reports `explorer total=0`; the next red
  edge remains generic service RPC/NPFS listener/association behavior, with repeated
  `RpcServerListen() failed (Status 6b1)`. Do not paper over this with service-name, executable,
  launch-order, or shell-paint fallbacks.
