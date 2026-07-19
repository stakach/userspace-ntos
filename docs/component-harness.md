# Unified Component-Runtime Harness — Design Note

Status: **IMPLEMENTED — Phase B complete.** The design below was fully realised: the FSD (npfs,
both instances + a 2nd by-path IRP driver) and win32k are now migrated onto the shared
`component_main`/`component_pump` harness (Steps 1/2/4/4.5 DONE; see `tasks/todo.md`). Gate at
authorship: **180/98**; current gate after the migration + Phase-A consolidation: **183/98, fully
green** (clean `qemu_exit`, `exec_win32k_desktop_painted` 768/768, `exec_fsd_on_shared_harness` +
`exec_win32k_on_shared_harness` PASS). The rest of this note reads as the design of record; the
consolidated final state is summarised in **§6** below.

All file:line citations are to `components/ntos-executive/src/` unless noted.

---

## 0. Executive summary

Four isolated seL4 components — **win32k.sys**, **npfs.sys (FSD)**, the **KMDF host**, and the
**PnP/NIC driver-host** — already share ONE launcher: `spawn_hosts.rs::spawn_component(&ComponentDescriptor)`
(`spawn_hosts.rs:103`). The four `spawn_*` builders (and the two inlined descriptors in `main.rs`) are
thin data builders over it. That consolidation is DONE.

What is NOT yet shared is the **run loop** each component enters after `spawn_component` resumes it, and
the **executive-side driver** that pumps it. Investigation shows the four components fall into **two
structural families**, not four variants of one:

* **Family A — persistent dispatch servers** (`npfs` FSD + `win32k`): run `DriverEntry(DRIVER_OBJECT,
  RegistryPath)`, then loop `send_done → recv_req → dispatch(req) → write reply`. On the executive side a
  fault-recv loop pumps them: fill the shared frame → `ep_send(DISPATCH_LABEL)` → recv, demand-mapping
  page faults and replying, until the component sends its DONE label. **These two are near-identical in
  shape** and are the real consolidation target.
* **Family B — one-shot lifecycle runners** (`driver_host` + `kmdf_host`): pre-map everything, run a
  fixed lifecycle to completion internally, write a verdict to their shared frame, `SYS_SEND` on
  `CT_RESULT_NTFN`, and park. The executive `ep_recv`s the result notification ONCE; there is NO
  demand-map dispatch loop (their fault EP is armed for crash-containment only — `main.rs:6632`, `:6722`).

The design therefore delivers a **`component_main` harness for Family A** (the recv→dispatch→reply
server loop + its executive-side pump), parameterised by a `dispatch(req) -> reply` callback and a set of
**capability flags** on `ComponentDescriptor` that gate win32k's irreducible specifics. Family B is
folded to the extent it shares the DriverEntry preamble + the result-notify epilogue (a much smaller
`run_once` shape), but it is explicitly NOT forced onto the Family-A dispatch protocol — doing so would be
new behaviour, not a refactor.

---

## 1. Shared-vs-specific map (with file:line)

### 1.1 The already-shared launcher

`ComponentDescriptor<'a>` (`spawn_hosts.rs:65-88`): `entry` (fn ptr), `image_rights`, `map_heap_pt`,
`stack_base/stack_frames/stack_dedicated_pt`, `regions: &[Region]`, `granted: GrantedCaps`, `prio`,
`gs_base`. `GrantedCaps` (`:57-61`): `irq_ntfn`, `result_ntfn`, `fault_ep` (all `Option<u64>`).
`spawn_component` (`:103-172`) builds PML4 + image skeleton + stack + IPC buffer + regions + a guarded
CNode (PML4 + granted caps) + TCB, sets entry/stack/prio/gs, attaches an SC, resumes. Returns
`SpawnedComponent { pml4, tcb, cnode, stack_frame_base }` (`:91-98`). **Unchanged by this work** except
for added capability flags (§2.3).

### 1.2 Family A — persistent dispatch servers

| Step | FSD / npfs | win32k |
|---|---|---|
| Component entry | `fsd_component_entry` `driver_launch.rs:785-852` | `win32k_subsystem_entry` `win32k_subsystem.rs:2662-2717` |
| Build `DRIVER_OBJECT` + `RegistryPath` from pool | `:795-818` | `:2668-2679` |
| Mark `V_ENTERED`, call `DriverEntry` (`extern "win64" fn(u64,u64)->i32`) | `:820-824` | `:2682-2686` |
| Record verdict/status/mj-table into shared frame | `:826-841` | `:2688-2696` |
| **(win32k-only) establish client + connect** | — | `establish_client_and_dispatch()` `:2708-2710` |
| Enter recv→dispatch→reply loop | `dispatch_loop(drv)` `:851`, body `:885-904` | `dispatch_loop()` `:2716`, body `:3344-3448` |
| Ready/done signal (plain Send on `CT_FAULT`, distinct label) | `send_done` `:856-867`, `FSD_DISPATCH_LABEL=0x771` `:116` | `send_done` `:2958-2968`, `W32_DISPATCH_LABEL=0x770` `:487` |
| Block for request (plain Recv on `CT_FAULT`) | `recv_req` `:870-880` | `recv_req` `:2974-2983` |
| **Dispatch routing** | `DriverObject->MajorFunction[major]` at `mj_base+major*8` `:892` | SSDT: `dispatch_ssn` `:2722-2948`, `handler = [SH_SSDT_BASE + (ssn-0x1000)*8]` `:2733` |
| **Arg marshal** | fixed IRP build `run_irp` `:915-1090` | wide-arg reconstruct via `win32k_ssn_argc` + exact-arity transmute `:2737-2786` |
| Write reply (status/info/seq) | `:899-902` | `:3444-3446` |

**Shared-frame protocol** — both use one RW page shared into the executive, with a header of fixed
offsets. FSD `FSD_SHARED_VADDR=0x…0F38_0000` (`driver_launch.rs:78`), offsets `:88-103`
(`SH_ENTRY_RVA=0x00`, `SH_VERDICT=0x08`, … `SH_REQ_MAJOR=0x40`, `SH_REQ_MINOR=0x48`, `SH_REQ_FSCTL=0x50`,
`SH_REQ_INLEN=0x58`, `SH_REQ_OUTLEN=0x60`, `SH_REQ_FILEID=0x68`, `SH_REQ_STATUS=0x70`, `SH_REQ_INFO=0x78`,
`SH_REQ_SEQ=0x80`). win32k `WIN32K_SHARED_VADDR=0x…0718_0000` (`win32k_subsystem.rs:104`), offsets
`:141-176` (`SH_ENTRY_RVA=0x00`, `SH_VERDICT=0x08`, `SH_DE_STATUS=0x10`, `SH_SSDT_BASE=0x18`,
`SH_REQ_SSN=0x50`, `SH_REQ_A0..A3=0x58/0x60/0x68/0x70`, `SH_REQ_STATUS=0x78`, `SH_REQ_SEQ=0x80`,
`SH_FONT_SIZE=0x88`, wide-arg tail `SH_REQ_A4=0x90 .. SH_REQ_NARGS=0xF0`).

> Note: the two frames deliberately DIFFER in their per-request field offsets (`SH_REQ_MAJOR=0x40` for
> IRP vs `SH_REQ_SSN=0x50` for SSN) and DONE labels (0x771 vs 0x770). The header prefix (0x00-0x30) is
> the same shape (entry-rva / verdict / status). This is the seam to unify.

**Executive-side pump** — the fault-recv/demand-map/reply shapes are structurally the SAME:

* FSD per-IRP pump `npfs_dispatch_irp` `driver_launch.rs:1584-1654`: fill request `:1603-1610`,
  `ep_send(ep, FSD_DISPATCH_LABEL)` `:1614`, `ep_recv_full` `:1615`, loop: label `FSD_DISPATCH_LABEL`
  = done `:1619`; label `6` (VMFault) → `ensure_paging` + `alloc_frame` + `page_map(RW_NX, pml4)` +
  `reply_recv_full(ep, …)` `:1621-1636`; read back status/info `:1646-1652`. (Init-time variant in
  `load_driver` `:1402-1455`.)
* win32k pump `win32k_dispatch_wide` `win32k_glue.rs:388-614`: attach client `:405-406`, fill request +
  wide-args `:408-424`, `ep_send(w_fault, W32_DISPATCH_LABEL)` `:443`, recv `:444-448`, loop: label `6`
  (VMFault, with foreign/client-frame-share + internal-low branches) `:451-550`; label
  `W32_DISPATCH_LABEL` = done `:551-557`; label `3` (UserException / int-0x2c assert-skip) `:558-591`;
  else wall `:592-612`.

The **skeleton is identical**: `ep_send(DISPATCH_LABEL)`, recv, `loop { match label { fault => demand +
reply-recv-continue, DONE => read status + return, else => wall } }`. What differs is (i) the reply
transport (FSD uses `reply_recv_full` on the fault EP; win32k uses a bound per-caller reply cap REPLY_W32
via `send_on_reply`/`recv_full_r12`), and (ii) win32k's extra fault sub-cases. Both are expressible as
capability-gated branches of ONE loop (§2.4).

### 1.3 Family B — one-shot lifecycle runners

`driver_host_entry` `driver_host.rs:19-100`: parse `CM_RESOURCE_LIST` `:26-27`, drive MMIO + confined DMA
`:39-81`, host a real `.sys` via `driver_pe::sys_start` `:86-88`, write verdict `:89/:95`,
`SYS_SEND CT_RESULT_NTFN` `:96`, park `:97-99`. Executive side: `ep_recv(dh_result)` ONCE `main.rs:6633`.

`kmdf_host_entry` `kmdf_host.rs:766-779`: read entry RVA `:769`, `run(entry_rva)` (full WDF lifecycle
`:633-761`), write verdict `:771`, `SYS_SEND CT_RESULT_NTFN` `:775`, park `:776-778`. Executive side:
`ep_recv(kmdf_result)` ONCE `main.rs:6723`.

**No recv→dispatch→reply loop; no demand-map pump.** Shared frames are ad-hoc verdict scratch
(`RESLIST_VADDR+0x200/0x210` for driver-host; `KMDF_SHARED_VADDR+0/8/0x10` for kmdf). fault EP is
containment-only. What Family B DOES share with Family A is the top of the file — nothing routes IRPs to
them today. They already share `spawn_component` + the `DriverExportRegistry` IAT mechanism
(`FSD_EXPORTS` `driver_launch.rs:668`, `KMDF_EXPORTS` `kmdf_host.rs:488`, win32k's own export registry).

### 1.4 The irreducible win32k-specific behaviours (MUST survive exactly)

| # | Behaviour | Lives at |
|---|---|---|
| (c) | Client-memory attach (KeStackAttachProcess model): `w32_client_attach` (detach prev client's pages), `map_csrss_page_into_win32k` (share client frame at identity VA, RW so out-params propagate) | `win32k_glue.rs:157-179`, `:184-199`; attach tables `:130-153`; `ensure_w32_client_paging` `:88-110` |
| (d) | Usermode callback / WINDOWPROC bridge: `s_ke_user_mode_callback`, `api==0` WINDOWPROC → `Result=1` (WM_NCCALCSIZE→0) so `co_UserCreateWindowEx` continues | `win32k_subsystem.rs:2162-2240`, bound `:2349` |
| (e) | Wide-arg stack marshal: executive stages client stack args into `SH_REQ_A4..`, `SH_REQ_NARGS`; component transmutes to exact arity | exec `win32k_glue.rs:415-423`; component `win32k_subsystem.rs:2737-2786`; `win32k_ssn_argc` `:185-324`; forward arm `service_sec_image.rs:3120-3122` |
| (f) | Demand-fault CLIENT-FRAME-SHARING (foreign-pointer detection + internal-low zero-fill discrimination) | `win32k_glue.rs:451-550` (foreign detect `:464-466`) |
| (g) | Checked-build int-0x2c ASSERT-SKIP (verify `CD 2C` via executive RW image view, resume IP+2) | `win32k_glue.rs:558-591` |
| (h) | REPLY_W32 nesting fix (Fix A: DONE via plain Send not Call; Fix B: nested faults answered through per-caller REPLY_W32 cap so REPLY_MAIN's binding to the outer csrss caller survives) | `win32k_glue.rs:434-448`, `:534-545`; component `win32k_subsystem.rs:2950-2983`; self-test `SSN_TEST_FAULT` `:358-364` |

Load-bearing fragilities flagged in-code (do NOT "clean up"): pool must stay a pre-mapped bump arena
(`win32k_subsystem.rs:50-54, 499-501`); win32k's own stack must NOT be at `STACK_BASE` (`:55-60`);
FreeType arena isolation (`:524-547`); gptiDesktopThread == current dispatch thread (`:3030-3044`);
BATCH-43 thread↔desktop re-assert before every dispatch (`:3372-3404`); BATCH-44 wide-arg garbage-hMenu
wall (`:162-184` + `service_sec_image.rs:3245-3253`); BATCH-46 paint trigger `co_IntGraphicsCheck(TRUE)`
(`:2788-2872`).

---

## 2. The unified harness design

### 2.1 Scope decision

Consolidate **Family A** (npfs + win32k) onto ONE component-side `component_main` and ONE executive-side
`component_pump`. Fold **Family B** (driver-host + kmdf) onto a much thinner shared `run_once` preamble/
epilogue only (DriverEntry call + result-notify). Do NOT force Family B onto the Family-A dispatch
protocol.

### 2.2 The request/reply protocol over the shared frame

Introduce a KIND-tagged request header at a FIXED offset (choose an offset unused by BOTH frames — e.g.
carve `SH_REQ_KIND` at 0x38, which is free in both the FSD header (0x30 pool-used → 0x40 req-major) and
the win32k header (0x30 pool-used/index → 0x50 req-ssn)). Verify 0x38 is free in both before use.

```
// nt-component-abi (new tiny module, or a shared const block in the harness):
pub const SH_REQ_KIND:   u64 = 0x38; // in: ReqKind tag
pub const SH_REQ_STATUS: u64 = 0x78; // out: NTSTATUS (unify: FSD uses 0x70, win32k 0x78 — see note)
pub const SH_REQ_SEQ:    u64 = 0x80; // out: monotonic seq (both already agree)

#[repr(u64)]
pub enum ReqKind { Irp = 0, Syscall = 1 }
```

The per-KIND payload keeps its EXISTING offsets to avoid churn:
* `ReqKind::Irp` reads `SH_REQ_MAJOR/MINOR/FSCTL/INLEN/OUTLEN/FILEID` at their current FSD offsets
  (0x40..0x68) and writes `SH_REQ_STATUS(0x70)/INFO(0x78)`.
* `ReqKind::Syscall` reads `SH_REQ_SSN(0x50)/A0..A3(0x58-0x70)/A4..(0x90)/NARGS(0xF0)` and writes
  `SH_REQ_STATUS(0x78)`.

**Status-offset collision (0x70 vs 0x78):** FSD writes status at 0x70 and info at 0x78; win32k writes
status at 0x78. These do NOT need to unify — the harness reads the status offset appropriate to the
`ReqKind`. Keeping both is the low-risk choice; a later tidy-up (Phase A) may align them. The KIND tag +
DONE-label stay distinct per component (0x770/0x771) so the executive can always tell them apart even if
one frame is stale.

`SH_REQ_KIND` is written by the component builder at spawn time (constant per component) — win32k always
Syscall, FSD always Irp — so no per-request write is needed; a runtime KIND only matters if a single
component ever served both (none does today).

### 2.3 Capability flags on `ComponentDescriptor`

Add a `caps: HostCaps` field (default all-false → byte-identical to today for Family B and the FSD):

```
#[derive(Clone, Copy, Default)]
pub(crate) struct HostCaps {
    /// Component runs a persistent recv→dispatch→reply server loop (Family A).
    /// false => one-shot run_once (Family B).
    pub dispatch_server: bool,
    /// Dispatch KIND the server speaks (only meaningful when dispatch_server).
    pub kind: ReqKind,                 // Irp | Syscall
    /// win32k: attach the calling client's user memory (w32_client_attach) before each dispatch,
    /// and share foreign client frames on demand-fault instead of zero-filling.
    pub client_attach: bool,
    /// win32k: honour KeUserModeCallback / WINDOWPROC bridge (component-side registration only —
    /// this flag documents the capability; the callback is bound in DriverEntry).
    pub usermode_callback: bool,
    /// win32k: stage wide (>4) stack args from the caller frame into SH_REQ_A4.. / SH_REQ_NARGS.
    pub wide_arg_marshal: bool,
    /// win32k: skip checked-build int-0x2c NT_ASSERTs (resume IP+2) on a label-3 UserException.
    pub assert_skip: bool,
    /// win32k: answer nested demand-page faults through a per-caller reply cap (REPLY_W32) rather
    /// than the fault EP's reply_recv, so an outer caller's reply binding survives.
    pub nested_reply_cap: bool,
}
```

`ComponentDescriptor` gains `pub caps: HostCaps` (`spawn_hosts.rs:88`). Every existing builder gets
`caps: HostCaps::default()` (byte-identical). The FSD builder sets `{ dispatch_server: true, kind: Irp }`.
The win32k builder sets `{ dispatch_server: true, kind: Syscall, client_attach: true,
usermode_callback: true, wide_arg_marshal: true, assert_skip: true, nested_reply_cap: true }`.

The flags are consumed on the EXECUTIVE side (`component_pump`, §2.4) to gate the win32k-only branches.
The component side reads them from its shared frame is NOT needed — win32k's component-side specifics
((d) usermode callback registration, (e) exact-arity transmute) are already keyed off the KIND/SSN, not a
runtime flag. So the flags primarily unify the *executive-side* loop.

### 2.4 The unified executive-side pump (`component_pump`)

The two Family-A pumps (`npfs_dispatch_irp`, `win32k_dispatch_wide`) merge into one, with win32k's extras
behind `caps` checks. Signature:

```
pub(crate) struct PumpChannel {
    pub fault_ep: u64,       // dispatch + fault channel (CT_FAULT peer)
    pub pml4: u64,           // component VSpace for demand-map
    pub code_va: u64, pub image_frames: u64,  // W^X / in-image wall bounds
    pub shared_va: u64,      // SH_* frame base
    pub dispatch_label: u64, // 0x770 (win32k) / 0x771 (FSD)
    pub reply_cap: u64,      // REPLY_W32 slot, or 0 => use reply_recv_full on fault_ep
    pub client_pi: u64,      // for client_attach / foreign-frame sharing (win32k)
    pub caps: HostCaps,
}

/// Drive ONE request: wake the parked server, demand-map its faults, return its NTSTATUS.
/// Returns (status, completed).
pub(crate) unsafe fn component_pump(ch: &PumpChannel) -> (i32, bool);
```

Body (single loop; the diffs from today are all `if ch.caps.*`):
1. if `caps.client_attach`: `w32_client_attach(ch.client_pi)`.
2. Request fields are ALREADY written by the caller (both `npfs_dispatch_irp` and the win32k forward arm
   fill the frame before calling the pump); the pump only writes wide-args when `caps.wide_arg_marshal`
   (stage `SH_REQ_A4../NARGS` from the caller SP). Clear `SH_REQ_STATUS`.
3. `ep_send(ch.fault_ep, ch.dispatch_label)`; recv (via `recv_full_r12(fault_ep, reply_cap)` when
   `caps.nested_reply_cap && reply_cap!=0`, else `ep_recv_full`).
4. `loop { match label:`
   * `6` (VMFault): demand-map. Base case (both families) = `ensure_paging`/`ensure_w32_client_paging` +
     `alloc_frame` + `page_map(RW_NX, pml4)`. If `caps.client_attach`: run the foreign-pointer detection
     (`win32k_glue.rs:464-524`) — share the client frame or internal-low zero-fill. Reply-continue via
     `send_on_reply(reply_cap,…)`+`recv_full_r12` when `nested_reply_cap`, else `reply_recv_full`.
   * `dispatch_label`: read `SH_REQ_STATUS` (offset per `caps.kind`), return `(status, true)`.
   * `3` (UserException): if `caps.assert_skip` and bytes are `CD 2C` → resume IP+2. Else wall.
   * else: wall (print + return `(0xC0000001,false)`). `}`

This preserves EVERY win32k branch verbatim; for the FSD, all `caps.*` are false so the loop degenerates
exactly to today's `npfs_dispatch_irp` inner loop. **The two executive-side loops CAN and SHOULD merge**
into `component_pump`. (Confirmed the shapes match: `ep_send`+recv+`match label {6, DONE, else}` in both;
the reply transport and win32k's sub-cases are the only diffs, all now flag-gated.)

The request *fill* (IRP struct build vs SSN+args) stays in the CALLER (`npfs_dispatch_irp` /
win32k forward arm), because it is genuinely KIND-specific; the pump is the shared IPC + fault engine.

### 2.5 The unified component-side entry (`component_main`)

```
/// Component-side shared entry: build DRIVER_OBJECT + RegistryPath, call DriverEntry, record the
/// verdict, then EITHER enter the persistent dispatch loop (Family A) or return to the caller for a
/// one-shot lifecycle (Family B).
pub(crate) unsafe fn component_main(
    shared_va: u64,
    code_va: u64,
    // dispatch(ssn_or_major, a0..a3, nargs) -> status ; called per request inside the loop.
    dispatch: unsafe fn(&DispatchReq) -> i32,
    post_driver_entry: unsafe fn(status: i32),  // win32k: establish_client_and_dispatch; FSD: no-op
    run_loop: bool,                              // true = Family A dispatch_loop; false = return
    dispatch_label: u64,
) -> i32;  // returns DriverEntry status (Family B continues; Family A never returns)
```

* Preamble (identical today at `fsd_component_entry:788-849` and `win32k_subsystem_entry:2663-2701`):
  read entry RVA, build DRIVER_OBJECT (0x150/0x200) + zero-len RegistryPath, `V_ENTERED`, call
  `DriverEntry`, record verdict/status/pool-used.
* `post_driver_entry(status)`: FSD = no-op; win32k = `establish_client_and_dispatch()` (keeps (c)/(h)
  bring-up).
* If `run_loop`: the shared server loop `{ send_done(dispatch_label); recv_req(); read req from SH_*;
  status = dispatch(&req); write SH_REQ_STATUS + bump SH_REQ_SEQ; }`. `send_done`/`recv_req` are already
  byte-identical between the two (`driver_launch.rs:856-880`, `win32k_subsystem.rs:2958-2983`) — hoist
  ONE copy into the harness, parameterised by `dispatch_label`.
* The `dispatch` callback:
  * FSD plugs an IRP router: `major → MajorFunction[major] → run_irp`.
  * win32k plugs an SSN router: `ssn → dispatch_ssn` (which itself owns the exact-arity transmute (e) —
    that stays win32k-internal, keyed off `win32k_ssn_argc`).

DriverEntry preamble differences that MUST be parameterised (not hard-coded): DRIVER_OBJECT size (FSD
0x150 / win32k 0x200) and DriverExtension offset (0x68 / 0x30) — pass as fields of a small
`DriverObjectSpec` so the byte layout each `DriverEntry` expects is preserved.

### 2.6 Family B fold (`run_once`)

`driver_host_entry` / `kmdf_host_entry` share only: run a fixed body → write verdict → `SYS_SEND
CT_RESULT_NTFN` → park. Extract a `run_once(body: unsafe fn() -> u32, verdict_va: u64)` that runs `body`,
stores its verdict, signals `CT_RESULT_NTFN`, and parks. The bodies (CM_RESOURCE_LIST/DMA vs WDF
lifecycle) stay component-specific. This is a small win (the notify+park epilogue) and is OPTIONAL — do it
last, low priority; it is NOT the point of this task.

---

## 3. Incremental migration order (safest first, win32k LAST)

Each step MUST leave the gate at **180/98** and qemu_exit clean. Verify the named specs stay PASS. Every
step is a separate commit = a rollback point.

### Step 0 — land the ABI scaffolding, wire NOTHING (pure additive)
* Add `HostCaps` + `ReqKind` + `SH_REQ_KIND` const + `caps: HostCaps` field to `ComponentDescriptor`
  (default). Add `caps: HostCaps::default()` to all 6 descriptor sites. Define `component_pump`,
  `component_main`, `run_once` as NEW fns but call them from NOWHERE.
* Verify: full gate 180/98 (no call sites changed → byte-identical). Build only; no behaviour.
* Rollback: revert the additive commit.

### Step 1 — migrate the FSD (npfs) executive pump onto `component_pump`
* Re-express `npfs_dispatch_irp`'s inner loop as a `component_pump` call with `caps = { dispatch_server,
  kind: Irp }` (all win32k flags false). Keep the request-fill (IRP field writes + ARG copy) in
  `npfs_dispatch_irp`; only the `ep_send`+fault-loop moves into the pump.
* Also migrate the FSD *init-time* fault loop (`load_driver:1402-1455`) — it is the same shape with
  `dispatch_label = FSD_DISPATCH_LABEL`.
* Verify: `npfs_driver_entry_entered/_success`, `npfs_major_function_table`, `npfs_isolated_vspace`
  (`main.rs:7178`), `npfs_dispatch_roundtrip`, `npfs_create_named_pipe_complete`,
  `npfs_client_connect_finds_fcb`, `npfs_set_pipe_information`,
  `exec_pipe_syscalls_routed_through_npfs` (`main.rs:7583`), `exec_pipe_data_plane_*`,
  `exec_npfs_flush_pending`. Full gate 180/98.
* Rollback: revert; `npfs_dispatch_irp` keeps its inline loop.

### Step 2 — migrate the FSD component entry onto `component_main`
* Re-express `fsd_component_entry` as `component_main(...)` with an IRP `dispatch` closure (`major →
  run_irp`), `post_driver_entry = no-op`, `run_loop = true`, `DriverObjectSpec{size:0x150, ext:0x68}`.
  Hoist `send_done`/`recv_req` into the harness.
* Verify: same npfs spec set as Step 1. Full gate 180/98.
* Rollback: revert; keep `fsd_component_entry` bespoke.

### Step 3 — fold Family B onto `run_once` (OPTIONAL, low-risk, do before win32k for confidence)
* `driver_host_entry` + `kmdf_host_entry` call `run_once(body, verdict_va)`.
* Verify: `exec_driver_host_drove_nic` (`main.rs:6640`), `exec_sys_driver_entry_ok`,
  `exec_sys_start_reached_real_nic`, `exec_kmdf_driver_create`, `exec_kmdf_adddevice_queue`,
  `exec_kmdf_prepare_hw_read_real_nic`, `exec_kmdf_ioctl`, `exec_kmdf_remove`, `exec_kmdf_read_real_nic`.
  Full gate 180/98.
* Rollback: revert.

### Step 4 — migrate win32k LAST, capability-gating every specific
* 4a. Executive pump: replace `win32k_dispatch_wide`'s loop with `component_pump` using `caps = { all
  win32k flags true }`, `reply_cap = REPLY_W32_SLOT`, `client_pi = W32_CLIENT_PI`. The foreign-frame
  sharing (f), int-0x2c skip (g), REPLY_W32 nesting (h), wide-arg staging (e) all move behind their
  respective flags INSIDE the shared loop — no logic deleted, only relocated. Keep the win32k forward arm
  (`service_sec_image.rs:3120-3122`) filling `SH_REQ_SSN/A*` and computing `nargs = win32k_ssn_argc`.
* 4b. Component entry: `win32k_subsystem_entry` → `component_main(...)` with an SSN `dispatch` closure
  (`ssn → dispatch_ssn`, which retains (e)), `post_driver_entry = establish_client_and_dispatch`,
  `DriverObjectSpec{size:0x200, ext:0x30}`.
* Verify (THE critical gate): `exec_win32k_desktop_painted` == 768/768 @ 0x003a6ea5 (`main.rs:8048`,
  driver `service_sec_image.rs`), plus `exec_win32k_*connect*`, the SSN_TEST_FAULT round-trip
  (nested-reply proof), and the whole 180/98. Compare the boot serial for win32k `[w32disp]` fault
  sequence + `[w32attach]` client-switch lines against a pre-migration reference boot to confirm
  byte-identical dispatch behaviour.
* Rollback: revert 4a/4b independently; win32k keeps its bespoke loop.

### Step 5 — retire the now-duplicated bespoke functions
* Once all four route through the harness, delete the dead inner loops (guarded per-step so each deletion
  is its own commit). This is the tail of Phase B; the broader dead-code/diagnostic tidy is **Phase A**,
  which the user chose to do AFTER harness-first.

---

## 4. Risk register

| Risk | Where | Mitigation |
|---|---|---|
| **The REPLY_W32 nesting fix (h) regressing** — merging the reply transport could reintroduce the reply_to clobber that made win32k never run | `win32k_glue.rs:434-448, 534-545` | Keep `nested_reply_cap` a strict flag; when true the pump uses `recv_full_r12`/`send_on_reply` on `reply_cap` EXACTLY as today; when false it uses `reply_recv_full`. Do NOT collapse the two transports. Prove with `SSN_TEST_FAULT`. |
| **The paint gate (`exec_win32k_desktop_painted` 768/768)** — any change to the demand-fault client-frame sharing or the wide-arg marshal breaks winlogon's window creation → no paint | `win32k_glue.rs:451-550`, `:415-423` | win32k migrated LAST; diff boot serial `[w32disp]`/`[w32attach]` against reference; the foreign-frame branch relocates verbatim behind `client_attach`. |
| **int-0x2c assert-skip (g) altitude** — verifying `CD 2C` via the executive RW image view must stay | `win32k_glue.rs:558-591` | Behind `assert_skip`; byte-for-byte relocation; keep the global `W32_ASSERT_LOG` gate + per-dispatch `skips<4000` bound. |
| **Client-attach detach/remap ordering (c)** — `w32_client_attach` must run BEFORE the request fill each dispatch or a stale client's frames leak in | `win32k_glue.rs:157-179`; forward arm sets `W32_CLIENT_PI` `service_sec_image.rs:2849` | Pump step 1 does `client_attach` first, exactly as `win32k_dispatch_wide:405-406`. |
| **Status-offset unification (0x70 vs 0x78)** — a wrong read = wrong NTSTATUS to the caller | §2.2 | Do NOT unify; read the offset by `caps.kind`. |
| **`SH_REQ_KIND=0x38` collision** — must be free in BOTH frames | §2.2 | **UNCERTAIN — implementer MUST verify** 0x38 is unused in the FSD frame (between `SH_POOL_USED=0x28` and `SH_REQ_MAJOR=0x40`) and the win32k frame (between `SH_SSDT_INDEX=0x24` and `SH_REQ_SSN=0x50`). If not free, pick another gap or drop `SH_REQ_KIND` and key KIND off the descriptor (constant per component) — likely sufficient since no component serves both KINDs. |
| **DriverObject byte-layout parameterisation** — FSD (0x150, ext 0x68) vs win32k (0x200, ext 0x30) | `driver_launch.rs:795-810`, `win32k_subsystem.rs:2668-2673` | Pass a `DriverObjectSpec`; each DriverEntry reads the layout it expects. |
| **Family B is NOT a dispatch server** — attempting to force it onto `component_pump` would be new behaviour | §1.3 | Keep Family B on `run_once` only; do NOT route IRPs to it. |
| **win32k's component-side `dispatch_loop` extras** (BATCH-43 thread↔desktop re-assert `:3372-3404`, setup_dispatch_context) are INSIDE the loop, not the harness | `win32k_subsystem.rs:3344-3448` | The `dispatch` closure / `post_driver_entry` retains them; `component_main`'s loop only owns send_done/recv_req/status-writeback. Confirm no reordering. |

**Flagged uncertainties for the implementer to verify from code (not fully confirmable in a read pass):**
1. Whether the win32k `dispatch_loop` writes `SH_REQ_STATUS` at 0x78 vs the FSD 0x70 in the exact same
   relative position when abstracted (confirm `SH_REQ_SEQ=0x80` is shared — it appears so).
2. Whether `establish_client_and_dispatch()` must run strictly between DriverEntry and the FIRST
   `send_done` (it does today — the first `send_done` IS the "DriverEntry+attach done" signal). The
   harness must preserve that ordering.
3. Whether the FSD init-time fault loop (`load_driver:1402-1455`) and the per-IRP loop
   (`npfs_dispatch_irp:1584-1654`) have any subtle DEMAND_CAP / guard difference (512 vs 256) that must
   be a `PumpChannel` field.

---

## 5. Adding / running a new (user-specified) driver — the reusable substrate

**First-class requirement:** the unified harness must be the REUSABLE substrate for arbitrary,
USER-SPECIFIED drivers loaded BY-PATH — a user can point at a `.sys` and have it run — with **zero
bespoke per-driver code**. Adding a driver = *stage the `.sys` by path + declare its CLASS* → it runs
through the SAME `component_main` + `component_pump`. This section maps the current by-path path, states
the goal, gives the class→caps mapping, the exact add-a-driver recipe, and the gaps the harness work MUST
close.

### 5.1 The current general dynamic path (with file:line)

* **The general by-path loader:** `load_driver(fs, path, class)` `driver_launch.rs:1330-1489`. Today it:
  (a) `if class != DriverClass::Fsd { return None }` `:1335-1338` — **only FSD is routed; Device and
  Subsystem are stub seams**; (b) `load_file_to_pool(fs, path)` reads the `.sys` bytes by path `:1341`
  (the full-FS by-path loader — see MEMORY `project_full_fs`); (c) maps executive-side CODE/POOL/DATA/
  SHARED/ARG frames `:1351-1387`; (d) `load_pe_into(src_va, code_va, img_frames, rights, fsd_export_addr)`
  — the **driver-agnostic** PE parse+copy+DIR64-reloc+IAT-patch with an INJECTED name resolver
  `:1159-1316`, `:1391`; (e) builds the FSD-class descriptor + `spawn_component` via
  `spawn_fsd_component` `:1398-1400`, `:1492-1530`; (f) drives the init fault-recv loop `:1402-1455`;
  (g) returns a `DriverComponent { pml4, fault_ep, code_va, mj_table, devobj, verdict, finished }`
  `:1121-1136`, `:1487`.

* **The IAT resolver is already generic:** `load_pe_into` takes `resolve: fn(&str) -> u64` `:1164`; the
  FSD passes `fsd_export_addr` `:745-770` which resolves ntoskrnl imports through a
  `DriverExportRegistry` (`FSD_EXPORTS` `:668`) — the SAME mechanism win32k + KMDF use
  (`nt-compat-exports`). Unbound names fail soft to `s_true`/`s_zero` with an audit log `:745-774`. This
  is reusable across drivers UNCHANGED (comment `:667` "Reusable for the next FSD (fastfat) unchanged").

* **The persistent IRP dispatch server:** `fsd_component_entry` `:785-852` (DriverEntry → `dispatch_loop`)
  + the executive per-IRP pump `npfs_dispatch_irp` `:1584-1654`, keyed off `DriverObject->
  MajorFunction[major]`. This IS the Family-A shape §1.2 — the canonical persistent-driver substrate.

* **How a user "specifies a driver to run" TODAY:** there is **no user-facing driver list / class
  registry / boot enumeration**. `load_driver` has exactly ONE call site: `main.rs:7165`, hardcoded
  `load_driver(&fs, b"reactos\\system32\\drivers\\npfs.sys", DriverClass::Fsd)`. The two *fixture*
  drivers (PnpMmioInterruptTest.sys, KmdfBasicTest.sys) do NOT go through `load_driver` at all — they are
  read by-path with `load_file_to_pool` then handed to the bespoke `driver_host_entry`/`kmdf_host_entry`
  one-shot fixtures (`main.rs:6669-6720`) = Family B. So "run a driver" today = one hardcoded FSD.

* **How `.sys` files reach the by-path FS:** `rust-micro/scripts/make_image.sh:145-164` stages
  `nt-driver-test-fixtures/fixtures/*.sys` into `::reactos/system32/drivers/`; real ReactOS drivers
  arrive via the recursive `\reactos` tree copy `:130-140`. So "add a driver's bytes" = drop the `.sys`
  under `\reactos\system32\drivers\` (either fetched or staged like the fixtures).

### 5.2 The reusability goal (what the harness must guarantee)

Adding a NEW driver must reduce to **two declarative inputs**, no code:

1. **Stage the `.sys` by path** under `\reactos\system32\drivers\NAME.sys` (fetched or staged in
   `make_image.sh`, exactly like the fixtures).
2. **Declare its policy:** a `DriverSpec { path, class }` entry. `class` selects `HostCaps` + granted
   caps + regions (§5.4). Nothing else.

Then `load_driver(path, class)` builds the `ComponentDescriptor` FROM the class, `spawn_component`s it,
and it runs as a Family-A IRP dispatch server through the SAME `component_main` (recv→dispatch→reply) +
`component_pump` (executive fault/IRP loop). The driver's own `DriverEntry` registers its
`MajorFunction[]` handlers; the harness routes IRPs to them. **No bespoke entry loop, no hand-written
dispatch skeleton, no new fault loop.**

`ComponentDescriptor` + `HostCaps` + `class` are the SINGLE declarative surface. The design in §2 already
delivers the generic run loop; §5.4-5.6 make `load_driver` build the descriptor from `class` so an
arbitrary driver needs zero per-driver code.

### 5.3 Family A (persistent IRP server) is the DEFAULT driver path — NOT Family B

A real user-specified driver (FS filter, NIC, class driver, …) registers MajorFunction handlers in
`DriverEntry` and services IRPs over its whole lifetime. That is **Family A, `kind = Irp`, all win32k
caps false** — the npfs substrate. **This is the canonical, default path for a general persistent
driver.**

Family B (driver-host + kmdf_host) is a **TEST-lifecycle fixture shape** — it runs a fixed
DriverEntry→AddDevice→Start→IOCTL→Remove script once, writes a verdict, and parks. It exists to *exercise
and prove* the WDM/KMDF import surface end-to-end in isolation; it is NOT how a general persistent driver
runs, and a user driver must NOT be forced onto it. The design keeps Family B on its thin `run_once`
(§2.6) for the fixtures, while **`load_driver(path, class)` spawns general drivers as Family-A IRP
dispatch servers** through the unified harness. (A future device driver that needs a persistent IRP loop
AND device caps = Family A with the `Device` class's granted caps — §5.4 — still through `component_main`,
never a bespoke loop.)

### 5.4 Class → capabilities mapping (declarative, no per-driver code)

`load_driver` derives the whole descriptor from `class`. Proposed table (extends `DriverClass`
`driver_launch.rs:1104-1117`):

| `DriverClass` | `HostCaps` | Granted caps | Regions | Notes |
|---|---|---|---|---|
| `Fsd` (npfs, fastfat, ntfs) | `{ dispatch_server, kind: Irp }` (all win32k flags false) | `fault_ep` only | image W^X + pool + DATA/SHARED/ARG + stack | **The default user-driver path.** |
| `Device` (NIC, AHCI, GPU function driver) | `{ dispatch_server, kind: Irp }` | `fault_ep` + `irq_ntfn` + **device caps** (MMIO BAR frames, DMA frame, IRQ) minted by `nt-pnp` (`pnp.rs`) | image W^X + pool + SHARED/ARG + stack + **BAR/DMA regions** (aliased device frames) | Same IRP substrate; ONLY the granted-cap/region *device section* differs. `nt-pnp` populates it (the descriptor "device-cap section" — `spawn_hosts.rs:6-9`). |
| `Filter` (FS/bus filter) | `{ dispatch_server, kind: Irp }` | `fault_ep` | as `Fsd` | Attaches above a target stack; IRP forwarding is driver logic, not a harness concern. |
| `GuiSyscallServer` (**win32k ONLY**) | `{ dispatch_server, kind: Syscall, client_attach, usermode_callback, wide_arg_marshal, assert_skip, nested_reply_cap }` | `fault_ep` + GS/KPCR | win32k's bespoke region set (session/pool/aux/framebuffer) | **A UNIQUE class.** These caps are win32k-specific and are NEVER set for a normal user driver. Renaming `Subsystem`→`GuiSyscallServer` makes explicit that "the GUI syscall server" is one privileged class, not a general option. |
| `TestLifecycle` (driver-host/KMDF fixtures) | `{ dispatch_server: false }` → `run_once` | per-fixture (device caps for driver-host; heap for kmdf) | per-fixture | Family B. Not a persistent server; explicitly a fixture shape. |

The mapping is a pure `fn caps_and_layout_for(class) -> (HostCaps, GrantedCapsPolicy, &[Region])` inside
`load_driver` — **no branch per driver, only per class.** A new FSD/filter/device driver picks an existing
class and gets the descriptor for free.

### 5.5 The add-a-driver recipe (the deliverable)

To run a new user-specified driver `foo.sys` (an FS/filter/NIC driver):

1. **Stage the bytes by path:** put `foo.sys` at `\reactos\system32\drivers\foo.sys` on the image — via
   the fetched `\reactos` tree, or add it to the `make_image.sh` staging loop
   (`rust-micro/scripts/make_image.sh:159`, alongside the fixtures).
2. **Declare it:** add a `DriverSpec { path: b"reactos\\system32\\drivers\\foo.sys", class: Fsd }`
   (or `Device`/`Filter`) to the driver list (§5.6). For a device driver, `nt-pnp` supplies the device
   caps for its `class`.
3. **That's it.** At boot, the executive iterates the driver list and calls
   `load_driver(&fs, spec.path, spec.class)` for each. `load_driver` reads the bytes, PE-loads +
   IAT-resolves through the shared `DriverExportRegistry`, builds the class descriptor, `spawn_component`s
   an isolated VSpace, and runs it as a Family-A IRP dispatch server on `component_main`. The driver's
   `DriverEntry` registers `MajorFunction[]`; the executive routes IRPs via `component_pump`
   (`kind = Irp`). **No new entry loop, no new dispatch code, no new fault loop.**

Generic (harness provides for free): by-path load, PE parse/reloc/IAT-patch, isolated VSpace/CSpace/TCB,
the DriverEntry preamble (DRIVER_OBJECT/RegistryPath), the recv→dispatch→reply server loop, the
demand-map fault pump, the IRP marshal, crash-containment. **Per-driver (author/user provides): the
`.sys` binary + one `DriverSpec` line. Plus, ONLY if the driver imports an ntoskrnl API not yet in the
`DriverExportRegistry`, a real implementation of that export** (the standing "implement-the-stubs" backlog
— MEMORY `feedback_implement_kernel_api_for_real`); the resolver fails-soft + audit-logs unbound names so
this surfaces cleanly.

### 5.6 Gaps in the CURRENT path the harness work MUST close

For an arbitrary driver to truly need zero bespoke code, these must be fixed as part of / alongside the
harness migration (none are win32k-specific; they DON'T disturb the win32k-last order):

* **G1 — `load_driver` only routes `Fsd`.** `:1335-1338` returns `None` for `Device`/`Subsystem`. Make
  the Family-A IRP path serve `Fsd` AND `Device`/`Filter` (same `component_main`; the class only changes
  caps/regions §5.4). win32k stays its own `GuiSyscallServer` class (not routed through `load_driver`'s
  IRP builder — it keeps its Syscall substrate, migrated last).
* **G2 — single-instance singletons.** The FSD path uses FIXED VAs (`FSD_CODE_VA` `:54`, `FSD_POOL/DATA/
  SHARED/ARG/STACK_VADDR`), a single `static mut FSD_RIGHTS` `:1319`, one `FSD_EXPORTS` `:668`, and
  single `NPFS_PML4/FAULT_EP/MJ_TABLE/DEVOBJ` atomics `:1546-1550`. Loading a SECOND IRP driver would
  collide. To host N drivers: parameterise the VA base per instance (an instance index → distinct
  2 MiB windows, or per-driver VA allocation) and hold the live-driver state in a small
  `[DriverComponent; N]` table keyed by instance instead of the npfs-only atomics. `npfs_dispatch_irp`
  becomes `dispatch_irp(instance, …)`. **This is the core reusability enabler.**
* **G3 — no driver list / enumeration.** One hardcoded call site (`main.rs:7165`). Add a declarative
  `DRIVERS: &[DriverSpec]` (path + class) that the boot iterates. This is the "user specifies drivers to
  run" surface; a user-config-driven list can populate it later (registry `\Services` or a boot arg),
  but the static list is the minimum to prove reuse.
* **G4 — DriverExportRegistry coverage.** A new driver may import ntoskrnl APIs not yet bound. Not a
  harness bug (fails soft + audits), but the standing backlog. No harness change needed; noted so a new
  driver's missing exports are an expected, surfaced task not a mystery hang.

Closing G1-G3 is what turns "npfs runs" into "any user-specified IRP driver runs through the same
harness." G2 is the load-bearing one (multi-instance). The harness (`component_main`/`component_pump`)
from §2 is already multi-instance-ready by construction (it takes a `PumpChannel`/shared-VA parameter,
not globals) — so closing G2 is mostly de-singletoning `load_driver`, not the harness itself.

### 5.7 Proof obligation

Reuse is proven when a SECOND, DIFFERENT IRP driver loads through the unified harness with ONLY a
`DriverSpec` (no bespoke code) and services an IRP end-to-end — e.g. a minimal synthetic FSD/filter
fixture staged by path, spawned by `load_driver(path, Fsd)`, that registers `IRP_MJ_CREATE`/
`IRP_MJ_DEVICE_CONTROL` and round-trips one IRP via `component_pump`. A counted spec
(`exec_second_irp_driver_via_harness`) asserts it entered DriverEntry, built its MajorFunction table in
its OWN isolated VSpace (distinct PML4 from npfs), and completed an IRP — all with zero driver-specific
executive code. This directly exercises G1+G2+G3.

---

## 6. Consolidated final state (Phase B DONE + Phase A tidy)

The design above is IMPLEMENTED. The end-state, tight:

**Unified harness (Family A — persistent dispatch servers).** Both the FSD (npfs.sys) and win32k
run on ONE shared component-side entry `component_main` + ONE executive-side pump `component_pump`
(`spawn_hosts.rs`), replacing the retired bespoke `dispatch_loop`/`send_done`/`recv_req` loops. The
win32k-only specifics (client-memory attach, foreign-frame sharing, wide-arg marshal, int-0x2c
assert-skip, REPLY_W32 nested-reply) survive VERBATIM behind `HostCaps` capability flags on the
pump, so the FSD (all flags false) degenerates to the old npfs loop exactly. Proven durable by
`exec_fsd_on_shared_harness` (IRP dispatches through the pump) + `exec_win32k_on_shared_harness`
(syscall dispatches) + the paint gate `exec_win32k_desktop_painted` (768/768).

**Multi-driver substrate.** `load_driver(fs, path, class)` is the reusable by-path driver loader:
stage a `.sys` + declare a `DriverSpec { path, class }` and it runs on the SAME harness with zero
bespoke code. `DriverClass` → caps/regions via `caps_and_layout_for` (the ONLY per-class code): `Fsd`
(default IRP server), `Filter` + `Device` (future-wiring seams, `#[allow(dead_code)]`), and
`GuiSyscallServer` (win32k's unique privileged class — kept its Syscall substrate, not routed
through the IRP builder). Reuse is proven by `exec_second_irp_driver_via_harness` (a 2nd by-path IRP
driver, `IrpFsdTest.sys`, in its OWN isolated PML4). Family B (driver-host + KMDF fixtures) stays on
its thin one-shot `run_once` shape — a test-lifecycle fixture, NOT a general driver path.

**Isolated vs. deliberately in-executive.**
* ISOLATED as their own seL4 components (own VSpace/CSpace/TCB): the four SURT-brokered managers —
  Object (`server.rs`), Config/registry (`cm_server.rs`), I/O (`io_server.rs`), LPC broker
  (`lpc_server.rs`) — each stood up via `stand_up_service` and exercised by counted `exec_ob_*/
  exec_cm_*/exec_io_*/exec_lpc_*` specs; plus win32k, npfs, and any by-path driver via
  `spawn_component`.
* DELIBERATELY IN THE EXECUTIVE (the trusted root): the Process Manager (`nt-process` — "can't
  isolate away the thing that manufactures isolation"; it mints VSpace/CSpace/TCB from Untyped) and
  the native-syscall dispatch seam that hosts smss/csrss/winlogon. See MEMORY
  `project_process_convergence` for the rationale.

**Diagnostics.** Grind-era verbose trace prints (the winlogon loader-trace ring in
`loader_trace_diag.rs`; per-fault demand-map traces in `component_pump`) are gated behind the
OFF-by-default `debug-trace` cargo feature. The default build ships clean serial but keeps every
milestone marker, spec PASS/FAIL line, and the `N/98 ... checks passed` gate summary.
