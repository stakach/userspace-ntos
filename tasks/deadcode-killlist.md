# Dead-code / scaffold KILL-LIST — Phase A step 1 (READ-ONLY inventory)

Repo: `userspace-ntos` @ `aee4fab` (gate 183/98, green). Component:
`components/ntos-executive/src/`. Produced by a read-only inventory pass (build for
warnings + grep + read). **NOTHING deleted or edited.** A later batch deletes from the
approved subset of this list.

Context: `docs/component-harness.md`, `tasks/todo.md`. The executive just finished the
component-harness unification (Phase B Steps 0–4.5): win32k + npfs/FSD migrated onto the
shared `component_main`/`component_pump` loop. The bespoke `dispatch_loop`/`send_done`/
`recv_req` functions were ALREADY deleted (Step 5, partial) — this pass confirms that and
inventories what the migration left dead.

All `file:line` are `components/ntos-executive/src/…` unless noted. Build used for §1 warnings:
`./build.sh` (exit 0, 234 warnings; 194 are the `direct cast of function item into an integer`
lint = NOT dead code, excluded).

---

## Summary — buckets, counts, reclaimable LOC, recommended DELETE-ORDER

| # | Bucket | Items | Est. reclaimable LOC | Confidence |
|---|---|---|---|---|
| 1 | Compiler-flagged dead code (`dead_code`/`unused`) | 7 consts + 3 fns + 8 fields/variant + 8 dead assigns + 8 unnecessary-`unsafe` + 6 mut/shadow/nullcheck | ~60–90 (mostly 1–3 lines each; most are lint-only tidies, not block removals) | definitely-dead (compiler) |
| 2 | Harness-migration leftovers | bespoke loops ALREADY deleted; residual = the additive Step-0 ABI that never got wired | ~15–30 | mixed (see items) |
| 3 | Retired scaffolds / superseded paths | all doc-comments describing retired behavior; NO unreferenced retired *code blocks* found (the paint scaffold was already deleted) | ~0 code (comments only) | see items |
| 4 | Milestone parks / quiesce hacks (INVENTORY ONLY — keep/consolidate) | ~10 mechanisms | n/a (load-bearing) | keep |
| 5 | Heavy/one-shot diagnostics (INVENTORY ONLY) | `loader_trace_diag` + budget-throttled `print_str` | n/a (gate them) | keep, gate |
| 6 | Dual-path subsystems | none found live-dead; a couple of duplicate consts | ~2 | dedup |

**Recommended DELETE-ORDER (lowest-risk first):**
1. **§1a — unused `const`s** (7 items): pure removals, no callers, no fn-ptr/asm/link_section
   risk. Highest confidence. ~15 LOC.
2. **§1b — unused `fn`s** (`fsd_is_bound`, `npfs_devobj`, `last_file_id`): confirm no
   spec/test references (they're `pub(crate)`, not exported) then delete. ~12 LOC.
3. **§1c — unused struct fields + the `Filter` variant**: needs a compile after each (removing
   a field shifts nothing here since they're plain data, but `Filter` is a documented class
   seam — see risk). ~8 LOC.
4. **§1d — dead assignments / unnecessary-`unsafe` / redundant `mut` / shadow / null-check**:
   these are in-place tidies (change a line, don't remove a block); do LAST and carefully —
   several sit inside the load-bearing service loop. ~10 LOC touched.
5. **§2 — the unwired Step-0 harness ABI** (`ComponentDescriptor.caps`, `HostCaps::{usermode_callback,
   wide_arg_marshal}`, `SH_REQ_KIND`): delete only after confirming no future harness step
   plans to wire them (see §2 risk — design doc treats them as an intentional seam).

Everything in §4 and §5 is **KEEP / consolidate**, not kill.

---

## §1 — Compiler-flagged dead code (highest confidence)

### §1a — Unused constants (definitely-dead; pure removal)

* `win32k_subsystem.rs:107` — `WIN32K_SENTINEL_VADDR` — an unmapped "ready/done" sentinel VA
  from the pre-harness fault-recv loop — **why dead:** the harness signals done via a distinct
  DISPATCH_LABEL (`send_done_on`), not a sentinel-VA fault; superseded by the migration —
  **definitely-dead** — RISK: none (a bare `u64` const, no asm/link).
* `win32k_subsystem.rs:329` — `V_RETURNED: u32 = 2` — verdict bit "DriverEntry returned" —
  **why dead:** the harness records V_ENTERED/V_SUCCESS but never the intermediate V_RETURNED —
  **definitely-dead** — RISK: none. (Note it sits in a bitmask family whose other members ARE
  live; removing just this one is fine, but it slightly breaks the documentary completeness of
  the verdict-bit table — judgment call whether to keep for docs.)
* `win32k_subsystem.rs:372` — `CO_INIT_DESKTOP_GFX_RVA: u64 = 0xfca10` — **explicitly documented
  in-code as retired scaffold**: "the eager SSN_INIT_DESKTOP_GFX scaffold that called it was
  RETIRED … Kept only as a structural landmark" — **why dead:** no callers; the paint runs
  lazily now — **definitely-dead** (compiler-confirmed) — RISK: none for build; it's kept
  deliberately as a landmark, so flag to the user whether to preserve the doc-comment.
* `win32k_subsystem.rs:1364` — `MEM_COMMIT: u64 = 0x1000` — in the ZwAllocateVirtualMemory /
  RTL_BITMAP block; sibling `MEM_RESERVE` (:1365) IS used — **why dead:** only RESERVE ended up
  referenced — **definitely-dead** — RISK: none.
* `win32k_subsystem.rs:3538` — `WIN32K_FB_FRAMES: u64 = 768` — sibling `WIN32K_FB_VA`/
  `WIN32K_FB_SIZE` are used — **why dead:** the frame count is computed from SIZE elsewhere —
  **definitely-dead** — RISK: none.
* `spawn_hosts.rs:102` — `SH_REQ_KIND: u64 = 0x38` — the Step-0 KIND-tag offset — **why dead:**
  the design (`docs/component-harness.md` §2.3, Risk register row "SH_REQ_KIND=0x38 collision")
  chose to key KIND off the descriptor (constant per component) instead of a per-request frame
  tag, so the offset was never written/read — **definitely-dead** — RISK: low; it's ABI-real
  (a shared-frame offset) but nothing uses it. Confirm no future harness step reintroduces a
  runtime KIND before removing (§2).
* `driver_launch.rs:157` — `SH_REQ_SEQ: u64 = 0x80` — **DUPLICATE** of the live
  `spawn_hosts.rs:109` `SH_REQ_SEQ` (and `win32k_subsystem.rs:160`) — **why dead:** the harness
  reads/writes SEQ via the `spawn_hosts` copy; this driver_launch copy is unreferenced —
  **definitely-dead** — RISK: none (see §6 dedup).

### §1b — Unused functions (definitely-dead; confirm no spec ref)

* `driver_launch.rs:829` — `pub fn fsd_is_bound(name: &str) -> bool` — reported the
  explicitly-bound-vs-fail-soft surface for auditing — **why dead:** no callers (the audit is
  done inline in `fsd_export_addr`'s fail-soft path) — **probably-dead** — RISK: `pub` (not
  `pub(crate)`) so grep the WHOLE workspace + specs before deleting; it's a plausible
  test/spec helper. Compiler flags it unused within this crate, but a `pub` fn could be called
  from a sibling crate — **needs-judgment on the `pub`**.
* `driver_launch.rs:1734` — `pub(crate) fn npfs_devobj() -> u64` — returns instance-0's
  DEVICE_OBJECT — **why dead:** no callers (the harness routes IRPs via the instance table, not
  this accessor) — **probably-dead** — RISK: `pub(crate)`, grep confirms no in-crate caller; a
  spec might reach it — quick grep says no. Low risk.
* `driver_launch.rs:1745` — `pub(crate) unsafe fn last_file_id(inst: usize) -> u64` — per-
  instance FILE_OBJECT id accessor (generalized form of the live `npfs_last_file_id` at :1739,
  which IS used) — **why dead:** the multi-instance accessor was added in Step 4.5 (G2) but no
  caller reads a non-0 instance's file-id yet — **probably-dead** — RISK: it's the multi-
  instance-ready sibling of a live fn; a future 2nd-driver spec may want it. Flag needs-judgment
  (kill vs keep-for-substrate).

### §1c — Unused struct fields + variant (needs-judgment; mostly intentional metadata)

* `win32k_pe.rs:41` — field `Win32kPe.image_base` — struct doc'd "PE metrics … Reported for the
  record" — **why dead:** metadata struct; only some fields are read — **needs-judgment** —
  RISK: deliberate documentation-of-record; removing loses the recorded value. LOW code value.
* `pnp.rs:41` — field `GrantedDevice.device` (a `PciDevice`) — sibling `assignment` IS read —
  **why dead:** only the resource `assignment` is consumed downstream — **needs-judgment** —
  RISK: the bound device identity is arguably wanted for future device-driver granting; keeping
  is defensible.
* `spawn_hosts.rs:128` — fields `HostCaps.usermode_callback` and `HostCaps.wide_arg_marshal` —
  **why dead:** the design (§2.3) documents these two as capability-DOCUMENTATION flags —
  win32k's usermode-callback registration + exact-arity transmute are keyed off the SSN
  component-side, NOT off these runtime flags, so `component_pump` never reads them (it reads
  `client_attach`/`assert_skip`/`nested_reply_cap`/`kind`, which ARE live) — **probably-dead**
  — RISK: they're a documented seam; removing them contradicts the design note. Flag
  needs-judgment (align with the design doc first). See §2.
* `spawn_hosts.rs:165` — field `ComponentDescriptor.caps: HostCaps` — **why dead:** the Step-0
  additive plan put `caps` on the descriptor, but `component_pump` reads caps from a SEPARATE
  `PumpChannel.caps` (`spawn_hosts.rs:426`) built independently by the win32k/FSD callers, so
  the descriptor's own `caps` field is never read after being set by 3 builders (driver_launch
  :1525/:1805, win32k_glue :447) — **probably-dead** — RISK: HARNESS SEAM. This is the Step-0
  ABI that never got wired through `spawn_component`. Deleting it means those 3 builders drop
  `caps:` too. Only remove if no future step plans to consume descriptor.caps inside
  `spawn_component`. **needs-judgment** (see §2).
* `spawn_hosts.rs:172` — field `SpawnedComponent.cnode` — **why dead:** callers use `pml4`/
  `tcb`/`stack_frame_base` but not the returned CNode cap — **probably-dead** — RISK: low, but
  a CNode cap is plausibly wanted for teardown/revoke; keeping is cheap. needs-judgment.
* `driver_launch.rs:1194` — field `code_va` (on the load result struct near `DriverComponent`) —
  **why dead:** the run VA is tracked per-instance elsewhere — **probably-dead** — RISK: low.
* `driver_launch.rs:1652` — fields `DriverInstance.mj_table` and `DriverInstance.devobj` —
  **why dead:** set at launch but not read (the harness routes via the instance's shared frame,
  and `npfs_devobj`/`fsd_is_bound` that would read them are themselves dead — §1b) — **probably-
  dead** — RISK: these + `npfs_devobj` form one dead cluster; kill together. Removing fields from
  a `#[derive(Clone,Copy)]` struct is mechanical.
* `driver_launch.rs:1144` — enum variant `DriverClass::Filter` — **why dead:** added in Step 4.5
  (G1) as a documented class seam ("Same IRP substrate + caps as Fsd; distinction is policy
  documentation"); no `DriverSpec` constructs it yet — **needs-judgment** — RISK: it's a
  deliberate extension point for user-specified filter drivers (design §5.4). Sibling `Device`
  is `#[allow(dead_code)]`-suppressed for the same reason; `Filter` just lacks the attribute.
  KEEP (or add `#[allow(dead_code)]` to match `Device`) rather than delete — flag to user.

### §1d — Dead assignments / unnecessary `unsafe` / redundant `mut` / misc lints (in-place tidies)

These change a single token/line (not block removals). LOW LOC but several sit in the
load-bearing service loop — do LAST, one build per edit.

Dead assignments (`value assigned … is never read`):
* `service_sec_image.rs:27` `faults`, `:37` `first`, `:39` `ntfaults`, `:73`
  `winlogon_process_handle`, `:973` `crash_parked`, `:1458` `result` — loop counters/locals in
  the big per-process demand-fault service loop assigned a final value that's never read —
  **probably-dead** (the assignment, not the variable) — RISK: **these live inside the
  load-bearing dispatch loop** (`FAULT_CAP` backstop etc.); the *variable* is used, only a
  terminal store is dead. Tidy with care; do not remove the whole counter.
* `exec_handler.rs:3588` `idx` — never-read store — **probably-dead** — RISK: low.
* `main.rs:5702` `map_ok` — never-read store — **probably-dead** — RISK: low.

Unnecessary `unsafe` blocks (`clippy`/rustc `unused_unsafe`):
* `win32k_subsystem.rs:962`, `:1322`, `:1332`; `exec_handler.rs:3034`, `:3213`, `:3437`,
  `:3465`, `:3928` — inner `unsafe {}` inside an already-`unsafe` context — **definitely-dead**
  (redundant) — RISK: none (removing the keyword changes no semantics).

Redundant `mut`:
* `alpc_selftest.rs:295`, `rendezvous.rs:205`, `rendezvous.rs:820` — `variable does not need to
  be mutable` — **definitely-dead** — RISK: none.

Other:
* `main.rs:4792` — `fn print_hex` **private item shadows a public glob re-export** — a local
  `print_hex` shadows one pulled in by `use …::*` — **needs-judgment** — RISK: this is a
  name-collision warning, not dead code; resolving it may change which `print_hex` is called.
  Do NOT treat as a delete; flag for the user to disambiguate the glob.
* `win32k_pe.rs:134` — `function pointers are not nullable, so checking them for null will
  always return false` — a `== null`/`is_null()` on a fn-ptr that's always non-null —
  **needs-judgment** — RISK: the null-check is dead logic (always false); removing the dead
  branch is safe but verify it wasn't a guard the author expected to fire.

**§1 reclaimable:** ~60–90 LOC, but weighted toward 1–3-line tidies. The clean block-removals
are §1a (consts) + §1b (fns) + the §1c dead-field cluster (`DriverInstance.mj_table`/`devobj`
+ `npfs_devobj`/`last_file_id`) ≈ 40 LOC of genuine removal.

---

## §2 — Harness-migration leftovers

**Confirmed GONE (Step 5 already deleted them):** the bespoke `fn dispatch_loop`, `fn
send_done`, `fn recv_req` on BOTH the FSD (`driver_launch.rs`) and win32k
(`win32k_subsystem.rs`) sides — grep for `fn dispatch_loop|fn send_done|fn recv_req` returns
NOTHING. Replaced by the shared `send_done_on`/`recv_req_on` (`driver_launch.rs:913/928`) +
`component_main`/`component_pump` (`spawn_hosts.rs`). No dead loop remnants remain. ✅

**Residual leftover = the Step-0 additive ABI that never got wired** (all also appear in §1c):
* `ComponentDescriptor.caps` field (`spawn_hosts.rs:165`) + its 3 builder writes — the pump
  reads `PumpChannel.caps`, not this — **why dead:** Step-0 landed the field "wired to nothing"
  (todo.md Step 0) and the wiring went through `PumpChannel` instead — **needs-judgment** —
  RISK: **intended seam.** Only kill if the descriptor→spawn_component caps path is confirmed
  never coming.
* `HostCaps::{usermode_callback, wide_arg_marshal}` (`spawn_hosts.rs:128`) — documented
  capability flags the pump never reads — same story.
* `SH_REQ_KIND` const (`spawn_hosts.rs:102`) — the design chose descriptor-keyed KIND instead.
* `SH_REQ_SEQ` duplicate in `driver_launch.rs:157` — superseded by the `spawn_hosts` copy.

**Reclaimable:** ~15–30 LOC. **Confidence mixed** — the consts (SH_REQ_KIND, dup SH_REQ_SEQ)
are definitely-dead; the `caps`/`HostCaps` flag seam is needs-judgment (design-doc-blessed).

---

## §3 — Retired scaffolds / superseded paths

Grepped `RETIRED|scaffold|superseded|deprecated|legacy|no longer|HISTORICAL`. **Finding: every
hit is a DOC-COMMENT describing behavior that was retired, NOT an unreferenced retired code
block.** The actual retired code (the eager paint scaffold `SSN_INIT_DESKTOP_GFX`, the modeled
`NtRequestWaitReplyPort` CSR arm, the parallel `Win32kExportRegistry`) was ALREADY deleted in
earlier batches. So there is **no scaffold code to kill here** — only stale comments to
consider trimming (cosmetic, not a kill-list item).

Verified LIVE (dead-looking-but-live — do NOT kill):
* `NtRequestWaitReplyPort` handler `exec_handler.rs:2931` — **LIVE**, registered in the native
  service table (`main.rs:3783`); the "old modeled NtRequestWaitReplyPort arm no longer runs"
  comment (`main.rs:7621`) refers to a DIFFERENT (already-removed) modeled branch, not this
  handler.
* `SSN_INIT_DESKTOP_GFX` — only survives in 3 comments (`service_sec_image.rs:3234`,
  `win32k_subsystem.rs:368`, `main.rs:4463`) documenting that the scaffold is gone. No code.
* `CO_INIT_DESKTOP_GFX_RVA` (§1a) is the one remaining *const* from that scaffold — the only
  killable artifact.

Kept-because-still-LIVE despite "temporary"-sounding comments:
* `service_sec_image.rs:2440` — the single `TODO(migrate)` in the tree (a real cross-AS
  NtWriteVirtualMemory migration note) — **temporary but the surrounding code is LIVE** —
  keep.

**Reclaimable code:** ~0 (comments only). Only `CO_INIT_DESKTOP_GFX_RVA` (already in §1a).

---

## §4 — Milestone parks / quiesce hacks (INVENTORY ONLY — KEEP, consolidate)

**These are LOAD-BEARING:** they make the boot quiesce so the counted gate can run and
`qemu_exit`. This is an inventory for a FUTURE consolidation (unify behind one documented
mechanism), NOT a kill-list. Do NOT delete.

* `main.rs:1166` — `WINLOGON_SAS_MILESTONE: AtomicU64` — set when winlogon registers its
  logon-notify window (InitializeSAS complete); read by the quiesce decision
  (`service_sec_image.rs:3269`, gate assert `main.rs:7946`). **KEEP** — stands in for "winlogon
  reached steady state."
* `service_sec_image.rs:1462` / `:3272` — `wl_milestone_park` — the winlogon main-loop park on
  the SAS milestone (boot quiesces; gate runs). **KEEP.**
* `service_sec_image.rs:973` — `crash_parked` — crash-containment park flag. **KEEP.**
* `maybe_quiesce_all_parked` + the broad `quiesce`/`QUIESCE`/`quiesces` family (~70 hits across
  `service_sec_image.rs`, `main.rs`) — the parked-thread → quiesce → run-gate machinery.
  **KEEP, CONSOLIDATE.**
* `wait_park` / `mark_wait_parked` / `wait_park_event` / `wait_park_multi` / `wait_parked`
  (~30 hits) — the NtWaitFor{Single,Multiple}Objects park model. **KEEP** (real wait
  semantics, not a scaffold).
* `pipe_park_fid` / `pipe_park_transceive` / `pipe_park_iosb_va` / `pipe_park_buffer_*` /
  `pipe_wait_park` — the npfs async pipe-listen/transceive park state (BATCH 34/40). **KEEP**
  (real async I/O, load-bearing for the SCM round-trip).
* `delay_park` / `delay_park_wake_ok` / `exec_delay_execution_park_wake` — NtDelayExecution
  park. **KEEP.**
* `exec_wait_reply_cap_park_wake`, `exec_blocking_wait_parked` — counted GATE SPECS asserting
  park/wake behavior. **KEEP** (these are the gate, not debug).

**Consolidation note (for the future step, not now):** there are at least 4 distinct park
idioms (wait-park, pipe-park, delay-park, milestone-park) plus the crash-containment park. A
consolidation could unify them behind one documented `park(reason)` + `maybe_quiesce()`
mechanism. NONE is genuinely dead.

---

## §5 — Heavy / one-shot diagnostics (INVENTORY ONLY — KEEP, gate behind a debug flag)

`print_str` call sites total ~1300, concentrated in `main.rs` (401), `service_sec_image.rs`
(357), `exec_handler.rs` (236). Most are boot-progress/diagnostic. Candidates to gate behind a
debug flag (NOT delete — several are load-bearing serial-gate assertions):

* `loader_trace_diag.rs` (whole module, 132 LOC) — `WINLOGON_LOADER_TRACE` ring +
  `loader_trace_record` (scoped to `pi==2` winlogon) + `loader_trace_dump`. **LIVE** (recorded
  at ~10 sites in `exec_handler.rs`, dumped at `service_sec_image.rs:3992`). This is a
  DIAGNOSTIC subsystem — a prime candidate to gate behind a `debug`/`loader-trace` cargo
  feature. **KEEP, gate.** Not dead (dump IS called).
* Budget-throttled diagnostics (~39 hits of `throttle`/`budget`/`_LOGGED`/`_ONCE` patterns) —
  one-shot / N-bounded `print_str` added during the grind (e.g. the win32k `W32_ASSERT_LOG`
  4000-skip bound, per-process fault-trace throttles). **KEEP, gate** — pure debug noise once
  the boot is stable, but currently harmless.
* Load-bearing serial-gate assertions (do NOT gate/remove): the `[quiesce]` lines
  (`service_sec_image.rs:3295`), the paint readback, and any `print_str` the counted gate
  greps for. Distinguish these from noise before gating anything.

**No diagnostics are DEAD.** This bucket is "gate behind a flag," a Phase-A-step-3 follow-up.

---

## §6 — Dual-path subsystems (flag for dedup review — NOT assumed dead)

* **`SH_REQ_SEQ` defined 3×**: `spawn_hosts.rs:109` (LIVE), `win32k_subsystem.rs:160` (LIVE,
  read at `main.rs:7126/7143`), `driver_launch.rs:157` (DEAD — §1a/§2). Consolidate to one
  shared const; the driver_launch copy is the removable duplicate. LOW risk.
* **Server modules `cm_server.rs` / `io_server.rs` / `lpc_server.rs` / `server.rs`** (56/109/90/
  69 LOC): potential isolated-service-vs-in-executive siblings of the config/io/LPC managers.
  All are `mod`-wired in `main.rs`. **NOT inventoried as dead** — needs a caller-graph pass to
  judge whether any is an unused alternative impl. **needs-judgment** — flagged for a dedicated
  dedup review, do NOT assume dead.
* **`Win32kExportRegistry`** — already retired (comment `win32k_subsystem.rs:2247`: "the
  parallel `Win32kExportRegistry` struct was retired" — unified onto the one registry). No
  residual code found. ✅ (dead-looking-but-already-gone.)

---

## Load-bearing "KEEP / consolidate" highlights (so a deletion batch doesn't touch them)

* All of §4 (parks/quiesce/milestone) — **KEEP.** These make the boot quiesce so the gate runs.
* `loader_trace_diag` + throttled diagnostics (§5) — **KEEP, gate behind a debug feature.**
* `DriverClass::{Filter, Device}` (§1c) — **KEEP** (documented user-driver class seams; `Device`
  already `#[allow(dead_code)]`; give `Filter` the same rather than deleting).
* `HostCaps.{usermode_callback, wide_arg_marshal}` + `ComponentDescriptor.caps` (§2) —
  **needs-judgment** — design-doc-blessed seam; align with `docs/component-harness.md` §2.3
  before removing.
* `last_file_id(inst)` (§1b) — **needs-judgment** — the multi-instance substrate accessor; a
  future 2nd-driver spec may consume it.

## Dead-looking-but-LIVE (do NOT delete — would break the boot/gate)

* `exec_handler.rs:2931` `NtRequestWaitReplyPort` — registered + live (§3).
* `loader_trace_dump` — called at `service_sec_image.rs:3992` (§5).
* Every `SSN_INIT_DESKTOP_GFX` reference — comments only; the const `CO_INIT_DESKTOP_GFX_RVA`
  is the sole killable artifact (§1a/§3).

## Not dead but flagged (needs disambiguation, not deletion)

* `main.rs:4792` `print_hex` shadowing a glob re-export — resolve the name collision (§1d).
* `win32k_pe.rs:134` fn-ptr null-check that's always false — dead *branch*, not dead item (§1d).

---

*The 194 `direct cast of function item into an integer` warnings are a lint (fn-ptr→usize casts
for the export/SSDT tables), NOT dead code, and are excluded — those casts are load-bearing
(they build the dispatch tables).*

---

## EXECUTION LOG — high-confidence deletions applied (Phase A step 2)

Plan changed mid-pass: DELETE the high-confidence dead code (compiler + git + green gate as the
authority), DEFER the needs-judgment seams. Done in gate-verified `./build.sh` increments.

### DELETED (all compiler-confirmed dead, build clean after each; executive-only):

Unused `const`s (§1a):
* `win32k_subsystem.rs` — `WIN32K_SENTINEL_VADDR`, `V_RETURNED`, `CO_INIT_DESKTOP_GFX_RVA`
  (retired-scaffold landmark), `MEM_COMMIT`, `WIN32K_FB_FRAMES`.
* `spawn_hosts.rs` — `SH_REQ_KIND` (design chose descriptor-keyed KIND; never wired).
* `driver_launch.rs` — duplicate `SH_REQ_SEQ` (superseded by the `spawn_hosts` copy).

Unused `fn`s (§1b):
* `driver_launch.rs` — `fsd_is_bound` (pub, zero workspace callers), `npfs_devobj`,
  `last_file_id` (multi-instance sibling, zero callers).

Dead struct fields (§1c dead cluster):
* `driver_launch.rs` — `DriverComponent.code_va` + `.mj_table`; `DriverInstance.mj_table` +
  `.devobj` (their only reader was `npfs_devobj`); + the now-unused `let mj_table` local and the
  constructor sites. (`DriverInstance.devobj` deleted; `DriverComponent.devobj` kept — still read
  by `dc.finished && dc.devobj != 0`.)

Redundant `mut` (§1d, behavior-neutral):
* `alpc_selftest.rs:295` (`mk_view` closure), `rendezvous.rs:205` & `:820` (`let result`).

**Reclaimed: ~55 LOC deleted across 5 files (net −52).** Each batch built clean (EXIT 0, zero
errors). No new cascading dead code surfaced (verified SH_MJ_TABLE still live via
`mj_table_off`).

### DEFERRED (left in place for review — NOT deleted):

* **Design-doc-blessed harness seams** (`docs/component-harness.md` §2.3): `ComponentDescriptor.caps`
  field + its 3 builder writes; `HostCaps::{usermode_callback, wide_arg_marshal}`. These are the
  documented capability-flag surface; the pump reads `PumpChannel.caps` instead. Removing
  contradicts the approved design — flag for the user.
* **`DriverClass::Filter` variant** — documented user-driver class seam (sibling `Device` carries
  `#[allow(dead_code)]`; give `Filter` the same rather than delete). KEEP.
* **Documentation-of-record fields**: `Win32kPe.image_base`, `GrantedDevice.device`,
  `SpawnedComponent.cnode` — intentional recorded metadata / plausibly-wanted caps. KEEP.
* **In-loop dead assignments** (§1d): `service_sec_image.rs` `faults`/`first`/`ntfaults`/
  `winlogon_process_handle`/`crash_parked`/`result`, `exec_handler.rs:3588 idx`, `main.rs:5702
  map_ok` — the *variable* is live, only a terminal store is dead; they sit inside the
  load-bearing per-process dispatch loop. DEFER (risky for marginal LOC).
* **Redundant `unsafe` blocks** (8 sites, `win32k_subsystem.rs`/`exec_handler.rs`) — behavior-
  neutral lint but inside closures in the dispatch path; DEFER as a mechanical follow-up.
* **`main.rs:4792 print_hex` glob-shadow** + **`win32k_pe.rs:134` always-false fn-ptr null-check** —
  needs disambiguation, not deletion.
* **§4 parks/quiesce/milestone, §5 diagnostics (`loader_trace_diag` + throttled prints), §6
  dual-path server modules** — all load-bearing or needing a caller-graph pass. DEFER per plan.
* **ALL `crates/nt-ntdll*` C-ABI exports** — never touched (a hosted binary may import an
  unused-looking export at runtime).

### GATE VERIFICATION: see the commit message / final report (183/98, sentinel, paint 768/768,
`exec_fsd_on_shared_harness` + `exec_win32k_on_shared_harness` PASS).
