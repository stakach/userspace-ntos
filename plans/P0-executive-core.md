# P0 — Executive Core & Service Model

**Goal:** a dedicated, minimal, trusted **`ntos-executive`** root task that owns
the root untyped + hardware caps, spawns the executive service components and
driver hosts, brokers their SURT rings + capability transfer, and hosts the
native syscall trap front‑end. This replaces the ad‑hoc broker role currently
carried by `driver-host-pnp`.

**Why first:** every later phase composes multiple isolated components. We need a
single, small, well‑understood broker/loader — the seL4 analogue of the boot
executive — rather than growing one driver host into everything.

## Status: in progress (increments 1–5 landed — c2e904f, 44d95bf, db7edac+448673c, 3edd34c, b054569)

## Background (what already exists to reuse)
- `object-service` already spawns **two isolated components over SURT** with cap
  transfer and a result endpoint — the canonical broker pattern.
- `driver-host-pnp` already: slot allocator from `bootinfo.empty.start`,
  `su_*` cap/frame/vspace helpers, ELF loader (`elf_loader.rs`), spawns isolated
  components with fault endpoints, brokers reflector rings, runs the supervisor.
- `nt-*-abi` + `nt-*-server`/`-client` exist for Ob, Io, HAL, PnP, Power, DMA.

## Tasks
- [x] **`components/ntos-executive/` root task** — spawn machinery in place
      (`build_service_vspace` / `spawn_service` / `map_own_heap` / ring init +
      cap copy), reusing `object-service`'s proven pattern. (commit c2e904f)
- [x] **SURT wiring:** the executive creates a ring pair + 2 ntfns + data frames,
      maps them in its own VSpace, `init_ring`s both, spawns a service seeded with
      the copies — and drives it as the front-end. (c2e904f)
- [x] **One service isolated + driven by the executive:** the **Object Manager**
      runs as its own component; the executive round-trips the full OB namespace
      script over SURT. 8/8 in QEMU. (c2e904f)
- [x] **Native syscall front-end (44d95bf):** an isolated USER thread (own VSpace/
      CSpace) traps `syscall`s → seL4 UnknownSyscall fault → executive catches +
      routes to the isolated Ob service over SURT + replies register-accurately so
      the user resumes. 3 syscalls serviced across the boundary; verdict + created-
      dir-visible checks pass. Trap/reply mechanics ported from `driver-host-ntdll`.
- [x] **SURT-ize Cm (db7edac):** new `nt-config-abi/-server/-client` (ping/create_
      key/open_key/set_dword/query_dword), host-tested end-to-end (3 tests).
- [x] **Second isolated service (448673c):** the Configuration Manager runs as the
      executive's second isolated service over its own ring pair; the executive
      drives it (5 checks: ping/create/open/set/query DWORD). Refactored the
      transport into a reusable `RingChannel` (per-channel req/rep vaddrs) + ObChan/
      CmChan wrappers. **16/16 in QEMU.**
- [x] **Third service — I/O Manager (3edd34c):** `nt_io_server::IoServer` (over an
      embedded Object Manager + mock driver) runs as the executive's third isolated
      service over its own ring pair (0x58-0x5B). The executive drives open/write
      "hello"/read/close on `\??\Test0`. `RingChannel` extended for `IoReply`'s
      `flags` + u64 `information`. **21/21 in QEMU.** (Unblocks P2 storage/file.)
- [x] **Route registry syscalls through the front-end (b054569):** the user thread
      issues SSN_CM_SET_DWORD/SSN_CM_QUERY_DWORD → the executive routes to the
      isolated Cm service. Syscall-set DWORD=42 is independently visible. The front-
      end now dispatches to **two** isolated services. **22/22 in QEMU.**
- [x] **Component-launch primitive (fc73302):** the three copy-pasted service
      blocks collapsed into one `stand_up_service(entry, sub/comp/req/rep vaddrs)
      -> RingChannel` helper; adding a service is one call + wrapping the channel in
      its client. (A fully data-driven manifest would need trait objects for the
      heterogeneous clients — deferred; the helper captures the reusable part.)
- [x] **Pointer-based arg copyin (5420b9f):** the front-end now copies in a real x64
      `UNICODE_STRING` (Buffer pointer) from a shared arg frame mapped at the same
      vaddr in both the executive + the isolated user thread, bounds-checked like a
      kernel probe, and routes a real `create_directory` with the user's path. 23/23.
- [ ] **Real ntdll syscall numbers + OBJECT_ATTRIBUTES:** swap the placeholder SSNs
      for the real ntdll SSNs and wrap the `UNICODE_STRING` in an `OBJECT_ATTRIBUTES`,
      so a real isolated ntdll process (as in `driver-host-ntdll`) drives this path
      unchanged. (P3 territory — the copyin mechanism is now in place.)
- [ ] **Migrate the driver-host broker role:** fold `driver-host-pnp`'s broker/
      supervisor duties under `ntos-executive` (later, once services land).

## Design decisions to record here as they're made
- Manifest format (static Rust table vs. a small on-disk descriptor).
- Where Mm/Ps trusted shims live (Tier 1 vs Tier 2) — they touch microkernel
  VSpace/TCB directly; likely a thin Tier‑1 shim + a Tier‑2 policy service.
- Cap-transfer story for handles that cross services (an Ob handle used by Io).

## Exit criteria
- `ntos-executive` boots on rust-micro, spawns **Ob + Io (or Cm)** as separate
  isolated components, connects them over SURT, and the native front‑end routes a
  handful of real `Nt*` calls to them — verified by a QEMU microtest (PASS/FAIL),
  clean `qemu_exit`, no `#PF`.

## E2E test
`e2e-executive`: userland stub issues `NtCreateKey("\Registry\Machine\Test")` →
executive front‑end → Cm component (own VSpace) → returns a handle;
`NtQueryValueKey` round-trips a value. Two components, one syscall path, over
SURT.

## Notes / findings
- **Only the Object Manager is fully SURT-ized today** (`nt-object-abi` +
  `-server` + `-client`, opcodes 0x2000–0x20ff, `ObReply{status,information,
  detail0,detail1}`). **Cm/registry, Io, Ob's own component, all currently run
  IN-PROCESS** (`configuration-manager`, `object-manager`, `io-manager`
  components use a `Direct` backend, no SURT split). Io *does* have
  `nt-io-abi/-server/-client`; Cm does **not** have an abi/server/client — that's
  the gap to close before the syscall front-end can route registry calls.
- **Syscall trap mechanism already exists** (`driver-host-ntdll`): real ntdll
  thread `syscall` → seL4 UnknownSyscall fault (label 2) → SSN in mr0 →
  `NativeSyscallDispatcher::dispatch(ssn, args, origin, handler)` → `set_reply_mr`
  + `reply_recv`. The front-end task is to make that `handler` marshal to the
  isolated services over SURT instead of calling in-process cores.
- **Executive-as-front-end works cleanly:** the root task maps the rings + its own
  heap in its VSpace and runs `ObjectClient` directly — no separate client
  component needed. This is the shape to keep.
- **Next concrete step:** wire the native front-end to route a few Ob `Nt*` calls
  to the isolated Ob service (reuses everything above); in parallel, stand up
  `nt-config-abi/-server/-client` so Cm can isolate + join the executive.
