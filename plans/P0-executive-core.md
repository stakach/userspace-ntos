# P0 — Executive Core & Service Model

**Goal:** a dedicated, minimal, trusted **`ntos-executive`** root task that owns
the root untyped + hardware caps, spawns the executive service components and
driver hosts, brokers their SURT rings + capability transfer, and hosts the
native syscall trap front‑end. This replaces the ad‑hoc broker role currently
carried by `driver-host-pnp`.

**Why first:** every later phase composes multiple isolated components. We need a
single, small, well‑understood broker/loader — the seL4 analogue of the boot
executive — rather than growing one driver host into everything.

## Status: in progress (increment 1 landed — commit c2e904f)

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
- [ ] **Native syscall front-end:** route real `Nt*` traps (mechanism proven in
      `driver-host-ntdll`: user `syscall` → seL4 UnknownSyscall fault →
      `NativeSyscallDispatcher::dispatch`) to the owning service over SURT. Start
      with 2–3 Ob calls (`NtCreateDirectoryObject`/create/lookup/close).
- [ ] **Second isolated service:** add a second service under the executive.
      **Cm/registry needs SURT-izing first** (see finding below) — do that, or add
      Io (already has `nt-io-abi/-server/-client`), whichever unblocks the syscall
      front-end demo.
- [ ] **Component-launch manifest:** generalize the ad-hoc spawn into a static
      table (which service ELFs, caps, ring peers) — least-privilege per component.
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
