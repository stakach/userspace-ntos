# P0 — Executive Core & Service Model

**Goal:** a dedicated, minimal, trusted **`ntos-executive`** root task that owns
the root untyped + hardware caps, spawns the executive service components and
driver hosts, brokers their SURT rings + capability transfer, and hosts the
native syscall trap front‑end. This replaces the ad‑hoc broker role currently
carried by `driver-host-pnp`.

**Why first:** every later phase composes multiple isolated components. We need a
single, small, well‑understood broker/loader — the seL4 analogue of the boot
executive — rather than growing one driver host into everything.

## Status: not started

## Background (what already exists to reuse)
- `object-service` already spawns **two isolated components over SURT** with cap
  transfer and a result endpoint — the canonical broker pattern.
- `driver-host-pnp` already: slot allocator from `bootinfo.empty.start`,
  `su_*` cap/frame/vspace helpers, ELF loader (`elf_loader.rs`), spawns isolated
  components with fault endpoints, brokers reflector rings, runs the supervisor.
- `nt-*-abi` + `nt-*-server`/`-client` exist for Ob, Io, HAL, PnP, Power, DMA.

## Tasks
- [ ] **Extract the broker** from `driver-host-pnp` into `components/ntos-executive/`:
      slot allocator, `su_map_*`, `su_build_*_vspace`, `su_copy_cap`, cnode/tcb
      spawn, fault‑endpoint wiring, SURT ring setup + `init_ring`. (Move, don't
      reinvent — port the proven code.)
- [ ] **Component-launch table:** the executive reads a static manifest (which
      service/driver-host ELFs to spawn, what caps each gets, which rings connect
      to which peers). Least-privilege: each component gets only its caps.
- [ ] **SURT wiring generalized:** a helper to create a ring pair + 2 ntfns + data
      frames and connect two named components as producer/consumer (from the
      `object-service` init pattern).
- [ ] **Native syscall front-end:** a trap handler component (or executive thread)
      that receives `Nt*` from userland and marshals to the owning service over
      SURT. Start with a stub that routes 2–3 calls (e.g. `NtCreateKey`,
      `NtQueryValueKey` → Cm; `NtCreateFile` → Io) end-to-end.
- [ ] **Two services as separate components:** stand up **Ob** and **Io** (or Cm)
      as their own components under the executive, not embedded — talking over
      SURT, each with host-tested cores behind them.
- [ ] `scripts/run-executive.sh` + a component microtest spec.

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
_(append as work proceeds)_
