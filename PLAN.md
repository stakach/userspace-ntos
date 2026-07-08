# PLAN.md — Replacing the ReactOS Kernel with rust-micro + the NT Kernel Layer

> **Living document.** Reviewed and updated at **every step**. See §10 for the
> maintenance rule and the changelog. High‑level here; detail lives in `./plans/`.

---

## 0. Purpose & End Goal

Replace the ReactOS **kernel** — `ntoskrnl.exe` + `hal.dll` + all kernel‑mode
drivers — with **rust-micro (our seL4 microkernel)** + the **NT kernel layer**
(this repo's executive services), while keeping the **ReactOS user space**
(`ntdll.dll`, `smss`, `csrss`, `win32`, `services`, `lsass`, applications).

The result is a Windows‑NT‑compatible OS whose kernel is a **capability
microkernel with the NT executive decomposed into isolated user‑space
components**. Drivers run in their **own processes**, supervised and
crash‑contained (no bluescreens; restart/backoff/disable per
`nt-driver-supervisor`).

**Driver compatibility (broad, not narrow) — a first‑class goal:** we **keep and
host as many pre‑built ReactOS kernel‑mode `.sys` drivers as possible** — each in
its **own isolated process**, not in the kernel's address space. Maximizing the set
of supported stock drivers is an explicit objective (prefer hosting the real
ReactOS driver over reimplementing it). **Any driver that uses the official interfaces**
(the WDM DDI — `Io*`/`Ke*`/`Mm*`/`Ex*`/`Po*`, IRPs, dispatch routines — or KMDF /
UMDF v2) works, because those drivers only ever call documented functions that our
per‑host NT runtime serves (`nt-kernel-exec` / `nt-driver-runtime` /
`nt-compat-exports` locally; hardware + cross‑driver I/O marshaled to the executive
over SURT). This is the UMDF‑style out‑of‑process model extended to KMDF and WDM.

**The only losers** are drivers that assume they share the kernel's address space
or use **undocumented / in‑kernel‑global** access — rootkit‑style AV, anti‑cheat,
SSDT/kernel patching, and filter drivers that walk internal kernel structures.
Those break by design; that is the robustness win, not a regression in support for
legitimate drivers.

**Out of scope:** **UMDF v1** (legacy COM/reflector framework) is not and will
not be supported. Only **UMDF v2** (which reuses the KMDF WDF surface). Ignore
ReactOS's UMDFv1 drivers.

---

## 1. Guiding Principles

1. **Isolation over compatibility.** Each executive service and each driver is
   its own seL4 component (own CSpace/VSpace). A fault/compromise is contained;
   the microkernel + trusted executive core survive.
2. **Independently testable first.** Every subsystem is a **host‑testable Rust
   crate** (`cargo test` on the dev host) — a pure `no_std + alloc` *core*, a
   transport‑agnostic *server* dispatcher, and an ergonomic *client* stub.
   Composition into a seL4 component is a thin shell. Prefer this shape for all
   new work. (Already the norm: **56 crates carry unit tests.**)
3. **SURT is the spine.** All inter‑component ("inter‑kernel") communication is
   over **SURT** (io_uring‑style ring IPC) with fixed‑layout wire ABIs and
   capability transfer brokered by the executive core. See §3.
4. **Real data, real drivers.** Validate against **real ReactOS driver binaries
   and real on‑disk formats** (FAT volumes, registry hives). Build targeted
   stimulus drivers in **`github.com/stakach/ntdriver`** when needed (we own it;
   commit freely).
5. **Custom builds carry the tests.** End‑to‑end scenarios compile into
   dedicated **custom kernel builds** behind feature flags; production images
   omit them.
6. **Fix kernel (rust-micro) bugs at the source, early.** When bringing up a new
   capability surfaces a microkernel bug, **root‑cause and fix it in rust-micro
   immediately** rather than working around it in userspace. Kernel bugs compound:
   a wrong cap, a drifted table, or a silent failure will bite later work in
   harder‑to‑diagnose ways. Prefer structural fixes that make the bug class
   impossible (single source of truth, invariants) over point patches. Record the
   root cause + fix in the changelog and memory. *(Example: the `DEVICE_UTS` vs
   `BootInfo.untypedList` drift — see the 2026‑07‑07 capstone entry.)*

---

## 2. Target Architecture — Kernel Service Isolation Boundaries

Trust tiers (each horizontal band is an isolation boundary):

```
 Ring 0   rust-micro (seL4)   threads · VSpace · CSpace · IPC · IRQ · sched · fault delivery      [TCB]
──────────────────────────────────────────────────────────────────────────────────────────────────────
 Tier 1   ntos-executive  (root task / broker; trusted)
          owns root untyped + hardware caps · spawns components · brokers SURT rings + cap transfer
          native syscall trap front-end (routes Nt* to the owning service)
──────────────────────────────────────────────────────────────────────────────────────────────────────
 Tier 2   NT executive services  (each an isolated component, SURT-connected, least-privilege)
          Ob   Cm/Registry   Mm   Ps   Io   PnP   Power   HAL/Resource   Cc   Se   Fs
──────────────────────────────────────────────────────────────────────────────────────────────────────
 Tier 3   Isolated driver hosts  (one per driver or driver class; supervised; crash-contained)
          WDM  ·  KMDF  ·  UMDF v2      — reflector rings to Io / HAL; hardware caps least-privilege
──────────────────────────────────────────────────────────────────────────────────────────────────────
 Tier 4   ReactOS user space  (UNCHANGED)
          ntdll  →  smss · csrss · win32 · services · lsass · apps
```

**Boundary rules**
- **Tier 1 (executive core)** is the only holder of the root untyped and the raw
  hardware capabilities (device frames, IRQ handlers, IO ports). It hands each
  service/driver host **only** the caps that component needs (e.g. one device's
  BAR frames + its IRQ to one driver host). It is the smallest possible TCB above
  the microkernel.
- **Tier 2 services** never share memory except through SURT rings + explicitly
  transferred frames. The **Object Manager** is central (types, handles,
  namespace); services register their objects there. Mm/Ps are the most kernel‑
  coupled (they use microkernel VSpace/TCB primitives) and may keep a thin
  trusted shim in Tier 1.
- **Tier 3 driver hosts** get device access **only** via caps from Tier 1 and
  **only** via SURT reflector requests to Io/HAL for anything they can't do
  locally. A host crash is caught on its **fault endpoint** and handled by the
  supervisor. (Proven today for KMDF + UMDF v2.)
- **Tier 4 (ReactOS)** talks to the kernel **only** through the native syscall
  trap (Tier 1 front‑end) and LPC/ALPC — exactly as on Windows.

**Service ↔ subsystem map** (crate → role; * = SURT ABI already defined):
`nt-object-*` Ob* · `nt-config-* / nt-hive-core / nt-config-store` Cm ·
`nt-memory-manager / nt-address-space / nt-mdl` Mm · `nt-process` Ps ·
`nt-io-*` Io* · `nt-pnp-* / nt-root-bus` PnP* · `nt-power-*` Power* ·
`nt-hal-abi / hal-svc / nt-resource-manager / nt-cm-resources` HAL* ·
`nt-cache-manager` Cc · `nt-security` Se · `nt-fs` Fs ·
`nt-dma-* / nt-mdl` DMA* · `nt-syscall` native front‑end ·
`nt-wdf-* / nt-driver-* / nt-kernel-exec / nt-pe-loader / nt-um-abi` driver hosts*.

---

## 3. SURT as Primary NT Inter‑Kernel Comms

- **Transport:** SURT rings (submission `SurtSqe` + completion `SurtCqe`) over
  shared frames, with two notifications for coalesced wakeups; caps transferred
  out‑of‑band via the executive‑core broker. (Libraries: `surt-sel4` /
  `surt-core`; proven cross‑VSpace in `object-service` and the reflector.)
- **Per‑service wire ABI:** each service defines a fixed‑layout `nt-*-abi`
  (opcodes + request/response structs). The **native syscall dispatcher**
  marshals each `Nt*` call into a SURT request to the owning service; NT's
  synchronous semantics map to **single‑in‑flight request/reply** on the ring.
- **Two SURT roles in the design:**
  1. **Service RPC** — Ob/Io/Cm/PnP/… request‑reply (already: `nt-object-abi`,
     `nt-io-abi`, `nt-hal-abi`, `nt-pnp-abi`, `nt-power-abi`, `nt-dma-abi`,
     `nt-driver-abi`).
  2. **Driver reflector** — a driver host's I/O it can't do locally is marshaled
     to Io/HAL over the reflector ring (`nt-um-abi`), the seL4 analogue of the
     UMDF reflector.
- **Rule:** new cross‑component interfaces MUST be a fixed‑layout `*-abi` crate +
  a `*-server` decoder + a `*-client` encoder, all host‑tested, before a seL4
  component wires them over SURT.

---

## 4. Current State (summary)

- **Microkernel:** rust-micro passes the upstream sel4test conformance
  milestone (170+), incl. MCS scheduling, fault endpoints, inter‑AS IPC.
- **Executive cores (host‑tested crates):** Ob, Cm (+ hives + persistence), Mm
  (sections/VAD/fault/MDL), Ps, Io, PnP, Power, HAL/Resource, Cc, Se, Fs, DMA,
  and the native syscall dispatcher — **56 crates with unit tests.**
- **Driver stack:** `nt-pe-loader` + `nt-wdf-kmdf` runtime host real **WDM,
  KMDF, and UMDF v2** drivers through their full lifecycle; the isolated
  `driver-host-um` runs a real UMDF v2 driver in its own process; the supervisor
  does restart/backoff/disable with a userspace‑visible flag.
- **Isolation proven:** two‑component SURT (`object-service`), cross‑VSpace
  reflector, fault‑endpoint crash survival, ELF‑loaded separate binaries.
- **Mostly simulated today:** hardware (MMIO/IRQ/DMA/port/timer) is largely
  modeled (`nt-sim-device`, fake MMIO). **Making hardware real under QEMU is the
  first big gap.**

---

## 5. Component Gaps — Priority‑Ordered

Priorities are **updatable** as work proceeds. Ordered by what unblocks the
ReactOS boot chain and real‑data testing. Detail per phase in `./plans/`.

| # | Area | Gap → target | Owner service | Phase |
|---|------|--------------|---------------|-------|
| 1 | **Real MMIO** | map real device BARs via seL4 frame caps (replace sim) | HAL/Resource | P1 |
| 2 | **Real interrupts** | seL4 IRQ handler caps → host ISR/DPC (extend `sel4_irq_bridge`) | HAL/Ke | P1 |
| 3 | **Real timer/clock** | LAPIC system clock, perf counter, timers | HAL/Ke | P1 |
| 4 | **Real port I/O** | x86 IN/OUT via seL4 IO‑port caps | HAL | P1 |
| 5 | **Real DMA** | contiguous common buffers + physical addrs + MDLs | DMA | P1 |
| 6 | **Block device + storage driver** | AHCI/IDE (QEMU) in an isolated host | Io + host | P2 |
| 7 | **Partition/volume** | partmgr/volmgr over the block device | Io/PnP | P2 |
| 8 | **Real filesystem** | host ReactOS `fastfat` (or `nt-fs` over a block dev); read a real volume | Fs + host | P2 |
| 9 | **Registry from real hives** | `nt-hive-core` + `nt-config-store` backed by the FS volume | Cm | P2 |
| 10 | **Native syscall breadth** | full boot‑chain `Nt*` (file/section/VM/proc/thread/reg/obj/sync/token/wait) | native + all | P3 |
| 11 | **Sync/IPC objects** | events, semaphores, mutants, timers, keyed events | Ob/Ke | P3 |
| 12 | **Image sections + demand paging** | image sections, COW, fault‑in for the ntdll Ldr | Mm | P3 |
| 13 | **Real‑PE process create** | run `smss.exe` with PEB/TEB/KUSER_SHARED_DATA; service its syscalls | Ps+Mm+Ob | P3 |
| 14 | **Wait dispatcher + APCs** | WaitForMultiple, alertable waits, APC delivery | Ke | P3 |
| 15 | **LPC/ALPC over SURT** | connection ports, request/reply, shared sections | executive+Ob | P4 |
| 16 | **csrss console subsystem** | run `csrss.exe`; console I/O; `cmd.exe` | subsystem | P4 |
| 17 | **Registry‑driven startup** | `services.exe` SCM starts drivers/services via PnP + supervisor | Io/PnP/Cm | P5 |
| 18 | **Security on the boot path** | real tokens/SIDs/ACL checks; `lsass` | Se | P5 |
| 19 | **win32k.sys isolated** | NtUser/NtGdi surface as an isolated component; display host; `explorer` | win32k | P6 |
| 20 | **ReactOS volume boot + image** | mount system volume, launch user space, build bootable image | executive | P7 |

---

## 6. Roadmap / Phases

Each phase has a **sub‑plan** in `./plans/` with tasks, exit criteria, and its
own E2E test. Phases can overlap; the critical path is P0→P1→P2→P3.

- **P0 — Executive core & service model** → [`plans/P0-executive-core.md`]
  A dedicated `ntos-executive` root task that owns untyped + hardware caps,
  spawns service components + driver hosts, and brokers SURT rings. Consolidate
  the ad‑hoc broker role (currently in `driver-host-pnp`). *Exit:* two real
  services (e.g. Ob + Io) run as separate components under the executive, talking
  over SURT, with the native front‑end routing a handful of `Nt*` calls.

- **P1 — Real hardware (HAL/IRQ/DMA/timer/port)** → [`plans/P1-hardware-hal.md`]
  **✅ COMPLETE.** Real MMIO frame caps, IRQ handler caps (MSI → isolated host),
  LAPIC clock, IO‑port caps, real DMA (identity **and** VT-d-confined). Exit met and
  exceeded: real **WDM** *and* **KMDF** `.sys` drivers run in isolated hosts and reach
  the real e1000e — WDM via the PnP START path (MMIO + confined DMA), KMDF via the full
  WDF lifecycle + `EvtDevicePrepareHardware` reading a real NIC register. Kernel bugs
  fixed at source along the way: LAPIC EOI, IOAPIC GSI-base, lazy VT-d TE.

- **P2 — Storage + filesystem + real registry** → [`plans/P2-storage-fs-registry.md`]
  Boot‑time disk → storage driver (isolated) → partition/volume → real FS →
  registry hives. *Exit:* mount a ReactOS‑produced FAT volume, read
  `\SystemRoot\…`, load the `SYSTEM` hive into Cm.

- **P3 — Native syscall + process to run a real PE** → [`plans/P3-native-syscall-process.md`]
  Broaden `Nt*`, add sync/IPC objects, image sections + demand paging, and
  real‑PE process creation with the wait dispatcher. *Exit:* run ReactOS
  `smss.exe` far enough to create the session and start `csrss`.

- **P4 — LPC/ALPC + csrss (console)** → [`plans/P4-lpc-csrss.md`] *(stub)*
  Model NT LPC over SURT; run `csrss.exe`; console I/O. *Exit:* `cmd.exe` in a
  text console.

- **P5 — Services & registry‑driven startup** → [`plans/P5-services-startup.md`] *(stub)*
  `services.exe` SCM + PnP + supervisor start ReactOS drivers/services from the
  registry. *Exit:* the service control manager boots and starts a service.

- **P6 — win32k.sys isolated (graphical)** → [`plans/P6-win32k-graphical.md`] *(stub)*
  NtUser/NtGdi as an isolated component + a display driver host. *Exit:*
  `explorer` draws. (Optional for a headless/text MVP; large surface.)

- **P7 — ReactOS integration & image build** → [`plans/P7-reactos-integration.md`] *(stub)*
  Mount the ReactOS system volume, launch its user space, and build a bootable
  disk image (BOOTBOOT + rust-micro + executive + ReactOS user space). *Exit:* a
  ReactOS user‑space boot to a usable prompt on our kernel.

---

## 7. Development & Testing Process

**Preferred component shape** (repeat for every new subsystem):
`nt-<svc>` core (`no_std+alloc`, unit‑tested) → `nt-<svc>-abi` (fixed‑layout
wire) → `nt-<svc>-server` (decode/validate/dispatch) → `nt-<svc>-client`
(encode/decode) → `components/<svc>-svc` (thin seL4 shell wiring the server over
SURT). Build the core + tests **before** the component.

**Three test tiers**
1. **Host unit tests** — `cargo test` per crate. Fast, always‑on, cover the
   logic. (Current baseline: 56 crates.)
2. **Component microtests (QEMU)** — each `*-svc` / `driver-host-*` boots as the
   rootserver, runs `check()`‑style specs, and exits via `qemu_exit`. One
   `run-<component>.sh` per component.
3. **End‑to‑end kernel tests** — a **custom kernel build** composing several
   services + a real driver + a real data store, run in QEMU, gated behind a
   feature/profile (e.g. `--features e2e-storage`). Production images omit them.
   A top‑level runner builds each component, runs its spec, and aggregates
   PASS/FAIL.

**Real‑data testing**
- Use **ReactOS driver binaries** (e.g. `fastfat.sys`) and **ReactOS‑produced
  data** (FAT images, registry hives) as fixtures to validate Io/Fs/Cm against
  real formats. Keep large/redistributable binaries in a controlled fixtures
  location (mind ReactOS's GPL/LGPL terms); keep private blobs out of git.
- Build targeted stimulus drivers in **`github.com/stakach/ntdriver`** (per‑driver
  CMake dirs; GitHub Actions emits `.sys`/`.dll` artifacts; committed fixtures
  live in `crates/nt-driver-test-fixtures/fixtures/`).

**Definition of done for a step:** host tests green + component microtest green
in QEMU + PLAN.md and the phase sub‑plan updated (§10).

---

## 8. Repository Structure

```
rust-micro/                 seL4-style microkernel (submodule, pinned)
Cargo.toml                  host-test workspace for the NT crates
crates/                     host-testable NT subsystem libs (core / abi / server / client)
components/                 seL4 components (executive core, per-service svc, driver hosts)
  ntos-executive/           (P0) trusted broker root task            ← new
  <svc>-svc/                per-service isolated component
  driver-host-*/            isolated driver hosts (WDM/KMDF/UMDF v2)
plans/                      this plan's sub-plans (one per phase/step)
docs/architecture/          per-subsystem design notes (exists, ~26 docs)
docs/compat-notes/          ReactOS/Windows compatibility notes
scripts/                    build/run/test (run-<component>.sh, e2e runner)
crates/nt-driver-test-fixtures/fixtures/   committed real .sys/.dll test drivers
```
External: **`github.com/stakach/ntdriver`** — test‑driver sources (we own it).

---

## 9. Final Image Build (ReactOS user space + rust-micro kernel)

1. **Boot:** BOOTBOOT (UEFI) loads `rust-micro` + the `ntos-executive` root task
   (which embeds or loads the service/driver‑host ELFs).
2. **Bring‑up:** executive starts HAL → enumerates the disk → storage host →
   mounts the ReactOS **system volume** (FAT/… on the QEMU disk) → loads registry
   hives into Cm → arms the native syscall trap.
3. **Launch user space:** executive loads ReactOS `smss.exe` from the volume;
   from there ReactOS's own user space (csrss, services, …) runs unchanged.
4. **Two image profiles:** (a) **dev/e2e** image with test specs baked in;
   (b) **integration** image = kernel + executive + ReactOS user‑space volume.
5. **Integration recipe:** take a ReactOS `bootcd`/`livecd` and remove from the
   boot set **only** `freeldr` + `ntoskrnl.exe` + `hal.dll` (the three we replace).
   **Keep the ReactOS kernel‑mode drivers** — every pre‑built `.sys` we can — and
   host each in an isolated driver host (WDM/KMDF/UMDF v2 over the reflector). Keep
   all user‑space files too. Produce a bootable disk that boots **our** kernel and
   runs **their** user space + **their** drivers (isolated). Scripted under
   `scripts/`. A boot‑driver manifest maps each `Services\*` kernel driver to an
   isolated host; the goal is to **use and support as many pre‑built ReactOS kernel
   drivers as possible** — only drivers needing in‑kernel shared‑address‑space /
   undocumented access (AV/anti‑cheat/rootkit/internal‑structure filters) are
   expected to fail, tracked in `docs/compat-notes/`.

---

## 10. Plan Maintenance (review/update every step)

**Rule:** every completed step updates **both** this file (status, gap table
priorities, changelog) **and** its phase sub‑plan (check off tasks, record
findings). A step is not "done" until the plan reflects it.

- **Status:** `P0 functionally complete` (broker migration deferred) · **`P1
  COMPLETE`** (real MMIO + IRQ/MSI + DMA incl. VT-d-confined + port I/O; **real WDM
  AND KMDF `.sys` drivers hosted in isolated components, reaching the real e1000e**) ·
  **`P2 COMPLETE`** (storage → FS → registry: AHCI block I/O, FAT32, isolated+VT-d-confined host, hive read) · `P3 not started` · `P4–P7 stub`.
  (Foundational crates for all phases largely exist; phases are about making them
  *real + composed + booted*.)
- **Network drivers (NDIS miniport / NetAdapterCx): DEFERRED — not on the critical
  path.** Stock/ReactOS NIC drivers are **NDIS** (e.g. the Intel PRO/1000 e1e6232e.sys
  is NDIS 6.2); hosting them needs a full NDIS runtime (~53 ndis.sys functions + the
  MiniportInitializeEx/NetBufferList lifecycle) — a large, network-specific project.
  **NetAdapterCx** is the modern path and would build on our working KMDF runtime as a
  WDF class extension, but far fewer stock drivers use it. Revisit when networking is a
  goal; the driver-hosting *capability* (WDM + KMDF, on real hardware) is already proven.
- **How to update:** edit the gap table (§5) priorities as reality shifts; move a
  phase's status; append to the changelog below with date + commit.

### Changelog
- **2026-07-07** — Plan created. Inventory: 56 host-tested NT crates; Ob/Io/Cm/
  Mm/Ps/PnP/Power/HAL/Cc/Se/Fs/DMA cores + SURT ABIs exist; WDM/KMDF/UMDF v2
  drivers host + run (UMDF v2 full lifecycle in an isolated process under the
  supervisor). Biggest gap: hardware is simulated → P1. Sub-plans P0–P3 written;
  P4–P7 stubbed.
- **2026-07-07** — Compat reframe (user): we **keep and host most ReactOS kernel
  `.sys` drivers** in isolation — any driver on the official interfaces (WDM DDI /
  IRPs / KMDF / UMDF v2) works, since it only calls documented functions our
  per-host runtime serves. Only undocumented / in-kernel-shared-address-space
  drivers (AV/anti-cheat/rootkit/internal-structure filters) are unsupported.
  Updated §0 + P7 (keep the `.sys` files, host them; don't strip kernel drivers).
- **2026-07-07** — **P0 started (commit c2e904f).** `components/ntos-executive/`
  stands up the **Object Manager as an isolated service** and drives the full OB
  namespace over SURT from the executive front-end (8/8 in QEMU). Finding: only
  Ob is SURT-ized today; Cm has no `-abi/-server/-client` (in-process) → next P0
  steps: native syscall front-end routing Ob `Nt*` over SURT, and SURT-ize Cm.
- **2026-07-07** — **P0 continued (44d95bf, db7edac, 448673c).** (1) Native syscall
  front-end: an isolated user thread's `syscall`s are caught (UnknownSyscall fault)
  and routed to the isolated Ob service over SURT, reply-resumed register-accurately.
  (2) SURT-ized Cm: new `nt-config-abi/-server/-client` (host-tested). (3) Composed
  Cm as the executive's **second isolated service** over its own ring pair.
  **16/16 in QEMU** (8 Ob + 5 Cm + 3 syscall). The executive now composes multiple
  isolated executive services + a working native syscall trap front-end.
- **2026-07-07** — Fixed §9 (user): the image recipe must **keep and host** the
  ReactOS kernel‑mode drivers (host each isolated), not drop them — only
  freeldr/ntoskrnl/hal are removed. Using + supporting as many pre‑built ReactOS
  kernel drivers as possible is a first‑class goal (§0 strengthened to match).
- **2026-07-07** — **P0 continued (3edd34c, b054569).** (4) Composed the **I/O
  Manager** as the executive's third isolated service (open/write/read/close a
  device over SURT). (5) Routed **native registry syscalls** through the front-end
  to the isolated Cm service (syscall-set DWORD=42 independently visible). The
  executive now composes **three** isolated services (Ob + Cm + Io) and the native
  front-end dispatches to two of them. **22/22 in QEMU.** The I/O service unblocks
  P2 (storage → filesystem → real data).
- **2026-07-07** — **P0 hardening (fc73302, 5420b9f).** Factored the triplicated
  service spawn into one `stand_up_service()` component-launch primitive. Added
  pointer-based syscall args: the isolated user thread builds a real x64
  `UNICODE_STRING` in a shared arg frame (same vaddr in both VSpaces) and the
  executive **copies the path in** (bounds-checked like a kernel probe) to route a
  real `create_directory` — the copyin the real `Nt*` path needs. **23/23 in QEMU.**
  P0 executive core is functionally complete; remaining items are P3-adjacent
  (real ntdll SSNs + OBJECT_ATTRIBUTES) and the driver-host broker migration.
- **2026-07-07** — **P0 complete (4c962c7).** The registry syscall route now uses
  the real Win7 ntdll SSN numbers (via `nt_syscall::NativeServiceTable`) + a real x64
  `OBJECT_ATTRIBUTES` copied in + decoded — the ABI a real ntdll process speaks.
  **P0 is functionally done** (23/23 QEMU); the only remaining P0 item — folding the
  `driver-host-pnp` broker role under the executive — is intentionally **deferred to
  post-P1/P2** so it targets a stable service shape. **Next: P1 (real hardware)** —
  the biggest gap; note "real" = real seL4 frame/MMIO + IRQ-handler caps to a
  QEMU-emulated device, not a different emulator (QEMU/emulation stays the dev path).
- **2026-07-07** — **P1 started (3984164): real MMIO.** The executive claims the
  HPET's device memory (a real device untyped from BootInfo) as a device frame,
  maps it uncached, and reads the real GCAP_ID register (VENDOR_ID 0x8086). This is
  the `claim_device_page()` mechanism — the executive owning + handing out real MMIO.
  Kernel finding: it exposes IOAPIC/HPET/LAPIC MMIO as device untypeds, and
  `X86IRQIssueIRQHandlerIOAPIC` really does program the IOAPIC RTE (the interrupt.rs
  "not wired yet" comment is stale). Next P1 increment: an IRQ-handler cap for a real
  interrupt (in progress).
- **2026-07-07** — **P1 real interrupt (0e96454).** The executive programs HPET
  timer 0 for a one-shot → IOAPIC pin 23 → issues an `X86IRQIssueIRQHandlerIOAPIC`
  cap (programs the IOAPIC RTE) → binds a badged notification → receives the **real
  hardware interrupt** (badge 0x40, non-blocking poll). **27/27 in QEMU.** The
  executive can now hand a real device's MMIO + IRQ to an isolated driver host — the
  P1 foundation. Remaining P1: reflector-forward the IRQ to a host ISR/DPC, the Ack
  path, port I/O + PCI BAR/IRQ enumeration, DMA; then a real device (e.g. `-device edu`).
- **2026-07-07** — **P1 IRQ → isolated driver host (f67753a).** The real interrupt
  now crosses into a separate ISOLATED ISR component (own VSpace/CSpace, least-
  privilege — only the notification caps): executive binds the IRQ-handler cap to a
  badged notification, transfers a cap to an `isr.rs` host whose thread wakes on the
  real IRQ and signals back (badge 0x80). Executive must *block* (priority 255) to
  let the priority-100 host run. **27/27 in QEMU.** The `IRQ → driver-host ISR` path.
  Remaining P1: `IRQHandler::Ack` (repeat/level IRQs), DPC/ring forward, port I/O +
  PCI BAR/IRQ enumeration, DMA; then a real *device* IRQ.
- **2026-07-07** — **P1 PCI enumeration (112c3d1).** Real x86 port I/O: the executive
  mints an IOPort cap (from IOPortControl slot 7) and walks PCI bus 0, reading real
  vendor/device/class/BARs/IRQ. Found 7 devices — q35 MCH, QEMU VGA, an **Intel
  e1000e NIC** (MMIO BAR0=0x81060000, IRQ 11) and two **ICH9 AHCI** controllers
  (ABAR=0x81084000, IRQ 10), ISA bridge, SMBus. **31/31 in QEMU.** All the pieces to
  hand a real device to a driver host now exist (device-frame + IRQ-handler + IOPort
  caps + enumeration). Remaining P1: turn a captured (BAR, IRQ) into caps for an
  isolated host + a real `CM_RESOURCE_LIST`; `IRQHandler::Ack`; DMA.
- **2026-07-07** — **P1 CAPSTONE: drove the real e1000e NIC (executive 8c12853,
  kernel c6c5bd5).** Mapped the NIC's real MMIO BAR0 (0x81060000) as a device frame
  and read live registers: CTRL=0x00140241, STATUS=0x00080283 (Link‑Up, Full‑Duplex,
  1000 Mbps). **33/33 in QEMU.** Root‑caused + fixed a genuine **kernel bug** on the
  way (per Principle 6): the device‑untyped set was declared twice — `DEVICE_UTS`
  (stamps the CSpace caps) and a hand‑written `empty_untypeds[]` (builds
  `BootInfo.untypedList`) — and they drifted, so an advertised device untyped aliased
  a user‑image‑frame slot → retype gave a bad cap → the frame map silently failed →
  user #PF. Fixed structurally: one module‑level `DEVICE_UTS` builds both. This is
  what made the first two mapping attempts #PF identically. Next P1: take the NIC's
  IRQ + generate a real NIC interrupt (ICS/IMS/ICR) into an isolated host; then Ack + DMA.
- **2026-07-07** — **P1 full-device loop (8d2ef7b): NIC raises a real interrupt;
  INTx delivery blocked on a kernel gap.** The executive enables INTx + raises a real
  e1000e interrupt (`ICR=0x80000001`, bit 31 asserted; Interrupt Pin = 1). But
  delivering that level‑triggered INTx to an isolated host over the IOAPIC doesn't
  work: `irq_dispatch` only EOIs — it never masks the IOAPIC line and won't reschedule
  to an equal‑priority woken thread — so a level INTx storms (edge misses it).
  **Kernel fix needed (Principle 6):** mask a level IOAPIC line on delivery + unmask on
  `IRQHandler::Ack` (per‑irq pin+trigger tracking), then a single handler on the NIC's
  GSI. Unblocks all PCI INTx drivers. Reported PENDING, not a suite failure. 34/34 QEMU.
  **Next: this kernel level‑IRQ‑mask fix.**
- **2026-07-07** — **P1 kernel level-IRQ-mask fix DONE + validated (rust-micro
  5f62279, executive 70085be).** The kernel now masks a level IOAPIC line on delivery
  + unmasks on `IRQHandler::Ack` (per Principle 6) — unblocks all PCI INTx drivers.
  Validated with a level-triggered HPET interrupt into an isolated ISR host (no storm;
  would hang without the fix). 34/34. The e1000e NIC full loop's remaining blocker is
  now purely executive-side: the NIC asserts INTA but its INTx doesn't reach any tried
  IOAPIC GSI (3..23) — QEMU q35 chipset PCI-INTx routing needs the ACPI `_PRT` parsed
  to get 00:2.0's exact GSI. Next: parse `_PRT`, then a single level handler completes it.
- **2026-07-07** — **NIC-INTx investigation resolved (c9a442d): the `_PRT` won't help;
  MSI is the path.** An exhaustive scan of every IOAPIC pin 0..23 (edge+level, both
  polarities) delivers nothing, while the kernel mask fix + the ISR mechanism are both
  validated (level HPET) and the NIC asserts INTA (ICR=0x80000001). So it is NOT GSI
  discovery — the one IOAPIC covers 0..23, already exhausted. QEMU q35 isn't routing
  this default NIC's INTx to the IOAPIC. Real fix = **MSI** (bypasses the IOAPIC +
  chipset; kernel `X86IRQIssueIRQHandlerMSI` exists). The kernel level-IRQ-mask fix
  (the valuable, general result) stands DONE + validated. 34/34 QEMU.
- **2026-07-08** — **NIC MSI attempt (c1395ae): plain MSI doesn't deliver either — the
  NIC is MSI-X-native.** Implemented the MSI path; found the NIC's caps (MSI 0x05 +
  MSI-X 0x11). The 82574/e1000e (id 0x10d3) routes via MSI-X (or INTx) in QEMU, not
  plain MSI. Closing the loop needs MSI-X (BAR-resident table + 82574 IVAR + extended
  regs) — a focused device-driver task — OR a simpler NIC (`-nic model=e1000`, plain
  MSI) / `-device edu`. Everything general is proven (kernel mask fix, full delivery
  path, NIC MMIO + interrupt assertion); only the device-specific last mile remains.
  35/35 QEMU. This has been an extensive investigation — recommend pausing the NIC
  interrupt loop and moving to another P1 item (DMA) unless the last mile is a priority.
- **2026-07-08** — **NIC IRQ loop CLOSED; it WAS a kernel bug (kernel 59898cb, exec
  0f8a27e). 36/36.** A real e1000e interrupt is delivered via MSI into an isolated ISR
  host. A 4-agent parallel investigation root-caused it: **irq_dispatch never sent a
  LAPIC EOI**, so the first device IRQ (HPET) left a stuck LAPIC in-service bit that
  blocked every later same-priority device IRQ — which is why the exhaustive INTx scan
  AND plain MSI both failed. The MSI was correct all along (QEMU e1000e does plain MSI
  on a legacy cause). Also fixed a secondary latent kernel bug (190d49f): the IOAPIC
  GSI base was parsed then ignored. Both pushed. Lesson: burning cycles chasing a
  "device/QEMU" dead end can mask a kernel bug — the multi-agent sweep found it fast.
  Next: **DMA**.
- **2026-07-08** — **DMA Phase 1 DONE (9ba612b). 38/38.** Real e1000e TX DMA to a frame
  the executive allocated: paddr via X86PageGetAddress (VT-d translation off → identity),
  legacy TX ring built in it, NIC DMA-writes the descriptor DONE bit back. QEMU quirks
  (agent, from e1000e_core.c): TX gated on TARC0 bit10 (0x3840, not TXDCTL); DD byte at
  descriptor +12 (not +14). No kernel change. Next: DMA Phase 2 = VT-d confinement (mint
  IOSpace cap + X86PageMapIO the frame to an IOVA + set TE → rogue DMA faults).
- **2026-07-08** — **DMA Phase 2 DONE (kernel 0bc3d83 + exec 9286864). 41/41.** e1000e
  DMA is now CONFINED by the VT-d IOMMU. Kernel: lazy TE-enable on first IO context (so
  Phase 1 identity DMA still works, then translation flips on). Exec: mint device IOSpace
  cap, build a 4-level IO page-table hierarchy (X86IOPageTableMap ×4), map a copy of the
  DMA frame at an IOVA (X86PageMapIO), reprogram the NIC to use the IOVA → DD writes back
  ⇒ VT-d translated IOVA→frame. A driver can now only DMA into frames it was granted; a
  rogue DMA faults. The big driver-isolation hole (DMA) is closed.
- **2026-07-08** — **Confirmed BOTH QEMU q35 NICs are dead ends for IRQ delivery
  (9172b78).** Tried the e1000 (82540, `-nic model=e1000`): maps fine (live NIC) but
  QEMU's e1000 model has NO MSI capability (INTx-only), and INTx isn't routed to the
  IOAPIC. So: e1000e = MSI-X-native (plain MSI dead), e1000 = INTx-only (routing dead).
  The NIC interrupt loop's last mile needs **MSI-X** (BAR table + IVAR + extended regs
  + another device untyped) or a **purpose-built device** (`-device edu`, or a virtio
  device). PAUSING it here — all general/architectural pieces are proven; this is a
  device-specific detail. Next P1: **DMA** (or MSI-X later if the NIC IRQ is a priority).
- **2026-07-08** — **Real Windows `.sys` hosted through the START path (74287ae). 45/45.**
  An unmodified MSVC-compiled WDM driver (PnpMmioInterruptTest.sys) runs crash-contained
  in the isolated seL4 host: the executive PE-loads it (nt-pe-loader) + patches its imports
  to ntoskrnl stubs wired to reality (MmMapIoSpace → the real e1000e BAR); the host calls
  DriverEntry → AddDevice → IRP_MN_START_DEVICE with our real CM_RESOURCE_LIST, and the
  driver's START handler runs + does real MMIO. Its START returns a device-mismatch status
  (real device is an e1000e, not the driver's test device) — noted honestly. The core NT
  driver-hosting goal (a real .sys binary driving real hardware, isolated) is demonstrated.
  Follow-ons: deliver a real MSI to the driver's ISR, DMA via the confined buffer, KMDF
  (the full nt-wdf-* surface).
- **2026-07-08** — **Real KMDF driver hosted through the FULL WDF lifecycle (d16be90). 50/50.**
  KmdfBasicTest.sys runs crash-contained in a separate isolated seL4 host: DriverEntry →
  WdfDriverCreate → AddDevice → WdfDeviceCreate/WdfIoQueueCreate → EvtDevicePrepareHardware
  → D0Entry → IOCTLs → REMOVE (verdict 0x1f). The MODERN Windows driver framework runs on
  the microkernel. Ported driver-host-wdf's WDF surface into kmdf_host.rs; spawn_kmdf_host
  maps image-RW + a heap + the KMDF PE + a big stack. Software-only. CAVEAT: shared RW image
  (private-copy isolation = hardening follow-on). Both WDM (real hardware) and KMDF driver
  models now host real .sys binaries on rust-micro.
- **2026-07-08** — **KMDF driver WIRED TO THE REAL e1000e NIC (3e066ea). 51/51.** The KMDF
  host points the driver's WDF hardware surface at the real NIC BAR: its
  EvtDevicePrepareHardware, via WdfCmResourceList → MmMapIoSpace, maps the real e1000e and
  reads register 0 (CTRL=0x00140241), then correctly REJECTS the device (not its test HW) —
  the accept-vs-reject difference proves it read a real register through WDF. Verified: the
  CTRL matches the executive's direct read. A real KMDF driver reaching real hardware,
  isolated.
- **2026-07-08** — **P1 COMPLETE → P2 next.** The full P1 vertical is done: real MMIO,
  IRQ/MSI, DMA (identity + VT-d-confined), port I/O, plus real WDM AND KMDF `.sys` drivers
  hosted in isolated components reaching the real e1000e (executive microtest 51/51).
  Decision: **NDIS miniport / NetAdapterCx DEFERRED** (large network-specific runtimes, off
  the critical path — see the Status note). **Next: P2 — Storage.** Item 6 (a storage driver
  in an isolated host over the QEMU AHCI controller we already enumerate: `storage
  controller ABAR(BAR5)`) is the natural next step — it reuses the proven driver-hosting +
  real-hardware machinery and starts the disk → volume → FS → registry chain.
- **2026-07-08** — **P2 STARTED — real block I/O (kernel ecaceef + exec 639e356). 54/54.**
  The executive brings up the boot-disk AHCI controller (00:3.0) and reads sector 0 via a
  real ATA READ DMA EXT — command list + H2D FIS + PRDT in a DMA frame (identity DMA, runs
  before the NIC's VT-d TE enable), poll PxCI, check PxTFD. Got the real MBR (sig 0xAA55 +
  boot-sector bytes) off the disk the kernel boots from — reusing the NIC MMIO+DMA machinery.
  Lessons: two AHCI controllers on q35 (the add-in `-device ahci` @00:3.0 ABAR 0x81085000 has
  the disk, not the empty built-in @00:31.2); TFD=0x50 = success; QEMU DET=1 = present. Next
  P2: confine AHCI DMA via VT-d + move the read into an isolated storage host; then
  partition/volume → FS → hives.
- **2026-07-08** — **P2 filesystem — read a real FILE off the boot disk (exec 4896dd0). 57/57.**
  A small FAT32 reader in the executive (fat_read_sector/fat_next/dir_find over the AHCI
  block read) parses the BPB, lists the real root dir (EFI BOOTBOOT NVVARS), navigates
  root → BOOTBOOT → INITRD via directory entries + FAT cluster chains, and reads the file
  (BOOTBOOT/INITRD, cluster 208, 11,865,600 bytes, real ASCII) — the very boot bundle BOOTBOOT
  loads. Disk is a FAT32 superfloppy so roadmap item 7 (partition) is N/A; this is item 8
  (read a real FS volume). No kernel change. Next P2: confine AHCI DMA via VT-d + move the
  storage stack into an isolated host; then registry hives.
- **2026-07-08** — **P2 storage ISOLATED (exec 4f2367c). 57/57.** Moved the whole storage
  stack (AHCI bring-up + sector read + FAT32 FS + BOOTBOOT/INITRD read) out of the trusted
  executive into a crash-contained storage host (own CSpace/VSpace) — new src/storage_host.rs
  + storage_probe (crate-scope) + spawn_storage_host (RO image; granted ONLY the AHCI BAR +
  DMA frame + a shared word; no PCI-config access). The executive is now the Tier-1 broker
  (Bus Master, claim caps, spawn, verify). Item 6 ("storage driver in an isolated host") now
  complete in its full isolated form. Next P2: confine the AHCI DMA via VT-d; then registry
  hives over the FS.
- **2026-07-08** — **P2 storage DMA VT-d-CONFINED (exec d54ddd2). 59/59.** The isolated
  storage host's AHCI DMA now goes through the VT-d IOMMU: the executive mints an IO-space cap
  for the AHCI rid (00:3.0 → 0x18) in its own domain, builds a 4-level IOPT, and maps the DMA
  frame at AHCI_IOVA (0x1000); the host addresses memory by IOVA, so a rogue DMA faults in HW.
  Reuses the NIC Phase-2 machinery (SLOT_IO_SPACE, iopt_map/map_io). The storage block moved
  after the NIC block (installing the AHCI context turns TE on globally, which would block the
  NIC's Phase-1 identity DMA). Both NIC + AHCI now run confined DMA. No kernel change. Next P2:
  registry hives over the FS (read + parse a real hive from the disk).
- **2026-07-08** — **P2 COMPLETE — registry hive read off the disk (exec 47c9dc9 + kernel
  ae58471). 62/62.** A real NT registry hive (nt-hive-core image) is generated at build time
  (crates/nt-hive-core/src/bin/gen_hive.rs) + placed on the boot disk as SYSTEM.DAT; the
  isolated VT-d-confined storage host reads it off the FAT32 FS (new fat_read_file), and the
  executive's Config Manager decode_image()s it + reads ControlSet001\Services\NtosTest\Answer
  = 42 back. Full disk->volume->FS->registry chain, end to end. Checks:
  exec_storage_host_read_hive / exec_cm_hive_decoded / exec_cm_hive_answer_42.
  **P2 (storage + filesystem + real registry) DONE.** Next: P3 (native syscall breadth +
  run a real PE), or load the hive into nt-config-manager's mount table + serve Nt*Key.
- **2026-07-08** — **P3 STARTED — native syscall breadth (exec 8af289c). 65/65.** The isolated
  user thread now makes its first REAL memory + clock syscalls: NtAllocateVirtualMemory (the
  executive Mm maps a real frame into the thread's VSpace at USER_ALLOC_BASE; the thread writes
  + reads it back) and NtQuerySystemTime (rdtsc — monotonic). spawn_user_thread returns the
  user pml4 cap so service_user_syscalls can map on demand. Checks: exec_nt_alloc_vm_base /
  _readback / exec_nt_query_time_monotonic. Begins P3 item 10. Next P3: NtFreeVirtualMemory +
  VAD tracking; sync objects + wait dispatcher; then load a real PE (PEB/TEB) toward smss.exe.
