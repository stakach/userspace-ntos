# P8 — Windows 7 Pivot — STUB / NEW NORTH STAR

**Goal (pointer, not a full plan yet):** the original NT-on-ReactOS goal is
**largely met for the bring-up** — P0–P4 + P6 are done/largely-done and the ReactOS
user-space stack (smss → csrss → winlogon → win32k) runs to a **painted desktop**.
ReactOS was the on-ramp. The **new north star is hosting real Windows 7 binaries and
drivers** on rust-micro + the NT executive layer.

## Status: stub (new direction, 2026-07-14)

## Why now
The hosting machinery is proven on real Windows-family binaries: PE load + SEC_IMAGE
demand-paging, multi-image IAT resolution against real ntdll, PEB/TEB/KUSER, base
relocations, an object-manager namespace, real registry, isolated driver hosts
(WDM + KMDF), LPC + **ALPC**. Win7 exercises the same surfaces with higher fidelity.

## Key insight (already captured, load-bearing for P8)
**Win7 and ReactOS SSNs collide.** Route syscalls by **per-process ABI identity, not a
global table** — each hosted process carries which native ABI it speaks, and the
dispatcher selects the service table from that identity. (The rdx-for-nr ABI-collision
theory was implemented then DISPROVEN+reverted; the durable answer is per-process ABI
routing.) The kernel hook that makes this clean already exists:
**`TCBSetHostedSyscalls`** (label 66) — a per-TCB flag that makes every syscall from a
hosted process fault as UnknownSyscall so the executive front-end always sees it.

## Readiness / what's already in place
- **ALPC** is the first Win7-facing subsystem and is **built** (full surface + a
  LPC↔ALPC bridge over a unified `nt-port-core`; two-VSpace shared-section views).
- The PE/loader/section/IAT/reloc pipeline is binary-agnostic (already ran real
  ReactOS x64 PE32+).
- Isolated WDM + KMDF driver hosts + the supervisor host real `.sys` on real hardware.

## First candidate steps (to be planned when picked)
1. Stage a first real Win7 x64 binary through the existing SEC_IMAGE pipeline; classify
   its SSNs by per-process ABI identity; service the first divergent calls.
2. Extend the native service table with a Win7 profile keyed off the per-process ABI.
3. Host a first real Win7 driver (WDM/KMDF) — the runtime is closer than for NDIS.

## Note
This file is intentionally a **pointer/stub**, not a full roadmap. Expand it into
phased tasks + exit criteria when the Win7 pivot is chosen over the residual ReactOS
phases (P5 SCM, P7 image build). See PLAN.md §10 (2026-07-14) for the fork.
