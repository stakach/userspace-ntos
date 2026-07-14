# P3 — Native Syscall Surface + Process to Run a Real PE

**Goal:** broaden the native `Nt*` surface, add the sync/IPC objects and the
memory + process machinery so we can **load and run a real ReactOS PE**
(`smss.exe`) with the real `ntdll.dll`, servicing its syscalls until it creates
the session and starts `csrss`.

**Why:** this is the transition from "kernel services exist" to "the ReactOS user
space actually runs on them."

## Status: ~~not started~~ → **DONE (2026-07-14)**

### Status (2026-07-14): DONE — real smss.exe runs its full ntdll init + launches csrss/winlogon
The P3 exit is met and far exceeded. The native syscall dispatcher is the real
`nt-syscall` `NativeServiceTable` (~63 services) and it has **converged** — the
hand-wired SSN ladder was deleted. Real, unmodified ReactOS **smss.exe** runs its
full ntdll **LdrpInitialize** (creates the process heap, ~13 syscall types serviced,
NLS tables, PEB->Ldr module list) → **SmpInit** (registry enum, KnownDLLs, pagefile,
ObjectDirectory + DOS-device symlinks) → and **launches csrss.exe + winlogon.exe**.
Two (then three) real NT processes run concurrently, multiplexed by the executive's
single service loop keyed by fault-endpoint badge. Along the way: SEC_IMAGE
demand-paging by RVA, multi-image IAT resolution against real ntdll, PEB/TEB/KUSER,
base relocations, a mark/reset bump-heap reclaim, an object-manager namespace, and
real registry reads via `nt-hive-regf`. See PLAN §10 (2026-07-08/09 run) and
memory `project_smss_sec_image.md` for the blow-by-blow. **Nothing in P3 is
outstanding** — csrss/winlogon carried into P4/P6.

## Background to reuse
- `nt-syscall` (per‑profile service table, dispatcher, PreviousMode, copyin/out),
  `nt-user-host` (Windows version profile, PEB/TEB/KUSER_SHARED_DATA builders,
  KernelServices wiring), `nt-process`, `nt-memory-manager`, `nt-address-space`,
  `nt-object-manager`, `nt-security`.
- Existing `Nt*` (from `nt-syscall`): Create/Open/Read/Write/QueryInfo File,
  Create/Open/Enumerate/QueryValue/SetValue Key, Allocate/Free/Query VM,
  Create/MapView/UnmapView Section, CreateThreadEx, WaitForSingleObject,
  Duplicate/QueryObject/Close, QueryInformationProcess, AccessCheck,
  Terminate{Process,Thread}, QuerySystemInformation/Time.
- `docs/architecture/syscall.md`, `syscall-trap.md`, `user-process-host.md`,
  `dispatcher.md`, `process-manager.md`, `memory-manager.md`, `address-space.md`.

## Tasks (gap = what smss/ntdll need beyond today) — ALL DONE (2026-07-14)
- [x] **Sync/IPC objects:** real KEVENT (Notification/Synchronization) via
      `NtCreateEvent`/`SetEvent`/`ResetEvent` + `NtWaitForSingleObject`
      (exec `e436be4`). Semaphore/Mutant/Timer/keyed-events enumerated as smss needed.
- [x] **Wait dispatcher:** a real cross-thread blocking wait (waiter parks on a
      notification, a signaler wakes it) within the kernel's reply_to model (exec `cf24f5d`).
- [x] **Image sections + demand paging:** `SEC_IMAGE` demand-load by RVA + file-backed
      section fault-in from disk; multi-image (smss + ntdll) VMFault routing
      (exec `d8213d2`, `7538436`, `9331c27`, `d1a3a1a`).
- [x] **Real-PE process create:** real ReactOS smss.exe mapped, PEB/TEB/KUSER built,
      IAT resolved against real ntdll, base relocations applied, run on a real TCB with
      its syscall trap serviced (exec `d32aa81`, `144e9cd`, `611d23f`, `d14ddec`, and on).
- [x] **Object namespace + handles across the boot chain:** `\??`, `\Sessions`,
      DOS-device symlinks, `\KnownDlls`, directory objects — a compact Ob namespace in
      the executive (converged onto `nt-object-manager`).
- [x] **Info classes:** the `NtQueryInformation{Process,Token,…}` /
      `NtQuerySystemInformation` classes smss/csrss actually call — serviced on demand.
- [x] **Fault → syscall bridge hardening:** user threads restart correctly after a
      serviced trap and after a page-fault fill (the load-bearing fault-reply MR1/RBX
      lesson is captured in PLAN §10 + memory).

## Real data to test against
- Real **`ntdll.dll`** + **`smss.exe`** from a ReactOS build (fixtures; keep in a
  controlled location, GPL/LGPL terms). Cross‑reference behavior with ReactOS
  source when a call's semantics are unclear.

## Exit criteria
- The kernel loads real `ntdll.dll` + `smss.exe`, runs `smss`'s initial thread,
  services its native calls (objects, sections, files, registry, sync), and
  `smss` proceeds far enough to **create the session and launch `csrss.exe`**
  (which will block on LPC → hands off to P4) — verified in QEMU.

## E2E test
`e2e-smss`: boot → executive → mount volume (P2) → load `ntdll`+`smss` → run →
assert smss reaches session‑create / csrss‑launch (a known syscall/log
checkpoint). Gated build.

## Notes / findings
_(append as work proceeds)_
