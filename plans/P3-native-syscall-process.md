# P3 — Native Syscall Surface + Process to Run a Real PE

**Goal:** broaden the native `Nt*` surface, add the sync/IPC objects and the
memory + process machinery so we can **load and run a real ReactOS PE**
(`smss.exe`) with the real `ntdll.dll`, servicing its syscalls until it creates
the session and starts `csrss`.

**Why:** this is the transition from "kernel services exist" to "the ReactOS user
space actually runs on them."

## Status: not started

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

## Tasks (gap = what smss/ntdll need beyond today)
- [ ] **Sync/IPC objects:** `NtCreateEvent`/`SetEvent`/`ResetEvent`,
      `NtCreateSemaphore`/`Release`, `NtCreateMutant`/`Release`,
      `NtCreateTimer`/`Set`, keyed events — as Ob objects with waitable state.
- [ ] **Wait dispatcher:** `NtWaitForMultipleObjects`, alertable waits, timeouts,
      satisfaction/signal propagation; APC queue + delivery (user + kernel APCs).
- [ ] **Image sections + demand paging:** `SEC_IMAGE` sections for DLLs/EXEs,
      copy‑on‑write, fault‑in on access so the `ntdll` Ldr can map + relocate its
      dependency graph. (Mm has sections/VAD/fault today — extend to image + COW.)
- [ ] **Real‑PE process create:** map `ntdll.dll` + `smss.exe` at their bases,
      build PEB/TEB/KUSER_SHARED_DATA, set up the initial thread + stack, start it
      on a real seL4 TCB, and service its syscall trap through `nt-syscall`.
- [ ] **Object namespace + handles across the boot chain:** `\KnownDlls`,
      `\Sessions`, `\Device`, `\??`, `BaseNamedObjects`; symbolic links; the
      handle table semantics `ntdll`/smss assume.
- [ ] **Info classes:** the `NtQueryInformation{Process,Thread,File,…}` +
      `NtQuerySystemInformation` classes smss/ntdll actually call at boot
      (enumerate as encountered; don't build them all upfront).
- [ ] **Fault → syscall bridge hardening:** the trap path already reports fault‑IP
      for `restart_after_syscall`; ensure user threads restart correctly after a
      serviced trap and after a page fault fault‑in.

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
