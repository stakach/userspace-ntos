# Task: SERVICE 10 step 2 — real NtWaitForMultipleObjects + multiplex winlogon's rpcrt4 worker

Baseline: main @ 371bc8c, gate 169/96, paint 768/768 @ 0x003a6ea5, sel4test byte-identical, exit 3.

## Plan
- [x] Part 1: make NtWaitForMultipleObjects (SSN 280) a REAL array-wait with reply-cap parking
      (WaitAny/WaitAll, auto-reset event semantics, no-deadlock fallback to immediate).
- [x] Part 2: multiplex winlogon's rpcrt4 server WORKER thread (badge WINLOGON_WORKER_BADGE,
      own stack-mirror/TEB, resumed into the loop) instead of leaving it suspended.
- [x] Contain the worker's own unrecoverable fault (park it) so the boot continues.
- [x] Land green, paint intact, no hang.

## Review
- Part 1 DONE: generalized the Checkpoint-B waiter machinery to a SET of events
  (WAITER_EVENTS[16][8] + WAITER_EVENT_COUNT + WAITER_WAIT_ALL); `wait_park_multi` + a rewritten
  `wait_wake_event_set(just_set, &mut obj_ns)` that wakes on WaitAny (first signalled → WAIT_0+idx)
  or WaitAll (all signalled → WAIT_0) and AUTO-RESETS consumed SynchronizationEvents. `wait_park`
  is now a 1-event wrapper. New ObjEntry.auto_reset field. The 280 handler resolves the handle
  array → obj_ns events, satisfies immediately or parks (no-deadlock: only parks when the set holds
  a real event with a live signaler; else immediate WAIT_0, documented). smss's badge-0 280 park
  kept unchanged.
- Part 2 DONE + PROVEN: `spawn_wl_listener_thread` now RESUMES the rpcrt4 worker into the loop with
  a badged fault EP (WINLOGON_WORKER_BADGE=11) + its own stack mirror (WINLOGON_WORKER_STACK_MIRROR_VA)
  at prio 106. Loop sub-selects `is_wl_worker` → pi 2 + the worker's stack mirror. Worker fault
  containment added (both the NULL-deref and blocking-syscall park arms). Spec
  `exec_winlogon_worker_multiplex` (WL_WORKER_FAULTS>=1) passes: the worker ran 2 multiplex events.
- ★ KEY FINDING (the memory was WRONG): winlogon's `4:122` loop is NOT NtWaitForMultipleObjects —
  SSN 122 = NtOpenFile (ReactOS sysfuncs line 123 → SSN 122). NtWaitForMultipleObjects = SSN 280.
  winlogon's stop is a DLL-LOAD loop (OpenFile→CreateSection→MapView→Protect→Flush, +QueryAttributes/
  QueryPerfCounter) that OVERFLOWS the stack (cr2=0x105b0ff0 below STACK_GROWTH_FLOOR) — NOT a wait.
  So the real winlogon frontier is a loader/stack issue, a SEPARATE increment from the wait work.
- Result: gate 170/96 (+1 exec_winlogon_worker_multiplex), 0 FAIL, paint 768/768, exit 3, no hang,
  sel4test byte-identical (submodule clean). winlogon's own trajectory unchanged (same DLL-load stop
  at iters 5217, was 5215 — +2 worker events). The wait infrastructure (Part 1) + worker multiplex
  (Part 2) are correct and in place; winlogon advancing needs the loader/stack frontier next.
