# Lessons

## Build / verification
- **build.sh silently leaves a STALE rootserver.elf if `cargo build` fails** (documented in
  MEMORY too). A non-ASCII char (em-dash `—`) inside a `b"..."` byte-string literal is a HARD
  compile error — but build.sh's tail still prints "staged: rootserver.elf" from the PRIOR build,
  so the boot runs stale code. ALWAYS verify `rust-micro/.tmp/rootserver.elf` mtime > your edits
  after `./build.sh`, and `grep -E "error\[|error:"` the build output. Keep byte-string literals
  ASCII-only (use `-` not `—`); em-dashes are fine in `//` comments.
- SYNCHRONOUS foreground boots only. The harness may auto-background a foreground `run_specs.sh`;
  don't poll it — arm a single Bash `run_in_background` `until grep -q <terminal marker>` waiter
  and act on the ONE completion notification. Terminal markers: "microtest sentinel matched",
  "All specs passed", "ntos-exec summary", "terminating on signal" (timeout).

## seL4 invocation error-hiding
- `SYS_SEND` invocations (page_map / paging_struct_map / untyped_retype / copy_cap /
  tcb_write_registers / tcb_set_space) HIDE all errors. When a failure would be silent (a thread
  that won't run, a map that may have collided), use the `_r` / SYS_CALL variants
  (`page_map_r`, `untyped_retype_r`, `copy_cap_r`) which return the real error label (0 = success).

## Hosted-thread multiplex
- The per-thread multiplex idiom = a NAMED slot per server thread: a badge constant + dedicated
  target-VSpace VAs (stack/teb/tramp/ipcbuf, distinct per running thread) + executive-side
  env-scratch + stack-mirror (MUST be globally distinct) + a `spawn_*_thread` wrapper over
  `spawn_hosted_thread` + branches in the loop's badge sub-select (`is_*`, pi resolution,
  active stack base/mirror, `current_tid`) + `mirror_ctx_for` + `owner_top_badge` +
  `hosted_thread_tcb_cell`. Generalizing to a dynamic worker = one more named slot with a
  dynamic badge (next free after the last listener badge).
- **The BATCH-35 "3rd running hosted thread faults at cr2=0" was NOT a kernel bug — it was an
  executive VA COLLISION masked by an error-hiding SYS_SEND (BATCH 36 root-cause).** `SCM_WORKER_ENV_SCRATCH_VA`
  (the executive-side 3-page env/trampoline scratch) was set to 0x107C, which is ALSO **winlogon's
  process-spawn `scr_base`** (`spawn_sec_image` for winlogon). Winlogon's spawn maps its TEB/TEB2/tramp
  frames at 0x107C_0000/1000/2000 and NEVER unmaps them. When `spawn_hosted_thread` later did
  `page_map(tramp, scr+0x2000, …)` for the SCM worker at the SAME VA, the kernel returned
  `seL4_DeleteFirst` (8, leaf PTE busy) — but that map used the **fire-and-forget `page_map` (SYS_SEND)**,
  so the error was INVISIBLE. The trampoline bytes were written into winlogon's stale env frame; the
  worker's REAL trampoline frame stayed ZERO and was mapped into services' VSpace, so the worker executed
  `00 00` (`add [rax],al`, rax=0) at entry → the reproducible `cr2=0` READ (err=4) fault at the tramp VA.
  RIP was correctly AT the trampoline; the frame was just zero. **Diagnosis technique that cracked it:**
  convert the spawn-path maps to `page_map_r` + read the target frame back through a FRESH independent
  alias and compare to what was written — `exec_map=8`, `via_fresh_alias=0xDEAD…` ≠ `wrote=…48b9…`
  named the collision in ONE boot. **Lesson reinforced:** when a hosted thread runs zeros/garbage, audit
  EVERY executive-side scratch/mirror VA for a collision with an already-mapped (never-unmapped) region
  BEFORE blaming the kernel — and use the `_r`/SYS_CALL map variants on the spawn path so a DeleteFirst
  can't hide. lsass's 3 listeners worked only because their scratch VAs (0x1079/107A/107E) happened to be
  genuinely free; the "3rd thread" framing was a red herring. Fix = one-line VA change (0x107C → 0x1075,
  a real free gap), pure executive, no rust-micro change.

## BATCH 39 — diagnose a NULL-deref CHAIN at the actual null, not the "obvious" pointer
Symptom: winlogon crash-parks at user32 `GetThreadDesktopWnd` (RVA 0x50009, `mov rax,[rax+0x10]`,
cr2=0x10). The instruction reads `[pDeskInfo+0x10]`, so it LOOKS like `pDeskInfo` (TEB+0x820) is NULL.
I seeded pDeskInfo — the fault PERSISTED. A **fault-time read-back diagnostic** (read the pointer via
the executive's persistent TEB alias, print it, then RESUME) proved pDeskInfo was ALREADY my seeded
value, so it was NOT the null. The real null was ONE call earlier: `GetThreadDesktopInfo()` returns
NULL when its guard `GetW32ThreadInfo()` (`[TEB+0x78]`=Win32ThreadInfo) is NULL — SHORT-CIRCUITING
before it ever reads pDeskInfo. So `rax==0` at the fault. LESSON: for a `mov rax,[rax+off]` NULL-deref,
`rax` is the RETURN VALUE of the preceding call — trace THAT function's control flow (it may return NULL
from an early guard on a DIFFERENT field), don't assume the field named in the faulting instruction is
the null one. A one-line fault-time readback of the suspected pointer disproves the wrong hypothesis in
a single boot. Fix = seed BOTH TEB.Win32ThreadInfo(+0x78) AND CLIENTINFO.pDeskInfo(+0x820).

## BATCH 39 — win32k's IntSetThreadDesktop ELSE branch actively CLEARS client CLIENTINFO
A spawn-time TEB seed of Win32ThreadInfo/pDeskInfo is not enough: win32k's real `IntSetThreadDesktop`
(desktop.c:3456), run KeStackAttachProcess'd to the client during `NtUserProcessConnect`, takes its
ELSE branch (client `pti->rpdesk==NULL` in our host) and sets `pci->pDeskInfo=NULL` — clobbering the
seed. Reliable fix = LAZILY REPAIR at the exact fault (scoped to `rip==<site> && cr2==<off>`) via the
executive's persistent alias of the client's TEB frame (env-scratch base `0x…107C_0000`, never unmapped
after spawn) + `reply_recv_badge` to re-run the faulting instruction. Idempotent, source-faithful.

## BATCH 39 — a SUCCEEDING RPC changes thread lifecycle → lifecycle-observing specs must be re-anchored
Specs that COUNT live self-exits of server threads (SCM worker/listener) were implicitly asserting the
BROKEN-RPC teardown. Once the RPC succeeds those threads PERSIST as servers → the count drops → the
specs go red. Re-anchor them to a DIRECT throwaway create→terminate self-test (same real mechanism:
`resolve_terminate_thread_handle`/`terminate_thread`/`exit_thread`/`can_reclaim_thread`), decoupled from
the RPC lifecycle. Keep the spec NAMES (gate count stable) but assert the mechanism, not the trajectory.

## BATCH 39 — route-ON needs a "driving-process crash → quiesce" so the boot reaches the gate
When the top interactive process (winlogon) crash-parks at its GUI/login frontier, the remaining live
top-level processes are just idle RPC servers (SCM/LSA) with no client left — the loop blocks in `recv`
forever → timeout. Add: `pi==2 crash && LSA signalled -> mark crash_parked + stop + break` so the gate
runs cleanly. This is the "break-on-winlogon-crash quiesce."

## BATCH 58 — "it got slower" is a HYPOTHESIS; timestamp the log on the HOST before believing it
A boot that blows the TCG budget (`RUNEXIT=124`) is NOT evidence of more/slower work. Batch 57
attributed it to "post-logon UI work grew ~2.5x" from a LINE COUNT (788 -> 1744) and shipped a
working feature disabled for "time". It was a **deadlock**: host-side timestamps
(`timeout 555 ./scripts/run_specs.sh 2>&1 | perl -ne 'BEGIN{$|=1;$t0=time()} s/\x00//g;
printf("[%04d] %s", time()-$t0, $_)'`) showed **zero output for the last 245 s** and a final
`SSN 0x1006 (dispatch)` with no reply. Rules:
- **Timestamp on the HOST, not the guest.** A guest clock is a suspect in exactly the scenario you
  are investigating (this batch spent one boot on a false "the HPET froze" lead; the host timestamps
  killed it in one).
- **Line counts and per-op averages computed from a truncated log are worthless.** Compute the RATE
  from real timestamps, and check whether the tail is slow or ABSENT.
- **A periodic census beats a final one.** `print_progress_census` only ran at quiesce, i.e. only on
  the boots that did not need diagnosing. It now dumps every 30 s — and the clock is a STATIC ticked
  from the win32k dispatch arm too, because that arm runs a NESTED pump and can spend minutes
  without the service-loop top ever being reached (which is why the first periodic census still
  stopped at dump #6 and looked like a frozen clock).
- **Cover BOTH service tables in any per-SSN histogram.** `SSN_HIST_N = 512` collapsed every win32k
  SSN (`0x1000+`) into one bucket, so "the win32k work grew" was unmeasurable by construction.
- **Count vs COST are different questions with different fixes.** Attribute wall-clock between two
  consecutive dispatch entries to the SSN in between (`W32_SSN_TIME_100NS`), the same technique the
  per-badge census uses at the loop top.

## BATCH 58 — a blocking win32k call in a single-threaded host is a SYSTEM-WIDE deadlock
`NtUserGetMessage` (`0x1006`) on an empty queue does not block one thread — the executive drives
win32k synchronously, so it blocks everything, INCLUDING the loop-top stall watchdog, so the boot
cannot even quiesce to the gate. Never dispatch a blocking win32k service speculatively: ask the
NON-blocking half first (`NtUserPeekMessage` with `PM_NOREMOVE`) and park on empty. Per-window
special cases do not generalise — the next dialog nobody anticipated (here: userenv's error
MessageBox) walks straight into the wall.
Corollary: **whose park ends the boot matters.** Quiescing on a WORKER thread's park cut a
still-advancing `CopyDirectory` off mid-tree; only the process's MAIN thread running dry is a
terminal condition.

## BATCH 58 — the executive's stack floats right after its image; do not put big values on it
`NtAllocateVirtualMemory`/`NtFreeVirtualMemory` copied a whole `VmRegionMap` onto the stack TWICE per
call. Raising `VM_REGION_CAPACITY` 64 -> 256 (a control experiment, ~10 KB per copy) killed the boot
instantly with a `#PF err=6` in the executive one page past `.bss`. Snapshot/rollback state belongs
in a STATIC scratch (the executive is single-threaded). A `#PF` whose cr2 is just past `.bss_end` is
a stack overflow into the guard page, not a bad pointer.

## BATCH 58 — a truncating staging buffer is silent until a bigger structure arrives
`NtSetInformationFile` staged the caller's payload into `[0u8; 32]` and passed `&payload[..32]`;
`FILE_BASIC_INFORMATION` is 40, so the volume correctly rejected it and `CopyFileW` failed with a
DOS error (24) that named nothing. Size staging buffers by the LARGEST class the handler serves, and
trace `class` + `length` next to the status.
