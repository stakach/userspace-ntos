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

## BATCH 59 — "resource exhausted" is a HYPOTHESIS; make the failing STEP name itself
`STATUS_INSUFFICIENT_RESOURCES` out of a multi-step helper says nothing about WHICH step failed.
`vm_map_private_page` has five failure points (page-table retype, frame acquire, `page_map`, alias
map, registry insert) and collapsed all five into one status. A per-step counter plus the seL4 error
LABEL named the real one in a single boot: `page_map_r` → **label 8 `seL4_DeleteFirst`**, i.e. a leaf
PTE that was already occupied — a VA collision, with 89 MiB of the boot Untyped still free. Rules:
- **Count the sub-steps, print the label.** A helper that maps a status onto several distinct causes
  must carry a per-cause counter, or every diagnosis of it is a guess.
- **Measure the pool before raising it.** The census said Untyped 64 %, registry 59 %, VAD 31 %,
  free list 16/4096 — no pool was near its cap, which is what falsified the whole framing.
- **A bounded map/unmap WATCH over the one suspect VA** (`[vm-watch]`, `VM_WATCH_LO/HI`) gives the
  life of that address — who mapped it, who released it, with which frame cap — in one boot.

## BATCH 59 — seL4 `Page::Unmap` needs the VSpace to have an ASID, or it silently does NOTHING
`decode_frame_unmap` finds the vspace via `pml4_paddr_for_asid(frame.asid)`; a PML4 retyped out of an
Untyped has `asid == 0`, and that lookup returns "no vspace" — so the unmap clears no PTE **and
returns `seL4_NoError`**. The root task must call `X86ASIDPoolAssign` on every VSpace it creates.
Until it does, every unmap in a hosted VSpace is a no-op whose only symptom is a `DeleteFirst` on the
next map at that VA, arbitrarily far away in time. **Assign the ASID at PML4 creation, before
anything is mapped**, and prove unmap with a commit → decommit → **RE-COMMIT** self-test — the only
assertion that goes red when the unmap is a no-op.

## BATCH 59 — a suppressed log line is a diagnostic hole; key the LOG on the thread, the STATE on the process
`park_and_log!` printed `[parked] pi=… fault=…` only if the PROCESS's crash bit was clear. A worker
thread's earlier milestone park already set that bit, so a genuinely new fault on the MAIN thread
printed **nothing** and the boot quiesced with no fault line at all. Per-process STATE with a
per-thread LOG key is the right split.

## BATCH 59 — a crash park latches the process as a DEAD win32k callback client
`park_and_log!` calls `unwind_dead_client_user_callbacks(pi)`, which sets the whole `pi` dead. Every
later callback for that process then fails closed with `STATUS_THREAD_IS_TERMINATING`, which disarms
the post-quiesce injections `exec_user_callback_dead_client_unwind` and
`exec_win32k_transport_call_nested` — they go red with `proof=0x00`, and the reason is invisible
unless you look for `[user-callback] callback not redirected … status=0xc000004b`. **Any new fault
arm on a process that has passed a real milestone must take the MILESTONE park** (guarded by
`!client_has_active_callback_frames(pi)`), never `park_and_log!`.

## BATCH 59 — fixing a wall MOVES the boot; budget for the next wall before turning it on
The ASID fix let `CopyDirectory` complete, which took winlogon into kernel32 code that ASSERTs on a
TEB field win32k clobbers, whose `int 3` crash-parked winlogon and cost two protected specs;
repairing THAT field took winlogon into an MS-RPC wait that deadlocks the single-threaded loop
(`RUNEXIT=124`). Land the fix plus a **milestone park** at the new frontier, and ship the next
repair only with the machinery its own frontier needs. Do not ship a repair that is measured to hang.

## BATCH 60 — "it looks like X's data" is NOT attribution; make the accused's access COUNTABLE
Two batches attributed a clobbered client TEB page to win32k because the bytes contained
`0x00c8d0d4` (`COLOR_BTNFACE`) and win32k is the component that owns system colours. It was wrong.
The refutation took three cheap, independent measurements, and every one of them is a counter, not a
narrative:
- **Map the accused's view READ-ONLY and count its store faults.** Zero faults = the accused never
  wrote it. The same mapping doubles as the fix if the accusation had been right (copy-on-write into
  a private shadow), so the experiment costs nothing to keep.
- **Count whether the accused was ever even handed the page** (`ro-maps`). It was not — the page is
  *registered* as reachable but no fault ever asked for it. "Registered" is not "accessed"; without
  this counter, "zero store faults" is unfalsifiable.
- **Scan for a FRAME ALIAS.** A second registration of the same frame cap under another key would
  make a write anywhere else land in this page. There was none.
- **Sample the invariant at EVERY boundary and report only the TRANSITION**, with a tag naming the
  call site: before/after every dispatch (at the one funnel nested dispatches also use), after every
  serviced syscall, and at the service-loop top. The transition only ever appeared across the window
  in which the CLIENT runs — which is the whole answer.
Then, to name the writer, protect the page **in the suspect's own address space** and log the RIP of
every store. The flood from one legitimate high-frequency writer (`RtlNtStatusToDosError`'s
`TEB.LastStatusValue` store) is handled by EMULATING that one instruction — write the value through
the executive's alias and step the client past it — so the protection stays continuously armed
instead of being torn down and re-armed thousands of times. Arm such a watch from the SUSPECT'S
SPAWN: arming it at the milestone nearest the symptom was measured to be one second too late.

## BATCH 60 — an "unserviceable" RPC is usually a REFUSED resource, so read the client's own error
The `\pipe\lsarpc` deadlock looked like a park/wake correlation gap (both sides parked, nothing to
signal). It was not: rpcrt4 printed its own diagnosis into the log — `rpc_server.c:631 failed to
create thread, error=5aa` — i.e. `RPCRT4_new_client`'s `CreateThread` was refused
STATUS_INSUFFICIENT_RESOURCES, so the connection was released and nobody ever read the bind PDU.
A per-connection server needs one worker PER CONNECTION; a single NAMED slot serves exactly one, and
a server thread never frees it. Before inventing a new named slot, check whether the generic
`(pi, slot)` hosted-thread layout already has a free one — it is fully general (badge, target VAs,
mirror, env scratch, multiplex sub-select), so an extra connection worker can be one `else if` arm.

## BATCH 60 — the only place a single-threaded loop can be watched is the place it BLOCKS
A wall-clock stall watchdog at the service-loop top cannot see a deadlock, because a deadlock is
precisely "the loop top is never reached again". Put the check inside the ONE blocking primitive
(`recv_full_r12`) and give it a deadline that joins the existing delay-timer `min()`, using the
bound notification that can already cancel any `Recv`. Two rules keep it from becoming the next
interrupt storm: every comparator write must be strictly AHEAD of the main counter, and the
trigger-type bit is never an arm control. Count a watchdog delivery as WORK, or it inflates the
"woke nothing" metric that exists to detect a storm. A nested pump that merely LATCHES the tick must
also re-arm + Ack it, or a deadlock inside a dispatch gets exactly one tick and can never trip.

## BATCH 61 — DISASSEMBLE THE FAULTING INSTRUCTION BEFORE THEORISING ABOUT THE FUNCTION
A fault reported as "`RtlEnterCriticalSection+0x14` — our code" produced a whole candidate list
(`DebugInfo == -1`, NULL `LockSemaphore`, a wrong field offset, an uninitialised CS). Objdump on the
staged DLL answered it in one command: `+0x14` is `lock incl 0x8(%rcx)`, the FIRST dereference of the
structure. Everything on the list is downstream of an instruction that never ran, so the function was
never a suspect — only its ARGUMENT was. Rules:
- **`objdump -d --start-address=<base+rva>` the artefact you actually shipped.** The symbol name plus
  an offset is not a diagnosis; the instruction is.
- **Read the exception VECTOR, not just "it crashed".** seL4 label 3 carried `exc# = 13` (`#GP`) with
  `code = 0`. In long mode a memory operand only `#GP(0)`s when the effective address is
  NON-CANONICAL — a `#PF` would mean unmapped/read-only. That single bit says "the pointer is
  garbage", not "the memory is bad", and it eliminated half the hypotheses for free.
- **A label-3/label-6 fault message carries IP/SP only; recover the GPRs.** `tcb_read_regs20` plus
  `[rsp + <frame size from the prologue>]` gives the argument AND the caller's return address, which
  named the module and the exact call site (`rpcrt4+0x4d97e`) in the same boot.

## BATCH 61 — WHEN A FIELD IS WRITTEN CORRECTLY AND LATER WRONG, WATCH THE FIELD, NOT THE SUSPECTS
The `TEB.ReservedForNtRpc` slot went `0 -> <real heap pointer, stored by rpcrt4 itself> -> garbage`.
An 8-byte watch on that ONE address — sampled at every service-loop event and on both sides of every
win32k dispatch, reporting only TRANSITIONS with the neighbouring 0x30 bytes — turned "who corrupts
the TEB" into "the neighbourhood 0x1680..0x16A8 fills with structured data while the CLIENT runs".
That is what made the answer findable: it was gdi32's deferred-GDI batch writing at
`TEB + 0x300 + Offset`, with `Offset` unbounded. Three batches had blamed win32k for the same class.
**Corollary: an unbounded producer with a bound the CONSUMER is supposed to reset is a clobber
engine.** When a client-side buffer has a "the kernel empties this" contract (`GdiTebBatch`,
`GdiBatchCount`), the host MUST implement the emptying step, or the buffer walks whatever follows it.

## BATCH 61 — A BUG CAN BE LOAD-BEARING; CHECK WHAT THE BROKEN STATE WAS ACCIDENTALLY BUYING
Bounding `GdiTebBatch.Offset` correctly LOST drawing: `ExtTextOutW`/`PolyPatBlt` fall through to the
real win32k system call **only when the batch record would not fit**, so the runaway `Offset` was the
only reason those calls reached win32k at all. Fixing it silently converted a memory-corruption bug
into a lost-rendering bug (`exec_msgina_credentials_entered` went red, `gdi-readbacks` 1 -> 0). Rules:
- **After a root-cause fix, diff the SPEC LIST, not just the symptom.** The spec that goes red is
  telling you what the bug was propping up.
- **Re-anchor an observation to the data, not to the transport.** The credential read-back moved from
  a dispatched `NtGdiExtTextOutW` to a `GdiBCTextOut` batch record — the same live `EDITSTATE.text`.
  Asserting the CONTENT (with the walk in a host-tested crate) survives the transport change; asserting
  the SSN did not.
- **A "clean" total fix can be worse than a scoped one — measure it.** Disabling gdi32 batching
  outright (a non-HDC sentinel in `GdiTebBatch.HDC`) looked more correct and was measured at
  **226/99 with 27 FAILs**. One control boot beat a plausible argument.

## BATCH 61 — "CLAIMED A SLOT" IS NOT "GOT A THREAD"
Batch 60 shipped `exec_lsarpc_deadlock_guarded` asserting the extra RPC connection worker was
*claimed*; the claim succeeded and `NtCreateThread` still answered STATUS_INSUFFICIENT_RESOURCES,
because the pre-created ETHREAD pool behind the slot was empty (`used-mask = 0x1f`, all 5). It stayed
invisible for a batch because the process then crashed for an unrelated reason before it could
deadlock. Assert the RESOURCE the caller receives, and make every "insufficient resources" refusal
print WHICH pool and how full — a status code that several distinct causes collapse onto is a
diagnosis-free failure.
