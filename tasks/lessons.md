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
