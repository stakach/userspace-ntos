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
- **A RUNNING 3rd native hosted thread in a hosted VSpace faults at its trampoline entry**
  (cr2=0 VMFault) even with a byte-perfect, page_map_r-confirmed RX trampoline — INDEPENDENT of
  VA window (cluster or fresh-PT), transport (native/trap), and resume timing (in-spawn/deferred).
  The `WL_WORKER2/3` and `LSASS_LISTENER2/3` VA blocks work for suspended/query-only threads but a
  running 3rd hosted thread walls. This is a KERNEL-level issue (TCB VSpace/CNode binding via
  error-hiding SYS_SEND); needs a gdb-stub session, not more executive-side VA/transport tweaks.
  When such a fault destabilizes the boot, GATE the whole feature behind a compile-time `const …
  = false` that falls through to the pre-batch behavior, so the boot stays clean + committable.
