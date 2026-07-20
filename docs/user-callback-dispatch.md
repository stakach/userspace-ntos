# Plan: the win32k → client user-mode callback machinery (`KeUserModeCallback`)

Status: **PLAN for review** (no code yet). Author target: the executive + `nt-ntdll`.
Gate baseline: 187/98 (HEAD `ee3a804`); desktop paints 768/768; the IDD_LOGON logon dialog
is *created* (17 `#32770` windows) but never *painted* because its `WM_PAINT` is never
dispatched to the control procs.

## 0. Why

Every interactive window message that win32k must run in the *client's* window procedure —
`WM_PAINT`, `WM_ERASEBKGND`, `WM_INITDIALOG` to a server-side/queued window, hooks,
cross-thread `SendMessage` — flows through **`KeUserModeCallback`**. Today the executive's
`s_ke_user_mode_callback` (`win32k_subsystem.rs:2223`) is a *synthetic shortcut*: for the
window-creation callbacks (`WM_NCCREATE`/`WM_CREATE`) it stamps a canned `LRESULT` (Result=1)
into the output buffer and returns, **without ever running the client's `WndProc`**. That was
enough to make `CreateWindowEx` succeed, but it cannot render anything: the login dialog's
paint requires the *real* control window procedures to run and issue `BeginPaint`/GDI draws.

This plan builds the real mechanism. It is a prerequisite for the rendered login box and for
all future interactive UI (menus, hooks, real dialogs).

## 1. The correct model (per review feedback)

`KeUserModeCallback` is a **synchronous, reversible reverse-transition on the current thread**,
NOT asynchronous message delivery. It does NOT enqueue `WM_PAINT`, wake another thread,
inject execution asynchronously, identify a `WndProc`, or jump to an arbitrary user pointer.
It runs a *registered callback thunk* on the GUI thread that is **already inside a
user-originated syscall**, via a callback *index* interpreted in user mode through the process
callback table (`PEB->KernelCallbackTable`).

```
WM_PAINT lifecycle:            invalid region → message retrieval → dispatch → WndProc → validate region
KeUserModeCallback lifecycle:  kernel continuation → temporary user execution → NtCallbackReturn
```

The user-mode leg and its return:

```
Application WndProc returns LRESULT
  → user32 callback thunk returns
    → ntdll!KiUserCallbackDispatcher
      → syscall: NtCallbackReturn(result_buffer, result_length, callback_status)
        → kernel restores the suspended KeUserModeCallback continuation
```

**Critical properties (all mandatory):**
1. The callback executes as the *same thread* that entered win32k.
2. The original syscall stays *active* — `NtUserDispatchMessage` has NOT returned while the
   `WndProc` runs.
3. **Nested syscalls are legal** during the callback: `BeginPaint`, GDI calls, `SendMessage`,
   hooks, window create/destroy may all re-enter the subsystem.
4. **Nested callbacks are legal**: painting may trigger `WM_ERASEBKGND`, hooks, other
   synchronous messages — each its own reverse-transition.
5. `NtCallbackReturn` is *special*: it resumes an existing kernel continuation rather than
   returning to a caller like an ordinary syscall.
6. User buffers are marshalled *deliberately*: callback arguments live in user-visible memory;
   kernel/subsystem-internal pointers must not be exposed directly.
7. **No GUI locks are held across user execution.** The callback is an adversarial
   re-entrancy point — the `WndProc` may destroy or mutate the very window being processed.
   Objects (`PWND`, DCs, …) must be *revalidated* after every callback return.

Arbitrary nesting must work:

```
syscall → callback → syscall → callback → syscall
        ← callback return ← syscall return ← callback return ← original syscall return
```

## 2. The architectural adaptation (the crux)

In real NT, win32k IS the kernel: it shares the address space and the thread's kernel stack, so
the "saved continuation" is literally the thread's kernel stack frame, and the reverse
transition is a return-to-user with a callback frame pushed. **Our topology is different, and
this is the whole design problem:**

- **winlogon** (the GUI thread) runs in its own VSpace/TCB. It issues `NtUserDispatchMessage`
  as a **native seL4 `Call`** to the executive, which routes it to win32k.
- **win32k.sys** runs as an **isolated seL4 component** (own VSpace/TCB/dispatch loop —
  `component_main`/`component_pump`), reached over an endpoint. It is NOT in winlogon's address
  space and cannot itself run code in winlogon's VSpace.
- The **executive** is the mediator between them.

So the reverse transition is a **three-party dance mediated by the executive**, and "the
kernel continuation that is saved/restored" is *win32k's suspended component dispatch*, while
"the thread that runs the callback" is *winlogon's thread*:

```
winlogon thread                     executive (mediator)                 win32k component
───────────────                     ────────────────────                 ────────────────
NtUserDispatchMessage  ──Call──▶    route to win32k        ──dispatch──▶  co_IntDispatchMessage
  (blocked on reply)                                                        … decides to run WndProc
                                    ◀── KeUserModeCallback request ──       KeUserModeCallback(api,in,inlen)
                        ◀─redirect  push UserCallbackFrame;                  (component now BLOCKED,
  resume at             (reply w/   SUSPEND win32k dispatch;                  awaiting callback result)
  KiUserCallbackDispatcher  redirected RIP + marshalled args)
    KernelCallbackTable[api]
    user32 thunk → WndProc
      BeginPaint ─────Call──▶        route to win32k (NESTED) ─────────▶    (nested dispatch frame)
        …GDI draws… ◀── reply ──                                            NtGdi* → framebuffer surface
      WndProc returns LRESULT
    NtCallbackReturn(result) ─Call▶  pop UserCallbackFrame;
                                     RESUME win32k dispatch  ──reply w/ result──▶ KeUserModeCallback returns
                                                             ◀── win32k finishes DispatchMessage ──
                        ◀─restore    restore winlogon's saved
  NtUserDispatchMessage  (reply w/   pre-callback context
  returns                 orig ctx)
```

Two consequences that make this harder than in-kernel NT:

- **Both sides need a continuation stack.** winlogon needs a *callback-continuation* stack
  (the reverse transitions in flight); win32k needs a *nested-dispatch* stack (the nested
  `NtGdi*/NtUser*` syscalls serviced while an outer dispatch is suspended awaiting a callback).
  The executive interleaves them: `win32k-frame-1 → cb-frame-1 → win32k-frame-2 → cb-frame-2 …`.
- **win32k's component dispatch must be RE-ENTRANT.** While its outer `co_IntDispatchMessage`
  is suspended awaiting the callback, a nested `BeginPaint` from winlogon must be serviced by
  win32k *on top of* the suspended frame. `component_pump` currently services one dispatch at a
  time; it must gain a nested-dispatch capability (a stack of win32k dispatch continuations,
  keyed per client thread).

## 3. State to add

### 3a. Per-client-thread callback-continuation stack (executive-side)
Keyed by the client thread (badge/tid). Mirrors the review's struct, adapted:

```rust
struct UserCallbackFrame {
    /// How to resume win32k's suspended dispatch: the parked reply cap + component identity
    /// of the win32k Call that issued KeUserModeCallback. (Our "syscall_continuation".)
    win32k_continuation: SuspendedDispatch,     // reply cap + win32k component/thread id
    callback_index:       u32,                  // ApiIndex → PEB->KernelCallbackTable
    user_argument:        ClientAddr,           // marshalled input buffer in the CLIENT VSpace
    argument_length:      usize,
    /// winlogon's register/context at the instant win32k called back — restored when THIS
    /// frame's syscall finally unwinds (only the OUTERMOST frame restores to the original
    /// NtUserDispatchMessage return; inner frames restore to their KiUserCallbackDispatcher).
    saved_user_context:   ClientContext,        // rip/rsp/rflags/arg regs
    previous_callback:    Option<CallbackFrameId>,
}
```

### 3b. Per-client-thread win32k nested-dispatch stack (executive-side / win32k-side)
The stack of win32k dispatch continuations for one client thread. `component_pump` pushes a
frame when it forwards a (possibly nested) `NtUser*/NtGdi*` to win32k and pops on completion; a
`KeUserModeCallback` mid-dispatch suspends the *top* frame (does not pop it) and hands control
back to the executive to run the callback.

### 3c. Client-side callback table + entry
`PEB->KernelCallbackTable` (PEB **+0x58**, x64) must point at winlogon's `KernelCallbackTable` —
the array of user32 client thunks (`__fnDWORD`, `__fnINLPCREATESTRUCT`, the `WINDOWPROC`
dispatcher, …). user32 builds this during its client-pfn init (`NtUserInitializeClientPfnArrays`
/ `apfnClientA/W`); we must ensure it is populated (either user32 populates it and we seed the
PEB pointer, or we seed the table). `ntdll!KiUserCallbackDispatcher` reads `[PEB+0x58][index]`.

## 4. Pieces: exist vs to build

| Piece | State |
|---|---|
| `KiUserCallbackDispatcher` **dispatch logic** (`ki.rs::callback_dispatcher`, `UserCallback`) | ✅ exists, host-tested |
| `KiUserCallbackDispatcher` **target entry** (naked thunk: read frame → call logic → `NtCallbackReturn`) | ☐ build (in `nt-ntdll-dll`, mirror the SEH `KiUserExceptionDispatcher` seam) |
| `PEB->KernelCallbackTable` populated + PEB+0x58 seeded for winlogon | ☐ build (verify user32's client-pfn init runs; seed the pointer at spawn) |
| `NtCallbackReturn` (`ZwCallbackReturn`) target syscall | ☐ build (ntdll stub + the executive-side special handler) |
| Executive: intercept win32k's real `KeUserModeCallback` → issue a **callback request** | ☐ build (replace the `s_ke_user_mode_callback` shortcut) |
| Executive: **reverse transition** (suspend win32k, redirect winlogon → `KiUserCallbackDispatcher`, restore) | ☐ build |
| Executive: per-thread **callback-continuation stack** (3a) | ☐ build |
| win32k **nested-dispatch** / re-entrant `component_pump` (3b) | ☐ build |
| **buffer marshalling** in/out across VSpaces (client-visible only) | ☐ build |

`s_ke_user_mode_callback` today intercepts win32k's `KeUserModeCallback` ntoskrnl import and
short-circuits it. The real version turns that interception into the reverse transition instead
of a synthetic return.

## 5. Control-transfer mechanics (seL4 level)

- **Suspend win32k:** win32k's `KeUserModeCallback` is (already) an executive-intercepted call.
  Instead of replying, the executive *withholds* the reply — win32k stays blocked in that call
  (its parked reply cap = the `win32k_continuation`). This is exactly the cooperative
  reply-cap park already used for events/pipes, applied to the win32k dispatch.
- **Redirect winlogon → `KiUserCallbackDispatcher`:** winlogon is blocked awaiting the reply to
  its (possibly nested) native `Call`. The executive marshals the callback input buffer into a
  client-side callback-args region, then **replies to winlogon's Call with a redirected resume
  point**: set `RIP = KiUserCallbackDispatcher`, `RSP =` a fresh callback stack, and the
  argument registers per the `KiUserCallbackDispatcher` ABI (ApiIndex, input ptr, input length).
  Save winlogon's *pre-redirect* context (its real post-syscall RIP/RSP/regs) into the
  `UserCallbackFrame.saved_user_context`. Use `seL4_TCB_WriteRegisters` (or the reply-with-context
  path) — the register ABI must be exact.
- **Nested syscalls during the callback** (`BeginPaint`, GDI, `SendMessage`): ordinary native
  `Call`s from winlogon → routed to win32k as a **nested dispatch** (push a win32k
  nested-dispatch frame; win32k services it on top of the suspended outer frame). A nested
  `KeUserModeCallback` inside that recurses (another `UserCallbackFrame`).
- **`NtCallbackReturn(result, len, status)`:** recognised specially by the executive. It:
  (1) copies the result buffer from the client into the reply for win32k;
  (2) pops the top `UserCallbackFrame`;
  (3) **resumes win32k's suspended dispatch** — replies to the withheld `KeUserModeCallback`
      call with the result → win32k continues (revalidates its objects) and finishes its
      dispatch;
  (4) when win32k's dispatch completes, the executive resumes winlogon by restoring
      `saved_user_context` (the outermost frame returns from the original
      `NtUserDispatchMessage`; an inner frame returns into the enclosing
      `KiUserCallbackDispatcher`).

## 6. Requirements → how they are met

- **(1) same thread / (2) syscall stays active:** the callback runs on winlogon's TCB; win32k's
  dispatch is *suspended not completed* (reply withheld), so `NtUserDispatchMessage` has not
  returned.
- **(3)(4) nesting:** the two continuation stacks (3a/3b) + re-entrant `component_pump`.
- **(5) `NtCallbackReturn` special:** it resumes a *withheld win32k reply*, not a normal return.
- **(6) marshalling:** the executive copies callback in/out buffers between win32k's view and a
  *client-visible* args region; win32k-internal pointers are never placed in the client buffer
  (win32k already passes handle-based args in `*_CALLBACK_ARGUMENTS`).
- **(7) no locks / revalidation:** we HOST the real win32k, whose own `co_IntCallWindowProc`
  revalidates `PWND` after the callback. Our mediation must *preserve* that: hold no
  executive-side state that assumes win32k is frozen across the callback, keep the handle table
  coherent, and let win32k re-run its own validation on resume. The executive adds no GUI lock.

## 7. Phased implementation (each phase gate-verified, boot must QUIESCE, paint stays 768/768)

- **Phase 1 — client dispatcher (mostly host-testable).** Real `KiUserCallbackDispatcher`
  target entry in `nt-ntdll-dll` (naked: read the frame, call the existing `ki::callback_dispatcher`
  logic, invoke the resolved thunk, `NtCallbackReturn` with the LRESULT). Seed
  `PEB->KernelCallbackTable` (verify user32's client-pfn table is built; seed PEB+0x58). ntdll
  stub for `NtCallbackReturn`/`ZwCallbackReturn`. Host-test the dispatch logic (exists) + the
  frame unpack. No behavior change yet (nothing calls it) → gate 187 held, byte-identical.
- **Phase 2 — single reverse transition (no nesting).** Executive: replace the
  `s_ke_user_mode_callback` shortcut for **one** callback (start with the create-time
  `WM_NCCREATE`, whose synthetic path we can compare against) with the real reverse transition:
  suspend win32k, redirect winlogon to `KiUserCallbackDispatcher`, run its real `WndProc`,
  `NtCallbackReturn` → resume win32k. Prove the real `WndProc` ran (a counter / the client proc's
  observable effect) and that `CreateWindowEx` still succeeds + `exec_win32k_desktop_painted`
  stays 768/768 + the SAS specs hold. Gate 187 held (behavior-equivalent) or +1 for a
  "callback ran for real" spec.
- **Phase 3 — nesting + re-entrant win32k dispatch.** Per-thread callback-continuation stack +
  win32k nested-dispatch stack + re-entrant `component_pump`. Prove with a callback whose
  `WndProc` issues a nested syscall (e.g. `GetDC`/`BeginPaint`) that re-enters win32k while the
  outer dispatch is suspended, returns, and unwinds correctly. Host-test the continuation-stack
  push/pop/nesting logic (pure). Gate green.
- **Phase 4 — `WM_PAINT` → the login box renders.** With the machinery real, drive the dialog's
  `WM_PAINT`/`WM_ERASEBKGND`/`WM_INITDIALOG` to the control procs via the callback; the procs'
  `BeginPaint → GetDC/GetStockObject/GetSysColorBrush/FillRect/DrawTextW` first exercise the
  GDI validity check → seed the client GDI-object entries (per the disassembled contract in
  DIALOG BATCH 3/4) + route `NtGdi*` draws to the real framebuffer surface. Result: the
  credential box paints ON TOP of the `0x003a6ea5` desktop. New spec
  `exec_msgina_logon_dialog_painted` (framebuffer readback of the dialog rect). Gate → 188.
  NB: an **adjacent prerequisite** (separate from this machinery) — the dialog's modal
  `DIALOG_DoDialogBox` pump currently returns instead of pumping (DIALOG BATCH 4); Phase 4 must
  also make that pump run so a `WM_PAINT` is generated to dispatch.

## 8. Risks / notes

- **Context save/restore correctness.** A wrong register/RSP on the redirect or restore
  corrupts winlogon. The seL4 register ABI (`TCB_WriteRegisters` / reply-with-context) must be
  exact; test the round-trip on a trivial callback (Phase 2) before nesting.
- **win32k re-entrancy.** The isolated win32k component servicing a nested dispatch while an
  outer dispatch is suspended is the subtlest part; if win32k's component can only hold one
  dispatch context, Phase 3 must give it a nested-dispatch stack. Validate that win32k's own
  object revalidation still works across the boundary.
- **The paint is the canary.** The win32k-side desktop paint (768/768) MUST stay green through
  every phase — the callback path must not disturb it.
- **Modal-pump prerequisite** (Phase 4) is a separate wall from the callback machinery; keep
  them distinct in implementation + specs.
- **Scope:** Phases 1–3 are the reusable machinery (every future interactive message benefits);
  Phase 4 is its first real consumer (the login box). Land 1–3 behavior-preserving before 4.

## 9. Relationship to existing code / plans

- Builds on `crates/nt-ntdll/src/ki.rs` (`callback_dispatcher`, host-tested) and mirrors the SEH
  `KiUserExceptionDispatcher` target seam (batch 42) for the client entry.
- Replaces the `win32k_subsystem.rs::s_ke_user_mode_callback` synthetic shortcut with the real
  reverse transition; extends `component_pump` for re-entrant/nested win32k dispatch.
- Reuses the cooperative reply-cap park (events/pipes) for "suspend win32k", and the
  client-memory mapping patterns (desktop-heap window mapping, GDI handle table) for Phase 4.
- Tracked in `ntdll_plan.md` (the desktop/logon-UI frontier) as the machinery behind the
  rendered login box.
