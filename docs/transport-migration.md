# Component-Dispatch Transport Migration — hand-rolled Send/Recv → seL4 `Call` + MCS reply objects

**Status:** **Phase 0 DONE. Phase 1 DONE** (gate **231/99 ZERO FAILs**, RUNEXIT=3, paint 768/768 @
`0x003a6ea5`). Phases 2-4 are still plan-only. Baseline `1141349` → Phase 0 `d287c48` → Phase 1.

> ### ★ WHAT THE PLAN GOT WRONG — read this before Phase 2
>
> Three corrections, all found by running it. They are folded into §3.5, §4 and §6 below, and each
> is documented at the code that carries it.
>
> 1. **`reply_on` CANNOT carry an arbitrary message LABEL** (§3.5 said it could). `reply_on` is a
>    `SYS_CALL` on a non-endpoint cap, so the kernel routes it through
>    `invocation.rs::decode_invocation`, which parses the msginfo label as an `InvocationLabel`
>    **before** dispatching on the cap type. `InvocationLabel::from_u64(0x771)` is `None`, so
>    `reply_on(R, DISPATCH_LABEL<<12)` fails `seL4_InvalidArgument` and never reaches `decode_reply`.
>    Only label **0** (`InvalidInvocation`) survives that gate. **The request tag must ride in MR0**
>    (`spawn_hosts::REQUEST_TAG_LEN`, a length-1 reply). Phase 2 needs exactly this to distinguish a
>    nested DISPATCH from a callback RESUME — the `RESUME`/`DISPATCH` labels in §3.4 must become MR0
>    tags. *(The component→executive direction is unaffected: the component Calls an **Endpoint**
>    cap, so its `dispatch_label` still rides in the message label, which is what the pump's DONE
>    arm matches on.)*
>
> 2. **★★ THE COMPONENT'S `Call` CLOBBERS THE EXECUTIVE'S LEGACY `reply_to`.** §2.3 declared the
>    recorded objection "wrong" because `finish_call` writes the **receiver's** `reply_to`, not the
>    sender's. That is true — and it is precisely why inverting the direction reintroduces the same
>    hazard from the other side: the executive is now the RECEIVER, so every component `Call` writes
>    `executive.reply_to = component`. For a demand-page fault this is self-correcting (the pump
>    answers it at once, and `decode_reply` clears `reply_to` when it names that caller). The
>    DISPATCH COMPLETION is not: the component is deliberately LEFT blocked in that Call, so
>    `reply_to` keeps pointing at it after the pump returns. The main service loop's fast path replies
>    to a client syscall through that `reply_to` (`service_sec_image.rs`, the `else` arm commented
>    *"Non-routed path: reply_to names this caller (never clobbered)"*). Once an IRP is dispatched
>    while servicing a client syscall, that comment is FALSE — the reply resumed **npfs** with a
>    length-18 syscall result, npfs re-ran a dispatch off a stale shared frame, and the client never
>    woke. **Silent hang, RUNEXIT=124, observed on the first Phase-1 boot.** Fix: the same mechanism
>    the win32k plane already uses (Fix B) — reply through the caller's BOUND reply object, gated on
>    `spawn_hosts::COMPONENT_CALL_CLOBBERED_REPLY_TO`. **Phase 2 must assume win32k's conversion will
>    make this flag true far more often, and Phase 3 should retire the legacy `reply_to` reply from
>    the main loop entirely rather than keep widening the guard.**
>
> 3. **`seL4_InvalidCapability` is 2, not 6** (§Phase-1 step 5 said 6; 6 is `seL4_FailedLookup`).
>    See `rust-micro/src/types.rs:114`.
>
> Two smaller deviations, deliberate:
>
> * `REPLY_FSD_SLOT` is sized at `MAX_DRIVER_INSTANCES` (4), not the plan's 2, so a third
>   `DriverSpec` cannot silently get cptr 0 and therefore no transport at all. Cost: 2 extra objects
>   out of `MAX_REPLIES = 384`.
> * `PumpChannel` also carries `tcb`, needed for the R2 wall handling.


**Decision (user, explicit):** replace the hand-rolled Send/Recv component-dispatch transport with
proper seL4 `Call` + MCS reply objects, then **delete** the hand-rolled machinery. Breakage is
tolerated mid-phase; every phase ENDS green.

---

## 0. Why — three defects, one root cause

| # | Defect | Fix shipped | Commit |
|---|--------|-------------|--------|
| 1 | **IRP correlation.** `component_main` publishes its completion BEFORE waiting for the next request; `component_pump` accepted ANY `dispatch_label` message as its answer → phase slip → both sides block in `Send` → deadlock with no fault and no log line. | `SH_REQ_SEQ` sequence handshake, scoped to the IRP substrate | `7d0703b` |
| 2 | **Syscall correlation under nesting.** Same class, but the seq handshake is unusable: `SH_REQ_SEQ` is bumped only by `component_main`'s outer loop, never by the rendezvous' nested arm. | per-dispatch **token** in MR0 echoed by the component + an executive-side LIFO token stack for the callback-resume level | `1141349` |
| 3 | **Availability (OPEN).** The executive's wake `Send` blocks against a component that is not receiving. RIP-sampled over 909 wakes: 907 at `send_done_on`+2, 3 at the `recv_req_on` syscall, and the ONE wake that never completes is the only sample at `recv_req_on`+2. | none — this is the current wall (`LSA_WORKER_ROUTE_ENABLED`, `exec_handler.rs:7062`) | open |

All three are consequences of the SAME root: **the transport carries no kernel-enforced binding
between a request and its answer, and both halves are blocking `Send`s on one endpoint.** seL4's
`Call` + a first-class MCS Reply object gives both properties for free:

* the kernel binds the reply object to the caller at pair-up (`endpoint.rs:180` `finish_call` →
  `s.replies[ridx].bound_tcb = Some(sender)`), so a reply cannot reach the wrong level;
* a thread blocked in `Call` is `BlockedOnReply` and **cannot** race ahead to a `Send` — phase slip
  is not expressible;
* answering is `Send`-on-a-`Cap::Reply` (`invocation.rs:1504` `decode_reply`), which **never
  blocks** — it wakes the bound caller or fails immediately with `seL4_InvalidCapability`.

---

## 1. Inventory of the hand-rolled transport

### 1.1 Raw IPC helpers (executive side, `components/ntos-executive/src/main.rs`)

| Symbol | Line | What it is | Exists to work around |
|---|---|---|---|
| `ep_send(ep, label)` | 3855 | blocking `SYS_SEND`, msginfo `label<<12`, len 0 | **win32k "fix A"** — the dispatch was made a plain Send explicitly so it would *not* consume the executive's per-TCB `reply_to`. This is the wake that blocks (defect 3). |
| `ep_send_token(ep, label, token)` | 3871 | as above, len 1, MR0 = correlation token | defect 2 — carries the token the component must echo |
| `ep_recv_full(ep)` | 3883 | `SYS_RECV`, returns `(badge, msginfo, mr0..mr3)`, **no** reply register | the FSD/pre-reply-cap receive |
| `reply_recv_full(ep, len, r0..r3)` | 3907 | `SYS_REPLY_RECV` — reply half uses the **legacy per-TCB `reply_to`** (`syscall_handler.rs:105` → `handle_reply` → `current.reply_to`) | the pre-reply-cap fault resume; the reason `reply_to` clobbering was ever a problem |
| `reply_recv_badge(...)` | 3932 | as above but registers `REPLY_MAIN` in r12 on the RECV half | the main service loop's half-migration to reply objects |
| `recv_full_r12(ep, reply_cptr)` | 3967 | `SYS_RECV` **with the MCS reply register r12** → kernel binds `reply_cptr` to whoever Calls | **fix B** — already the correct primitive |
| `send_on_reply(reply_cptr, msginfo, r0..r3)` | 3995 | `SYS_SEND` on a `Cap::Reply` → `decode_reply` | **fix B** — already the correct primitive; note it *silently swallows* errors (SYS_SEND) |

### 1.2 Component side (`components/ntos-executive/src/driver_launch.rs`)

| Symbol | Line | What it is | Works around |
|---|---|---|---|
| `send_done_on(label, token)` | 1563 | plain `SYS_SEND` on `CT_FAULT`, len 1, MR0 = echoed token | "fix A" (Send not Call) + defect 2 (token echo) |
| `recv_req_on() -> (label, token)` | 1580 | plain `SYS_RECV` on `CT_FAULT` | the other half of the un-bound pair |

The **gap between these two syscalls** is precisely defect 3: the component is runnable-but-not-yet-
receiving for the whole window, and the executive's wake `Send` blocks in it.

### 1.3 The run loops (`components/ntos-executive/src/spawn_hosts.rs`)

| Piece | Lines | Works around |
|---|---|---|
| `PumpChannel` | 408–443 | the channel descriptor |
| `PumpChannel.wake_first` | 427–433 | encodes "is the component parked at a recv or is it a blocked sender?" — a question that only exists because the transport is unpaired |
| `PumpChannel.reply_cap` / `HostCaps::nested_reply_cap` | 436, 129 | **fix B**, kept strictly gated so the two transports never merged |
| `component_pump` / `component_pump_resume_user_callback` / `component_pump_inner` | 616 / 620 / 624 | the executive-side loop |
| `SH_REQ_SEQ` const | 102 (and `win32k_subsystem.rs:187`) | defect 1 |
| `seq_before` sample + `seq_handshake` gate | 702–716 | defect 1 |
| stale-`done` re-wait arm | 731–752 | defect 1 |
| token allocator `DISPATCH_TOKEN_NEXT` | 534 | defect 2 |
| `DISPATCH_TOKEN_STACK` / `_MAX` / `_DEPTH` / `_MAX_DEPTH` | 539–543 | defect 2 (callback-resume level) |
| `dispatch_token_push` / `_top` / `_pop` / `dispatch_token_depth` / `suspended_dispatch_token` | 548–588 | defect 2 |
| `PUMP_TOKEN_MISMATCHES` | 546 | defect 2 observability |
| token-mismatch re-wait arm | 753–778 | defect 2 |
| `owns_token_stack_top` retire | 976–982 | defect 2 |
| `PUMP_STALE_DONES` | 1152 | defect 1 observability |
| `PUMP_SLIP_INJECT` | 1155 | defect-1 fault injector |
| `W32_SLIP_INJECT` / `W32_SLIP_INJECT_TOKEN` | 1163–1165 | defect-2 fault injector |
| `component_main` `send_done → recv_req → dispatch → status → seq++` loop | 1115–1145 | the component-side loop; the `seq` write (1142–1143) and the `token` variable (1119) are pure workaround |
| slip-injection block in `component_main` | 1131–1133 | defect-1 injector |

### 1.4 The win32k re-entrancy plane

| Piece | Location | Note |
|---|---|---|
| `s_ke_user_mode_callback_rendezvous` | `win32k_subsystem.rs:2374` | component side: `send_done_on(W32_USER_CALLBACK_LABEL, 0)` (2435) then a `recv_req_on()` loop (2443) taking either `W32_USER_CALLBACK_RESUME_LABEL` (break) or a nested `W32_DISPATCH_LABEL` |
| nested slip injector | `win32k_subsystem.rs:2450–2456` | defect-2 injector |
| labels | `win32k_subsystem.rs:550 / 552 / 556` | `W32_DISPATCH_LABEL 0x770`, `W32_USER_CALLBACK_LABEL 0x772`, `W32_USER_CALLBACK_RESUME_LABEL 0x773` |
| `UserCallbackDisposition::{ReplyImmediately, SuspendComponent}` | `win32k_glue.rs:99–101`, decided at 728/749 | `SuspendComponent` = "leave the component parked in its callback receive loop and RETURN from the pump" |
| callback arm in the pump | `spawn_hosts.rs:781–808` | on `ReplyImmediately`: `ep_send(RESUME)` + `recv_full_r12`; on `SuspendComponent`: break out with `callback_suspended` |
| `resume_suspended_user_callback_component` | `win32k_glue.rs:930–963` | builds a `wake_first: false` channel and calls `component_pump_resume_user_callback`, whose first act is `ep_send(RESUME)` (`spawn_hosts.rs:676`) |
| resume call sites | `win32k_glue.rs:993`, `1164`, `1889` | normal `NtCallbackReturn`, dead-client unwind, cancel |

### 1.5 Executive-side pump call sites (what must keep working)

| Site | Location | Shape |
|---|---|---|
| FSD DriverEntry init | `driver_launch.rs:2216–2241` | `wake_first: false`, demand 512, `trace_faults`, kind `Irp` |
| FSD per-IRP dispatch | `driver_launch.rs:2481–2516` | `wake_first: true`, demand 256, kind `Irp` |
| win32k dispatch | `win32k_glue.rs:2623–2660` | `wake_first: true`, demand 8192, all win32k caps true |
| win32k callback resume | `win32k_glue.rs:930–963` | `wake_first: false` + `resume_user_callback` |
| **win32k DriverEntry init — NOT on the pump** | `main.rs:10127–10190` | a *bespoke* inline `ep_recv_full` + `reply_recv_full` loop that ends on `W32_DISPATCH_LABEL`. It uses the LEGACY `reply_to`. Must migrate too. |

### 1.6 The bypass switches and their gate specs

| Switch | Location | Gate spec |
|---|---|---|
| `FSD_DISPATCH_SEQ_HANDSHAKE` | `main.rs:773` (used 10820, 12185) | `exec_component_dispatch_in_phase` (`main.rs:10819`) |
| `W32_DISPATCH_TOKEN_BINDING` | `main.rs:782` (used `spawn_hosts.rs:658`, 12310–12333) | `exec_win32k_dispatch_in_phase_nested` (`main.rs:12326`) + injector `win32k_glue.rs:1335` + proof bits `NESTED_SLIP_*` (`win32k_glue.rs:1283–1301`) + `WIN32K_NESTED_SLIP_INJECTION` (`main.rs:7492`) |

---

## 2. ★ The objection, and why MCS reply objects dissolve it

### 2.1 The objection as recorded

`ntdll_plan.md:4988–4996`:

> `Call`/`ReplyRecv` … was rejected here for one concrete reason: this transport already had to be a
> plain **Send/Recv** pair — win32k's fix A. A `Call` consumes the executive's single `reply_to`
> slot, and the executive is mid-`Call` from the csrss/winlogon client whose syscall it is
> forwarding; that is precisely the clobber that once made win32k never run … Making the DISPATCH a
> Call would reintroduce fix A's bug, and making the COMPONENT the caller would invert the loop …
> which is a rewrite of the shared `component_main` both substrates now run.

### 2.2 What the kernel actually does (code, not memory)

Read `rust-micro` @ submodule `f76be01` (`src/syscall_handler.rs`, `src/endpoint.rs`,
`src/invocation.rs`, `src/reply.rs`, `src/fault.rs`):

1. **`reply_to` is written on the RECEIVER, never on the SENDER.**
   `endpoint.rs:180` `finish_call(sched, sender, receiver)` does
   `sched.slab.get_mut(receiver).reply_to = Some(sender)`.
   An *outgoing* `Call` from the executive therefore writes **win32k's** `reply_to`, not the
   executive's. The clobber the objection names comes from *incoming* Calls (each fault the
   executive receives overwrites `executive.reply_to`), which is a **receive-side** problem — and
   it is already solved.

2. **The executive already receives through first-class reply objects.**
   `handle_recv` (`syscall_handler.rs:737–756`) reads the MCS reply register **r12**, looks up a
   `Cap::Reply`, and stores `pending_reply`; `finish_call` (`endpoint.rs:185–190`) then does
   `s.replies[ridx].bound_tcb = Some(sender)`. The executive's main loop is
   `recv_full_r12(fault_ep, REPLY_MAIN_SLOT)` (e.g. `service_sec_image.rs:576`, `660`, `814`,
   `5437`) and win32k's dispatch faults ride `REPLY_W32` (`win32k_glue.rs:2628`,
   `spawn_hosts.rs:635`). `reply_to` is already **not** the executive's binding mechanism on the
   channels that matter.

3. **Reply objects are per-object state, not per-thread.**
   `reply.rs:19` — `struct Reply { bound_tcb: Option<TcbId> }`. `kernel.rs:39` — `MAX_REPLIES = 384`.
   The executive already holds a *set* of them: `REPLY_MAIN_SLOT`, `REPLY_W32_SLOT`,
   `REPLY_SMLOOP_SLOT`, `REPLY_CSRLOOP_SLOT`, plus a 16-deep `WAIT_REPLY_POOL`
   (`main.rs:8252–8285`), and it already **steals and rotates** them (`wait_park`,
   `pipe_wait_park`, `dbgk_reporter_park`, `io_completion_park` — `main.rs:4186`, `4431`, `4572`,
   `service_sec_image.rs:9428`, `9567`, `9971`).

4. **Answering via a reply cap never blocks and never touches `reply_to` of the replier.**
   `invocation.rs:1504` `decode_reply` looks the caller up from `replies[idx].bound_tcb`, transfers
   the message (fault-shaped via `fault::apply_fault_reply`, or normal via
   `endpoint::deliver_message`), makes the caller runnable, and clears the binding. If the object is
   unbound it returns `seL4_InvalidCapability` **immediately**.

### 2.3 The dissolution

The objection is correct about *one* thing and wrong about the rest:

* **Correct:** the executive must not be blocked in `Call` on the component, because the component's
  demand-page faults are delivered to the SAME endpoint (`deliver_fault`, `fault.rs:108–176`, sends
  with `do_call: true`) and the single-threaded executive must be in `Recv` to take them. So
  "executive `Call`s the component" is genuinely unworkable — **not because of `reply_to`, but
  because the executive is the component's PAGER and cannot block on it.**

* **Wrong:** "a Call consumes the executive's single `reply_to` slot". It does not — outgoing Calls
  write the *receiver's* slot, and the executive's own binding is already a reply **object**, not
  `reply_to`.

* **Wrong (as a cost estimate):** "making the COMPONENT the caller … is a rewrite of the shared
  `component_main`". It is a **two-line** change: `send_done_on(label, token)` + `recv_req_on()`
  collapse into ONE `Call`. Everything else in `component_main` is unchanged.

**Therefore the target direction is: the component is always the CALLER; the executive is always the
SERVER.** That is also the direction the kernel already forces for faults, so dispatch and
fault-handling become ONE protocol instead of two interleaved ones.

### 2.4 The single-reply-object invariant (the crux)

> **A component host has ONE TCB. A thread can be blocked in at most ONE `Call` at a time.
> Therefore ONE reply object per component is sufficient at ARBITRARY nesting depth.**

The nesting that today needs a 32-deep LIFO token stack needs **zero** bookkeeping under Call,
because the "stack" is the component's own C stack and the kernel's `bound_tcb` is the only
correlation state required. Trace of the observed depth-5 shape with a single reply object `R`
(the successor of `REPLY_W32`):

```
step  executive                                    component (win32k, one TCB)      R.bound_tcb
 0    (steady state)                               blocked in Call(DONE_prev)       win32k
 1    reply_on(R, req_outer)          ───────────▶ resumes, runs SSN               (cleared)
 2    recv_full_r12(ep, R)            ◀─────────── Call(W32_USER_CALLBACK)          win32k
 3    service_user_callback ⇒ Suspend
      pump RETURNS (outer outstanding)             still blocked in that Call       win32k   ✔
 4    client WndProc issues NtUser*
      reply_on(R, req_nested)         ───────────▶ rendezvous loop resumes,
                                                   runs the NESTED dispatch        (cleared)
 5    recv_full_r12(ep, R)            ◀─────────── Call(DONE_nested)                win32k
 6    nested pump returns completed                blocked in that Call             win32k   ✔
 7    NtCallbackReturn:
      reply_on(R, RESUME)             ───────────▶ rendezvous breaks; outer
                                                   dispatch finishes               (cleared)
 8    recv_full_r12(ep, R)            ◀─────────── Call(DONE_outer)                 win32k
```

At every instant exactly one binding exists, and it always names the level the executive is about to
talk to, **because the component physically cannot be anywhere else**. Steps 3 and 6 are exactly
"the executive holds the outer dispatch's reply cap across the callback and replies later" — which
is what reply objects are for.

Nested **page faults** interleave into the same sequence without any special case: a fault is a Call
from the same TCB, binds the same `R`, and is answered with `reply_on(R, len 0)` — literally what
`spawn_hosts.rs:909–916` already does today.

### 2.5 Why this also kills defects 1 and 3 by construction

* **Correlation (1, 2).** There is no "message that might be someone else's answer": the executive
  *replies to a specific blocked caller*, and the component *receives its request as the return
  value of its own Call*. A stale `done` cannot exist because the component cannot publish a second
  completion without first being replied to.
* **Availability (3).** The executive never `Send`s to an endpoint again. `reply_on` is
  `decode_reply`, which is non-blocking by construction: it either wakes the bound caller or returns
  `seL4_InvalidCapability`. The dangerous window (`send_done_on` → `recv_req_on`, where the
  component is runnable but not receiving) **does not exist**: after a Call the component is
  `BlockedOnReply` from the instant the kernel pairs it, with no user-visible gap.

---

## 3. The target design

### 3.1 Protocol (both substrates)

```
COMPONENT (one TCB, always the caller):
    loop {
        let (label, mr0..mr3) = call_on(CT_FAULT, DONE_LABEL | status);   // seL4_Call
        match label { DISPATCH => run(); RESUME => ...; }
    }

EXECUTIVE (always the server, one Reply object R per component):
    // invariant on entry to a "drive one request" pump: the component is blocked in a Call bound to R
    reply_on(R, request);                      // decode_reply — cannot block
    loop {
        let (badge, mi, m0..m3) = recv_full_r12(ep, R);   // rebinds R to the caller
        match mi >> 12 {
            DONE_LABEL      => break,                       // leave the component blocked (steady state)
            CALLBACK_LABEL  => { dispose(); }               // reply RESUME, or RETURN holding R
            6 /* VMFault */ => { demand_map(); reply_on(R, 0 /*len 0*/); }
            3 /* UserException, int-0x2c */
                            => { reply_on(R, len 1, ip+2); }
            _               => wall (see §5.5)
        }
    }
```

The shared frame keeps carrying the request/response payload exactly as today (`SH_REQ_*`,
`SH_REQ_STATUS_IRP 0x70` / `SH_REQ_STATUS_SYSCALL 0x78`). **Only the rendezvous changes**, not the
marshalling. The `dispatch_label` stays as the message label so the pump can still tell DONE from a
fault from a callback.

### 3.2 Who holds which reply object

| Object | Owner | Bound to | Lives across |
|---|---|---|---|
| `REPLY_MAIN` + `WAIT_REPLY_POOL[1..]` | executive main service loop | the hosted **client** thread (csrss/winlogon/…) whose syscall or fault is in flight | unchanged by this migration |
| `REPLY_W32` → **`R_win32k`** | executive | the win32k component TCB, in whatever Call it is currently blocked in (dispatch-done / callback / fault) | the whole nested tree |
| **new** `R_fsd[inst]`, one per FSD instance (npfs + `IrpFsdTest`) | executive | that FSD component TCB | one dispatch |

No pooling, no rotation, no stack. `MAX_REPLIES = 384`; we add exactly 2.

### 3.3 The IRP substrate (simple, non-nested)

* **`component_main`** (`spawn_hosts.rs:1115–1145`) becomes:
  ```
  let mut status = READY;                      // the post-DriverEntry ready signal
  loop {
      let (_label, _) = call_on(dispatch_label, status_msginfo);
      let sel = read(shared + SH_REQ_SEL);
      let (st, info) = dispatch(&DispatchReq { sel, drv });
      write(shared + SH_REQ_INFO, info);
      write(shared + status_off, st);
      status = /* nothing to carry — status is in the shared frame */;
  }
  ```
  `token`, `seq`, the `SH_REQ_SEQ` write and the injection block all disappear.

* **DriverEntry-init pump** (`driver_launch.rs:2216–2241`, `wake_first: false`): the component is
  mid-DriverEntry, i.e. a *blocked sender* (fault Call) or about to issue its ready Call. The pump
  therefore starts with `recv_full_r12(ep, R_fsd)` and never issues an initial reply — the
  `wake_first` flag is replaced by `initial: InitialAction::{ReplyRequest, RecvFirst}`. It ends when
  the ready `Call` arrives; the component is then left blocked (steady state) instead of racing to a
  `recv_req_on`.

* **Per-IRP pump** (`driver_launch.rs:2481–2516`): `initial: ReplyRequest`.

* `reply_recv_full` (legacy `reply_to`) disappears from the pump entirely; fault resumes become
  `reply_on(R_fsd, ...)`. This removes the FSD's last dependence on the single per-TCB `reply_to`.

### 3.4 The win32k Syscall substrate (re-entrant)

* **`s_ke_user_mode_callback_rendezvous`** (`win32k_subsystem.rs:2374`): `send_done_on(CALLBACK,0)` +
  the `recv_req_on()` loop collapse into
  ```
  let mut out = CALLBACK_LABEL;                 // first Call raises the callback
  loop {
      let (label, _) = call_on(CT_FAULT, out);
      match label {
          W32_USER_CALLBACK_RESUME_LABEL => break,
          W32_DISPATCH_LABEL => { run nested dispatch; out = W32_DISPATCH_LABEL; }
          _ => return STATUS_UNSUCCESSFUL,
      }
  }
  ```
  Note that the nested completion and the next Call are the **same** syscall — which is precisely
  what removes the nested phase slip.

* **Callback suspend** (`spawn_hosts.rs:781–808`, `win32k_glue.rs:728`): on `SuspendComponent` the
  pump breaks out **without replying**. `R_win32k` stays bound to the component's callback Call.
  This is the *only* piece of state that survives across the callback, and it is kernel state, not
  ours.

* **Callback resume** (`win32k_glue.rs:930–963` → `component_pump_resume_user_callback`): the
  channel becomes `initial: ReplyRequest` with the request being
  `W32_USER_CALLBACK_RESUME_LABEL` — i.e. `reply_on(R_win32k, RESUME<<12)`. The
  `resume_user_callback` special case in `component_pump_inner` (663–679) collapses into "the
  initial reply carries the RESUME label instead of the DISPATCH label".

* **Nested dispatch** (`win32k_glue.rs:2623–2660` re-entered from a redirected `WndProc`): also
  `initial: ReplyRequest`, replying `W32_DISPATCH_LABEL` onto the SAME `R_win32k` — which the
  component receives inside its rendezvous loop. No new reply object, no depth tracking.

* **win32k's bespoke DriverEntry-init loop** (`main.rs:10127–10190`) migrates onto the shared pump
  with `initial: RecvFirst` and `reply_cap: R_win32k`, deleting its `ep_recv_full` /
  `reply_recv_full` pair. (It should have been on the pump already; doing it here is required
  because after DriverEntry the component must end up blocked in a `Call`, not in a `Recv`.)

### 3.5 New/changed userspace ABI helpers

| Helper | Where | Note |
|---|---|---|
| `call_on(cptr, msginfo) -> (label, mr0..mr3)` | `driver_launch.rs` (component side) | `SYS_CALL` (= `-1`, `abi_layout_tests.rs:66`) on `CT_FAULT`; returns `rsi>>12` + `r10/r8/r9/r15` |
| `reply_on(reply_cptr, msginfo, r0..r3) -> u64` | `main.rs` | **SYS_CALL** variant of `send_on_reply` so the invocation error label is RETURNED. Per `tasks/lessons.md`: *"seL4 SYS_SEND invocations HIDE ALL errors — use SYS_CALL when a failure would be silent."* Replying to an unbound object is exactly such a failure. Kernel support already exists: `handle_send`'s `other =>` arm (`syscall_handler.rs:649–695`) routes a Call on a non-EP cap through `decode_invocation` → `decode_reply` and writes the error label into `rsi`. |
| `PumpChannel.initial: InitialAction` | `spawn_hosts.rs` | replaces `wake_first: bool` |
| `PumpChannel.reply_cap` | `spawn_hosts.rs:436` | becomes **mandatory** (non-zero); `HostCaps::nested_reply_cap` deleted |

---

## 4. Does rust-micro need work?

**No kernel change is REQUIRED.** Verified against the submodule at `f76be01`:

| Requirement | Kernel support | Evidence |
|---|---|---|
| `seL4_Call` on an endpoint from a component | yes | `syscall_handler.rs:97` `SysCall => handle_send(.., call: true, donate: true)`; `endpoint.rs:259` `if opts.do_call { finish_call(..) }`; deferred pair-up handled at `endpoint.rs:334–340` via `blocked_is_call` |
| Call on a cap without grant-reply rights | permitted (only `can_send` is checked, `syscall_handler.rs:611`) | our `CT_FAULT` is a plain `CNode_Copy` of the EP (`spawn_hosts.rs:232`) — full rights |
| Recv registering a reply object | yes | `syscall_handler.rs:743–756` reads r12 → `pending_reply`; `endpoint.rs:185–190` binds it |
| Reply that resumes a normal (non-fault) Call with a label + MRs | yes | `invocation.rs:1582` `deliver_message(invoker, caller, 0)`; `endpoint.rs:505–520` fans `mi`→rsi, MRs→r10/r8/r9/r15 |
| Reply that resumes a FAULT | yes | `invocation.rs:1553–1576` → `fault::apply_fault_reply` |
| Reply that returns an error label (so a mis-reply is loud) | yes | `syscall_handler.rs:649–695` (Call-on-invocation writes the label to rsi) |
| Long replies (>4 MRs, e.g. the len-18 syscall fault reply) | yes | `invocation.rs:1530–1543` reads MR4+ from the invoker's IPC buffer; `endpoint.rs:469–497` fans them out |
| Enough reply objects | yes | `kernel.rs:39` `MAX_REPLIES = 384`; we add 2 |
| Component TCBs are schedulable in their own right (no passive-server donation surprises) | yes | `spawn_hosts.rs:248` `attach_sched_context(tcb)`; `finish_call`'s donation arm only fires when the *callee* is passive |

### 4.1 Two OPTIONAL kernel improvements (scope them, do not block on them)

1. **True `seL4_ReplyRecv` (reply half honouring r12).** Today `SysReplyRecv`
   (`syscall_handler.rs:105–129`) replies via the **legacy `reply_to`** and only the Recv half reads
   r12. Upstream MCS `seL4_ReplyRecv(ep, mi, &badge, reply)` replies on the reply *object*. We do
   not need it — `send_on_reply` + `recv_full_r12` is the same thing in two syscalls, and that is
   already the shipping win32k path — but merging them would halve the syscall count on the hot
   dispatch path.
2. **Reject/diagnose rebinding an already-bound reply object.** `finish_call`
   (`endpoint.rs:188–190`) does `s.replies[ridx].bound_tcb = Some(sender)` unconditionally; if the
   executive ever Recvs with an `R` it still owes a reply on, the previous caller is silently
   orphaned. A debug-only counter or a `seL4_InvalidCapability` on rebind would turn a silent hang
   into a loud one. Relevant to the wall case (§5.5).

### 4.2 Conformance discipline if a kernel change IS made

`rust-micro` is built two ways: **with** `--features extern-rootserver` (this repo's kernel, `run.sh`
step 4) and **without** it (the sel4test conformance kernel, `rust-micro/README.md` §"Running the
sel4test conformance suite"). Any kernel edit MUST be `#[cfg(feature = "extern-rootserver")]`-gated
(or provably inert) so the sel4test kernel is **byte-identical**. Verification recipe:

1. Before the change: `cd rust-micro && ./scripts/build_kernel.sh` (no `extern-rootserver`) →
   `shasum` the kernel binary. Keep it.
2. After the change: rebuild the same way → `shasum` must match **exactly**. If it does not, the
   gating is wrong; fix the gating, do not rationalise the diff.
3. Independently, run the suite: `./vendor/sel4test/build.sh` + repack + boot → **170 pass**, and
   with `smp` + `MAX_NUM_NODES=4`, **MULTICORE 5/5**.
4. Only then rebuild the `extern-rootserver` kernel for userspace-ntos.

*(Lesson from `tasks/lessons.md`: `build_kernel.sh` silently leaves a STALE kernel if cargo fails —
verify the binary mtime is newer than the sources before trusting either shasum.)*

---

## 5. Phased migration

Every phase ends with a **foreground** boot (`./run.sh`), the gate line, and the paint check. No
background subagents, no concurrent git ops while QEMU runs (`feedback_verify_and_agent_hygiene`).
Each phase is one commit = one rollback point.

### Phase 0 — prerequisites (purely additive, wired to nothing) — **DONE (`d287c48`)**

Landed exactly as written (`call_on`, error-returning `reply_on`, `REPLY_FSD_SLOT[..]`,
`PumpChannel.initial`), plus the `MAX_DRIVER_INSTANCES` sizing noted above. Behaviour-neutral:
gate **231/99 ZERO FAILs**, RUNEXIT=3, paint 768/768, PASS list byte-identical to the baseline.


**Changes**
* Add `call_on` (component side, `driver_launch.rs`) and `reply_on` (executive side, `main.rs`).
* Retype two more `OBJ_REPLY` objects next to `REPLY_MAIN`/`REPLY_W32` (`main.rs:8252–8285`):
  `REPLY_FSD_SLOT[0..2]`. Assert each retype returned 0 and the slot is non-zero.
* Add `PumpChannel.initial: InitialAction` **alongside** `wake_first` (both present; `initial`
  derived from `wake_first` so behaviour is unchanged).
* NO kernel change.

**Must stay green:** everything — this phase is behaviour-neutral. Gate **231/99**, paint
`768/768 @ 0x003a6ea5`.

**Rollback:** trivial (revert the commit).

**Proof it is neutral:** the new helpers have zero call sites; `initial` is unread. Grep-verify:
`call_on|reply_on|InitialAction` appear only in their definitions plus the derivation.

---

### Phase 1 — convert the IRP substrate (npfs / FSD) — **DONE**

Landed as planned, with the three corrections above. Result: gate **231/99 ZERO FAILs**
(`exec_component_dispatch_in_phase` deleted, `exec_irp_transport_call_bound` added), RUNEXIT=3,
`microtest sentinel`, paint **768/768 @ `0x003a6ea5`**, three consecutive boots with identical PASS
lists. Measured: 71 IRP dispatches, all 71 completed as the return of the component's own `Call`;
69 request replies (the 2-dispatch shortfall is the two `RecvFirst` DriverEntry-init pumps, whose
ready `Call` *is* the completion); **0 reply errors**; 0 wall-suspends; unbound-probe label 2.

**R2 (walls)** was handled with option (a) as the plan directed: `TCB_Suspend` on a wall, plus
`register_instance_ready(inst, false)` so a walled driver is retired and never pumped again (its
reply object stays bound to a thread that will never run — which is safe precisely because nothing
will ever reply on it). Zero walls occur on a green boot, so this path is defensive.

**`Transport::{Legacy, Call}`** is the temporary parameter R1 called for. It is threaded through
exactly two places — `component_main`'s dispatch loop and `PumpChannel` — and every win32k site
passes `Legacy`. Phase 2 deletes the enum and both arms.


Chosen first because it is non-nested, has two independent instances, and is protected by
`exec_npfs_concurrent_irp_read_and_write`, `exec_npfs_file_object_lifetime`,
`exec_npfs_write_split_across_pending_read`, `exec_npfs_flush_pending`,
`exec_fsd_on_shared_harness`, and `exec_second_irp_driver_via_harness`.

**Changes**
1. `component_main` (`spawn_hosts.rs:1115–1145`): `send_done_on` + `recv_req_on` → one `call_on`.
   Drop `token`, `seq`, the `SH_REQ_SEQ` write and the `PUMP_SLIP_INJECT` block.
   *(This is shared code — win32k's `component_main` changes here too. That is fine and intended:
   win32k's OUTER loop has the same shape. Its RENDEZVOUS loop is Phase 2.)*
2. `component_pump_inner`: for `kind == Irp`, `initial: ReplyRequest` ⇒
   `reply_on(R_fsd, dispatch_label<<12)`; fault resume ⇒ `reply_on(R_fsd, 0)` (replacing
   `reply_recv_full`); receive ⇒ `recv_full_r12(ep, R_fsd)`.
3. `driver_launch.rs:2216–2241` init pump ⇒ `initial: RecvFirst`, `reply_cap: R_fsd[inst]`.
   `driver_launch.rs:2481–2516` per-IRP pump ⇒ `initial: ReplyRequest`, `reply_cap: R_fsd[inst]`.
4. Delete the `seq_handshake` arm (`spawn_hosts.rs:702–716, 731–752`) and
   `FSD_DISPATCH_SEQ_HANDSHAKE`.
5. Replace `exec_component_dispatch_in_phase` with **`exec_irp_transport_call_bound`**, a spec that
   proves the *real* transport rather than the workaround:
   * counter `PUMP_REPLY_ERRORS` — every `reply_on` return label recorded; must be **0** across the
     whole boot (a non-zero value means we replied to an unbound object, i.e. an invariant break);
   * counter `PUMP_CALL_DISPATCHES` — dispatches whose completion arrived as the return of the
     component's own Call; must equal `HARNESS_IRP_DISPATCHES`;
   * **negative proof (the bypass experiment's successor):** an injected `reply_on(R_fsd, …)` issued
     when the component is *known runnable* (i.e. `R_fsd` unbound) must return
     `seL4_InvalidCapability` (6) *without blocking*, and the boot must continue. That is the
     structural statement "the wake cannot block" — the exact property defect 3 lacks.

**Must stay green:** all five npfs specs, `exec_fsd_on_shared_harness` (≥8),
`exec_second_irp_driver_via_harness`, `exec_kebugcheck_bound_and_reported`, the desktop paint, gate
count (231 − `exec_component_dispatch_in_phase` + `exec_irp_transport_call_bound` = 231).

**Expected mid-phase breakage:** win32k, because step 1 changes shared `component_main` while
win32k's rendezvous still speaks the old protocol. **Mitigation:** do steps 1+2 and the win32k
rendezvous conversion (Phase 2 step 1) in one working tree, but land the *commit boundary* only when
both are green. If that proves awkward, invert: give `component_main` a
`transport: Transport::{Legacy, Call}` parameter for the duration of Phase 1 and delete it in
Phase 2. **Prefer the temporary parameter** — it keeps every phase independently green, which is the
stated constraint.

**Rollback:** the Phase-0 commit.

---

### Phase 2 — convert the win32k Syscall substrate (the crux)

**Changes**
1. `s_ke_user_mode_callback_rendezvous` (`win32k_subsystem.rs:2374–2470`): the
   `send_done_on(CALLBACK,0)` + `recv_req_on()` loop → the `call_on` loop of §3.4. Delete the
   `W32_SLIP_INJECT` block (2450–2456).
2. `component_pump_inner`:
   * the callback arm (781–808): `ReplyImmediately` ⇒ `reply_on(R_w32, RESUME<<12)` +
     `recv_full_r12`; `SuspendComponent` ⇒ break **without replying** (R stays bound).
   * `component_pump_resume_user_callback` (620–679): becomes
     `initial: ReplyRequest { label: W32_USER_CALLBACK_RESUME_LABEL }`; the bespoke resume preamble
     and its `use_reply_cap` guard disappear.
   * the assert-skip arm (926–954) and the demand-fault arm (907–924) already use
     `send_on_reply`/`recv_full_r12` — switch `send_on_reply` → `reply_on` and check the label.
3. `main.rs:10127–10190`: win32k's bespoke DriverEntry-init loop → `component_pump` with
   `initial: RecvFirst`.
4. Delete the token machinery (`spawn_hosts.rs:534–588`, 656–658, 753–778, 976–982) and
   `W32_DISPATCH_TOKEN_BINDING`.
5. Delete `HostCaps::nested_reply_cap` and the `use_reply_cap` branching (635, 717–721, 741–745,
   767–771, 909–924) — there is now exactly ONE transport.
6. Replace `exec_win32k_dispatch_in_phase_nested` with **`exec_win32k_transport_call_nested`**,
   reusing the SAME real scenario (`inject_win32k_nested_dispatch_slip`, post-quiesce, expendable
   winlogon RPC worker, `WM_NULL`) but asserting the new invariants:
   * the five *behavioural* proof bits survive unchanged — parked / redirected / nested-matched /
     outer-resumed / drained-idle (`NESTED_SLIP_REJECTED` has no meaning any more: a stale
     completion is **unrepresentable**, so it is replaced by…);
   * `R_w32` remained bound to the component for the whole suspension (sampled before and after the
     client redirect) — i.e. the outer dispatch's reply really did survive the callback;
   * measured nesting high-water ≥ 2 via a *dispatch-depth* counter kept for observability only
     (not for correlation);
   * `PUMP_REPLY_ERRORS == 0`.

**Must stay green:** `exec_win32k_desktop_painted` (**768/768 @ `0x003a6ea5`** — non-negotiable),
`exec_win32k_on_shared_harness` (≥4), `win32k_dispatch_fault_via_reply_cap`,
`exec_user_callback_*` (both), `exec_user_callback_dead_client_unwind`, all 7 `exec_msgina_*`, all
5 `exec_lsa_*`, all 21 `exec_dbgk_*`, `exec_win32k_load_contract`.

**Rollback:** the Phase-1 commit.

---

### Phase 3 — DELETE the hand-rolled machinery

Pure deletion + spec cleanup (see §7 for the kill-list). Nothing new is written except the two
replacement specs already landed in Phases 1–2.

**Must stay green:** the whole gate, unchanged count, PASS-list `diff`-identical to Phase 2 modulo
the removed/renamed spec names. Three consecutive foreground boots with identical PASS lists
(the established verification bar).

**Rollback:** the Phase-2 commit.

---

### Phase 4 — re-enable `LSA_WORKER_ROUTE_ENABLED`

Flip `exec_handler.rs:7062` to `true` and boot. The expectation, stated as a falsifiable
prediction rather than a hope: the route previously died on a wake `Send` that never returned, at a
point where correlation was already measured clean (zero token mismatches, zero pump walls, callback
plane drained to depth 0). With the wake replaced by a non-blocking `reply_on`, that specific wall
cannot recur.

**Watch for:** `LsaOpenPolicy` returning → `SampGetAccountDomainInfo` / `SampInitDatabase` →
`SamIConnect` → `Administrator` validated → `WLX_SAS_ACTION_LOGON`.

**If it stops somewhere else** — record exactly where, do **not** fabricate progress, and leave the
switch `false` with the new evidence written down (that is what `1141349` and `7d0703b` did, and it
is why this migration is well-targeted).

**Must stay green:** the paint and the full gate must survive with the route ON. If a
timing-perturbed run loses the paint (as it did at `1141349`), the route goes back off and Phase 4
becomes its own follow-up batch — Phases 0–3 stand on their own merits.

---

## 6. Risk register

| # | Risk | Why it matters | Mitigation / what to verify |
|---|---|---|---|
| R1 | **`component_main` is shared** — changing it breaks BOTH substrates at once. | The paint is downstream of win32k. | Temporary `Transport::{Legacy, Call}` parameter so Phase 1 lands green (see Phase 1 note), deleted in Phase 2. |
| R2 | **Wall handling leaves `R` bound to a fault-blocked component.** The next pump's first act is `reply_on(R, request)`, which the kernel would deliver as a **fault reply** (`decode_reply` branches on `pending_fault`, `invocation.rs:1553`), resuming the component at the faulting instruction with a request it never asked for. | Silent corruption where today the component just stays stuck. | On a wall, explicitly `reply_on(R, label≠0)` to force `restart == false` → `block(caller, Inactive)`. **CAVEAT:** `apply_fault_reply` returns `true` unconditionally for VMFault(6) and CapFault(1) (`fault.rs:400–403`), so a VMFault-walled component **cannot** be parked via the reply — it will restart and re-fault. Options: (a) `TCB_Suspend` the component on a wall; (b) mark the channel dead and never pump it again; (c) the optional kernel change §4.1.2. **Decide (a) — it uses an existing invocation and is honest.** |
| R3 | **Reply-object rebinding is silent** (`endpoint.rs:188`). If the executive Recvs on `R` while still owing a reply, the previous caller is orphaned with no diagnostic. | Turns an invariant break into a hang. | `reply_on` returns the error label (§3.5); add `PUMP_REPLY_ERRORS`, asserted **0** by both new specs. Consider §4.1.2. |
| R4 | **Fault-reply shapes differ per fault type.** Measured from the code, and one item in the brief needs correcting: **UserException(3)** → reply len **3**, MR0=FaultIP, MR1=SP, MR2=FLAGS (`fault.rs:342–347`; e.g. `rendezvous.rs:595`). **VMFault(6)** → len 0, restart unconditional (`fault.rs:400–403`). **UnknownSyscall(2)** → reply len **18**; the resume IP is **MR15**, SP=MR16, FLAGS=MR17 (`fault.rs:316–338`; `rendezvous.rs:808–811`, `set_reply_mr(15/16/17)`). The **RCX/MR2** the brief mentions is on the **incoming** side: an UnknownSyscall fault message delivers RCX (the `syscall`-saved return address) in **MR2**, which is where the executive reads `resume_ip` (`service_sec_image.rs:2408`, `rendezvous.rs:612`, `main.rs:7715`). | Getting the length wrong resumes a thread with garbage RIP/RSP. | The component pump only ever emits len 0 (VMFault) and len 1 (int-0x2c UserException, `spawn_hosts.rs:946`) — both already correct today. **The migration must not touch the len-18 client-syscall replies at all**; they are on `REPLY_MAIN`, a different plane. Grep-assert that no `reply_on` on `R_fsd`/`R_w32` uses length > 3. |
| R5 | **`REPLY_W32` interaction.** `REPLY_W32` is today a *strictly gated* second transport (`nested_reply_cap`) that must never merge with the FSD path (`docs/component-harness.md:378`). Phase 2 deliberately merges them. | The historical bug this gating prevents is "win32k never runs". | The merge is safe **only because both sides become Call-based**. Verify with `win32k_dispatch_fault_via_reply_cap` (the SSN_TEST_FAULT nested-reply proof) and the paint, and keep `R_w32` and `R_fsd` as **distinct objects** — merging the *transport shape* is not merging the *objects*. |
| R6 | **Callback suspend/resume ordering.** `SuspendComponent` returns from the pump holding `R`; three different call sites later resume (`win32k_glue.rs:993` normal, `1164` dead-client unwind, `1889` cancel). If any path returns without ever resuming, the component is wedged forever with `R` bound. | Silent wedge, exactly the class we are removing. | Add a `SUSPENDED_COMPONENT_OUTSTANDING` counter incremented on suspend, decremented on resume; assert it is **0** at the quiesce point in the new `exec_win32k_transport_call_nested`. This is strictly stronger than today's `NESTED_SLIP_DRAINED_IDLE`. |
| R7 | **Dead-client unwind + blocked-reporter release steal reply objects.** `wait_park` / `pipe_wait_park` / `dbgk_reporter_park` / `io_completion_park` steal `REPLY_MAIN` and rotate a spare in (`main.rs:4186, 4431, 4572`; `service_sec_image.rs:9428, 9567, 9971`). | If `R_w32`/`R_fsd` were ever drawn from that pool, a park would steal the component's binding. | **They must NOT be**: `R_w32`/`R_fsd` are dedicated, never entered into `WAIT_REPLY_POOL`, never rotated. Grep-assert `WAIT_REPLY_POOL` is written only at `main.rs:8265–8276`. |
| R8 | **Reply-object exhaustion under nesting.** | The stated worry against `Call`. | **Structurally impossible**: one TCB ⇒ at most one outstanding Call ⇒ one object per component regardless of depth (§2.4). Total new objects: **2**. `MAX_REPLIES = 384`. The 32-deep `DISPATCH_TOKEN_STACK` and its overflow-fails-safe path are deleted with nothing replacing them. |
| R9 | **SC donation semantics change?** `finish_call` donates the caller's SC when the callee is passive (`endpoint.rs:191–203`). | Could alter scheduling and thus timing-sensitive paint. | The component→executive direction is unchanged (that is already how faults arrive), and both sides have their own SC (`spawn_hosts.rs:248` `attach_sched_context`; the executive is the rootserver). The `active_sc` charge attribution arm applies today too. **No change expected — but a timing-perturbed boot is a required check** because the paint has been lost to timing before (`1141349`). |
| R10 | **The `assert_skip` (int-0x2c) arm depends on `ch.reply_cap != 0`** (`spawn_hosts.rs:935`). Making `reply_cap` mandatory changes when this arm is reachable for the FSD. | An FSD int-0x2c would newly be skipped rather than walled. | Keep the arm gated on `caps.assert_skip` (win32k only), NOT on `reply_cap != 0`. Explicitly re-read 926–963 during Phase 2. |
| R11 | **`ep_recv_full` has non-pump users** (`main.rs:7683, 7887, 7904` — hosted-thread fault loops; `driver-host-ntdll/src/main.rs:355, 631`). | Deleting it breaks unrelated planes. | It is **not** on the kill-list; only its pump call sites go. Same for `reply_recv_full` (`main.rs:7697, 7864, 7930` survive) and `reply_recv_badge` (untouched). |
| R12 | **The component may Call while the executive is not receiving.** | Would queue the component as a blocked sender — recoverable, but a latency surprise. | By construction the component only Calls in response to a reply the executive just sent, and the executive immediately Recvs. The one exception is the post-DriverEntry ready Call, which the `RecvFirst` init pump is already waiting for. |
| R13 | **Cannot determine from code:** whether the LSA route's failure is *solely* the wake `Send`. The evidence (909 RIP samples) strongly implicates it, but the route also perturbs timing enough to lose the paint in one run. | Phase 4 may not close. | Phase 4 is explicitly separable; Phases 0–3 are justified by defects 1+2 alone (they delete two workarounds and a whole correlation plane). Do not claim the logon chain resumed unless the serial shows it. |
| R14 | **Cannot determine from code:** whether any hosted binary observes `SH_REQ_SEQ`. | Deleting it could break a reader. | Grep before deleting: `SH_REQ_SEQ` appears at `spawn_hosts.rs:102, 703, 732, 1143` and `win32k_subsystem.rs:187`. All executive-side. No ReactOS binary reads it (it is our own frame layout). Re-verify at Phase 3. |

---

## 7. Kill-list — what gets deleted (the checkable outcome)

**34 items.** After Phase 3, `grep` for each of these must return **zero** hits outside this document.

### Executive IPC helpers (`components/ntos-executive/src/main.rs`)
1. `ep_send` (3855)
2. `ep_send_token` (3871)
3. `send_on_reply` (3995) — *renamed/replaced by* `reply_on` (error-returning). Delete the
   error-swallowing form.

### Component IPC helpers (`components/ntos-executive/src/driver_launch.rs`)
4. `send_done_on` (1563)
5. `recv_req_on` (1580)

### Sequence handshake (defect 1)
6. `SH_REQ_SEQ` (`spawn_hosts.rs:102`)
7. `SH_REQ_SEQ` (`win32k_subsystem.rs:187`)
8. `seq_before` sample + `seq_handshake` gate (`spawn_hosts.rs:702–716`)
9. stale-`done` re-wait arm (`spawn_hosts.rs:731–752`)
10. `PUMP_STALE_DONES` (`spawn_hosts.rs:1152`)
11. `PUMP_SLIP_INJECT` (`spawn_hosts.rs:1155`)
12. the `seq` variable + `SH_REQ_SEQ` write in `component_main` (`spawn_hosts.rs:1118, 1142–1143`)
13. the slip-injection block in `component_main` (`spawn_hosts.rs:1131–1133`)
14. `FSD_DISPATCH_SEQ_HANDSHAKE` (`main.rs:773`) + its uses (10820, 12185)

### Token binding (defect 2)
15. `DISPATCH_TOKEN_NEXT` (`spawn_hosts.rs:534`)
16. `DISPATCH_TOKEN_STACK_MAX` (539)
17. `DISPATCH_TOKEN_STACK` (540)
18. `DISPATCH_TOKEN_DEPTH` (541)
19. `DISPATCH_TOKEN_MAX_DEPTH` (543)
20. `PUMP_TOKEN_MISMATCHES` (546)
21. `dispatch_token_push` (548)
22. `dispatch_token_top` (562)
23. `dispatch_token_pop` (569)
24. `dispatch_token_depth` (579)
25. `suspended_dispatch_token` (586)
26. the `expected_token` / `nesting` / `owns_token_stack_top` / `token_binding` block
    (`spawn_hosts.rs:642–658`) + the token-mismatch arm (753–778) + the retire (976–982)
27. the `token` variable in `component_main` (`spawn_hosts.rs:1119, 1121–1123, 1132`)
28. `W32_SLIP_INJECT` + `W32_SLIP_INJECT_TOKEN` (`spawn_hosts.rs:1163–1165`) and the injection block
    in the rendezvous (`win32k_subsystem.rs:2450–2456`)
29. `W32_DISPATCH_TOKEN_BINDING` (`main.rs:782`) + its uses (`spawn_hosts.rs:658`, `main.rs:12310–12333`)

### Dual-transport scaffolding
30. `HostCaps::nested_reply_cap` (`spawn_hosts.rs:129`) + `use_reply_cap` and every
    `if use_reply_cap { … } else { … }` fork (`spawn_hosts.rs:635, 717–721, 741–745, 767–771, 909–924`)
31. `PumpChannel.wake_first` (`spawn_hosts.rs:433`) — replaced by `initial: InitialAction`
32. `component_pump_resume_user_callback`'s bespoke preamble (`spawn_hosts.rs:663–679`) — folds into
    `initial: ReplyRequest { label: RESUME }`
33. win32k's bespoke DriverEntry-init loop (`main.rs:10127–10190`) — folds onto `component_pump`

### Specs that only tested the workarounds (replaced, not dropped)
34. `exec_component_dispatch_in_phase` (`main.rs:10819`) → **`exec_irp_transport_call_bound`**;
    `exec_win32k_dispatch_in_phase_nested` (`main.rs:12326`) + `NESTED_SLIP_REJECTED`
    (`win32k_glue.rs:1291`) → **`exec_win32k_transport_call_nested`**. The injector
    `inject_win32k_nested_dispatch_slip` (`win32k_glue.rs:1335`) is **kept** — the *scenario* (real
    parked callback, real client redirect, real nested dispatch) is still exactly the right test; only
    the "publish a stale `done`" step becomes unrepresentable and is replaced by the
    reply-binding assertions of §5/Phase 2.

**Net:** two correlation planes, one 32-deep stack, two bypass switches, two fault injectors, one
duplicated transport fork and one bespoke init loop are removed; **one** primitive
(`Call` ⇄ reply-object) replaces them.

---

## 8. Verification bar (every phase)

1. `cargo build` clean for the executive **and** every host crate test suite that the touched crates
   own (`nt-user-callback`, `nt-io-manager`, `nt-process`, `nt-ntdll`, …) — unchanged counts.
2. **One foreground boot per check**, `timeout 600000`, no `&`, no until-loop wrappers, no
   concurrent git/QEMU (`feedback_verify_and_agent_hygiene`).
3. Gate line + `RUNEXIT=3` + `microtest sentinel matched`.
4. `exec_win32k_desktop_painted` = **768/768 @ `0x003a6ea5`**.
5. **Three consecutive boots** with `diff`-identical PASS lists at the end of Phases 1, 2 and 3.
6. A **positive proof** for each phase, not just green: the new counters
   (`PUMP_REPLY_ERRORS == 0`, `PUMP_CALL_DISPATCHES == HARNESS_*_DISPATCHES`,
   `SUSPENDED_COMPONENT_OUTSTANDING == 0`) plus the call-site grep showing the deleted symbols are
   gone — because a byte-identical-looking refactor needs a counter-backed spec, not just a green
   gate.
7. If any kernel change lands: the §4.2 byte-identical sel4test recipe.
