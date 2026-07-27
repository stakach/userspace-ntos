# Component-Dispatch Transport Migration — hand-rolled Send/Recv → seL4 `Call` + MCS reply objects

**Status:** **ALL PHASES (0-5) DONE** (gate **236/99 ZERO FAILs**, RUNEXIT=3, paint 768/768 @
`0x003a6ea5`, **six consecutive boots**). **There is now exactly ONE dispatch transport — seL4
`Call` ⇄ MCS reply objects, on BOTH substrates — and exactly ONE reply mechanism anywhere in the
executive: `Cap::Reply`.** The 34-item kill-list is EXHAUSTED (§7); the legacy per-TCB `reply_to`
reply is retired.
Phase 4 CONFIRMED the migration's falsifiable prediction — the availability defect that gated the
LSA worker route is structurally gone. **Phase 5 landed the route: `LSA_WORKER_ROUTE_ENABLED` and
`PIPE_FULL_DUPLEX_PARK` are both ON permanently**, after root-causing the last thing that kept them
off, which turned out to be neither scheduling nor the RPC but an **HPET interrupt storm in the
executive's own delay timer** (§Phase 5).
Baseline `1141349` → Phase 0 `d287c48` → Phase 1 `01d0423` → Phase 2 `cc46342` → Phase 3a `e49e8b0`
→ Phase 3b `c587b8f` → Phase 4 `fae8bdc` → Phase 5.

> ### ★ WHAT THE PLAN GOT WRONG — corrections 1-3 found in Phase 1, 4-6 in Phase 2
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
> 4. **★ `client_attach` was hiding a SECOND, unrelated property: PAGE-TABLE DEPTH.** §3.4 step 3
>    says win32k's DriverEntry-init loop "migrates onto the shared pump", full stop. But the pump
>    picks its demand-fault paging by `caps.client_attach`: true ⇒ `ensure_w32_client_paging`
>    (builds PDPT→PD→PT), false ⇒ `driver_launch::ensure_paging` (a PT only, assuming the PDPT/PD
>    already exist). win32k's init needs the DEEP walk (its windows straddle several 512 GiB / 1 GiB
>    regions) but must NOT do client-frame sharing (there is no client yet, and `client_pi = 0` is a
>    REAL client — smss — so it cannot double as a sentinel). Setting `client_attach: true` there
>    would have let a low-VA init fault map **smss's** frame into win32k. Fix: split the two ideas —
>    a new `HostCaps::sparse_vspace` selects the paging discipline, `client_attach` keeps meaning
>    only "share the client's frames". Net flag count unchanged (`nested_reply_cap` deleted).
>
> 5. **`SH_REQ_SEQ` had two readers the kill-list did not name** (R14 said "all executive-side", which
>    is true but incomplete): `win32k_dispatch_loop_roundtrip` and `win32k_dispatch_fault_via_reply_cap`
>    (`main.rs`) both asserted `seq >= 1` as their evidence that the dispatch loop really ran. They now
>    read `pump_call_dispatches(ReqKind::Syscall)` — the KERNEL-attested count of completions that
>    arrived as the return value of win32k's own `Call`, which is strictly stronger than a counter the
>    component wrote into a shared page.
>
> 6. **`PUMP_CALL_REQUESTS`/`PUMP_CALL_DISPATCHES` had to become PER-KIND.** `exec_irp_transport_call_bound`
>    asserts `call_dispatches == HARNESS_IRP_DISPATCHES`; the moment win32k joined the transport a single
>    global counter broke that equality. Both are now `[AtomicU64; 2]` indexed by `ReqKind`, read through
>    `pump_call_requests(kind)` / `pump_call_dispatches(kind)`, and BOTH specs now assert the equality
>    for their own substrate.
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
| 3 | **Availability.** The executive's wake `Send` blocks against a component that is not receiving. RIP-sampled over 909 wakes: 907 at the component's completion-`Send`+2, 3 at the receive syscall, and the ONE wake that never completes is the only sample at that receive+2. | **the wake `Send` NO LONGER EXISTS** — the executive answers with `reply_on` (`decode_reply`), which cannot block. Whether that closes the LSA route is Phase 4's falsifiable prediction, not a claim. | mechanism removed (Phases 1-2); route still `false` |

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

### Phase 2 — convert the win32k Syscall substrate (the crux) — **DONE**

Landed as planned, plus corrections 4-6 above. Result: gate **231/99 ZERO FAILs**
(`exec_win32k_dispatch_in_phase_nested` deleted, `exec_win32k_transport_call_nested` added — net 0),
RUNEXIT=3, `microtest sentinel`, paint **768/768 @ `0x003a6ea5`**, three consecutive boots with
`diff`-identical PASS lists.

**Measured on a green boot:** 2557 win32k dispatches, **all 2557** completed as the return of the
component's own `Call`; 2829 request replies (dispatches + callback RESUMEs); **0 reply errors**;
**live nesting high-water 5**; suspended-outstanding **0** at quiesce; **0** walls. The IRP substrate
is unchanged at 71/71 with 0 reply errors.

**What the code looks like now**

* `component_main`'s loop is ONE `call_on` and nothing else. `Transport::{Legacy, Call}` and the
  whole legacy arm are gone.
* `s_ke_user_mode_callback_rendezvous` is the `call_on` loop of §3.4: the first Call raises the
  callback, each subsequent Call publishes a nested completion AND receives the next request, and it
  breaks on the RESUME **MR0 tag** (correction 1 — it cannot be a label).
* `component_pump_inner` has exactly one shape. `initial: ReplyRequest` ⇒ one `reply_on`; the request
  tag is `dispatch_label`, or `W32_USER_CALLBACK_RESUME_LABEL` when the pump is a resume — which is
  the entirety of what `component_pump_resume_user_callback`'s bespoke preamble used to be.
* **Callback suspend = return without replying.** `R_win32k` stays bound to win32k's callback `Call`
  across the client redirect, every nested dispatch, and the `NtCallbackReturn`. That kernel binding
  IS the suspended-dispatch state; we keep none.
* win32k's bespoke DriverEntry-init loop (`main.rs`) is gone — it is a `RecvFirst` pump on
  `R_win32k`, so after DriverEntry win32k ends up BLOCKED IN A `Call` (the steady state every later
  dispatch answers) instead of parked in a bare `Recv`.

**The `reply_to` clobber (correction 2): the legacy path was KEPT, deliberately.** The brief invited
retiring it early. It is not needed and it is not free:

* the guard is **already sound, not an approximation that needs widening**. `reply_to` can only be
  clobbered by a message the executive RECEIVES, every component message is received in
  `pump_recv`, and `pump_recv` unconditionally sets `COMPONENT_CALL_CLOBBERED_REPLY_TO`. There is no
  longer a `transport == Call` condition on that store — with one transport, the flag is set on
  every component recv, so the main loop's fast path is taken only when no component spoke at all
  during that syscall;
* retiring it turns every non-routed client-syscall reply from ONE `SysReplyRecv` into TWO syscalls
  (`send_on_reply` + `recv_full_r12`) on the hottest path in the boot. The paint has been lost to
  timing perturbation before (`1141349`), and Phase 2 already perturbs win32k's whole rendezvous.
  Doing both in one batch would make a lost paint un-attributable.

So it stays for Phase 3, which is a pure-deletion batch with no other moving parts — the right place
to take a measurable timing change.

**R2 (walls)** — win32k's equivalent of Phase 1's instance retirement is `win32k_glue::WIN32K_RETIRED`:
the pump `TCB_Suspend`s the component, `retire_win32k_on_wall` latches the flag, and
`win32k_dispatch_wide` refuses every later dispatch, so nothing can ever `reply_on` a binding held by
a thread that will never run again. Zero walls occur on a green boot (the gate asserts `walled == 0`),
so this path is defensive.

**R6 (three resume sites)** — all three (`win32k_glue.rs` normal `NtCallbackReturn`, dead-client
unwind, cancel) funnel through the single `resume_suspended_user_callback_component`, so converting
that ONE function converted all three. `SUSPENDED_COMPONENT_OUTSTANDING` (incremented on suspend,
decremented on resume) is asserted **0** at quiesce.

**The new spec: `exec_win32k_transport_call_nested`.** It reuses the SAME real scenario
(`inject_win32k_nested_dispatch_slip` — post-quiesce, expendable winlogon RPC worker, `WM_NULL`) and
asserts: `PUMP_REPLY_ERRORS == 0`, call-bound completions == `HARNESS_SYSCALL_DISPATCHES` (2557/2557),
requests >= 4, nesting high-water >= 2, suspended-outstanding == 0, not walled, and all six
`NESTED_SLIP_*` bits. `NESTED_SLIP_REJECTED` is replaced by **`NESTED_SLIP_R_HELD`**: the reply object
stayed outstanding across the client redirect (sampled before and after), which is the property that
used to require a token stack. `NESTED_SLIP_MATCHED` additionally requires
`dispatch_depth() >= 1` at the instant the nested dispatch is issued — the DIRECT measurement that
the nested level really was nested, since the boot-wide high-water (5) is reached long before.

**Bypass vs negative control.** There is no bypass switch and there cannot be one:
`W32_DISPATCH_TOKEN_BINDING` was flippable because the binding was OUR code, whereas "a stale
completion is unrepresentable" is structural — there is no mechanism left to disable, only the
kernel's `bound_tcb`. The honest substitute is the same NEGATIVE CONTROL Phase 1 used, which
falsifies the kernel-level premise rather than a flag of ours: `reply_on` on a known-unbound object
returns `seL4_InvalidCapability` (**2**) immediately and without blocking (measured every boot by
`exec_irp_transport_call_bound`). If that were false, "label 0" would mean nothing and the
executive's answer could block — the two properties the whole migration buys.

**Changes (as executed)**
1. `s_ke_user_mode_callback_rendezvous` → the `call_on` loop; `W32_SLIP_INJECT` block deleted.
2. `component_pump_inner`: one transport, MR0 request tag, callback arm replies RESUME via
   `pump_resume_recv`, suspend = no reply, `pump_recv`/`pump_resume_recv` lost their
   `call_transport`/`use_reply_cap` parameters.
3. `main.rs` win32k DriverEntry-init loop → `component_pump` with `initial: RecvFirst`.
4. Deleted: the token machinery (`DISPATCH_TOKEN_NEXT/_STACK/_DEPTH/_MAX_DEPTH`, `PUMP_TOKEN_MISMATCHES`,
   `dispatch_token_push/_top/_pop/_depth`, `suspended_dispatch_token`), `W32_SLIP_INJECT(_TOKEN)`,
   `W32_DISPATCH_TOKEN_BINDING`, `Transport` + both arms, `PumpChannel::wake_first`,
   `HostCaps::nested_reply_cap`, `SH_REQ_SEQ` (both copies), `send_done_on`, `recv_req_on`, `ep_send`,
   `ep_send_token`.
5. Added: `HostCaps::sparse_vspace` (correction 4), `PUMP_DISPATCH_DEPTH`/`PUMP_MAX_DISPATCH_DEPTH`/
   `SUSPENDED_COMPONENT_OUTSTANDING` (observability only), `WIN32K_RETIRED` (R2).

**Rollback:** the Phase-1 commit.

---

### Phase 3 — DELETE the hand-rolled machinery — **DONE** (two commits)

Landed in two commits so the one TIMING change in the batch is independently attributable and
independently revertable.

#### 3a (`e49e8b0`) — retire the legacy `reply_to` reply

Phase 2 kept it deliberately (see the reasoning at the end of Phase 2). Phase 3 took it, alone:

* `main.rs::reply_recv_badge` — the main service loop's ONE-syscall `SYS_REPLY_RECV`, whose reply
  half targets `current.reply_to` — becomes `client_reply_on` + `recv_full_r12` on the object the
  kernel BOUND to this caller. A pre-retype fallback (cptr 0, the demo/no-ntdll path, where the
  reply objects do not exist yet) keeps the legacy syscall; nothing on the live boot reaches it.
* The main loop's four-way reply fork COLLAPSES. `routed_win32k`, `routed_lpc`, `routed_csr` and
  `spawn_hosts::COMPONENT_CALL_CLOBBERED_REPLY_TO` are DELETED — all four existed only to ask "has
  a component `Call` re-pointed `reply_to` since this caller's recv?", and the answer no longer
  matters because no reply reads `reply_to`.
* New spec **`exec_client_reply_bound`** (231 → 232/99): `CLIENT_REPLY_BOUND` client replies through
  a bound reply object with `CLIENT_REPLY_ERRORS == 0`, plus the same unbound-reply negative control
  (label **2**, non-blocking) that makes a 0 label non-vacuous.

**★ THE TIMING QUESTION, ANSWERED WITH DATA.** The stated worry was that turning one `SysReplyRecv`
into two syscalls on the hottest path in the boot would perturb timing enough to lose the paint (as
`1141349` once did). It does not. Boot wall-clock, same host, same image pipeline:

| build | boots | wall time |
|---|---|---|
| baseline `cc46342` (legacy reply live) | 1 | **299 s** |
| Phase 3a (legacy reply retired) | 3 | **297 s / 311 s / 304 s** |

Within run-to-run noise, and every counter is bit-identical across boots (9281 bound client replies
on 3a, 9619 after 3b folds the remaining sites in; IRP 71/71; win32k 2557/2557; nesting high-water
5). The legacy path is KEPT ONLY as the pre-retype fallback; it is not reachable on the live boot.

#### 3b — fold `send_on_reply` into `reply_on`, and the prose sweep

* Kill-list item 3, the last of the 34. All **36** `send_on_reply` call sites (22 in `rendezvous.rs`,
  6 in `service_sec_image.rs`, 8 in `main.rs`) now go through `client_reply_on`, the error-counting
  wrapper over the error-RETURNING `reply_on`. The `SYS_SEND` form — which *silently swallowed*
  every invocation error — is deleted. Net: the executive has exactly ONE reply primitive
  (`reply_on`) with exactly two bookkeeping wrappers, `client_reply_on` (clients) and
  `pump_reply_on` (components), each backed by its own must-be-zero error counter.
* All 36 sites reply with message **label 0** (the `msginfo` argument carries a length only), so
  correction 1 does not bite; long (len-18) replies are unaffected because `decode_reply` re-stages
  the length from `args.a1` itself and reads MR4+ from the invoker's IPC buffer exactly as the
  `SYS_SEND` form did.
* Prose sweep: `docs/component-harness.md` §7 and the `reply_to` narration in `main.rs` /
  `spawn_hosts.rs` / `service_sec_image.rs` now describe the retired planes in the past tense.
  **`reply_recv_full` and `ep_recv_full` are NOT deleted** (risk R11): the hosted-thread fault loops
  (`main.rs:7749/7916/7982`) and `driver-host-ntdll` still use them.

**Verified:** three consecutive foreground boots each for 3a and 3b — ALL RUNEXIT=3, `microtest
sentinel`, **ZERO FAILs**, gate **232/99**, `diff`-identical PASS lists, paint **768/768 @
`0x003a6ea5`**. Host tests unchanged: nt-ntdll 694, nt-process 79, nt-io-manager 86, nt-syscall 42.

**Rollback:** the Phase-2 commit (or just 3a's, which is self-contained).

---

### Phase 4 — re-enable `LSA_WORKER_ROUTE_ENABLED` — **DONE: prediction CONFIRMED, route re-gated**

Gate **234/99 ZERO FAILs**, RUNEXIT=3, paint **768/768 @ `0x003a6ea5`**, three consecutive boots with
`diff`-identical PASS lists. `LSA_WORKER_ROUTE_ENABLED` ends this phase **`false`** — for a
completely different reason than it started it.

#### 4.1 The prediction was RIGHT: the availability defect is structurally gone

The falsifiable claim was "the route previously died on a wake `Send` that never returned; with the
wake replaced by a non-blocking `reply_on`, that specific wall cannot recur". **Measured with the
route ON, five boots:** the boot **never hangs**. It reaches the gate with `RUNEXIT=3` every single
time, with **zero pump walls** and **zero reply errors** over the whole boot, and the self-RPC
completes a real MS-RPC handshake inside lsass — the routed per-connection worker reads the ncacn
**bind** (PDU type `0x0b`) off npfs and writes the **bind_ack** (`0x0c`). Before the migration this
configuration was a silent wedge. **Two of the five route-ON boots were fully green: 232/99, ZERO
FAILs, paint 768/768.**

That is the payoff Phases 0-3 were justified by, and it is confirmed.

#### 4.2 Turning it on root-caused TWO real defects. Both are fixed; one is landed live

**(a) `component_pump` did not screen bound-notification deliveries. LANDED, unconditional.**

The executive's ROOT TCB has a notification BOUND to it (`delay_timer_init` →
`LBL_TCB_BIND_NOTIFICATION`) so an HPET tick can cancel a blocking `Recv` and wake a parked
`NtDelayExecution`. That is the point of binding — but `component_pump`'s recv is one of those
`Recv`s. The kernel's bound-notification pre-check (`syscall_handler.rs::handle_recv`) returns
`rdi = DELAY_TIMER_BADGE`, `rsi = 0` and **leaves the message registers untouched**. The pump
discarded the badge, so it read `label = 0` with MR0 still holding the request tag `pump_reply_on`
had just left there, fell into its "any other fault" arm, and **suspended + retired the component**:
`[pump] WALL label=0 ip=0x771`, npfs dead mid-boot. The LSA route is simply the first thing in the
boot that arms an HPET one-shot (`NtDelayExecution` from the RPC worker) WHILE a component dispatch
is in flight.

`pump_recv` now recognises the badge, latches `DELAY_TIMER_TICK_PENDING` and re-receives; the service
loop drains it into `delay_timer_interrupt` on its next iteration. No spin is possible — the IOAPIC
line stays masked until that Ack, so at most one tick is outstanding.

Proven live and route-independently by **`exec_pump_screens_bound_notification`**: an injection
(`inject_bound_notification_tick`) mints a notification badged `DELAY_TIMER_BADGE`, binds it to the
root TCB, signals it, and then runs the REAL 2nd-driver IRP dispatch, so the delivery lands on that
dispatch's first `pump_recv`. The spec asserts the pump SAW it (`absorbed >= 1`, else the injection
would be vacuous) AND the dispatch still returned the driver's own answer (`status 0`,
`Information 0x5A5A`). **Bypass experiment** (screen disabled, one boot): reproduces the original
signature exactly — `[pump] WALL label=0 ip=0x771` → `instance RETIRED` — and both that spec and
`exec_second_irp_driver_via_harness` FAIL (234 → 231/99, 3 FAILs).

**(b) Pipe parking was per-CONNECTION, not per-DIRECTION. Fixed, host-tested, GATED OFF.**

The async pipe park pre-checks gated on `PipeWaiterTable::parked_on(file_id)`, making a connection
half-duplex. Every rpcrt4 ncacn_np SERVER violates that: `RPCRT4_io_thread` keeps a READ pending on
the connection while `RPCRT4_worker_thread` writes the RESPONSE on the SAME connection. The write was
refused with `STATUS_INSUFFICIENT_RESOURCES` — not a hang, a **silent functional degrade** — which is
exactly how the 48-byte `LsarOpenPolicy` RESPONSE was lost, so lsass' parked client read never woke
and `LsaOpenPolicy` never returned. (The first suspect, table exhaustion, was WRONG: `PIPE_WAITERS_FULL`
is 0 on every boot. It is counted now rather than silent, and `PIPE_WAITER_N` stays 16.)

`PipeWaiterTable::parked_on_dir(file_id, is_write)` + a host test
(`pipe_waiter_parked_on_dir_is_full_duplex_per_connection`, nt-io-manager 86 → 87) allow one pending
read AND one pending write per connection, which the re-drive already supports (it completes the two
from separate per-direction stashes, `take_completed_write` / `take_completed_read`). It is wired in
behind `PIPE_FULL_DUPLEX_PARK`, **`false`** — see §4.3.

#### 4.3 How far the logon got, and why the route is OFF anyway

With BOTH fixes on and the route ON, one measured boot:

| evidence | route OFF | route ON + both fixes |
|---|---|---|
| routed per-connection worker PDUs | 0 | bind read, **bind_ack written** |
| 48-byte `LsarOpenPolicy` RESPONSE write | — | **status 0, info 48** (repeatedly) |
| `SamIConnect-null-root-miss` | 1 | **0** |
| `sam-setup-keys` / `sam-mount-opens` | 2 / 1 | **36 / 2** |
| lsass creates `\pipe\samr` | no | **yes** (samsrv publishes its own RPC endpoint) |

So the chain really does advance: the LSA self-RPC completes, `SamIConnect` succeeds and
`SampInitDatabase` runs against the real SAM hive. **It does not reach a logon.** `Administrator` is
not validated and `WLX_SAS_ACTION_LOGON` is not returned — nothing is fabricated.

**And the paint is lost.** Across five route-ON boots of the same binaries the desktop paint survived
**twice** and was lost **three times** (gate 211-213/99, ~20 FAILs, paint 0/768) — no crash, no hang,
`RUNEXIT=3` every time. What happens is forward-progress starvation: winlogon does not reach its SAS
window because lsass' self-RPC churns until the 45 s no-progress watchdog quiesces. With
`PIPE_FULL_DUPLEX_PARK` also on (the chain gets *further*), the paint was lost every time.

The paint is a hard safety invariant, and a route that keeps it ~40% of the time cannot land. So the
route is re-gated `false` with the evidence recorded on the const itself
(`main.rs::LSA_WORKER_ROUTE_ENABLED`), exactly as `1141349` and `7d0703b` did. **The wall is now a
SCHEDULING/forward-progress problem, not an availability or correlation one** — which is a materially
better-isolated place to be, and it is the next batch's problem.

#### 4.4 What the gate says with the route off

`exec_lsa_worker_route` is route-AWARE: with the route on it asserts the handshake invariants (first
read PDU = bind, first write PDU = bind_ack); with it off it asserts the worker counters are **0**,
i.e. nothing was fabricated — while `exec_lsa_rpc_handoff_reaches_new_client` still proves rpcrt4
ASKED for the worker, so the route decision is ours and not a failure to get there. Either way it
asserts the transport invariants: **0** pump walls, **0** reply errors, **0** pipe-waiter refusals,
and every absorbed bound-notification tick accounted for.

---

### Phase 5 — land the route: it was an HPET INTERRUPT STORM, not scheduling — **DONE**

Gate **236/99 ZERO FAILs**, RUNEXIT=3, paint **768/768 @ `0x003a6ea5`**, **six consecutive boots**
with `diff`-identical PASS lists. `LSA_WORKER_ROUTE_ENABLED` and `PIPE_FULL_DUPLEX_PARK` end this
phase **`true`**. **No kernel change; `rust-micro` is untouched**, so no sel4test re-verification is
required. **No scheduling context, budget, period or priority was changed anywhere.**

#### 5.1 Step one was to MEASURE the churn — and there wasn't any

Phase 4 ended on "winlogon starves while the self-RPC churns and the 45 s watchdog quiesces first".
That is a claim about who is spending the executive's wall-clock, and the executive's service loop is
SINGLE-THREADED, so it is directly countable. A per-badge census (`print_progress_census`,
`BADGE_EVENTS` / `BADGE_TIME_100NS` / `BADGE_LAST_T`, plus per-SSN histograms for lsass and winlogon)
was added and a route-ON boot measured:

| badge | who | loop events | wall-clock |
|---|---|---:|---:|
| 26 | **the LSA per-connection worker** | **51** | 0.4 s |
| 15 | the SCM `\ntsvcs` worker (known-good 8-PDU baseline) | 49 | 0.4 s |
| 8 | lsass' main thread | 2 074 | 50 s |
| 4 | winlogon | 2 528 | 60 s |
| 2 | csrss | 714 | 71 s |
| **36** | **the HPET delay-timer notification** | **2 773 385** | **82 s** |

lsass' ENTIRE process issued 1 253 native syscalls on that boot, spread across ~40 distinct SSNs —
a flat, bounded profile with no retry loop, no poll and no repeated SSN. **The self-RPC is bounded,
proportionate work, comparable to the SCM baseline it was asked to be compared against.** The
livelock was somewhere else entirely: a timer delivering **2.77 million** times.

#### 5.2 The root cause: `delay_timer_rearm` toggled the wrong bit

Instrumented (`TIMER_TICKS_SEEN` / `TIMER_TICKS_SPURIOUS` + a bounded dump of the live HPET
registers on a spurious tick):

```
[census] timer ticks-seen=2745192 spurious=2745189 past-deadline-rearms=2
[timer-storm] spurious #0 counter=0x6_6015e9b8 cmp=0x6_60001125 cfg=0x00ff0104_00002c34 armed=0 ...
```

`cfg` bit 2 is **set** and bit 1 is **clear**, while `armed=0` says the last rearm had NO deadline
and had taken its disarm branch. Per the IA-PC HPET spec §2.3.8, Timer N Configuration bit 1 is
`Tn_INT_TYPE_CNF` (0 = edge, 1 = level) and bit **2** is `Tn_INT_ENB_CNF`. `delay_timer_rearm` (and
`delay_timer_shutdown`) toggled **bit 1** to arm/disarm; the actual enable, bit 2, was set once by
`delay_timer_init` and never cleared. So "disarm" only flipped the timer from level- to
edge-triggered and left it ENABLED with a comparator now permanently behind the main counter —
`counter = 0x6_6015e9b8 > cmp = 0x6_60001125` — which re-fires on every comparator re-arm. ~34 kHz,
forever, each delivery a full round trip through the executive's single service loop.

**Why it had never been seen:** on a route-OFF boot the HPET one-shot is **never armed at all**
(`ticks-seen=0`, measured on a control boot). The LSA route is the first thing on the boot that ever
calls `NtDelayExecution` — the rpcrt4 worker's `Sleep(1)`. It did not cause the storm; it was the
first thing to switch the storm on.

The fix names the bits (`HPET_TN_INT_TYPE_LEVEL`, `HPET_TN_INT_ENB`), keeps the trigger type LEVEL
for the timer's whole life (matching the IOAPIC pin, which is issued `level = 1`), leaves the timer
DISARMED at init, and uses `Tn_INT_ENB_CNF` as the one arm/disarm control. Three lines.

| | before | after |
|---|---:|---:|
| HPET deliveries per boot | 2 745 192 | **3 – 60** |
| of which woke nothing | 2 745 189 | **0 – 1** |
| executive wall-clock on the timer | 82 s | **< 0.05 s** |
| desktop paint | lost 3 of 5 boots | **768/768, 6 of 6 boots** |

**Positive proof, not just green:** `exec_delay_timer_disarms` reads the LIVE `T0_CONFIG` back off
the HPET at gate time and asserts `Tn_INT_TYPE_CNF` is still SET (under the bug it reads 0 whenever
the timer is disarmed, which is the steady state) plus a delivery ceiling and a woke-nothing ceiling.
`exec_lsa_selfrpc_route_enabled` asserts the route is ON and its cost is BOUNDED, printing the SCM
worker's event count alongside as the comparison baseline.

#### 5.3 What the 45 s watchdog is, and whether it fired legitimately

`service_sec_image.rs`'s `STALL_BUDGET_100NS` — 45 s of WALL-CLOCK with no `PROGRESS_EPOCH` bump (a
new DLL demand-loaded, a fresh page filled, an event created/signalled, a process spawned, or the
paint). It is the boot's termination backstop: cooperatively-parked processes plus one thread that
keeps issuing syscalls would otherwise block the service loop's `recv` forever, and the boot could
never reach `qemu_exit`. It is deliberately blunt, and it **fired correctly**: the storm meant no
process made any qualifying progress for 45 s, which is exactly the condition it exists to detect.
It was reporting the bug, not causing it. With the storm gone it does not fire at all — all six
verification boots quiesce on the normal steady-state path ("server listener parked + winlogon parked
at empty SAS message loop + LSA signalled").

#### 5.4 A third defect the route exposed: a spec that raced on the shared endpoint

`exec_dbgk_debugger_wait_blocks_and_wakes` did a bare `recv_full_r12(fault_ep, …)` and assumed the
next message was its own injected client's. `fault_ep` is the executive's SHARED endpoint, so a
hosted thread still runnable at quiesce can land there first — observed with the route on as a
win32k `m0 = 0x101b` from a live winlogon worker, which made the step read a foreign syscall and
silently skip the whole assertion. It now SELECTS on the client's own SSN and leaves any foreign
message unanswered (post-quiesce, an un-replied caller is exactly as parked as everything else on the
`[parked]` list). The assertion itself is unchanged in strength.

#### 5.5 How far the logon chain got, and the next wall

Measured against a route-OFF **control boot of the same binaries**:

| evidence | route OFF | route ON (Phase 5) |
|---|---|---|
| `SamIConnect-null-root-miss` | 1 | **0** — the wall is GONE |
| `sam-setup-keys` / `sam-mount-opens` | 2 / 1 | **36 / 2** |
| LSA policy attribute reads | 8 | **12** |
| real SECURITY/SAM hive opens | 2 | **3** |
| `LsaLogonUser` (api 2) outcome | replied `0xC0000034` at `SamIConnect` | server runs the FULL chain |
| LSA server wall | none | **`NtCreateToken`, SSN 57** |

The real LSA server thread now runs the whole `LsapLogonUser` → MSV1_0 → `SamValidateNormalUser`
chain against a real `SampInitDatabase`, works through the privilege lookups
(`LsapOpenDbObject(Accounts/S…)`), and stops at the last step before it could answer:
**`NtCreateToken` (SSN 57), which the executive does not service.**
`lsa_release_client_on_server_wall` releases winlogon with `STATUS_UNSUCCESSFUL`, which msgina
reports as the real `LsaLogonUser failed (Status 0xc0000001)`. **Nothing is fabricated:**
`Administrator` is not validated, no token is minted, `WLX_SAS_ACTION_LOGON` is not returned.
`NtCreateToken` is the next frontier — a real service to implement (the token store, SID/group/
privilege types and handle insertion already exist; `NtOpenProcessToken`, `NtDuplicateToken` and
`NtQueryInformationToken` are already serviced), not a workaround.

**Four specs that PINNED THE OLD WALL were re-pointed at the new one**, each strictly stronger:
`exec_lsa_auth_port_connected` now asserts the wall SSN is EXACTLY `NtCreateToken` (resolved from the
ABI table, so an unexpected wall anywhere else fails it) instead of "no wall";
`exec_msv1_0_account_domain_sid_resolved` asserts the null-root miss is **0** (it asserted `>= 1`)
plus the 16+ SAM database keys and the second mount open that only a SUCCEEDING `SamIConnect`
produces; `exec_lsa_msv1_0_sam_validation_reached` asserts the same absence plus an unset reply
status; `exec_lsa_logon_user_reached` asserts the exact `replies + 1 == requests` relation.

**Verified:** six consecutive foreground boots — ALL RUNEXIT=3, `microtest sentinel`, **ZERO FAILs**,
gate **236/99**, `diff`-identical 236-line PASS lists, paint **768/768 changed @ `0x003a6ea5`**.
Host tests unchanged: nt-ntdll 694, nt-process 79, nt-io-manager 87, nt-syscall 42.

**Rollback:** flip both consts back to `false`. The HPET fix is independent of them and should be
kept regardless — it is a latent storm in any boot that ever arms the one-shot.

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

**34 items — ALL DELETED.** Grep-verified at the end of Phase 3 over `components/**/*.rs`: every
one of the 34 names has **zero CODE hits**. What remains is prose only — 18 mentions across 6 files,
each a comment or doc-comment explaining what the symbol *was* and what replaced it, deliberately
retained as the record of why the current shape is what it is. Verification recipe (re-runnable):

```sh
for s in ep_send ep_send_token send_on_reply send_done_on recv_req_on SH_REQ_SEQ \
         PUMP_STALE_DONES PUMP_SLIP_INJECT FSD_DISPATCH_SEQ_HANDSHAKE DISPATCH_TOKEN_NEXT \
         DISPATCH_TOKEN_STACK_MAX DISPATCH_TOKEN_STACK DISPATCH_TOKEN_DEPTH DISPATCH_TOKEN_MAX_DEPTH \
         PUMP_TOKEN_MISMATCHES dispatch_token_push dispatch_token_top dispatch_token_pop \
         dispatch_token_depth suspended_dispatch_token owns_token_stack_top W32_SLIP_INJECT \
         W32_SLIP_INJECT_TOKEN W32_DISPATCH_TOKEN_BINDING nested_reply_cap use_reply_cap wake_first \
         Transport exec_component_dispatch_in_phase exec_win32k_dispatch_in_phase_nested \
         NESTED_SLIP_REJECTED COMPONENT_CALL_CLOBBERED_REPLY_TO; do
  printf '%-38s code=%s\n' "$s" \
    "$(grep -rn --include='*.rs' "\b$s\b" components/ | grep -v ':[[:space:]]*//' | wc -l)"
done
```

**Two symbols the kill-list must NOT touch** (risk R11), re-verified: `reply_recv_full` (3 live call
sites in `main.rs`'s hosted-thread fault loops + `driver-host-ntdll`) and `ep_recv_full`. They are
not part of the dispatch transport.

**One item was ADDED to the list during Phase 3** and is also deleted: the Phase-1
`COMPONENT_CALL_CLOBBERED_REPLY_TO` guard, together with `routed_win32k` / `routed_lpc` /
`routed_csr`. Those were the *workaround for the workaround* — the shape correction 2 warned would
otherwise keep widening.

### Executive IPC helpers (`components/ntos-executive/src/main.rs`)
1. `ep_send` (3855)
2. `ep_send_token` (3871)
3. `send_on_reply` (3995) — *replaced by* `reply_on` (error-returning) + its counting wrapper
   `client_reply_on`. The error-swallowing `SYS_SEND` form is deleted; all 36 call sites moved.

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
