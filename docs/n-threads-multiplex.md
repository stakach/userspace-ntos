# N-threads-per-process multiplex + the SCM svcctl RPC round-trip

**Status:** Phase-1 diagnosis + design (checkpoint before implementation).
**Frontier:** winlogon's `OpenSCManager` connects to `\??\pipe\ntsvcs` (services.exe =
SCM), writes its `RROpenSCManagerW` request, but never gets a reply →
`RPC_X_BAD_STUB_DATA (0x6be)`. The desktop paint (`exec_win32k_desktop_painted`,
768/768 @ `0x003a6ea5`) is *after* this RPC in winlogon's login flow.

All file:line refs are under `components/ntos-executive/src/` unless noted.

---

## 1. How the current multiplex actually works

The executive runs ONE service loop (`service_sec_image.rs:12`
`service_sec_image()`) that receives on a single fault endpoint `fault_ep` and
multiplexes **all** hosted threads by the **badge** on the message. The badge
selects which process/thread's state to load.

### Threads are already per-thread, not one-per-process

Contrary to the task framing ("multiplexes PROCESSES by badge, one context per
process"), the per-thread infrastructure **already exists**. Every hosted thread
faults/syscalls through a fault-EP cap minted at its own badge:

- Process **main** threads: `CSRSS_BADGE=2`, `WINLOGON_BADGE=4`,
  `SERVICES_BADGE=6`, `LSASS_BADGE=8` (`main.rs:607,624,629,634`). smss = badge 0.
- **Listener / worker** threads have their OWN badges:
  `SVC_LISTENER_BADGE=7` (services' SCM RPC listener), `LSASS_LISTENER_BADGE=9`,
  `LSASS_LISTENER2_BADGE=10`, `LSASS_LISTENER3_BADGE=14`,
  `WINLOGON_WORKER_BADGE=11/12/13` (`main.rs:327,345,360,368,289,300,308`).

The listener's fault EP is minted off the SAME `fault_ep`:
`rendezvous.rs:428` `let listener_ep = mint_badged(main_fault_ep, SVC_LISTENER_BADGE);`
so **the listener's events already arrive in the one loop and are selectable by
badge.** The loop sub-selects at `service_sec_image.rs:485-495` (`is_svc_listener
= badge == SVC_LISTENER_BADGE`, …) and resolves badge → owning `pi`
(process index) at `:545-559` (`SERVICES_BADGE || is_svc_listener → pi 3`).

### Per-thread state is real

Each listener gets its own dedicated VAs, all passed to `spawn_hosted_thread`
(`rendezvous.rs:418-451`): its own TEB (`SVC_LISTENER_TEB_VA`, GS base = TEB),
stack + **stack mirror** (`SVC_LISTENER_STACK_MIRROR_VA`), IPC buffer, trampoline,
env scratch. The loop switches the **active stack mirror by badge**
(`service_sec_image.rs:585-620`, `is_svc_listener → svc listener's own mirror`) so
the listener's syscall out-params land on ITS stack, not the process main thread's.
`current_tid` is resolved per-thread (`:1388-1404`).

### The svc listener IS alive and resumed

services.exe's first `NtCreateThread` (its SCM RPC listener) is recognized in the
handler (`exec_handler.rs:2381`), which pops a pool ETHREAD, sets its TEB, and
sets `svc_listener_spawn = true`. The loop then spawns it **RESUMED** into the
multiplex (`service_sec_image.rs:2003-2028` → `spawn_svc_listener_thread(...,
resume=true)`, `rendezvous.rs:418`). Boot log confirms:

```
[svc-thread] spawned + resumed tcb=0x0001d7db (runs into the main multiplex, badge 7)
[svc-listener] multiplex event #0 label=0x2 m1=0x0 (N-threads sub-select: pi 3 listener)
```

So the listener runs at least once. (winlogon's RPC listener is the exception —
spawned **SUSPENDED**, `service_sec_image.rs:1930-1994`; it only needs a queryable
TEB to unblock `StartRpcServer`. The svc + lsass listeners are resumed/live.)

### Cross-thread wakeups the loop already models

The loop already handles cooperative parks and cross-thread wakeups for **events**:
`NtWaitForSingleObject`/`MultipleObjects` park a caller (withhold the reply cap),
and a later `NtSetEvent` from another thread wakes it (`wait_parked` bitmask,
`service_sec_image.rs:296-303,560-562`; `[wait] … -> WOKE 1 parked waiter(s)` in
the log). This is the rpcrt4 two-thread handshake mechanism (main thread
`SetEvent` wakes the worker parked on a wait-array).

### The npfs data plane is REAL

`\pipe\ntsvcs` is served by the **real ReactOS npfs.sys** driver, launched as an
isolated component (`driver_launch.rs`). Client/server pipe ops become **real
IRPs** dispatched to npfs's own `NpFsdCreate*`/`NpFsdRead`/`NpFsdWrite`/
`NpFsdFileSystemControl` (`driver_launch.rs:run_irp` @ `:870-997`;
`npfs_route_raw` @ `exec_handler.rs:766`). The two pipe ends are matched by name
through npfs's real Unicode prefix table (`driver_launch.rs:354-416`).
`NtFsControlFile`/`NtReadFile`/`NtWriteFile`/`NtSetInformationFile` all route to
npfs (`exec_handler.rs:1931,4040,3966-ish,4098`). npfs returns **STATUS_PENDING
(0x103)** on a read/listen with no queued data, and the executive stores it in a
`PENDING_IRPS` table (`driver_launch.rs:969-981`) with an `IoCompleteRequest`
trampoline (`:328-352`) to reclaim it — but see §2, nothing re-drives it.

**Summary: the "N-threads multiplex" is largely BUILT. Per-thread badges, EPs,
TEB/GS/stack-mirror, resume-into-loop, event-based cross-thread wake, and a real
npfs pipe data plane all already exist.** The stall is NOT missing thread
scheduling.

---

## 2. The evidenced stall (boot log `/tmp/boot_fix2.log`)

Exact timeline (line numbers in that log):

```
2727 [svc-listener] multiplex event #0 label=0x2 m1=0x0 (N-threads sub-select: pi 3 listener)
2728 [svc-listener] blocking server syscall SSN=... -> PARK thread (reached its RPC receive loop / unserviced); boot continues
...
2740 [nt-create-file-frontier] pi=2 ... name="\??\pipe\ntsvcs"      (winlogon opens the pipe)
2741 [nt-create-file-winlogon] status=0x0 info=1                    (open OK)
2743 [fsd-data-result] major=4 length=72 status=0x0 info=72         (winlogon WRITE 72 bytes OK -> npfs)
2745 [fsd-data-result] major=3 length=16 status=0x103 info=0        (winlogon READ -> STATUS_PENDING, no data)
2749 [bp-diag] int3 rva=0x5882 ...
2750 [bp-diag] EXCEPTION_RECORD code=0x6be ...                      (RPC_X_BAD_STUB_DATA)
...  [parked] pi=2 badge=4 ... -> PARK process (unrecoverable)
```

- **Client thread:** winlogon main (badge 4, pi 2). It writes the 72-byte
  `RROpenSCManagerW` request PDU into `\pipe\ntsvcs` (delivered to npfs OK), then
  reads the reply → npfs returns **STATUS_PENDING** (no reply queued) → rpcrt4
  sees an empty/garbage receive buffer → raises `0x6be` and the process parks.
- **Server thread:** services' SCM listener (badge 7, pi 3). It ran event #0 and
  then **PARKED at its "blocking server syscall"** — the
  `service_sec_image.rs:2990-3005` arm: when a listener thread makes a syscall the
  loop can't service/fake (its RPC-receive loop syscall — `NtFsControlFile
  FSCTL_PIPE_LISTEN` / `NtReplyWaitReceivePort` / `NtReadFile`), the loop does
  `recv WITHOUT replying` → the listener's seL4 thread stays blocked forever.

### Why the listener never dispatches — the root cause

It is **(c) + a data-plane gap**, not (a) or (b):

- Not (a): the listener's faults/syscalls **are** selected by the loop (it printed
  `multiplex event #0`).
- The listener reaches its RPC receive/listen syscall **before winlogon ever
  connects** (line 2728 fires before 2740). At that instant npfs has no client and
  no data, so a real `FSCTL_PIPE_LISTEN`/`NtReadFile` returns **STATUS_PENDING**.
  The current loop does not know how to hold a server thread on a pending pipe
  receive and **re-drive it when the client later writes** — so it takes the
  shortcut `blocking server syscall -> PARK thread` and drops the listener.
- Consequently, when winlogon writes at line 2743, **there is no live server-side
  reader** and **no re-drive of the parked listener's pending read.** winlogon's
  own read (2745) also goes PENDING and is likewise never re-driven → `0x6be`.

**The gap = pipe-pending-read re-drive across threads.** A `STATUS_PENDING`
pipe read/receive must (i) leave the requesting thread cooperatively parked
(reply withheld, exactly like an event wait), and (ii) be **completed/re-driven
when the peer writes matching data to the other end of the same npfs pipe
instance**, at which point the loop replies to the parked reader with the bytes.
npfs already queues the write data and pairs the ends by name; the executive is
missing the "peer write → complete the peer's pending read → wake that thread"
edge. Today `io_signal_event` only signals an *event object* on a completed
(non-pending) I/O (`exec_handler.rs:3960,4070`); it does nothing for a read that
returned PENDING.

**Corroborating detail (independent trace).** The live pipe path is a fully
*synchronous* IRP RPC: `npfs_dispatch_irp` (`driver_launch.rs:1492`) does one
`ep_send(FSD_DISPATCH_LABEL)`, drives npfs to re-park, and reads back the result —
**one caller syscall == one complete IRP round-trip.** Real npfs on an empty
blocking read *correctly* queues the read as a pending ReadEntry and returns
STATUS_PENDING (`references/reactos/drivers/filesystems/npfs/read.c:126-149`); the
executive stashes the IRP in `PENDING_IRPS` (`driver_launch.rs:969-981`) and
`s_io_complete_request` (`:328-352`) reclaims it when a later peer write completes
it *inside npfs* — **but nothing on the caller side is parked or resumed.** The
`0x103` return only means "don't copy / don't signal the completion event"
(`exec_handler.rs:4054,4068`); the status is written to the IOSB and returned
*directly to the reader's syscall*, and the reader is never resumed with the bytes
when a writer arrives. The genuine block-then-wake machinery
(`main.rs:854-933`, `WAITER_EVENT_IDX`/`WAITER_REPLY_CAP` +
`NtSetEvent → send_on_reply(stolen_cap, WAIT_0)`) is keyed **exclusively on an
obj_ns event index** — there is **no pipe-handle/file-id-keyed waiter and no wake
trigger from a pipe write.** (Note: `crates/nt-io-manager/src/pipe.rs` is a
host-tested passive NPFS model with no wait/wake logic and is NOT on the live path;
the live path is the real `npfs.sys` binary.)

---

## 3. Design: minimal-first — pipe-pending completion, not a multiplex rewrite

The multiplex itself needs **no redesign**. The minimal change is to make a
pending pipe receive a first-class cooperative park (like an event wait) and to
re-drive it on the peer write. Concretely:

### 3a. Park a pending pipe receive (both client and server sides)

When `NtReadFile` / `NtFsControlFile(FSCTL_PIPE_TRANSCEIVE)` /
`NtFsControlFile(FSCTL_PIPE_LISTEN)` on a tracked npfs pipe handle returns
STATUS_PENDING for the **current thread** (any badge — svc listener OR winlogon
main), record a **PipeWaiter**: `{ badge, pi, tid, npfs_file_id, buffer_va,
buffer_len, iosb_va, reply_cap }` and **withhold the reply** (park the thread),
reusing the existing wait-park machinery (`park_wait_event`/reply-cap park). This
REPLACES the `blocking server syscall -> PARK (drop)` shortcut for pipe receives
on the listener path (`service_sec_image.rs:2997-3005`), so the listener parks
*recoverably* (re-drivable) instead of being abandoned.

### 3b. Re-drive on peer write

On `NtWriteFile` to a tracked pipe handle (after npfs queues the bytes), look up
any **PipeWaiter blocked on the PEER npfs file-id of the same pipe instance**.
npfs already pairs the two ends and holds the queued data, so re-issue that
waiter's read against npfs (`npfs_route_raw(IRP_MJ_READ, peer_fid, …)`), copy the
bytes into the waiter's buffer/IOSB (cross-AS via the waiter's `pi`), and
**reply to the parked waiter's reply cap** so its seL4 thread wakes with
STATUS_SUCCESS + the data. This is the same shape as `NtSetEvent -> WOKE parked
waiter`, generalized to pipe data. Do it symmetrically for
`FSCTL_PIPE_LISTEN`/`TRANSCEIVE` so the server's listen wakes on the client
connect/write.

### 3c. Selection over all threads is already correct

No change: the loop already receives on the one `fault_ep`, and both the client
(badge 4) and the listener (badge 7) already arrive there. The only new thing is a
**PipeWaiter table** (a small fixed-capacity static, like `PENDING_IRPS`) and the
write→peer-read completion edge, plus routing the listener's pending receive into
it instead of the drop-park.

### Why this is minimal and correct (not a fake)

- Both processes keep running the **real rpcrt4.dll** over the **real npfs pipe**;
  we only schedule the real reads to complete. No hand-rolled RPC.
- It reuses the existing reply-cap park + wake mechanism and the existing npfs
  routing and `PENDING_IRPS`/`IoCompleteRequest` graph.
- It generalizes: it unblocks **every** multi-threaded pipe server (services' SCM
  listener now, lsass' LSA thread, csrss) — the same edge serves all of them.

### Follow-ups (only if evidence demands after 3a/3b land)

- If the listener's server receive is `NtReplyWaitReceivePort`/an ALPC/LPC receive
  rather than a raw `NtReadFile` on the pipe, route it through the same
  PipeWaiter edge keyed by the connection instead of raw pipe fid.
- npfs message-mode framing (`FILE_PIPE_MESSAGE_TYPE`, set at create,
  `driver_launch.rs:918`) — ensure a single 72-byte write is delivered as one
  message read (npfs handles this; verify the completed length == 72).

---

## 4. Honest depth assessment — is real MSRPC NDR servicing needed?

**Most likely: NO extra MSRPC NDR code in the executive.** Both ends run the real
`rpcrt4.dll` (client marshals `RROpenSCManagerW`, server's svcctl stub
unmarshals + dispatches + marshals the reply). The executive's job is to be the
**transport** — deliver the client's request bytes to the server's pending read
and the server's reply bytes to the client's pending read. Once 3a/3b re-drive the
reads with the real bytes, the real svcctl NDR on both sides does the rest.

**Risks that could add a batch:**
1. **MSRPC connection-oriented bind sequence.** Before `RROpenSCManagerW`, MSRPC
   does a `bind`/`bind_ack` PDU exchange over the pipe. If the client's first
   72-byte write is the bind (the prefix `0x05 0x00 0x0b 0x03` in the log =
   MSRPC version 5.0, PTYPE 0x0b = **bind**), the server must read it, and rpcrt4
   auto-generates the `bind_ack` — still just transport, but it's a
   **multi-round-trip** (bind→bind_ack, then request→response), so the re-drive
   edge must survive several read/write cycles, not one. The PipeWaiter table must
   support re-parking after each reply. (The log confirms: the 72-byte write is
   PTYPE 0x0b bind, not the request yet — so at minimum bind + request = 2 round
   trips.)
2. **Server-side listen/accept semantics.** The listener must have actually posted
   its `FSCTL_PIPE_LISTEN` and a follow-up read; if it parked at a *different*
   syscall (e.g. it hadn't reached the read yet), we must let it run PAST the
   listen to its first read before parking it — i.e. service the listen
   (return the connect) rather than drop-park it.
3. **Message vs byte mode / partial reads.** rpcrt4 may read a header then the
   body (two reads per PDU). The re-drive must handle a read smaller than the
   queued message.

**Batch estimate to the paint:**
- **Batch 33:** PipeWaiter table + park-pending-pipe-receive + peer-write re-drive
  (3a/3b). Get the bind→bind_ack round trip flowing (listener reads the bind,
  rpcrt4 replies bind_ack, winlogon reads it).
- **Batch 34:** carry it through the `RROpenSCManagerW` request→response round trip
  (re-park after bind_ack, re-drive on the request write, deliver the response).
  `OpenSCManager` returns a real SC handle → winlogon proceeds past the SCM wall.
- **Batch 35 (likely):** winlogon's next SCM calls in its login flow (e.g.
  `OpenService`/`StartService` or a `QueryServiceStatus`) reuse the SAME edge —
  probably no new mechanism, but 1 batch of shaking out the login-flow calls that
  gate `SwitchDesktop`.
- **Paint:** once winlogon's login flow passes the SCM gate, its natural
  `NtUserSwitchDesktop → co_IntShowDesktop → IntPaintDesktop` reconverges the
  768/768 `0x003a6ea5` paint (the gate is already wired, `service_sec_image.rs:2886`).

**Realistic: 2–4 batches**, with the risk concentrated in the MSRPC
multi-round-trip (bind then request) rather than in thread scheduling. If the
bind/request turns out to be a clean single request→response after all, it's 2.

---

## Recommended plan

1. **Batch 33 (this design's core):** add the `PipeWaiter` table + park-on-pending
   + peer-write-re-drive edge; replace the listener drop-park for pipe receives.
   Verify the bind→bind_ack round trip in the boot log
   (`[fsd-peer-complete]` on both fids, no `0x6be`).
2. **Batch 34:** carry the RROpenSCManagerW request→response; confirm winlogon gets
   a real SC handle.
3. **Re-check** whether winlogon's login flow reaches `SwitchDesktop`; if a further
   SCM call gates it, batch 35 reuses the same edge.

No multiplex rewrite. No fake RPC. The listener thread already runs — it just
needs its pending pipe reads to complete when the peer writes.
