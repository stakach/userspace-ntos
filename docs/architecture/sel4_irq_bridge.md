# seL4 IRQ bridge — design

Status: design only (spec Milestone 11.8). No real-hardware implementation lands
until the simulated path is stable — which it now is (`driver-host-mmio` runs
`MmioInterruptTest.sys` end to end with simulated MMIO + injected interrupts).

This document specifies how the simulated interrupt path becomes a **real**
seL4-delivered interrupt path under the same HAL API, and the authority + teardown
model that governs it.

## 1. Where we are (the simulated path)

Today the interrupt is injected by the test harness, entirely in user space:

```text
run() asserts the device status line (SimDevice::raise_interrupt)
  -> ResourceManager::inject_vector(5) resolves the connected ISR's tokens
  -> Driver Host raises to the device IRQL, calls the ISR (a driver fn ptr)
  -> ISR reads status / writes ack / KeInsertQueueDpc
  -> Driver Host lowers IRQL, drains the DPC
  -> DPC completes the pending IRP
```

The canonical interrupt record (owner, vector, ISR tokens, connected state) lives in
the `nt-resource-manager`; the ISR + DPC run inside the Driver Host because they are
driver function pointers (spec §4.1, §16.3 — the service never calls driver code).

## 2. The real bridge

Replace only the **source** of the interrupt event. The ISR/DPC path is unchanged.

```text
+-------------------+     IRQHandler cap (bind)      +----------------------+
|  bootstrap /      | -----------------------------> |  HAL / Interrupt     |
|  resource authority|    Notification cap (granted) |  Manager service     |
+-------------------+                                 +----------+-----------+
                                                                 | seL4_Wait(ntfn)
                                                                 v
                                                      +----------------------+
                                                      | IRQ-waiter thread     |
                                                      |  loops: Wait -> lookup |
                                                      |  record -> SURT event  |
                                                      +----------+-----------+
                                                                 | SURT: interrupt event
                                                                 |  { interrupt_id, token }
                                                                 v
                                                      +----------------------+
                                                      |  Driver Host          |
                                                      |  resolve token->ISR    |
                                                      |  raise IRQL, call ISR  |
                                                      |  ack via IRQHandler    |
                                                      |  lower, drain DPC      |
                                                      +----------------------+
```

### 2.1 Caps involved (rust-micro / seL4)

- **IRQControl** (held by the trusted bootstrap): mints an **IRQHandler** cap for a
  specific vector via `IRQControlGet`.
- **IRQHandler**: `IRQHandlerSetNotification` binds it to a **Notification**;
  `IRQHandlerAck` re-arms the line after servicing.
- **Notification**: the Interrupt Manager's IRQ-waiter thread blocks on it with
  `seL4_Wait`; a hardware IRQ signals it.

The rust-micro kernel already delivers device IRQs to a user Notification (the LAPIC
timer is the kernel clock; the PIT/IOAPIC lines fan out to user IRQ notifications —
see the sel4test IRQ bring-up). This bridge reuses that machinery: the HAL service is
just another user of an IRQHandler+Notification pair.

### 2.2 Bridge steps

1. **Assign** (fixture / future PnP): the resource authority records that device D
   owns interrupt resource R with translated vector V, and mints an IRQHandler cap
   for V into the Interrupt Manager's CSpace.
2. **Connect** (`IoConnectInterrupt`): the Driver Host sends `HAL_OP_CONNECT_INTERRUPT`
   with opaque ISR `service_routine_token` / `service_context_token`. The Interrupt
   Manager creates the canonical `InterruptRecord`, `IRQHandlerSetNotification`-binds
   V to its notification, and returns an `interrupt_id`. The Driver Host builds the
   local `PKINTERRUPT` projection.
3. **Deliver**: on a hardware IRQ, the notification signals; the IRQ-waiter thread
   looks up the record by badge/vector and sends a SURT **interrupt event**
   (`interrupt_id` + the Driver Host's opaque token) to the owning Driver Host.
4. **Service**: the Driver Host raises to the device IRQL, resolves the token to the
   local ISR pointer, calls it (reads/acks device registers through its mapped MMIO
   frame), then `IRQHandlerAck`s (via a `HAL_OP` round-trip or a delegated ack cap)
   and lowers IRQL. The ISR's `KeInsertQueueDpc` + the existing DPC drain complete
   the IRP — identical to the simulated path.

### 2.3 What stays simulated first

- The **register bank**: for the simulated backend it is Driver-Host memory; for real
  hardware it becomes an seL4 device **frame cap** granted by the authority and mapped
  into the Driver Host (spec §16.1). Register access is inlined in the driver either
  way, so the mapping is always real Driver-Host memory — only its *backing* changes
  (anonymous frame vs. device frame).
- **Injection** (`HAL_OP_INJECT_INTERRUPT`) remains, gated behind a privileged test
  endpoint, so tests keep working without hardware (spec §16.2).

## 3. Authority model

- Only the trusted bootstrap / resource authority holds **IRQControl** and device
  **frame** authority. It grants an IRQHandler + Notification (and device frames) to
  the HAL / Interrupt Manager, and records the grant.
- The HAL service exposes only **resource IDs / mapping IDs / interrupt IDs** to the
  Driver Host — never raw caps, addresses, or function pointers (spec §6.2, §16.3).
- The Driver Host exposes only local projected pointers to the loaded driver.
- ISR/DPC callbacks are driver function pointers; **only the Driver Host** ever calls
  them. The service sends opaque token events (spec §11.1, §16.3).

## 4. Teardown + revoke

- **Disconnect** (`IoDisconnectInterrupt`): the Interrupt Manager clears the record's
  connected flag, `IRQHandlerClearNotification`-unbinds (and masks) the line, and
  drains any in-flight dispatch before freeing (spec §9.6). Further deliveries/
  injections for that `interrupt_id` are dropped.
- **Resource revoke** (`HAL_OP_RESOURCE_REVOKE`): the mapping/interrupt ID becomes
  stale; register access faults, injections are rejected, and a stale-generation check
  rejects the old IDs (spec §15.2 — already enforced by `nt-resource-manager`).
- **Driver Host fault/death**: the HAL service `revoke_host`s — unbinds + masks every
  IRQHandler, revokes every mapping, drops pending simulated interrupts, and the I/O
  Manager fails the host's outstanding IRPs (spec §15.1). `ResourceManager::revoke_host`
  already implements the resource side.

## 5. Non-goals (unchanged from spec §3)

MSI/MSI-X, shared lines, interrupt affinity/moderation, DIRQL-accurate preemption,
and passive-level interrupts stay out until the single-vector level-sensitive path is
solid on real hardware. The bridge above is deliberately one-ISR-per-vector, exclusive,
level-sensitive — matching `MmioInterruptTest`.
