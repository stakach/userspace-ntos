# KMDF hardware extensions — compatibility notes

WDF hardware objects (spec: NT KMDF Hardware Extensions, v0.2). Target driver
`KmdfDmaInterruptTest.sys` — KMDF 1.15, same WDFLDR bind as `driver-host-wdf`; adds
WDFINTERRUPT, WDFDMAENABLER, WDFCOMMONBUFFER, WDFDMATRANSACTION, WDFTIMER, WDFWORKITEM.
New function-table indices (KMDF 1.15): WdfCommonBufferCreate=21 / GetAlignedVirtualAddress=22 /
GetAlignedLogicalAddress=23 / GetLength=24; WdfDmaEnablerCreate=94 / GetMaximumLength=95;
WdfDmaTransactionCreate=98 / InitializeUsingRequest=100 / Execute=101 / Release=102 /
DmaCompletedFinal=105; WdfInterruptCreate=141 / QueueDpcForIsr=142 / Synchronize=143 /
Enable=146 / Disable=147; WdfTimerCreate=318 / Start=319 / Stop=320; WdfWorkItemCreate=379 /
Enqueue=380 / Flush=382; WdfIoQueueRetrieveNextRequest=158; WdfDeviceGetDefaultQueue=92.

## WDFINTERRUPT (implemented, Milestone 16.1 — `nt-wdf-interrupt`)

- `WdfInterrupt`: ISR/DPC callback config, connect/enable/disable state, `queue_dpc_for_isr`
  latching (once until it runs), `take_dpc`, interrupt/DPC counters. `on_hardware_interrupt`
  returns the ISR callback only while **active** (connected+enabled) — a disabled/out-of-D0
  interrupt is dropped (spec §7, §14.3). Returns callback pointers; never calls the driver.
  4 tests.

## WDF DMA objects (implemented, Milestones 16.2/16.3/16.6 — `nt-wdf-dma`)

`WdfDmaManager` wraps `nt-dma-manager` + `nt-mdl`, keyed by WDF handle:
- WDFDMAENABLER: `create_enabler` (→ DMA adapter via the DMA Manager, profile→sg/dma64),
  `enabler_maximum_length` (spec §8).
- WDFCOMMONBUFFER: `create_common_buffer` (real backing VA + a **fake logical address** from
  the DMA Manager, never a host physical address, §9.4), `common_buffer_virtual/logical_address/
  length`, `decode_logical` (IOMMU-facade lookup for the sim device), `free_common_buffer` (§9.5).
- WDFDMATRANSACTION: Created→Initialized→Executing→Completed state machine —
  `create_transaction`, `init_transaction_using_request` (registers an MDL), `execute_transaction`
  (maps the buffer → logical address + returns `EvtProgramDma`), `complete_transaction_final`
  (releases the mapping, records bytes) (§10.3-§10.5). State guards reject out-of-order calls.
  3 tests.

## WDF runtime hardware objects (implemented, Milestones 16.4/16.5/16.7 — `nt-wdf-runtime`)

`WdfRuntime` gains the hardware-object management (over `nt-wdf-interrupt` + `nt-wdf-dma`):
- Interrupt: `create_interrupt` (parented to device), `interrupt_get_device`,
  `connect_device_interrupts` (framework auto-connect after PrepareHardware, §7.4),
  `interrupt_enable/disable`, `fire_interrupt` (→ EvtInterruptIsr if active),
  `interrupt_queue_dpc` / `interrupt_take_dpc` (→ EvtInterruptDpc), `interrupt_counts`.
- DMA: `create_dma_enabler` (profile→adapter), `dma_enabler_maximum_length`,
  `create_common_buffer` (→ handle + fake logical), `common_buffer_virtual/logical_address/
  length`, `dma_decode_logical` (sim device lookup).
- Timer: `create_timer`/`timer_start`/`timer_stop`/`timer_get_parent`/`timer_fire` (one-shot
  → EvtTimerFunc)/`timer_fired_count`.
- WorkItem: `create_workitem`/`workitem_enqueue`/`workitem_get_parent`/`workitem_run`
  (→ EvtWorkItem)/`workitem_ran_count`.
- `delete_object` revokes the device DMA domain + prunes interrupt/timer/workitem/common-buffer
  side-state.

3 new tests (interrupt ISR→DPC, DMA enabler+common buffer, timer+workitem). 32 WDF tests total.
