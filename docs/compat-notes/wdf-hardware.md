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
