//! # `nt-kernel-exec` — the local NT kernel execution runtime
//!
//! The IRQL / spin-lock / DPC / timer / event / work-item runtime a Driver Host
//! provides to a loaded driver, so drivers can defer work and complete IRPs
//! asynchronously (spec: NT Dispatcher/DPC/Timer/Work-Item, Milestone 10). DPC /
//! timer / work-item callbacks are function pointers into the loaded driver image
//! and run **inside** the Driver Host at the correct simulated IRQL. `no_std` +
//! `alloc`; the driver-visible dispatcher structures are opaque storage keyed by
//! the driver's pointer in runtime-side tables.

#![no_std]

extern crate alloc;

mod dpc;
mod event;
mod irql;
mod spin;
mod timer;

pub use dpc::{DpcImportance, DpcQueue};
pub use event::{EventKind, EventStore, WaitResult};
pub use irql::{IrqlState, APC_LEVEL, DISPATCH_LEVEL, PASSIVE_LEVEL};
pub use spin::{SpinError, SpinLockTable};
pub use timer::{Clock, FakeClock, TimerQueue};

/// Invokes driver callbacks (DPC / timer-DPC / work-item routines) — function
/// pointers into the loaded driver image (spec §7.2). Calling into driver code is
/// `unsafe` in the real Driver Host (the impl wraps a Microsoft-x64 call);
/// host tests use a recording mock. `irql` is the simulated IRQL the callback runs
/// at, passed so tests can assert the context (spec §6.1) — the real driver reads
/// it via `KeGetCurrentIrql`.
pub trait DriverCallbackInvoker {
    /// `Routine(Dpc, DeferredContext, SystemArgument1, SystemArgument2)`.
    fn call_dpc(
        &mut self,
        irql: u8,
        routine: u64,
        dpc: u64,
        deferred_context: u64,
        arg1: u64,
        arg2: u64,
    );

    /// `Routine(DeviceObject, Context)`.
    fn call_work_item(&mut self, irql: u8, routine: u64, device_object: u64, context: u64);
}
