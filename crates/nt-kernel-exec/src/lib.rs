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

mod irql;
mod spin;

pub use irql::{IrqlState, APC_LEVEL, DISPATCH_LEVEL, PASSIVE_LEVEL};
pub use spin::{SpinError, SpinLockTable};
