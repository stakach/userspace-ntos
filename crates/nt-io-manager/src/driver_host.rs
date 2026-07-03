//! Driver Host readiness: the support-routine plan (spec §20).
//!
//! The names + MVP status of the I/O Manager-compatible support routines a future
//! Driver Host runtime will provide, as a **machine-readable plan** — planned now
//! so the Driver Host spec can build on this I/O Manager without redesigning IRP
//! ownership, but not yet callable by real drivers. The export names feed a future
//! `nt-compat-exports` crate.

/// An I/O Manager-compatible driver support routine (WDK `Io*` name).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DriverHostRoutine {
    IoCreateDevice,
    IoDeleteDevice,
    IoCreateSymbolicLink,
    IoDeleteSymbolicLink,
    IoCompleteRequest,
    IoMarkIrpPending,
    IoGetCurrentIrpStackLocation,
    IoGetNextIrpStackLocation,
    IoCopyCurrentIrpStackLocationToNext,
    IoSkipCurrentIrpStackLocation,
    IoCallDriver,
    IoSetCompletionRoutine,
    IoCancelIrp,
}

/// The v0.1 MVP implementation status of a support routine (spec §20).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum MvpStatus {
    /// Implemented internally by the I/O Manager today (e.g. `IoCreateDevice`).
    RequiredInternal,
    /// Realised through the driver-peer protocol (e.g. `IoCompleteRequest`).
    ThroughPeerProtocol,
    /// Provided by the Driver Host runtime later (stack-location accessors).
    DriverHostLater,
    /// A single-device-stack stub for now (`IoCallDriver`).
    SingleStackStub,
    /// Deferred (`IoSetCompletionRoutine`).
    Deferred,
    /// Partially available (`IoCancelIrp`).
    Partial,
    /// Optional for the MVP (`IoDeleteSymbolicLink`).
    Optional,
}

impl DriverHostRoutine {
    /// Every planned support routine.
    pub const ALL: [DriverHostRoutine; 13] = [
        DriverHostRoutine::IoCreateDevice,
        DriverHostRoutine::IoDeleteDevice,
        DriverHostRoutine::IoCreateSymbolicLink,
        DriverHostRoutine::IoDeleteSymbolicLink,
        DriverHostRoutine::IoCompleteRequest,
        DriverHostRoutine::IoMarkIrpPending,
        DriverHostRoutine::IoGetCurrentIrpStackLocation,
        DriverHostRoutine::IoGetNextIrpStackLocation,
        DriverHostRoutine::IoCopyCurrentIrpStackLocationToNext,
        DriverHostRoutine::IoSkipCurrentIrpStackLocation,
        DriverHostRoutine::IoCallDriver,
        DriverHostRoutine::IoSetCompletionRoutine,
        DriverHostRoutine::IoCancelIrp,
    ];

    /// The exported symbol name (the future `nt-compat-exports` symbol).
    pub fn export_name(self) -> &'static str {
        use DriverHostRoutine::*;
        match self {
            IoCreateDevice => "IoCreateDevice",
            IoDeleteDevice => "IoDeleteDevice",
            IoCreateSymbolicLink => "IoCreateSymbolicLink",
            IoDeleteSymbolicLink => "IoDeleteSymbolicLink",
            IoCompleteRequest => "IoCompleteRequest",
            IoMarkIrpPending => "IoMarkIrpPending",
            IoGetCurrentIrpStackLocation => "IoGetCurrentIrpStackLocation",
            IoGetNextIrpStackLocation => "IoGetNextIrpStackLocation",
            IoCopyCurrentIrpStackLocationToNext => "IoCopyCurrentIrpStackLocationToNext",
            IoSkipCurrentIrpStackLocation => "IoSkipCurrentIrpStackLocation",
            IoCallDriver => "IoCallDriver",
            IoSetCompletionRoutine => "IoSetCompletionRoutine",
            IoCancelIrp => "IoCancelIrp",
        }
    }

    /// The v0.1 MVP status (spec §20).
    pub fn mvp_status(self) -> MvpStatus {
        use DriverHostRoutine::*;
        match self {
            IoCreateDevice | IoDeleteDevice | IoCreateSymbolicLink => MvpStatus::RequiredInternal,
            IoDeleteSymbolicLink => MvpStatus::Optional,
            IoCompleteRequest | IoMarkIrpPending => MvpStatus::ThroughPeerProtocol,
            IoGetCurrentIrpStackLocation
            | IoGetNextIrpStackLocation
            | IoCopyCurrentIrpStackLocationToNext
            | IoSkipCurrentIrpStackLocation => MvpStatus::DriverHostLater,
            IoCallDriver => MvpStatus::SingleStackStub,
            IoSetCompletionRoutine => MvpStatus::Deferred,
            IoCancelIrp => MvpStatus::Partial,
        }
    }
}
