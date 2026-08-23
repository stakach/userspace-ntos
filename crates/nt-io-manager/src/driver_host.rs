//! Machine-readable status of the hosted WDM I/O support surface (spec §20).

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
    /// Owned by the canonical I/O Manager and Object Manager.
    Canonical,
    /// Implemented by the component-local WDM projection runtime.
    HostedRuntime,
    /// WDK inline helper operating on the projected IRP layout.
    InlineWdm,
    /// Crosses the authenticated hosted-provider boundary.
    ProviderBoundary,
    /// Partially available (`IoCancelIrp`).
    Partial,
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

    /// Current implementation boundary (spec §20).
    pub fn mvp_status(self) -> MvpStatus {
        use DriverHostRoutine::*;
        match self {
            IoCreateDevice | IoDeleteDevice | IoCreateSymbolicLink | IoDeleteSymbolicLink => {
                MvpStatus::Canonical
            }
            IoCompleteRequest | IoCallDriver => MvpStatus::ProviderBoundary,
            IoMarkIrpPending | IoSetCompletionRoutine => MvpStatus::InlineWdm,
            IoGetCurrentIrpStackLocation
            | IoGetNextIrpStackLocation
            | IoCopyCurrentIrpStackLocationToNext
            | IoSkipCurrentIrpStackLocation => MvpStatus::HostedRuntime,
            IoCancelIrp => MvpStatus::Partial,
        }
    }
}
