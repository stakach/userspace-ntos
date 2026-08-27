//! File object records + their lifecycle state machine (spec §12).

use nt_io_abi::{DeviceId, FileId};
use nt_types::{AccessMask, ClientId, ObjectId, UnicodeString};

bitflags::bitflags! {
    /// `FILE_SHARE_*` share access.
    #[repr(transparent)]
    #[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Default)]
    pub struct ShareAccess: u32 {
        const READ = 0x0000_0001;
        const WRITE = 0x0000_0002;
        const DELETE = 0x0000_0004;
    }
}

bitflags::bitflags! {
    /// `FILE_*` create options.
    #[repr(transparent)]
    #[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Default)]
    pub struct CreateOptions: u32 {
        const DIRECTORY_FILE = 0x0000_0001;
        const WRITE_THROUGH = 0x0000_0002;
        const SEQUENTIAL_ONLY = 0x0000_0004;
        const NO_INTERMEDIATE_BUFFERING = 0x0000_0008;
        const SYNCHRONOUS_IO_ALERT = 0x0000_0010;
        const SYNCHRONOUS_IO_NONALERT = 0x0000_0020;
        const NON_DIRECTORY_FILE = 0x0000_0040;
        const DELETE_ON_CLOSE = 0x0000_1000;
        const OPEN_FOR_BACKUP_INTENT = 0x0000_4000;
    }
}

bitflags::bitflags! {
    /// Internal `FO_*`-style file-object flags.
    #[repr(transparent)]
    #[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Default)]
    pub struct FileFlags: u32 {
        const SYNCHRONOUS_IO = 0x0000_0001;
        const CLEANUP_COMPLETE = 0x0000_0002;
    }
}

/// File lifecycle (spec §12.2). `IRP_MJ_CREATE` must succeed (→ `Open`) before a
/// usable handle is returned; cleanup (handle release) and close (final deref)
/// are kept distinct even where a simple device collapses them.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum FileState {
    #[default]
    Allocated,
    CreateIrpDispatched,
    Open,
    CleanupPending,
    CleanupComplete,
    ClosePending,
    Closed,
}

impl FileState {
    /// Whether `self -> next` is an allowed transition (spec §12.2).
    pub fn can_transition_to(self, next: FileState) -> bool {
        use FileState::*;
        matches!(
            (self, next),
            (Allocated, CreateIrpDispatched)
                | (Allocated, Closed) // create never dispatched (early failure)
                | (CreateIrpDispatched, Open)
                | (CreateIrpDispatched, ClosePending) // pending create cancelled by sync caller
                | (CreateIrpDispatched, Closed) // create failed
                | (Open, CleanupPending)
                | (CleanupPending, Open) // cleanup rejected before reaching the driver
                | (Open, ClosePending)
                | (CleanupPending, CleanupComplete)
                | (CleanupPending, ClosePending)
                | (CleanupComplete, ClosePending)
                | (CleanupComplete, Closed)
                | (ClosePending, Closed)
        )
    }

    /// A usable (opened, not yet cleaned-up) file.
    pub fn is_open(self) -> bool {
        matches!(self, FileState::Open)
    }

    /// The file has been fully closed.
    pub fn is_closed(self) -> bool {
        matches!(self, FileState::Closed)
    }
}

/// Canonical I/O Manager file-object record (spec §12.1). A File is an open
/// instance of a Device. `object_id` points at the Object Manager `File` object;
/// the canonical handle lives in the Object Manager's per-client table.
///
/// Note: the spec's separate `cleanup_done`/`close_done` booleans are subsumed by
/// the [`FileState`] machine here, which keeps cleanup and close distinct.
pub struct FileRecord {
    pub id: FileId,
    pub object_id: ObjectId,
    /// Opaque Object Manager strong-reference token held for this record.
    pub object_reference: u64,
    pub client_id: ClientId,
    pub device_id: DeviceId,
    pub desired_access: AccessMask,
    pub share_access: ShareAccess,
    pub create_options: CreateOptions,
    pub flags: FileFlags,
    /// Parent captured for a handle-relative CREATE. `allocate_irp` transfers this identity into
    /// the CREATE stack and clears it here; the CREATE IRP, not the child File lifetime, retains
    /// the parent.
    pub related_file: Option<FileId>,
    /// Exact `FILE_OBJECT.FileName` supplied to the filesystem. It may be absolute, relative, or
    /// empty; it is not an Object Manager path and therefore must not be parsed as `NtPath`.
    pub file_name: UnicodeString,
    /// Mutable driver-owned `FILE_OBJECT.FsContext` payload. Canonical identity
    /// is always `id`; drivers may share, replace, tag, clear, or leave this
    /// value null.
    pub driver_context: Option<u64>,
    pub state: FileState,
    /// IRPs whose canonical records still reference this file, including
    /// terminal completions that have not yet been acknowledged by their owner.
    pub outstanding_irp_refs: u32,
    /// The user handle is gone, but final close is waiting for IRP references.
    pub close_deferred: bool,
    /// `IRP_MJ_CLEANUP` has been handed to the driver exactly once.
    pub cleanup_dispatched: bool,
    /// `IRP_MJ_CLOSE` has been handed to the driver exactly once.
    pub close_dispatched: bool,
}

impl FileRecord {
    /// A freshly-allocated file record (id filled in by the store's caller).
    pub fn new(
        object_id: ObjectId,
        client_id: ClientId,
        device_id: DeviceId,
        desired_access: AccessMask,
        share_access: ShareAccess,
        create_options: CreateOptions,
        file_name: UnicodeString,
    ) -> Self {
        Self {
            id: FileId::NULL,
            object_id,
            object_reference: 0,
            client_id,
            device_id,
            desired_access,
            share_access,
            create_options,
            flags: FileFlags::empty(),
            related_file: None,
            file_name,
            driver_context: None,
            state: FileState::Allocated,
            outstanding_irp_refs: 0,
            close_deferred: false,
            cleanup_dispatched: false,
            close_dispatched: false,
        }
    }

    /// Advance the lifecycle state if the transition is allowed. Returns whether
    /// the transition was applied.
    pub fn transition(&mut self, next: FileState) -> bool {
        if self.state.can_transition_to(next) {
            self.state = next;
            true
        } else {
            false
        }
    }
}
